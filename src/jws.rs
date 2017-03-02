use std::sync::Arc;

use serde::{Serialize, Serializer};
use serde::ser::SerializeStruct;
use ring::{digest, hmac, rand, signature};
use ring::constant_time::verify_slices_are_equal;
use rustc_serialize::base64::{self, ToBase64};

use untrusted;

use errors::Error;

#[derive(Debug, PartialEq, Deserialize)]
/// A basic JWT header part, the alg defaults to HS256 and typ is automatically
/// set to `JWT`. All the other fields are optional
// TODO: Implement verification for registered headers and support custom headers
// https://tools.ietf.org/html/rfc7515#section-4.1
pub struct Header {
    pub alg: Algorithm,
    /// Type of the JWT. Usually "JWT".
    pub typ: Option<String>,
    pub jku: Option<String>,
    pub kid: Option<String>,
    pub x5u: Option<String>,
    pub x5t: Option<String>,
}

impl Header {
    pub fn new(algorithm: Algorithm) -> Header {
        Header {
            alg: algorithm,
            typ: Some("JWT".to_string()),
            jku: None,
            kid: None,
            x5u: None,
            x5t: None,
        }
    }

    fn count_fields(&self) -> usize {
        macro_rules! count {
            ($field_name:ident) => (
                match self.$field_name {
                    Some(_) => 1,
                    None => 0
                }
            )
        }

        1 + count!(typ) + count!(jku) + count!(kid) + count!(x5u) + count!(x5t)
    }
}

impl Serialize for Header {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
        where S: Serializer
    {
        let mut struc = serializer.serialize_struct("Header", self.count_fields())?;
        struc.serialize_field("alg", &self.alg)?;

        macro_rules! optional {
            ($field_name:ident) => (
                if let Some(ref value) = self.$field_name {
                    struc.serialize_field(stringify!($field_name), value)?;
                }
            )
        }

        optional!(typ);
        optional!(jku);
        optional!(kid);
        optional!(x5u);
        optional!(x5t);

        struc.end()
    }
}

impl Default for Header {
    fn default() -> Header {
        Header::new(Algorithm::HS256)
    }
}

#[derive(Debug, PartialEq, Copy, Clone, Serialize, Deserialize)]
/// The algorithms supported for signing/verifying
// TODO: Add support for `none`
pub enum Algorithm {
    HS256,
    HS384,
    HS512,
    RS256,
    RS384,
    RS512,
}

impl Algorithm {
    /// Take the payload of a JWT and sign it using the algorithm given.
    /// Returns the base64 url safe encoded of the result
    /// # Secret
    /// This is dependent on the algorithm. For HMAC algorithm, this is some secret string.
    ///
    /// For RSA algorithm, this should be a private key in DER-encoded ASN.1 `RSAPrivateKey` form
    /// (see [RFC 3447 Appendix A.1.2]).
    ///
    /// Only two-prime keys (version 0) keys are supported. The public modulus
    /// (n) must be at least 2048 bits. Currently, the public modulus must be
    /// no larger than 4096 bits.
    ///
    /// Here's one way to generate a key in the required format using OpenSSL:
    ///
    /// ```sh
    /// openssl genpkey -algorithm RSA \
    ///                 -pkeyopt rsa_keygen_bits:2048 \
    ///                 -outform der \
    ///                 -out private_key.der
    /// ```
    ///
    /// Often, keys generated for use in OpenSSL-based software are
    /// encoded in PEM format, which is not supported by `ring`, the cryptographic library used.
    /// PEM-encoded keys that are in `RSAPrivateKey` format can be decoded into the using
    /// an OpenSSL command like this:
    ///
    /// ```sh
    /// openssl rsa -in private_key.pem -outform DER -out private_key.der
    /// ```
    ///
    /// If these commands don't work, it is likely that the private key is in a
    /// different format like PKCS#8, which isn't supported yet.
    ///
    /// [RFC 3447 Appendix A.1.2]:
    ///     https://tools.ietf.org/html/rfc3447#appendix-A.1.2
    pub fn sign(&self, data: &str, secret: &[u8]) -> Result<String, Error> {
        use self::Algorithm::*;

        match *self {
            HS256 | HS384 | HS512 => Ok(Self::sign_hmac(data, secret, self)),
            RS256 | RS384 | RS512 => Self::sign_rsa(data, secret, self),
        }
    }

    /// Compares the signature given with a re-computed signature
    /// Signatures should be provided in Base64 URL_SAFE strings
    pub fn verify(&self, expected_signature: &str, data: &str, secret: &[u8]) -> bool {
        let actual_signature = match self.sign(data, secret) {
            Ok(signature) => signature,
            Err(_) => return false,
        };

        verify_slices_are_equal(expected_signature.as_ref(), actual_signature.as_ref()).is_ok()
    }

    fn sign_hmac(data: &str, secret: &[u8], algorithm: &Algorithm) -> String {
        let digest = match *algorithm {
            Algorithm::HS256 => &digest::SHA256,
            Algorithm::HS384 => &digest::SHA384,
            Algorithm::HS512 => &digest::SHA512,
            _ => unreachable!("Should not happen"),
        };
        let key = hmac::SigningKey::new(digest, secret);
        hmac::sign(&key, data.as_bytes()).as_ref().to_base64(base64::URL_SAFE)
    }

    fn sign_rsa(data: &str, private_key: &[u8], algorithm: &Algorithm) -> Result<String, Error> {
        let key_pair = Arc::new(signature::RSAKeyPair::from_der(untrusted::Input::from(private_key))?);
        let mut signing_state = signature::RSASigningState::new(key_pair)?;
        let rng = rand::SystemRandom::new();
        let mut signature = vec![0; signing_state.key_pair().public_modulus_len()];
        let padding_algorithm = match *algorithm {
            Algorithm::RS256 => &signature::RSA_PKCS1_SHA256,
            Algorithm::RS384 => &signature::RSA_PKCS1_SHA384,
            Algorithm::RS512 => &signature::RSA_PKCS1_SHA512,
            _ => unreachable!("Should not happen"),
        };
        signing_state.sign(padding_algorithm, &rng, data.as_bytes(), &mut signature)?;
        Ok(signature.as_slice().to_base64(base64::URL_SAFE))
    }
}

#[cfg(test)]
mod tests {
    use std::str;
    use serde_json;
    use rustc_serialize::base64::{self, ToBase64, FromBase64};
    use super::{Algorithm, Header};

    #[test]
    fn header_serialization_round_trip_no_optional() {
        let expected = Header::default();
        let expected_json = r#"{"alg":"HS256","typ":"JWT"}"#;

        let encoded = not_err!(serde_json::to_string(&expected));
        assert_eq!(expected_json, encoded);

        let decoded: Header = not_err!(serde_json::from_str(&encoded));
        assert_eq!(decoded, expected);
    }

    #[test]
    fn header_serialization_round_trip_with_optional() {
        let mut expected = Header::default();
        expected.kid = Some("kid".to_string());

        let expected_json = r#"{"alg":"HS256","typ":"JWT","kid":"kid"}"#;

        let encoded = not_err!(serde_json::to_string(&expected));
        assert_eq!(expected_json, encoded);

        let decoded: Header = not_err!(serde_json::from_str(&encoded));
        assert_eq!(decoded, expected);
    }

    #[test]
    fn sign_hs256() {
        let expected = "c0zGLzKEFWj0VxWuufTXiRMk5tlI5MbGDAYhzaxIYjo";
        let result = not_err!(Algorithm::HS256.sign("hello world", b"secret"));
        assert_eq!(result, expected);

        let valid = Algorithm::HS256.verify(expected, "hello world", b"secret");
        assert!(valid);
    }

    /// To generate hash, use
    ///
    /// ```sh
    /// openssl dgst -sha256 -sign test/fixtures/private_key.pem  test/fixtures/signature_payload.txt | base64
    /// ```
    ///
    /// The base64 encoding will be in `STANDARD` form and not URL_SAFE.
    #[test]
    fn sign_rs256() {
        let private_key = ::test::read_private_key();
        let payload = not_err!(str::from_utf8(::test::read_signature_payload()));
        // Convert STANDARD base64 to URL_SAFE
        let expected_signature = "rg1MvJA9sH9x5xf8hZ3lFyAeUkz1wShrgB5G5rOlRI6oTZsUGwp7UBkxiopW80iBP/wvIbHEdI86\
                                  Q0jHaG4n1X7ij0NSSbN3LRawFOEodPDvXsk8kaoyUaLsLyFUf4Gdg3z7YSc0ZT8Ry0pKLls7c0ga\
                                  cpdYb7+Vw35+FNwA70tSt6vV5YKiFDDoiTvubM/3gizsDGCPMLVeRKGpSvBPaHtclgbM+kxML4fR\
                                  qqHsNdnbrI/ic+A5E1KFm9oeUAbbwb1dxhz6d6N3jwg8j7ttyskIa4gK9yxBUASYoFaakMDhBfeg\
                                  QAyE/zz7nWs3j9B4cy9a9tVV/3E7N3U5J0xRzQ==";
        let expected_signature = not_err!(str::from_base64(expected_signature));
        let expected_signature = expected_signature.to_base64(base64::URL_SAFE);

        let actual_signature = not_err!(Algorithm::RS256.sign(payload, private_key));
        assert_eq!(expected_signature, actual_signature);

        let valid = Algorithm::RS256.verify(&*expected_signature, payload, private_key);
        assert!(valid);
    }

    #[test]
    fn invalid_hs256() {
        let invalid_signature = "broken";
        assert!(!Algorithm::HS256.verify(invalid_signature, "hello world", b"secret"));
    }

    #[test]
    fn invalid_rs256() {
        let private_key = ::test::read_private_key();
        let invalid_signature = "broken";
        assert!(!Algorithm::RS256.verify(invalid_signature, "hello world", private_key));
    }
}
