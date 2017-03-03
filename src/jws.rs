use std::sync::Arc;

use ring::{digest, hmac, rand, signature};
use ring::constant_time::verify_slices_are_equal;
use rustc_serialize::base64::{self, ToBase64};
use untrusted;

use errors::Error;

pub enum Secret {
    /// Bytes used for HMAC secret. Can be constructed from a string literal
    ///
    /// # Examples
    /// ```
    /// use jwt::jws::Secret;
    ///
    /// let secret = Secret::Bytes("secret".to_string().into_bytes());
    /// ```
    Bytes(Vec<u8>),
    /// An RSA Key pair constructed from a DER-encoded private key
    ///
    /// To generate a private key, use
    ///
    /// ```sh
    /// openssl genpkey -algorithm RSA \
    ///                 -pkeyopt rsa_keygen_bits:2048 \
    ///                 -outform der \
    ///                 -out private_key.der
    /// ```
    ///
    /// Often, keys generated for use in OpenSSL-based software are
    /// encoded in PEM format, which is not supported by *ring*. PEM-encoded
    /// keys that are in `RSAPrivateKey` format can be decoded into the using
    /// an OpenSSL command like this:
    ///
    /// ```sh
    /// openssl rsa -in private_key.pem -outform DER -out private_key.der
    /// ```
    ///
    /// # Examples
    /// ```
    /// extern crate jwt;
    /// extern crate ring;
    /// extern crate untrusted;
    ///
    /// use jwt::jws::Secret;
    /// use ring::signature;
    ///
    /// # fn main() {
    /// let der = include_bytes!("test/fixtures/private_key.der");
    /// let key_pair = signature::RSAKeyPair::from_der(untrusted::Input::from(der)).unwrap();
    /// let secret = Secret::RSAKeyPair(key_pair);
    /// # }
    /// ```
    RSAKeyPair(signature::RSAKeyPair),
    /// Bytes of a DER encoded RSA Public Key
    ///
    /// To generate the public key from your DER-encoded private key
    ///
    /// ```sh
    /// openssl rsa -in private_key.der \
    ///             -inform DER
    ///             -RSAPublicKey_out \
    ///             -outform DER \
    ///             -out public_key.der
    ///```
    ///
    /// To convert a PEM formatted public key
    ///
    /// ```sh
    /// openssl rsa -RSAPublicKey_in \
    ///             -in public_key.pem \
    ///             -inform PEM \
    ///             -outform DER \
    ///             -RSAPublicKey_out \
    ///             -out public_key.der
    /// ```
    ///
    /// # Examples
    /// ```
    /// use jwt::jws::Secret;
    ///
    /// let der = include_bytes!("test/fixtures/public_key.der");
    /// let secret = Secret::PublicKey(der.iter().map(|b| b.clone()).collect());
    PublicKey(Vec<u8>),
}

#[derive(Debug, PartialEq, Serialize, Deserialize)]
/// A basic JWT header part, the alg defaults to HS256 and typ is automatically
/// set to `JWT`. All the other fields are optional
// TODO: Implement verification for registered headers and support custom headers
// https://tools.ietf.org/html/rfc7515#section-4.1
pub struct Header {
    pub alg: Algorithm,
    /// Type of the JWT. Usually "JWT".
    #[serde(skip_serializing_if = "Option::is_none")]
    pub typ: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub jku: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub kid: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub x5u: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
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
    pub fn sign(&self, data: &[u8], secret: Secret) -> Result<Vec<u8>, Error> {
        use self::Algorithm::*;

        match *self {
            HS256 | HS384 | HS512 => Self::sign_hmac(data, secret, self),
            RS256 | RS384 | RS512 => Self::sign_rsa(data, secret, self),
        }
    }

    /// CVerify signature
    pub fn verify(&self, expected_signature: &[u8], data: &[u8], secret: Secret) -> Result<bool, Error> {
        use self::Algorithm::*;

        match *self {
            HS256 | HS384 | HS512 => Self::verify_hmac(expected_signature, data, secret, self),
            RS256 | RS384 | RS512 => Self::verify_rsa(expected_signature, data, secret, self),
        }

    }

    fn sign_hmac(data: &[u8], secret: Secret, algorithm: &Algorithm) -> Result<Vec<u8>, Error> {
        let secret = match secret {
            Secret::Bytes(secret) => secret,
            _ => Err("Invalid secret type. A byte array is required".to_string())?,
        };

        let digest = match *algorithm {
            Algorithm::HS256 => &digest::SHA256,
            Algorithm::HS384 => &digest::SHA384,
            Algorithm::HS512 => &digest::SHA512,
            _ => unreachable!("Should not happen"),
        };
        let key = hmac::SigningKey::new(digest, &secret);
        Ok(hmac::sign(&key, data).as_ref().iter().map(|b| b.clone()).collect())
    }

    fn sign_rsa(data: &[u8], secret: Secret, algorithm: &Algorithm) -> Result<Vec<u8>, Error> {
        let private_key = match secret {
            Secret::RSAKeyPair(key_pair) => key_pair,
            _ => Err("Invalid secret type. A RSAKeyPair is required".to_string())?,
        };
        let key_pair = Arc::new(private_key);
        let mut signing_state = signature::RSASigningState::new(key_pair)?;
        let rng = rand::SystemRandom::new();
        let mut signature = vec![0; signing_state.key_pair().public_modulus_len()];
        let padding_algorithm = match *algorithm {
            Algorithm::RS256 => &signature::RSA_PKCS1_SHA256,
            Algorithm::RS384 => &signature::RSA_PKCS1_SHA384,
            Algorithm::RS512 => &signature::RSA_PKCS1_SHA512,
            _ => unreachable!("Should not happen"),
        };
        signing_state.sign(padding_algorithm, &rng, data, &mut signature)?;
        Ok(signature)
    }

    fn verify_hmac(expected_signature: &[u8],
                   data: &[u8],
                   secret: Secret,
                   algorithm: &Algorithm)
                   -> Result<bool, Error> {
        let actual_signature = algorithm.sign(data, secret)?;
        Ok(verify_slices_are_equal(expected_signature.as_ref(), actual_signature.as_ref()).is_ok())
    }

    fn verify_rsa(expected_signature: &[u8],
                  data: &[u8],
                  secret: Secret,
                  algorithm: &Algorithm)
                  -> Result<bool, Error> {
        let public_key = match secret {
            Secret::PublicKey(public_key) => public_key,
            _ => Err("Invalid secret type. A PublicKey is required".to_string())?,
        };
        let public_key_der = untrusted::Input::from(public_key.as_slice());

        let verification_algorithm = match *algorithm {
            Algorithm::RS256 => &signature::RSA_PKCS1_2048_8192_SHA256,
            Algorithm::RS384 => &signature::RSA_PKCS1_2048_8192_SHA384,
            Algorithm::RS512 => &signature::RSA_PKCS1_2048_8192_SHA512,
            _ => unreachable!("Should not happen"),
        };

        let message = untrusted::Input::from(data);
        let expected_signature = untrusted::Input::from(expected_signature);
        match signature::verify(verification_algorithm,
                                public_key_der,
                                message,
                                expected_signature) {
            Ok(()) => Ok(true),
            Err(e) => {
                println!("{}", e);
                Ok(false)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use std::str;
    use serde_json;
    use rustc_serialize::base64::{self, ToBase64, FromBase64};
    use super::{Secret, Algorithm, Header};

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
        let expected_base64 = "c0zGLzKEFWj0VxWuufTXiRMk5tlI5MbGDAYhzaxIYjo";
        let expected_bytes: Vec<u8> = not_err!(expected_base64.from_base64());

        let actual_signature = not_err!(Algorithm::HS256.sign("hello world".to_string().as_bytes(),
                                                              Secret::Bytes("secret".to_string().into_bytes())));
        assert_eq!(actual_signature.as_slice().to_base64(base64::URL_SAFE),
                   expected_base64);

        let valid = not_err!(Algorithm::HS256.verify(expected_bytes.as_slice(),
                                                     "hello world".to_string().as_bytes(),
                                                     Secret::Bytes("secret".to_string().into_bytes())));
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
        let private_key = Secret::RSAKeyPair(::test::read_private_key());
        let payload = not_err!(str::from_utf8(::test::read_signature_payload())).to_string();
        let payload_bytes = payload.as_bytes();
        // This is standard base64
        let expected_signature = "rg1MvJA9sH9x5xf8hZ3lFyAeUkz1wShrgB5G5rOlRI6oTZsUGwp7UBkxiopW80iBP/wvIbHEdI86\
                                  Q0jHaG4n1X7ij0NSSbN3LRawFOEodPDvXsk8kaoyUaLsLyFUf4Gdg3z7YSc0ZT8Ry0pKLls7c0ga\
                                  cpdYb7+Vw35+FNwA70tSt6vV5YKiFDDoiTvubM/3gizsDGCPMLVeRKGpSvBPaHtclgbM+kxML4fR\
                                  qqHsNdnbrI/ic+A5E1KFm9oeUAbbwb1dxhz6d6N3jwg8j7ttyskIa4gK9yxBUASYoFaakMDhBfeg\
                                  QAyE/zz7nWs3j9B4cy9a9tVV/3E7N3U5J0xRzQ==";
        let expected_signature_bytes: Vec<u8> = not_err!(expected_signature.from_base64());

        let actual_signature = not_err!(Algorithm::RS256.sign(payload_bytes, private_key));
        assert_eq!(expected_signature,
                   actual_signature.as_slice().to_base64(base64::STANDARD));

        let public_key = Secret::PublicKey(::test::read_public_key());
        let valid = not_err!(Algorithm::RS256.verify(expected_signature_bytes.as_slice(),
                                                     payload_bytes,
                                                     public_key));
        assert!(valid);
    }

    #[test]
    fn invalid_hs256() {
        let invalid_signature = "broken".to_string();
        let signature_bytes = invalid_signature.as_bytes();
        let valid = not_err!(Algorithm::HS256.verify(signature_bytes,
                                                     "hello world".to_string().as_bytes(),
                                                     Secret::Bytes("secret".to_string().into_bytes())));
        assert!(!valid);
    }

    #[test]
    fn invalid_rs256() {
        let public_key = Secret::PublicKey(::test::read_public_key());
        let invalid_signature = "broken".to_string();
        let signature_bytes = invalid_signature.as_bytes();
        let valid = not_err!(Algorithm::RS256.verify(signature_bytes,
                                                     "hello world".to_string().as_bytes(),
                                                     public_key));
        assert!(!valid);
    }
}
