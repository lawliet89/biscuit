use std::sync::Arc;
use std::collections::BTreeMap;

use ring::{digest, hmac, rand, signature};
use ring::constant_time::verify_slices_are_equal;
use rustc_serialize;
use rustc_serialize::Encodable;
use rustc_serialize::base64::{self, ToBase64};
use rustc_serialize::json::{ToJson, Json};

use untrusted;

use errors::Error;

#[derive(Debug, PartialEq, RustcDecodable)]
/// A basic JWT header part, the alg defaults to HS256 and typ is automatically
/// set to `JWT`. All the other fields are optional
// TODO: Implement verification for registered headers and support custom headers
// https://tools.ietf.org/html/rfc7515#section-4.1
pub struct Header {
    typ: String,
    pub alg: Algorithm,
    pub jku: Option<String>,
    pub kid: Option<String>,
    pub x5u: Option<String>,
    pub x5t: Option<String>,
}

impl Header {
    pub fn new(algorithm: Algorithm) -> Header {
        Header {
            typ: "JWT".to_string(),
            alg: algorithm,
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

impl Encodable for Header {
    fn encode<S: rustc_serialize::Encoder>(&self, s: &mut S) -> Result<(), S::Error> {
        self.to_json().encode(s)
    }
}

/// The default serializer will serialize `None` values as `null`. We don't want that.
impl ToJson for Header {
    fn to_json(&self) -> Json {
        let mut d = BTreeMap::new();
        d.insert("typ".to_string(), self.typ.to_json());
        d.insert("alg".to_string(), self.alg.to_json());

        // Define a macro to reduce boilerplate.
        macro_rules! optional {
            ($field_name:ident) => (
                if let Some(ref value) = self.$field_name {
                    d.insert(stringify!($field_name).to_string(), value.to_json());
                }
            )
        }
        optional!(jku);
        optional!(kid);
        optional!(x5u);
        optional!(x5t);
        Json::Object(d)
    }
}

#[derive(Debug, PartialEq, Copy, Clone, RustcDecodable, RustcEncodable)]
/// The algorithms supported for signing/verifying
pub enum Algorithm {
    HS256,
    HS384,
    HS512,
    RS256,
    RS384,
    RS512,
}

impl ToJson for Algorithm {
    fn to_json(&self) -> Json {
        use self::Algorithm::*;

        match *self {
            HS256 => Json::String("HS256".to_string()),
            HS384 => Json::String("HS384".to_string()),
            HS512 => Json::String("HS512".to_string()),
            RS256 => Json::String("RS256".to_string()),
            RS384 => Json::String("RS384".to_string()),
            RS512 => Json::String("RS512".to_string()),
        }
    }
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
    use rustc_serialize::base64::{self, ToBase64, FromBase64};
    use super::Algorithm;

    #[test]
    fn sign_hs256() {
        let expected = "uC_LeRrOxXhZuYm0MKgmSIzi5Hn9-SMmvQoug3WkK6Q";
        let actual = not_err!(Algorithm::HS256.sign("payload", b"secret"));
        assert_eq!(expected, actual);

        let valid = Algorithm::HS256.verify(expected, "payload", b"secret");
        assert!(valid);
    }

    /// To generate hash, use
    ///
    /// ```sh
    /// echo -n "payload" | openssl dgst -sha256 -sign test/fixtures/private_key.pem | base64
    /// ```
    ///
    /// The base64 encoding will be in `STANDARD` form and not URL_SAFE.
    #[test]
    fn sign_rs256() {
        let private_key = ::test::read_private_key();
        // Convert STANDARD base64 to URL_SAFE
        let expected_signature = "JIHqiBfUknrFPDLT0gxyoufD06S43ZqWN_PzQqHZqQ-met7kZmkSTYB_rUyotLMxlKkuXdnvKmWm\
                                  dwGAHWEwDvb5392pCmAAtmUIl6LormxJptWYb2PoF5jmtX_lwV8y4RYIh54Ai51162VARQCKAsxL\
                                  uH772MEChkcpjd31NWzaePWoi_IIk11iqy6uFWmbLLwzD_Vbpl2C6aHR3vQjkXZi05gA3zksjYAh\
                                  j-m7GgBt0UFOE56A4USjhQwpb4g3NEamgp51_kZ2ULi4Aoo_KJC6ynIm_pR6rEzBgwZjlCUnE-6o\
                                  5RPQZ8Oau03UDVH2EwZe-Q91LaWRvkKjGg5Tcw";
        let expected_signature = not_err!(str::from_base64(expected_signature));
        let expected_signature = expected_signature.to_base64(base64::URL_SAFE);

        let actual_signature = not_err!(Algorithm::RS256.sign("payload", private_key));
        assert_eq!(expected_signature, actual_signature);

        let valid = Algorithm::RS256.verify(&*expected_signature, "payload", private_key);
        assert!(valid);
    }

    #[test]
    fn invalid_hs256() {
        assert!(!Algorithm::HS256.verify("invalid signature", "payload", b"secret"));
    }

    #[test]
    fn invalid_rs256() {
        let private_key = ::test::read_private_key();
        assert!(!Algorithm::RS256.verify("invalid signature", "payload", private_key));
    }
}
