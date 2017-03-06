use std::sync::Arc;

use ring::{digest, hmac, rand, signature};
use ring::constant_time::verify_slices_are_equal;
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
    /// ```
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
    #[serde(rename = "alg")]
    pub algorithm: Algorithm,

    /// Type of the JWT. Usually "JWT".
    #[serde(rename = "typ", skip_serializing_if = "Option::is_none")]
    pub media_type: Option<String>,

    /// Content Type
    #[serde(rename = "cty", skip_serializing_if = "Option::is_none")]
    pub content_type: Option<String>,

    #[serde(rename = "jku", skip_serializing_if = "Option::is_none")]
    pub web_key_url: Option<String>,

    #[serde(rename = "jwk", skip_serializing_if = "Option::is_none")]
    pub web_key: Option<String>,

    #[serde(rename = "kid", skip_serializing_if = "Option::is_none")]
    pub key_id: Option<String>,

    #[serde(rename="x5u", skip_serializing_if = "Option::is_none")]
    pub x509_url: Option<String>,

    #[serde(rename="x5c", skip_serializing_if = "Option::is_none")]
    pub x509_chain: Option<Vec<String>>,

    #[serde(rename="x5t", skip_serializing_if = "Option::is_none")]
    // XXX: what about x5t#256
    pub x509_fingerprint: Option<String>,

    #[serde(rename="crit", skip_serializing_if = "Option::is_none")]
    pub critical: Option<Vec<String>>,
}

impl Header {
    pub fn new(algorithm: Algorithm) -> Header {
        Header {
            algorithm: algorithm,
            media_type: Some("JWT".to_string()),
            content_type: None,
            web_key_url: None,
            web_key: None,
            key_id: None,
            x509_url: None,
            x509_chain: None,
            x509_fingerprint: None,
            critical: None,
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

    /// Verify signature
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
        Ok(hmac::sign(&key, data).as_ref().to_vec())
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
        let actual_signature = Self::sign_hmac(data, secret, algorithm)?;
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
        expected.key_id = Some("kid".to_string());

        let expected_json = r#"{"alg":"HS256","typ":"JWT","kid":"kid"}"#;

        let encoded = not_err!(serde_json::to_string(&expected));
        assert_eq!(expected_json, encoded);

        let decoded: Header = not_err!(serde_json::from_str(&encoded));
        assert_eq!(decoded, expected);
    }

    #[test]
    fn sign_hs256() {
        let expected_base64 = "uC_LeRrOxXhZuYm0MKgmSIzi5Hn9-SMmvQoug3WkK6Q";
        let expected_bytes: Vec<u8> = not_err!(expected_base64.from_base64());

        let actual_signature = not_err!(Algorithm::HS256.sign("payload".to_string().as_bytes(),
                                                              Secret::Bytes("secret".to_string().into_bytes())));
        assert_eq!(actual_signature.as_slice().to_base64(base64::URL_SAFE),
                   expected_base64);

        let valid = not_err!(Algorithm::HS256.verify(expected_bytes.as_slice(),
                                                     "payload".to_string().as_bytes(),
                                                     Secret::Bytes("secret".to_string().into_bytes())));
        assert!(valid);
    }

    /// To generate hash, use
    ///
    /// ```sh
    /// echo -n "payload" | openssl dgst -sha256 -sign test/fixtures/private_key.pem | base64
    /// ```
    ///
    /// The base64 encoding from this command will be in `STANDARD` form and not URL_SAFE.
    #[test]
    fn sign_rs256() {
        let private_key = Secret::RSAKeyPair(::test::read_private_key());
        let payload = "payload".to_string();
        let payload_bytes = payload.as_bytes();
        // This is standard base64
        let expected_signature = "JIHqiBfUknrFPDLT0gxyoufD06S43ZqWN_PzQqHZqQ-met7kZmkSTYB_rUyotLMxlKkuXdnvKmWm\
                                  dwGAHWEwDvb5392pCmAAtmUIl6LormxJptWYb2PoF5jmtX_lwV8y4RYIh54Ai51162VARQCKAsxL\
                                  uH772MEChkcpjd31NWzaePWoi_IIk11iqy6uFWmbLLwzD_Vbpl2C6aHR3vQjkXZi05gA3zksjYAh\
                                  j-m7GgBt0UFOE56A4USjhQwpb4g3NEamgp51_kZ2ULi4Aoo_KJC6ynIm_pR6rEzBgwZjlCUnE-6o\
                                  5RPQZ8Oau03UDVH2EwZe-Q91LaWRvkKjGg5Tcw";
        let expected_signature_bytes: Vec<u8> = not_err!(expected_signature.from_base64());

        let actual_signature = not_err!(Algorithm::RS256.sign(payload_bytes, private_key));
        assert_eq!(expected_signature,
                   actual_signature.as_slice().to_base64(base64::URL_SAFE));

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
                                                     "payload".to_string().as_bytes(),
                                                     Secret::Bytes("secret".to_string().into_bytes())));
        assert!(!valid);
    }

    #[test]
    fn invalid_rs256() {
        let public_key = Secret::PublicKey(::test::read_public_key());
        let invalid_signature = "broken".to_string();
        let signature_bytes = invalid_signature.as_bytes();
        let valid = not_err!(Algorithm::RS256.verify(signature_bytes,
                                                     "payload".to_string().as_bytes(),
                                                     public_key));
        assert!(!valid);
    }
}
