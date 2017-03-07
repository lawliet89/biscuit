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
    /// let der = include_bytes!("test/fixtures/rsa_private_key.der");
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
    /// let der = include_bytes!("test/fixtures/rsa_public_key.der");
    /// let secret = Secret::PublicKey(der.iter().map(|b| b.clone()).collect());
    PublicKey(Vec<u8>),
    ECDSAPublicKey(Vec<u8>),
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
/// The algorithms supported for signing/verifying.
// TODO: Add support for `none`
pub enum Algorithm {
    /// HMAC using SHA-256
    HS256,
    /// HMAC using SHA-384
    HS384,
    /// HMAC using SHA-512
    HS512,
    /// RSASSA-PKCS1-v1_5 using SHA-256
    RS256,
    /// RSASSA-PKCS1-v1_5 using SHA-384
    RS384,
    /// RSASSA-PKCS1-v1_5 using SHA-512
    RS512,
    /// ECDSA using P-256 and SHA-256
    ES256,
    /// ECDSA using P-384 and SHA-384
    ES384,
    /// ECDSA using P-521 and SHA-512 --
    /// This variant is [unsupported](https://github.com/briansmith/ring/issues/268) and will probably never be.
    ES512,
    /// RSASSA-PSS using SHA-256 and MGF1 with SHA-256.
    /// The size of the salt value is the same size as the hash function output.
    PS256,
    /// RSASSA-PSS using SHA-384 and MGF1 with SHA-384
    /// The size of the salt value is the same size as the hash function output.
    PS384,
    /// RSASSA-PSS using SHA-512 and MGF1 with SHA-512
    /// The size of the salt value is the same size as the hash function output.
    PS512,
}

impl Algorithm {
    /// Take the payload of a JWT and sign it using the algorithm given.
    pub fn sign(&self, data: &[u8], secret: Secret) -> Result<Vec<u8>, Error> {
        use self::Algorithm::*;

        match *self {
            HS256 | HS384 | HS512 => Self::sign_hmac(data, secret, self),
            RS256 | RS384 | RS512 | PS256 | PS384 | PS512 => Self::sign_rsa(data, secret, self),
            ES256 | ES384 | ES512 => Self::sign_ecdsa(data, secret, self),
        }
    }

    /// Verify signature
    pub fn verify(&self, expected_signature: &[u8], data: &[u8], secret: Secret) -> Result<bool, Error> {
        use self::Algorithm::*;

        match *self {
            HS256 | HS384 | HS512 => Self::verify_hmac(expected_signature, data, secret, self),
            RS256 | RS384 | RS512 | PS256 | PS384 | PS512 | ES256 | ES384 | ES512 => {
                Self::verify_public_key(expected_signature, data, secret, self)
            }
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
        let padding_algorithm: &signature::RSAEncoding = match *algorithm {
            Algorithm::RS256 => &signature::RSA_PKCS1_SHA256,
            Algorithm::RS384 => &signature::RSA_PKCS1_SHA384,
            Algorithm::RS512 => &signature::RSA_PKCS1_SHA512,
            Algorithm::PS256 => &signature::RSA_PSS_SHA256,
            Algorithm::PS384 => &signature::RSA_PSS_SHA384,
            Algorithm::PS512 => &signature::RSA_PSS_SHA512,
            _ => unreachable!("Should not happen"),
        };
        signing_state.sign(padding_algorithm, &rng, data, &mut signature)?;
        Ok(signature)
    }

    fn sign_ecdsa(_data: &[u8], _secret: Secret, _algorithm: &Algorithm) -> Result<Vec<u8>, Error> {
        // Not supported at the moment by ring
        // Tracking issues:
        //  - P-256: https://github.com/briansmith/ring/issues/207
        //  - P-384: https://github.com/briansmith/ring/issues/209
        //  - P-521: Probably never: https://github.com/briansmith/ring/issues/268
        Err(Error::UnsupportedOperation)
    }

    fn verify_hmac(expected_signature: &[u8],
                   data: &[u8],
                   secret: Secret,
                   algorithm: &Algorithm)
                   -> Result<bool, Error> {
        let actual_signature = Self::sign_hmac(data, secret, algorithm)?;
        Ok(verify_slices_are_equal(expected_signature.as_ref(), actual_signature.as_ref()).is_ok())
    }

    fn verify_public_key(expected_signature: &[u8],
                         data: &[u8],
                         secret: Secret,
                         algorithm: &Algorithm)
                         -> Result<bool, Error> {
        let public_key = match secret {
            Secret::PublicKey(public_key) => public_key,
            _ => Err("Invalid secret type. A PublicKey is required".to_string())?,
        };
        let public_key_der = untrusted::Input::from(public_key.as_slice());

        let verification_algorithm: &signature::VerificationAlgorithm = match *algorithm {
            Algorithm::RS256 => &signature::RSA_PKCS1_2048_8192_SHA256,
            Algorithm::RS384 => &signature::RSA_PKCS1_2048_8192_SHA384,
            Algorithm::RS512 => &signature::RSA_PKCS1_2048_8192_SHA512,
            Algorithm::PS256 => &signature::RSA_PSS_2048_8192_SHA256,
            Algorithm::PS384 => &signature::RSA_PSS_2048_8192_SHA384,
            Algorithm::PS512 => &signature::RSA_PSS_2048_8192_SHA512,
            Algorithm::ES256 => &signature::ECDSA_P256_SHA256_ASN1,
            Algorithm::ES384 => &signature::ECDSA_P384_SHA384_ASN1,
            Algorithm::ES512 => Err(Error::UnsupportedOperation)?,
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
    fn sign_and_verify_hs256() {
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

    /// To generate the signature, use
    ///
    /// ```sh
    /// echo -n "payload" | openssl dgst -sha256 -sign test/fixtures/rsa_private_key.pem | base64
    /// ```
    ///
    /// The base64 encoding from this command will be in `STANDARD` form and not URL_SAFE.
    #[test]
    fn sign_and_verify_rs256() {
        let private_key = Secret::RSAKeyPair(::test::read_rsa_private_key());
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

        let public_key = Secret::PublicKey(::test::read_rsa_public_key());
        let valid = not_err!(Algorithm::RS256.verify(expected_signature_bytes.as_slice(),
                                                     payload_bytes,
                                                     public_key));
        assert!(valid);
    }

    /// This signature is non-deterministic.
    #[test]
    fn sign_and_verify_ps256_round_trip() {
        let private_key = Secret::RSAKeyPair(::test::read_rsa_private_key());
        let payload = "payload".to_string();
        let payload_bytes = payload.as_bytes();

        let actual_signature = not_err!(Algorithm::PS256.sign(payload_bytes, private_key));

        let public_key = Secret::PublicKey(::test::read_rsa_public_key());
        let valid = not_err!(Algorithm::PS256.verify(actual_signature.as_slice(),
                                                     payload_bytes,
                                                     public_key));
        assert!(valid);
    }

    /// To generate a (non-deterministic) signature:
    ///
    /// ```sh
    /// echo -n "payload" | openssl dgst -sha256 -sigopt rsa_padding_mode:pss -sigopt rsa_pss_saltlen:-1 \
    ///    -sign test/fixtures/rsa_private_key.pem | base64
    /// ```
    ///
    /// The base64 encoding from this command will be in `STANDARD` form and not URL_SAFE.
    #[test]
    fn verify_ps256() {
        let payload = "payload".to_string();
        let payload_bytes = payload.as_bytes();
        let signature = "TiMXtt3Wmv/a/tbLWuJPDlFYMfuKsD7U5lbBUn2mBu8DLMLj1EplEZNmkB8w65BgUijnu9hxmhwv\
                         ET2k7RrsYamEst6BHZf20hIK1yE/YWaktbVmAZwUDdIpXYaZn8ukTsMT06CDrVk6RXF0EPMaSL33\
                         tFNPZpz4/3pYQdxco/n6DpaR5206wsur/8H0FwoyiFKanhqLb1SgZqyc+SXRPepjKc28wzBnfWl4\
                         mmlZcJ2xk8O2/t1Y1/m/4G7drBwOItNl7EadbMVCetYnc9EILv39hjcL9JvaA9q0M2RB75DIu8SF\
                         9Kr/l+wzUJjWAHthgqSBpe15jLkpO8tvqR89fw==";
        let signature_bytes: Vec<u8> = not_err!(signature.from_base64());
        let public_key = Secret::PublicKey(::test::read_rsa_public_key());
        let valid = not_err!(Algorithm::PS256.verify(signature_bytes.as_slice(),
                                                     payload_bytes,
                                                     public_key));
        assert!(valid);
    }

    #[test]
    #[should_panic(expected = "UnsupportedOperation")]
    fn sign_ecdsa() {
        let private_key = Secret::Bytes("secret".to_string().into_bytes()); // irrelevant
        let payload = "payload".to_string();
        let payload_bytes = payload.as_bytes();

        Algorithm::ES256.sign(payload_bytes, private_key).unwrap();
    }

    /// Test case from https://github.com/briansmith/ring/blob/c5b8113/src/ec/suite_b/ecdsa_verify_tests.txt#L248
    #[test]
    fn verify_es256() {
        use rustc_serialize::hex::FromHex;

        let payload = "sample".to_string();
        let payload_bytes = payload.as_bytes();
        let public_key = "0460FED4BA255A9D31C961EB74C6356D68C049B8923B61FA6CE669622E60F29FB67903FE1008B8BC99A41AE9E9562\
                          8BC64F2F1B20C2D7E9F5177A3C294D4462299";
        let public_key = Secret::PublicKey(not_err!(public_key.from_hex()));
        let signature = "3046022100EFD48B2AACB6A8FD1140DD9CD45E81D69D2C877B56AAF991C34D0EA84EAF3716022100F7CB1C942D657C\
                         41D436C7A1B6E29F65F3E900DBB9AFF4064DC4AB2F843ACDA8";
        let signature_bytes: Vec<u8> = not_err!(signature.from_hex());
        let valid = not_err!(Algorithm::ES256.verify(signature_bytes.as_slice(), payload_bytes, public_key));
        assert!(valid);
    }

    /// Test case from https://github.com/briansmith/ring/blob/c5b8113/src/ec/suite_b/ecdsa_verify_tests.txt#L283
    #[test]
    fn verify_es384() {
        use rustc_serialize::hex::FromHex;

        let payload = "sample".to_string();
        let payload_bytes = payload.as_bytes();
        let public_key = "04EC3A4E415B4E19A4568618029F427FA5DA9A8BC4AE92E02E06AAE5286B300C64DEF8F0EA9055866064A25451548\
                          0BC138015D9B72D7D57244EA8EF9AC0C621896708A59367F9DFB9F54CA84B3F1C9DB1288B231C3AE0D4FE7344FD25\
                          33264720";
        let public_key = Secret::PublicKey(not_err!(public_key.from_hex()));
        let signature = "306602310094EDBB92A5ECB8AAD4736E56C691916B3F88140666CE9FA73D64C4EA95AD133C81A648152E44ACF96E36\
                         DD1E80FABE4602310099EF4AEB15F178CEA1FE40DB2603138F130E740A19624526203B6351D0A3A94FA329C145786E\
                         679E7B82C71A38628AC8";
        let signature_bytes: Vec<u8> = not_err!(signature.from_hex());
        let valid = not_err!(Algorithm::ES384.verify(signature_bytes.as_slice(), payload_bytes, public_key));
        assert!(valid);
    }

    #[test]
    #[should_panic(expected = "UnsupportedOperation")]
    fn verify_es512() {
        let payload: Vec<u8> = vec![];
        let signature: Vec<u8> = vec![];
        let public_key = Secret::PublicKey(vec![]);
        Algorithm::ES512.verify(signature.as_slice(), payload.as_slice(), public_key).unwrap();
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
        let public_key = Secret::PublicKey(::test::read_rsa_public_key());
        let invalid_signature = "broken".to_string();
        let signature_bytes = invalid_signature.as_bytes();
        let valid = not_err!(Algorithm::RS256.verify(signature_bytes,
                                                     "payload".to_string().as_bytes(),
                                                     public_key));
        assert!(!valid);
    }
}
