//! JSON Web Algorithms
//!
//! Code for implementing JWA according to [RFC 7518](https://tools.ietf.org/html/rfc7518)
use ring::{digest, hmac, rand, signature};
use ring::constant_time::verify_slices_are_equal;
use untrusted;

use errors::Error;
use jws::Secret;

#[derive(Debug, Eq, PartialEq, Copy, Clone, Serialize, Deserialize)]
/// Algorithms described by [RFC 7518](https://tools.ietf.org/html/rfc7518).
/// This enum is serialized `untagged`.
#[serde(untagged)]
pub enum Algorithm {
    /// Algorithms meant for Digital signature or MACs
    /// See [RFC7518#3](https://tools.ietf.org/html/rfc7518#section-3)
    Signature(SignatureAlgorithm),
    /// Algorithms meant for key management. The algorithms are either meant to
    /// encrypt a content encryption key or determine the content encryption key.
    /// See [RFC7518#4](https://tools.ietf.org/html/rfc7518#section-4)
    KeyManagement(KeyManagementAlgorithm),
    /// Algorithms meant for content encryption.
    /// See [RFC7518#5](https://tools.ietf.org/html/rfc7518#section-5)
    ContentEncryption(ContentEncryptionAlgorithm),
}

#[derive(Debug, Eq, PartialEq, Copy, Clone, Serialize, Deserialize)]
/// The algorithms supported for digital signature and MACs, defined by
/// [RFC7518#3](https://tools.ietf.org/html/rfc7518#section-3).
pub enum SignatureAlgorithm {
    /// No encryption/signature is included for the JWT.
    /// During verification, the signature _MUST BE_ empty or verification  will fail.
    #[serde(rename = "none")]
    None,
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

/// Algorithms for key management as defined in [RFC7518#4](https://tools.ietf.org/html/rfc7518#section-4)
#[derive(Debug, Eq, PartialEq, Copy, Clone, Serialize, Deserialize)]
#[allow(non_camel_case_types)]
pub enum KeyManagementAlgorithm {
    /// RSAES-PKCS1-v1_5
    RSA1_5,
    /// RSAES OAEP using default parameters
    #[serde(rename = "RSA-OAEP")]
    RSA_OAEP,
    /// RSAES OAEP using SHA-256 and MGF1 with SHA-256
    #[serde(rename = "RSA-OAEP-256")]
    RSA_OAEP_256,
    /// AES Key Wrap using 128-bit key
    A128KW,
    /// AES Key Wrap using 192-bit key
    A192KW,
    /// AES Key Wrap using 256-bit key
    A256KW,
    /// Direct use of a shared symmetric key
    #[serde(rename = "dir")]
    DirectSymmetricKey,
    /// ECDH-ES using Concat KDF
    #[serde(rename = "ECDH-ES")]
    ECDH_ES,
    /// ECDH-ES using Concat KDF and "A128KW" wrapping
    #[serde(rename = "ECDH-ES+A128KW")]
    ECDH_ES_A128KW,
    /// ECDH-ES using Concat KDF and "A192KW" wrapping
    #[serde(rename = "ECDH-ES+A192KW")]
    ECDH_ES_A192KW,
    /// ECDH-ES using Concat KDF and "A256KW" wrapping
    #[serde(rename = "ECDH-ES+A256KW")]
    ECDH_ES_A256KW,
    /// Key wrapping with AES GCM using 128-bit key	alg
    A128GCMKW,
    /// Key wrapping with AES GCM using 192-bit key	alg
    A192GCMKW,
    /// Key wrapping with AES GCM using 256-bit key	alg
    A256GCMKW,
    /// PBES2 with HMAC SHA-256 and "A128KW" wrapping
    #[serde(rename = "PBES2-HS256+A128KW")]
    PBES2_HS256_A128KW,
    /// PBES2 with HMAC SHA-384 and "A192KW" wrapping
    #[serde(rename = "PBES2-HS384+A192KW")]
    PBES2_HS384_A192KW,
    /// PBES2 with HMAC SHA-512 and "A256KW" wrapping
    #[serde(rename = "PBES2-HS512+A256KW")]
    PBES2_HS512_A256KW,
}

/// Algorithms meant for content encryption.
/// See [RFC7518#5](https://tools.ietf.org/html/rfc7518#section-5)
#[derive(Debug, Eq, PartialEq, Copy, Clone, Serialize, Deserialize)]
#[allow(non_camel_case_types)]
pub enum ContentEncryptionAlgorithm {
    /// AES_128_CBC_HMAC_SHA_256 authenticated encryption algorithm	enc
    #[serde(rename = "A128CBC-HS256")]
    A128CBC_HS256,
    /// AES_192_CBC_HMAC_SHA_384 authenticated encryption algorithm	enc
    #[serde(rename = "A192CBC-HS384")]
    A192CBC_HS384,
    /// AES_256_CBC_HMAC_SHA_512 authenticated encryption algorithm	enc
    #[serde(rename = "A256CBC-HS512")]
    A256CBC_HS512,
    /// AES GCM using 128-bit key
    A128GCM,
    /// AES GCM using 192-bit key
    A192GCM,
    /// AES GCM using 256-bit key
    A256GCM,
}

impl Default for SignatureAlgorithm {
    fn default() -> Self {
        SignatureAlgorithm::HS256
    }
}

impl SignatureAlgorithm {
    /// Take some bytes and sign it according to the algorithm and secret provided.
    pub fn sign(&self, data: &[u8], secret: Secret) -> Result<Vec<u8>, Error> {
        use self::SignatureAlgorithm::*;

        match *self {
            None => Self::sign_none(secret),
            HS256 | HS384 | HS512 => Self::sign_hmac(data, secret, self),
            RS256 | RS384 | RS512 | PS256 | PS384 | PS512 => Self::sign_rsa(data, secret, self),
            ES256 | ES384 | ES512 => Self::sign_ecdsa(data, secret, self),
        }
    }

    /// Verify signature based on the algorithm and secret provided.
    pub fn verify(&self, expected_signature: &[u8], data: &[u8], secret: Secret) -> Result<bool, Error> {
        use self::SignatureAlgorithm::*;

        match *self {
            None => Self::verify_none(expected_signature, secret),
            HS256 | HS384 | HS512 => Self::verify_hmac(expected_signature, data, secret, self),
            RS256 | RS384 | RS512 | PS256 | PS384 | PS512 | ES256 | ES384 | ES512 => {
                Self::verify_public_key(expected_signature, data, secret, self)
            }
        }
    }

    /// Returns the type of operations the key is meant for

    fn sign_none(secret: Secret) -> Result<Vec<u8>, Error> {
        match secret {
            Secret::None => {}
            _ => Err("Invalid secret type. `None` should be provided".to_string())?,
        };
        Ok(vec![])
    }

    fn sign_hmac(data: &[u8], secret: Secret, algorithm: &SignatureAlgorithm) -> Result<Vec<u8>, Error> {
        let secret = match secret {
            Secret::Bytes(secret) => secret,
            _ => Err("Invalid secret type. A byte array is required".to_string())?,
        };

        let digest = match *algorithm {
            SignatureAlgorithm::HS256 => &digest::SHA256,
            SignatureAlgorithm::HS384 => &digest::SHA384,
            SignatureAlgorithm::HS512 => &digest::SHA512,
            _ => unreachable!("Should not happen"),
        };
        let key = hmac::SigningKey::new(digest, &secret);
        Ok(hmac::sign(&key, data).as_ref().to_vec())
    }

    fn sign_rsa(data: &[u8], secret: Secret, algorithm: &SignatureAlgorithm) -> Result<Vec<u8>, Error> {
        let key_pair = match secret {
            Secret::RSAKeyPair(key_pair) => key_pair,
            _ => Err("Invalid secret type. A RSAKeyPair is required".to_string())?,
        };
        let mut signing_state = signature::RSASigningState::new(key_pair)?;
        let rng = rand::SystemRandom::new();
        let mut signature = vec![0; signing_state.key_pair().public_modulus_len()];
        let padding_algorithm: &signature::RSAEncoding = match *algorithm {
            SignatureAlgorithm::RS256 => &signature::RSA_PKCS1_SHA256,
            SignatureAlgorithm::RS384 => &signature::RSA_PKCS1_SHA384,
            SignatureAlgorithm::RS512 => &signature::RSA_PKCS1_SHA512,
            SignatureAlgorithm::PS256 => &signature::RSA_PSS_SHA256,
            SignatureAlgorithm::PS384 => &signature::RSA_PSS_SHA384,
            SignatureAlgorithm::PS512 => &signature::RSA_PSS_SHA512,
            _ => unreachable!("Should not happen"),
        };
        signing_state.sign(padding_algorithm, &rng, data, &mut signature)?;
        Ok(signature)
    }

    fn sign_ecdsa(_data: &[u8], _secret: Secret, _algorithm: &SignatureAlgorithm) -> Result<Vec<u8>, Error> {
        // Not supported at the moment by ring
        // Tracking issues:
        //  - P-256: https://github.com/briansmith/ring/issues/207
        //  - P-384: https://github.com/briansmith/ring/issues/209
        //  - P-521: Probably never: https://github.com/briansmith/ring/issues/268
        Err(Error::UnsupportedOperation)
    }

    fn verify_none(expected_signature: &[u8], secret: Secret) -> Result<bool, Error> {
        match secret {
            Secret::None => {}
            _ => Err("Invalid secret type. `None` should be provided".to_string())?,
        };
        Ok(expected_signature.is_empty())
    }

    fn verify_hmac(expected_signature: &[u8],
                   data: &[u8],
                   secret: Secret,
                   algorithm: &SignatureAlgorithm)
                   -> Result<bool, Error> {
        let actual_signature = Self::sign_hmac(data, secret, algorithm)?;
        Ok(verify_slices_are_equal(expected_signature.as_ref(), actual_signature.as_ref()).is_ok())
    }

    fn verify_public_key(expected_signature: &[u8],
                         data: &[u8],
                         secret: Secret,
                         algorithm: &SignatureAlgorithm)
                         -> Result<bool, Error> {
        let public_key = match secret {
            Secret::PublicKey(public_key) => public_key,
            _ => Err("Invalid secret type. A PublicKey is required".to_string())?,
        };
        let public_key_der = untrusted::Input::from(public_key.as_slice());

        let verification_algorithm: &signature::VerificationAlgorithm = match *algorithm {
            SignatureAlgorithm::RS256 => &signature::RSA_PKCS1_2048_8192_SHA256,
            SignatureAlgorithm::RS384 => &signature::RSA_PKCS1_2048_8192_SHA384,
            SignatureAlgorithm::RS512 => &signature::RSA_PKCS1_2048_8192_SHA512,
            SignatureAlgorithm::PS256 => &signature::RSA_PSS_2048_8192_SHA256,
            SignatureAlgorithm::PS384 => &signature::RSA_PSS_2048_8192_SHA384,
            SignatureAlgorithm::PS512 => &signature::RSA_PSS_2048_8192_SHA512,
            SignatureAlgorithm::ES256 => &signature::ECDSA_P256_SHA256_ASN1,
            SignatureAlgorithm::ES384 => &signature::ECDSA_P384_SHA384_ASN1,
            SignatureAlgorithm::ES512 => Err(Error::UnsupportedOperation)?,
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
    use super::*;
    use CompactPart;

    #[test]
    fn sign_and_verify_none() {
        let expected_signature: Vec<u8> = vec![];
        let actual_signature = not_err!(SignatureAlgorithm::None.sign("payload".to_string().as_bytes(), Secret::None));
        assert_eq!(expected_signature, actual_signature);

        let valid = not_err!(SignatureAlgorithm::None.verify(vec![].as_slice(),
                                                             "payload".to_string().as_bytes(),
                                                             Secret::None));
        assert!(valid);
    }

    #[test]
    fn sign_and_verify_hs256() {
        let expected_base64 = "uC_LeRrOxXhZuYm0MKgmSIzi5Hn9-SMmvQoug3WkK6Q";
        let expected_bytes: Vec<u8> = not_err!(CompactPart::from_base64(expected_base64));

        let actual_signature =
            not_err!(SignatureAlgorithm::HS256.sign("payload".to_string().as_bytes(),
                                                                       Secret::bytes_from_str("secret")));
        assert_eq!(not_err!(actual_signature.to_base64()), expected_base64);

        let valid = not_err!(SignatureAlgorithm::HS256.verify(expected_bytes.as_slice(),
                                                              "payload".to_string().as_bytes(),
                                                              Secret::bytes_from_str("secret")));
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
        let private_key = Secret::rsa_keypair_from_file("test/fixtures/rsa_private_key.der").unwrap();
        let payload = "payload".to_string();
        let payload_bytes = payload.as_bytes();
        // This is standard base64
        let expected_signature = "JIHqiBfUknrFPDLT0gxyoufD06S43ZqWN_PzQqHZqQ-met7kZmkSTYB_rUyotLMxlKkuXdnvKmWm\
                                  dwGAHWEwDvb5392pCmAAtmUIl6LormxJptWYb2PoF5jmtX_lwV8y4RYIh54Ai51162VARQCKAsxL\
                                  uH772MEChkcpjd31NWzaePWoi_IIk11iqy6uFWmbLLwzD_Vbpl2C6aHR3vQjkXZi05gA3zksjYAh\
                                  j-m7GgBt0UFOE56A4USjhQwpb4g3NEamgp51_kZ2ULi4Aoo_KJC6ynIm_pR6rEzBgwZjlCUnE-6o\
                                  5RPQZ8Oau03UDVH2EwZe-Q91LaWRvkKjGg5Tcw";
        let expected_signature_bytes: Vec<u8> = not_err!(CompactPart::from_base64(expected_signature));

        let actual_signature = not_err!(SignatureAlgorithm::RS256.sign(payload_bytes, private_key));
        assert_eq!(not_err!(actual_signature.to_base64()), expected_signature);

        let public_key = Secret::public_key_from_file("test/fixtures/rsa_public_key.der").unwrap();
        let valid = not_err!(SignatureAlgorithm::RS256.verify(expected_signature_bytes.as_slice(),
                                                              payload_bytes,
                                                              public_key));
        assert!(valid);
    }

    /// This signature is non-deterministic.
    #[test]
    fn sign_and_verify_ps256_round_trip() {
        let private_key = Secret::rsa_keypair_from_file("test/fixtures/rsa_private_key.der").unwrap();
        let payload = "payload".to_string();
        let payload_bytes = payload.as_bytes();

        let actual_signature = not_err!(SignatureAlgorithm::PS256.sign(payload_bytes, private_key));

        let public_key = Secret::public_key_from_file("test/fixtures/rsa_public_key.der").unwrap();
        let valid = not_err!(SignatureAlgorithm::PS256.verify(actual_signature.as_slice(), payload_bytes, public_key));
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
        use data_encoding::base64;

        let payload = "payload".to_string();
        let payload_bytes = payload.as_bytes();
        let signature = "TiMXtt3Wmv/a/tbLWuJPDlFYMfuKsD7U5lbBUn2mBu8DLMLj1EplEZNmkB8w65BgUijnu9hxmhwv\
                         ET2k7RrsYamEst6BHZf20hIK1yE/YWaktbVmAZwUDdIpXYaZn8ukTsMT06CDrVk6RXF0EPMaSL33\
                         tFNPZpz4/3pYQdxco/n6DpaR5206wsur/8H0FwoyiFKanhqLb1SgZqyc+SXRPepjKc28wzBnfWl4\
                         mmlZcJ2xk8O2/t1Y1/m/4G7drBwOItNl7EadbMVCetYnc9EILv39hjcL9JvaA9q0M2RB75DIu8SF\
                         9Kr/l+wzUJjWAHthgqSBpe15jLkpO8tvqR89fw==";
        let signature_bytes: Vec<u8> = not_err!(base64::decode(signature.as_bytes()));
        let public_key = Secret::public_key_from_file("test/fixtures/rsa_public_key.der").unwrap();
        let valid = not_err!(SignatureAlgorithm::PS256.verify(signature_bytes.as_slice(), payload_bytes, public_key));
        assert!(valid);
    }

    #[test]
    #[should_panic(expected = "UnsupportedOperation")]
    fn sign_ecdsa() {
        let private_key = Secret::Bytes("secret".to_string().into_bytes()); // irrelevant
        let payload = "payload".to_string();
        let payload_bytes = payload.as_bytes();

        SignatureAlgorithm::ES256.sign(payload_bytes, private_key).unwrap();
    }

    /// Test case from https://github.com/briansmith/ring/blob/c5b8113/src/ec/suite_b/ecdsa_verify_tests.txt#L248
    #[test]
    fn verify_es256() {
        use data_encoding::hex;

        let payload = "sample".to_string();
        let payload_bytes = payload.as_bytes();
        let public_key = "0460FED4BA255A9D31C961EB74C6356D68C049B8923B61FA6CE669622E60F29FB67903FE1008B8BC99A41AE9E9562\
                          8BC64F2F1B20C2D7E9F5177A3C294D4462299";
        let public_key = Secret::PublicKey(not_err!(hex::decode(public_key.as_bytes())));
        let signature = "3046022100EFD48B2AACB6A8FD1140DD9CD45E81D69D2C877B56AAF991C34D0EA84EAF3716022100F7CB1C942D657C\
                         41D436C7A1B6E29F65F3E900DBB9AFF4064DC4AB2F843ACDA8";
        let signature_bytes: Vec<u8> = not_err!(hex::decode(signature.as_bytes()));
        let valid = not_err!(SignatureAlgorithm::ES256.verify(signature_bytes.as_slice(), payload_bytes, public_key));
        assert!(valid);
    }

    /// Test case from https://github.com/briansmith/ring/blob/c5b8113/src/ec/suite_b/ecdsa_verify_tests.txt#L283
    #[test]
    fn verify_es384() {
        use data_encoding::hex;

        let payload = "sample".to_string();
        let payload_bytes = payload.as_bytes();
        let public_key = "04EC3A4E415B4E19A4568618029F427FA5DA9A8BC4AE92E02E06AAE5286B300C64DEF8F0EA9055866064A25451548\
                          0BC138015D9B72D7D57244EA8EF9AC0C621896708A59367F9DFB9F54CA84B3F1C9DB1288B231C3AE0D4FE7344FD25\
                          33264720";
        let public_key = Secret::PublicKey(not_err!(hex::decode(public_key.as_bytes())));
        let signature = "306602310094EDBB92A5ECB8AAD4736E56C691916B3F88140666CE9FA73D64C4EA95AD133C81A648152E44ACF96E36\
                         DD1E80FABE4602310099EF4AEB15F178CEA1FE40DB2603138F130E740A19624526203B6351D0A3A94FA329C145786E\
                         679E7B82C71A38628AC8";
        let signature_bytes: Vec<u8> = not_err!(hex::decode(signature.as_bytes()));
        let valid = not_err!(SignatureAlgorithm::ES384.verify(signature_bytes.as_slice(), payload_bytes, public_key));
        assert!(valid);
    }

    #[test]
    #[should_panic(expected = "UnsupportedOperation")]
    fn verify_es512() {
        let payload: Vec<u8> = vec![];
        let signature: Vec<u8> = vec![];
        let public_key = Secret::PublicKey(vec![]);
        SignatureAlgorithm::ES512.verify(signature.as_slice(), payload.as_slice(), public_key).unwrap();
    }

    #[test]
    fn invalid_none() {
        let invalid_signature = "broken".to_string();
        let signature_bytes = invalid_signature.as_bytes();
        let valid = not_err!(SignatureAlgorithm::None.verify(signature_bytes,
                                                             "payload".to_string().as_bytes(),
                                                             Secret::None));
        assert!(!valid);
    }

    #[test]
    fn invalid_hs256() {
        let invalid_signature = "broken".to_string();
        let signature_bytes = invalid_signature.as_bytes();
        let valid =
            not_err!(SignatureAlgorithm::HS256.verify(signature_bytes,
                                                              "payload".to_string().as_bytes(),
                                                              Secret::Bytes("secret".to_string().into_bytes())));
        assert!(!valid);
    }

    #[test]
    fn invalid_rs256() {
        let public_key = Secret::public_key_from_file("test/fixtures/rsa_public_key.der").unwrap();
        let invalid_signature = "broken".to_string();
        let signature_bytes = invalid_signature.as_bytes();
        let valid = not_err!(SignatureAlgorithm::RS256.verify(signature_bytes,
                                                              "payload".to_string().as_bytes(),
                                                              public_key));
        assert!(!valid);
    }

    #[test]
    fn invalid_ps256() {
        let public_key = Secret::public_key_from_file("test/fixtures/rsa_public_key.der").unwrap();
        let invalid_signature = "broken".to_string();
        let signature_bytes = invalid_signature.as_bytes();
        let valid = not_err!(SignatureAlgorithm::PS256.verify(signature_bytes,
                                                              "payload".to_string().as_bytes(),
                                                              public_key));
        assert!(!valid);
    }

    #[test]
    fn invalid_es256() {
        let public_key = Secret::public_key_from_file("test/fixtures/rsa_public_key.der").unwrap();
        let invalid_signature = "broken".to_string();
        let signature_bytes = invalid_signature.as_bytes();
        let valid = not_err!(SignatureAlgorithm::ES256.verify(signature_bytes,
                                                              "payload".to_string().as_bytes(),
                                                              public_key));
        assert!(!valid);
    }
}
