//! [JSON Web Encryption](https://tools.ietf.org/html/rfc7516)
//!
//! This module contains code to implement JWE.
use std::fmt;

use serde::{self, Serialize, Deserialize, Serializer, Deserializer};
use serde_json;
use serde::de;

use {CompactJson, CompactPart, Empty};
use errors::{Error, ValidationError};
use jwa::{KeyManagementAlgorithm, ContentEncryptionAlgorithm, EncryptionResult};
use jwk;
use serde_custom;

#[derive(Debug, Eq, PartialEq, Clone)]
/// Compression algorithm applied to plaintext before encryption
pub enum CompressionAlgorithm {
    /// DEFLATE algorithm defined in [RFC 1951](https://tools.ietf.org/html/rfc1951)
    Deflate,
    /// Other user-defined algorithm
    Other(String),
}

impl Serialize for CompressionAlgorithm {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
        where S: Serializer
    {

        let string = match *self {
            CompressionAlgorithm::Deflate => "DEF",
            CompressionAlgorithm::Other(ref other) => other,
        };

        serializer.serialize_str(string)
    }
}

impl Deserialize for CompressionAlgorithm {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
        where D: Deserializer
    {

        struct CompressionAlgorithmVisitor;
        impl de::Visitor for CompressionAlgorithmVisitor {
            type Value = CompressionAlgorithm;

            fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                write!(formatter, "a string")
            }

            fn visit_str<E>(self, v: &str) -> Result<Self::Value, E>
                where E: de::Error
            {
                Ok(match v {
                       "DEF" => CompressionAlgorithm::Deflate,
                       other => CompressionAlgorithm::Other(other.to_string()),
                   })
            }
        }

        deserializer.deserialize_string(CompressionAlgorithmVisitor)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, Default)]
/// Registered JWE header fields.
/// The fields are defined by [RFC 7516#4.1](https://tools.ietf.org/html/rfc7516#section-4.1)
pub struct RegisteredHeader {
    /// Algorithm used to encrypt or determine the value of the Content Encryption Key
    #[serde(rename = "alg")]
    pub cek_algorithm: KeyManagementAlgorithm,

    /// Content encryption algorithm used to perform authenticated encryption
    /// on the plaintext to produce the ciphertext and the Authentication Tag
    #[serde(rename = "enc")]
    pub enc_algorithm: ContentEncryptionAlgorithm,

    /// Compression algorithm applied to plaintext before encryption, if any.
    /// Compression is not supported at the moment.
    /// _Must only appear in integrity protected header._
    #[serde(rename = "zip", skip_serializing_if = "Option::is_none")]
    pub compression_algorithm: Option<CompressionAlgorithm>,

    /// Media type of the complete JWE. Serialized to `typ`.
    /// Defined in [RFC7519#5.1](https://tools.ietf.org/html/rfc7519#section-5.1) and additionally
    /// [RFC7515#4.1.9](https://tools.ietf.org/html/rfc7515#section-4.1.9).
    #[serde(rename = "typ", skip_serializing_if = "Option::is_none")]
    pub media_type: Option<String>,

    /// Content Type of the secured content.
    /// Serialized to `cty`.
    /// Defined in [RFC7519#5.2](https://tools.ietf.org/html/rfc7519#section-5.2) and additionally
    /// [RFC7515#4.1.10](https://tools.ietf.org/html/rfc7515#section-4.1.10).
    #[serde(rename = "cty", skip_serializing_if = "Option::is_none")]
    pub content_type: Option<String>,

    /// The JSON Web Key Set URL. This is currently not implemented (correctly).
    /// Serialized to `jku`.
    /// Defined in [RFC7515#4.1.2](https://tools.ietf.org/html/rfc7515#section-4.1.2).
    #[serde(rename = "jku", skip_serializing_if = "Option::is_none")]
    pub web_key_url: Option<String>,

    /// The JSON Web Key. This is currently not implemented (correctly).
    /// Serialized to `jwk`.
    /// Defined in [RFC7515#4.1.3](https://tools.ietf.org/html/rfc7515#section-4.1.3).
    #[serde(rename = "jwk", skip_serializing_if = "Option::is_none")]
    pub web_key: Option<String>,

    /// The Key ID. This is currently not implemented (correctly).
    /// Serialized to `kid`.
    /// Defined in [RFC7515#4.1.3](https://tools.ietf.org/html/rfc7515#section-4.1.3).
    #[serde(rename = "kid", skip_serializing_if = "Option::is_none")]
    pub key_id: Option<String>,

    /// X.509 Public key cerfificate URL. This is currently not implemented (correctly).
    /// Serialized to `x5u`.
    /// Defined in [RFC7515#4.1.5](https://tools.ietf.org/html/rfc7515#section-4.1.5).
    #[serde(rename = "x5u", skip_serializing_if = "Option::is_none")]
    pub x509_url: Option<String>,

    /// X.509 public key certificate chain. This is currently not implemented (correctly).
    /// Serialized to `x5c`.
    /// Defined in [RFC7515#4.1.6](https://tools.ietf.org/html/rfc7515#section-4.1.6).
    #[serde(rename = "x5c", skip_serializing_if = "Option::is_none")]
    pub x509_chain: Option<Vec<String>>,

    /// X.509 Certificate thumbprint. This is currently not implemented (correctly).
    /// Also not implemented, is the SHA-256 thumbprint variant of this header.
    /// Serialized to `x5t`.
    /// Defined in [RFC7515#4.1.7](https://tools.ietf.org/html/rfc7515#section-4.1.7).
    // TODO: How to make sure the headers are mutually exclusive?
    #[serde(rename = "x5t", skip_serializing_if = "Option::is_none")]
    pub x509_fingerprint: Option<String>,

    /// List of critical extended headers.
    /// This is currently not implemented (correctly).
    /// Serialized to `crit`.
    /// Defined in [RFC7515#4.1.11](https://tools.ietf.org/html/rfc7515#section-4.1.11).
    #[serde(rename = "crit", skip_serializing_if = "Option::is_none")]
    pub critical: Option<Vec<String>>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, Default)]
/// Headers specific to the Key management algorithm used. Users should typically not construct these fields as they
/// will be filled in automatically when encrypting and stripped when decrypting
pub struct CekAlgorithmHeader {
    /// Header for AES GCM Keywrap algorithm.
    /// The initialization vector, or nonce used in the encryption
    #[serde(rename = "iv", skip_serializing_if = "Option::is_none")]
    pub nonce: Option<Vec<u8>>,

    /// Header for AES GCM Keywrap algorithm.
    /// The authentication tag resulting from the encryption
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tag: Option<Vec<u8>>,
}

/// JWE Header, consisting of the registered fields and other custom fields
#[derive(Debug, Eq, PartialEq, Clone, Default)]
pub struct Header<T: Serialize + Deserialize> {
    /// Registered header fields
    pub registered: RegisteredHeader,
    /// Key management algorithm specific headers
    pub cek_algorithm: CekAlgorithmHeader,
    /// Private header fields
    pub private: T,
}

impl_flatten_serde_generic!(Header<T>, serde_custom::flatten::DuplicateKeysBehaviour::RaiseError,
                            registered, cek_algorithm, private);

impl<T: Serialize + Deserialize + 'static> CompactJson for Header<T> {}

impl<T: Serialize + Deserialize + 'static> Header<T> {
    /// Update CEK algorithm specific header fields based on a CEK encryption result
    fn update_cek_algorithm(&mut self, encrypted: &EncryptionResult) {
        if encrypted.nonce.len() > 0 {
            self.cek_algorithm.nonce = Some(encrypted.nonce.clone());
        }

        if encrypted.tag.len() > 0 {
            self.cek_algorithm.tag = Some(encrypted.tag.clone());
        }
    }

    /// Extract the relevant fields from the header to build an `EncryptionResult` and strip them from the header
    fn extract_cek_encryption_result(&mut self, encrypted_payload: &[u8]) -> EncryptionResult {
        let result = EncryptionResult {
            encrypted: encrypted_payload.to_vec(),
            nonce: self.cek_algorithm.nonce.clone().unwrap_or_else(|| vec![]),
            tag: self.cek_algorithm.tag.clone().unwrap_or_else(|| vec![]),
            ..Default::default()
        };

        self.cek_algorithm = Default::default();
        result
    }
}

impl Header<Empty> {
    /// Convenience function to create a header with only registered headers
    pub fn from_registered_header(registered: RegisteredHeader) -> Self {
        Self {
            registered: registered,
            ..Default::default()
        }
    }
}

impl From<RegisteredHeader> for Header<Empty> {
    fn from(registered: RegisteredHeader) -> Self {
        Self::from_registered_header(registered)
    }
}

/// Compact representation of a JWE, or an encrypted JWT
///
/// This representation contains a payload of type `T` with custom headers provided by type `H`.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum Compact<T: CompactPart, H: Serialize + Deserialize + Clone + 'static> {
    /// Decrypted form of the JWE.
    /// This variant cannot be serialized or deserialized and will return an error.
    #[serde(skip_serializing)]
    #[serde(skip_deserializing)]
    Decrypted {
        /// Embedded header
        header: Header<H>,
        /// Payload, usually a signed/unsigned JWT
        payload: T,
    },
    /// Encrypted JWT. Use this form to send to your clients
    Encrypted(::Compact),
}

impl<T: CompactPart, H: Serialize + Deserialize + Clone + 'static> Compact<T, H> {
    /// Create a new encrypted JWE
    pub fn new_decrypted(header: Header<H>, payload: T) -> Self {
        Compact::Decrypted {
            header: header,
            payload: payload,
        }
    }

    /// Create a new encrypted JWE
    pub fn new_encrypted(token: &str) -> Self {
        Compact::Encrypted(::Compact::decode(token))
    }

    /// Consumes self and convert into encoded form. If the token is already encoded,
    /// this is a no-op.
    // TODO: Is the no-op dangerous? What if the secret between the previous encode and this time is different?
    pub fn into_encrypted<K: Serialize + Deserialize>(self, key: &jwk::JWK<K>) -> Result<Self, Error> {
        match self {
            Compact::Encrypted(_) => Ok(self),
            Compact::Decrypted { .. } => self.encrypt(key),
        }
    }

    /// Encrypt an Decrypted JWE
    pub fn encrypt<K: Serialize + Deserialize>(&self, key: &jwk::JWK<K>) -> Result<Self, Error> {
        match *self {
            Compact::Encrypted(_) => Err(Error::UnsupportedOperation),
            Compact::Decrypted {
                ref header,
                ref payload,
            } => {
                // RFC 7516 Section 5.1 describes the steps involved in encryption.
                // From steps 1 to 8, we will first determine the CEK, and then encrypt the CEK.
                let cek = header.registered
                    .cek_algorithm
                    .cek(header.registered.enc_algorithm, key)?;
                let encrypted_cek = header.registered
                    .cek_algorithm
                    .encrypt(cek.algorithm.octect_key()?, key)?;
                // Update header
                let mut header = header.clone();
                header.update_cek_algorithm(&encrypted_cek);

                // Steps 9 and 10 involves calculating an initialization vector (nonce) for content encryption. We do
                // this as part of the encryption process later

                // Step 11 involves compressing the payload, which we do not support at the moment
                let payload = payload.to_bytes()?;
                if let Some(_) = header.registered.compression_algorithm {
                    Err(Error::UnsupportedOperation)?
                }

                // Steps 12 to 14 involves the calculation of `Additional Authenticated Data` for encryption. In
                // our compact example, our header is the AAD.
                // Step 15 involves the actual encryption.
                let encrypted_payload = header.registered
                    .enc_algorithm
                    .encrypt(&payload, &header.to_bytes()?, &cek)?;

                // Finally create the JWE
                let mut compact = ::Compact::with_capacity(5);
                compact.push(&header)?;
                compact.push(&encrypted_cek.encrypted)?;
                compact.push(&encrypted_payload.nonce)?;
                compact.push(&encrypted_payload.encrypted)?;
                compact.push(&encrypted_payload.tag)?;

                Ok(Compact::Encrypted(compact))
            }
        }
    }

    /// Decrypt an encrypted JWE
    pub fn decrypt<K: Serialize + Deserialize>(&self,
                                               key: &jwk::JWK<K>,
                                               cek_alg: KeyManagementAlgorithm,
                                               enc_alg: ContentEncryptionAlgorithm)
                                               -> Result<Self, Error> {
        match *self {
            Compact::Encrypted(ref encrypted) => {
                if encrypted.len() != 5 {
                    Err(ValidationError::PartsLengthError {
                            actual: encrypted.len(),
                            expected: 5,
                        })?
                }
                // RFC 7516 Section 5.2 describes the steps involved in decryption.
                // Steps 1-3
                let mut header: Header<H> = encrypted.part(0)?;
                let encrypted_cek: Vec<u8> = encrypted.part(1)?;
                let nonce: Vec<u8> = encrypted.part(2)?;
                let encrypted_payload: Vec<u8> = encrypted.part(3)?;
                let tag: Vec<u8> = encrypted.part(4)?;

                // Verify that the algorithms are expected
                if header.registered.cek_algorithm != cek_alg || header.registered.enc_algorithm != enc_alg {
                    Err(Error::ValidationError(ValidationError::WrongAlgorithmHeader))?;
                }

                // TODO: Steps 4-5 not implemented at the moment.

                // Steps 6-13 involve the computation of the cek
                let cek_encryption_result = header.extract_cek_encryption_result(&encrypted_cek);
                let cek = header.registered
                    .cek_algorithm
                    .decrypt(&cek_encryption_result, header.registered.enc_algorithm, key)?;

                // Build encryption result as per steps 14-15
                let encrypted_payload_result = EncryptionResult {
                    nonce: nonce,
                    tag: tag,
                    encrypted: encrypted_payload,
                    additional_data: encrypted.part(0)?,
                };

                let payload = header.registered
                    .enc_algorithm
                    .decrypt(&encrypted_payload_result, &cek)?;

                // Decompression is not supported at the moment
                if let Some(_) = header.registered.compression_algorithm {
                    Err(Error::UnsupportedOperation)?
                }

                let payload = T::from_bytes(&payload)?;

                Ok(Compact::new_decrypted(header, payload))
            }
            Compact::Decrypted { .. } => Err(Error::UnsupportedOperation),
        }
    }

    /// Convenience method to extract the encrypted payload
    pub fn encrypted(&self) -> Result<String, Error> {
        match *self {
            Compact::Decrypted { .. } => Err(Error::UnsupportedOperation),
            Compact::Encrypted(ref encoded) => Ok(encoded.to_string()),
        }
    }

    /// Convenience method to extract the payload from an Decrypted JWE
    pub fn payload(&self) -> Result<&T, Error> {
        match *self {
            Compact::Decrypted { ref payload, .. } => Ok(payload),
            Compact::Encrypted(_) => Err(Error::UnsupportedOperation),
        }
    }

    /// Convenience method to extract the header from an Decrypted JWE
    pub fn header(&self) -> Result<&Header<H>, Error> {
        match *self {
            Compact::Decrypted { ref header, .. } => Ok(header),
            Compact::Encrypted(_) => Err(Error::UnsupportedOperation),
        }
    }
}

#[cfg(test)]
mod tests {
    use serde_test::{Token, assert_tokens};

    use super::*;
    use jwa::rng;
    use test::assert_serde_json;

    #[test]
    fn compression_algorithm_serde_token() {
        #[derive(Debug, Eq, PartialEq, Serialize, Deserialize)]
        struct Test {
            test: CompressionAlgorithm,
        }

        let test_value = Test { test: CompressionAlgorithm::Deflate };
        assert_tokens(&test_value,
                      &[Token::StructStart("Test", 1),
                        Token::StructSep,
                        Token::Str("test"),
                        Token::Str("DEF"),
                        Token::StructEnd]);

        let test_value = Test { test: CompressionAlgorithm::Other("xxx".to_string()) };
        assert_tokens(&test_value,
                      &[Token::StructStart("Test", 1),
                        Token::StructSep,
                        Token::Str("test"),
                        Token::Str("xxx"),
                        Token::StructEnd]);
    }

    #[test]
    fn compression_algorithm_json_serde() {
        #[derive(Debug, Eq, PartialEq, Serialize, Deserialize)]
        struct Test {
            test: CompressionAlgorithm,
        }

        let test_json = r#"{"test": "DEF"}"#;
        assert_serde_json(&Test { test: CompressionAlgorithm::Deflate },
                          Some(&test_json));

        let test_json = r#"{"test": "xxx"}"#;
        assert_serde_json(&Test { test: CompressionAlgorithm::Other("xxx".to_string()) },
                          Some(&test_json));
    }

    #[test]
    fn jwe_header_round_trips() {
        let test_value: Header<Empty> = From::from(RegisteredHeader {
                                                       cek_algorithm: KeyManagementAlgorithm::RSA_OAEP,
                                                       enc_algorithm: ContentEncryptionAlgorithm::A256GCM,
                                                       ..Default::default()
                                                   });
        let test_json = r#"{"alg":"RSA-OAEP","enc":"A256GCM"}"#;
        assert_serde_json(&test_value, Some(&test_json));

        let test_value: Header<Empty> = From::from(RegisteredHeader {
                                                       cek_algorithm: KeyManagementAlgorithm::RSA1_5,
                                                       enc_algorithm: ContentEncryptionAlgorithm::A128CBC_HS256,
                                                       ..Default::default()
                                                   });
        let test_json = r#"{"alg":"RSA1_5","enc":"A128CBC-HS256"}"#;
        assert_serde_json(&test_value, Some(&test_json));

        let test_value: Header<Empty> = From::from(RegisteredHeader {
                                                       cek_algorithm: KeyManagementAlgorithm::A128KW,
                                                       enc_algorithm: ContentEncryptionAlgorithm::A128CBC_HS256,
                                                       ..Default::default()
                                                   });
        let test_json = r#"{"alg":"A128KW","enc":"A128CBC-HS256"}"#;
        assert_serde_json(&test_value, Some(&test_json));
    }

    #[test]
    fn custom_jwe_header_round_trip() {
        #[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
        struct CustomHeader {
            something: String,
        }

        let test_value = Header {
            registered: RegisteredHeader {
                cek_algorithm: KeyManagementAlgorithm::RSA_OAEP,
                enc_algorithm: ContentEncryptionAlgorithm::A256GCM,
                ..Default::default()
            },
            cek_algorithm: Default::default(),
            private: CustomHeader { something: "foobar".to_string() },
        };
        let test_json = r#"{"alg":"RSA-OAEP","enc":"A256GCM","something":"foobar"}"#;
        assert_serde_json(&test_value, Some(&test_json));
    }

    #[test]
    fn jwe_aes256kw_aes256_gcm_round_trip() {
        let mut key: Vec<u8> = vec![0; 256/8];
        not_err!(rng().fill(&mut key));
        let key = jwk::JWK::<::Empty> {
            common: Default::default(),
            additional: Default::default(),
            algorithm: jwk::AlgorithmParameters::OctectKey {
                key_type: Default::default(),
                value: key,
            },
        };
        let payload = "The true sign of intelligence is not knowledge but imagination.";
        let jwe = Compact::new_decrypted(From::from(RegisteredHeader {
                                                        cek_algorithm: KeyManagementAlgorithm::A256GCMKW,
                                                        enc_algorithm: ContentEncryptionAlgorithm::A256GCM,
                                                        ..Default::default()
                                                    }),
                                         payload.as_bytes().to_vec());

        let encrypted_jwe = not_err!(jwe.encrypt(&key));

        let json = not_err!(serde_json::to_string(&encrypted_jwe));
        let deserialized_json: Compact<Vec<u8>, ::Empty> = not_err!(serde_json::from_str(&json));
        assert_eq!(deserialized_json, encrypted_jwe);

        let decrypted_jwe = not_err!(encrypted_jwe.decrypt(&key,
                                                           KeyManagementAlgorithm::A256GCMKW,
                                                           ContentEncryptionAlgorithm::A256GCM));
        assert_eq!(jwe, decrypted_jwe);
    }
}
