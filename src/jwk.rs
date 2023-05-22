//! JSON Web Key
//!
//! This module implements code for JWK as described in [RFC7517](https://tools.ietf.org/html/rfc7517).

use std::fmt;

use data_encoding::BASE64URL_NOPAD;
use num_bigint::BigUint;
use serde::de::{self, DeserializeOwned};
use serde::{self, Deserialize, Deserializer, Serialize, Serializer};

use crate::errors::Error;
use crate::jwa::Algorithm;
use crate::jws;
use crate::serde_custom;
use crate::Empty;

/// Type of Key as specified in RFC 7518.
#[derive(Debug, Eq, PartialEq, Serialize, Deserialize, Copy, Clone)]
pub enum KeyType {
    /// Elliptic curve (EC) key
    EllipticCurve,
    /// RSA key
    RSA,
    /// Octet symmetric key
    #[serde(rename = "oct")]
    Octet,
    /// Octet key pair
    #[serde(rename = "OKP")]
    OctetKeyPair,
}

impl KeyType {
    /// Description of the type of key
    pub fn description(self) -> &'static str {
        match self {
            KeyType::EllipticCurve => "Elliptic curve (EC) key",
            KeyType::RSA => "RSA key",
            KeyType::Octet => "Octet symmetric key",
            KeyType::OctetKeyPair => "Octet key pair",
        }
    }
}

impl fmt::Display for KeyType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.description())
    }
}

/// The intended usage of the public `KeyType`. This enum is serialized `untagged`
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum PublicKeyUse {
    /// Indicates a public key is meant for signature verification
    Signature,
    /// Indicates a public key is meant for encryption
    Encryption,
    /// Other usage
    Other(String),
}

impl Serialize for PublicKeyUse {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let string = match *self {
            PublicKeyUse::Signature => "sig",
            PublicKeyUse::Encryption => "enc",
            PublicKeyUse::Other(ref other) => other,
        };

        serializer.serialize_str(string)
    }
}

impl<'de> Deserialize<'de> for PublicKeyUse {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct PublicKeyUseVisitor;
        impl<'de> de::Visitor<'de> for PublicKeyUseVisitor {
            type Value = PublicKeyUse;

            fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                write!(formatter, "a string")
            }

            fn visit_str<E>(self, v: &str) -> Result<Self::Value, E>
            where
                E: de::Error,
            {
                Ok(match v {
                    "sig" => PublicKeyUse::Signature,
                    "enc" => PublicKeyUse::Encryption,
                    other => PublicKeyUse::Other(other.to_string()),
                })
            }
        }

        deserializer.deserialize_string(PublicKeyUseVisitor)
    }
}

/// Operations that the key is intended to be used for. This enum is serialized `untagged`
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum KeyOperations {
    /// Compute digital signature or MAC
    Sign,
    /// Verify digital signature or MAC
    Verify,
    /// Encrypt content
    Encrypt,
    /// Decrypt content and validate decryption, if applicable
    Decrypt,
    /// Encrypt key
    WrapKey,
    /// Decrypt key and validate decryption, if applicable
    UnwrapKey,
    /// Derive key
    DeriveKey,
    /// Derive bits not to be used as a key
    DeriveBits,
    /// Other operation
    Other(String),
}

impl Serialize for KeyOperations {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let string = match *self {
            KeyOperations::Sign => "sign",
            KeyOperations::Verify => "verify",
            KeyOperations::Encrypt => "encrypt",
            KeyOperations::Decrypt => "decrypt",
            KeyOperations::WrapKey => "wrapKey",
            KeyOperations::UnwrapKey => "unwrapKey",
            KeyOperations::DeriveKey => "deriveKey",
            KeyOperations::DeriveBits => "deriveBits",
            KeyOperations::Other(ref other) => other,
        };

        serializer.serialize_str(string)
    }
}

impl<'de> Deserialize<'de> for KeyOperations {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct KeyOperationsVisitor;
        impl<'de> de::Visitor<'de> for KeyOperationsVisitor {
            type Value = KeyOperations;

            fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                write!(formatter, "a string")
            }

            fn visit_str<E>(self, v: &str) -> Result<Self::Value, E>
            where
                E: de::Error,
            {
                Ok(match v {
                    "sign" => KeyOperations::Sign,
                    "verify" => KeyOperations::Verify,
                    "encrypt" => KeyOperations::Encrypt,
                    "decrypt" => KeyOperations::Decrypt,
                    "wrapKey" => KeyOperations::WrapKey,
                    "unwrapKey" => KeyOperations::UnwrapKey,
                    "deriveKey" => KeyOperations::DeriveKey,
                    "deriveBits" => KeyOperations::DeriveBits,
                    other => KeyOperations::Other(other.to_string()),
                })
            }
        }

        deserializer.deserialize_string(KeyOperationsVisitor)
    }
}

/// Common JWK parameters
#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize, Default)]
pub struct CommonParameters {
    /// The intended use of the public key. Should not be specified with `key_operations`.
    /// See sections 4.2 and 4.3 of [RFC7517](https://tools.ietf.org/html/rfc7517).
    #[serde(rename = "use", skip_serializing_if = "Option::is_none", default)]
    pub public_key_use: Option<PublicKeyUse>,

    /// The "key_ops" (key operations) parameter identifies the operation(s)
    /// for which the key is intended to be used.  The "key_ops" parameter is
    /// intended for use cases in which public, private, or symmetric keys
    /// may be present.
    /// Should not be specified with `public_key_use`.
    /// See sections 4.2 and 4.3 of [RFC7517](https://tools.ietf.org/html/rfc7517).
    #[serde(rename = "key_ops", skip_serializing_if = "Option::is_none", default)]
    pub key_operations: Option<Vec<KeyOperations>>,

    /// The algorithm intended for use with the key
    #[serde(rename = "alg", skip_serializing_if = "Option::is_none", default)]
    pub algorithm: Option<Algorithm>,

    /// The case sensitive Key ID for the key
    #[serde(rename = "kid", skip_serializing_if = "Option::is_none", default)]
    pub key_id: Option<String>,

    /// X.509 Public key cerfificate URL. This is currently not implemented (correctly).
    /// Serialized to `x5u`.
    #[serde(rename = "x5u", skip_serializing_if = "Option::is_none")]
    pub x509_url: Option<String>,

    /// X.509 public key certificate chain. This is currently not implemented (correctly).
    /// Serialized to `x5c`.
    #[serde(rename = "x5c", skip_serializing_if = "Option::is_none")]
    pub x509_chain: Option<Vec<String>>,

    /// X.509 Certificate thumbprint. This is currently not implemented (correctly).
    /// Also not implemented, is the SHA-256 thumbprint variant of this header.
    /// Serialized to `x5t`.
    // TODO: How to make sure the headers are mutually exclusive?
    #[serde(rename = "x5t", skip_serializing_if = "Option::is_none")]
    pub x509_fingerprint: Option<String>,
}

/// Algorithm specific parameters
#[derive(Clone, Eq, PartialEq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum AlgorithmParameters {
    /// Elliptic curve (EC) key
    EllipticCurve(EllipticCurveKeyParameters),

    /// RSA key
    RSA(RSAKeyParameters),

    /// Octet symmetric key
    OctetKey(OctetKeyParameters),

    /// Octet key pair
    OctetKeyPair(OctetKeyPairParameters),
}

impl fmt::Debug for AlgorithmParameters {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> Result<(), fmt::Error> {
        let algo_type = match *self {
            AlgorithmParameters::EllipticCurve(_) => "EllipticCurve",
            AlgorithmParameters::RSA(_) => "RSA",
            AlgorithmParameters::OctetKey(_) => "OctetKey",
            AlgorithmParameters::OctetKeyPair(_) => "OctetKeyPair",
        };
        write!(f, "{} {{ .. }}", algo_type)
    }
}

impl AlgorithmParameters {
    /// Returns the type of key represented by this set of algorithm parameters
    pub fn key_type(&self) -> KeyType {
        match *self {
            AlgorithmParameters::EllipticCurve(_) => KeyType::EllipticCurve,
            AlgorithmParameters::RSA(_) => KeyType::RSA,
            AlgorithmParameters::OctetKey(_) => KeyType::Octet,
            AlgorithmParameters::OctetKeyPair(_) => KeyType::OctetKeyPair,
        }
    }

    /// Return the byte sequence of an octet key
    pub fn octet_key(&self) -> Result<&[u8], Error> {
        match *self {
            AlgorithmParameters::OctetKey(ref oct) => Ok(oct.value.as_slice()),
            _ => Err(unexpected_key_type_error!(KeyType::Octet, self.key_type())),
        }
    }

    /// JWK thumbprints are digests for identifying key material.
    /// Their computation is specified in
    /// [RFC 7638](https://tools.ietf.org/html/rfc7638).
    ///
    /// This can be used to identify a public key; when the underlying digest algorithm
    /// is collision-resistant (currently, the SHA-2 family is provided), it is infeasible
    /// to build two keys sharing a thumbprint.
    ///
    /// As mentioned in the RFC's security considerations, it remains possible to build
    /// related keys with distinct parameters and thumbprints.
    ///
    /// ```
    /// // Example from https://tools.ietf.org/html/rfc7638#section-3.1
    /// let jwk: biscuit::jwk::JWK<biscuit::Empty> = serde_json::from_str(
    /// r#"{
    ///   "kty": "RSA",
    ///   "n": "0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw",
    ///   "e": "AQAB",
    ///   "alg": "RS256",
    ///   "kid": "2011-04-29"
    ///   }"#,
    /// ).unwrap();
    /// assert_eq!(
    ///   jwk.algorithm.thumbprint(&biscuit::digest::SHA256).unwrap(),
    ///   "NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs"
    /// );
    /// ```
    pub fn thumbprint(
        &self,
        algorithm: &'static crate::digest::Algorithm,
    ) -> Result<String, serde_json::error::Error> {
        use serde::ser::SerializeMap;

        use crate::serde_custom::{base64_url_uint, byte_sequence};

        let mut serializer = serde_json::Serializer::new(Vec::new());
        let mut map = serializer.serialize_map(None)?;
        // https://tools.ietf.org/html/rfc7638#section-3.2
        // Write required public key parameters in lexicographic order
        match self {
            AlgorithmParameters::EllipticCurve(params) => {
                map.serialize_entry("crv", &params.curve)?;
                map.serialize_entry("kty", &params.key_type)?;
                map.serialize_entry("x", &byte_sequence::wrap(&params.x))?;
                map.serialize_entry("y", &byte_sequence::wrap(&params.y))?;
            }
            AlgorithmParameters::RSA(params) => {
                map.serialize_entry("e", &base64_url_uint::wrap(&params.e))?;
                map.serialize_entry("kty", &params.key_type)?;
                map.serialize_entry("n", &base64_url_uint::wrap(&params.n))?;
            }
            AlgorithmParameters::OctetKey(params) => {
                map.serialize_entry("k", &byte_sequence::wrap(&params.value))?;
                map.serialize_entry("kty", &params.key_type)?;
            }
            AlgorithmParameters::OctetKeyPair(params) => {
                map.serialize_entry("crv", &params.curve)?;
                map.serialize_entry("kty", &params.key_type)?;
                map.serialize_entry("x", &byte_sequence::wrap(&params.x))?;
            }
        }
        map.end()?;
        let json_u8 = serializer.into_inner();
        Ok(BASE64URL_NOPAD.encode(ring::digest::digest(algorithm.0, &json_u8).as_ref()))
    }
}

/// Parameters for an Elliptic Curve Key
#[derive(Clone, Eq, PartialEq, Serialize, Deserialize, Default)]
pub struct EllipticCurveKeyParameters {
    /// Key type value for an Elliptic Curve Key.
    #[serde(rename = "kty")]
    pub key_type: EllipticCurveKeyType,
    /// The "crv" (curve) parameter identifies the cryptographic curve used
    /// with the key.
    #[serde(rename = "crv")]
    pub curve: EllipticCurve,
    /// The "x" (x coordinate) parameter contains the x coordinate for the
    /// Elliptic Curve point. Serialized to base64 URL encoded
    #[serde(with = "serde_custom::byte_sequence")]
    pub x: Vec<u8>,
    /// The "y" (y coordinate) parameter contains the y coordinate for the
    /// Elliptic Curve point. Serialized to base64 URL encoded
    #[serde(with = "serde_custom::byte_sequence")]
    pub y: Vec<u8>,
    /// The "d" (ECC private key) parameter contains the Elliptic Curve
    /// private key value.
    #[serde(
        with = "serde_custom::option_byte_sequence",
        skip_serializing_if = "Option::is_none",
        default
    )]
    pub d: Option<Vec<u8>>,
}

impl EllipticCurveKeyParameters {
    /// Construct a `jws::Secret` EC public key for signature verification
    pub fn jws_public_key_secret(&self) -> jws::Secret {
        let mut vec = Vec::with_capacity(self.x.len() + self.y.len() + 1);
        // to sec1 uncompressed
        vec.push(0x04);
        vec.extend(self.x.iter().copied());
        vec.extend(self.y.iter().copied());
        jws::Secret::PublicKey(vec)
    }
}

/// Parameters for a RSA Key
#[derive(Clone, Eq, PartialEq, Serialize, Deserialize, Default)]
pub struct RSAKeyParameters {
    /// Key type value for a RSA Key
    #[serde(rename = "kty")]
    pub key_type: RSAKeyType,

    /// The "n" (modulus) parameter contains the modulus value for the RSA
    /// public key.
    /// It is serialized as a `Base64urlUInt`-encoded value.
    #[serde(with = "serde_custom::base64_url_uint")]
    pub n: BigUint,

    /// The "e" (exponent) parameter contains the exponent value for the RSA
    /// public key.
    /// It is serialized as a `Base64urlUInt`-encoded value.
    #[serde(with = "serde_custom::base64_url_uint")]
    pub e: BigUint,

    /// The "d" (private exponent) parameter contains the private exponent
    /// value for the RSA private key.
    /// It is serialized as a `Base64urlUInt`-encoded value.
    #[serde(
        with = "serde_custom::option_base64_url_uint",
        skip_serializing_if = "Option::is_none",
        default
    )]
    pub d: Option<BigUint>,

    /// The "p" (first prime factor) parameter contains the first prime
    /// factor.
    /// It is serialized as a `Base64urlUInt`-encoded value.
    #[serde(
        with = "serde_custom::option_base64_url_uint",
        skip_serializing_if = "Option::is_none",
        default
    )]
    pub p: Option<BigUint>,

    /// The "q" (second prime factor) parameter contains the second prime
    /// factor.
    /// It is serialized as a `Base64urlUInt`-encoded value.
    #[serde(
        with = "serde_custom::option_base64_url_uint",
        skip_serializing_if = "Option::is_none",
        default
    )]
    pub q: Option<BigUint>,

    /// The "dp" (first factor CRT exponent) parameter contains the Chinese
    /// Remainder Theorem (CRT) exponent of the first factor.
    /// It is serialized as a `Base64urlUInt`-encoded value.
    #[serde(
        with = "serde_custom::option_base64_url_uint",
        skip_serializing_if = "Option::is_none",
        default
    )]
    pub dp: Option<BigUint>,

    /// The "dq" (second factor CRT exponent) parameter contains the CRT
    /// exponent of the second factor.
    /// It is serialized as a `Base64urlUInt`-encoded value.
    #[serde(
        with = "serde_custom::option_base64_url_uint",
        skip_serializing_if = "Option::is_none",
        default
    )]
    pub dq: Option<BigUint>,

    /// The "qi" (first CRT coefficient) parameter contains the CRT
    /// coefficient of the second factor
    /// It is serialized as a `Base64urlUInt`-encoded value.
    #[serde(
        with = "serde_custom::option_base64_url_uint",
        skip_serializing_if = "Option::is_none",
        default
    )]
    pub qi: Option<BigUint>,

    /// The "oth" (other primes info) parameter contains an array of
    /// information about any third and subsequent primes, should they exist.
    #[serde(rename = "oth", skip_serializing_if = "Option::is_none", default)]
    pub other_primes_info: Option<Vec<OtherPrimesInfo>>,
}

impl RSAKeyParameters {
    /// Construct a `jws::Secret` RSA public key for signature verification
    pub fn jws_public_key_secret(&self) -> jws::Secret {
        jws::Secret::RSAModulusExponent {
            n: self.n.clone(),
            e: self.e.clone(),
        }
    }
}

/// The "oth" (other primes info) parameter contains an array of
/// information about any third and subsequent primes, should they exist.
/// When only two primes have been used (the normal case), this parameter
/// MUST be omitted.  When three or more primes have been used, the
/// number of array elements MUST be the number of primes used minus two.
/// For more information on this case, see the description of the
/// `OtherPrimeInfo` parameters in [Appendix A.1.2 of RFC 3447](https://tools.ietf.org/html/rfc3447#appendix-A.1.2),
/// upon which the following parameters are modeled.  If the consumer of
/// a JWK does not support private keys with more than two primes and it
/// encounters a private key that includes the "oth" parameter, then it
/// MUST NOT use the key.
#[derive(Clone, Eq, PartialEq, Serialize, Deserialize)]
pub struct OtherPrimesInfo {
    /// The "r" (prime factor) parameter
    /// represents the value of a subsequent prime factor.
    /// It is serialized as a Base64urlUInt-encoded value.
    #[serde(with = "serde_custom::base64_url_uint")]
    pub r: BigUint,

    /// The "d" (factor CRT exponent) parameter
    /// represents the CRT exponent of the corresponding prime factor.
    /// It is serialized as a Base64urlUInt-encoded value.
    #[serde(with = "serde_custom::base64_url_uint")]
    pub d: BigUint,

    /// The "t" (factor CRT coefficient) parameter
    /// member represents the CRT coefficient of the corresponding prime
    /// factor.
    #[serde(with = "serde_custom::base64_url_uint")]
    pub t: BigUint,
}

/// Parameters for an Octet Key
#[derive(Clone, Eq, PartialEq, Serialize, Deserialize, Default)]
pub struct OctetKeyParameters {
    /// Key type value for an Octet Key
    #[serde(rename = "kty")]
    pub key_type: OctetKeyType,
    /// The octet key value
    #[serde(rename = "k", with = "serde_custom::byte_sequence")]
    pub value: Vec<u8>,
}

/// Parameters for an Octet Key Pair
#[derive(Clone, Eq, PartialEq, Serialize, Deserialize, Default)]
pub struct OctetKeyPairParameters {
    /// Key type value for an Octet Key Pair
    #[serde(rename = "kty")]
    pub key_type: OctetKeyPairType,
    /// The "crv" (curve) parameter identifies the cryptographic curve used
    /// with the key.
    #[serde(rename = "crv")]
    pub curve: EllipticCurve,
    /// The "x" parameter contains the base64 encoded public key
    #[serde(with = "serde_custom::byte_sequence")]
    pub x: Vec<u8>,
    /// The "d" parameter contains the base64 encoded private key
    #[serde(
        with = "serde_custom::option_byte_sequence",
        skip_serializing_if = "Option::is_none",
        default
    )]
    pub d: Option<Vec<u8>>,
}

/// Key type value for an Elliptic Curve Key.
/// This single value enum is a workaround for Rust not supporting associated constants.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize, Default)]
pub enum EllipticCurveKeyType {
    /// Key type value for an Elliptic Curve Key.
    #[default]
    EC,
}

/// Key type value for an RSA Key.
/// This single value enum is a workaround for Rust not supporting associated constants.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize, Default)]
pub enum RSAKeyType {
    /// Key type value for an RSA Key.
    #[default]
    RSA,
}

/// Key type value for an Octet symmetric key.
/// This single value enum is a workaround for Rust not supporting associated constants.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize, Default)]
pub enum OctetKeyType {
    /// Key type value for an Octet symmetric key.
    #[serde(rename = "oct")]
    #[default]
    Octet,
}

/// Key type value for an Octet Key Pair.
/// This single value enum is a workaround for Rust not supporting associated constants.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize, Default)]
pub enum OctetKeyPairType {
    /// Key type value for an Octet Key Pair.
    #[serde(rename = "OKP")]
    #[default]
    OctetKeyPair,
}

/// Type of cryptographic curve used by a key. This is defined in
/// [RFC 7518 #7.6](https://tools.ietf.org/html/rfc7518#section-7.6)
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, Default)]
pub enum EllipticCurve {
    /// P-256 curve
    #[serde(rename = "P-256")]
    #[default]
    P256,
    /// P-384 curve
    #[serde(rename = "P-384")]
    P384,
    /// P-521 curve -- unsupported by `ring`.
    #[serde(rename = "P-521")]
    P521,
    /// Curve25519
    #[serde(rename = "Ed25519")]
    Curve25519,
    /// Curve448
    #[serde(rename = "Ed448")]
    Curve448,
}

/// A JSON object that represents a cryptographic key.
/// The members of the object represent properties of the key, including its value.
/// Type `T` is a struct representing additional JWK properties
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct JWK<T> {
    /// Common JWK parameters
    #[serde(flatten)]
    pub common: CommonParameters,
    /// Key algorithm specific parameters
    #[serde(flatten)]
    pub algorithm: AlgorithmParameters,
    /// Additional JWK parameters
    #[serde(flatten)]
    pub additional: T,
}

impl<T: Serialize + DeserializeOwned> JWK<T> {
    /// Convenience to create a new bare-bones Octet key
    pub fn new_octet_key(key: &[u8], additional: T) -> Self {
        Self {
            algorithm: AlgorithmParameters::OctetKey(OctetKeyParameters {
                value: key.to_vec(),
                key_type: Default::default(),
            }),
            common: Default::default(),
            additional,
        }
    }

    /// Convenience function to strip out the additional fields
    pub fn clone_without_additional(&self) -> JWK<Empty> {
        JWK {
            common: self.common.clone(),
            algorithm: self.algorithm.clone(),
            additional: Default::default(),
        }
    }

    /// Returns the type of key represented by this key
    pub fn key_type(&self) -> KeyType {
        self.algorithm.key_type()
    }

    /// Return the byte sequence of an octet key
    pub fn octet_key(&self) -> Result<&[u8], Error> {
        self.algorithm.octet_key()
    }
}

/// A JSON object that represents a set of JWKs.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct JWKSet<T> {
    /// Contained JWKs
    pub keys: Vec<JWK<T>>,
}

impl<T> JWKSet<T> {
    /// Find the key in the set that matches the given key id, if any.
    pub fn find(&self, kid: &str) -> Option<&JWK<T>> {
        self.keys
            .iter()
            .find(|jwk| jwk.common.key_id.is_some() && jwk.common.key_id.as_ref().unwrap() == kid)
    }
}

#[cfg(test)]
#[allow(clippy::unreadable_literal)]
mod tests {
    use std::str;

    use serde_test::{assert_tokens, Token};

    use super::*;
    use crate::jwa;
    use crate::test::assert_serde_json;

    #[test]
    fn public_key_use_serde_token() {
        #[derive(Debug, Eq, PartialEq, Serialize, Deserialize)]
        struct Test {
            test: PublicKeyUse,
        }

        let test_value = Test {
            test: PublicKeyUse::Encryption,
        };
        assert_tokens(
            &test_value,
            &[
                Token::Struct {
                    name: "Test",
                    len: 1,
                },
                Token::Str("test"),
                Token::Str("enc"),
                Token::StructEnd,
            ],
        );

        let test_value = Test {
            test: PublicKeyUse::Encryption,
        };
        assert_tokens(
            &test_value,
            &[
                Token::Struct {
                    name: "Test",
                    len: 1,
                },
                Token::Str("test"),
                Token::Str("enc"),
                Token::StructEnd,
            ],
        );

        let test_value = Test {
            test: PublicKeyUse::Other("xxx".to_string()),
        };
        assert_tokens(
            &test_value,
            &[
                Token::Struct {
                    name: "Test",
                    len: 1,
                },
                Token::Str("test"),
                Token::Str("xxx"),
                Token::StructEnd,
            ],
        );
    }

    #[test]
    fn public_key_use_json_serde() {
        #[derive(Debug, Eq, PartialEq, Serialize, Deserialize)]
        struct Test {
            test: PublicKeyUse,
        }

        let test_json = r#"{"test": "enc"}"#;
        assert_serde_json(
            &Test {
                test: PublicKeyUse::Encryption,
            },
            Some(test_json),
        );

        let test_json = r#"{"test": "sig"}"#;
        assert_serde_json(
            &Test {
                test: PublicKeyUse::Signature,
            },
            Some(test_json),
        );

        let test_json = r#"{"test": "xxx"}"#;
        assert_serde_json(
            &Test {
                test: PublicKeyUse::Other("xxx".to_string()),
            },
            Some(test_json),
        );
    }

    #[test]
    fn key_operations_serde_token() {
        #[derive(Debug, Eq, PartialEq, Serialize, Deserialize)]
        struct Test {
            test: KeyOperations,
        }

        let test_value = Test {
            test: KeyOperations::Sign,
        };
        assert_tokens(
            &test_value,
            &[
                Token::Struct {
                    name: "Test",
                    len: 1,
                },
                Token::Str("test"),
                Token::Str("sign"),
                Token::StructEnd,
            ],
        );

        let test_value = Test {
            test: KeyOperations::Verify,
        };
        assert_tokens(
            &test_value,
            &[
                Token::Struct {
                    name: "Test",
                    len: 1,
                },
                Token::Str("test"),
                Token::Str("verify"),
                Token::StructEnd,
            ],
        );

        let test_value = Test {
            test: KeyOperations::Encrypt,
        };
        assert_tokens(
            &test_value,
            &[
                Token::Struct {
                    name: "Test",
                    len: 1,
                },
                Token::Str("test"),
                Token::Str("encrypt"),
                Token::StructEnd,
            ],
        );

        let test_value = Test {
            test: KeyOperations::Decrypt,
        };
        assert_tokens(
            &test_value,
            &[
                Token::Struct {
                    name: "Test",
                    len: 1,
                },
                Token::Str("test"),
                Token::Str("decrypt"),
                Token::StructEnd,
            ],
        );

        let test_value = Test {
            test: KeyOperations::WrapKey,
        };
        assert_tokens(
            &test_value,
            &[
                Token::Struct {
                    name: "Test",
                    len: 1,
                },
                Token::Str("test"),
                Token::Str("wrapKey"),
                Token::StructEnd,
            ],
        );

        let test_value = Test {
            test: KeyOperations::UnwrapKey,
        };
        assert_tokens(
            &test_value,
            &[
                Token::Struct {
                    name: "Test",
                    len: 1,
                },
                Token::Str("test"),
                Token::Str("unwrapKey"),
                Token::StructEnd,
            ],
        );

        let test_value = Test {
            test: KeyOperations::DeriveKey,
        };
        assert_tokens(
            &test_value,
            &[
                Token::Struct {
                    name: "Test",
                    len: 1,
                },
                Token::Str("test"),
                Token::Str("deriveKey"),
                Token::StructEnd,
            ],
        );

        let test_value = Test {
            test: KeyOperations::DeriveBits,
        };
        assert_tokens(
            &test_value,
            &[
                Token::Struct {
                    name: "Test",
                    len: 1,
                },
                Token::Str("test"),
                Token::Str("deriveBits"),
                Token::StructEnd,
            ],
        );

        let test_value = Test {
            test: KeyOperations::Other("xxx".to_string()),
        };
        assert_tokens(
            &test_value,
            &[
                Token::Struct {
                    name: "Test",
                    len: 1,
                },
                Token::Str("test"),
                Token::Str("xxx"),
                Token::StructEnd,
            ],
        );
    }

    #[test]
    fn key_operations_json_serde() {
        #[derive(Debug, Eq, PartialEq, Serialize, Deserialize)]
        struct Test {
            test: KeyOperations,
        }

        let test_json = r#"{"test": "sign"}"#;
        assert_serde_json(
            &Test {
                test: KeyOperations::Sign,
            },
            Some(test_json),
        );

        let test_json = r#"{"test": "verify"}"#;
        assert_serde_json(
            &Test {
                test: KeyOperations::Verify,
            },
            Some(test_json),
        );

        let test_json = r#"{"test": "encrypt"}"#;
        assert_serde_json(
            &Test {
                test: KeyOperations::Encrypt,
            },
            Some(test_json),
        );

        let test_json = r#"{"test": "decrypt"}"#;
        assert_serde_json(
            &Test {
                test: KeyOperations::Decrypt,
            },
            Some(test_json),
        );

        let test_json = r#"{"test": "wrapKey"}"#;
        assert_serde_json(
            &Test {
                test: KeyOperations::WrapKey,
            },
            Some(test_json),
        );

        let test_json = r#"{"test": "unwrapKey"}"#;
        assert_serde_json(
            &Test {
                test: KeyOperations::UnwrapKey,
            },
            Some(test_json),
        );

        let test_json = r#"{"test": "deriveKey"}"#;
        assert_serde_json(
            &Test {
                test: KeyOperations::DeriveKey,
            },
            Some(test_json),
        );

        let test_json = r#"{"test": "deriveBits"}"#;
        assert_serde_json(
            &Test {
                test: KeyOperations::DeriveBits,
            },
            Some(test_json),
        );

        let test_json = r#"{"test": "xxx"}"#;
        assert_serde_json(
            &Test {
                test: KeyOperations::Other("xxx".to_string()),
            },
            Some(test_json),
        );
    }

    /// Serialize and deserialize example JWK given in the RFC
    #[test]
    fn jwk_serde_smoke_test() {
        let test_value: JWK<Empty> = JWK {
            common: CommonParameters {
                key_id: Some("Public key used in JWS spec Appendix A.3 example".to_string()),
                ..Default::default()
            },
            algorithm: AlgorithmParameters::EllipticCurve(EllipticCurveKeyParameters {
                key_type: Default::default(),
                curve: EllipticCurve::P256,
                x: vec![
                    127, 205, 206, 39, 112, 246, 196, 93, 65, 131, 203, 238, 111, 219, 75, 123, 88,
                    7, 51, 53, 123, 233, 239, 19, 186, 207, 110, 60, 123, 209, 84, 69,
                ],
                y: vec![
                    199, 241, 68, 205, 27, 189, 155, 126, 135, 44, 223, 237, 185, 238, 185, 244,
                    179, 105, 93, 110, 169, 11, 36, 173, 138, 70, 35, 40, 133, 136, 229, 173,
                ],
                d: None,
            }),
            additional: Default::default(),
        };
        let expected_json = r#"{
  "kid": "Public key used in JWS spec Appendix A.3 example",
  "kty": "EC",
  "crv": "P-256",
  "x": "f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU",
  "y": "x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0"
}"#;

        assert_serde_json(&test_value, Some(expected_json));
    }

    /// rfc8037#appendix-A.1
    #[test]
    fn jwk_okp_private_key_json_serde() {
        let test_value: JWK<Empty> = JWK {
            common: CommonParameters::default(),
            algorithm: AlgorithmParameters::OctetKeyPair(OctetKeyPairParameters {
                key_type: Default::default(),
                curve: EllipticCurve::Curve25519,
                x: vec![
                    0xd7, 0x5a, 0x98, 0x01, 0x82, 0xb1, 0x0a, 0xb7, 0xd5, 0x4b, 0xfe, 0xd3, 0xc9,
                    0x64, 0x07, 0x3a, 0x0e, 0xe1, 0x72, 0xf3, 0xda, 0xa6, 0x23, 0x25, 0xaf, 0x02,
                    0x1a, 0x68, 0xf7, 0x07, 0x51, 0x1a,
                ],
                d: Some(vec![
                    0x9d, 0x61, 0xb1, 0x9d, 0xef, 0xfd, 0x5a, 0x60, 0xba, 0x84, 0x4a, 0xf4, 0x92,
                    0xec, 0x2c, 0xc4, 0x44, 0x49, 0xc5, 0x69, 0x7b, 0x32, 0x69, 0x19, 0x70, 0x3b,
                    0xac, 0x03, 0x1c, 0xae, 0x7f, 0x60,
                ]),
            }),
            additional: Default::default(),
        };
        let expected_json = r#"{
  "kty": "OKP",
  "crv": "Ed25519",
  "x": "11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo",
  "d": "nWGxne_9WmC6hEr0kuwsxERJxWl7MmkZcDusAxyuf2A"
}"#;

        assert_serde_json(&test_value, Some(expected_json));
    }

    /// rfc8037#appendix-A.2
    #[test]
    fn jwk_okp_public_key_json_serde() {
        let test_value: JWK<Empty> = JWK {
            common: CommonParameters::default(),
            algorithm: AlgorithmParameters::OctetKeyPair(OctetKeyPairParameters {
                key_type: Default::default(),
                curve: EllipticCurve::Curve25519,
                x: vec![
                    0xd7, 0x5a, 0x98, 0x01, 0x82, 0xb1, 0x0a, 0xb7, 0xd5, 0x4b, 0xfe, 0xd3, 0xc9,
                    0x64, 0x07, 0x3a, 0x0e, 0xe1, 0x72, 0xf3, 0xda, 0xa6, 0x23, 0x25, 0xaf, 0x02,
                    0x1a, 0x68, 0xf7, 0x07, 0x51, 0x1a,
                ],
                d: None,
            }),
            additional: Default::default(),
        };
        let expected_json = r#"{
  "kty": "OKP",
  "crv": "Ed25519",
  "x": "11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo"
}"#;

        assert_serde_json(&test_value, Some(expected_json));
    }

    #[test]
    fn jwk_set_symmetric_key() {
        let test_value: JWKSet<Empty> = JWKSet {
            keys: vec![
                JWK {
                    common: CommonParameters {
                        algorithm: Some(Algorithm::KeyManagement(
                            jwa::KeyManagementAlgorithm::A128KW,
                        )),
                        ..Default::default()
                    },
                    algorithm: AlgorithmParameters::OctetKey(OctetKeyParameters {
                        key_type: Default::default(),
                        value: vec![
                            25, 172, 32, 130, 225, 114, 26, 181, 138, 106, 254, 192, 95, 133, 74,
                            82,
                        ],
                    }),
                    additional: Default::default(),
                },
                JWK {
                    common: CommonParameters {
                        key_id: Some("HMAC key used in JWS spec Appendix A.1 example".to_string()),
                        ..Default::default()
                    },
                    algorithm: AlgorithmParameters::OctetKey(OctetKeyParameters {
                        key_type: Default::default(),
                        value: vec![
                            3, 35, 53, 75, 43, 15, 165, 188, 131, 126, 6, 101, 119, 123, 166, 143,
                            90, 179, 40, 230, 240, 84, 201, 40, 169, 15, 132, 178, 210, 80, 46,
                            191, 211, 251, 90, 146, 210, 6, 71, 239, 150, 138, 180, 195, 119, 98,
                            61, 34, 61, 46, 33, 114, 5, 46, 79, 8, 192, 205, 154, 245, 103, 208,
                            128, 163,
                        ],
                    }),
                    additional: Default::default(),
                },
            ],
        };

        let expected_json = r#"{"keys":
       [
         {"kty":"oct",
          "alg":"A128KW",
          "k":"GawgguFyGrWKav7AX4VKUg"},

         {"kty":"oct",
          "k":"AyM1SysPpbyDfgZld3umj1qzKObwVMkoqQ-EstJQLr_T-1qS0gZH75aKtMN3Yj0iPS4hcgUuTwjAzZr1Z9CAow",
          "kid":"HMAC key used in JWS spec Appendix A.1 example"}
       ]
     }"#;

        assert_serde_json(&test_value, Some(expected_json));
    }

    /// Example public key set
    #[test]
    fn jwk_set_public_key_serde_test() {
        let test_value: JWKSet<Empty> = JWKSet {
            keys: vec![
                JWK {
                    common: CommonParameters {
                        public_key_use: Some(PublicKeyUse::Encryption),
                        key_operations: None,
                        algorithm: None,
                        key_id: Some("1".to_string()),
                        ..Default::default()
                    },
                    algorithm: AlgorithmParameters::EllipticCurve(EllipticCurveKeyParameters {
                        key_type: Default::default(),
                        curve: EllipticCurve::P256,
                        x: vec![
                            48, 160, 66, 76, 210, 28, 41, 68, 131, 138, 45, 117, 201, 43, 55, 231,
                            110, 162, 13, 159, 0, 137, 58, 59, 78, 238, 138, 60, 10, 175, 236, 62,
                        ],
                        y: vec![
                            224, 75, 101, 233, 36, 86, 217, 136, 139, 82, 179, 121, 189, 251, 213,
                            30, 232, 105, 239, 31, 15, 198, 91, 102, 89, 105, 91, 108, 206, 8, 23,
                            35,
                        ],
                        d: None,
                    }),
                    additional: Default::default(),
                },
                JWK {
                    common: CommonParameters {
                        algorithm: Some(Algorithm::Signature(jwa::SignatureAlgorithm::RS256)),
                        key_id: Some("2011-04-29".to_string()),
                        ..Default::default()
                    },
                    algorithm: AlgorithmParameters::RSA(RSAKeyParameters {
                        key_type: Default::default(),
                        n: BigUint::new(vec![
                            2661337731, 446995658, 1209332140, 183172752, 955894533, 3140848734,
                            581365968, 3217299938, 3520742369, 1559833632, 1548159735, 2303031139,
                            1726816051, 92775838, 37272772, 1817499268, 2876656510, 1328166076,
                            2779910671, 4258539214, 2834014041, 3172137349, 4008354576, 121660540,
                            1941402830, 1620936445, 993798294, 47616683, 272681116, 983097263,
                            225284287, 3494334405, 4005126248, 1126447551, 2189379704, 4098746126,
                            3730484719, 3232696701, 2583545877, 428738419, 2533069420, 2922211325,
                            2227907999, 4154608099, 679827337, 1165541732, 2407118218, 3485541440,
                            799756961, 1854157941, 3062830172, 3270332715, 1431293619, 3068067851,
                            2238478449, 2704523019, 2826966453, 1548381401, 3719104923, 2605577849,
                            2293389158, 273345423, 169765991, 3539762026,
                        ]),
                        e: BigUint::new(vec![65537]),
                        ..Default::default()
                    }),
                    additional: Default::default(),
                },
            ],
        };

        let expected_json = include_str!("../test/fixtures/jwk_public_key.json");
        assert_serde_json(&test_value, Some(expected_json));
    }

    /// Example private key set
    #[test]
    fn jwk_set_private_key_serde_test() {
        let test_value: JWKSet<Empty> = JWKSet {
            keys: vec![
                JWK {
                    common: CommonParameters {
                        public_key_use: Some(PublicKeyUse::Encryption),
                        key_id: Some("1".to_string()),
                        ..Default::default()
                    },
                    algorithm: AlgorithmParameters::EllipticCurve(EllipticCurveKeyParameters {
                        key_type: Default::default(),
                        curve: EllipticCurve::P256,
                        x: vec![
                            48, 160, 66, 76, 210, 28, 41, 68, 131, 138, 45, 117, 201, 43, 55, 231,
                            110, 162, 13, 159, 0, 137, 58, 59, 78, 238, 138, 60, 10, 175, 236, 62,
                        ],
                        y: vec![
                            224, 75, 101, 233, 36, 86, 217, 136, 139, 82, 179, 121, 189, 251, 213,
                            30, 232, 105, 239, 31, 15, 198, 91, 102, 89, 105, 91, 108, 206, 8, 23,
                            35,
                        ],
                        d: Some(vec![
                            243, 189, 12, 7, 168, 31, 185, 50, 120, 30, 213, 39, 82, 246, 12, 200,
                            154, 107, 229, 229, 25, 52, 254, 1, 147, 141, 219, 85, 216, 247, 120,
                            1,
                        ]),
                    }),
                    additional: Default::default(),
                },
                JWK {
                    common: CommonParameters {
                        algorithm: Some(Algorithm::Signature(jwa::SignatureAlgorithm::RS256)),
                        key_id: Some("2011-04-29".to_string()),
                        ..Default::default()
                    },
                    algorithm: AlgorithmParameters::RSA(RSAKeyParameters {
                        n: BigUint::new(vec![
                            2661337731, 446995658, 1209332140, 183172752, 955894533, 3140848734,
                            581365968, 3217299938, 3520742369, 1559833632, 1548159735, 2303031139,
                            1726816051, 92775838, 37272772, 1817499268, 2876656510, 1328166076,
                            2779910671, 4258539214, 2834014041, 3172137349, 4008354576, 121660540,
                            1941402830, 1620936445, 993798294, 47616683, 272681116, 983097263,
                            225284287, 3494334405, 4005126248, 1126447551, 2189379704, 4098746126,
                            3730484719, 3232696701, 2583545877, 428738419, 2533069420, 2922211325,
                            2227907999, 4154608099, 679827337, 1165541732, 2407118218, 3485541440,
                            799756961, 1854157941, 3062830172, 3270332715, 1431293619, 3068067851,
                            2238478449, 2704523019, 2826966453, 1548381401, 3719104923, 2605577849,
                            2293389158, 273345423, 169765991, 3539762026,
                        ]),
                        e: BigUint::new(vec![65537]),
                        d: Some(BigUint::new(vec![
                            713032433, 400701404, 3861752269, 1672063644, 3365010676, 3983790198,
                            2118218649, 1180059196, 3214193513, 103331652, 3890363798, 149974729,
                            3621157035, 3968873060, 2871316584, 4055377082, 3404441811, 2991770705,
                            1288729501, 2747761153, 3336623437, 2364731106, 1645984872, 1574081430,
                            3820298762, 2596433775, 3693531604, 4039342668, 3035475437, 3285541752,
                            3070172669, 2361416509, 394294662, 2977738861, 2839890465, 841230222,
                            883615744, 114031047, 1313725071, 2810669078, 1097346134, 2647740217,
                            2124981186, 1406400018, 1957909244, 3961425321, 3596839919, 2973771986,
                            615724121, 3146071647, 471749184, 2647156653, 991511652, 3077695114,
                            748748083, 354410955, 2713339034, 932263697, 746803531, 2024924924,
                            1545546613, 4162159596, 3797483017, 1602687925,
                        ])),
                        p: Some(BigUint::new(vec![
                            1238724091, 318372667, 1355643853, 485701733, 3341746677, 1035832885,
                            3721261079, 425089171, 2054479354, 1436899400, 562311849, 4217170837,
                            2023494776, 842246473, 1670171010, 3629471803, 2613338008, 1336058667,
                            3907465950, 1278837722, 301706526, 1508904813, 84700477, 281588688,
                            1051290981, 4013685922, 1648080502, 3208306609, 3216888618, 207366948,
                            2345408890, 4084776684,
                        ])),
                        q: Some(BigUint::new(vec![
                            2896074521, 3807517807, 654326695, 805762229, 302497825, 3687241987,
                            3756840608, 1743610977, 2621828332, 419985079, 4047291779, 1029002427,
                            752954010, 2324424862, 3992768900, 1440975207, 2944332800, 1547302329,
                            661218096, 1997018012, 248893995, 1789089172, 2712859322, 2862464495,
                            3786711083, 2238161202, 1929865911, 3624669681, 347922466, 3024873892,
                            3610141359, 3721907783,
                        ])),
                        dp: Some(BigUint::new(vec![
                            1155663421, 4052197930, 2875421595, 3507788494, 2881675167, 838917555,
                            2601651989, 459386695, 3873213880, 2254232621, 4242124217, 15709214,
                            292087504, 1069982818, 1853923539, 1580521844, 4073993812, 2986647068,
                            2540273745, 2068123243, 2660839470, 2352030253, 323625625, 2640279336,
                            791777172, 531977105, 3029809343, 2356061851, 4159835023, 1928495702,
                            1195008431, 462098270,
                        ])),
                        dq: Some(BigUint::new(vec![
                            2218750473, 3313252599, 4264517421, 1492081333, 1067765483, 232198298,
                            2314112310, 1187650374, 3740239259, 1635257886, 1103093236, 2491201628,
                            718947546, 1371343186, 141466945, 37198959, 835764074, 2453692137,
                            970482580, 2037297103, 698337642, 4078896579, 3927675986, 897186496,
                            2305102129, 417341884, 917323172, 1302381423, 1775079932, 672472846,
                            3621814299, 3017359391,
                        ])),
                        qi: Some(BigUint::new(vec![
                            2822788373, 565097292, 169554874, 2338166229, 3171059040, 2497414769,
                            2887328684, 1224315260, 1462577079, 612121502, 660433863, 1066956358,
                            2410265369, 3691215764, 1134057558, 843539511, 694371854, 2599950644,
                            1558711302, 2053393907, 1148250800, 1108939089, 377893761, 1098804084,
                            1819782402, 3151682353, 3812854953, 1602843789, 369269593, 2731498344,
                            2724945700, 455294887,
                        ])),
                        ..Default::default()
                    }),
                    additional: Default::default(),
                },
            ],
        };

        let expected_json = include_str!("../test/fixtures/jwk_private_key.json");
        assert_serde_json(&test_value, Some(expected_json));
    }

    fn find_key_set() -> JWKSet<Empty> {
        JWKSet {
            keys: vec![
                JWK {
                    common: CommonParameters {
                        key_id: Some("first".to_string()),
                        ..Default::default()
                    },
                    algorithm: AlgorithmParameters::OctetKey(OctetKeyParameters {
                        key_type: Default::default(),
                        value: Default::default(),
                    }),
                    additional: Default::default(),
                },
                JWK {
                    common: CommonParameters {
                        key_id: Some("second".to_string()),
                        ..Default::default()
                    },
                    algorithm: AlgorithmParameters::OctetKey(OctetKeyParameters {
                        key_type: Default::default(),
                        value: Default::default(),
                    }),
                    additional: Default::default(),
                },
                JWK {
                    common: Default::default(),
                    algorithm: AlgorithmParameters::OctetKey(OctetKeyParameters {
                        key_type: Default::default(),
                        value: Default::default(),
                    }),
                    additional: Default::default(),
                },
            ],
        }
    }

    /// Example find success test
    #[test]
    fn jwk_set_find_some_test() {
        let keys = find_key_set();
        let key = keys.find("first").expect("Should have found key");
        let kid = key
            .common
            .key_id
            .as_ref()
            .expect("Key should have a key id");
        assert_eq!(kid, "first");
    }

    /// Example find fail test
    #[test]
    fn jwk_set_find_none_test() {
        let keys = find_key_set();
        assert_eq!(keys.find("third"), None);
    }

    #[test]
    fn jwk_ec_thumbprint() {
        let jwk: JWK<Empty> = serde_json::from_str(
            r#"{
                "alg":"ES256",
                "crv":"P-256",
                "key_ops":["sign","verify"],
                "kty":"EC",
                "x":"XAyWu1zgShU0q_C5EtiM4QuFfVqRo51J-4FdeBQVTXE",
                "y":"rvz9yHRaFcFn1vBIykwudyK85TEqR0OXOgBYnCeqN-M"
            }"#,
        )
        .unwrap();
        assert_eq!(
            jwk.algorithm.thumbprint(&crate::digest::SHA256).unwrap(),
            "5RQpPyszBq9VihghaQY1Ptj4OdOpQH7AIOOnngMEKrA"
        );
    }

    #[test]
    fn jwk_rsa_thumbprint() {
        // Example from https://tools.ietf.org/html/rfc7638#section-3.1
        let jwk: JWK<Empty> = serde_json::from_str(
            r#"{
            "kty": "RSA",
            "n": "0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw",
            "e": "AQAB",
            "alg": "RS256",
            "kid": "2011-04-29"
           }"#,
        )
        .unwrap();
        assert_eq!(
            jwk.algorithm.thumbprint(&crate::digest::SHA256).unwrap(),
            "NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs"
        );
    }

    #[test]
    fn jwk_rsa_thumbprint_normalization_gotcha() {
        // Modified from https://tools.ietf.org/html/rfc7638#section-3.1
        // to exemplify a gotcha from  https://tools.ietf.org/html/rfc7638#section-7
        let jwk: JWK<Empty> = serde_json::from_str(
            r#"{
            "kty": "RSA",
            "n": "0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw",
            "e": "AAEAAQ",
            "alg": "RS256",
            "kid": "2011-04-29"
           }"#,
        )
        .unwrap();
        assert_eq!(
            jwk.algorithm.thumbprint(&crate::digest::SHA256).unwrap(),
            "NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs"
        );
    }

    #[test]
    fn jwk_oct_thumbprint() {
        let jwk: JWK<Empty> = serde_json::from_str(
            r#"{
                "kty": "oct",
                "kid": "77c7e2b8-6e13-45cf-8672-617b5b45243a",
                "use": "enc",
                "alg": "A128GCM",
                "k": "XctOhJAkA-pD9Lh7ZgW_2A"
              }"#,
        )
        .unwrap();
        assert_eq!(
            jwk.algorithm.thumbprint(&crate::digest::SHA256).unwrap(),
            "svOLuZiKpi3RFmSHAcCJqsQqjBmWR4egaIsgk-2uBak"
        );
    }

    #[test]
    fn jwk_okp_thumbprint() {
        let jwk: JWK<Empty> = serde_json::from_str(
            r#"{
            "kty": "OKP",
            "crv": "Ed25519",
            "x": "11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo"
          }"#,
        )
        .unwrap();
        assert_eq!(
            jwk.algorithm.thumbprint(&crate::digest::SHA256).unwrap(),
            "kPrK_qmxVWaYVA9wwBF6Iuo3vVzz7TxHCTwXBygrS4k"
        );
    }
}
