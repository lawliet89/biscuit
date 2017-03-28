//! JSON Web Key
//!
//! This module implements code for JWK as described in [RFC7517](https://tools.ietf.org/html/rfc7517).
use std::default::Default;

use num::BigUint;
use serde::{Serialize, Deserialize};

use serde_custom;
use jwa::Algorithm;

/// Type of Key as specified in RFC 7518.
#[derive(Debug, Eq, PartialEq, Serialize, Deserialize)]
pub enum KeyType {
    ///  Elliptic curve keys
    EC,
    /// RSA Key
    RSA,
    /// Octet sequence, representing symmetric keys
    #[serde(rename = "oct")]
    Octect,
}

/// The intended usage of the public KeyType. This enum is serialized `untagged`
#[derive(Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum PublicKeyUse {
    /// Indicates a public key is meant for signature verification
    #[serde(rename = "sig")]
    Signature,
    /// Indicates a public key is meant for encryption
    #[serde(rename = "enc")]
    Encryption,
    /// Other usage
    Other(String),
}

/// Operations that the key is intended to be used for. This enum is serialized `untagged`
#[derive(Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum KeyOperations {
    /// Computer digitial signature or MAC
    #[serde(rename = "sign")]
    Sign,

    /// Verify digital signature or MAC
    #[serde(rename = "verify")]
    Verify,

    /// Encrypt content
    #[serde(rename = "encrypt")]
    Encrypt,

    /// Decrypt content and validate decryption, if applicable
    #[serde(rename = "decrypt")]
    Decrypt,

    /// Encrypt key
    #[serde(rename = "wrapKey")]
    WrapKey,

    /// Decrypt key and validate decryption, if applicable
    #[serde(rename = "unwrapKey")]
    UnwrapKey,

    /// Derive key
    #[serde(rename = "deriveKey")]
    DeriveKey,

    /// Derive bits not to be used as a key
    #[serde(rename = "deriveBits")]
    DeriveBits,

    /// Other operation
    Other(String),
}

/// A JSON object that represents a cryptographic key.
/// The members of the object represent properties of the key, including its value.
/// Type `T` is a struct representing additional JWK properties
#[derive(Debug, Eq, PartialEq)]
pub struct JWK<T: Serialize + Deserialize> {
    /// Common JWK parameters
    pub common: CommonParameters,
    /// Key algorithm specific parameters
    pub algorithm: AlgorithmParameters,
    /// Additional JWK parameters
    pub additional: T,
}

/// Common JWK parameters
#[derive(Debug, Eq, PartialEq, Serialize, Deserialize)]
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
#[derive(Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum AlgorithmParameters {
    /// An Elliptic Curve key
    EllipticCurve {
        /// Key type value for an Elliptic Curve Key.
        #[serde(rename = "kty")]
        key_type: EllipticCurveKeyType,
        /// The "crv" (curve) parameter identifies the cryptographic curve used
        /// with the key.
        #[serde(rename = "crv")]
        curve: EllipticCurve,
        /// The "x" (x coordinate) parameter contains the x coordinate for the
        /// Elliptic Curve point. Serialized to base64 URL encoded
        #[serde(with = "serde_custom::byte_sequence")]
        x: Vec<u8>,
        /// The "y" (y coordinate) parameter contains the y coordinate for the
        /// Elliptic Curve point. Serialized to base64 URL encoded
        #[serde(with = "serde_custom::byte_sequence")]
        y: Vec<u8>,
        /// The "d" (ECC private key) parameter contains the Elliptic Curve
        /// private key value.
        #[serde(with = "serde_custom::option_byte_sequence", skip_serializing_if = "Option::is_none", default)]
        d: Option<Vec<u8>>,
    },

    /// A RSA Public Key
    RSAPublicKey {
        /// Key type value for a RSA Key
        #[serde(rename = "kty")]
        key_type: RSAKeyType,

        /// The "n" (modulus) parameter contains the modulus value for the RSA
        /// public key.
        /// It is serialized as a `Base64urlUInt`-encoded value.
        #[serde(with = "serde_custom::base64_url_uint")]
        n: BigUint,

        /// The "e" (exponent) parameter contains the exponent value for the RSA
        /// public key.
        /// It is serialized as a `Base64urlUInt`-encoded value.
        #[serde(with = "serde_custom::base64_url_uint")]
        e: BigUint,
    },

    /// A RSA Private Key
    RSAPrivateKey {
        /// Key type value for a RSA Key
        #[serde(rename = "kty")]
        key_type: RSAKeyType,

        /// The "d" (private exponent) parameter contains the private exponent
        /// value for the RSA private key.
        /// It is serialized as a `Base64urlUInt`-encoded value.
        #[serde(with = "serde_custom::base64_url_uint")]
        d: BigUint,

        /// The "p" (first prime factor) parameter contains the first prime
        /// factor.
        /// It is serialized as a `Base64urlUInt`-encoded value.
        #[serde(with = "serde_custom::option_base64_url_uint")]
        p: Option<BigUint>,

        /// The "q" (second prime factor) parameter contains the second prime
        /// factor.
        /// It is serialized as a `Base64urlUInt`-encoded value.
        #[serde(with = "serde_custom::option_base64_url_uint")]
        q: Option<BigUint>,

        /// The "dp" (first factor CRT exponent) parameter contains the Chinese
        /// Remainder Theorem (CRT) exponent of the first factor.
        /// It is serialized as a `Base64urlUInt`-encoded value.
        #[serde(with = "serde_custom::option_base64_url_uint")]
        dp: Option<BigUint>,

        /// The "dq" (second factor CRT exponent) parameter contains the CRT
        /// exponent of the second factor.
        /// It is serialized as a `Base64urlUInt`-encoded value.
        #[serde(with = "serde_custom::option_base64_url_uint")]
        dq: Option<BigUint>,

        /// The "qi" (first CRT coefficient) parameter contains the CRT
        /// coefficient of the second factor
        /// It is serialized as a `Base64urlUInt`-encoded value.
        #[serde(with = "serde_custom::option_base64_url_uint")]
        qi: Option<BigUint>,

        /// The "oth" (other primes info) parameter contains an array of
        /// information about any third and subsequent primes, should they exist.
        #[serde(rename = "oth", skip_serializing_if = "Option::is_none")]
        other_primes_info: Option<Vec<OtherPrimesInfo>>,
    },

    /// A symmetric Octect key
    OctectKey {
        /// Key type value for an Octect Key
        #[serde(rename = "kty")]
        key_type: OctectKeyType,

        /// The octect key value
        #[serde(rename = "k", with = "serde_custom::byte_sequence")]
        value: Vec<u8>
    }
}

/// The "oth" (other primes info) parameter contains an array of
/// information about any third and subsequent primes, should they exist.
/// When only two primes have been used (the normal case), this parameter
/// MUST be omitted.  When three or more primes have been used, the
/// number of array elements MUST be the number of primes used minus two.
/// For more information on this case, see the description of the
/// OtherPrimeInfo parameters in [Appendix A.1.2 of RFC 3447](https://tools.ietf.org/html/rfc3447#appendix-A.1.2),
/// upon which the following parameters are modeled.  If the consumer of
/// a JWK does not support private keys with more than two primes and it
/// encounters a private key that includes the "oth" parameter, then it
/// MUST NOT use the key.
#[derive(Debug, Eq, PartialEq, Serialize, Deserialize)]
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

/// Key type value for an Elliptic Curve Key.
/// This single value enum is a workaround for Rust not supporting associated constants.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub enum EllipticCurveKeyType {
    /// Key type value for an Elliptic Curve Key.
    EC,
}

impl Default for EllipticCurveKeyType {
    fn default() -> Self {
        EllipticCurveKeyType::EC
    }
}

/// Key type value for an RSA Key.
/// This single value enum is a workaround for Rust not supporting associated constants.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub enum RSAKeyType {
    /// Key type value for an RSA Key.
    RSA,
}

impl Default for RSAKeyType {
    fn default() -> Self {
        RSAKeyType::RSA
    }
}

/// Key type value for an Octect symmetric Key.
/// This single value enum is a workaround for Rust not supporting associated constants.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub enum OctectKeyType {
    /// Key type value for an RSA Key.
    #[serde(rename = "oct")]
    Octect,
}

impl Default for OctectKeyType {
    fn default() -> Self {
        OctectKeyType::Octect
    }
}

/// Type of cryptographic curve used by a key. This is defined in
/// [RFC 7518 #7.6](https://tools.ietf.org/html/rfc7518#section-7.6)
#[derive(Debug, Eq, PartialEq, Serialize, Deserialize)]
pub enum EllipticCurve {
    /// P-256 curve
    #[serde(rename = "P-256")]
    P256,
    /// P-384 curve
    #[serde(rename = "P-384")]
    P384,
    /// P-521 curve -- unsupported by `ring`.
    #[serde(rename = "P-521")]
    P521,
}

/// A JSON object that represents a set of JWKs.
pub struct JWKSet<T: Serialize + Deserialize> {
    /// Containted JWKs
    keys: Vec<JWK<T>>,
}

// /// The type of key contained in this JWK
//     #[serde(rename = "kty")]
//     pub key_type: KeyType,
