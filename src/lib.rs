//! [![Build Status](https://travis-ci.org/lawliet89/biscuit.svg)](https://travis-ci.org/lawliet89/biscuit)
//! [![Crates.io](https://img.shields.io/crates/v/biscuit.svg)](https://crates.io/crates/biscuit)
//! [![Repository](https://img.shields.io/github/tag/lawliet89/biscuit.svg)](https://github.com/lawliet89/biscuit)
//! [![Documentation](https://docs.rs/biscuit/badge.svg)](https://docs.rs/biscuit)
//! [![dependency status](https://deps.rs/repo/github/lawliet89/biscuit/status.svg)](https://deps.rs/repo/github/lawliet89/biscuit)
//!
//! - Documentation:  [stable](https://docs.rs/biscuit/) | [master branch](https://lawliet89.github.io/biscuit)
//! - Changelog: [Link](https://github.com/lawliet89/biscuit/blob/master/CHANGELOG.md)
//!
//! A library to work with Javascript Object Signing and Encryption(JOSE),
//! including JSON Web Tokens (JWT), JSON Web Signature (JWS) and JSON Web Encryption (JWE)
//!
//! This was based off [`Keats/rust-jwt`](https://github.com/Keats/rust-jwt).
//!
//! ## Installation
//!
//! Add the following to Cargo.toml:
//!
//! ```toml
//! biscuit = "0.5.0"
//! ```
//!
//! To use the latest `master` branch, for example:
//!
//! ```toml
//! biscuit = { git = "https://github.com/lawliet89/biscuit", branch = "master" }
//! ```
//!
//! See [`JWT`] for common usage examples.
//!
//! ## Supported Features
//! The crate does not support all, and probably will never support all of
//! the features described in the various RFCs, including some algorithms and verification.
//!
//! See the [documentation](https://github.com/lawliet89/biscuit/blob/master/doc/supported.md) for more information.
//!
//! ## References
//! - [JWT Handbook](https://auth0.com/e-books/jwt-handbook) — great introduction to JWT
//! - [IANA JOSE Registry](https://www.iana.org/assignments/jose/jose.xhtml)
//!
//! ### RFCs
//! - [JSON Web Tokens RFC](https://tools.ietf.org/html/rfc7519)
//! - [JSON Web Signature RFC](https://tools.ietf.org/html/rfc7515)
//! - [JSON Web Algorithms RFC](https://tools.ietf.org/html/rfc7518)
//! - [JSON Web Encryption RFC](https://tools.ietf.org/html/rfc7516)
//! - [JSON Web Signature (JWS) Unencoded Payload Option](https://tools.ietf.org/html/rfc7797)
//! - [CFRG Elliptic Curve Diffie-Hellman (ECDH) and Signatures in JOSE](https://tools.ietf.org/html/rfc8037)
//! - [JWS Unencoded Payload Option](https://tools.ietf.org/html/rfc7797)
//! - [JWK Thumbprint](https://tools.ietf.org/html/rfc7638)

#![allow(
    missing_copy_implementations,
    missing_debug_implementations,
    unknown_lints,
    clippy::unknown_clippy_lints
)]
#![allow(clippy::try_err, clippy::needless_doctest_main)]
#![deny(
    const_err,
    dead_code,
    deprecated,
    exceeding_bitshifts,
    improper_ctypes,
    missing_docs,
    mutable_transmutes,
    no_mangle_const_items,
    non_camel_case_types,
    non_shorthand_field_patterns,
    non_upper_case_globals,
    overflowing_literals,
    path_statements,
    stable_features,
    trivial_casts,
    trivial_numeric_casts,
    unconditional_recursion,
    unknown_crate_types,
    unreachable_code,
    unused_allocation,
    unused_assignments,
    unused_attributes,
    unused_comparisons,
    unused_extern_crates,
    unused_features,
    unused_imports,
    unused_import_braces,
    unused_qualifications,
    unused_must_use,
    unused_mut,
    unused_parens,
    unused_results,
    unused_unsafe,
    unused_variables,
    variant_size_differences,
    warnings,
    while_true
)]
#![doc(test(attr(allow(unused_variables), deny(warnings))))]

use data_encoding;

use serde;
#[macro_use]
extern crate serde_derive;
use serde_json;

#[cfg(test)]
extern crate serde_test;

use std::borrow::Borrow;
use std::fmt::{self, Debug, Display};
use std::iter;
use std::ops::Deref;
use std::str::{self, FromStr};

use chrono::{DateTime, Duration, NaiveDateTime, Utc};
use data_encoding::BASE64URL_NOPAD;
use serde::de::{self, DeserializeOwned};
use serde::{Deserialize, Deserializer, Serialize, Serializer};

pub use url::{ParseError, Url};

mod helpers;
pub use crate::helpers::*;

#[cfg(test)]
#[macro_use]
mod test;

#[macro_use]
mod serde_custom;

#[macro_use]
mod macros;

pub mod errors;
pub mod jwa;
pub mod jwe;
pub mod jwk;
pub mod jws;

use crate::errors::{Error, ValidationError};

/// A convenience type alias of the common "JWT" which is a secured/unsecured compact JWS.
/// Type `T` is the type of the private claims, and type `H` is the type of private header fields
///
/// # Examples
/// ## Encoding and decoding with HS256
///
/// ```
/// extern crate biscuit;
/// #[macro_use]
/// extern crate serde_derive;
///
/// use std::str::FromStr;
/// use biscuit::*;
/// use biscuit::jws::*;
/// use biscuit::jwa::*;
///
/// # fn main() {
///
/// // Define our own private claims
/// #[derive(Debug, PartialEq, Clone, Serialize, Deserialize)]
/// struct PrivateClaims {
///     company: String,
///     department: String,
/// }
///
/// let signing_secret = Secret::Bytes("secret".to_string().into_bytes());
///
/// let expected_token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.\
///                         eyJpc3MiOiJodHRwczovL3d3dy5hY21lLmNv\
///                         bS8iLCJzdWIiOiJKb2huIERvZSIsImF1ZCI6I\
///                         mh0dHM6Ly9hY21lLWN1c3RvbWVyLmNvbS8iLC\
///                         JuYmYiOjEyMzQsImNvbXBhbnkiOiJBQ01FIiwi\
///                         ZGVwYXJ0bWVudCI6IlRvaWxldCBDbG\
///                         VhbmluZyJ9.dnx1OmRZSFxjCD1ivy4lveTT-sxay5Fq6vY6jnJvqeI";
///
/// let expected_claims = ClaimsSet::<PrivateClaims> {
///     registered: RegisteredClaims {
///         issuer: Some(FromStr::from_str("https://www.acme.com").unwrap()),
///         subject: Some(FromStr::from_str("John Doe").unwrap()),
///         audience:
///             Some(SingleOrMultiple::Single(FromStr::from_str("htts://acme-customer.com").unwrap())),
///         not_before: Some(1234.into()),
///         ..Default::default()
///     },
///     private: PrivateClaims {
///         department: "Toilet Cleaning".to_string(),
///         company: "ACME".to_string(),
///     },
/// };
///
/// let expected_jwt = JWT::new_decoded(From::from(
///                                         RegisteredHeader {
///                                             algorithm: SignatureAlgorithm::HS256,
///                                             ..Default::default()
///                                         }),
///                                     expected_claims.clone());
///
/// let token = expected_jwt
///     .into_encoded(&signing_secret).unwrap();
/// let token = token.unwrap_encoded().to_string();
/// assert_eq!(expected_token, token);
/// // Now, send `token` to your clients
///
/// // ... some time later, we get token back!
///
/// let token = JWT::<_, biscuit::Empty>::new_encoded(&token);
/// let token = token.into_decoded(&signing_secret,
///     SignatureAlgorithm::HS256).unwrap();
/// assert_eq!(*token.payload().unwrap(), expected_claims);
/// # }
/// ```
pub type JWT<T, H> = jws::Compact<ClaimsSet<T>, H>;

/// A convenience type alias of a "JWE" which is a compact JWE that contains a signed/unsigned compact JWS.
///
/// Type `T` is the type of private claims for the encapsulated JWT, and type `H` is the type of the private
/// header fields of the encapsulated JWT. Type `I` is the private header fields fo the encapsulating JWE.
///
/// Usually, you would set `H` and `I` to `biscuit::Empty` because you usually do not need any private header fields.
///
/// In general, you should [sign a JWT claims set, then encrypt it](http://crypto.stackexchange.com/a/5466),
/// although there is nothing stopping you from doing it the other way round.
///
/// # Examples
/// ## Sign with HS256, then encrypt with A256GCMKW and A256GCM
///
/// ```rust
/// extern crate biscuit;
/// extern crate num;
/// #[macro_use]
/// extern crate serde_derive;
///
/// use std::str::FromStr;
/// use biscuit::{ClaimsSet, RegisteredClaims, Empty, SingleOrMultiple, JWT, JWE};
/// use biscuit::jwk::JWK;
/// use biscuit::jws::{self, Secret};
/// use biscuit::jwe;
/// use biscuit::jwa::{EncryptionOptions, SignatureAlgorithm, KeyManagementAlgorithm,
///                    ContentEncryptionAlgorithm};
///
/// // Define our own private claims
/// #[derive(Debug, PartialEq, Clone, Serialize, Deserialize)]
/// struct PrivateClaims {
///     company: String,
///     department: String,
/// }
///
/// #[allow(unused_assignments)]
/// # fn main() {
/// // Craft our JWS
/// let expected_claims = ClaimsSet::<PrivateClaims> {
///     registered: RegisteredClaims {
///         issuer: Some(FromStr::from_str("https://www.acme.com").unwrap()),
///         subject: Some(FromStr::from_str("John Doe").unwrap()),
///         audience: Some(SingleOrMultiple::Single(
///             FromStr::from_str("htts://acme-customer.com").unwrap(),
///         )),
///         not_before: Some(1234.into()),
///         ..Default::default()
///     },
///     private: PrivateClaims {
///         department: "Toilet Cleaning".to_string(),
///         company: "ACME".to_string(),
///     },
/// };
///
/// let expected_jwt = JWT::new_decoded(
///     From::from(jws::RegisteredHeader {
///         algorithm: SignatureAlgorithm::HS256,
///         ..Default::default()
///     }),
///     expected_claims.clone(),
/// );
///
/// let jws = expected_jwt
///     .into_encoded(&Secret::Bytes("secret".to_string().into_bytes()))
///     .unwrap();
///
/// // Encrypt the token
///
/// // You would usually have your own AES key for this, but we will use a zeroed key as an example
/// let key: JWK<Empty> = JWK::new_octet_key(&vec![0; 256 / 8], Default::default());
///
/// // We need to create an `EncryptionOptions` with a nonce for AES GCM encryption.
/// // You must take care NOT to reuse the nonce. You can simply treat the nonce as a 96 bit
/// // counter that is incremented after every use
/// let mut nonce_counter = num::BigUint::from_bytes_le(&vec![0; 96 / 8]);
/// // Make sure it's no more than 96 bits!
/// assert!(nonce_counter.bits() <= 96);
/// let mut nonce_bytes = nonce_counter.to_bytes_le();
/// // We need to ensure it is exactly 96 bits
/// nonce_bytes.resize(96 / 8, 0);
/// let options = EncryptionOptions::AES_GCM { nonce: nonce_bytes };
///
/// // Construct the JWE
/// let jwe = JWE::new_decrypted(
///     From::from(jwe::RegisteredHeader {
///         cek_algorithm: KeyManagementAlgorithm::A256GCMKW,
///         enc_algorithm: ContentEncryptionAlgorithm::A256GCM,
///         media_type: Some("JOSE".to_string()),
///         content_type: Some("JOSE".to_string()),
///         ..Default::default()
///     }),
///     jws.clone(),
/// );
///
/// // Encrypt
/// let encrypted_jwe = jwe.encrypt(&key, &options).unwrap();
///
/// let token = encrypted_jwe.unwrap_encrypted().to_string();
///
/// // Now, send `token` to your clients
///
/// // ... some time later, we get token back!
/// let token: JWE<PrivateClaims, Empty, Empty> = JWE::new_encrypted(&token);
///
/// // Decrypt
/// let decrypted_jwe = token
///     .into_decrypted(
///         &key,
///         KeyManagementAlgorithm::A256GCMKW,
///         ContentEncryptionAlgorithm::A256GCM,
///     )
///     .unwrap();
///
/// let decrypted_jws = decrypted_jwe.payload().unwrap();
/// assert_eq!(jws, *decrypted_jws);
///
/// // Don't forget to increment the nonce!
/// nonce_counter = nonce_counter + 1u8;
/// # }
/// ```
pub type JWE<T, H, I> = jwe::Compact<JWT<T, H>, I>;

/// An empty struct that derives Serialize and Deserialize. Can be used, for example, in places where a type
/// for custom values (such as private claims in a `ClaimsSet`) is required but you have nothing to implement.
///
/// # Examples
/// ```
/// extern crate biscuit;
///
/// use std::str::FromStr;
/// use biscuit::*;
/// use biscuit::jws::*;
/// use biscuit::jwa::*;
///
/// # fn main() {
///
/// let claims_set = ClaimsSet::<biscuit::Empty> {
///     registered: RegisteredClaims {
///         issuer: Some(FromStr::from_str("https://www.acme.com").unwrap()),
///         subject: Some(FromStr::from_str("John Doe").unwrap()),
///         audience:
///             Some(SingleOrMultiple::Single(FromStr::from_str("htts://acme-customer.com").unwrap())),
///         not_before: Some(1234.into()),
///         ..Default::default()
///     },
///     private: Default::default(),
/// };
///
/// let expected_jwt = JWT::new_decoded(From::from(
///                                         RegisteredHeader {
///                                             algorithm: SignatureAlgorithm::HS256,
///                                             ..Default::default()
///                                     }),
///                                     claims_set);
///
/// # }
/// ```
#[derive(Debug, Eq, PartialEq, Clone, Copy, Serialize, Deserialize, Default)]
pub struct Empty {}

impl CompactJson for Empty {}

/// A "part" of the compact representation of JWT/JWS/JWE. Parts are first serialized to some form and then
/// base64 encoded and separated by periods.
///
/// An automatic implementation for any `T` that implements the marker trait `CompactJson` is provided.
/// This implementation will serialize/deserialize `T` to JSON via serde.
pub trait CompactPart {
    /// Convert this part into bytes
    fn to_bytes(&self) -> Result<Vec<u8>, Error>;

    /// Convert a sequence of bytes into Self
    fn from_bytes(bytes: &[u8]) -> Result<Self, Error>
    where
        Self: Sized;

    /// Base64 decode into Self
    fn from_base64<B: AsRef<[u8]>>(encoded: &B) -> Result<Self, Error>
    where
        Self: Sized,
    {
        let decoded = BASE64URL_NOPAD.decode(encoded.as_ref())?;
        Self::from_bytes(&decoded)
    }

    /// Serialize `Self` to some form and then base64URL Encode
    fn to_base64(&self) -> Result<Base64Url, Error> {
        let bytes = self.to_bytes()?;
        Ok(Base64Url(BASE64URL_NOPAD.encode(bytes.as_ref())))
    }
}

/// A marker trait that indicates that the object is to be serialized to JSON and deserialized from JSON.
/// This is primarily used in conjunction with the `CompactPart` trait which will serialize structs to JSON before
/// base64 encoding, and vice-versa.
pub trait CompactJson: Serialize + DeserializeOwned {}

impl<T> CompactPart for T
where
    T: CompactJson,
{
    /// JSON serialize the part and return the JSON string bytes
    fn to_bytes(&self) -> Result<Vec<u8>, Error> {
        Ok(serde_json::to_vec(&self)?)
    }

    fn from_bytes(bytes: &[u8]) -> Result<Self, Error> {
        Ok(serde_json::from_slice(bytes)?)
    }
}

impl CompactPart for Vec<u8> {
    fn to_bytes(&self) -> Result<Vec<u8>, Error> {
        Ok(self.clone())
    }

    /// Convert a sequence of bytes into Self
    fn from_bytes(bytes: &[u8]) -> Result<Self, Error> {
        Ok(bytes.to_vec())
    }
}

/// A newtype wrapper around a string to indicate it's base64 URL encoded
#[derive(Debug, Eq, PartialEq, Clone, Serialize, Deserialize)]
pub struct Base64Url(String);

impl Base64Url {
    /// Unwrap the embedded string, consuming self in the process
    pub fn unwrap(self) -> String {
        let Base64Url(string) = self;
        string
    }

    /// "Borrow" the string
    pub fn str(&self) -> &str {
        &self.0
    }
}

impl Deref for Base64Url {
    type Target = str;

    fn deref(&self) -> &str {
        &self.0
    }
}

impl FromStr for Base64Url {
    type Err = Error;

    /// This never fails
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(Base64Url(s.to_string()))
    }
}

impl Borrow<str> for Base64Url {
    fn borrow(&self) -> &str {
        self.str()
    }
}

impl CompactPart for Base64Url {
    fn to_bytes(&self) -> Result<Vec<u8>, Error> {
        Ok(BASE64URL_NOPAD.decode(self.as_ref())?)
    }

    /// Convert a sequence of bytes into Self
    fn from_bytes(bytes: &[u8]) -> Result<Self, Error> {
        let string = str::from_utf8(bytes)?;
        Ok(Base64Url(string.to_string()))
    }

    fn to_base64(&self) -> Result<Base64Url, Error> {
        Ok((*self).clone())
    }

    fn from_base64<B: AsRef<[u8]>>(encoded: &B) -> Result<Self, Error> {
        Self::from_bytes(encoded.as_ref())
    }
}

impl AsRef<[u8]> for Base64Url {
    fn as_ref(&self) -> &[u8] {
        self.0.as_ref()
    }
}

/// A collection of `CompactPart`s that have been converted to `Base64Url`
#[derive(Debug, Eq, PartialEq, Clone)]
pub struct Compact {
    /// Parts of the compact representation
    pub parts: Vec<Base64Url>,
}

impl Compact {
    /// Create an empty struct
    pub fn new() -> Self {
        Self { parts: vec![] }
    }

    /// Create an empty struct with some expected capacity
    pub fn with_capacity(capacity: usize) -> Self {
        Self {
            parts: Vec::with_capacity(capacity),
        }
    }

    /// Push a `CompactPart` to the end
    pub fn push(&mut self, part: &dyn CompactPart) -> Result<(), Error> {
        let base64 = part.to_base64()?;
        self.parts.push(base64);
        Ok(())
    }

    /// Returns the number of parts
    pub fn len(&self) -> usize {
        self.parts.len()
    }

    /// Returns whether there are no parts
    pub fn is_empty(&self) -> bool {
        self.parts.is_empty()
    }

    /// Encodes the various parts into Base64 URL encoding and then concatenates them with period '.'
    /// This corresponds to the various `Compact` representation in JWE and JWS, for example
    pub fn encode(&self) -> String {
        let strings: Vec<&str> = self.parts.iter().map(Deref::deref).collect();
        strings.join(".")
    }

    /// Convenience function to split an encoded compact representation into a list of `Base64Url`.
    pub fn decode(encoded: &str) -> Self {
        // Never fails
        let parts = encoded
            .split('.')
            .map(|s| FromStr::from_str(s).unwrap())
            .collect();
        Self { parts }
    }

    /// Convenience function to retrieve a part at a certain index and decode into the type desired
    pub fn part<T: CompactPart>(&self, index: usize) -> Result<T, Error> {
        let part = self
            .parts
            .get(index)
            .ok_or_else(|| "Out of bounds".to_string())?;
        CompactPart::from_base64(part)
    }
}

impl Default for Compact {
    fn default() -> Self {
        Compact::new()
    }
}

impl Display for Compact {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.encode())
    }
}

impl Serialize for Compact {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&self.encode())
    }
}

impl<'de> Deserialize<'de> for Compact {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct CompactVisitor;

        impl<'de> de::Visitor<'de> for CompactVisitor {
            type Value = Compact;

            fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str("a string containing a compact JOSE representation")
            }

            fn visit_str<E>(self, value: &str) -> Result<Self::Value, E>
            where
                E: de::Error,
            {
                Ok(Compact::decode(value))
            }
        }

        deserializer.deserialize_str(CompactVisitor)
    }
}

/// Represents a choice between a single value or multiple values.
/// This value is serialized by serde [untagged](https://serde.rs/enum-representations.html).
///
/// # Examples
/// ```
/// extern crate biscuit;
/// #[macro_use]
/// extern crate serde_derive;
/// extern crate serde_json;
///
/// use biscuit::SingleOrMultiple;
///
/// #[derive(Debug, Eq, PartialEq, Serialize, Deserialize)]
/// struct SingleOrMultipleStrings {
///     values: SingleOrMultiple<String>,
/// }
///
/// # fn main() {
/// let single = SingleOrMultipleStrings {
///     values: SingleOrMultiple::Single("foobar".to_string())
/// };
/// let expected_json = r#"{"values":"foobar"}"#;
///
/// let serialized = serde_json::to_string(&single).unwrap();
/// assert_eq!(expected_json, serialized);
///
/// let deserialized: SingleOrMultipleStrings = serde_json::from_str(&serialized).unwrap();
/// assert_eq!(deserialized, single);
///
/// let multiple = SingleOrMultipleStrings {
///     values: SingleOrMultiple::Multiple(vec!["foo".to_string(),
///                                             "bar".to_string(),
///                                             "baz".to_string()]),
/// };
///
/// let expected_json = r#"{"values":["foo","bar","baz"]}"#;
///
/// let serialized = serde_json::to_string(&multiple).unwrap();
/// assert_eq!(expected_json, serialized);
///
/// let deserialized: SingleOrMultipleStrings = serde_json::from_str(&serialized).unwrap();
/// assert_eq!(deserialized, multiple);
/// # }
/// ```
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum SingleOrMultiple<T> {
    /// One single value
    Single(T),
    /// Multiple values
    Multiple(Vec<T>),
}

impl<T> SingleOrMultiple<T>
where
    T: Clone + Debug + Eq + PartialEq + Serialize + DeserializeOwned + Send + Sync,
{
    /// Checks whether this enum, regardless of single or multiple value contains `value`.
    pub fn contains<Q: ?Sized>(&self, value: &Q) -> bool
    where
        T: Borrow<Q>,
        Q: PartialEq,
    {
        match *self {
            SingleOrMultiple::Single(ref single) => single.borrow() == value,
            SingleOrMultiple::Multiple(ref vector) => {
                vector.iter().map(Borrow::borrow).any(|v| v == value)
            }
        }
    }

    /// Yields an iterator for the single value or the list
    pub fn iter<'a>(&'a self) -> Box<dyn Iterator<Item = &'a T> + 'a> {
        match *self {
            SingleOrMultiple::Single(ref single) => Box::new(iter::once(single)),
            SingleOrMultiple::Multiple(ref vector) => Box::new(vector.iter()),
        }
    }
}
/// Represents a choice between a URI or an arbitrary string. Both variants will serialize to a string.
/// According to [RFC 7519](https://tools.ietf.org/html/rfc7519), any string containing the ":" character
/// will be deserialized as a URL. Any invalid URLs will be treated as a deserialization failure.
/// The URL is parsed according to the [URL Standard](https://url.spec.whatwg.org/) which supersedes
/// [RFC 3986](https://tools.ietf.org/html/rfc3986) as required in
/// the [JWT RFC](https://tools.ietf.org/html/rfc7519).
///
/// # Examples
/// ```
/// extern crate biscuit;
/// #[macro_use]
/// extern crate serde_derive;
/// extern crate serde_json;
///
/// use std::str::FromStr;
/// use biscuit::{SingleOrMultiple, StringOrUri};
///
/// #[derive(Debug, Eq, PartialEq, Serialize, Deserialize)]
/// struct SingleOrMultipleStringOrUris {
///     values: SingleOrMultiple<StringOrUri>,
/// }
///
/// # fn main() {
/// let multiple = SingleOrMultipleStringOrUris {
///     values: SingleOrMultiple::Multiple(vec![FromStr::from_str("foo").unwrap(),
///                                             FromStr::from_str("https://www.bar.com/").unwrap(),
///                                             FromStr::from_str("http://baz/").unwrap()]),
/// };
///
/// let expected_json = r#"{"values":["foo","https://www.bar.com/","http://baz/"]}"#;
///
/// let serialized = serde_json::to_string(&multiple).unwrap();
/// assert_eq!(expected_json, serialized);
///
/// let deserialized: SingleOrMultipleStringOrUris = serde_json::from_str(&serialized).unwrap();
/// assert_eq!(deserialized, multiple);
/// # }
/// ```
#[derive(Clone, Debug, Eq, PartialEq, Hash)]
#[allow(variant_size_differences)] // FIXME
pub enum StringOrUri {
    /// A generic string
    String(String),
    /// A parsed URI
    Uri(Url),
}

impl AsRef<str> for StringOrUri {
    fn as_ref(&self) -> &str {
        match *self {
            StringOrUri::String(ref string) => string.as_ref(),
            StringOrUri::Uri(ref uri) => uri.as_ref(),
        }
    }
}

impl FromStr for StringOrUri {
    type Err = Error;

    /// Parses a `&str` into a `StringOrUri`.
    /// According to [RFC 7519](https://tools.ietf.org/html/rfc7519), any string containing the ":" character
    /// will be treated as a URL. Any invalid URLs will be treated as failure.
    fn from_str(input: &str) -> Result<Self, Self::Err> {
        if input.contains(':') {
            let uri = Url::from_str(input)?;
            Ok(StringOrUri::Uri(uri))
        } else {
            Ok(StringOrUri::String(input.to_string()))
        }
    }
}

impl Serialize for StringOrUri {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(self.as_ref())
    }
}

impl<'de> Deserialize<'de> for StringOrUri {
    fn deserialize<D>(deserializer: D) -> Result<StringOrUri, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct StringOrUriVisitor {}

        impl<'de> de::Visitor<'de> for StringOrUriVisitor {
            type Value = StringOrUri;

            fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str("an arbitrary string or URI")
            }

            fn visit_str<E>(self, value: &str) -> Result<Self::Value, E>
            where
                E: de::Error,
            {
                StringOrUri::from_str(value).map_err(E::custom)
            }
        }

        deserializer.deserialize_str(StringOrUriVisitor {})
    }
}

impl Display for StringOrUri {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match *self {
            StringOrUri::String(ref string) => write!(f, "{}", string),
            StringOrUri::Uri(ref uri) => write!(f, "{}", uri),
        }
    }
}

/// Wrapper around `DateTime<Utc>` to allow us to do custom de(serialization)
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Timestamp(DateTime<Utc>);

impl Deref for Timestamp {
    type Target = DateTime<Utc>;
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl From<DateTime<Utc>> for Timestamp {
    fn from(datetime: DateTime<Utc>) -> Self {
        Timestamp(datetime)
    }
}

impl Into<DateTime<Utc>> for Timestamp {
    fn into(self) -> DateTime<Utc> {
        self.0
    }
}

impl From<i64> for Timestamp {
    fn from(timestamp: i64) -> Self {
        DateTime::<Utc>::from_utc(NaiveDateTime::from_timestamp(timestamp, 0), Utc).into()
    }
}

impl Serialize for Timestamp {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_i64(self.timestamp())
    }
}

impl<'de> Deserialize<'de> for Timestamp {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let timestamp = i64::deserialize(deserializer)?;
        Ok(Timestamp(DateTime::<Utc>::from_utc(
            NaiveDateTime::from_timestamp(timestamp, 0),
            Utc,
        )))
    }
}

/// Registered claims defined by [RFC7519#4.1](https://tools.ietf.org/html/rfc7519#section-4.1)
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, Default)]
pub struct RegisteredClaims {
    /// Token issuer. Serialized to `iss`.
    #[serde(rename = "iss", skip_serializing_if = "Option::is_none")]
    pub issuer: Option<StringOrUri>,

    /// Subject where the JWT is referring to. Serialized to `sub`
    #[serde(rename = "sub", skip_serializing_if = "Option::is_none")]
    pub subject: Option<StringOrUri>,

    /// Audience intended for the JWT. Serialized to `aud`
    #[serde(rename = "aud", skip_serializing_if = "Option::is_none")]
    pub audience: Option<SingleOrMultiple<StringOrUri>>,

    /// Expiration time in seconds since Unix Epoch. Serialized to `exp`
    #[serde(rename = "exp", skip_serializing_if = "Option::is_none")]
    pub expiry: Option<Timestamp>,

    /// Not before time in seconds since Unix Epoch. Serialized to `nbf`
    #[serde(rename = "nbf", skip_serializing_if = "Option::is_none")]
    pub not_before: Option<Timestamp>,

    /// Issued at Time in seconds since Unix Epoch. Serialized to `iat`
    #[serde(rename = "iat", skip_serializing_if = "Option::is_none")]
    pub issued_at: Option<Timestamp>,

    /// Application specific JWT ID. Serialized to `jti`
    #[serde(rename = "jti", skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
}

#[derive(Debug, Eq, PartialEq, Clone, Copy, Default)]
/// Options for claims presence validation
///
/// By default, no claims (namely `iat`, `exp`, `nbf`, `iss`, `aud`)
/// are required, and they pass validation if they are missing.
pub struct ClaimPresenceOptions {
    /// Whether the `iat` or `Issued At` field is required
    pub issued_at: Presence,
    /// Whether the `nbf` or `Not Before` field is required
    pub not_before: Presence,
    /// Whether the `exp` or `Expiry` field is required
    pub expiry: Presence,
    /// Whether the `iss` or `Issuer` field is required
    pub issuer: Presence,
    /// Whether the `aud` or `Audience` field is required
    pub audience: Presence,
    /// Whether the `sub` or `Subject` field is required
    pub subject: Presence,
    /// Whether the `jti` or `JWT ID` field is required
    pub id: Presence,
}

impl ClaimPresenceOptions {
    /// Returns a ClaimPresenceOptions where every claim is required as per [RFC7523](https://tools.ietf.org/html/rfc7523#section-3)
    pub fn strict() -> Self {
        use crate::Presence::*;
        ClaimPresenceOptions {
            issued_at: Required,
            not_before: Required,
            expiry: Required,
            issuer: Required,
            audience: Required,
            subject: Required,
            id: Required,
        }
    }
}

#[derive(Eq, PartialEq, Clone)]
/// Options for claims validation
///
/// If a claim is missing, it passes validation unless the claim is marked as required within the
/// `claim_presence_options`.
///
/// By default, no claims are required. If there are present, only expiry-related claims are validated
/// (namely `exp`, `nbf`, `iat`) with zero epsilon and maximum age duration.
///
/// Should any temporal claims be required, set the appropriate fields.
///
/// To deal with clock drifts, you might want to provide an `epsilon` error margin in the form of a
/// `std::time::Duration` to allow time comparisons to fall within the margin.
pub struct ValidationOptions {
    /// Claims marked as required will trigger a validation failure if they are missing
    pub claim_presence_options: ClaimPresenceOptions,

    /// Define how to validate temporal claims
    pub temporal_options: TemporalOptions,

    /// Validation options for `iat` or `Issued At` claim if present
    /// Parameter shows the maximum age of a token to be accepted,
    /// use [```Duration::max_value()```] if you do not want to skip validating
    /// the age of the token, and only validate it was not issued in the future
    pub issued_at: Validation<Duration>,
    /// Validation options for `nbf` or `Not Before` claim if present
    pub not_before: Validation<()>,
    /// Validation options for `exp` or `Expiry` claim if present
    pub expiry: Validation<()>,

    /// Validation options for `iss` or `Issuer` claim if present
    /// Parameter must match the issuer in the token exactly.
    pub issuer: Validation<StringOrUri>,

    /// Validation options for `aud` or `Audience` claim if present
    /// Token must include an audience with the value of the parameter
    pub audience: Validation<StringOrUri>,
}

impl Default for ValidationOptions {
    fn default() -> Self {
        ValidationOptions {
            expiry: Validation::Validate(()),
            not_before: Validation::Validate(()),
            issued_at: Validation::Validate(Duration::max_value()),

            claim_presence_options: Default::default(),
            temporal_options: Default::default(),
            audience: Default::default(),
            issuer: Default::default(),
        }
    }
}

impl RegisteredClaims {
    /// Validates that the token contains the claims defined as required
    pub fn validate_claim_presence(
        &self,
        options: ClaimPresenceOptions,
    ) -> Result<(), ValidationError> {
        use crate::Presence::Required;

        let mut missing_claims: Vec<&str> = vec![];

        if options.expiry == Required && self.expiry.is_none() {
            missing_claims.push("exp");
        }

        if options.not_before == Required && self.not_before.is_none() {
            missing_claims.push("nbf");
        }

        if options.issued_at == Required && self.issued_at.is_none() {
            missing_claims.push("iat");
        }

        if options.audience == Required && self.audience.is_none() {
            missing_claims.push("aud");
        }

        if options.issuer == Required && self.issuer.is_none() {
            missing_claims.push("iss");
        }

        if options.subject == Required && self.subject.is_none() {
            missing_claims.push("sub");
        }

        if options.id == Required && self.id.is_none() {
            missing_claims.push("jti");
        }

        if missing_claims.is_empty() {
            Ok(())
        } else {
            Err(ValidationError::MissingRequiredClaims(
                missing_claims.into_iter().map(|v| v.into()).collect(),
            ))
        }
    }

    /// Validates that if the token has an `exp` claim, it has not passed.
    pub fn validate_exp(
        &self,
        validation: Validation<TemporalOptions>,
    ) -> Result<(), ValidationError> {
        match validation {
            Validation::Ignored => Ok(()),
            Validation::Validate(temporal_options) => {
                let now = temporal_options.now.unwrap_or_else(Utc::now);

                match self.expiry {
                    Some(Timestamp(expiry)) if now - expiry > temporal_options.epsilon => {
                        Err(ValidationError::Expired(now - expiry))
                    }
                    _ => Ok(()),
                }
            }
        }
    }

    /// Validates that if the token has an `nbf` claim, it has passed.
    pub fn validate_nbf(
        &self,
        validation: Validation<TemporalOptions>,
    ) -> Result<(), ValidationError> {
        match validation {
            Validation::Ignored => Ok(()),
            Validation::Validate(temporal_options) => {
                let now = temporal_options.now.unwrap_or_else(Utc::now);

                match self.not_before {
                    Some(Timestamp(nbf)) if nbf - now > temporal_options.epsilon => {
                        Err(ValidationError::NotYetValid(nbf - now))
                    }
                    _ => Ok(()),
                }
            }
        }
    }

    /// Validates that if the token has an `iat` claim, it is not in the future and not older than the Duration
    pub fn validate_iat(
        &self,
        validation: Validation<(Duration, TemporalOptions)>,
    ) -> Result<(), ValidationError> {
        match validation {
            Validation::Ignored => Ok(()),
            Validation::Validate((max_age, temporal_options)) => {
                let now = temporal_options.now.unwrap_or_else(Utc::now);

                match self.issued_at {
                    Some(Timestamp(iat)) if iat - now > temporal_options.epsilon => {
                        Err(ValidationError::NotYetValid(iat - now))
                    }
                    Some(Timestamp(iat)) if now - iat > max_age - temporal_options.epsilon => {
                        Err(ValidationError::TooOld(now - iat - max_age))
                    }
                    _ => Ok(()),
                }
            }
        }
    }

    /// Validates that if the token has an `aud` claim, it contains an entry which matches the expected audience
    pub fn validate_aud(&self, validation: Validation<StringOrUri>) -> Result<(), ValidationError> {
        match validation {
            Validation::Ignored => Ok(()),
            Validation::Validate(expected_aud) => match self.audience {
                Some(SingleOrMultiple::Single(ref audience)) if audience != &expected_aud => Err(
                    ValidationError::InvalidAudience(self.audience.clone().unwrap()),
                ),
                Some(SingleOrMultiple::Multiple(ref audiences))
                    if !audiences.contains(&expected_aud) =>
                {
                    Err(ValidationError::InvalidAudience(
                        self.audience.clone().unwrap(),
                    ))
                }
                _ => Ok(()),
            },
        }
    }

    /// Validates that if the token has an `iss` claim, it matches the expected issuer
    pub fn validate_iss(&self, validation: Validation<StringOrUri>) -> Result<(), ValidationError> {
        match validation {
            Validation::Ignored => Ok(()),
            Validation::Validate(expected_issuer) => match self.issuer {
                Some(ref iss) if iss != &expected_issuer => {
                    Err(ValidationError::InvalidIssuer(self.issuer.clone().unwrap()))
                }
                _ => Ok(()),
            },
        }
    }

    /// Performs full validation of the token according to the `ValidationOptions` supplied
    ///
    /// First it validates that all claims marked as required are present
    /// Then it validates each claim marked to be validated if they are present in the token
    /// (even those that are not marked as required, but are present).
    pub fn validate(&self, options: ValidationOptions) -> Result<(), ValidationError> {
        self.validate_claim_presence(options.claim_presence_options)?;
        self.validate_exp(options.expiry.map(|_| options.temporal_options))?;
        self.validate_nbf(options.not_before.map(|_| options.temporal_options))?;
        self.validate_iat(options.issued_at.map(|dur| (dur, options.temporal_options)))?;

        self.validate_iss(options.issuer)?;
        self.validate_aud(options.audience)?;

        //        self.validate_sub(options.subject_validated)?;
        //        self.validate_custom(options.custom_validation)?;

        Ok(())
    }
}

/// A collection of claims, both [registered](https://tools.ietf.org/html/rfc7519#section-4.1) and your custom
/// private claims.
#[derive(Debug, Eq, PartialEq, Clone, Default, Serialize, Deserialize)]
pub struct ClaimsSet<T> {
    /// Registered claims defined by the RFC
    #[serde(flatten)]
    pub registered: RegisteredClaims,
    /// Application specific claims
    #[serde(flatten)]
    pub private: T,
}

impl<T> CompactJson for ClaimsSet<T> where T: Serialize + DeserializeOwned {}

#[cfg(test)]
mod tests {
    use std::str::{self, FromStr};

    use chrono::{Duration, TimeZone, Utc};
    use serde_json;
    use serde_test::{assert_tokens, Token};

    use super::*;

    #[derive(Debug, PartialEq, Clone, Serialize, Deserialize)]
    struct PrivateClaims {
        company: String,
        department: String,
    }

    impl CompactJson for PrivateClaims {}

    #[derive(Debug, PartialEq, Clone, Serialize, Deserialize)]
    struct InvalidPrivateClaim {
        sub: String,
        company: String,
    }

    #[derive(Debug, Eq, PartialEq, Serialize, Deserialize)]
    struct StringOrUriTest {
        string: StringOrUri,
    }

    #[derive(Debug, Eq, PartialEq, Serialize, Deserialize)]
    struct SingleOrMultipleStrings {
        values: SingleOrMultiple<String>,
    }

    #[derive(Debug, Eq, PartialEq, Serialize, Deserialize)]
    struct SingleOrMultipleStringOrUris {
        values: SingleOrMultiple<StringOrUri>,
    }

    #[test]
    fn string_or_uri_arbitrary_serialization_round_trip() {
        let test = StringOrUriTest {
            string: not_err!(FromStr::from_str("Random")),
        };
        assert_matches!(test, StringOrUriTest{ string: StringOrUri::String(_) });

        let expected_json = r#"{"string":"Random"}"#;
        let serialized = not_err!(serde_json::to_string(&test));
        assert_eq!(expected_json, serialized);

        let deserialized: StringOrUriTest = not_err!(serde_json::from_str(&serialized));
        assert_eq!(deserialized, test);

        assert_tokens(
            &test,
            &[
                Token::Struct {
                    name: "StringOrUriTest",
                    len: 1,
                },
                Token::Str("string"),
                Token::Str("Random"),
                Token::StructEnd,
            ],
        );
    }

    #[test]
    fn string_or_uri_uri_serialization_round_trip() {
        let test = StringOrUriTest {
            string: not_err!(FromStr::from_str("https://www.example.com/")),
        };
        assert_matches!(test, StringOrUriTest{ string: StringOrUri::Uri(_) });

        let expected_json = r#"{"string":"https://www.example.com/"}"#;
        let serialized = not_err!(serde_json::to_string(&test));
        assert_eq!(expected_json, serialized);

        let deserialized: StringOrUriTest = not_err!(serde_json::from_str(&serialized));
        assert_eq!(deserialized, test);

        assert_tokens(
            &test,
            &[
                Token::Struct {
                    name: "StringOrUriTest",
                    len: 1,
                },
                Token::Str("string"),
                Token::Str("https://www.example.com/"),
                Token::StructEnd,
            ],
        );
    }

    #[test]
    #[should_panic(expected = "UriParseError")]
    fn string_or_uri_will_fail_invalid_uris_containing_colons() {
        let _ = StringOrUriTest {
            string: FromStr::from_str("Invalid URI: yes!").unwrap(),
        };
    }

    #[test]
    fn single_string_serialization_round_trip() {
        let test = SingleOrMultipleStrings {
            values: SingleOrMultiple::Single("foobar".to_string()),
        };
        let expected_json = r#"{"values":"foobar"}"#;

        let serialized = not_err!(serde_json::to_string(&test));
        assert_eq!(expected_json, serialized);

        let deserialized: SingleOrMultipleStrings = not_err!(serde_json::from_str(&serialized));
        assert_eq!(deserialized, test);
        assert!(deserialized.values.contains("foobar"));
        assert!(!deserialized.values.contains("does not exist"));
    }

    #[test]
    fn multiple_strings_serialization_round_trip() {
        let test = SingleOrMultipleStrings {
            values: SingleOrMultiple::Multiple(vec![
                "foo".to_string(),
                "bar".to_string(),
                "baz".to_string(),
            ]),
        };
        let expected_json = r#"{"values":["foo","bar","baz"]}"#;

        let serialized = not_err!(serde_json::to_string(&test));
        assert_eq!(expected_json, serialized);

        let deserialized: SingleOrMultipleStrings = not_err!(serde_json::from_str(&serialized));
        assert_eq!(deserialized, test);
        assert!(deserialized.values.contains("foo"));
        assert!(deserialized.values.contains("bar"));
        assert!(deserialized.values.contains("baz"));
        assert!(!deserialized.values.contains("does not exist"));
    }

    #[test]
    fn single_string_or_uri_string_serialization_round_trip() {
        let test = SingleOrMultipleStringOrUris {
            values: SingleOrMultiple::Single(not_err!(FromStr::from_str("foobar"))),
        };
        let expected_json = r#"{"values":"foobar"}"#;

        let serialized = not_err!(serde_json::to_string(&test));
        assert_eq!(expected_json, serialized);

        let deserialized: SingleOrMultipleStringOrUris =
            not_err!(serde_json::from_str(&serialized));
        assert_eq!(deserialized, test);
        assert!(deserialized
            .values
            .contains(&FromStr::from_str("foobar").unwrap()));
        assert!(!deserialized
            .values
            .contains(&FromStr::from_str("does not exist").unwrap()));
    }

    #[test]
    fn single_string_or_uri_uri_serialization_round_trip() {
        let test = SingleOrMultipleStringOrUris {
            values: SingleOrMultiple::Single(not_err!(FromStr::from_str(
                "https://www.examples.com/"
            ))),
        };
        let expected_json = r#"{"values":"https://www.examples.com/"}"#;

        let serialized = not_err!(serde_json::to_string(&test));
        assert_eq!(expected_json, serialized);

        let deserialized: SingleOrMultipleStringOrUris =
            not_err!(serde_json::from_str(&serialized));
        assert_eq!(deserialized, test);
        assert!(deserialized
            .values
            .contains(&FromStr::from_str("https://www.examples.com").unwrap()));
        assert!(!deserialized
            .values
            .contains(&FromStr::from_str("https://ecorp.com").unwrap()));
    }

    #[test]
    fn multiple_string_or_uri_serialization_round_trip() {
        let test = SingleOrMultipleStringOrUris {
            values: SingleOrMultiple::Multiple(vec![
                not_err!(FromStr::from_str("foo")),
                not_err!(FromStr::from_str("https://www.example.com/")),
                not_err!(FromStr::from_str("data:text/plain,Hello?World#")),
                not_err!(FromStr::from_str("http://[::1]/")),
                not_err!(FromStr::from_str("baz")),
            ]),
        };
        let expected_json = r#"{"values":["foo","https://www.example.com/","data:text/plain,Hello?World#","http://[::1]/","baz"]}"#;

        let serialized = not_err!(serde_json::to_string(&test));
        assert_eq!(expected_json, serialized);

        let deserialized: SingleOrMultipleStringOrUris =
            not_err!(serde_json::from_str(&serialized));
        assert_eq!(deserialized, test);

        assert!(deserialized
            .values
            .contains(&FromStr::from_str("foo").unwrap()));
        assert!(deserialized
            .values
            .contains(&FromStr::from_str("https://www.example.com").unwrap()));
        assert!(deserialized
            .values
            .contains(&FromStr::from_str("data:text/plain,Hello?World#").unwrap()));
        assert!(deserialized
            .values
            .contains(&FromStr::from_str("http://[::1]").unwrap()));
        assert!(deserialized
            .values
            .contains(&FromStr::from_str("baz").unwrap()));
        assert!(!deserialized
            .values
            .contains(&FromStr::from_str("https://ecorp.com").unwrap()));
    }

    #[test]
    fn timestamp_serialization_roundtrip() {
        use chrono::Timelike;

        let now: Timestamp = Utc::now().with_nanosecond(0).unwrap().into();
        let serialized = not_err!(serde_json::to_string(&now));
        let deserialized = not_err!(serde_json::from_str(&serialized));
        assert_eq!(now, deserialized);

        let fixed_time: Timestamp = 1000.into();
        let serialized = not_err!(serde_json::to_string(&fixed_time));
        assert_eq!(serialized, "1000");
        let deserialized = not_err!(serde_json::from_str(&serialized));
        assert_eq!(fixed_time, deserialized);
    }

    #[test]
    fn empty_registered_claims_serialization_round_trip() {
        let claim = RegisteredClaims::default();
        let expected_json = "{}";

        let serialized = not_err!(serde_json::to_string(&claim));
        assert_eq!(expected_json, serialized);

        let deserialized: RegisteredClaims = not_err!(serde_json::from_str(&serialized));
        assert_eq!(deserialized, claim);
    }

    #[test]
    fn registered_claims_serialization_round_trip() {
        let claim = RegisteredClaims {
            issuer: Some(not_err!(FromStr::from_str("https://www.acme.com/"))),
            audience: Some(SingleOrMultiple::Single(not_err!(FromStr::from_str(
                "htts://acme-customer.com/"
            )))),
            not_before: Some(1234.into()),
            ..Default::default()
        };
        let expected_json =
            r#"{"iss":"https://www.acme.com/","aud":"htts://acme-customer.com/","nbf":1234}"#;

        let serialized = not_err!(serde_json::to_string(&claim));
        assert_eq!(expected_json, serialized);

        let deserialized: RegisteredClaims = not_err!(serde_json::from_str(&serialized));
        assert_eq!(deserialized, claim);
    }

    #[test]
    fn claims_set_serialization_round_trip() {
        let claim = ClaimsSet::<PrivateClaims> {
            registered: RegisteredClaims {
                issuer: Some(not_err!(FromStr::from_str("https://www.acme.com/"))),
                subject: Some(not_err!(FromStr::from_str("John Doe"))),
                audience: Some(SingleOrMultiple::Single(not_err!(FromStr::from_str(
                    "htts://acme-customer.com/"
                )))),
                not_before: Some(1234.into()),
                ..Default::default()
            },
            private: PrivateClaims {
                department: "Toilet Cleaning".to_string(),
                company: "ACME".to_string(),
            },
        };

        let expected_json = "{\"iss\":\"https://www.acme.com/\",\"sub\":\"John Doe\",\
                             \"aud\":\"htts://acme-customer.com/\",\
                             \"nbf\":1234,\"company\":\"ACME\",\"department\":\"Toilet Cleaning\"}";

        let serialized = not_err!(serde_json::to_string(&claim));
        assert_eq!(expected_json, serialized);

        let deserialized: ClaimsSet<PrivateClaims> = not_err!(serde_json::from_str(&serialized));
        assert_eq!(deserialized, claim);
    }

    #[test]
    // serde's flatten will serialize them twice
    fn duplicate_claims_round_trip() {
        let claim = ClaimsSet::<InvalidPrivateClaim> {
            registered: RegisteredClaims {
                issuer: Some(not_err!(FromStr::from_str("https://www.acme.com"))),
                subject: Some(not_err!(FromStr::from_str("John Doe"))),
                audience: Some(SingleOrMultiple::Single(not_err!(FromStr::from_str(
                    "htts://acme-customer.com"
                )))),
                not_before: Some(1234.into()),
                ..Default::default()
            },
            private: InvalidPrivateClaim {
                sub: "John Doe".to_string(),
                company: "ACME".to_string(),
            },
        };

        let json = serde_json::to_string(&claim).unwrap();
        assert_eq!(2, json.matches("\"sub\"").count());

        let duplicate: Result<ClaimsSet<InvalidPrivateClaim>, _> = serde_json::from_str(&json);
        assert!(duplicate.is_err());
        let error = duplicate.unwrap_err().to_string();
        assert!(error.contains("duplicate field `sub`"));
    }

    #[test]
    #[should_panic(expected = "MissingRequiredClaims([\"iat\"])")]
    fn validate_times_missing_iat() {
        let registered_claims: RegisteredClaims = Default::default();
        let options = ClaimPresenceOptions {
            issued_at: Presence::Required,
            ..Default::default()
        };
        registered_claims.validate_claim_presence(options).unwrap();
    }

    #[test]
    #[should_panic(expected = "MissingRequiredClaims([\"exp\"])")]
    fn validate_times_missing_exp() {
        let registered_claims: RegisteredClaims = Default::default();
        let options = ClaimPresenceOptions {
            expiry: Presence::Required,
            ..Default::default()
        };
        registered_claims.validate_claim_presence(options).unwrap();
    }

    #[test]
    #[should_panic(expected = "MissingRequiredClaims([\"nbf\"])")]
    fn validate_times_missing_nbf() {
        let registered_claims: RegisteredClaims = Default::default();
        let options = ClaimPresenceOptions {
            not_before: Presence::Required,
            ..Default::default()
        };
        registered_claims.validate_claim_presence(options).unwrap();
    }

    #[test]
    #[should_panic(expected = "MissingRequiredClaims([\"aud\"])")]
    fn validate_times_missing_aud() {
        let registered_claims: RegisteredClaims = Default::default();
        let options = ClaimPresenceOptions {
            audience: Presence::Required,
            ..Default::default()
        };
        registered_claims.validate_claim_presence(options).unwrap();
    }

    #[test]
    #[should_panic(expected = "MissingRequiredClaims([\"iss\"])")]
    fn validate_times_missing_iss() {
        let registered_claims: RegisteredClaims = Default::default();
        let options = ClaimPresenceOptions {
            issuer: Presence::Required,
            ..Default::default()
        };
        registered_claims.validate_claim_presence(options).unwrap();
    }

    #[test]
    #[should_panic(expected = "MissingRequiredClaims([\"sub\"])")]
    fn validate_times_missing_sub() {
        let registered_claims: RegisteredClaims = Default::default();
        let options = ClaimPresenceOptions {
            subject: Presence::Required,
            ..Default::default()
        };
        registered_claims.validate_claim_presence(options).unwrap();
    }

    #[test]
    #[should_panic(
        expected = "MissingRequiredClaims([\"exp\", \"nbf\", \"iat\", \"aud\", \"iss\", \"sub\", \"jti\"])"
    )]
    fn validate_times_missing_all() {
        let registered_claims: RegisteredClaims = Default::default();
        let options = ClaimPresenceOptions::strict();
        registered_claims.validate_claim_presence(options).unwrap();
    }

    #[test]
    fn validate_times_catch_future_token() {
        let temporal_options = TemporalOptions {
            now: Some(Utc.timestamp(0, 0)),
            ..Default::default()
        };

        let registered_claims = RegisteredClaims {
            issued_at: Some(10.into()),
            ..Default::default()
        };

        assert_eq!(
            Err(ValidationError::NotYetValid(Duration::seconds(10))),
            registered_claims.validate_iat(Validation::Validate((
                Duration::seconds(0),
                temporal_options
            )))
        );
    }

    #[test]
    fn validate_times_catch_too_old_token() {
        let temporal_options = TemporalOptions {
            now: Some(Utc.timestamp(40, 0)),
            ..Default::default()
        };

        let registered_claims = RegisteredClaims {
            issued_at: Some(10.into()),
            ..Default::default()
        };

        assert_eq!(
            Err(ValidationError::TooOld(Duration::seconds(5))),
            registered_claims.validate_iat(Validation::Validate((
                Duration::seconds(25),
                temporal_options
            )))
        );
    }

    #[test]
    fn validate_times_catch_expired_token() {
        let temporal_options = TemporalOptions {
            now: Some(Utc.timestamp(2, 0)),
            ..Default::default()
        };

        let registered_claims = RegisteredClaims {
            expiry: Some(1.into()),
            ..Default::default()
        };

        assert_eq!(
            Err(ValidationError::Expired(Duration::seconds(1))),
            registered_claims.validate_exp(Validation::Validate(temporal_options))
        );
    }

    #[test]
    fn validate_times_catch_early_token() {
        let temporal_options = TemporalOptions {
            now: Some(Utc.timestamp(0, 0)),
            ..Default::default()
        };

        let registered_claims = RegisteredClaims {
            not_before: Some(1.into()),
            ..Default::default()
        };

        assert_eq!(
            Err(ValidationError::NotYetValid(Duration::seconds(1))),
            registered_claims.validate_nbf(Validation::Validate(temporal_options))
        );
    }

    #[test]
    fn validate_times_valid_token_with_default_options() {
        let registered_claims = RegisteredClaims {
            not_before: Some(Timestamp(Utc::now() - Duration::days(2))),
            issued_at: Some(Timestamp(Utc::now() - Duration::days(1))),
            expiry: Some(Timestamp(Utc::now() + Duration::days(1))),
            ..Default::default()
        };

        let validation_options = ValidationOptions {
            temporal_options: Default::default(),
            claim_presence_options: Default::default(),

            expiry: Validation::Validate(()),
            not_before: Validation::Validate(()),
            issued_at: Validation::Validate(Duration::max_value()),

            ..Default::default()
        };

        not_err!(registered_claims.validate(validation_options));
    }

    #[test]
    fn validate_issuer_catch_mismatch() {
        let registered_claims = RegisteredClaims {
            issuer: Some(StringOrUri::String("issuer".into())),
            ..Default::default()
        };

        assert_eq!(
            Err(ValidationError::InvalidIssuer(StringOrUri::String(
                "issuer".into()
            ))),
            registered_claims.validate_iss(Validation::Validate(StringOrUri::Uri(
                Url::parse("http://issuer").unwrap()
            )))
        );
    }

    #[test]
    fn validate_audience_when_single() {
        let aud = SingleOrMultiple::Single(StringOrUri::String("audience".into()));

        let registered_claims = RegisteredClaims {
            audience: Some(aud.clone()),
            ..Default::default()
        };

        assert_eq!(
            Err(ValidationError::InvalidAudience(aud.clone())),
            registered_claims.validate_aud(Validation::Validate(StringOrUri::Uri(
                Url::parse("http://audience").unwrap()
            )))
        );

        assert_eq!(
            Err(ValidationError::InvalidAudience(aud)),
            registered_claims.validate_aud(Validation::Validate(StringOrUri::String(
                "audience2".into()
            )))
        );

        assert_eq!(
            Ok(()),
            registered_claims
                .validate_aud(Validation::Validate(StringOrUri::String("audience".into())))
        );
    }

    #[test]
    fn validate_audience_when_multiple() {
        let aud = SingleOrMultiple::Multiple(vec![
            StringOrUri::String("audience".into()),
            StringOrUri::Uri(Url::parse("http://audience").unwrap()),
        ]);

        let registered_claims = RegisteredClaims {
            audience: Some(aud.clone()),
            ..Default::default()
        };

        assert_eq!(
            Ok(()),
            registered_claims.validate_aud(Validation::Validate(StringOrUri::Uri(
                Url::parse("http://audience").unwrap()
            )))
        );

        assert_eq!(
            Err(ValidationError::InvalidAudience(aud.clone())),
            registered_claims.validate_aud(Validation::Validate(StringOrUri::String(
                "audience2".into()
            )))
        );

        assert_eq!(
            Err(ValidationError::InvalidAudience(aud)),
            registered_claims.validate_aud(Validation::Validate(StringOrUri::String(
                "https://audience".into()
            )))
        );

        assert_eq!(
            Ok(()),
            registered_claims
                .validate_aud(Validation::Validate(StringOrUri::String("audience".into())))
        );
    }

    #[test]
    fn validate_valid_token_with_all_required() {
        let registered_claims = RegisteredClaims {
            expiry: Some(999.into()),
            not_before: Some(1.into()),
            issued_at: Some(95.into()),
            subject: Some(StringOrUri::String("subject".into())),
            issuer: Some(StringOrUri::String("issuer".into())),
            audience: Some(SingleOrMultiple::Multiple(vec![
                StringOrUri::Uri(Url::parse("http://audience").unwrap()),
                StringOrUri::String("audience".into()),
            ])),
            id: Some("id".into()),
        };

        let temporal_options = TemporalOptions {
            now: Some(Utc.timestamp(100, 0)),
            ..Default::default()
        };

        let validation_options = ValidationOptions {
            temporal_options,
            claim_presence_options: ClaimPresenceOptions::strict(),

            expiry: Validation::Validate(()),
            not_before: Validation::Validate(()),
            issued_at: Validation::Validate(Duration::max_value()),
            audience: Validation::Validate(StringOrUri::String("audience".into())),
            issuer: Validation::Validate(StringOrUri::String("issuer".into())),
        };

        not_err!(registered_claims.validate(validation_options));
    }

    #[test]
    fn validate_times_valid_token_with_epsilon() {
        let registered_claims = RegisteredClaims {
            expiry: Some(99.into()),
            not_before: Some(96.into()),
            issued_at: Some(96.into()),
            ..Default::default()
        };

        let temporal_options = TemporalOptions {
            now: Some(Utc.timestamp(100, 0)),
            epsilon: Duration::seconds(10),
        };

        let validation_options = ValidationOptions {
            temporal_options,
            claim_presence_options: Default::default(),

            expiry: Validation::Validate(()),
            not_before: Validation::Validate(()),
            issued_at: Validation::Validate(Duration::max_value()),

            ..Default::default()
        };

        not_err!(registered_claims.validate(validation_options));
    }

    #[test]
    fn compact_part_round_trip() {
        let test_value = PrivateClaims {
            department: "Toilet Cleaning".to_string(),
            company: "ACME".to_string(),
        };

        let base64 = not_err!(test_value.to_base64());
        let expected_base64 = "eyJjb21wYW55IjoiQUNNRSIsImRlcGFydG1lbnQiOiJUb2lsZXQgQ2xlYW5pbmcifQ";
        assert_eq!(base64.str(), expected_base64);

        let actual_value = not_err!(PrivateClaims::from_base64(&base64));
        assert_eq!(actual_value, test_value);
    }

    #[test]
    fn compact_part_vec_u8_round_trip() {
        let test_value: Vec<u8> = vec![1, 2, 3, 4, 5];

        let base64 = not_err!(test_value.to_base64());
        let expected_base64 = "AQIDBAU";
        assert_eq!(base64.str(), expected_base64);

        let actual_value = not_err!(Vec::<u8>::from_base64(&base64));
        assert_eq!(actual_value, test_value);
    }

    #[test]
    fn compact_part_base64_url_round_trip() {
        let test_value = Base64Url("AQIDBAU".to_string());

        let base64 = not_err!(test_value.to_base64());
        let expected_base64 = "AQIDBAU";
        assert_eq!(base64.str(), expected_base64);

        let actual_value = not_err!(Base64Url::from_base64(&base64));
        assert_eq!(actual_value, test_value);
    }
}
