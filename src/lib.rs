//! [![Build Status](https://travis-ci.org/lawliet89/biscuit.svg)](https://travis-ci.org/lawliet89/biscuit)
//! [![Crates.io](https://img.shields.io/crates/v/biscuit.svg)](https://crates.io/crates/biscuit)
//! [![Repository](https://img.shields.io/github/tag/lawliet89/biscuit.svg)](https://github.com/lawliet89/biscuit)
//!
//! Documentation:  [stable](https://docs.rs/biscuit/) | [master branch](https://lawliet89.github.io/biscuit)
//!
//! A library based off [`Keats/rust-jwt`](https://github.com/Keats/rust-jwt) that allows you create,
//! parse, and verify JWT (JSON Web Tokens).
//!
//! ## Installation
//!
//! Add the following to Cargo.toml:
//!
//! ```toml
//! biscuit = "0.0.2"
//! ```
//!
//! To use the latest `master` branch, for example:
//!
//! ```toml
//! biscuit = { git = "https://github.com/lawliet89/biscuit", branch = "master" }
//! ```
//!
//! See [`JWT`] for usage examples.
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
#![deny(missing_docs)]
#![doc(test(attr(allow(unused_variables), deny(warnings))))]

extern crate chrono;
extern crate data_encoding;
#[macro_use]
extern crate lazy_static;
extern crate num;
extern crate ring;
extern crate serde;
#[macro_use]
extern crate serde_derive;
extern crate serde_json;
extern crate untrusted;
extern crate url;

#[cfg(test)]
extern crate serde_test;

use std::borrow::Borrow;
use std::fmt::{self, Debug};
use std::ops::Deref;
use std::str::FromStr;

use chrono::{DateTime, UTC, NaiveDateTime};
use data_encoding::base64url;
use serde::{Serialize, Serializer, Deserialize, Deserializer};
use serde::de;

pub use url::{Url, ParseError};

#[cfg(test)]
#[macro_use]
mod test;

#[macro_use]
mod serde_custom;

pub mod errors;
pub mod jwa;
pub mod jws;
pub mod jwk;
pub mod jwe;

use errors::{Error, ValidationError};

/// A convenience type alias of the common "JWT" which is a secured/unsecured compact JWS.
/// Type `T` is the type of the private claims, and type `H` is the type of private header fields
///
/// # Examples
/// ## Encoding and decoding with HS256
///
/// ```
/// extern crate biscuit;
/// extern crate serde;
/// #[macro_use]
/// extern crate serde_derive;
/// extern crate serde_json;
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
///     .into_encoded(Secret::Bytes("secret".to_string().into_bytes())).unwrap();
/// let token = serde_json::to_string(&token).unwrap();
/// assert_eq!(format!("\"{}\"", expected_token), token);
/// // Now, send `token` to your clients
///
/// // ... some time later, we get token back!
///
/// let token = serde_json::from_str::<JWT<PrivateClaims, Empty>>(&token).unwrap();
/// let token = token.into_decoded(Secret::Bytes("secret".to_string().into_bytes()),
///     SignatureAlgorithm::HS256).unwrap();
/// assert_eq!(*token.payload().unwrap(), expected_claims);
/// # }
/// ```
pub type JWT<T, H> = jws::Compact<ClaimsSet<T>, H>;

/// An empty struct that derives Serialize and Deserialize. Can be used, for example, in places where a type
/// for custom values (such as private claims in a `ClaimsSet`) is required but you have nothing to implement.
///
/// # Examples
/// ```
/// extern crate biscuit;
/// extern crate serde;
/// extern crate serde_json;
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
    /// Base64 decode `Encoded` and then deserialize it to `Self`.
    fn from_base64<B: AsRef<[u8]>>(encoded: &B) -> Result<Self, Error> where Self: Sized;
    /// Serialize `Self` to some form and then base64 encode to `Encoded`
    fn to_base64(&self) -> Result<Base64Url, Error>;
}

/// A marker trait that indicates that the object is to be serialized to JSON and deserialized from JSON.
/// This is primarily used in conjunction with the `CompactPart` trait which will serialize structs to JSON before
/// base64 encoding, and vice-versa.
pub trait CompactJson: Serialize + Deserialize {}

impl<T> CompactPart for T
    where T: CompactJson
{
    /// JSON serialize the part and then serialize into URL Safe base64
    fn to_base64(&self) -> Result<Base64Url, Error> {
        let encoded = serde_json::to_string(&self)?;
        Ok(Base64Url(base64url::encode_nopad(encoded.as_bytes())))
    }

    /// From base64, deserialize the JSON representation and further deserialize into `T`
    fn from_base64<B: AsRef<[u8]>>(encoded: &B) -> Result<Self, Error> {
        let decoded = base64url::decode_nopad(encoded.as_ref())?;
        let s = String::from_utf8(decoded)?;
        Ok(serde_json::from_str(&s)?)
    }
}

impl CompactPart for Vec<u8> {
    fn to_base64(&self) -> Result<Base64Url, Error> {
        Ok(Base64Url(base64url::encode_nopad(self)))
    }

    fn from_base64<B: AsRef<[u8]>>(encoded: &B) -> Result<Self, Error> {
        Ok(base64url::decode_nopad(encoded.as_ref())?)
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
        self.0.borrow()
    }
}

impl CompactPart for Base64Url {
    fn to_base64(&self) -> Result<Base64Url, Error> {
        Ok((*self).clone())
    }

    fn from_base64<B: AsRef<[u8]>>(encoded: &B) -> Result<Self, Error> {
        let bytes: Vec<u8> = encoded.as_ref().to_vec();
        let string = String::from_utf8(bytes)?;
        Ok(Base64Url(string))
    }
}

impl AsRef<[u8]> for Base64Url {
    fn as_ref(&self) -> &[u8] {
        self.0.as_ref()
    }
}

/// A collection of `CompactPart`s that have been converted to Base64Url
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
        Self { parts: Vec::with_capacity(capacity) }
    }

    /// Push a `CompactPart` to the end
    pub fn push(&mut self, part: &CompactPart) -> Result<(), Error> {
        let base64 = part.to_base64()?;
        self.parts.push(base64);
        Ok(())
    }

    /// Returns the number of parts
    pub fn len(&self) -> usize {
        self.parts.len()
    }

    /// Encodes the various parts into Base64 URL encoding and then concatenates them with period '.'
    /// This corresponds to the various `Compact` representation in JWE and JWS, for example
    pub fn encode(&self) -> String {
        let strings: Vec<&str> = self.parts.iter().map(|s| s.deref()).collect();
        strings.join(".")
    }

    /// Convenience function to split an encoded compact representation into a list of `Base64Url`.
    pub fn decode(encoded: &str) -> Self {
        // Never fails
        let parts = encoded
            .split('.')
            .map(|s| FromStr::from_str(s).unwrap())
            .collect();
        Self { parts: parts }
    }

    /// Convenience function to retrieve a part at a certain index and decode into the type desired
    pub fn part<T: CompactPart>(&self, index: usize) -> Result<T, Error> {
        let part = self.parts.get(index).ok_or_else(|| "Out of bounds".to_string())?;
        CompactPart::from_base64(part)
    }

    /// Alias of `encode`
    pub fn to_string(&self) -> String {
        self.encode()
    }
}

impl Serialize for Compact {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
        where S: Serializer
    {
        serializer.serialize_str(&self.encode())
    }
}

impl Deserialize for Compact {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
        where D: Deserializer {

        struct CompactVisitor;

        impl de::Visitor for CompactVisitor {
            type Value = Compact;

            fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                formatter.write_str("a string containing a compact JOSE representation")
            }

            fn visit_str<E>(self, value: &str) -> Result<Self::Value, E>
                where E: de::Error
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
/// extern crate serde;
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
pub enum SingleOrMultiple<T>
    where T: Clone + Debug + Eq + PartialEq + Serialize + Deserialize + Send + Sync
{
    /// One single value
    Single(T),
    /// Multiple values
    Multiple(Vec<T>),
}

impl<T> SingleOrMultiple<T>
    where T: Clone + Debug + Eq + PartialEq + Serialize + Deserialize + Send + Sync
{
    /// Checks whether this enum, regardless of single or multiple value contains `value`.
    pub fn contains<Q: ?Sized>(&self, value: &Q) -> bool
        where T: Borrow<Q>,
              Q: PartialEq
    {
        match *self {
            SingleOrMultiple::Single(ref single) => single.borrow() == value,
            SingleOrMultiple::Multiple(ref vector) => vector.iter().map(Borrow::borrow).any(|v| v == value),
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
/// extern crate serde;
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
#[derive(Clone, Debug, Eq, PartialEq)]
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
        where S: Serializer
    {
        serializer.serialize_str(self.as_ref())
    }
}

impl Deserialize for StringOrUri {
    fn deserialize<D>(deserializer: D) -> Result<StringOrUri, D::Error>
        where D: Deserializer
    {
        struct StringOrUriVisitor {}

        impl de::Visitor for StringOrUriVisitor {
            type Value = StringOrUri;

            fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                formatter.write_str("an arbitrary string or URI")
            }

            fn visit_str<E>(self, value: &str) -> Result<Self::Value, E>
                where E: de::Error
            {
                StringOrUri::from_str(value).map_err(E::custom)
            }
        }

        deserializer.deserialize_str(StringOrUriVisitor {})
    }
}

/// Wrapper around `DateTime<UTC>` to allow us to do custom de(serialization)
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Timestamp(DateTime<UTC>);

impl Deref for Timestamp {
    type Target = DateTime<UTC>;
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl From<DateTime<UTC>> for Timestamp {
    fn from(datetime: DateTime<UTC>) -> Self {
        Timestamp(datetime)
    }
}

impl Into<DateTime<UTC>> for Timestamp {
    fn into(self) -> DateTime<UTC> {
        self.0
    }
}

impl From<i64> for Timestamp {
    fn from(timestamp: i64) -> Self {
        DateTime::<UTC>::from_utc(NaiveDateTime::from_timestamp(timestamp, 0), UTC).into()
    }
}

impl Serialize for Timestamp {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
        where S: Serializer
    {
        serializer.serialize_i64(self.timestamp())
    }
}

impl Deserialize for Timestamp {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
        where D: Deserializer
    {
        let timestamp = i64::deserialize(deserializer)?;
        Ok(Timestamp(DateTime::<UTC>::from_utc(NaiveDateTime::from_timestamp(timestamp, 0), UTC)))
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
/// Options for claims time validation
/// By default, no temporal claims (namely `iat`, `exp`, `nbf`)
/// are required, and they will pass validation if they are missing.
/// Should any temporal claims be needed, set the appropriate fields.
/// To deal with clock drifts, you might want to provide an `epsilon` error margin in the form of a
/// `std::time::Duration` to allow time comparisons to fall within the margin.
pub struct TemporalValidationOptions {
    /// Whether the `iat` or `Issued At` field is required
    pub issued_at_required: bool,
    /// Whether the `nbf` or `Not Before` field is required
    pub not_before_required: bool,
    /// Whether the `exp` or `Expiry` field is required
    pub expiry_required: bool,
    /// Allow for some clock drifts, limited to this duration during temporal validation
    pub epsilon: Option<std::time::Duration>,
    /// Specify a time to use in temporal validation instead of `Now`.
    pub now: Option<DateTime<UTC>>,
}

impl RegisteredClaims {
    /// Validate the temporal claims in the token
    pub fn validate_times(&self, options: Option<TemporalValidationOptions>) -> Result<(), ValidationError> {
        let options = options.unwrap_or_default();

        if options.issued_at_required && self.issued_at.is_none() {
            Err(ValidationError::MissingRequired("iat".to_string()))?;
        }

        if options.expiry_required && self.expiry.is_none() {
            Err(ValidationError::MissingRequired("exp".to_string()))?;
        }

        if options.not_before_required && self.not_before.is_none() {
            Err(ValidationError::MissingRequired("nbf".to_string()))?;
        }

        let now = match options.now {
            None => UTC::now(),
            Some(now) => now,
        };

        let e = match options.epsilon {
            None => std::time::Duration::from_secs(0),
            Some(e) => e,
        };

        if self.expiry.is_some() && !Self::is_after(*self.expiry.unwrap(), now, e)? {
            Err(ValidationError::TemporalError("Token expired".to_string()))?;
        }

        if self.issued_at.is_some() && !Self::is_before(*self.issued_at.unwrap(), now, e)? {
            Err(ValidationError::TemporalError("Token issued in the future".to_string()))?;
        }

        if self.not_before.is_some() && !Self::is_before(*self.not_before.unwrap(), now, e)? {
            Err(ValidationError::TemporalError("Token not valid yet".to_string()))?;
        }

        Ok(())
    }


    /// Check `a` is after `b` within a tolerated duration of `e`, where `e` is unsigned: a - b >= -e
    fn is_after<Tz, Tz2>(a: DateTime<Tz>, b: DateTime<Tz2>, e: std::time::Duration) -> Result<bool, ValidationError>
        where Tz: chrono::offset::TimeZone,
              Tz2: chrono::offset::TimeZone
    {
        // FIXME: `chrono::Duration` is a re-export of `time::Duration` and this returns has an error of type
        // `time::OutOfRangeError`. We don't want to put `time` as a dependent crate just to `impl From` for this...
        // So I am just going to `map_err`.
        use std::error::Error;

        let e = chrono::Duration::from_std(e).map_err(|e| ValidationError::TemporalError(e.description().to_string()))?;
        Ok(a.signed_duration_since(b) >= -e)
    }

    /// Check that `a` is before `b` within a tolerated duration of `e`, where `e` is unsigned: a - b <= e
    fn is_before<Tz, Tz2>(a: DateTime<Tz>, b: DateTime<Tz2>, e: std::time::Duration) -> Result<bool, ValidationError>
        where Tz: chrono::offset::TimeZone,
              Tz2: chrono::offset::TimeZone
    {
        // FIXME: `chrono::Duration` is a re-export of `time::Duration` and this returns has an error of type
        // `time::OutOfRangeError`. We don't want to put `time` as a dependent crate just to `impl From` for this...
        // So I am just going to `map_err`.
        use std::error::Error;

        let e = chrono::Duration::from_std(e).map_err(|e| ValidationError::TemporalError(e.description().to_string()))?;
        Ok(a.signed_duration_since(b) <= e)
    }
}

/// A collection of claims, both [registered](https://tools.ietf.org/html/rfc7519#section-4.1) and your custom
/// private claims.
#[derive(Debug, Eq, PartialEq, Clone, Default)]
pub struct ClaimsSet<T: Serialize + Deserialize> {
    /// Registered claims defined by the RFC
    pub registered: RegisteredClaims,
    /// Application specific claims
    pub private: T,
}

impl_flatten_serde_generic!(ClaimsSet<T>, serde_custom::flatten::DuplicateKeysBehaviour::RaiseError,
                            registered, private);

impl<T> CompactJson for ClaimsSet<T> where T: Serialize + Deserialize + 'static {}

#[cfg(test)]
mod tests {
    use std::str::{self, FromStr};
    use std::time::Duration;

    use chrono::{UTC, TimeZone};
    use serde_json;
    use serde_test::{Token, assert_tokens, assert_ser_tokens_error};

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
        let test = StringOrUriTest { string: not_err!(FromStr::from_str("Random")) };
        assert_matches!(test, StringOrUriTest{ string: StringOrUri::String(_) });

        let expected_json = r#"{"string":"Random"}"#;
        let serialized = not_err!(serde_json::to_string(&test));
        assert_eq!(expected_json, serialized);

        let deserialized: StringOrUriTest = not_err!(serde_json::from_str(&serialized));
        assert_eq!(deserialized, test);

        assert_tokens(&test,
                      &[Token::StructStart("StringOrUriTest", 1),
                        Token::StructSep,
                        Token::Str("string"),
                        Token::Str("Random"),

                        Token::StructEnd]);
    }

    #[test]
    fn string_or_uri_uri_serialization_round_trip() {
        let test = StringOrUriTest { string: not_err!(FromStr::from_str("https://www.example.com/")) };
        assert_matches!(test, StringOrUriTest{ string: StringOrUri::Uri(_) });

        let expected_json = r#"{"string":"https://www.example.com/"}"#;
        let serialized = not_err!(serde_json::to_string(&test));
        assert_eq!(expected_json, serialized);

        let deserialized: StringOrUriTest = not_err!(serde_json::from_str(&serialized));
        assert_eq!(deserialized, test);

        assert_tokens(&test,
                      &[Token::StructStart("StringOrUriTest", 1),
                        Token::StructSep,
                        Token::Str("string"),
                        Token::Str("https://www.example.com/"),

                        Token::StructEnd]);
    }

    #[test]
    #[should_panic(expected = "UriParseError")]
    fn string_or_uri_will_fail_invalid_uris_containing_colons() {
        StringOrUriTest { string: FromStr::from_str("Invalid URI: yes!").unwrap() };
    }

    #[test]
    fn single_string_serialization_round_trip() {
        let test = SingleOrMultipleStrings { values: SingleOrMultiple::Single("foobar".to_string()) };
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
            values: SingleOrMultiple::Multiple(vec!["foo".to_string(), "bar".to_string(), "baz".to_string()]),
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
        let test =
            SingleOrMultipleStringOrUris { values: SingleOrMultiple::Single(not_err!(FromStr::from_str("foobar"))) };
        let expected_json = r#"{"values":"foobar"}"#;

        let serialized = not_err!(serde_json::to_string(&test));
        assert_eq!(expected_json, serialized);

        let deserialized: SingleOrMultipleStringOrUris = not_err!(serde_json::from_str(&serialized));
        assert_eq!(deserialized, test);
        assert!(deserialized.values.contains(&FromStr::from_str("foobar").unwrap()));
        assert!(!deserialized.values.contains(&FromStr::from_str("does not exist").unwrap()));
    }

    #[test]
    fn single_string_or_uri_uri_serialization_round_trip() {
        let test = SingleOrMultipleStringOrUris {
            values: SingleOrMultiple::Single(not_err!(FromStr::from_str("https://www.examples.com/"))),
        };
        let expected_json = r#"{"values":"https://www.examples.com/"}"#;

        let serialized = not_err!(serde_json::to_string(&test));
        assert_eq!(expected_json, serialized);

        let deserialized: SingleOrMultipleStringOrUris = not_err!(serde_json::from_str(&serialized));
        assert_eq!(deserialized, test);
        assert!(deserialized.values.contains(&FromStr::from_str("https://www.examples.com").unwrap()));
        assert!(!deserialized.values.contains(&FromStr::from_str("https://ecorp.com").unwrap()));
    }

    #[test]
    fn multiple_string_or_uri_serialization_round_trip() {
        let test = SingleOrMultipleStringOrUris {
            values: SingleOrMultiple::Multiple(vec![not_err!(FromStr::from_str("foo")),
                                                    not_err!(FromStr::from_str("https://www.example.com/")),
                                                    not_err!(FromStr::from_str("data:text/plain,Hello?World#")),
                                                    not_err!(FromStr::from_str("http://[::1]/")),
                                                    not_err!(FromStr::from_str("baz"))]),
        };
        let expected_json =
            r#"{"values":["foo","https://www.example.com/","data:text/plain,Hello?World#","http://[::1]/","baz"]}"#;

        let serialized = not_err!(serde_json::to_string(&test));
        assert_eq!(expected_json, serialized);

        let deserialized: SingleOrMultipleStringOrUris = not_err!(serde_json::from_str(&serialized));
        assert_eq!(deserialized, test);

        assert!(deserialized.values.contains(&FromStr::from_str("foo").unwrap()));
        assert!(deserialized.values.contains(&FromStr::from_str("https://www.example.com").unwrap()));
        assert!(deserialized.values.contains(&FromStr::from_str("data:text/plain,Hello?World#").unwrap()));
        assert!(deserialized.values.contains(&FromStr::from_str("http://[::1]").unwrap()));
        assert!(deserialized.values.contains(&FromStr::from_str("baz").unwrap()));
        assert!(!deserialized.values.contains(&FromStr::from_str("https://ecorp.com").unwrap()));
    }

    #[test]
    fn timestamp_serialization_roundtrip() {
        use chrono::Timelike;

        let now: Timestamp = UTC::now().with_nanosecond(0).unwrap().into();
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
            audience: Some(SingleOrMultiple::Single(not_err!(FromStr::from_str("htts://acme-customer.com/")))),
            not_before: Some(1234.into()),
            ..Default::default()
        };
        let expected_json = r#"{"iss":"https://www.acme.com/","aud":"htts://acme-customer.com/","nbf":1234}"#;

        let serialized = not_err!(serde_json::to_string(&claim));
        assert_eq!(expected_json, serialized);

        let deserialized: RegisteredClaims = not_err!(serde_json::from_str(&serialized));
        assert_eq!(deserialized, claim);
    }

    #[test]
    fn claims_set_serialization_tokens_round_trip() {
        let claim = ClaimsSet::<PrivateClaims> {
            registered: RegisteredClaims {
                issuer: Some(not_err!(FromStr::from_str("https://www.acme.com/"))),
                subject: Some(not_err!(FromStr::from_str("John Doe"))),
                audience: Some(SingleOrMultiple::Single(not_err!(FromStr::from_str("htts://acme-customer.com/")))),
                not_before: Some((-1234).into()),
                ..Default::default()
            },
            private: PrivateClaims {
                department: "Toilet Cleaning".to_string(),
                company: "ACME".to_string(),
            },
        };

        assert_tokens(&claim,
                      &[Token::MapStart(Some(6)),
                        Token::MapSep,
                        Token::Str("iss"),
                        Token::Str("https://www.acme.com/"),

                        Token::MapSep,
                        Token::Str("sub"),
                        Token::Str("John Doe"),

                        Token::MapSep,
                        Token::Str("aud"),
                        Token::Str("htts://acme-customer.com/"),

                        Token::MapSep,
                        Token::Str("nbf"),
                        Token::I64(-1234),

                        Token::MapSep,
                        Token::Str("company"),
                        Token::Str("ACME"),

                        Token::MapSep,
                        Token::Str("department"),
                        Token::Str("Toilet Cleaning"),
                        Token::MapEnd]);
    }

    #[test]
    fn claims_set_serialization_tokens_error() {
        let claim = ClaimsSet::<InvalidPrivateClaim> {
            registered: RegisteredClaims {
                issuer: Some(not_err!(FromStr::from_str("https://www.acme.com"))),
                subject: Some(not_err!(FromStr::from_str("John Doe"))),
                audience: Some(SingleOrMultiple::Single(not_err!(FromStr::from_str("htts://acme-customer.com")))),
                not_before: Some(1234.into()),
                ..Default::default()
            },
            private: InvalidPrivateClaim {
                sub: "John Doe".to_string(),
                company: "ACME".to_string(),
            },
        };

        assert_ser_tokens_error(&claim,
                                &[],
                                serde_test::Error::Message("Structs have duplicate keys".to_string()));
    }

    #[test]
    fn claims_set_serialization_round_trip() {
        let claim = ClaimsSet::<PrivateClaims> {
            registered: RegisteredClaims {
                issuer: Some(not_err!(FromStr::from_str("https://www.acme.com/"))),
                subject: Some(not_err!(FromStr::from_str("John Doe"))),
                audience: Some(SingleOrMultiple::Single(not_err!(FromStr::from_str("htts://acme-customer.com/")))),
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
    #[should_panic(expected = "Structs have duplicate keys")]
    fn invalid_private_claims_will_fail_to_serialize() {
        let claim = ClaimsSet::<InvalidPrivateClaim> {
            registered: RegisteredClaims {
                issuer: Some(not_err!(FromStr::from_str("https://www.acme.com"))),
                subject: Some(not_err!(FromStr::from_str("John Doe"))),
                audience: Some(SingleOrMultiple::Single(not_err!(FromStr::from_str("htts://acme-customer.com")))),
                not_before: Some(1234.into()),
                ..Default::default()
            },
            private: InvalidPrivateClaim {
                sub: "John Doe".to_string(),
                company: "ACME".to_string(),
            },
        };

        serde_json::to_string(&claim).unwrap();
    }

    #[test]
    fn is_after() {
        // Zero epsilon
        assert!(not_err!(RegisteredClaims::is_after(UTC.timestamp(2, 0),
                                                    UTC.timestamp(0, 0),
                                                    Duration::from_secs(0))));
        assert!(!not_err!(RegisteredClaims::is_after(UTC.timestamp(0, 0),
                                                     UTC.timestamp(3, 0),
                                                     Duration::from_secs(0))));

        // Valid only with epsilon
        assert!(not_err!(RegisteredClaims::is_after(UTC.timestamp(0, 0),
                                                    UTC.timestamp(3, 0),
                                                    Duration::from_secs(5))));

        // Exceeds epsilon
        assert!(!not_err!(RegisteredClaims::is_after(UTC.timestamp(0, 0),
                                                     UTC.timestamp(3, 0),
                                                     Duration::from_secs(1))));

        // Should be valid regardless of epsilon
        assert!(not_err!(RegisteredClaims::is_after(UTC.timestamp(7, 0),
                                                    UTC.timestamp(3, 0),
                                                    Duration::from_secs(5))));
        assert!(not_err!(RegisteredClaims::is_after(UTC.timestamp(10, 0),
                                                    UTC.timestamp(3, 0),
                                                    Duration::from_secs(5))));
    }

    #[test]
    fn is_before() {
        // Zero epsilon
        assert!(not_err!(RegisteredClaims::is_before(UTC.timestamp(-10, 0),
                                                     UTC.timestamp(0, 0),
                                                     Duration::from_secs(0))));
        assert!(!not_err!(RegisteredClaims::is_before(UTC.timestamp(10, 0),
                                                      UTC.timestamp(3, 0),
                                                      Duration::from_secs(0))));

        // Valid only with epsilon
        assert!(not_err!(RegisteredClaims::is_before(UTC.timestamp(5, 0),
                                                     UTC.timestamp(3, 0),
                                                     Duration::from_secs(5))));

        // Exceeds epsilon
        assert!(!not_err!(RegisteredClaims::is_before(UTC.timestamp(10, 0),
                                                      UTC.timestamp(3, 0),
                                                      Duration::from_secs(1))));

        // Should be valid regardless of epsilon
        assert!(not_err!(RegisteredClaims::is_before(UTC.timestamp(0, 0),
                                                     UTC.timestamp(3, 0),
                                                     Duration::from_secs(5))));
        assert!(not_err!(RegisteredClaims::is_before(UTC.timestamp(-10, 0),
                                                     UTC.timestamp(3, 0),
                                                     Duration::from_secs(5))));
    }

    #[test]
    #[should_panic(expected = "MissingRequired")]
    fn validate_times_missing_iat() {
        let options = TemporalValidationOptions {
            issued_at_required: true,
            ..Default::default()
        };

        let registered_claims = RegisteredClaims {
            expiry: Some(1.into()),
            not_before: Some(1.into()),
            ..Default::default()
        };
        registered_claims.validate_times(Some(options)).unwrap();
    }

    #[test]
    #[should_panic(expected = "MissingRequired")]
    fn validate_times_missing_exp() {
        let options = TemporalValidationOptions {
            expiry_required: true,
            ..Default::default()
        };

        let registered_claims = RegisteredClaims {
            not_before: Some(1.into()),
            issued_at: Some(1.into()),
            ..Default::default()
        };
        registered_claims.validate_times(Some(options)).unwrap();
    }

    #[test]
    #[should_panic(expected = "MissingRequired")]
    fn validate_times_missing_nbf() {
        let options = TemporalValidationOptions {
            not_before_required: true,
            ..Default::default()
        };

        let registered_claims = RegisteredClaims {
            expiry: Some(1.into()),
            issued_at: Some(1.into()),
            ..Default::default()
        };
        registered_claims.validate_times(Some(options)).unwrap();
    }

    #[test]
    #[should_panic(expected = "TemporalError")]
    fn validate_times_catch_future_token() {
        let options = TemporalValidationOptions {
            now: Some(UTC.timestamp(0, 0)),
            ..Default::default()
        };

        let registered_claims = RegisteredClaims {
            issued_at: Some(10.into()),
            ..Default::default()
        };
        registered_claims.validate_times(Some(options)).unwrap();
    }

    #[test]
    #[should_panic(expected = "TemporalError")]
    fn validate_times_catch_expired_token() {
        let options = TemporalValidationOptions {
            now: Some(UTC.timestamp(2, 0)),
            ..Default::default()
        };

        let registered_claims = RegisteredClaims {
            expiry: Some(1.into()),
            ..Default::default()
        };
        registered_claims.validate_times(Some(options)).unwrap();
    }

    #[test]
    #[should_panic(expected = "TemporalError")]
    fn validate_times_catch_early_token() {
        let options = TemporalValidationOptions {
            now: Some(UTC.timestamp(0, 0)),
            ..Default::default()
        };

        let registered_claims = RegisteredClaims {
            not_before: Some(1.into()),
            ..Default::default()
        };
        registered_claims.validate_times(Some(options)).unwrap();
    }

    #[test]
    fn validate_times_valid_token_with_default_options() {
        let registered_claims = RegisteredClaims {
            not_before: Some(1.into()),
            ..Default::default()
        };
        not_err!(registered_claims.validate_times(None));
    }

    #[test]
    fn validate_times_valid_token_with_all_required() {
        let options = TemporalValidationOptions {
            now: Some(UTC.timestamp(100, 0)),
            issued_at_required: true,
            not_before_required: true,
            expiry_required: true,
            ..Default::default()
        };

        let registered_claims = RegisteredClaims {
            expiry: Some(999.into()),
            not_before: Some(1.into()),
            issued_at: Some(95.into()),
            ..Default::default()
        };
        not_err!(registered_claims.validate_times(Some(options)));
    }

    #[test]
    fn validate_times_valid_token_with_epsilon() {
        let options = TemporalValidationOptions {
            now: Some(UTC.timestamp(100, 0)),
            epsilon: Some(Duration::from_secs(10)),
            ..Default::default()
        };

        let registered_claims = RegisteredClaims {
            expiry: Some(99.into()),
            not_before: Some(96.into()),
            issued_at: Some(96.into()),
            ..Default::default()
        };
        not_err!(registered_claims.validate_times(Some(options)));
    }
}
