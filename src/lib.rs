//! Create, parse, and verify JWT (JSON Web Tokens)
//!
//! # Usage
//! ```toml
//! [dependencies]
//! biscuit = "0.0.1"
//! ```
//!
//! See [`JWT`] for usage examples.
#![deny(missing_docs)]
#![doc(test(attr(allow(unused_variables), deny(warnings))))]

extern crate chrono;
extern crate rustc_serialize;
extern crate ring;
extern crate serde;
#[macro_use]
extern crate serde_derive;
extern crate serde_json;
extern crate untrusted;

use std::convert::{From, Into};
use std::ops::Deref;

use chrono::{DateTime, UTC, NaiveDateTime};
use rustc_serialize::base64::{self, ToBase64, FromBase64};
use serde::{Serialize, Serializer, Deserialize, Deserializer};
use serde_json::value;

#[cfg(test)]
#[macro_use]
mod test;
pub mod errors;
pub mod jws;

use errors::{Error, ValidationError};

/// A part of the JWT: header and claims specifically
/// Allows converting from/to struct with base64
trait Part {
    type Encoded: AsRef<str>;

    fn from_base64<B: AsRef<[u8]>>(encoded: B) -> Result<Self, Error> where Self: Sized;
    fn to_base64(&self) -> Result<Self::Encoded, Error>;
}

impl<T> Part for T
    where T: Serialize + Deserialize
{
    type Encoded = String;

    fn to_base64(&self) -> Result<Self::Encoded, Error> {
        let encoded = serde_json::to_string(&self)?;
        Ok(encoded.as_bytes().to_base64(base64::URL_SAFE))
    }

    fn from_base64<B: AsRef<[u8]>>(encoded: B) -> Result<T, Error> {
        let decoded = encoded.as_ref().from_base64()?;
        let s = String::from_utf8(decoded)?;
        Ok(serde_json::from_str(&s)?)
    }
}

/// Represents a choice between a single string value or multiple strings
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum SingleOrMultipleStrings {
    /// One string value
    Single(String),
    /// Multiple string values
    Multiple(Vec<String>),
}

/// List of registered claims defined by [RFC7519#4.1](https://tools.ietf.org/html/rfc7519#section-4.1)
static REGISTERED_CLAIMS: &'static [&'static str] = &["iss", "sub", "aud", "exp", "nbf", "iat", "jti"];

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
    pub issuer: Option<String>,

    /// Subject where the JWT is referring to. Serialized to `sub`
    #[serde(rename = "sub", skip_serializing_if = "Option::is_none")]
    pub subject: Option<String>,

    /// Audience intended for the JWT. Serialized to `aud`
    #[serde(rename = "aud", skip_serializing_if = "Option::is_none")]
    pub audience: Option<SingleOrMultipleStrings>,

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
#[derive(Debug, Eq, PartialEq)]
pub struct ClaimsSet<T: Serialize + Deserialize> {
    /// Registered claims defined by the RFC
    pub registered: RegisteredClaims,
    /// Application specific claims
    pub private: T,
}

impl<T: Serialize + Deserialize> Serialize for ClaimsSet<T> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
        where S: Serializer
    {
        use serde::ser::Error;

        // A "hack" to combine two structs into one serialized JSON
        // First, we serialize each of them into JSON Value enum
        let registered = value::to_value(&self.registered).map_err(S::Error::custom)?;
        let private = value::to_value(&self.private).map_err(S::Error::custom)?;

        // Extract the Maps out
        let mut registered = match registered {
            value::Value::Object(map) => map,
            _ => unreachable!("RegisteredClaims needs to be a struct"),
        };
        let private = match private {
            value::Value::Object(map) => map,
            _ => Err(S::Error::custom("Private Claims type is not a struct"))?,
        };

        // Merge the Maps
        for (key, value) in private {
            if REGISTERED_CLAIMS.iter().any(|claim| *claim == key) {
                Err(S::Error::custom(format!("Private claims has registered claim `{}`", key)))?
            }
            if registered.insert(key.clone(), value).is_some() {
                unreachable!("Should have been caught above!");
            }
        }

        registered.serialize(serializer)
    }
}

impl<T: Serialize + Deserialize> Deserialize for ClaimsSet<T> {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
        where D: Deserializer
    {
        use serde::de::Error;
        use serde_json::value::{from_value, Value};
        use serde_json::map::Map;

        // Deserialize the whole thing into a JSON Value
        let value: Value = Deserialize::deserialize(deserializer)?;
        // ... which should be of the Object variant containing a Map
        let mut map = match value {
            Value::Object(map) => map,
            others => Err(D::Error::custom(format!("Expected a map, got {:?}", others)))?,
        };

        // Let's extract the registered claims from the object
        let mut registered = Map::with_capacity(REGISTERED_CLAIMS.len());
        for claim in REGISTERED_CLAIMS.iter() {
            match map.remove(*claim) {
                Some(value) => {
                    registered.insert(claim.to_string(), value);
                }
                None => {
                    registered.insert(claim.to_string(), Value::Null);
                }
            }
        }

        // Deserialize the two parts separately
        let registered: RegisteredClaims =
            from_value(Value::Object(registered))
                .map_err(|e| D::Error::custom(format!("Error deserializing registered claims: {}", e)))?;
        let private: T = from_value(Value::Object(map))
            .map_err(|e| D::Error::custom(format!("Error deserializing private claims: {}", e)))?;

        Ok(ClaimsSet {
               registered: registered,
               private: private,
           })
    }
}

impl<T> Clone for ClaimsSet<T>
    where T: Serialize + Deserialize + Clone
{
    fn clone(&self) -> Self {
        ClaimsSet {
            registered: self.registered.clone(),
            private: self.private.clone(),
        }
    }
}

/// A JWT that can be encoded/decoded
///
/// The serialization/deserialization is handled by serde. Before you transport the token, make sure you
/// turn it into the encoded form first.
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
/// use biscuit::*;
/// use biscuit::jws::*;
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
///     eyJpc3MiOiJodHRwczovL3d3dy5hY21lLmNvbSIsInN1YiI6IkpvaG4g\
///     RG9lIiwiYXVkIjoiaHR0czovL2FjbWUtY3VzdG9tZXIuY29tIiwibmJmI\
///     joxMjM0LCJjb21wYW55IjoiQUNNRSIsImRlcGFydG1lbnQiOiJUb2lsZXQ\
///     gQ2xlYW5pbmcifQ.u3ORB8my861WsYulP6UE_m2nwSDo3uu3K0ylCRjCiFw";
///
/// let expected_claims = ClaimsSet::<PrivateClaims> {
///     registered: RegisteredClaims {
///         issuer: Some("https://www.acme.com".to_string()),
///         subject: Some("John Doe".to_string()),
///         audience: Some(
///             SingleOrMultipleStrings::Single("htts://acme-customer.com"
///                                              .to_string())),
///         not_before: Some(1234.into()),
///         ..Default::default()
///     },
///     private: PrivateClaims {
///         department: "Toilet Cleaning".to_string(),
///         company: "ACME".to_string(),
///     },
/// };
///
/// let expected_jwt = JWT::new_decoded(Header {
///                                         algorithm: Algorithm::HS256,
///                                         ..Default::default()
///                                     },
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
/// let token = serde_json::from_str::<JWT<PrivateClaims>>(&token).unwrap();
/// let token = token.into_decoded(Secret::Bytes("secret".to_string().into_bytes()),
///     Algorithm::HS256).unwrap();
/// assert_eq!(*token.claims_set().unwrap(), expected_claims);
/// # }
/// ```
#[derive(Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum JWT<T: Serialize + Deserialize> {
    /// Decoded form of the JWT. **DO NOT SERIALIZE THIS AND SEND TO YOUR CLIENTS.**.
    /// This variant cannot be serialized or deserialized and will return an error.
    #[serde(skip_serializing)]
    #[serde(skip_deserializing)]
    Decoded {
        /// Embedded header
        header: jws::Header,
        /// Claims sets, including registered and private claims
        claims_set: ClaimsSet<T>,
    },
    /// Encoded and (optionally) signed JWT. Use this form to send to your clients
    Encoded(String),
}

/// Used in decode: takes the result of a rsplit and ensure we only get 2 parts
/// Errors if we don't
macro_rules! expect_two {
    ($iter:expr) => {{
        let mut i = $iter; // evaluate the expr
        match (i.next(), i.next(), i.next()) {
            (Some(first), Some(second), None) => Ok((first, second)),
            _ => Err(Error::ValidationError(ValidationError::InvalidToken))
        }
    }}
}

impl<T: Serialize + Deserialize> JWT<T> {
    /// New decoded JWT
    pub fn new_decoded(header: jws::Header, claims_set: ClaimsSet<T>) -> Self {
        JWT::Decoded {
            header: header,
            claims_set: claims_set,
        }
    }

    /// New encoded JWT
    pub fn new_encoded(token: &str) -> Self {
        JWT::Encoded(token.to_string())
    }

    /// Consumes self and convert into encoded form. If the token is already encoded,
    /// this is a no-op.
    // TODO: Is the no-op dangerous? What if the secret between the previous encode and this time is different?
    pub fn into_encoded(self, secret: jws::Secret) -> Result<Self, Error> {
        match self {
            JWT::Encoded(_) => Ok(self),
            JWT::Decoded { .. } => self.encode(secret),
        }
    }

    /// Encode the JWT passed and sign the payload using the algorithm from the header and the secret
    /// The secret is dependent on the signing algorithm
    pub fn encode(&self, secret: jws::Secret) -> Result<Self, Error> {
        match *self {
            JWT::Decoded { ref header, ref claims_set } => {
                let encoded_header = header.to_base64()?;
                let encoded_claims = claims_set.to_base64()?;
                let payload = [&*encoded_header, &*encoded_claims].join(".");
                let signature = header.algorithm
                    .sign(payload.as_bytes(), secret)?
                    .as_slice()
                    .to_base64(base64::URL_SAFE);

                Ok(JWT::Encoded([payload, signature].join(".")))
            }
            JWT::Encoded(_) => Err(Error::UnsupportedOperation),
        }
    }


    /// Consumes self and convert into decoded form, verifying the signature, if any.
    /// If the token is already decoded, this is a no-op.AsMut
    // TODO: Is the no-op dangerous? What if the secret between the previous decode and this time is different?
    pub fn into_decoded(self, secret: jws::Secret, algorithm: jws::Algorithm) -> Result<Self, Error> {
        match self {
            JWT::Encoded(_) => self.decode(secret, algorithm),
            JWT::Decoded { .. } => Ok(self),
        }
    }

    /// Decode a token into the JWT struct and verify its signature
    /// If the token or its signature is invalid, it will return an error
    pub fn decode(&self, secret: jws::Secret, algorithm: jws::Algorithm) -> Result<Self, Error> {
        match *self {
            JWT::Decoded { .. } => Err(Error::UnsupportedOperation),
            JWT::Encoded(ref token) => {
                // Check that there are only two parts
                let (signature, payload) = expect_two!(token.rsplitn(2, '.'))?;
                let signature: Vec<u8> = signature.from_base64()?;

                if !algorithm.verify(signature.as_ref(), payload.as_ref(), secret)? {
                    Err(ValidationError::InvalidSignature)?;
                }

                let (claims, header) = expect_two!(payload.rsplitn(2, '.'))?;

                let header = jws::Header::from_base64(header)?;
                if header.algorithm != algorithm {
                    Err(ValidationError::WrongAlgorithmHeader)?;
                }
                let decoded_claims = ClaimsSet::<T>::from_base64(claims)?;

                Ok(Self::new_decoded(header, decoded_claims))
            }
        }
    }

    /// Convenience method to extract the encoded string from an encoded JWT
    pub fn encoded(&self) -> Result<&str, Error> {
        match *self {
            JWT::Decoded { .. } => Err(Error::UnsupportedOperation),
            JWT::Encoded(ref encoded) => Ok(encoded),
        }
    }

    /// Convenience method to extract the claims set from a decoded JWT
    pub fn claims_set(&self) -> Result<&ClaimsSet<T>, Error> {
        match *self {
            JWT::Decoded { ref claims_set, .. } => Ok(claims_set),
            JWT::Encoded(_) => Err(Error::UnsupportedOperation),
        }
    }

    /// Convenience method to extract the header from a decoded JWT
    pub fn header(&self) -> Result<&jws::Header, Error> {
        match *self {
            JWT::Decoded { ref header, .. } => Ok(header),
            JWT::Encoded(_) => Err(Error::UnsupportedOperation),
        }
    }
}

impl<T> Clone for JWT<T>
    where T: Serialize + Deserialize + Clone
{
    fn clone(&self) -> Self {
        match *self {
            JWT::Decoded { ref header, ref claims_set } => {
                JWT::Decoded {
                    header: (*header).clone(),
                    claims_set: (*claims_set).clone(),
                }
            }
            JWT::Encoded(ref encoded) => JWT::Encoded((*encoded).clone()),
        }
    }
}

#[cfg(test)]
mod tests {
    extern crate serde_test;

    use std::default::Default;
    use std::str;
    use std::time::Duration;

    use chrono::{UTC, TimeZone};
    use serde_json;
    use self::serde_test::{Token, assert_tokens, assert_ser_tokens_error};

    use super::{JWT, SingleOrMultipleStrings, RegisteredClaims, ClaimsSet, TemporalValidationOptions, Timestamp};
    use jws::{Algorithm, Header, Secret};

    #[derive(Debug, PartialEq, Clone, Serialize, Deserialize)]
    struct PrivateClaims {
        company: String,
        department: String,
    }

    #[derive(Debug, PartialEq, Clone, Serialize, Deserialize)]
    struct InvalidPrivateClaim {
        sub: String,
        company: String,
    }

    #[derive(Debug, Eq, PartialEq, Serialize, Deserialize)]
    struct SingleOrMultipleStringsTest {
        values: SingleOrMultipleStrings,
    }

    #[test]
    fn single_string_serialization_round_trip() {
        let test = SingleOrMultipleStringsTest { values: SingleOrMultipleStrings::Single("foobar".to_string()) };
        let expected_json = r#"{"values":"foobar"}"#;

        let serialized = not_err!(serde_json::to_string(&test));
        assert_eq!(expected_json, serialized);

        let deserialized: SingleOrMultipleStringsTest = not_err!(serde_json::from_str(&serialized));
        assert_eq!(deserialized, test);
    }

    #[test]
    fn multiple_strings_serialization_round_trip() {
        let test = SingleOrMultipleStringsTest {
            values: SingleOrMultipleStrings::Multiple(vec!["foo".to_string(), "bar".to_string(), "baz".to_string()]),
        };
        let expected_json = r#"{"values":["foo","bar","baz"]}"#;

        let serialized = not_err!(serde_json::to_string(&test));
        assert_eq!(expected_json, serialized);

        let deserialized: SingleOrMultipleStringsTest = not_err!(serde_json::from_str(&serialized));
        assert_eq!(deserialized, test);
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
            issuer: Some("https://www.acme.com".to_string()),
            audience: Some(SingleOrMultipleStrings::Single("htts://acme-customer.com".to_string())),
            not_before: Some(1234.into()),
            ..Default::default()
        };
        let expected_json = r#"{"iss":"https://www.acme.com","aud":"htts://acme-customer.com","nbf":1234}"#;

        let serialized = not_err!(serde_json::to_string(&claim));
        assert_eq!(expected_json, serialized);

        let deserialized: RegisteredClaims = not_err!(serde_json::from_str(&serialized));
        assert_eq!(deserialized, claim);
    }

    #[test]
    fn claims_set_serialization_tokens_round_trip() {
        let claim = ClaimsSet::<PrivateClaims> {
            registered: RegisteredClaims {
                issuer: Some("https://www.acme.com".to_string()),
                subject: Some("John Doe".to_string()),
                audience: Some(SingleOrMultipleStrings::Single("htts://acme-customer.com".to_string())),
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
                        Token::Str("https://www.acme.com"),

                        Token::MapSep,
                        Token::Str("sub"),
                        Token::Str("John Doe"),

                        Token::MapSep,
                        Token::Str("aud"),
                        Token::Str("htts://acme-customer.com"),

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
                issuer: Some("https://www.acme.com".to_string()),
                subject: Some("John Doe".to_string()),
                audience: Some(SingleOrMultipleStrings::Single("htts://acme-customer.com".to_string())),
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
                                serde_test::Error::Message("Private claims has registered claim `sub`".to_string()));
    }

    #[test]
    fn claims_set_serialization_round_trip() {
        let claim = ClaimsSet::<PrivateClaims> {
            registered: RegisteredClaims {
                issuer: Some("https://www.acme.com".to_string()),
                subject: Some("John Doe".to_string()),
                audience: Some(SingleOrMultipleStrings::Single("htts://acme-customer.com".to_string())),
                not_before: Some(1234.into()),
                ..Default::default()
            },
            private: PrivateClaims {
                department: "Toilet Cleaning".to_string(),
                company: "ACME".to_string(),
            },
        };

        let expected_json = "{\"iss\":\"https://www.acme.com\",\"sub\":\"John Doe\",\
                            \"aud\":\"htts://acme-customer.com\",\
                            \"nbf\":1234,\"company\":\"ACME\",\"department\":\"Toilet Cleaning\"}";

        let serialized = not_err!(serde_json::to_string(&claim));
        assert_eq!(expected_json, serialized);

        let deserialized: ClaimsSet<PrivateClaims> = not_err!(serde_json::from_str(&serialized));
        assert_eq!(deserialized, claim);
    }

    #[test]
    #[should_panic(expected = "Private claims has registered claim `sub`")]
    fn invalid_private_claims_will_fail_to_serialize() {
        let claim = ClaimsSet::<InvalidPrivateClaim> {
            registered: RegisteredClaims {
                issuer: Some("https://www.acme.com".to_string()),
                subject: Some("John Doe".to_string()),
                audience: Some(SingleOrMultipleStrings::Single("htts://acme-customer.com".to_string())),
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
    #[should_panic(expected = "the enum variant JWT::Decoded cannot be serialized")]
    fn decoded_jwt_cannot_be_serialized() {
        let expected_claims = ClaimsSet::<PrivateClaims> {
            registered: RegisteredClaims {
                issuer: Some("https://www.acme.com".to_string()),
                subject: Some("John Doe".to_string()),
                audience: Some(SingleOrMultipleStrings::Single("htts://acme-customer.com".to_string())),
                not_before: Some(1234.into()),
                ..Default::default()
            },
            private: PrivateClaims {
                department: "Toilet Cleaning".to_string(),
                company: "ACME".to_string(),
            },
        };

        let biscuit = JWT::new_decoded(Header { algorithm: Algorithm::None, ..Default::default() },
                                   expected_claims.clone());
        serde_json::to_string(&biscuit).unwrap();
    }

    #[test]
    #[should_panic(expected = "data did not match any variant of untagged enum JWT")]
    fn decoded_jwt_cannot_be_deserialized() {
        let json = r#"{"header":{"alg":"none","typ":"JWT"},
                       "claims_set":{"iss":"https://www.acme.com","sub":"John Doe",
                                     "aud":"htts://acme-customer.com","nbf":1234,
                                     "company":"ACME","department":"Toilet Cleaning"}}"#;
        serde_json::from_str::<JWT<PrivateClaims>>(json).unwrap();
    }

    #[test]
    fn round_trip_none() {
        let expected_token = "eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.\
            eyJpc3MiOiJodHRwczovL3d3dy5hY21lLmNvbSIsInN1YiI6IkpvaG4gRG9lIiwiYXVkIjoiaHR0czovL2FjbWUt\
            Y3VzdG9tZXIuY29tIiwibmJmIjoxMjM0LCJjb21wYW55IjoiQUNNRSIsImRlcGFydG1lbnQiOiJUb2lsZXQgQ2xlYW5pbmcifQ.";

        let expected_claims = ClaimsSet::<PrivateClaims> {
            registered: RegisteredClaims {
                issuer: Some("https://www.acme.com".to_string()),
                subject: Some("John Doe".to_string()),
                audience: Some(SingleOrMultipleStrings::Single("htts://acme-customer.com".to_string())),
                not_before: Some(1234.into()),
                ..Default::default()
            },
            private: PrivateClaims {
                department: "Toilet Cleaning".to_string(),
                company: "ACME".to_string(),
            },
        };

        let expected_jwt = JWT::new_decoded(Header { algorithm: Algorithm::None, ..Default::default() },
                                            expected_claims.clone());
        let token = not_err!(expected_jwt.into_encoded(Secret::None));
        assert_eq!(expected_token, not_err!(token.encoded()));

        let biscuit = not_err!(token.into_decoded(Secret::None, Algorithm::None));
        let actual_claims = not_err!(biscuit.claims_set());
        assert_eq!(expected_claims, *actual_claims);
    }

    #[test]
    fn round_trip_hs256() {
        let expected_token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.\
            eyJpc3MiOiJodHRwczovL3d3dy5hY21lLmNvbSIsInN1YiI6IkpvaG4gRG9lIiwiYXVkIjoiaHR0czovL2FjbWUt\
            Y3VzdG9tZXIuY29tIiwibmJmIjoxMjM0LCJjb21wYW55IjoiQUNNRSIsImRlcGFydG1lbnQiOiJUb2lsZXQgQ2xlYW5pbmcifQ.\
            u3ORB8my861WsYulP6UE_m2nwSDo3uu3K0ylCRjCiFw";

        let expected_claims = ClaimsSet::<PrivateClaims> {
            registered: RegisteredClaims {
                issuer: Some("https://www.acme.com".to_string()),
                subject: Some("John Doe".to_string()),
                audience: Some(SingleOrMultipleStrings::Single("htts://acme-customer.com".to_string())),
                not_before: Some(1234.into()),
                ..Default::default()
            },
            private: PrivateClaims {
                department: "Toilet Cleaning".to_string(),
                company: "ACME".to_string(),
            },
        };

        let expected_jwt = JWT::new_decoded(Header { algorithm: Algorithm::HS256, ..Default::default() },
                                            expected_claims.clone());
        let token = not_err!(expected_jwt.into_encoded(Secret::Bytes("secret".to_string().into_bytes())));
        assert_eq!(expected_token, not_err!(token.encoded()));

        let biscuit = not_err!(token.into_decoded(Secret::Bytes("secret".to_string().into_bytes()),
                                              Algorithm::HS256));
        assert_eq!(expected_claims, *not_err!(biscuit.claims_set()));
    }

    #[test]
    fn round_trip_rs256() {
        let expected_token = "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.\
            eyJpc3MiOiJodHRwczovL3d3dy5hY21lLmNvbSIsInN1YiI6IkpvaG4gRG9lIiwiYXVkIjoiaHR0czovL2FjbWU\
            tY3VzdG9tZXIuY29tIiwibmJmIjoxMjM0LCJjb21wYW55IjoiQUNNRSIsImRlcGFydG1lbnQiOiJUb2lsZXQgQ2xlYW5pbmcifQ.\
            jHqjTw5360qo-0vaQF9JI6cnc14m_VNNeqTzhG90xSNZN8242adFW-EhOPKPrwY7NqDEZh1YmilxpVKy-qMlNWEQ7HxHzYY8ldFznH\
            chJdXTy90RHw6zJVlawttj5PmGpHiQ8aBktu-TPNE03xDOIBd_97a5-WDQ_O1xENQ45YTwHGStit77Zov2VLYFtt7zeU8OC50wbbbnGP\
            XNmDKcXAcx8ZVz30B2lTFq3UWwy0GuvKI4hKdZK7ga_cfu5d6Ch2Uv1mK3Hg5cNZ8tTIXv6J69rr3ZG5pE9DDxlJ7Hq082YOgAr7LFtdFYg\
            jchhVxIiE2zrQPuwnXD2Uw9zyr5ag";

        let expected_claims = ClaimsSet::<PrivateClaims> {
            registered: RegisteredClaims {
                issuer: Some("https://www.acme.com".to_string()),
                subject: Some("John Doe".to_string()),
                audience: Some(SingleOrMultipleStrings::Single("htts://acme-customer.com".to_string())),
                not_before: Some(1234.into()),
                ..Default::default()
            },
            private: PrivateClaims {
                department: "Toilet Cleaning".to_string(),
                company: "ACME".to_string(),
            },
        };
        let private_key = Secret::rsa_keypair_from_file("test/fixtures/rsa_private_key.der").unwrap();

        let expected_jwt = JWT::new_decoded(Header { algorithm: Algorithm::RS256, ..Default::default() },
                                            expected_claims.clone());
        let token = not_err!(expected_jwt.into_encoded(private_key));
        assert_eq!(expected_token, not_err!(token.encoded()));

        let public_key = Secret::public_key_from_file("test/fixtures/rsa_public_key.der").unwrap();
        let biscuit = not_err!(token.into_decoded(public_key, Algorithm::RS256));
        assert_eq!(expected_claims, *not_err!(biscuit.claims_set()));
    }

    #[test]
    fn encode_with_additional_header_fields() {
        let expected_claims = ClaimsSet::<PrivateClaims> {
            registered: RegisteredClaims {
                issuer: Some("https://www.acme.com".to_string()),
                subject: Some("John Doe".to_string()),
                audience: Some(SingleOrMultipleStrings::Single("htts://acme-customer.com".to_string())),
                not_before: Some(1234.into()),
                ..Default::default()
            },
            private: PrivateClaims {
                department: "Toilet Cleaning".to_string(),
                company: "ACME".to_string(),
            },
        };

        let mut header = Header::default();
        header.key_id = Some("kid".to_string());

        let expected_jwt = JWT::new_decoded(header.clone(), expected_claims);
        let token = not_err!(expected_jwt.into_encoded(Secret::Bytes("secret".to_string().into_bytes())));
        let biscuit = not_err!(token.into_decoded(Secret::Bytes("secret".to_string().into_bytes()),
                                              Algorithm::HS256));
        assert_eq!(header, *not_err!(biscuit.header()));
    }

    #[test]
    #[should_panic(expected = "InvalidToken")]
    fn decode_token_missing_parts() {
        let token = JWT::<PrivateClaims>::new_encoded("eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9");
        let claims = token.decode(Secret::Bytes("secret".to_string().into_bytes()),
                                  Algorithm::HS256);
        claims.unwrap();
    }

    #[test]
    #[should_panic(expected = "InvalidSignature")]
    fn decode_token_invalid_signature_hs256() {
        let token = JWT::<PrivateClaims>::new_encoded("eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.\
                                                       eyJzdWIiOiJiQGIuY29tIiwiY29tcGFueSI6IkFDTUUifQ.\
                                                       WRONGWRONGWRONGWRONGWRONGWRONGWRONGWRONG___");
        let claims = token.decode(Secret::Bytes("secret".to_string().into_bytes()),
                                  Algorithm::HS256);
        claims.unwrap();
    }

    #[test]
    #[should_panic(expected = "InvalidSignature")]
    fn decode_token_invalid_signature_rs256() {
        let token = JWT::<PrivateClaims>::new_encoded("eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.\
                                                       eyJzdWIiOiJiQGIuY29tIiwiY29tcGFueSI6IkFDTUUifQ.\
                                                       WRONGWRONGWRONGWRONGWRONGWRONGWRONGWRONG___");
        let public_key = Secret::public_key_from_file("test/fixtures/rsa_public_key.der").unwrap();
        let claims = token.decode(public_key, Algorithm::RS256);
        claims.unwrap();
    }

    #[test]
    #[should_panic(expected = "WrongAlgorithmHeader")]
    fn decode_token_wrong_algorithm() {
        let token = JWT::<PrivateClaims>::new_encoded("eyJhbGciOiJIUzUxMiIsInR5cCI6IkpXVCJ9.\
                                                       eyJzdWIiOiJiQGIuY29tIiwiY29tcGFueSI6IkFDTUUifQ.\
                                                       pKscJVk7-aHxfmQKlaZxh5uhuKhGMAa-1F5IX5mfUwI");
        let claims = token.decode(Secret::Bytes("secret".to_string().into_bytes()),
                                  Algorithm::HS256);
        claims.unwrap();
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
        let options = TemporalValidationOptions { issued_at_required: true, ..Default::default() };

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
        let options = TemporalValidationOptions { expiry_required: true, ..Default::default() };

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
        let options = TemporalValidationOptions { not_before_required: true, ..Default::default() };

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
        let options = TemporalValidationOptions { now: Some(UTC.timestamp(0, 0)), ..Default::default() };

        let registered_claims = RegisteredClaims { issued_at: Some(10.into()), ..Default::default() };
        registered_claims.validate_times(Some(options)).unwrap();
    }

    #[test]
    #[should_panic(expected = "TemporalError")]
    fn validate_times_catch_expired_token() {
        let options = TemporalValidationOptions { now: Some(UTC.timestamp(2, 0)), ..Default::default() };

        let registered_claims = RegisteredClaims { expiry: Some(1.into()), ..Default::default() };
        registered_claims.validate_times(Some(options)).unwrap();
    }

    #[test]
    #[should_panic(expected = "TemporalError")]
    fn validate_times_catch_early_token() {
        let options = TemporalValidationOptions { now: Some(UTC.timestamp(0, 0)), ..Default::default() };

        let registered_claims = RegisteredClaims { not_before: Some(1.into()), ..Default::default() };
        registered_claims.validate_times(Some(options)).unwrap();
    }

    #[test]
    fn validate_times_valid_token_with_default_options() {
        let registered_claims = RegisteredClaims { not_before: Some(1.into()), ..Default::default() };
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
