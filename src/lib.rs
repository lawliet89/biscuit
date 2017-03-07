//! Create and parses JWT (JSON Web Tokens)
//!

// #![warn(missing_docs)]
#![doc(test(attr(allow(unused_variables), deny(warnings))))]

extern crate chrono;
extern crate rustc_serialize;
extern crate ring;
extern crate serde;
#[macro_use]
extern crate serde_derive;
extern crate serde_json;
extern crate untrusted;

use std::fmt;

use chrono::{DateTime, UTC};
use rustc_serialize::base64::{self, ToBase64, FromBase64};
use serde::{Serialize, Serializer, Deserialize, Deserializer};
use serde::ser::SerializeSeq;
use serde::de::{self, Visitor};
use serde_json::value;

#[cfg(test)]
#[macro_use]
mod test;
pub mod errors;
pub mod jws;

use errors::{Error, ValidationError};

/// A part of the JWT: header and claims specifically
/// Allows converting from/to struct with base64
pub trait Part {
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

#[derive(Debug, Eq, PartialEq)]
pub enum SingleOrMultipleStrings {
    Single(String),
    Multiple(Vec<String>),
}

impl Serialize for SingleOrMultipleStrings {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
        where S: Serializer
    {
        use SingleOrMultipleStrings::*;
        match *self {
            Single(ref value) => serializer.serialize_str(value),
            Multiple(ref values) => {
                let mut seq = serializer.serialize_seq(Some(values.len()))?;
                for element in values {
                    seq.serialize_element(element)?;
                }
                seq.end()
            }
        }
    }
}

impl Deserialize for SingleOrMultipleStrings {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
        where D: Deserializer
    {
        struct SingleOrMultipleStringsVisitor;

        impl Visitor for SingleOrMultipleStringsVisitor {
            type Value = SingleOrMultipleStrings;

            fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                write!(formatter, "a string or an array of strings")
            }

            fn visit_str<E>(self, s: &str) -> Result<Self::Value, E>
                where E: de::Error
            {
                Ok(SingleOrMultipleStrings::Single(s.to_string()))
            }

            fn visit_string<E>(self, s: String) -> Result<Self::Value, E>
                where E: de::Error
            {
                Ok(SingleOrMultipleStrings::Single(s))
            }

            fn visit_seq<V>(self, mut visitor: V) -> Result<Self::Value, V::Error>
                where V: de::SeqVisitor
            {
                let capacity_hint = match visitor.size_hint() {
                    (lower, None) => lower,
                    (_, Some(upper)) => upper,
                };

                let mut strings: Vec<String> = Vec::with_capacity(capacity_hint);
                while let Ok(Some(string)) = visitor.visit::<String>() {
                    strings.push(string);
                }
                Ok(SingleOrMultipleStrings::Multiple(strings))
            }
        }

        deserializer.deserialize(SingleOrMultipleStringsVisitor {})
    }
}

/// List of registered claims defined by [RFC7519#4.1](https://tools.ietf.org/html/rfc7519#section-4.1)
pub static REGISTERED_CLAIMS: &'static [&'static str] = &["iss", "sub", "aud", "exp", "nbf", "iat", "jti"];

/// Registered claims defined by [RFC7519#4.1](https://tools.ietf.org/html/rfc7519#section-4.1)
#[derive(Debug, Eq, PartialEq, Serialize, Deserialize, Default)]
pub struct RegisteredClaims {
    // Token issuer. Serialized to `iss`.
    #[serde(rename = "iss", skip_serializing_if = "Option::is_none")]
    pub issuer: Option<String>,

    /// Subject where the JWT is referring to. Serialized to `sub`
    #[serde(rename="sub", skip_serializing_if = "Option::is_none")]
    pub subject: Option<String>,

    /// Audience intended for the JWT. Serialized to `aud`
    #[serde(rename = "aud", skip_serializing_if = "Option::is_none")]
    pub audience: Option<SingleOrMultipleStrings>,

    /// Expiration time in seconds since Unix Epoch. Serialized to `exp`
    #[serde(rename = "exp", skip_serializing_if = "Option::is_none")]
    pub expiry: Option<i64>,

    /// Not before time in seconds since Unix Epoch. Serialized to `nbf`
    #[serde(rename = "nbf", skip_serializing_if = "Option::is_none")]
    pub not_before: Option<i64>,

    /// Issued at Time in seconds since Unix Epoch. Serialized to `iat`
    #[serde(rename="iat", skip_serializing_if = "Option::is_none")]
    pub issued_at: Option<i64>,

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

        if self.expiry.is_some() && !Self::is_after(Self::timestamp_to_datetime(self.expiry.unwrap()), now, e)? {
            Err(ValidationError::TemporalError("Token expired".to_string()))?;
        }

        if self.issued_at.is_some() && !Self::is_before(Self::timestamp_to_datetime(self.issued_at.unwrap()), now, e)? {
            Err(ValidationError::TemporalError("Token issued in the future".to_string()))?;
        }

        if self.not_before.is_some() &&
           !Self::is_before(Self::timestamp_to_datetime(self.not_before.unwrap()),
                            now,
                            e)? {
            Err(ValidationError::TemporalError("Token not valid yet".to_string()))?;
        }

        Ok(())
    }

    fn timestamp_to_datetime(timestamp: i64) -> DateTime<UTC> {
        DateTime::<UTC>::from_utc(chrono::NaiveDateTime::from_timestamp(timestamp, 0), UTC)
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

#[derive(Debug, Eq, PartialEq)]
pub struct ClaimsSet<T: Serialize + Deserialize> {
    /// Registered claims defined by the RFC
    pub registered: RegisteredClaims,
    /// Application specific claims
    pub private: T,
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

impl<T: Serialize + Deserialize> ClaimsSet<T> {
    /// Encode the claims passed and sign the payload using the algorithm from the header and the secret
    /// The secret is dependent on the signing algorithm
    pub fn encode(&self, header: jws::Header, secret: jws::Secret) -> Result<String, Error> {
        let encoded_header = header.to_base64()?;
        let encoded_claims = self.to_base64()?;
        // seems to be a tiny bit faster than format!("{}.{}", x, y)
        let payload = [encoded_header.as_ref(), encoded_claims.as_ref()].join(".");
        let signature = header.algorithm.sign(payload.as_bytes(), secret)?.as_slice().to_base64(base64::URL_SAFE);

        Ok([payload, signature].join("."))
    }

    /// Decode a token into a Claims struct
    /// If the token or its signature is invalid, it will return an error
    pub fn decode(token: &str,
                  secret: jws::Secret,
                  algorithm: jws::Algorithm)
                  -> Result<(jws::Header, ClaimsSet<T>), Error> {
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

        Ok((header, decoded_claims))
    }
}

/// Serializer for `ClaimsSet`.
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
            _ => unreachable!("RegisteredClaims needs to be a Struct"),
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
            others => Err(D::Error::custom(format!("Expected a struct, got {:?}", others)))?,
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

#[cfg(test)]
mod tests {
    use std::default::Default;
    use std::str;
    use std::time::Duration;

    use chrono::{UTC, TimeZone};
    use serde_json;

    use super::{SingleOrMultipleStrings, RegisteredClaims, ClaimsSet, TemporalValidationOptions};
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
            not_before: Some(1234),
            ..Default::default()
        };
        let expected_json = r#"{"iss":"https://www.acme.com","aud":"htts://acme-customer.com","nbf":1234}"#;

        let serialized = not_err!(serde_json::to_string(&claim));
        assert_eq!(expected_json, serialized);

        let deserialized: RegisteredClaims = not_err!(serde_json::from_str(&serialized));
        assert_eq!(deserialized, claim);
    }

    #[test]
    fn claims_set_serialization_round_trip() {
        let claim = ClaimsSet::<PrivateClaims> {
            registered: RegisteredClaims {
                issuer: Some("https://www.acme.com".to_string()),
                subject: Some("John Doe".to_string()),
                audience: Some(SingleOrMultipleStrings::Single("htts://acme-customer.com".to_string())),
                not_before: Some(1234),
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
                not_before: Some(1234),
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
    fn encode_with_additional_header_fields() {
        let expected_claims = ClaimsSet::<PrivateClaims> {
            registered: RegisteredClaims {
                issuer: Some("https://www.acme.com".to_string()),
                subject: Some("John Doe".to_string()),
                audience: Some(SingleOrMultipleStrings::Single("htts://acme-customer.com".to_string())),
                not_before: Some(1234),
                ..Default::default()
            },
            private: PrivateClaims {
                department: "Toilet Cleaning".to_string(),
                company: "ACME".to_string(),
            },
        };

        let mut header = Header::default();
        header.key_id = Some("kid".to_string());
        let token = not_err!(expected_claims.encode(header, Secret::Bytes("secret".to_string().into_bytes())));
        let (actual_headers, actual_claims) =
            not_err!(ClaimsSet::<PrivateClaims>::decode(&token,
                                                        Secret::Bytes("secret".to_string().into_bytes()),
                                                        Algorithm::HS256));
        assert_eq!(expected_claims, actual_claims);
        assert_eq!("kid", actual_headers.key_id.unwrap());
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
                not_before: Some(1234),
                ..Default::default()
            },
            private: PrivateClaims {
                department: "Toilet Cleaning".to_string(),
                company: "ACME".to_string(),
            },
        };

        let token = not_err!(expected_claims.encode(Header { algorithm: Algorithm::HS256, ..Default::default() },
                                                    Secret::Bytes("secret".to_string().into_bytes())));
        assert_eq!(expected_token, token);

        let (_headers, claims) =
            not_err!(ClaimsSet::<PrivateClaims>::decode(&token,
                                                        Secret::Bytes("secret".to_string().into_bytes()),
                                                        Algorithm::HS256));
        assert_eq!(expected_claims, claims);
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
                not_before: Some(1234),
                ..Default::default()
            },
            private: PrivateClaims {
                department: "Toilet Cleaning".to_string(),
                company: "ACME".to_string(),
            },
        };
        let private_key = Secret::RSAKeyPair(::test::read_rsa_private_key());

        let token = not_err!(expected_claims.encode(Header { algorithm: Algorithm::RS256, ..Default::default() },
                                                    private_key));
        assert_eq!(expected_token, token);

        let public_key = Secret::PublicKey(::test::read_rsa_public_key());
        let (_headers, claims) = not_err!(ClaimsSet::<PrivateClaims>::decode(&token, public_key, Algorithm::RS256));
        assert_eq!(expected_claims, claims);
    }

    #[test]
    #[should_panic(expected = "InvalidToken")]
    fn decode_token_missing_parts() {
        let token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9";
        let claims = ClaimsSet::<PrivateClaims>::decode(token,
                                                        Secret::Bytes("secret".to_string().into_bytes()),
                                                        Algorithm::HS256);
        claims.unwrap();
    }

    #[test]
    #[should_panic(expected = "InvalidSignature")]
    fn decode_token_invalid_signature_hs256() {
        let token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.\
                     eyJzdWIiOiJiQGIuY29tIiwiY29tcGFueSI6IkFDTUUifQ.\
                     WRONGWRONGWRONGWRONGWRONGWRONGWRONGWRONG___";
        let claims = ClaimsSet::<PrivateClaims>::decode(token,
                                                        Secret::Bytes("secret".to_string().into_bytes()),
                                                        Algorithm::HS256);
        claims.unwrap();
    }

    #[test]
    #[should_panic(expected = "InvalidSignature")]
    fn decode_token_invalid_signature_rs256() {
        let token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.\
                     eyJzdWIiOiJiQGIuY29tIiwiY29tcGFueSI6IkFDTUUifQ.\
                     WRONGWRONGWRONGWRONGWRONGWRONGWRONGWRONG___";
        let public_key = Secret::PublicKey(::test::read_rsa_public_key());
        let claims = ClaimsSet::<PrivateClaims>::decode(token, public_key, Algorithm::RS256);
        claims.unwrap();
    }

    #[test]
    #[should_panic(expected = "WrongAlgorithmHeader")]
    fn decode_token_wrong_algorithm() {
        let token = "eyJhbGciOiJIUzUxMiIsInR5cCI6IkpXVCJ9.\
                     eyJzdWIiOiJiQGIuY29tIiwiY29tcGFueSI6IkFDTUUifQ.\
                     pKscJVk7-aHxfmQKlaZxh5uhuKhGMAa-1F5IX5mfUwI";
        let claims = ClaimsSet::<PrivateClaims>::decode(token,
                                                        Secret::Bytes("secret".to_string().into_bytes()),
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
            expiry: Some(1),
            not_before: Some(1),
            ..Default::default()
        };
        registered_claims.validate_times(Some(options)).unwrap();
    }

    #[test]
    #[should_panic(expected = "MissingRequired")]
    fn validate_times_missing_exp() {
        let options = TemporalValidationOptions { expiry_required: true, ..Default::default() };

        let registered_claims = RegisteredClaims {
            not_before: Some(1),
            issued_at: Some(1),
            ..Default::default()
        };
        registered_claims.validate_times(Some(options)).unwrap();
    }

    #[test]
    #[should_panic(expected = "MissingRequired")]
    fn validate_times_missing_nbf() {
        let options = TemporalValidationOptions { not_before_required: true, ..Default::default() };

        let registered_claims = RegisteredClaims {
            expiry: Some(1),
            issued_at: Some(1),
            ..Default::default()
        };
        registered_claims.validate_times(Some(options)).unwrap();
    }

    #[test]
    #[should_panic(expected = "TemporalError")]
    fn validate_times_catch_future_token() {
        let options = TemporalValidationOptions { now: Some(UTC.timestamp(0, 0)), ..Default::default() };

        let registered_claims = RegisteredClaims { issued_at: Some(10), ..Default::default() };
        registered_claims.validate_times(Some(options)).unwrap();
    }

    #[test]
    #[should_panic(expected = "TemporalError")]
    fn validate_times_catch_expired_token() {
        let options = TemporalValidationOptions { now: Some(UTC.timestamp(2, 0)), ..Default::default() };

        let registered_claims = RegisteredClaims { expiry: Some(1), ..Default::default() };
        registered_claims.validate_times(Some(options)).unwrap();
    }

    #[test]
    #[should_panic(expected = "TemporalError")]
    fn validate_times_catch_early_token() {
        let options = TemporalValidationOptions { now: Some(UTC.timestamp(0, 0)), ..Default::default() };

        let registered_claims = RegisteredClaims { not_before: Some(1), ..Default::default() };
        registered_claims.validate_times(Some(options)).unwrap();
    }

    #[test]
    fn validate_times_valid_token_with_default_options() {
        let registered_claims = RegisteredClaims { not_before: Some(1), ..Default::default() };
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
            expiry: Some(999),
            not_before: Some(1),
            issued_at: Some(95),
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
            expiry: Some(99),
            not_before: Some(96),
            issued_at: Some(96),
            ..Default::default()
        };
        not_err!(registered_claims.validate_times(Some(options)));
    }
}
