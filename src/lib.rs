//! Create and parses JWT (JSON Web Tokens)
//!

// #![warn(missing_docs)]
#![doc(test(attr(allow(unused_variables), deny(warnings))))]

extern crate rustc_serialize;
extern crate ring;
extern crate serde;
#[macro_use]
extern crate serde_derive;
extern crate serde_json;
extern crate untrusted;

use std::fmt;

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

use errors::Error;

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
                Ok(SingleOrMultipleStrings::Single(s.to_string()))
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

pub static REGISTERED_CLAIMS: &'static [&'static str] = &["iss", "sub", "aud", "exp", "nbf", "iat", "jti"];

#[derive(Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct RegisteredClaims {
    // Issuer
    #[serde(skip_serializing_if = "Option::is_none")]
    pub iss: Option<String>,
    /// Subject
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sub: Option<String>,
    /// Audience
    #[serde(skip_serializing_if = "Option::is_none")]
    pub aud: Option<SingleOrMultipleStrings>,
    /// Expiration time in seconds since Unix Epoch
    #[serde(skip_serializing_if = "Option::is_none")]
    pub exp: Option<u64>,
    /// Not before time in seconds since Unix Epoch
    #[serde(skip_serializing_if = "Option::is_none")]
    pub nbf: Option<u64>,
    /// Issued at Time in seconds since Unix Epoch
    #[serde(skip_serializing_if = "Option::is_none")]
    pub iat: Option<u64>,
    /// JWT ID
    #[serde(skip_serializing_if = "Option::is_none")]
    pub jti: Option<String>,
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
            _ => Err(Error::InvalidToken)
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
        let signature = header.alg.sign(payload.as_bytes(), secret)?.as_slice().to_base64(base64::URL_SAFE);

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
            return Err(Error::InvalidSignature);
        }

        let (claims, header) = expect_two!(payload.rsplitn(2, '.'))?;

        let header = jws::Header::from_base64(header)?;
        if header.alg != algorithm {
            return Err(Error::WrongAlgorithmHeader);
        }
        let decoded_claims = ClaimsSet::<T>::from_base64(claims)?;

        Ok((header, decoded_claims))
    }
}

/// Serializer for ClaimsSet.
impl<T: Serialize + Deserialize> Serialize for ClaimsSet<T> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
        where S: Serializer
    {
        use serde::ser::Error;

        // A "hack" to combine two structs into one serialized JSON
        // First, we serialize each of them into JSON Value enum
        let registered = value::to_value(&self.registered).map_err(|e| S::Error::custom(e))?;
        let private = value::to_value(&self.private).map_err(|e| S::Error::custom(e))?;

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
        for (key, value) in private.into_iter() {
            if REGISTERED_CLAIMS.iter().any(|claim| *claim == key) {
                Err(S::Error::custom(format!("Private claims has registered claim `{}`", key)))?
            }
            if let Some(_) = registered.insert(key.clone(), value) {
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
            others @ _ => Err(D::Error::custom(format!("Expected a struct, got {:?}", others)))?,
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
    use std::str;
    use serde_json;

    use super::{SingleOrMultipleStrings, RegisteredClaims, ClaimsSet};
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
        let claim = RegisteredClaims {
            iss: None,
            sub: None,
            aud: None,
            exp: None,
            nbf: None,
            iat: None,
            jti: None,
        };
        let expected_json = "{}";

        let serialized = not_err!(serde_json::to_string(&claim));
        assert_eq!(expected_json, serialized);

        let deserialized: RegisteredClaims = not_err!(serde_json::from_str(&serialized));
        assert_eq!(deserialized, claim);
    }

    #[test]
    fn registered_claims_serialization_round_trip() {
        let claim = RegisteredClaims {
            iss: Some("https://www.acme.com".to_string()),
            sub: None,
            aud: Some(SingleOrMultipleStrings::Single("htts://acme-customer.com".to_string())),
            exp: None,
            nbf: Some(1234),
            iat: None,
            jti: None,
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
                iss: Some("https://www.acme.com".to_string()),
                sub: Some("John Doe".to_string()),
                aud: Some(SingleOrMultipleStrings::Single("htts://acme-customer.com".to_string())),
                exp: None,
                nbf: Some(1234),
                iat: None,
                jti: None,
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
    fn encode_with_custom_header() {
        let expected_claims = ClaimsSet::<PrivateClaims> {
            registered: RegisteredClaims {
                iss: Some("https://www.acme.com".to_string()),
                sub: Some("John Doe".to_string()),
                aud: Some(SingleOrMultipleStrings::Single("htts://acme-customer.com".to_string())),
                exp: None,
                nbf: Some(1234),
                iat: None,
                jti: None,
            },
            private: PrivateClaims {
                department: "Toilet Cleaning".to_string(),
                company: "ACME".to_string(),
            },
        };

        let mut header = Header::default();
        header.kid = Some("kid".to_string());
        let token = not_err!(expected_claims.encode(header, Secret::Bytes("secret".to_string().into_bytes())));
        let (actual_headers, actual_claims) =
            not_err!(ClaimsSet::<PrivateClaims>::decode(&token,
                                                        Secret::Bytes("secret".to_string().into_bytes()),
                                                        Algorithm::HS256));
        assert_eq!(expected_claims, actual_claims);
        assert_eq!("kid", actual_headers.kid.unwrap());
    }

    #[test]
    fn round_trip_hs256() {
        let expected_token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.\
        eyJpc3MiOiJodHRwczovL3d3dy5hY21lLmNvbSIsInN1YiI6IkpvaG4gRG9lIiwiYXVkIjoiaHR0czovL2FjbWUt\
        Y3VzdG9tZXIuY29tIiwibmJmIjoxMjM0LCJjb21wYW55IjoiQUNNRSIsImRlcGFydG1lbnQiOiJUb2lsZXQgQ2xlYW5pbmcifQ.\
        u3ORB8my861WsYulP6UE_m2nwSDo3uu3K0ylCRjCiFw";

        let expected_claims = ClaimsSet::<PrivateClaims> {
            registered: RegisteredClaims {
                iss: Some("https://www.acme.com".to_string()),
                sub: Some("John Doe".to_string()),
                aud: Some(SingleOrMultipleStrings::Single("htts://acme-customer.com".to_string())),
                exp: None,
                nbf: Some(1234),
                iat: None,
                jti: None,
            },
            private: PrivateClaims {
                department: "Toilet Cleaning".to_string(),
                company: "ACME".to_string(),
            },
        };

        let token = not_err!(expected_claims.encode(Header::new(Algorithm::HS256),
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
                iss: Some("https://www.acme.com".to_string()),
                sub: Some("John Doe".to_string()),
                aud: Some(SingleOrMultipleStrings::Single("htts://acme-customer.com".to_string())),
                exp: None,
                nbf: Some(1234),
                iat: None,
                jti: None,
            },
            private: PrivateClaims {
                department: "Toilet Cleaning".to_string(),
                company: "ACME".to_string(),
            },
        };
        let private_key = Secret::RSAKeyPair(::test::read_private_key());

        let token = not_err!(expected_claims.encode(Header::new(Algorithm::RS256), private_key));
        assert_eq!(expected_token, token);

        let public_key = Secret::PublicKey(::test::read_public_key());
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
        let public_key = Secret::PublicKey(::test::read_public_key());
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
}
