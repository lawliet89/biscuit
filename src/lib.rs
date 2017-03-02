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
use serde::ser::{SerializeSeq, SerializeStruct};
use serde::de::{self, Visitor};

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

        deserializer.deserialize_map(SingleOrMultipleStringsVisitor {})
    }
}

pub struct ClaimsSet<T: Serialize + Deserialize> {
    registered: RegisteredClaims,
    private: T,
}

#[derive(Debug, Eq, PartialEq, Deserialize)]
// TODO: TEST!
pub struct RegisteredClaims {
    // Issuer
    pub iss: Option<String>,
    /// Subject
    pub sub: Option<String>,
    /// Audience
    pub aud: Option<SingleOrMultipleStrings>,
    /// Expiration time
    pub exp: Option<DateTime<UTC>>,
    /// Not before time
    pub nbf: Option<DateTime<UTC>>,
    /// Issued at Time
    pub iat: Option<DateTime<UTC>>,
    /// JWT ID
    pub jti: Option<String>,
}

impl RegisteredClaims {
    fn count_fields(&self) -> usize {
        macro_rules! count {
            ($field_name:ident) => (
                match self.$field_name {
                    Some(_) => 1,
                    None => 0
                }
            )
        }

        count!(iss) + count!(sub) + count!(aud) + count!(exp) + count!(nbf) + count!(iat) + count!(jti)
    }
}

impl Serialize for RegisteredClaims {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
        where S: Serializer
    {
        let mut struc = serializer.serialize_struct("RegisteredClaims", self.count_fields())?;

        macro_rules! optional {
            ($field_name:ident) => (
                if let Some(ref value) = self.$field_name {
                    struc.serialize_field(stringify!($field_name), value)?;
                }
            )
        }

        optional!(iss);
        optional!(sub);
        optional!(aud);
        optional!(exp);
        optional!(nbf);
        optional!(iat);
        optional!(jti);

        struc.end()
    }
}

#[derive(Debug)]
/// The return type of a successful call to decode(...)
pub struct TokenData<T: Part> {
    pub header: jws::Header,
    pub claims: T,
}

/// Encode the claims passed and sign the payload using the algorithm from the header and the secret
pub fn encode<T: Part>(header: jws::Header, claims: &T, secret: &[u8]) -> Result<String, Error> {
    let encoded_header = header.to_base64()?;
    let encoded_claims = claims.to_base64()?;
    // seems to be a tiny bit faster than format!("{}.{}", x, y)
    let payload = [encoded_header.as_ref(), encoded_claims.as_ref()].join(".");
    let signature = header.alg.sign(&*payload, secret.as_ref())?;

    Ok([payload, signature].join("."))
}

/// Used in decode: takes the result of a rsplit and ensure we only get 2 parts
/// Errors if we don't
macro_rules! expect_two {
    ($iter:expr) => {{
        let mut i = $iter; // evaluate the expr
        match (i.next(), i.next(), i.next()) {
            (Some(first), Some(second), None) => (first, second),
            _ => return Err(Error::InvalidToken)
        }
    }}
}

/// Decode a token into a Claims struct
/// If the token or its signature is invalid, it will return an error
pub fn decode<T: Part>(token: &str, secret: &[u8], algorithm: jws::Algorithm) -> Result<TokenData<T>, Error> {
    let (signature, payload) = expect_two!(token.rsplitn(2, '.'));

    let is_valid = algorithm.verify(signature, payload, secret);

    if !is_valid {
        return Err(Error::InvalidSignature);
    }

    let (claims, header) = expect_two!(payload.rsplitn(2, '.'));

    let header = jws::Header::from_base64(header)?;
    if header.alg != algorithm {
        return Err(Error::WrongAlgorithmHeader);
    }
    let decoded_claims = T::from_base64(claims)?;

    Ok(TokenData {
        header: header,
        claims: decoded_claims,
    })
}

#[cfg(test)]
mod tests {
    use std::str;
    use serde_json;

    use super::{encode, decode, SingleOrMultipleStrings};
    use jws::{Algorithm, Header};

    #[derive(Debug, PartialEq, Clone, Serialize, Deserialize)]
    struct Claims {
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
    fn encode_with_custom_header() {
        let expected_claims = Claims {
            sub: "b@b.com".to_string(),
            company: "ACME".to_string(),
        };
        let mut header = Header::default();
        header.kid = Some("kid".to_string());
        let token = not_err!(encode(header, &expected_claims, "secret".as_ref()));
        let token_data = not_err!(decode::<Claims>(&token, "secret".as_ref(), Algorithm::HS256));
        assert_eq!(expected_claims, token_data.claims);
        assert_eq!("kid", token_data.header.kid.unwrap());
    }

    #[test]
    fn round_trip_rs256() {
        let expected_token = "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.\
                              eyJzdWIiOiJiQGIuY29tIiwiY29tcGFueSI6IkFDTUUifQ.\
                              C35LD5nqS_Gx9KF19E2wwf_KFcQ7TNqZLThivXZMXKWen9XVjr6kIF_fjZoaA-\
                              F9q1QjK4EAG6ZwFO2l3rL7MFsrOJwcCgfSkcnTLFOI_RewEFKSDDrfeZyXwQo4PlYd\
                              q5i2Ue1hxQwbv4MuVcnW1rEPqb04WMo3pS2IpNkJxbiUyWIz_Ze4enPXby8YRbidHfC0eS0CK\
                              7bvycE8RJC0Ynpdf0lnd_5jZmAQjC_imz9bjL_wLZq-ggl8Bbi-sA8VcIQWLTPbrpCuYPDrXkjdxL\
                              VpJXoBNEEkfNryqD9asu2r2tFJXrSVLxZGV9AAtkks7uk1nkyEfHVQiOE6JrNODA";
        let expected_claims = Claims {
            sub: "b@b.com".to_string(),
            company: "ACME".to_string(),
        };
        let private_key = ::test::read_private_key();

        let token = not_err!(encode(Header::new(Algorithm::RS256), &expected_claims, private_key));
        assert_eq!(expected_token, token);

        let token_data = not_err!(decode::<Claims>(&token, private_key, Algorithm::RS256));
        assert_eq!(expected_claims, token_data.claims);
        assert!(token_data.header.kid.is_none());
    }


    #[test]
    fn round_trip_hs256() {
        let expected_token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.\
                              eyJzdWIiOiJiQGIuY29tIiwiY29tcGFueSI6IkFDTUUifQ.\
                              I1BvFoHe94AFf09O6tDbcSB8-jp8w6xZqmyHIwPeSdY";
        let expected_claims = Claims {
            sub: "b@b.com".to_string(),
            company: "ACME".to_string(),
        };

        let token = not_err!(encode(Header::new(Algorithm::HS256),
                                    &expected_claims,
                                    "secret".as_bytes()));
        assert_eq!(expected_token, token);

        let token_data = not_err!(decode::<Claims>(&token, "secret".as_bytes(), Algorithm::HS256));
        assert_eq!(expected_claims, token_data.claims);
        assert!(token_data.header.kid.is_none());
    }

    #[test]
    #[should_panic(expected = "InvalidToken")]
    fn decode_token_missing_parts() {
        let token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9";
        let claims = decode::<Claims>(token, "secret".as_ref(), Algorithm::HS256);
        claims.unwrap();
    }

    #[test]
    #[should_panic(expected = "InvalidSignature")]
    fn decode_token_invalid_signature_hs256() {
        let token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.\
                     eyJzdWIiOiJiQGIuY29tIiwiY29tcGFueSI6IkFDTUUifQ.wrong";
        let claims = decode::<Claims>(token, "secret".as_ref(), Algorithm::HS256);
        claims.unwrap();
    }

    #[test]
    #[should_panic(expected = "InvalidSignature")]
    fn decode_token_invalid_signature_rs256() {
        let token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.\
                     eyJzdWIiOiJiQGIuY29tIiwiY29tcGFueSI6IkFDTUUifQ.wrong";
        let private_key = ::test::read_private_key();
        let claims = decode::<Claims>(token, private_key, Algorithm::RS256);
        claims.unwrap();
    }

    #[test]
    #[should_panic(expected = "WrongAlgorithmHeader")]
    fn decode_token_wrong_algorithm() {
        let token = "eyJhbGciOiJIUzUxMiIsInR5cCI6IkpXVCJ9.\
                     eyJzdWIiOiJiQGIuY29tIiwiY29tcGFueSI6IkFDTUUifQ.\
                     pKscJVk7-aHxfmQKlaZxh5uhuKhGMAa-1F5IX5mfUwI";
        let claims = decode::<Claims>(token, "secret".as_ref(), Algorithm::HS256);
        claims.unwrap();
    }

    #[test]
    fn decode_token_with_bytes_secret_hs256() {
        let token = "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.\
                     eyJzdWIiOiIxMjM0NTY3ODkwIiwiY29tcGFueSI6Ikdvb2dvbCJ9.\
                     27QxgG96vpX4akKNpD1YdRGHE3_u2X35wR3EHA2eCrs";
        let claims = decode::<Claims>(token, b"\x01\x02\x03", Algorithm::HS256);
        assert!(claims.is_ok());
    }

    #[test]
    fn decode_token_with_shuffled_header_fields() {
        let token = "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.\
                     eyJjb21wYW55IjoiMTIzNDU2Nzg5MCIsInN1YiI6IkpvaG4gRG9lIn0.\
                     SEIZ4Jg46VGhquuwPYDLY5qHF8AkQczF14aXM3a2c28";
        let claims = decode::<Claims>(token, "secret".as_ref(), Algorithm::HS256);
        assert!(claims.is_ok());
    }
}
