//! Serialize and Deserialize `num_bigint::BigUint` into `Base64urlUInt` form as described in
//! [RFC 7518](https://tools.ietf.org/html/rfc7518).
//! The integers are first converted into bytes in big-endian form and then base64 encoded.
use std::fmt;

use data_encoding::BASE64URL_NOPAD;
use num::BigUint;
use serde::{Deserializer, Serializer};
use serde::de;

/// Serialize a `BigUint` into Base64 URL encoded big endian bytes
pub fn serialize<S>(value: &Option<BigUint>, serializer: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    match *value {
        Some(ref value) => {
            let bytes = value.to_bytes_be();
            let base64 = BASE64URL_NOPAD.encode(bytes.as_slice());
            serializer.serialize_some(&base64)
        }
        None => serializer.serialize_none(),
    }
}

/// Deserialize a `BigUint` from Base64 URL encoded big endian bytes
pub fn deserialize<'de, D>(deserializer: D) -> Result<Option<BigUint>, D::Error>
where
    D: Deserializer<'de>,
{
    struct BigUintVisitor;

    impl<'de> de::Visitor<'de> for BigUintVisitor {
        type Value = Option<BigUint>;

        fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
            formatter.write_str("a Base64urlUInt string")
        }

        fn visit_none<E>(self) -> Result<Self::Value, E>
        where
            E: de::Error,
        {
            Ok(None)
        }

        fn visit_some<D>(self, deserializer: D) -> Result<Self::Value, D::Error>
        where
            D: Deserializer<'de>,
        {
            deserializer.deserialize_str(self)
        }

        fn visit_str<E>(self, value: &str) -> Result<Self::Value, E>
        where
            E: de::Error,
        {
            let bytes = BASE64URL_NOPAD.decode(value.as_bytes()).map_err(E::custom)?;
            Ok(Some(BigUint::from_bytes_be(&bytes)))
        }
    }

    deserializer.deserialize_option(BigUintVisitor)
}

#[cfg(test)]
mod tests {
    use num::BigUint;
    use num::cast::FromPrimitive;
    use serde_json;
    use serde_test::{assert_tokens, Token};

    #[derive(Serialize, Deserialize, Eq, PartialEq, Debug)]
    struct TestStruct {
        #[serde(with = "super")]
        bytes: Option<BigUint>,
    }

    #[test]
    fn some_serialization_round_trip() {
        let test_value = TestStruct {
            bytes: Some(BigUint::from_u64(12345).unwrap()),
        };

        assert_tokens(
            &test_value,
            &[
                Token::Struct {
                    name: "TestStruct",
                    len: 1,
                },
                Token::Str("bytes"),
                Token::Some,
                Token::Str("MDk"),
                Token::StructEnd,
            ],
        );
    }

    #[test]
    fn none_serialization_round_trip() {
        let test_value = TestStruct { bytes: None };

        assert_tokens(
            &test_value,
            &[
                Token::Struct {
                    name: "TestStruct",
                    len: 1,
                },
                Token::Str("bytes"),
                Token::None,
                Token::StructEnd,
            ],
        );
    }

    #[test]
    fn some_json_serialization_round_trip() {
        let test_value = TestStruct {
            bytes: Some(BigUint::from_u64(12345).unwrap()),
        };
        let expected_json = r#"{"bytes":"MDk"}"#;

        let actual_json = not_err!(serde_json::to_string(&test_value));
        assert_eq!(expected_json, actual_json);

        let deserialized_value: TestStruct = not_err!(serde_json::from_str(&actual_json));
        assert_eq!(test_value, deserialized_value);
    }

    #[test]
    fn none_json_serialization_round_trip() {
        let test_value = TestStruct { bytes: None };
        let expected_json = r#"{"bytes":null}"#;

        let actual_json = not_err!(serde_json::to_string(&test_value));
        assert_eq!(expected_json, actual_json);

        let deserialized_value: TestStruct = not_err!(serde_json::from_str(&actual_json));
        assert_eq!(test_value, deserialized_value);
    }
}
