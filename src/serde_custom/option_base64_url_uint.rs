//! Serialize and Deserialize `num_bigint::BigUint` into `Base64urlUInt` form as described in
//! [RFC 7518](https://tools.ietf.org/html/rfc7518)
use std::fmt;

use data_encoding::base64url;
use num::BigUint;
use serde::{Serializer, Deserializer};
use serde::de;

pub fn serialize<S>(value: &Option<BigUint>, serializer: S) -> Result<S::Ok, S::Error>
    where S: Serializer
{
    match *value {
        Some(ref value) => {
            let bytes = value.to_bytes_be();
            let base64 = base64url::encode_nopad(bytes.as_slice());
            serializer.serialize_some(&base64)
        },
        None => serializer.serialize_none()
    }
}

pub fn deserialize<D>(deserializer: D) -> Result<Option<BigUint>, D::Error>
    where D: Deserializer
{
    struct BigUintVisitor;

    impl de::Visitor for BigUintVisitor {
        type Value = Option<BigUint>;

        fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
            formatter.write_str("a Base64urlUInt string")
        }

        fn visit_none<E>(self) -> Result<Self::Value, E>
            where E: de::Error {

            Ok(None)
        }

        fn visit_some<D>(self, deserializer: D) -> Result<Self::Value, D::Error>
            where D: Deserializer {

            deserializer.deserialize_str(self)
        }

        fn visit_str<E>(self, value: &str) -> Result<Self::Value, E>
            where E: de::Error
        {
            let bytes = base64url::decode_nopad(value.as_bytes()).map_err(E::custom)?;
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
    use serde_test::{Token, assert_tokens};

    #[derive(Serialize, Deserialize, Eq, PartialEq, Debug)]
    struct TestStruct {
        #[serde(with = "super")]
        bytes: Option<BigUint>,
    }

    #[test]
    fn some_serialization_round_trip() {
        let test_value = TestStruct { bytes: Some(BigUint::from_u64(12345).unwrap()) };

        assert_tokens(&test_value,
                      &[Token::StructStart("TestStruct", 1),
                        Token::StructSep,
                        Token::Str("bytes"),
                        Token::Option(true),
                        Token::Str("MDk"),

                        Token::StructEnd]);
    }

    #[test]
    fn none_serialization_round_trip() {
        let test_value = TestStruct { bytes: None };

        assert_tokens(&test_value,
                      &[Token::StructStart("TestStruct", 1),
                        Token::StructSep,
                        Token::Str("bytes"),
                        Token::Option(false),

                        Token::StructEnd]);
    }

    #[test]
    fn some_json_serialization_round_trip() {
        let test_value = TestStruct { bytes: Some(BigUint::from_u64(12345).unwrap()) };
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
