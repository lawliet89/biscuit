//! Serialize or deserialize an Option<Vec<u8>>
use std::fmt;

use data_encoding::base64url;
use serde::{Serializer, Deserializer};
use serde::de;

pub fn serialize<S>(value: &Option<Vec<u8>>, serializer: S) -> Result<S::Ok, S::Error>
    where S: Serializer
{
    match *value {
        Some(ref value) => {
            let base64 = base64url::encode_nopad(value.as_slice());
            serializer.serialize_some(&base64)
        },
        None => serializer.serialize_none()
    }

}

pub fn deserialize<D>(deserializer: D) -> Result<Option<Vec<u8>>, D::Error>
    where D: Deserializer
{
    struct BytesVisitor;

    impl de::Visitor for BytesVisitor {
        type Value = Option<Vec<u8>>;

        fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
            formatter.write_str("a URL safe base64 encoding of a byte sequence")
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
            Ok(Some(bytes))
        }
    }

    deserializer.deserialize_option(BytesVisitor)
}

#[cfg(test)]
mod tests {
    use serde_json;
    use serde_test::{Token, assert_tokens};

    #[derive(Serialize, Deserialize, Eq, PartialEq, Debug)]
    struct TestStruct {
        #[serde(with = "super")]
        bytes: Option<Vec<u8>>,
    }

    #[test]
    fn some_serialization_round_trip() {
        let test_value = TestStruct { bytes: Some("hello world".to_string().into_bytes()) };

        assert_tokens(&test_value,
                      &[Token::StructStart("TestStruct", 1),
                        Token::StructSep,
                        Token::Str("bytes"),
                        Token::Option(true),
                        Token::Str("aGVsbG8gd29ybGQ"),

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
        let test_value = TestStruct { bytes: Some("hello world".to_string().into_bytes()) };
        let expected_json = r#"{"bytes":"aGVsbG8gd29ybGQ"}"#;

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
