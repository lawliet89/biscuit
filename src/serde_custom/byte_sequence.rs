//! Serialize a sequence of bytes as base64 URL encoding vice-versa for deserialization
use std::fmt;

use data_encoding::BASE64URL_NOPAD;
use serde::de;
use serde::{Deserializer, Serializer};

/// Serialize a byte sequence into Base64 URL encoded string
pub fn serialize<S>(value: &[u8], serializer: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    let base64 = BASE64URL_NOPAD.encode(value);
    serializer.serialize_str(&base64)
}

/// Deserialize a byte sequence from Base64 URL encoded string
pub fn deserialize<'de, D>(deserializer: D) -> Result<Vec<u8>, D::Error>
where
    D: Deserializer<'de>,
{
    struct BytesVisitor;

    impl<'de> de::Visitor<'de> for BytesVisitor {
        type Value = Vec<u8>;

        fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
            formatter.write_str("a URL safe base64 encoding of a byte sequence")
        }

        fn visit_str<E>(self, value: &str) -> Result<Self::Value, E>
        where
            E: de::Error,
        {
            let bytes = BASE64URL_NOPAD
                .decode(value.as_bytes())
                .map_err(E::custom)?;
            Ok(bytes)
        }
    }

    deserializer.deserialize_str(BytesVisitor)
}

pub struct Wrapper<'a>(&'a [u8]);

pub fn wrap(data: &[u8]) -> Wrapper<'_> {
    Wrapper(data)
}

impl<'a> serde::Serialize for Wrapper<'a> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serialize(self.0, serializer)
    }
}

#[cfg(test)]
mod tests {
    use serde::{Deserialize, Serialize};
    use serde_test::{assert_tokens, Token};

    #[derive(Serialize, Deserialize, Eq, PartialEq, Debug)]
    struct TestStruct {
        #[serde(with = "super")]
        bytes: Vec<u8>,
    }

    #[test]
    fn serialization_round_trip() {
        let test_value = TestStruct {
            bytes: "hello world".to_string().into_bytes(),
        };

        assert_tokens(
            &test_value,
            &[
                Token::Struct {
                    name: "TestStruct",
                    len: 1,
                },
                Token::Str("bytes"),
                Token::Str("aGVsbG8gd29ybGQ"),
                Token::StructEnd,
            ],
        );
    }

    #[test]
    fn empty_bytes_serialization_round_trip() {
        let test_value = TestStruct { bytes: vec![] };
        let expected_json = r#"{"bytes":""}"#;

        let serialized = not_err!(serde_json::to_string(&test_value));
        assert_eq!(expected_json, serialized);

        let deserialized: TestStruct = not_err!(serde_json::from_str(&serialized));
        assert_eq!(test_value, deserialized);
    }

    #[test]
    fn wrap_serializes_to_base64url() {
        let bytes = b"hello world";
        let wrapped = super::wrap(bytes);
        let json = not_err!(serde_json::to_string(&wrapped));
        assert_eq!(r#""aGVsbG8gd29ybGQ""#, json);
    }

    #[test]
    fn invalid_base64_deserialization_fails() {
        let invalid_json = r#"{"bytes":"!@#$%^"}"#;
        let result: Result<TestStruct, _> = serde_json::from_str(invalid_json);
        assert!(result.is_err());
    }
}
