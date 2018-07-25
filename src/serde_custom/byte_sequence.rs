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

        fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
            formatter.write_str("a URL safe base64 encoding of a byte sequence")
        }

        fn visit_str<E>(self, value: &str) -> Result<Self::Value, E>
        where
            E: de::Error,
        {
            let bytes = BASE64URL_NOPAD.decode(value.as_bytes()).map_err(E::custom)?;
            Ok(bytes)
        }
    }

    deserializer.deserialize_str(BytesVisitor)
}

#[cfg(test)]
mod tests {
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
}
