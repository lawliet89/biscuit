//! Serialize a sequence of bytes as base64 URL encoding vice-versa for deserialization
use std::fmt;

use data_encoding::base64url;
use serde::{Serializer, Deserializer};
use serde::de;

pub fn serialize<S>(value: &[u8], serializer: S) -> Result<S::Ok, S::Error>
    where S: Serializer
{
    let base64 = base64url::encode_nopad(value);
    serializer.serialize_str(&base64)
}

pub fn deserialize<D>(deserializer: D) -> Result<Vec<u8>, D::Error>
    where D: Deserializer
{
    struct BytesVisitor;

    impl de::Visitor for BytesVisitor {
        type Value = Vec<u8>;

        fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
            formatter.write_str("a URL safe base64 encoding of a byte sequence")
        }

        fn visit_str<E>(self, value: &str) -> Result<Self::Value, E>
            where E: de::Error
        {
            let bytes = base64url::decode_nopad(value.as_bytes()).map_err(E::custom)?;
            Ok(bytes)
        }
    }

    deserializer.deserialize_str(BytesVisitor)
}

#[cfg(test)]
mod tests {
    use serde_test::{Token, assert_tokens};

    #[derive(Serialize, Deserialize, Eq, PartialEq, Debug)]
    struct TestStruct {
        #[serde(with = "super")]
        bytes: Vec<u8>,
    }

    #[test]
    fn serialization_round_trip() {
        let test_value = TestStruct { bytes: "hello world".to_string().into_bytes() };

        assert_tokens(&test_value,
                      &[Token::StructStart("TestStruct", 1),
                        Token::StructSep,
                        Token::Str("bytes"),
                        Token::Str("aGVsbG8gd29ybGQ"),

                        Token::StructEnd]);
    }
}
