//! Serialize and Deserialize `num_bigint::BigUint` into `Base64urlUInt` form as described in
//! [RFC 7518](https://tools.ietf.org/html/rfc7518)
use std::fmt;

use data_encoding::base64url;
use num::BigUint;
use serde::{Serializer, Deserializer};
use serde::de;

pub fn serialize<S>(value: &BigUint, serializer: S) -> Result<S::Ok, S::Error>
    where S: Serializer
{
    let bytes = value.to_bytes_be();
    let base64 = base64url::encode_nopad(bytes.as_slice());
    serializer.serialize_str(&base64)
}

pub fn deserialize<D>(deserializer: D) -> Result<BigUint, D::Error>
    where D: Deserializer
{
    struct BigUintVisitor;

    impl de::Visitor for BigUintVisitor {
        type Value = BigUint;

        fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
            formatter.write_str("a Base64urlUInt string")
        }

        fn visit_str<E>(self, value: &str) -> Result<Self::Value, E>
            where E: de::Error
        {
            let bytes = base64url::decode_nopad(value.as_bytes()).map_err(E::custom)?;
            Ok(BigUint::from_bytes_be(&bytes))
        }
    }

    deserializer.deserialize_str(BigUintVisitor)
}

#[cfg(test)]
mod tests {
    use num::BigUint;
    use num::cast::FromPrimitive;
    use serde_test::{Token, assert_tokens};

    #[derive(Serialize, Deserialize, Eq, PartialEq, Debug)]
    struct TestStruct {
        #[serde(with = "super")]
        bytes: BigUint,
    }

    #[test]
    fn serialization_round_trip() {
        let test_value = TestStruct { bytes: BigUint::from_u64(12345).unwrap() };

        assert_tokens(&test_value,
                      &[Token::StructStart("TestStruct", 1),
                        Token::StructSep,
                        Token::Str("bytes"),
                        Token::Str("MDk"),

                        Token::StructEnd]);
    }
}
