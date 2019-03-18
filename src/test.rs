use serde::de::DeserializeOwned;
use serde::Serialize;
use serde_json;
use std::fmt::Debug;

macro_rules! not_err {
    ($e:expr) => {
        match $e {
            Ok(e) => e,
            Err(e) => panic!("{} failed with {}", stringify!($e), e),
        }
    };
}

macro_rules! assert_matches {
    ($e:expr, $p:pat) => {
        assert_matches!($e, $p, ())
    };
    ($e:expr, $p:pat, $f:expr) => {
        match $e {
            $p => $f,
            e => panic!(
                "{}: Expected pattern {} \ndoes not match {:?}",
                stringify!($e),
                stringify!($p),
                e
            ),
        }
    };
}

/// Tests that `value` can be serialized to JSON, and then back to type `T` and that the deserialized type `T`
/// is equal to the provided `value`.
/// If `expected_json` is provided, it will be deserialized to `T` and checked for equality with `value`.
pub fn assert_serde_json<T>(value: &T, expected_json: Option<&str>)
where
    T: Serialize + DeserializeOwned + Debug + PartialEq,
{
    let serialized = not_err!(serde_json::to_string_pretty(value));
    let deserialized: T = not_err!(serde_json::from_str(&serialized));
    assert_eq!(value, &deserialized);

    if let Some(ref expected_json) = expected_json {
        let deserialized: T = not_err!(serde_json::from_str(expected_json));
        assert_eq!(value, &deserialized);
    }
}
