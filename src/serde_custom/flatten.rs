//! A "flattened" serializer and deserializer.
//!
//! This serializer will take a struct, and then flatten all its first-level children. The implementation makes use
//! of some macros to enable implementation
//!
//! # Examples
//! ## Non-generic
//!
//! ```rust,ignore
//! #[macro_use]
//! extern crate biscuit;
//! extern crate serde;
//! extern crate serde_json;
//! #[macro_use]
//! extern crate serde_derive;
//!
//! #[derive(Eq, PartialEq, Debug, Clone, Serialize, Deserialize, Default)]
//! struct InnerOne {
//!     a: i32,
//!     b: i32,
//!     c: i32,
//!     d: InnerTwo,
//! }
//!
//! #[derive(Eq, PartialEq, Debug, Clone, Serialize, Deserialize, Default)]
//! struct InnerTwo {
//!     a: bool,
//!     e: bool,
//!     f: u32,
//! }
//!
//! #[derive(Eq, PartialEq, Debug, Clone, Serialize, Deserialize, Default)]
//! struct InnerThree {
//!     g: bool,
//!     h: bool,
//!     i: bool,
//! }
//!
//! #[derive(Eq, PartialEq, Debug, Clone, Default)]
//! struct Outer {
//!     one: InnerOne,
//!     three: InnerThree
//! }
//!
//! impl_flatten_serde!(Outer, biscuit::serde_custom::flatten::DuplicateKeysBehaviour::Overwrite, one, three);
//!
//! # fn main() {
//! let test_value = Outer::default();
//! let expected_json = r#"{
//!   "a": 0,
//!   "b": 0,
//!   "c": 0,
//!   "d": {
//!     "a": false,
//!     "e": false,
//!     "f": 0
//!   },
//!   "g": false,
//!   "h": false,
//!   "i": false
//! }"#;
//! let serialized = serde_json::to_string_pretty(&test_value).unwrap();
//! assert_eq!(expected_json, serialized);
//!
//! let deserialized: Outer = serde_json::from_str(&serialized).unwrap();
//! assert_eq!(deserialized, test_value);
//! # }
//! ```
//!
//! # Generics
//!
//! ```rust,ignore
//! #[macro_use]
//! extern crate biscuit;
//! extern crate serde;
//! extern crate serde_json;
//! #[macro_use]
//! extern crate serde_derive;
//!
//! use serde::{Serialize, Deserialize};
//!
//! #[derive(Eq, PartialEq, Debug, Clone, Serialize, Deserialize, Default)]
//! struct InnerOne {
//!     a: i32,
//!     b: i32,
//!     c: i32,
//!     d: InnerTwo,
//! }
//!
//! #[derive(Eq, PartialEq, Debug, Clone, Serialize, Deserialize, Default)]
//! struct InnerTwo {
//!     a: bool,
//!     e: bool,
//!     f: u32,
//! }
//!
//! #[derive(Eq, PartialEq, Debug, Clone, Serialize, Deserialize, Default)]
//! struct InnerThree {
//!     g: bool,
//!     h: bool,
//!     i: bool,
//! }
//!
//! #[derive(Eq, PartialEq, Debug, Clone, Default)]
//! struct Outer<T: Serialize + Deserialize> {
//!     one: InnerOne,
//!     generic: T
//! }
//!
//! impl_flatten_serde_generic!(Outer<T>, biscuit::serde_custom::flatten::DuplicateKeysBehaviour::Overwrite,
//!                             one, generic);
//!
//! # fn main() {
//! let test_value = Outer::<InnerThree>::default();
//! let expected_json = r#"{
//!   "a": 0,
//!   "b": 0,
//!   "c": 0,
//!   "d": {
//!     "a": false,
//!     "e": false,
//!     "f": 0
//!   },
//!   "g": false,
//!   "h": false,
//!   "i": false
//! }"#;
//! let serialized = serde_json::to_string_pretty(&test_value).unwrap();
//! assert_eq!(expected_json, serialized);
//!
//! let deserialized: Outer<InnerThree> = serde_json::from_str(&serialized).unwrap();
//! assert_eq!(deserialized, test_value);
//! # }
//! ```
use std::collections::HashSet;
use std::hash::Hash;

use serde::{Serialize, Serializer};
use serde_json;
use serde_json::map::Map;
use serde_json::value::{Value, to_value};

/// Representation of any serializable data as a `serde_json::Value`.
/// Stop gap trait since `serde_json` removed it: https://github.com/serde-rs/json/issues/294
// FIXME: See if we can use something else
pub trait ToJson {
    /// Represent `self` as a `serde_json::Value`. Note that `Value` is not a
    /// JSON string. If you need a string, use `serde_json::to_string` instead.
    ///
    /// This conversion can fail if `T`'s implementation of `Serialize` decides
    /// to fail, or if `T` contains a map with non-string keys.
    fn to_json(&self) -> Result<Value, serde_json::Error>;
}

impl<T: ?Sized> ToJson for T
    where T: Serialize
{
    fn to_json(&self) -> Result<Value, serde_json::Error> {
        to_value(self)
    }
}

/// The behaviour the serializer should adopt when encountering duplicate keys
#[derive(Eq, PartialEq, Clone, Copy)]
pub enum DuplicateKeysBehaviour {
    /// Raise an error when a duplicate key is encountered
    RaiseError,
    /// Overwrite the keys encountered earlier with the ones encountered later. If the types of the values of the
    /// duplicated keys differ, this type will probably fail deserialization
    #[allow(dead_code)]
    Overwrite,
}

/// A trait that allows a struct to be serialized flattened.
pub trait FlattenSerializable {
    /// Yield references to children that needs serializing. The order matters. The later children who have
    /// duplicate keys will overwrite earlier keys, or raise errors, depending on the `duplicate_keys` behaviour.
    fn yield_children(&self) -> Vec<Box<&ToJson>>;

    /// The behaviour the serializer should adopt when encountering duplicate keys. The default implementation
    /// is to raise errors.
    fn duplicate_keys(&self) -> DuplicateKeysBehaviour {
        DuplicateKeysBehaviour::RaiseError
    }

    fn serialize_internal<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
        where S: Serializer
    {
        use serde::ser::Error;

        // A "hack" to combine structs into one serialized JSON
        // First, we serialize each of them into JSON Value enum
        let value_maps: Vec<Result<Value, String>> = self.yield_children()
            .iter()
            .map(|child| child.to_json().map_err(|e| e.to_string()))
            .collect();

        let (value_maps, errors): (Vec<_>, Vec<_>) = value_maps.into_iter().partition(Result::is_ok);

        if !errors.is_empty() {
            let errors: Vec<String> = errors.into_iter().map(|r| r.unwrap_err()).collect();
            Err(S::Error::custom(errors.join("; ")))?;
        }

        let value_maps: Vec<Map<String, Value>> = value_maps
            .into_iter()
            .map(|r| r.unwrap())
            .map(|value| match value {
                     Value::Object(map) => map,
                     _ => unreachable!("Child was not a struct: {:?}", value),
                 })
            .collect();

        if let DuplicateKeysBehaviour::RaiseError = self.duplicate_keys() {
            // We need to check for duplicate keys
            let keys: Vec<HashSet<String>> = value_maps
                .iter()
                .map(|k| k.keys().cloned().collect())
                .collect();
            if pairwise_intersection(keys.as_slice()) {
                Err(S::Error::custom("Structs have duplicate keys"))?
            }
        }

        let map: Map<String, Value> = value_maps
            .into_iter()
            .flat_map(|m| m.into_iter())
            .collect();
        map.serialize(serializer)
    }
}

/// Check if n sets have any pairwise intersection, at all
///
/// If n is less than two, this returns `false`. This operation should be O(n) where n is the total number of elements
fn pairwise_intersection<T: Hash + Eq + Clone>(sets: &[HashSet<T>]) -> bool {
    let sets: Vec<&HashSet<T>> = sets.iter().collect();
    if sets.len() < 2 {
        return false;
    }
    let size = sets.iter().fold(0, |acc, x| x.len() + acc);

    let mut all: HashSet<T> = HashSet::with_capacity(size);
    for set in sets {
        for key in set {
            if !all.insert(key.clone()) {
                return true;
            }
        }
    }
    false
}

/// Implement flatten serialization for a struct.
/// Due to the way the type system is set up, we cannot do a blanket
/// `impl <T: FlattenSerializable> Serialize for T`. This is just a wrapper to get around that problem.
/// The first parameter is the type of the struct you want to implement for, followed by `DuplicateKeysBehaviour`,
/// followed by the names of the children.
/// See module level documentation for `serde_custom::flatten`.
// TODO: Procedural macro
macro_rules! impl_flatten_serialize {
    ($t:ty, $behaviour:expr, $( $child:ident ),*) => {
        impl $crate::serde_custom::flatten::FlattenSerializable for $t {
            fn yield_children(&self) -> Vec<Box<&$crate::serde_custom::flatten::ToJson>> {
                vec![$( Box::<&$crate::serde_custom::flatten::ToJson>::new(&self.$child) ),*]
            }

            fn duplicate_keys(&self) -> $crate::serde_custom::flatten::DuplicateKeysBehaviour {
                $behaviour
            }
        }

        impl serde::Serialize for $t {
            fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
                where S: serde::Serializer
            {
                use $crate::serde_custom::flatten::FlattenSerializable;

                self.serialize_internal(serializer)
            }
        }
    };
}

/// Implement flatten deserialization for a struct.
/// Due to the way the type system is set up, there is no way to define a trait and then have an automatic
/// implementation of the trait.
/// The first parameter is the type of the struct you want to implement for, followed by the names of the children.
/// See module level documentation for `serde_custom::flatten`.
// TODO: Procedural macro
macro_rules! impl_flatten_deserialize {
    ($t:ty, $( $child:ident ),*) => {
        impl<'de> serde::Deserialize<'de> for $t {
            fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
                where D: serde::Deserializer<'de>
            {
                use serde::de::Error;

                let value: serde_json::value::Value = serde::Deserialize::deserialize(deserializer)?;
                Ok(Self {
                    $( $child: serde_json::from_value(value.clone()).map_err(D::Error::custom)? ),*
                })
            }
        }
    }
}

/// Implement flatten serde for a struct.
/// Due to the way the type system is set up, we cannot do a blanket
/// `impl <T: FlattenSerializable> Serialize for T`. This is just a wrapper to get around that problem.
/// Neither can we do the same for deserialization.
/// The first parameter is the type of the struct you want to implement for, followed by the names of the children.
/// See module level documentation for `serde_custom::flatten`.
macro_rules! impl_flatten_serde {
    ($t:ty, $behaviour:expr, $( $child:ident ),*) => {
        impl_flatten_serialize!($t, $behaviour, $( $child ),*);
        impl_flatten_deserialize!($t, $( $child ),*);
    }
}

/// Implement flatten serialization for a struct with a generic type `T: Serialize + Deserialize`.
/// Due to the way the type system is set up, we cannot do a blanket
/// `impl <T: FlattenSerializable> Serialize for T`. This is just a wrapper to get around that problem.
/// The first parameter is the type of the struct you want to implement for, followed by `DuplicateKeysBehaviour`,
/// followed by the names of the children.
/// See module level documentation for `serde_custom::flatten`.
// TODO: Procedural macro
macro_rules! impl_flatten_serialize_generic {
    ($t:ty, $behaviour:expr, $( $child:ident ),*) => {
        impl<T> $crate::serde_custom::flatten::FlattenSerializable for $t
            where T: Serialize + for<'de_inner> Deserialize<'de_inner>
        {
            fn yield_children(&self) -> Vec<Box<&$crate::serde_custom::flatten::ToJson>> {
                vec![$( Box::<&$crate::serde_custom::flatten::ToJson>::new(&self.$child) ),*]
            }

            fn duplicate_keys(&self) -> $crate::serde_custom::flatten::DuplicateKeysBehaviour {
                $behaviour
            }
        }

        impl<T: Serialize + for<'de_inner> Deserialize<'de_inner>> serde::Serialize for $t {
            fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
                where S: serde::Serializer
            {
                use $crate::serde_custom::flatten::FlattenSerializable;

                self.serialize_internal(serializer)
            }
        }
    };
}

/// Implement flatten deserialization for a struct with a generic type `T: Serialize + Deserialize`.
/// Due to the way the type system is set up, there is no way to define a trait and then have an automatic
/// implementation of the trait.
/// The first parameter is the type of the struct you want to implement for, followed by the names of the children.
/// See module level documentation for `serde_custom::flatten`.
// TODO: Procedural macro
macro_rules! impl_flatten_deserialize_generic {
    ($t:ty, $( $child:ident ),*) => {
        impl<'de, T: Serialize + for<'de_inner> Deserialize<'de_inner>> serde::Deserialize<'de> for $t {
            fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
                where D: serde::Deserializer<'de>
            {
                use serde::de::Error;

                let value: serde_json::value::Value = serde::Deserialize::deserialize(deserializer)?;
                Ok(Self {
                    $( $child: serde_json::from_value(value.clone()).map_err(D::Error::custom)? ),*
                })
            }
        }
    }
}

/// Implement flatten serde for a struct with a generic type `T: Serialize + Deserialize`.
/// Due to the way the type system is set up, we cannot do a blanket
/// `impl <T: FlattenSerializable> Serialize for T`. This is just a wrapper to get around that problem.
/// Neither can we do the same for deserialization.
/// The first parameter is the type of the struct you want to implement for, followed by the names of the children.
/// See module level documentation for `serde_custom::flatten`.
macro_rules! impl_flatten_serde_generic {
    ($t:ty, $behaviour:expr, $( $child:ident ),*) => {
        impl_flatten_serialize_generic!($t, $behaviour, $( $child ),*);
        impl_flatten_deserialize_generic!($t, $( $child ),*);
    }
}

#[cfg(test)]
mod tests {
    use serde::{self, Serialize, Deserialize};
    use serde_json;
    use serde_test::{Token, assert_tokens, assert_ser_tokens_error};

    use super::*;

    #[derive(Eq, PartialEq, Debug, Clone, Serialize, Deserialize, Default)]
    struct InnerOne {
        a: i32,
        b: i32,
        c: i32,
        d: InnerTwo,
    }

    #[derive(Eq, PartialEq, Debug, Clone, Serialize, Deserialize, Default)]
    struct InnerTwo {
        a: bool,
        e: bool,
        f: u32,
    }

    #[derive(Eq, PartialEq, Debug, Clone, Serialize, Deserialize, Default)]
    struct InnerThree {
        g: bool,
        h: bool,
        i: bool,
    }

    /// Will not serialize (and certainly not deserialize) due to conflicting keys
    #[derive(Eq, PartialEq, Debug, Clone, Default)]
    struct OuterNoDuplicates {
        one: InnerOne,
        two: InnerTwo,
        three: InnerThree,
    }

    impl_flatten_serde!(OuterNoDuplicates,
                        DuplicateKeysBehaviour::RaiseError,
                        one,
                        two,
                        three);

    /// Will not deserialize due to conflicting keys
    #[derive(Eq, PartialEq, Debug, Clone, Default)]
    struct OuterOverwrite {
        one: InnerOne,
        two: InnerTwo,
        three: InnerThree,
    }

    impl_flatten_serde!(OuterOverwrite,
                        DuplicateKeysBehaviour::Overwrite,
                        one,
                        two,
                        three);

    #[derive(Eq, PartialEq, Debug, Clone, Default)]
    struct Outer {
        one: InnerOne,
        three: InnerThree,
    }

    impl_flatten_serde!(Outer, DuplicateKeysBehaviour::RaiseError, one, three);

    #[derive(Eq, PartialEq, Debug, Clone, Default)]
    struct OuterGeneric<T: Serialize + for<'de_inner> Deserialize<'de_inner>> {
        one: InnerOne,
        generic: T,
    }

    impl_flatten_serde_generic!(OuterGeneric<T>, DuplicateKeysBehaviour::RaiseError, one, generic);


    #[test]
    fn pairwise_intersection_for_one() {
        let sets: Vec<HashSet<i32>> = vec![[1, 2, 3].iter().cloned().collect()];
        assert!(!pairwise_intersection(sets.as_slice()))
    }

    #[test]
    fn pairwise_intersection_for_two_sets() {
        let sets: Vec<HashSet<i32>> = vec![[1, 2, 3].iter().cloned().collect(), [3].iter().cloned().collect()];
        assert!(pairwise_intersection(sets.as_slice()))
    }

    #[test]
    fn pairwise_non_intersection_for_two_sets() {
        let sets: Vec<HashSet<i32>> = vec![[1, 2, 3].iter().cloned().collect(), [99, 101].iter().cloned().collect()];
        assert!(!pairwise_intersection(sets.as_slice()))
    }

    /// Intersecting element is in the shortest set
    #[test]
    fn pairwise_intersection_for_three_sets() {
        let sets: Vec<HashSet<i32>> = vec![[1, 2, 3].iter().cloned().collect(),
                                           [3, 5, 6, 10, 11, 23].iter().cloned().collect(),
                                           [3].iter().cloned().collect()];
        assert!(pairwise_intersection(sets.as_slice()))
    }

    #[test]
    fn pairwise_non_intersection_for_three_sets() {
        let sets: Vec<HashSet<i32>> = vec![[1, 2, 3].iter().cloned().collect(),
                                           [4, 5, 6, 10, 11, 23].iter().cloned().collect(),
                                           [0].iter().cloned().collect()];
        assert!(!pairwise_intersection(sets.as_slice()))
    }

    /// Intersecting element is not in the shortest set
    #[test]
    fn pairwise_intersection_for_five_sets() {
        let sets: Vec<HashSet<i32>> =
            vec![[1, 2, 3].iter().cloned().collect(),
                                           [4, 5, 6, 7, 8, 9, 10].iter().cloned().collect(),
                                           [11, 12, 13, 14].iter().cloned().collect(),
                                           [15, 16, 17].iter().cloned().collect(),
                                           [18, 19, 20, 21, 22, 23, 4].iter().cloned().collect()];
        assert!(pairwise_intersection(sets.as_slice()))
    }

    #[test]
    fn pairwise_non_intersection_for_five_sets() {
        let sets: Vec<HashSet<i32>> =
            vec![[1, 2, 3].iter().cloned().collect(),
                                           [4, 5, 6, 7, 8, 9, 10].iter().cloned().collect(),
                                           [11, 12, 13, 14].iter().cloned().collect(),
                                           [15, 16, 17].iter().cloned().collect(),
                                           [18, 19, 20, 21, 22, 23, 24].iter().cloned().collect()];
        assert!(!pairwise_intersection(sets.as_slice()))
    }

    #[test]
    #[should_panic(expected = "Structs have duplicate keys")]
    fn errors_on_duplicate_keys() {
        let test_value = OuterNoDuplicates::default();
        serde_json::to_string(&test_value).unwrap();
    }

    #[test]
    fn duplicate_keys_serialization_token_error() {
        let test_value = OuterNoDuplicates::default();
        assert_ser_tokens_error(&test_value, &[], "Structs have duplicate keys");
    }

    #[test]
    fn serialization_overwrite_test() {
        let test_value = OuterOverwrite::default();
        let serialized = not_err!(serde_json::to_string_pretty(&test_value));

        let expected_json = r#"{
  "b": 0,
  "c": 0,
  "d": {
    "a": false,
    "e": false,
    "f": 0
  },
  "a": false,
  "e": false,
  "f": 0,
  "g": false,
  "h": false,
  "i": false
}"#;
        assert_eq!(expected_json, serialized);
    }

    #[test]
    fn serde_json() {
        let test_value = Outer::default();
        let expected_json = r#"{
  "a": 0,
  "b": 0,
  "c": 0,
  "d": {
    "a": false,
    "e": false,
    "f": 0
  },
  "g": false,
  "h": false,
  "i": false
}"#;
        let serialized = not_err!(serde_json::to_string_pretty(&test_value));
        assert_eq!(expected_json, serialized);

        let deserialized: Outer = not_err!(serde_json::from_str(&serialized));
        assert_eq!(deserialized, test_value);
    }

    #[test]
    fn serde_tokens() {
        let test_value = Outer::default();

        assert_tokens(&test_value,
                      &[Token::Map { len: Some(7) },

                        Token::Str("a"),
                        Token::U64(0),

                        Token::Str("b"),
                        Token::U64(0),

                        Token::Str("c"),
                        Token::U64(0),

                        Token::Str("d"),

                        // InnerTwo map
                        Token::Map { len: Some(3) },

                        Token::Str("a"),
                        Token::Bool(false),

                        Token::Str("e"),
                        Token::Bool(false),

                        Token::Str("f"),
                        Token::U64(0),
                        Token::MapEnd,
                        // End InnerTwo map
                        Token::Str("g"),
                        Token::Bool(false),

                        Token::Str("h"),
                        Token::Bool(false),

                        Token::Str("i"),
                        Token::Bool(false),
                        Token::MapEnd]);
    }

    #[test]
    fn serde_json_generic() {
        let test_value = OuterGeneric::<InnerThree>::default();
        let expected_json = r#"{
  "a": 0,
  "b": 0,
  "c": 0,
  "d": {
    "a": false,
    "e": false,
    "f": 0
  },
  "g": false,
  "h": false,
  "i": false
}"#;
        let serialized = not_err!(serde_json::to_string_pretty(&test_value));
        assert_eq!(expected_json, serialized);

        let deserialized: OuterGeneric<InnerThree> = not_err!(serde_json::from_str(&serialized));
        assert_eq!(deserialized, test_value);
    }

    #[test]
    fn serde_tokens_generic() {
        let test_value = OuterGeneric::<InnerThree>::default();

        assert_tokens(&test_value,
                      &[Token::Map { len: Some(7) },

                        Token::Str("a"),
                        Token::U64(0),

                        Token::Str("b"),
                        Token::U64(0),

                        Token::Str("c"),
                        Token::U64(0),

                        Token::Str("d"),

                        // InnerTwo map
                        Token::Map { len: Some(3) },

                        Token::Str("a"),
                        Token::Bool(false),

                        Token::Str("e"),
                        Token::Bool(false),

                        Token::Str("f"),
                        Token::U64(0),
                        Token::MapEnd,
                        // End InnerTwo map
                        Token::Str("g"),
                        Token::Bool(false),

                        Token::Str("h"),
                        Token::Bool(false),

                        Token::Str("i"),
                        Token::Bool(false),
                        Token::MapEnd]);
    }
}
