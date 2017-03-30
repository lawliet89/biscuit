//! A "flattened" serializer and deserializer.
//!
//! This serializer will take a struct, and then flatten all its first-level children.
use std::collections::HashSet;
use std::default::Default;
use std::fmt;
use std::hash::Hash;
use std::marker::PhantomData;

use serde::{Serialize, Serializer, Deserialize, Deserializer};
use serde::de;
use serde_json;
use serde_json::map::Map;
use serde_json::value::{Value, ToJson};

/// The behaviour the serializer should adopt when encountering duplicate keys
#[derive(Eq, PartialEq, Clone, Copy)]
pub enum DuplicateKeysBehaviour {
    /// Raise an error when a duplicate key is encountered
    RaiseError,
    /// Overwrite the keys encountered earlier with the ones encountered later. If the types of the values of the
    /// duplicated keys differ, this type will probably fail deserialization
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

impl Serialize for FlattenSerializable {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
        where S: Serializer
    {
        use serde::ser::Error;

        // A "hack" to combine structs into one serialized JSON
        // First, we serialize each of them into JSON Value enum
        let value_maps: Vec<Result<Value, String>> = self.yield_children()
            .iter()
            .map(|child| child.to_json().map_err(|e| format!("{}", e)))
            .collect();

        if value_maps.iter().any(|r| r.is_err()) {
            let errors: Vec<String> = value_maps.iter()
                .cloned()
                .filter(|r| r.is_err())
                .map(|r| r.unwrap_err())
                .collect();
            Err(S::Error::custom(errors.join("; ")))?;
        }

        let value_maps: Vec<Map<String, Value>> = value_maps.into_iter()
            .filter(|r| r.is_ok())
            .map(|r| r.unwrap())
            .map(|value| match value {
                     Value::Object(map) => map,
                     _ => unreachable!("Child was not a struct"),
                 })
            .collect();

        if let DuplicateKeysBehaviour::RaiseError = self.duplicate_keys() {
            // We need to check for duplicate keys
            let keys: Vec<HashSet<String>> = value_maps.iter().map(|k| k.keys().cloned().collect()).collect();
            if pairwise_intersection(keys.as_slice()) {
                Err(S::Error::custom("Structs have duplicate keys"))?
            }
        }

        let map: Map<String, Value> = value_maps.into_iter().flat_map(|m| m.into_iter()).collect();
        map.serialize(serializer)
    }
}

pub trait FromJson {
    fn from_json(value: Value) -> Result<Self, serde_json::error::Error> where Self: Sized;
}

impl<T> FromJson for T
    where T: Deserialize
{
    fn from_json(value: Value) -> Result<T, serde_json::error::Error> {
        serde_json::value::from_value(value)
    }
}

macro_rules! impl_flatten_deserialize {
    ($t:ty, $( $child:ident ),*) => {
        impl Deserialize for $t {
            fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
                where D: Deserializer
            {
                use serde::de::Error;

                let value: Value = Deserialize::deserialize(deserializer)?;
                Ok(Self {
                    $( $child: serde_json::from_value(value.clone()).map_err(D::Error::custom)? ),*
                })
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use serde_json;

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

    impl FlattenSerializable for OuterNoDuplicates {
        fn yield_children(&self) -> Vec<Box<&ToJson>> {
            vec![Box::<&ToJson>::new(&self.one), Box::<&ToJson>::new(&self.two), Box::<&ToJson>::new(&self.three)]
        }
    }

    /// Will not deserialize due to conflicting keys
    #[derive(Eq, PartialEq, Debug, Clone, Default)]
    struct OuterOverwrite {
        one: InnerOne,
        two: InnerTwo,
        three: InnerThree,
    }

    impl FlattenSerializable for OuterOverwrite {
        fn yield_children(&self) -> Vec<Box<&ToJson>> {
            vec![Box::<&ToJson>::new(&self.one), Box::<&ToJson>::new(&self.two), Box::<&ToJson>::new(&self.three)]
        }

        fn duplicate_keys(&self) -> DuplicateKeysBehaviour {
            DuplicateKeysBehaviour::Overwrite
        }
    }

    impl_flatten_deserialize!(OuterOverwrite, one, two, three);

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
        serde_json::to_string(&test_value as &FlattenSerializable).unwrap();
    }

    #[test]
    fn serialization_overwrite_test() {
        let test_value = OuterOverwrite::default();
        let serialized = not_err!(serde_json::to_string_pretty(&test_value as &FlattenSerializable));

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
    fn deserialization_test() {
        let test_json = r#"{
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

        let deserialized: InnerThree = not_err!(serde_json::from_str(&test_json));
    }
}
