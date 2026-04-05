#[derive(Debug, Eq, PartialEq, Clone, Copy)]
/// Defines whether a claim is validated or not
///
/// The generic type T is used as the "options" for validating claims and is
/// specific to each claim being validated. Refer to [`crate::ValidationOptions`]
/// for the specifics of each claim.
#[derive(Default)]
pub enum Validation<T> {
    /// This claim is not validated
    #[default]
    Ignored,

    /// Validate this claim with type T.
    /// Refer to [`crate::ValidationOptions`] for the specifics of each claim.
    Validate(T),
}

impl<T> Validation<T> {
    /// Map the value to another validation requirement, similar to how .map works on iter()
    pub fn map<U, F>(self, f: F) -> Validation<U>
    where
        F: FnOnce(T) -> U,
    {
        match self {
            Validation::Ignored => Validation::Ignored,
            Validation::Validate(t) => Validation::Validate(f(t)),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_is_ignored() {
        let v: Validation<String> = Default::default();
        assert_eq!(Validation::Ignored, v);
    }

    #[test]
    fn map_on_ignored_stays_ignored() {
        let v: Validation<i32> = Validation::Ignored;
        let mapped: Validation<String> = v.map(|x| x.to_string());
        assert_eq!(Validation::Ignored, mapped);
    }

    #[test]
    fn map_on_validate_transforms_value() {
        let v: Validation<i32> = Validation::Validate(42);
        let mapped: Validation<String> = v.map(|x| x.to_string());
        assert_eq!(Validation::Validate("42".to_string()), mapped);
    }

    #[test]
    fn equality() {
        assert_eq!(Validation::<i32>::Ignored, Validation::Ignored);
        assert_eq!(Validation::Validate(42), Validation::Validate(42));
        assert_ne!(Validation::<i32>::Ignored, Validation::Validate(42));
    }

    #[test]
    fn copy_semantics() {
        let v = Validation::Validate(42i32);
        let cloned = v;
        assert_eq!(v, cloned);
    }
}
