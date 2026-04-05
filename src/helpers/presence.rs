#[derive(Clone, Copy, Debug, Eq, PartialEq)]
/// Defines whether a claim is required or not
#[derive(Default)]
pub enum Presence {
    /// Claim is optional
    #[default]
    Optional,
    /// Claim is required
    Required,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_is_optional() {
        let p: Presence = Default::default();
        assert_eq!(Presence::Optional, p);
    }

    #[test]
    fn equality() {
        assert_eq!(Presence::Optional, Presence::Optional);
        assert_eq!(Presence::Required, Presence::Required);
        assert_ne!(Presence::Optional, Presence::Required);
    }

    #[test]
    fn copy_semantics() {
        let p = Presence::Required;
        let cloned = p;
        assert_eq!(p, cloned);
    }
}
