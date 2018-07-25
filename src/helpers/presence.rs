#[derive(Clone, Copy, Debug, Eq, PartialEq)]
/// Defines wether a claim is required or not
pub enum Presence {
    /// Claim is optional
    Optional,
    /// Claim is required
    Required,
}

impl Default for Presence {
    fn default() -> Self {
        Presence::Optional
    }
}
