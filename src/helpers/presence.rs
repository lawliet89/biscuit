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
