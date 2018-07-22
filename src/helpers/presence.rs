#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Presence {
    Optional,
    Required
}

impl Default for Presence {
    fn default() -> Self {
        Presence::Optional
    }
}
