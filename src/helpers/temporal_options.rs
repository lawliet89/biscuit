use chrono::{DateTime, Duration, Utc};

#[derive(Debug, Eq, PartialEq, Clone, Copy)]
/// Options for validating temporal claims
///
///
/// To deal with clock drifts, you might want to provide an `epsilon` error margin in the form of a
/// `chrono::Duration` to allow time comparisons to fall within the margin.
pub struct TemporalOptions {
    /// Allow for some leeway for clock drifts, limited to this duration during temporal validation
    pub epsilon: Duration,

    /// Specify a time to use in temporal validation instead of `Now`
    pub now: Option<DateTime<Utc>>,
}

impl Default for TemporalOptions {
    fn default() -> Self {
        TemporalOptions {
            epsilon: Duration::seconds(0),
            now: None,
        }
    }
}
