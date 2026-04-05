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

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::{Duration, TimeZone, Utc};

    #[test]
    fn default_has_zero_epsilon_and_no_now() {
        let opts = TemporalOptions::default();
        assert_eq!(Duration::seconds(0), opts.epsilon);
        assert!(opts.now.is_none());
    }

    #[test]
    fn equality() {
        let opts1 = TemporalOptions::default();
        let opts2 = TemporalOptions::default();
        assert_eq!(opts1, opts2);
    }

    #[test]
    fn copy_semantics() {
        let opts = TemporalOptions {
            epsilon: Duration::seconds(5),
            now: Some(Utc.timestamp_opt(1000, 0).unwrap()),
        };
        let cloned = opts;
        assert_eq!(opts, cloned);
    }

    #[test]
    fn custom_epsilon_and_now() {
        let now = Utc.timestamp_opt(42, 0).unwrap();
        let opts = TemporalOptions {
            epsilon: Duration::seconds(30),
            now: Some(now),
        };
        assert_eq!(Duration::seconds(30), opts.epsilon);
        assert_eq!(Some(now), opts.now);
    }
}
