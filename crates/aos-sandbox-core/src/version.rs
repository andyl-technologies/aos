//! Monotonic counters used to fence stale sandbox operations.
//!
//! Counter types are intentionally distinct even though each is encoded as an
//! unsigned 64-bit integer. Advancing a desired generation must never be
//! mistaken for acquiring a new assignment epoch.

use serde::{Deserialize, Serialize};

/// Reports that a monotonic counter cannot advance without wrapping.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
#[error("{counter} reached its maximum value")]
pub struct CounterOverflow {
    counter: &'static str,
}

macro_rules! define_counter {
    ($name:ident, $summary:literal) => {
        #[doc = $summary]
        #[derive(
            Clone,
            Copy,
            Debug,
            Default,
            Deserialize,
            Eq,
            Hash,
            Ord,
            PartialEq,
            PartialOrd,
            Serialize,
        )]
        #[serde(transparent)]
        pub struct $name(u64);

        impl $name {
            /// Constructs a counter from its portable unsigned value.
            #[must_use]
            pub const fn new(value: u64) -> Self {
                Self(value)
            }

            /// Returns the portable unsigned value.
            #[must_use]
            pub const fn get(self) -> u64 {
                self.0
            }

            /// Returns the next value without permitting wraparound.
            ///
            /// # Errors
            ///
            /// Returns [`CounterOverflow`] when the current value is
            /// [`u64::MAX`]. Exhaustion is a fail-closed condition requiring a
            /// new containing identity, never a reason to reuse an old value.
            pub const fn checked_next(self) -> Result<Self, CounterOverflow> {
                match self.0.checked_add(1) {
                    Some(next) => Ok(Self(next)),
                    None => Err(CounterOverflow {
                        counter: stringify!($name),
                    }),
                }
            }

            /// Reports whether this counter is newer than `previous`.
            #[must_use]
            pub const fn is_newer_than(self, previous: Self) -> bool {
                self.0 > previous.0
            }
        }

        impl From<u64> for $name {
            fn from(value: u64) -> Self {
                Self::new(value)
            }
        }

        impl From<$name> for u64 {
            fn from(value: $name) -> Self {
                value.get()
            }
        }
    };
}

define_counter!(
    DesiredGeneration,
    "Identifies a monotonically ordered desired-state revision within an incarnation."
);
define_counter!(
    AssignmentEpoch,
    "Fences coordinator decisions assigning an incarnation to a node."
);
define_counter!(
    NamespaceGeneration,
    "Identifies a runtime namespace generation within an incarnation."
);
define_counter!(
    ObservationSequence,
    "Orders node observations within one assignment and boot identity."
);
define_counter!(
    Revision,
    "Identifies a monotonically ordered object revision."
);

#[cfg(test)]
mod tests {
    use super::{AssignmentEpoch, DesiredGeneration};

    #[test]
    fn advance_is_monotonic() {
        let initial = DesiredGeneration::new(41);
        let next = initial.checked_next();

        assert_eq!(next.map(DesiredGeneration::get), Ok(42));
        assert!(next.is_ok_and(|value| value.is_newer_than(initial)));
    }

    #[test]
    fn advance_fails_closed_at_exhaustion() {
        let exhausted = AssignmentEpoch::new(u64::MAX);

        assert!(exhausted.checked_next().is_err());
    }
}
