//! Resolves typed root retention and preserves explanations for root decisions.

use super::{GcError, RetentionTimes, Windows};
use crate::{
    properties::{self, PropertyName, Value},
    refs::Retention,
    tree_format::Property,
};

/// The exact full-parent policy carried by roots and resumable frontiers.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ParentCutoff {
    /// Ordinary ancestors are witness-only; independently selected roots expand fully.
    RootsOnly,
    /// Ordinary ancestors at or after this authoritative timestamp expand fully.
    Since(u64),
    /// Every ordinary ancestor expands fully.
    Unbounded,
}

impl ParentCutoff {
    /// Tests whether this context admits a parent's ordinary content.
    pub const fn allows(self, timestamp: u64) -> bool {
        match self {
            Self::RootsOnly => false,
            Self::Since(cutoff) => timestamp >= cutoff,
            Self::Unbounded => true,
        }
    }

    /// Tests whether this already-expanded context includes another context.
    pub const fn covers(self, other: Self) -> bool {
        match (self, other) {
            (Self::Unbounded, _) | (_, Self::RootsOnly) => true,
            (Self::Since(old), Self::Since(next)) => old <= next,
            _ => false,
        }
    }
}

/// The registered duration or committed-sequence count selecting GC history.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ReflogRetention {
    /// Retains records within this duration of their own log timestamp.
    Duration(u64),
    /// Retains this many newest committed log records, beginning with rank zero.
    Count(u64),
}

impl ReflogRetention {
    /// Selects a log by its timestamp or rank in the committed sequence ordering.
    pub fn keeps(self, now: u64, timestamp: u64, rank: u64) -> bool {
        match self {
            Self::Duration(duration) => {
                now.checked_sub(timestamp).is_none_or(|age| age <= duration)
            }
            Self::Count(count) => rank < count,
        }
    }
}

/// Effective root content mode and ordinary committed reflog selection.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RetentionPolicy {
    /// Closed retention mode from the registered root property.
    pub mode: Retention,
    /// GC history selection, independent of overriding lease, TTL, or forever modes.
    pub reflog: ReflogRetention,
}

impl RetentionPolicy {
    /// Resolves a ref root's own properties over inherited repository defaults.
    ///
    /// The caller supplies the already resolved inherited policy along the
    /// actual graft path. A ref-policy override applies after root properties.
    ///
    /// # Errors
    /// Rejects invalid or duplicate registered properties and oversized maps.
    pub fn resolve(
        properties: &[Property<'_>],
        inherited: Self,
        override_mode: Option<Retention>,
    ) -> Result<Self, GcError> {
        properties::validate_map(properties).map_err(|_| GcError::Schema)?;

        let mut policy = inherited;
        for property in properties {
            let (name, value) =
                properties::validate_property(property).map_err(|_| GcError::Schema)?;
            match (name, value) {
                (PropertyName::Retain, Value::Text("gc")) => policy.mode = Retention::Gc,
                (PropertyName::Retain, Value::Text("lease")) => policy.mode = Retention::Lease,
                (PropertyName::Retain, Value::Text("forever")) => policy.mode = Retention::Forever,
                (PropertyName::Retain, Value::Ttl(duration)) => {
                    policy.mode = Retention::Ttl(duration)
                }
                (PropertyName::ReflogRetain, Value::Unsigned(duration)) => {
                    policy.reflog = ReflogRetention::Duration(duration)
                }
                (PropertyName::ReflogRetain, Value::Count(count)) => {
                    policy.reflog = ReflogRetention::Count(count)
                }
                _ => {}
            }
        }
        if let Some(mode) = override_mode {
            policy.mode = mode;
        }
        Ok(policy)
    }

    /// Constructs repository defaults from validated collection windows.
    pub const fn default_for(windows: Windows) -> Self {
        Self {
            mode: Retention::Gc,
            reflog: ReflogRetention::Duration(if windows.retention() > 90 * 24 * 60 * 60 {
                windows.retention()
            } else {
                90 * 24 * 60 * 60
            }),
        }
    }

    /// Tests a historical record against the retention rule's prescribed clock.
    ///
    /// `rank` begins at zero in descending committed sequence order. It does
    /// not depend on advisory log time and is consulted only for GC count mode.
    pub fn retains(self, times: RetentionTimes, rank: u64) -> bool {
        match self.mode {
            Retention::Gc => self.reflog.keeps(times.now, times.reflog, rank),
            Retention::Ttl(duration) => times
                .now
                .checked_sub(times.commit)
                .is_none_or(|age| age <= duration),
            Retention::Lease => times.lease_expiry.is_some_and(|expiry| times.now < expiry),
            Retention::Forever => true,
        }
    }

    /// Returns the oldest ordinary parent timestamp permitted by this policy.
    ///
    /// Lease and forever roots keep their complete ordinary ancestry while
    /// rooted. Receipt and introduction edges bypass this cutoff independently.
    pub fn parent_cutoff(self, now: u64) -> ParentCutoff {
        match self.mode {
            Retention::Gc => match self.reflog {
                ReflogRetention::Duration(duration) => {
                    ParentCutoff::Since(now.saturating_sub(duration))
                }
                ReflogRetention::Count(_) => ParentCutoff::RootsOnly,
            },
            Retention::Ttl(duration) => ParentCutoff::Since(now.saturating_sub(duration)),
            Retention::Lease | Retention::Forever => ParentCutoff::Unbounded,
        }
    }
}

#[cfg(test)]
mod tests {
    //! Checks pure retention policy invariants.

    use super::*;
    use crate::cbor;
    use alloc::vec::Vec;

    #[test]
    fn gc_roots_retention_resolves_root_values_and_ref_override() -> Result<(), GcError> {
        let windows = Windows::new(6, 24, 24, 30)?;
        let defaults = RetentionPolicy::default_for(windows);
        let mut encoded = Vec::new();
        cbor::write_array(&mut encoded, 2);
        cbor::write_text(&mut encoded, "ttl");
        cbor::write_uint(&mut encoded, 12);
        let props = [Property {
            name: "retain",
            value: &encoded,
        }];
        let policy = RetentionPolicy::resolve(&props, defaults, None)?;
        let times = RetentionTimes {
            now: 100,
            commit: 88,
            reflog: 99,
            lease_expiry: None,
        };

        assert_eq!(policy.mode, Retention::Ttl(12));
        assert_eq!(policy.parent_cutoff(100), ParentCutoff::Since(88));
        assert!(policy.retains(times, 0));
        assert!(!policy.retains(
            RetentionTimes {
                commit: 87,
                ..times
            },
            0
        ));
        let policy = RetentionPolicy::resolve(&props, defaults, Some(Retention::Forever))?;
        assert_eq!(policy.parent_cutoff(100), ParentCutoff::Unbounded);
        assert!(policy.retains(RetentionTimes { commit: 0, ..times }, 0));
        Ok(())
    }

    #[test]
    fn gc_retention_count_zero_and_overrides_have_distinct_selection() -> Result<(), GcError> {
        let windows = Windows::new(2, 10, 10, 12)?;
        let default = RetentionPolicy::default_for(windows);
        assert_eq!(default.reflog, ReflogRetention::Duration(90 * 24 * 60 * 60));
        let mut bytes = Vec::new();
        cbor::write_array(&mut bytes, 2);
        cbor::write_text(&mut bytes, "count");
        cbor::write_uint(&mut bytes, 0);
        let properties = [Property {
            name: "reflog_retain",
            value: &bytes,
        }];
        let policy = RetentionPolicy::resolve(&properties, default, None)?;
        let times = RetentionTimes {
            now: 100,
            commit: 99,
            reflog: 100,
            lease_expiry: None,
        };
        assert_eq!(policy.parent_cutoff(100), ParentCutoff::RootsOnly);
        assert!(!policy.retains(times, 0));
        let forever = RetentionPolicy::resolve(&properties, default, Some(Retention::Forever))?;
        assert!(forever.retains(times, u64::MAX));
        assert_eq!(forever.parent_cutoff(100), ParentCutoff::Unbounded);
        assert!(ReflogRetention::Count(2).keeps(100, 1, 1));
        assert!(!ReflogRetention::Count(2).keeps(100, 100, 2));
        Ok(())
    }

    #[test]
    fn gc_retention_rejects_duplicate_properties_and_raises_default_to_window_minimum()
    -> Result<(), GcError> {
        let windows = Windows::new(1, 10_000_000, 10_000_000, 10_000_001)?;
        let default = RetentionPolicy::default_for(windows);
        assert_eq!(default.reflog, ReflogRetention::Duration(10_000_001));

        let properties = [
            Property {
                name: "retain",
                value: b"\x62gc",
            },
            Property {
                name: "retain",
                value: b"\x65lease",
            },
        ];
        assert_eq!(
            RetentionPolicy::resolve(&properties, default, None),
            Err(GcError::Schema)
        );
        Ok(())
    }
}
