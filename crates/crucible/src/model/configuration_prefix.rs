//! Identified prefixes of one shared configuration.
//!
//! Campaign replay authenticates every campaign-branch selection against the
//! exact configuration before it. Building an owned prefix configuration for
//! each such selection copies the schedule once per branch, so retaining the
//! results makes memory grow with schedule length times branch count.
//!
//! A [`ConfigurationPrefix`] instead names the first `len` decisions of a
//! shared basis configuration and carries that prefix's canonical identity.
//! Cloning a prefix copies reference counts only, and many prefixes of one
//! configuration share its storage:
//!
//! ```text
//! basis:  [d0 d1 d2 d3 d4 d5 d6 d7]      one shared schedule
//! parent:  len 3, id(d0..d2)             branch at decision 3
//! child:   len 5, id(d0..d4)             after its two branch decisions
//! ```
//!
//! Computing a prefix identity still reads the prefix once, because the
//! canonical configuration hash commits to the decision count first. That is
//! time linear in the prefix and never a copy.

use std::fmt;

use super::*;

/// The first `len` decisions of a shared configuration, with their identity.
///
/// Equality compares the definition, the decision count, and the canonical
/// configuration identity, which commits to every decision in the prefix.
///
/// # Examples
///
/// ```rust
/// use crucible::{Configuration, ConfigurationPrefix};
///
/// # fn example(target: &Configuration) -> Result<(), crucible::ScheduleError> {
/// let whole = ConfigurationPrefix::whole(target);
/// assert_eq!(whole.id(), target.id());
///
/// let genesis = ConfigurationPrefix::new(target, 0)?;
/// assert_eq!(genesis.to_configuration(), Configuration::genesis(target.def.clone()));
/// # Ok(())
/// # }
/// ```
#[derive(Clone)]
pub struct ConfigurationPrefix {
    // Shared configuration whose schedule holds at least `len` decisions.
    basis: Configuration,
    len: usize,
    // Canonical identity of the configuration made of exactly the prefix.
    id: ContentHash,
}

impl ConfigurationPrefix {
    /// Names the first `len` decisions of `basis`.
    ///
    /// The prefix identity is hashed once here, in time linear in `len`; the
    /// decisions themselves are shared with `basis`, not copied.
    ///
    /// # Errors
    ///
    /// Returns [`ScheduleError::PrefixTooLong`] when `len` exceeds the number
    /// of decisions in `basis`.
    pub fn new(basis: &Configuration, len: usize) -> Result<Self, ScheduleError> {
        if len == basis.schedule.len() {
            return Ok(Self::whole(basis));
        }

        let id = canonical::configuration_prefix_hash(&basis.def, &basis.schedule, len).ok_or(
            ScheduleError::PrefixTooLong {
                requested: len,
                available: basis.schedule.len(),
            },
        )?;
        Ok(Self {
            basis: basis.clone(),
            len,
            id,
        })
    }

    /// Names every decision of `configuration`.
    ///
    /// The identity is the configuration's memoized [`Configuration::id`].
    #[must_use]
    pub fn whole(configuration: &Configuration) -> Self {
        Self {
            basis: configuration.clone(),
            len: configuration.schedule.len(),
            id: configuration.id(),
        }
    }

    /// Returns the number of decisions in the prefix.
    #[must_use]
    pub const fn len(&self) -> usize {
        self.len
    }

    /// Returns whether the prefix is the genesis configuration.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// Returns the canonical identity of the prefix configuration.
    #[must_use]
    pub const fn id(&self) -> ContentHash {
        self.id
    }

    /// Returns the scenario definition shared by the prefix and its basis.
    #[must_use]
    pub const fn def(&self) -> &ScenarioDef {
        &self.basis.def
    }

    /// Returns the prefix decisions in recorded order without copying them.
    pub fn decisions(&self) -> impl Iterator<Item = &Decision> {
        self.basis.schedule.decision_history().iter().take(self.len)
    }

    /// Returns whether `configuration` is exactly this prefix.
    ///
    /// The comparison reads decisions rather than hashing, and skips storage
    /// that `configuration` shares with the basis.
    #[must_use]
    pub fn matches(&self, configuration: &Configuration) -> bool {
        configuration.def == self.basis.def
            && configuration.schedule.len() == self.len
            && configuration
                .schedule
                .decision_history()
                .prefix_eq(self.basis.schedule.decision_history(), self.len)
    }

    /// Materializes the prefix as an owned configuration.
    ///
    /// A whole-basis prefix clones the basis in constant time; a shorter one
    /// copies its decisions. Retained values should keep the prefix instead.
    #[must_use]
    pub fn to_configuration(&self) -> Configuration {
        if self.len == self.basis.schedule.len() {
            return self.basis.clone();
        }

        Configuration {
            def: self.basis.def.clone(),
            schedule: Schedule::from_decisions(self.decisions().cloned()),
        }
    }

    /// Returns the shared configuration this prefix names part of.
    #[cfg(test)]
    pub(crate) const fn basis(&self) -> &Configuration {
        &self.basis
    }

    /// Returns the same prefix over `target`'s storage, if `target` extends it.
    ///
    /// The identity is reused: equal definitions and decisions imply an equal
    /// canonical identity.
    pub(crate) fn rebased_onto(&self, target: &Configuration) -> Option<Self> {
        let extends = target.def == self.basis.def
            && target
                .schedule
                .decision_history()
                .prefix_eq(self.basis.schedule.decision_history(), self.len);
        extends.then(|| Self {
            basis: target.clone(),
            len: self.len,
            id: self.id,
        })
    }

    /// Returns the next `len + count` prefix when the basis already holds
    /// exactly `decisions` after this prefix.
    ///
    /// The extension is admitted only when the whole basis satisfies the
    /// scenario's app-random draw cap; prefixes of an admitted schedule never
    /// hold more draws than it does. Otherwise the caller must step through
    /// [`crate::try_step`] as for any new configuration.
    pub(crate) fn extended_in_basis(&self, decisions: &[Decision]) -> Option<Self> {
        let history = self.basis.schedule.decision_history();
        let end = self.len.checked_add(decisions.len())?;
        let recorded = end <= history.len()
            && history
                .iter_from(self.len)
                .take(decisions.len())
                .eq(decisions);
        let admitted =
            super::runtime::validate_app_random_draw_cap(&self.basis.def, &self.basis.schedule)
                .is_ok();
        if !recorded || !admitted {
            return None;
        }
        Self::new(&self.basis, end).ok()
    }
}

impl PartialEq for ConfigurationPrefix {
    fn eq(&self, other: &Self) -> bool {
        self.basis.def == other.basis.def && self.len == other.len && self.id == other.id
    }
}

impl Eq for ConfigurationPrefix {}

// The basis can hold far more decisions than the prefix names, so debug
// output reports the prefix identity rather than the shared schedule.
impl fmt::Debug for ConfigurationPrefix {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ConfigurationPrefix")
            .field("def", &self.basis.def)
            .field("len", &self.len)
            .field("id", &self.id)
            .finish()
    }
}

#[cfg(test)]
// crucible-lint: allow panic-shortcut -- test fixtures use panic shortcuts for exact failure localization.
#[allow(clippy::expect_used)]
mod tests {
    use super::*;

    fn configuration(decisions: usize) -> Configuration {
        let def = ScenarioDef::from_canonical_material("configuration-prefix-test", "basis");
        let schedule = Schedule::from_decisions((0..decisions).map(|index| {
            Decision::RngDraw(RngDecision::ordinal(
                RngStreamId::from_name("configuration-prefix-test"),
                0,
                index as u64,
            ))
        }));
        Configuration { def, schedule }
    }

    #[test]
    fn prefix_identity_equals_the_materialized_prefix_identity() {
        let basis = configuration(150);

        for len in [0, 1, 64, 149, 150] {
            let prefix = ConfigurationPrefix::new(&basis, len).expect("prefix fits");
            let materialized = Configuration {
                def: basis.def.clone(),
                schedule: basis.schedule.prefix(len).expect("prefix fits"),
            };

            assert_eq!(prefix.len(), len);
            assert_eq!(prefix.id(), materialized.id());
            assert_eq!(prefix.to_configuration(), materialized);
            assert!(prefix.matches(&materialized));
            assert_eq!(prefix, ConfigurationPrefix::whole(&materialized));
        }
    }

    #[test]
    fn prefix_longer_than_its_basis_is_rejected() {
        let basis = configuration(3);

        assert_eq!(
            ConfigurationPrefix::new(&basis, 4),
            Err(ScheduleError::PrefixTooLong {
                requested: 4,
                available: 3,
            })
        );
    }

    #[test]
    fn rebasing_keeps_identity_only_for_an_extending_target() {
        let short = configuration(70);
        let long = configuration(140);
        let prefix = ConfigurationPrefix::whole(&short);

        let rebased = prefix.rebased_onto(&long).expect("long extends short");
        assert_eq!(rebased, prefix);
        assert!(rebased.matches(&short));

        let mut diverged = long.clone();
        diverged.schedule = Schedule::from_decisions(
            long.schedule
                .decision_history()
                .iter()
                .cloned()
                .enumerate()
                .map(|(index, decision)| {
                    if index == 10 {
                        Decision::RngDraw(RngDecision::ordinal(
                            RngStreamId::from_name("diverged"),
                            0,
                            0,
                        ))
                    } else {
                        decision
                    }
                }),
        );
        assert_eq!(prefix.rebased_onto(&diverged), None);
    }

    #[test]
    fn matching_rejects_a_configuration_of_another_length() {
        let basis = configuration(10);
        let prefix = ConfigurationPrefix::new(&basis, 5).expect("prefix fits");

        assert!(!prefix.matches(&basis));
        assert!(!prefix.matches(&configuration(4)));
    }
}
