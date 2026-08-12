//! Transactional raw-value root rewrites for packed heap publication.
//!
//! Packed generations use logical Candidate-C coordinates rather than native
//! addresses. The minor-GC root writer therefore cannot represent their
//! replacements through [`crate::heap::ResolvedValueGeneration`]. This module
//! keeps the publication boundary at the raw [`Value`] level: an immutable
//! plan names each exact [`EvalRootSource`], the value observed while preparing
//! the destination, and the opaque replacement word.
//!
//! The mutator supplies explicit borrowed bindings to its live root storage.
//! Applying a plan validates one-to-one source coverage and every expected word
//! before the first write. No root address is inferred from copied scan data,
//! and no packed coordinate is reconstructed as a native pointer.

use thiserror::Error;

use super::{EvalRootSource, Value, ValueTag};

/// One immutable raw-value root rewrite prepared before packed publication.
#[derive(Clone, Debug)]
pub(in crate::eval) struct DirectRootRewrite {
    source: EvalRootSource,
    expected: Value,
    replacement: Value,
}

impl DirectRootRewrite {
    /// Creates a rewrite for one exact mutator root source.
    pub(in crate::eval) const fn new(
        source: EvalRootSource,
        expected: Value,
        replacement: Value,
    ) -> Self {
        Self {
            source,
            expected,
            replacement,
        }
    }

    /// Returns the exact mutator root source to rewrite.
    pub(in crate::eval) const fn source(&self) -> &EvalRootSource {
        &self.source
    }

    /// Returns the raw value that must still occupy the root.
    pub(in crate::eval) const fn expected(&self) -> Value {
        self.expected
    }

    /// Returns the opaque raw replacement, which may be a packed coordinate.
    pub(in crate::eval) const fn replacement(&self) -> Value {
        self.replacement
    }
}

/// An owned, prevalidated set of raw-value root rewrites.
#[derive(Clone, Debug, Default)]
pub(in crate::eval) struct DirectRootRewritePlan {
    rewrites: Vec<DirectRootRewrite>,
}

impl DirectRootRewritePlan {
    /// Builds a plan after rejecting duplicate or conflicting root sources.
    ///
    /// Rewrites retain their input order. Equality of expected and replacement
    /// values is representation equality, not Nix semantic equality.
    ///
    /// # Errors
    ///
    /// Returns [`DirectRootRewriteError::DuplicateRewriteSource`] when an exact
    /// rewrite occurs twice, or
    /// [`DirectRootRewriteError::ConflictingRewriteSource`] when two rewrites
    /// name the same root but disagree about its expected or replacement word.
    pub(in crate::eval) fn try_new(
        rewrites: Vec<DirectRootRewrite>,
    ) -> Result<Self, DirectRootRewriteError> {
        for duplicate in 0..rewrites.len() {
            for first in 0..duplicate {
                if rewrites[first].source != rewrites[duplicate].source {
                    continue;
                }
                let same_expected = rewrites[first]
                    .expected
                    .raw_eq(rewrites[duplicate].expected);
                let same_replacement = rewrites[first]
                    .replacement
                    .raw_eq(rewrites[duplicate].replacement);
                if same_expected && same_replacement {
                    return Err(DirectRootRewriteError::DuplicateRewriteSource {
                        root_source: rewrites[duplicate].source.clone(),
                        first,
                        duplicate,
                    });
                }
                return Err(DirectRootRewriteError::ConflictingRewriteSource {
                    root_source: rewrites[duplicate].source.clone(),
                    first,
                    conflicting: duplicate,
                });
            }
        }
        Ok(Self { rewrites })
    }

    /// Returns the immutable rewrites in preparation order.
    pub(in crate::eval) fn rewrites(&self) -> &[DirectRootRewrite] {
        &self.rewrites
    }

    /// Returns the number of exact root rewrites.
    pub(in crate::eval) const fn len(&self) -> usize {
        self.rewrites.len()
    }

    /// Returns whether the plan contains no root rewrites.
    pub(in crate::eval) const fn is_empty(&self) -> bool {
        self.rewrites.is_empty()
    }

    /// Validates and commits this plan through explicitly borrowed root bindings.
    ///
    /// Bindings may be presented in any order. Every planned source must have
    /// exactly one binding, and there may be no unplanned bindings. All current
    /// raw words are validated before any replacement is written, so every
    /// error leaves all bound roots unchanged.
    ///
    /// # Errors
    ///
    /// Returns [`DirectRootRewriteError`] when binding coverage is not exactly
    /// one-to-one or any bound root no longer contains its planned expected
    /// value.
    pub(in crate::eval) fn apply(
        &self,
        bindings: &mut [DirectRootBinding<'_>],
    ) -> Result<DirectRootRewriteReport, DirectRootRewriteError> {
        self.validate_bindings(bindings)?;

        // Validation proved one-to-one coverage. This commit loop is therefore
        // infallible and performs no allocation or packed-word interpretation.
        for rewrite in &self.rewrites {
            for binding in bindings.iter_mut() {
                if binding.source == rewrite.source {
                    *binding.value = rewrite.replacement;
                    break;
                }
            }
        }

        Ok(DirectRootRewriteReport {
            rewrites: self.rewrites.len(),
        })
    }

    /// Validates copied observations of every root before a separate commit.
    ///
    /// This form supports evaluator-owned root stores whose heterogeneous
    /// slots cannot be borrowed mutably at the same time. The caller must
    /// validate every write target, call this method, and then commit without
    /// allowing the suspended mutator to resume between validation and writes.
    ///
    /// # Errors
    ///
    /// Returns [`DirectRootRewriteError`] when observation coverage is not
    /// exactly one-to-one or any observed word differs from its expected word.
    pub(in crate::eval) fn validate_observations(
        &self,
        observations: &[DirectRootObservation],
    ) -> Result<(), DirectRootRewriteError> {
        for duplicate in 0..observations.len() {
            for first in 0..duplicate {
                if observations[first].source == observations[duplicate].source {
                    return Err(DirectRootRewriteError::DuplicateObservationSource {
                        root_source: observations[duplicate].source.clone(),
                        first,
                        duplicate,
                    });
                }
            }
        }
        if observations.len() != self.rewrites.len() {
            return Err(DirectRootRewriteError::ObservationCountMismatch {
                expected: self.rewrites.len(),
                actual: observations.len(),
            });
        }
        for rewrite in &self.rewrites {
            let observation = observations
                .iter()
                .find(|observation| observation.source == rewrite.source)
                .ok_or_else(|| DirectRootRewriteError::MissingObservation {
                    root_source: rewrite.source.clone(),
                })?;
            if !observation.value.raw_eq(rewrite.expected) {
                return Err(DirectRootRewriteError::StaleBinding {
                    root_source: rewrite.source.clone(),
                    expected_tag: rewrite.expected.tag(),
                    expected_payload: rewrite.expected.payload_bits(),
                    actual_tag: observation.value.tag(),
                    actual_payload: observation.value.payload_bits(),
                });
            }
        }
        Ok(())
    }

    fn validate_bindings(
        &self,
        bindings: &[DirectRootBinding<'_>],
    ) -> Result<(), DirectRootRewriteError> {
        for duplicate in 0..bindings.len() {
            for first in 0..duplicate {
                if bindings[first].source == bindings[duplicate].source {
                    return Err(DirectRootRewriteError::DuplicateBindingSource {
                        root_source: bindings[duplicate].source.clone(),
                        first,
                        duplicate,
                    });
                }
            }
        }

        if bindings.len() != self.rewrites.len() {
            return Err(DirectRootRewriteError::BindingCountMismatch {
                expected: self.rewrites.len(),
                actual: bindings.len(),
            });
        }

        for rewrite in &self.rewrites {
            let mut matching = None;
            for binding in bindings {
                if binding.source == rewrite.source {
                    matching = Some(binding);
                    break;
                }
            }
            let Some(binding) = matching else {
                return Err(DirectRootRewriteError::MissingBinding {
                    root_source: rewrite.source.clone(),
                });
            };
            let actual = *binding.value;
            if !actual.raw_eq(rewrite.expected) {
                return Err(DirectRootRewriteError::StaleBinding {
                    root_source: rewrite.source.clone(),
                    expected_tag: rewrite.expected.tag(),
                    expected_payload: rewrite.expected.payload_bits(),
                    actual_tag: actual.tag(),
                    actual_payload: actual.payload_bits(),
                });
            }
        }

        Ok(())
    }
}

/// One copied raw root word observed while the mutator remains suspended.
#[derive(Clone, Debug)]
pub(in crate::eval) struct DirectRootObservation {
    source: EvalRootSource,
    value: Value,
}

impl DirectRootObservation {
    /// Records the current word for one exact root source.
    pub(in crate::eval) const fn new(source: EvalRootSource, value: Value) -> Self {
        Self { source, value }
    }
}

/// An explicit mutable binding to one live raw-value root slot.
#[derive(Debug)]
pub(in crate::eval) struct DirectRootBinding<'a> {
    source: EvalRootSource,
    value: &'a mut Value,
}

impl<'a> DirectRootBinding<'a> {
    /// Binds an exact root source to its caller-owned live storage.
    pub(in crate::eval) fn new(source: EvalRootSource, value: &'a mut Value) -> Self {
        Self { source, value }
    }

    /// Returns the exact root source represented by this binding.
    pub(in crate::eval) const fn source(&self) -> &EvalRootSource {
        &self.source
    }

    /// Returns the current raw value in the bound live root.
    pub(in crate::eval) const fn value(&self) -> Value {
        *self.value
    }
}

/// A summary of raw-value roots committed by one rewrite transaction.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub(in crate::eval) struct DirectRootRewriteReport {
    rewrites: usize,
}

impl DirectRootRewriteReport {
    /// Returns the number of live root slots rewritten.
    pub(in crate::eval) const fn rewrites(self) -> usize {
        self.rewrites
    }
}

/// A packed-publication raw root transaction was ambiguous or stale.
#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub(in crate::eval) enum DirectRootRewriteError {
    /// Two identical plan entries name the same exact root.
    #[error(
        "direct root rewrite source {root_source:?} is duplicated at plan indices {first} and {duplicate}"
    )]
    DuplicateRewriteSource {
        /// The duplicated exact root source.
        root_source: EvalRootSource,
        /// The first plan index.
        first: usize,
        /// The duplicate plan index.
        duplicate: usize,
    },
    /// Two plan entries disagree about the same exact root.
    #[error(
        "direct root rewrite source {root_source:?} conflicts at plan indices {first} and {conflicting}"
    )]
    ConflictingRewriteSource {
        /// The conflicting exact root source.
        root_source: EvalRootSource,
        /// The first plan index.
        first: usize,
        /// The conflicting plan index.
        conflicting: usize,
    },
    /// The caller supplied a different number of bindings than rewrites.
    #[error("direct root rewrite expected {expected} bindings, found {actual}")]
    BindingCountMismatch {
        /// The exact number of bindings required by the plan.
        expected: usize,
        /// The number of bindings supplied by the caller.
        actual: usize,
    },
    /// Two mutable bindings claim the same exact root source.
    #[error(
        "direct root binding source {root_source:?} is duplicated at binding indices {first} and {duplicate}"
    )]
    DuplicateBindingSource {
        /// The duplicated exact root source.
        root_source: EvalRootSource,
        /// The first binding index.
        first: usize,
        /// The duplicate binding index.
        duplicate: usize,
    },
    /// The caller supplied a different number of observations than rewrites.
    #[error("direct root rewrite expected {expected} observations, found {actual}")]
    ObservationCountMismatch {
        /// The exact number of observations required by the plan.
        expected: usize,
        /// The number supplied by the caller.
        actual: usize,
    },
    /// Two copied observations claim the same exact root source.
    #[error(
        "direct root observation source {root_source:?} is duplicated at indices {first} and {duplicate}"
    )]
    DuplicateObservationSource {
        /// The duplicated exact root source.
        root_source: EvalRootSource,
        /// The first observation index.
        first: usize,
        /// The duplicate observation index.
        duplicate: usize,
    },
    /// No copied observation names one of the planned roots.
    #[error("direct root rewrite source {root_source:?} has no copied observation")]
    MissingObservation {
        /// The unobserved exact root source.
        root_source: EvalRootSource,
    },
    /// No supplied binding names one of the plan's exact roots.
    #[error("direct root rewrite source {root_source:?} has no mutable binding")]
    MissingBinding {
        /// The unbound exact root source.
        root_source: EvalRootSource,
    },
    /// A live root changed after the rewrite plan was prepared.
    #[error(
        "direct root rewrite source {root_source:?} expected {expected_tag:?}/0x{expected_payload:016x}, found {actual_tag:?}/0x{actual_payload:016x}"
    )]
    StaleBinding {
        /// The stale exact root source.
        root_source: EvalRootSource,
        /// The expected raw value tag.
        expected_tag: ValueTag,
        /// The expected raw value payload.
        expected_payload: u64,
        /// The current raw value tag.
        actual_tag: ValueTag,
        /// The current raw value payload.
        actual_payload: u64,
    },
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::heap::{ArenaDomainId, ArenaIndex};
    use crate::value::compressed::CompressedValueWord;

    fn source(slot: usize) -> EvalRootSource {
        EvalRootSource::ValueStack { slot }
    }

    fn rewrite(slot: usize, expected: Value, replacement: Value) -> DirectRootRewrite {
        DirectRootRewrite::new(source(slot), expected, replacement)
    }

    #[test]
    fn validates_all_bindings_before_mutating_any_root() {
        let original_first = Value::int(1);
        let original_second = Value::int(2);
        let mut first = original_first;
        let mut second = Value::int(99);
        let plan = DirectRootRewritePlan::try_new(vec![
            rewrite(0, original_first, Value::int(10)),
            rewrite(1, original_second, Value::int(20)),
        ])
        .expect("distinct plan builds");
        let mut bindings = [
            DirectRootBinding::new(source(0), &mut first),
            DirectRootBinding::new(source(1), &mut second),
        ];

        let error = plan
            .apply(&mut bindings)
            .expect_err("stale second root rejects transaction");

        assert!(matches!(
            error,
            DirectRootRewriteError::StaleBinding {
                root_source: EvalRootSource::ValueStack { slot: 1 },
                ..
            }
        ));
        assert!(first.raw_eq(original_first));
        assert!(second.raw_eq(Value::int(99)));
    }

    #[test]
    fn commits_bindings_in_source_order_not_slice_order() {
        let mut first = Value::int(1);
        let mut second = Value::int(2);
        let plan = DirectRootRewritePlan::try_new(vec![
            rewrite(0, first, Value::int(10)),
            rewrite(1, second, Value::int(20)),
        ])
        .expect("distinct plan builds");
        let mut bindings = [
            DirectRootBinding::new(source(1), &mut second),
            DirectRootBinding::new(source(0), &mut first),
        ];

        let report = plan.apply(&mut bindings).expect("bindings commit");

        assert_eq!(report.rewrites(), 2);
        assert!(first.raw_eq(Value::int(10)));
        assert!(second.raw_eq(Value::int(20)));
    }

    #[test]
    fn copied_observations_validate_before_heterogeneous_root_commit() {
        let plan = DirectRootRewritePlan::try_new(vec![
            rewrite(0, Value::int(1), Value::int(10)),
            rewrite(1, Value::int(2), Value::int(20)),
        ])
        .expect("distinct plan builds");
        let observations = [
            DirectRootObservation::new(source(1), Value::int(2)),
            DirectRootObservation::new(source(0), Value::int(1)),
        ];
        plan.validate_observations(&observations)
            .expect("complete observations validate");

        let stale = [
            DirectRootObservation::new(source(0), Value::int(1)),
            DirectRootObservation::new(source(1), Value::int(99)),
        ];
        assert!(matches!(
            plan.validate_observations(&stale),
            Err(DirectRootRewriteError::StaleBinding {
                root_source: EvalRootSource::ValueStack { slot: 1 },
                ..
            })
        ));
    }

    #[test]
    fn rejects_duplicate_and_conflicting_plan_sources() {
        let duplicate = DirectRootRewritePlan::try_new(vec![
            rewrite(0, Value::int(1), Value::int(2)),
            rewrite(0, Value::int(1), Value::int(2)),
        ])
        .expect_err("duplicate plan rejects");
        assert!(matches!(
            duplicate,
            DirectRootRewriteError::DuplicateRewriteSource { .. }
        ));

        let conflict = DirectRootRewritePlan::try_new(vec![
            rewrite(0, Value::int(1), Value::int(2)),
            rewrite(0, Value::int(1), Value::int(3)),
        ])
        .expect_err("conflicting plan rejects");
        assert!(matches!(
            conflict,
            DirectRootRewriteError::ConflictingRewriteSource { .. }
        ));
    }

    #[test]
    fn rejects_duplicate_or_incomplete_binding_coverage() {
        let plan = DirectRootRewritePlan::try_new(vec![
            rewrite(0, Value::int(1), Value::int(10)),
            rewrite(1, Value::int(2), Value::int(20)),
        ])
        .expect("distinct plan builds");
        let mut first = Value::int(1);
        let mut duplicate = Value::int(1);
        let mut duplicate_bindings = [
            DirectRootBinding::new(source(0), &mut first),
            DirectRootBinding::new(source(0), &mut duplicate),
        ];
        assert!(matches!(
            plan.apply(&mut duplicate_bindings),
            Err(DirectRootRewriteError::DuplicateBindingSource { .. })
        ));
        assert!(first.raw_eq(Value::int(1)));
        assert!(duplicate.raw_eq(Value::int(1)));

        let mut only = Value::int(1);
        let mut incomplete = [DirectRootBinding::new(source(0), &mut only)];
        assert_eq!(
            plan.apply(&mut incomplete),
            Err(DirectRootRewriteError::BindingCountMismatch {
                expected: 2,
                actual: 1,
            })
        );
        assert!(only.raw_eq(Value::int(1)));

        let mut matched = Value::int(1);
        let mut unexpected = Value::int(3);
        let mut wrong_source = [
            DirectRootBinding::new(source(0), &mut matched),
            DirectRootBinding::new(source(2), &mut unexpected),
        ];
        assert_eq!(
            plan.apply(&mut wrong_source),
            Err(DirectRootRewriteError::MissingBinding {
                root_source: source(1),
            })
        );
        assert!(matched.raw_eq(Value::int(1)));
        assert!(unexpected.raw_eq(Value::int(3)));
    }

    #[test]
    fn commits_logical_packed_coordinate_as_opaque_raw_word() {
        let domain = ArenaDomainId::allocate_logical().expect("logical domain allocates");
        let packed_word = CompressedValueWord::heap(domain, ValueTag::List, ArenaIndex::new(37))
            .expect("packed list word builds");
        let packed = Value::from_word(packed_word);
        let expected = Value::int(7);
        let mut root = expected;
        let plan = DirectRootRewritePlan::try_new(vec![rewrite(0, expected, packed)])
            .expect("packed rewrite plan builds");
        let mut bindings = [DirectRootBinding::new(source(0), &mut root)];

        plan.apply(&mut bindings)
            .expect("packed coordinate commits without resolution");

        assert!(root.raw_eq(packed));
        assert_eq!(root.word().arena_domain(), Some(domain));
    }
}
