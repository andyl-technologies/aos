//! Infallible commit staging for the benchmark's packed-publication roots.
//!
//! The whole-demand loop-head census admits only transient value-stack slots
//! and ready import-cache entries at the late memory checkpoints. This module
//! deliberately supports exactly those stable, allocation-free write channels
//! and rejects every other [`EvalRootSource`] before publication. Preparation
//! allocates compact coordinate/replacement vectors and validates every current
//! raw word. Commit runs while the mutator remains suspended and performs only
//! direct stores and ordered import-cache iteration.

use thiserror::Error;

use super::*;

/// A fully validated, allocation-free packed root commit.
#[derive(Debug)]
pub(in crate::eval) struct PackedMutatorRootStage {
    value_stack: Vec<(usize, Value)>,
    import_cache: Vec<(usize, Value)>,
}

impl PackedMutatorRootStage {
    /// Returns the exact number of prevalidated root rewrites.
    pub(in crate::eval) fn rewrite_count(&self) -> usize {
        self.value_stack
            .len()
            .saturating_add(self.import_cache.len())
    }

    /// Returns allocator-capacity bytes owned by the staged root vectors.
    pub(in crate::eval) fn capacity_bytes(&self) -> Option<usize> {
        self.value_stack
            .capacity()
            .checked_add(self.import_cache.capacity())?
            .checked_mul(std::mem::size_of::<(usize, Value)>())
    }
}

impl TreeWalk {
    /// Stages the exact supported root rewrites without mutating evaluator state.
    ///
    /// # Errors
    ///
    /// Returns [`PackedMutatorRootStageError`] if staging storage cannot be
    /// reserved, a root class lacks an infallible commit channel at the
    /// whole-demand loop head, a coordinate is absent, or its current raw word
    /// differs from the prepared observation.
    pub(in crate::eval) fn stage_packed_mutator_roots(
        &self,
        plan: &DirectRootRewritePlan,
    ) -> Result<PackedMutatorRootStage, PackedMutatorRootStageError> {
        let value_stack_count = plan
            .rewrites()
            .iter()
            .filter(|rewrite| matches!(rewrite.source(), EvalRootSource::ValueStack { .. }))
            .count();
        let import_cache_count = plan.len().saturating_sub(value_stack_count);
        let mut value_stack = try_stage_vec(value_stack_count, "value-stack")?;
        let mut import_cache = try_stage_vec(import_cache_count, "import-cache")?;

        for rewrite in plan.rewrites() {
            let current =
                match rewrite.source() {
                    EvalRootSource::ValueStack { slot } => {
                        let current = self
                            .transient_value_stack_roots
                            .get(*slot)
                            .copied()
                            .ok_or_else(|| PackedMutatorRootStageError::Unavailable {
                                root_source: rewrite.source().clone(),
                            })?;
                        value_stack.push((*slot, rewrite.replacement()));
                        current
                    }
                    EvalRootSource::ImportCache { index } => {
                        let current = ready_import_cache_value(&self.import_cache, *index)
                            .ok_or_else(|| PackedMutatorRootStageError::Unavailable {
                                root_source: rewrite.source().clone(),
                            })?;
                        import_cache.push((*index, rewrite.replacement()));
                        current
                    }
                    root_source => {
                        return Err(PackedMutatorRootStageError::Unsupported {
                            root_source: root_source.clone(),
                        });
                    }
                };
            if !current.raw_eq(rewrite.expected()) {
                return Err(PackedMutatorRootStageError::Stale {
                    root_source: rewrite.source().clone(),
                    expected: rewrite.expected().word().raw(),
                    actual: current.word().raw(),
                });
            }
        }

        value_stack.sort_unstable_by_key(|(slot, _)| *slot);
        import_cache.sort_unstable_by_key(|(index, _)| *index);
        if value_stack.windows(2).any(|pair| pair[0].0 == pair[1].0)
            || import_cache.windows(2).any(|pair| pair[0].0 == pair[1].0)
        {
            return Err(PackedMutatorRootStageError::DuplicateCoordinate);
        }
        Ok(PackedMutatorRootStage {
            value_stack,
            import_cache,
        })
    }

    /// Commits a validated root stage without allocation or a recoverable error.
    ///
    /// The caller must preserve the suspended evaluator state between
    /// [`Self::stage_packed_mutator_roots`] and this call.
    ///
    /// # Panics
    ///
    /// Panics only if the caller violates the suspension invariant and removes
    /// a validated transient value-stack slot before commit.
    pub(in crate::eval) fn commit_packed_mutator_roots(&mut self, stage: PackedMutatorRootStage) {
        for (slot, replacement) in stage.value_stack {
            self.transient_value_stack_roots[slot] = replacement;
        }

        let mut replacements = stage.import_cache.into_iter().peekable();
        let mut ready_index = 0usize;
        for entry in self.import_cache.values_mut() {
            let ImportCacheEntry::Ready { value, .. } = entry else {
                continue;
            };
            if replacements
                .peek()
                .is_some_and(|(index, _)| *index == ready_index)
            {
                if let Some((_, replacement)) = replacements.next() {
                    *value = replacement;
                }
            }
            ready_index = ready_index.saturating_add(1);
        }
        debug_assert!(replacements.next().is_none());
    }
}

fn ready_import_cache_value(
    import_cache: &BTreeMap<PathBuf, ImportCacheEntry>,
    target: usize,
) -> Option<Value> {
    let mut ready_index = 0usize;
    for entry in import_cache.values() {
        let ImportCacheEntry::Ready { value, .. } = entry else {
            continue;
        };
        if ready_index == target {
            return Some(*value);
        }
        ready_index = ready_index.saturating_add(1);
    }
    None
}

fn try_stage_vec(
    entries: usize,
    storage: &'static str,
) -> Result<Vec<(usize, Value)>, PackedMutatorRootStageError> {
    let mut values = Vec::new();
    values
        .try_reserve_exact(entries)
        .map_err(|_| PackedMutatorRootStageError::AllocationFailed { storage, entries })?;
    Ok(values)
}

/// Packed mutator-root staging failed before publication.
#[derive(Debug, Error)]
pub(in crate::eval) enum PackedMutatorRootStageError {
    /// Exact staging storage could not be reserved.
    #[error("packed root staging could not reserve {entries} {storage} entries")]
    AllocationFailed {
        /// Root storage class.
        storage: &'static str,
        /// Exact entry count.
        entries: usize,
    },
    /// The loop head exposed a root class without an infallible commit channel.
    #[error("packed root staging does not support {root_source:?} at this loop head")]
    Unsupported {
        /// Rejected root source.
        root_source: EvalRootSource,
    },
    /// A prepared root coordinate is no longer present.
    #[error("packed root staging could not resolve {root_source:?}")]
    Unavailable {
        /// Missing root source.
        root_source: EvalRootSource,
    },
    /// A root changed after the collection-poll snapshot.
    #[error(
        "packed root staging found stale {root_source:?}: expected {expected:#018x}, actual {actual:#018x}"
    )]
    Stale {
        /// Stale root source.
        root_source: EvalRootSource,
        /// Prepared raw word.
        expected: u64,
        /// Current raw word.
        actual: u64,
    },
    /// Two rewrites unexpectedly named the same stable coordinate.
    #[error("packed root staging found a duplicate stable coordinate")]
    DuplicateCoordinate,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::compile::resolve as resolve_ast;
    use crate::string::NixString;
    use crate::syntax::parse_str;

    #[test]
    fn value_stack_and_ready_import_cache_commit_without_revalidation() {
        let parsed = parse_str("null").expect("source parses");
        let resolved = resolve_ast(parsed).expect("source resolves");
        let ir = aos_nix_dialect::nix_lower(resolved).expect("source lowers");
        let mut evaluator = TreeWalk::new(&ir);
        let stack_source = evaluator
            .heap
            .alloc_string(NixString::from_bytes(b"stack-source".to_vec()))
            .expect("stack source allocates");
        let stack_replacement = evaluator
            .heap
            .alloc_string(NixString::from_bytes(b"stack-replacement".to_vec()))
            .expect("stack replacement allocates");
        let cache_source = evaluator
            .heap
            .alloc_string(NixString::from_bytes(b"cache-source".to_vec()))
            .expect("cache source allocates");
        let cache_replacement = evaluator
            .heap
            .alloc_string(NixString::from_bytes(b"cache-replacement".to_vec()))
            .expect("cache replacement allocates");
        evaluator.transient_value_stack_roots.push(stack_source);
        evaluator.import_cache.insert(
            PathBuf::from("/ready"),
            ImportCacheEntry::Ready {
                value: cache_source,
                trace: None,
                force_cache_trace_complete: true,
            },
        );
        let plan = DirectRootRewritePlan::try_new(vec![
            crate::eval::heap::DirectRootRewrite::new(
                EvalRootSource::ValueStack { slot: 0 },
                stack_source,
                stack_replacement,
            ),
            crate::eval::heap::DirectRootRewrite::new(
                EvalRootSource::ImportCache { index: 0 },
                cache_source,
                cache_replacement,
            ),
        ])
        .expect("root plan builds");

        let stage = evaluator
            .stage_packed_mutator_roots(&plan)
            .expect("supported roots stage");
        assert!(evaluator.transient_value_stack_roots[0].raw_eq(stack_source));
        assert!(
            ready_import_cache_value(&evaluator.import_cache, 0)
                .is_some_and(|value| value.raw_eq(cache_source))
        );

        evaluator.commit_packed_mutator_roots(stage);

        assert!(evaluator.transient_value_stack_roots[0].raw_eq(stack_replacement));
        assert!(
            ready_import_cache_value(&evaluator.import_cache, 0)
                .is_some_and(|value| value.raw_eq(cache_replacement))
        );
    }
}
