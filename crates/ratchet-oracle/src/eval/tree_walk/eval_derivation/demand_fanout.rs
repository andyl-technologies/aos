//! Eager entry-time demand fan-out for `derivationStrict` (L2-P5).
//!
//! When a derivation's strict evaluation begins, every attribute entry is
//! already committed demand: the serial loop in
//! `eval_derivation_strict_value_inner` unconditionally forces every attribute
//! value, and string-coerces every non-scalar attribute - element by element
//! for lists (`append_derivation_list_to_string_fields`), through `outPath`
//! for hookless attrsets (`derivation_attrs_to_string_value`), and through the
//! same shapes under `__structuredAttrs` (`write_json_value` recurses lists
//! and coerces `outPath`-bearing attrsets). Publishing that coercion demand at
//! *entry* - instead of after the serial loop has ground through the
//! attributes that lexicographically precede it - lets helper workers walk the
//! dependency closure ahead of the serializer: a helper that coerces a
//! dependency attrset forces its `outPath`, which runs that dependency's own
//! `derivationStrict`, which publishes *its* entry fan-out in turn, unfolding
//! the transitive `.drv` closure breadth-first while the main worker
//! serializes it depth-first.
//!
//! Running ahead top-down at entry is the only sound direction: a completed
//! derivation's `input_derivations` edges name derivations that were already
//! strictly evaluated (the edges exist only as string context produced by
//! coercing the inputs' `outPath`s, and `known_derivation_hashes_for_inputs`
//! *errors* on an unknown input), so a completion-time hook over `inputDrvs`
//! could never publish unevaluated work.
//!
//! Everything published here mirrors demand the serial loop performs for the
//! same entry, kind for kind:
//!
//! - scalar-only special attributes (`name`, `builder`, `system`, the hash
//!   declarations, and the boolean `__` toggles) are forced but never reach
//!   element coercion, so they publish as [`DemandTaskKind::Force`];
//! - every other attribute publishes as [`DemandTaskKind::Coerce`], whose
//!   executor forces the value, recurses into list elements, and forces the
//!   `outPath` of hookless attrsets - a subset of both the plain string
//!   coercion and the structured-attrs JSON serialization of that entry.
//!
//! `__ignoreNulls` needs no special casing: the serial loop forces every
//! entry value *before* the null check, and coercing a forced `null` is a
//! no-op in the task executor.

use super::*;

impl TreeWalk {
    /// True for derivation attribute keys whose serial handling never
    /// string-coerces list elements or attrset `outPath`s.
    ///
    /// These attributes are forced and validated as scalars (strings or
    /// booleans); publishing coercion fan-out for them would be speculative
    /// work the serial evaluator is not committed to (a list value type-errors
    /// instead of reaching element coercion).
    pub(in crate::eval::tree_walk) fn derivation_scalar_only_attr(key: &[u8]) -> bool {
        const SCALAR_ONLY_KEYS: &[&[u8]] = &[
            NAME_ATTR,
            BUILDER_ATTR,
            SYSTEM_ATTR,
            IGNORE_NULLS_ATTR,
            STRUCTURED_ATTRS_ATTR,
            CONTENT_ADDRESSED_ATTR,
            IMPURE_ATTR,
            OUTPUT_HASH_ATTR,
            OUTPUT_HASH_ALGO_ATTR,
            OUTPUT_HASH_MODE_ATTR,
        ];
        SCALAR_ONLY_KEYS.contains(&key)
    }

    /// Publishes eager entry-time fan-out for a `derivationStrict` call.
    ///
    /// Splits `entries` by the demand the serial attribute loop is committed
    /// to: scalar-only keys publish unforced thunks as force-only tasks, and
    /// every other key publishes its value (thunk, list, or attrset) as a
    /// coercion task whose executor unfolds dependency subtrees transitively.
    /// No-op unless this evaluation runs a demand pool.
    pub(in crate::eval::tree_walk) fn publish_derivation_entry_fanout(
        &mut self,
        entries: &[AttrEntry],
    ) {
        if self.shared.is_none() {
            return;
        }
        let mut force = Vec::new();
        let mut coerce = Vec::new();
        for entry in entries {
            let Some(key) = self.symbols.resolve(entry.key) else {
                continue;
            };
            let is_unforced_thunk = matches!(
                classify_whnf_tag_fast_path(entry.value),
                WhnfTagFastPath::RequiresThunkProtocol(_)
            );
            if Self::derivation_scalar_only_attr(key) {
                if is_unforced_thunk {
                    force.push(entry.value);
                }
            } else if is_unforced_thunk
                || matches!(entry.value.tag(), ValueTag::Attrs | ValueTag::List)
            {
                coerce.push(entry.value);
            }
        }
        self.publish_demand_values(parallel_demand::DemandTaskKind::Force, &force);
        self.publish_demand_values(parallel_demand::DemandTaskKind::Coerce, &coerce);
    }
}
