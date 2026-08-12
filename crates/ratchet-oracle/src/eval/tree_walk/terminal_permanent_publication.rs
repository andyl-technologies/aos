//! Default-off terminal publication of a compact permanent generation.
//!
//! This is the first end-to-end proving ground for whole-permanent relocation.
//! It runs only after root evaluation has fully unwound, sweeps unreachable
//! worker objects first, copies the mutator-reachable permanent graph, stages
//! every heap and root rewrite, publishes the destination, and retires the
//! source only after a fresh precise scan proves that no retained source word
//! remains. The terminal-only gate keeps dynamic stacks and native frames out
//! of the transaction until their moving-writeback protocols are proven.

use super::*;

const TERMINAL_PERMANENT_PUBLICATION_ENV: &str = "AOS_NIX_PERMANENT_EVACUATE_TERMINAL";

impl TreeWalk {
    /// Publishes and retires the reachable permanent graph at a strict terminal point.
    ///
    /// The door is default off and returns `Ok(None)` unless
    /// `AOS_NIX_PERMANENT_EVACUATE_TERMINAL=1`. It also declines unless every
    /// evaluator continuation, dynamic scope, native session, remembered edge,
    /// and dirty card is absent.
    ///
    /// # Errors
    ///
    /// Returns [`TreeWalkError`] if unconditional worker sweeping, precise root
    /// collection, destination preparation, root-writeback validation,
    /// publication, the post-publication alias audit, or source retirement
    /// cannot complete.
    pub(in crate::eval::tree_walk) fn maybe_publish_terminal_permanent(
        &mut self,
        value: &mut Value,
    ) -> Result<Option<crate::eval::heap::PermanentRetirementReport>, TreeWalkError> {
        if !terminal_permanent_publication_enabled()
            || !self.is_terminal_permanent_publication_quiescent()
        {
            return Ok(None);
        }
        self.publish_terminal_permanent(value).map(Some)
    }

    fn publish_terminal_permanent(
        &mut self,
        value: &mut Value,
    ) -> Result<crate::eval::heap::PermanentRetirementReport, TreeWalkError> {
        // Unreachable worker objects can retain old permanent words even
        // though they are absent from a mutator-root scan. Remove them before
        // staging the complete retained heap rewrite.
        self.sweep_heap_for_validation(&[*value])?;
        if !self.is_terminal_permanent_publication_quiescent() {
            return Err(self.terminal_permanent_publication_error(
                "post-sweep quiescence",
                "the terminal root set changed while sweeping",
            ));
        }

        let mut roots = self
            .mutator_root_set()
            .map_err(|error| self.terminal_permanent_publication_error("root collection", error))?;
        roots.try_push_value_stack(0, *value).map_err(|error| {
            self.terminal_permanent_publication_error("result root publication", error)
        })?;
        let scan = self
            .heap
            .scan_precise_roots(&roots)
            .map_err(|error| self.terminal_permanent_publication_error("precise scan", error))?;
        let prepared = self
            .heap
            .prepare_permanent_publication(&scan)
            .map_err(|error| self.terminal_permanent_publication_error("preparation", error))?;
        let root_writebacks = prepared.root_writebacks().clone();
        let mut value_stack = [*value];
        let mut slots = self
            .safepoint_root_value_writeback_slots(&root_writebacks, &value_stack, &[])
            .map_err(|error| self.terminal_permanent_publication_error("root readback", error))?;
        root_writebacks
            .apply_to_value_slots(&mut slots)
            .map_err(|error| {
                self.terminal_permanent_publication_error("root rewrite validation", error)
            })?;
        self.validate_safepoint_root_writeback_targets(&slots, &value_stack, &[])
            .map_err(|error| {
                self.terminal_permanent_publication_error("root target validation", error)
            })?;
        drop(scan);
        drop(roots);

        let published = self
            .heap
            .publish_prepared_permanent(prepared)
            .map_err(|error| self.terminal_permanent_publication_error("publication", error))?;
        let mut primop_arguments: [Value; 0] = [];
        for slot in &slots {
            self.write_safepoint_root_writeback_value(
                slot.source(),
                slot.value(),
                &mut value_stack,
                &mut primop_arguments,
            )
            .map_err(|error| self.terminal_permanent_publication_error("root commit", error))?;
        }
        *value = value_stack[0];
        self.force_payload_memo
            .try_borrow_mut()
            .map_err(|error| self.terminal_permanent_publication_error("memo invalidation", error))?
            .clear();

        let mut healed_roots = self.mutator_root_set().map_err(|error| {
            self.terminal_permanent_publication_error("healed root collection", error)
        })?;
        healed_roots
            .try_push_value_stack(0, *value)
            .map_err(|error| {
                self.terminal_permanent_publication_error("healed result root", error)
            })?;
        let healed_scan = self
            .heap
            .scan_precise_roots(&healed_roots)
            .map_err(|error| {
                self.terminal_permanent_publication_error("healed precise scan", error)
            })?;
        let residual_aliases = self.heap.residual_permanent_source_aliases(&healed_scan);
        if residual_aliases != 0 {
            return Err(self.terminal_permanent_publication_error(
                "source alias audit",
                format!("{residual_aliases} retained source words remain"),
            ));
        }

        let report = self.heap.retire_published_permanent_source(published);
        eprintln!(
            "aos_nix_terminal_permanent_publication \
             {{\"retired_objects\":{},\"copied_objects\":{},\
             \"healed_heap_fields\":{},\"candidate_pages\":{},\
             \"advised_pages\":{},\"advice_failed\":{}}}",
            report.retired_objects(),
            report.copied_objects(),
            report.healed_heap_fields(),
            report.candidate_pages(),
            report.advised_pages(),
            report.advice_failed()
        );
        Ok(report)
    }

    fn is_terminal_permanent_publication_quiescent(&self) -> bool {
        self.has_complete_terminal_root_set()
            && self.active_env_is_empty()
            && self.with_scopes.is_empty()
            && self.scoped_globals.is_empty()
            && self.active_gc_stress_accumulator_allocation_node.is_none()
            && self.active_gc_stress_primop_arg_root_admission_depth == 0
            && self.active_derivation_trace_cursors.is_empty()
            && self.thunk_resolve_remembered_set.is_empty()
            && self.thunk_resolve_card_table.is_empty()
    }

    fn terminal_permanent_publication_error(
        &self,
        stage: &'static str,
        error: impl std::fmt::Display,
    ) -> TreeWalkError {
        let id = self.current_ir().root;
        let span = match self.current_ir().arena.node(id) {
            Some(node) => node.span,
            None => Span::default(),
        };
        TreeWalkError::new(
            TreeWalkErrorKind::TerminalPermanentPublication {
                id,
                stage,
                reason: error.to_string(),
            },
            span,
        )
    }
}

fn terminal_permanent_publication_enabled() -> bool {
    std::env::var(TERMINAL_PERMANENT_PUBLICATION_ENV).is_ok_and(|setting| setting == "1")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::compile::resolve as resolve_ast;
    use crate::syntax::parse_str;

    #[test]
    fn terminal_publication_rewrites_result_and_retires_source() {
        let parsed = parse_str("\"terminal\"").expect("source parses");
        let resolved = resolve_ast(parsed).expect("source resolves");
        let ir = aos_nix_dialect::nix_lower(resolved).expect("source lowers");
        let mut evaluator = TreeWalk::with_options(&ir, TreeWalkOptions::default());
        let mut value = evaluator.eval_root().expect("source evaluates");
        let source = value;

        let report = evaluator
            .publish_terminal_permanent(&mut value)
            .expect("terminal publication succeeds");

        assert!(!value.raw_eq(source));
        assert_eq!(report.retired_objects(), 1);
        assert_eq!(report.copied_objects(), 1);
        assert!(evaluator.heap.get_string(source).is_err());
        assert_eq!(
            evaluator
                .heap
                .get_string(value)
                .expect("published result resolves")
                .bytes(),
            b"terminal"
        );
    }
}
