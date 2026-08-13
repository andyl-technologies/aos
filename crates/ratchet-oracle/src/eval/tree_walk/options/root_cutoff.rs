//! Root-level early-cutoff option accessors for `TreeWalkOptions`.
//!
//! Groups the toggles that govern whether a fully warm `instantiate(file, attr)`
//! may be answered from a durable root record (skipping parse, lower, and eval)
//! and whether such a cutoff is cross-checked against a full evaluation.

use super::*;

impl TreeWalkOptions {
    /// Enables or disables root-level early cutoff for file instantiation.
    ///
    /// When enabled (and a persistent-cache root is configured), a fully warm
    /// `instantiate(file, attr)` can be answered from a durable root record by
    /// revalidating the recorded transitive impure inputs and re-emitting the
    /// stored closure without parsing, lowering, or evaluating. Any mismatch,
    /// missing record, or error falls through to a normal evaluation.
    pub fn set_root_cutoff_enabled(&mut self, root_cutoff_enabled: bool) {
        self.root_cutoff_enabled = root_cutoff_enabled;
    }

    /// Enables or disables root-cutoff cross-check mode, which re-evaluates a
    /// taken cutoff and asserts a byte-identical closure, reporting divergence.
    pub fn set_root_cutoff_check(&mut self, root_cutoff_check: bool) {
        self.root_cutoff_check = root_cutoff_check;
    }

    /// Returns whether root-level early cutoff is enabled.
    pub const fn root_cutoff_enabled(&self) -> bool {
        self.root_cutoff_enabled
    }

    /// Returns whether root-cutoff cross-check mode is enabled.
    pub const fn root_cutoff_check(&self) -> bool {
        self.root_cutoff_check
    }
}
