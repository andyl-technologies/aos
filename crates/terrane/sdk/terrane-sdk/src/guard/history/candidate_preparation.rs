//! Binds reusable pure candidate data to exact inputs and live operation allocations.
//!
//! Weak discriminators retain neither Guard nor exclusion and confer no authority.

use std::sync::{Arc, Weak};
use terrane_format::{identity::Digest, provenance::VerifiedCommit, tree_format::TreeUse};

use super::completion::{PendingViewUse, SelectedInputs};
use crate::bucket::held::HeldIdentity;
use crate::guard::{Guard, TreeEvidence};
use crate::store::NativeExclusion;

/// Identifies complete pure inputs under one Guard and retained operation.
#[derive(Clone)]
pub(in crate::guard) struct Key {
    guard: Weak<()>,
    held: Weak<NativeExclusion>,
    inputs: SelectedInputs,
    view: Digest,
    root: Digest,
    default_domain: String,
    minimum: u64,
    usage: TreeUse,
    requested_usage: TreeUse,
}

impl Key {
    /// Captures exact inputs after the caller's fresh canonical acquisition.
    ///
    /// Missing or contradictory certificates and unheld observations disable
    /// reuse. Retained weak control blocks cannot be recycled into a new scope;
    /// replacement Guards and holders therefore miss even at recycled addresses.
    /// The sole production caller is `record_candidate`, immediately after
    /// `load_tree_for`: canonical addressed bytes determine the complete closure,
    /// graft paths and ordinary-root classification under this minimum and use.
    /// A manually edited evidence carrier is not fresh acquisition evidence.
    pub(in crate::guard) fn capture<S, C>(
        guard: &Guard<S, C>,
        held: Option<&HeldIdentity<'_>>,
        inputs: &SelectedInputs,
        commit: &VerifiedCommit,
        evidence: &TreeEvidence,
        requested_usage: TreeUse,
    ) -> Option<Self> {
        let minimum = guard.config().min_chunk_size;
        if commit.commit().tree != evidence.root
            || !evidence
                .grafts
                .as_ref()?
                .matches(evidence.root, minimum, evidence.usage)
        {
            return None;
        }
        Some(Self {
            guard: Arc::downgrade(&guard.candidate_preparation_scope),
            held: held?.candidate_preparation_scope()?,
            inputs: inputs.clone(),
            view: commit.identity(),
            root: evidence.root,
            default_domain: evidence.default_domain.clone(),
            minimum,
            usage: evidence.usage,
            requested_usage,
        })
    }

    /// Compares complete semantics and exact still-live owning allocations.
    pub(in crate::guard) fn matches(&self, other: &Self) -> bool {
        self.guard.strong_count() != 0
            && self.held.strong_count() != 0
            && other.guard.strong_count() != 0
            && other.held.strong_count() != 0
            && self.guard.ptr_eq(&other.guard)
            && self.held.ptr_eq(&other.held)
            && self.inputs == other.inputs
            && self.view == other.view
            && self.root == other.root
            && self.default_domain == other.default_domain
            && self.minimum == other.minimum
            && self.usage == other.usage
            && self.requested_usage == other.requested_usage
    }

    /// Returns the exact signed pending view named by this key.
    pub(in crate::guard) fn view(&self) -> Digest {
        self.view
    }

    /// Requires the key to describe the arguments passed to pure preparation.
    pub(in crate::guard) fn binds(
        &self,
        inputs: &SelectedInputs,
        commit: &VerifiedCommit,
        evidence: &TreeEvidence,
    ) -> bool {
        self.inputs == *inputs
            && self.view == commit.identity()
            && self.root == commit.commit().tree
            && self.root == evidence.root
            && self.default_domain == evidence.default_domain
            && self.usage == evidence.usage
            && evidence
                .grafts
                .as_ref()
                .is_some_and(|grafts| grafts.matches(self.root, self.minimum, self.usage))
    }

    /// Requires the surviving pending row to retain this key's complete pure data.
    pub(in crate::guard) fn covers(&self, pending: &PendingViewUse) -> bool {
        pending.inputs == self.inputs
            && pending.context().view == self.view
            && pending.context().original_root == self.root
            && pending.policy().view == self.view
            && pending.policy().default_domain == self.default_domain
    }
}
