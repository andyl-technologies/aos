//! Owns actual selected Source construction and independently owed posts.
//!
//! Only the genuine continuously held C pre-Bank Source loan enters the fixed
//! native recipe. This owner drives complete raw semantic replay itself; no
//! caller-supplied semantic result, callback or ordinary UID opener admits the
//! protected Source owner. Its full reached state remains resident on refusal.

use aos_sandbox_broker::controller_receiving::{
    ControllerReceivingErrorV1, ControllerSourcePreBankConstructionLoanV1,
};
use aos_sandbox_broker::canonical_journal::CanonicalJournalMechanicalErrorV1;
use aos_sandbox_broker::source_receiving::{SourceNativeErrorV1, SourceWriterOpeningOriginalsV1};
use aos_sandbox_model::ResourceVector;
use aos_sandbox_journal::protected_storage::FileIdentity;
use aos_sandbox_ledger_replay::cold::ColdReplayRemainderDataV1;

use super::owner::SourceNativeJournalOwnerV1;
use super::semantic::{
    self, SourcePaidReplayV1, SourceSemanticOriginalV1, move_cold_remainder_data_v1,
};

/// Retains the fixed Source opening, full semantics and original post debts.
///
/// Actual lifecycle/project recovery runs with the returned same native owner
/// before `finish_posts` observes Source names and the independent C post.
/// No public factory accepts opened native custody, a path or a writer UID.
#[must_use]
pub struct SourceJournalConstructionOriginalsV1<P> {
    opening: SourceWriterOpeningOriginalsV1,
    semantics: Option<SourceSemanticOriginalV1>,
    preparation: Option<Result<(), SourceNativeErrorV1>>,
    semantic_preparation: Option<Result<(), SourceNativeErrorV1>>,
    semantic_shape: Option<Result<ResourceVector, CanonicalJournalMechanicalErrorV1>>,
    identity: Option<Result<FileIdentity, SourceNativeErrorV1>>,
    replay_entry: Option<Result<(), SourceNativeErrorV1>>,
    handoff: Option<Result<(), SourceNativeErrorV1>>,
    owner: Option<SourceNativeJournalOwnerV1<P>>,
    names: Option<Result<(), SourceNativeErrorV1>>,
    post: Option<Result<(), ControllerReceivingErrorV1>>,
    disposition: Option<Result<(), SourceNativeErrorV1>>,
    attempted: bool,
    taken: bool,
    finished: bool,
}

impl<P> SourceJournalConstructionOriginalsV1<P> {
    /// Creates vacant construction custody without claiming or opening anything.
    pub const fn new() -> Self {
        Self {
            opening: SourceWriterOpeningOriginalsV1::new(), semantics: None,
            preparation: None, semantic_preparation: None, semantic_shape: None,
            identity: None, replay_entry: None, handoff: None, owner: None,
            names: None, post: None, disposition: None, attempted: false, taken: false, finished: false,
        }
    }

    /// Opens the actual fixed Source recipe and drives its complete semantics.
    ///
    /// `Outer` prices the actual enclosing constructor's compiled storage only.
    /// It supplies no work, capacity, native custody or semantic completion.
    ///
    /// # Errors
    /// Retains the first original, representation, acquisition, native or full
    /// semantic replay refusal. The same independently owed posts remain due.
    pub fn open_once<Outer>(
        &mut self,
        loan: &mut ControllerSourcePreBankConstructionLoanV1<'_>,
    ) -> Result<(), ()> {
        self.open_with_recipe_once::<Outer>(loan, false)
    }

    /// Opens existing fixed Source history without creating or repairing it.
    ///
    /// # Errors
    /// Retains the same paid native/semantic cause and independently owed posts.
    pub fn open_existing_once<Outer>(
        &mut self,
        loan: &mut ControllerSourcePreBankConstructionLoanV1<'_>,
    ) -> Result<(), ()> {
        self.open_with_recipe_once::<Outer>(loan, true)
    }

    fn open_with_recipe_once<Outer>(
        &mut self,
        loan: &mut ControllerSourcePreBankConstructionLoanV1<'_>,
        existing_only: bool,
    ) -> Result<(), ()> {
        if self.attempted { return Err(()); }
        self.attempted = true;
        self.preparation = Some(if existing_only {
            self.opening.prepare_existing_once::<(Self, Outer)>(loan)
        } else { self.opening.prepare_once::<(Self, Outer)>(loan) });
        if !matches!(self.preparation, Some(Ok(()))) {
            return Err(());
        }
        self.semantic_shape = Some((|| {
            let fixed = semantic::fixed_demand_v1()?;
            let prefix = self.opening.captured_native_bytes_data_v1()
                .map_err(|_| CanonicalJournalMechanicalErrorV1::ProtectedBoundary)?;
            fixed.checked_add(aos_sandbox_ledger_replay::geometry::retained_challenge_history_demand_v1(prefix)?)
                .map_err(|_| CanonicalJournalMechanicalErrorV1::JournalTooLarge)
        })());
        let shape = self.semantic_shape.as_ref().and_then(|value| value.as_ref().ok())
            .copied().ok_or(())?;
        self.semantic_preparation = Some(self.opening.debit_semantic_representation_once(shape));
        if !matches!(self.semantic_preparation, Some(Ok(()))) {
            return Err(());
        }
        self.semantics = Some(SourceSemanticOriginalV1::new());
        self.identity = Some(self.opening.prepare_semantic_identity_once());
        let identity = self.identity.as_ref().and_then(|value| value.as_ref().ok())
            .copied().ok_or(())?;
        let limits = self.opening.fixed_limits();
        let (native, receiving) = match self.opening.begin_paid_replay_once() {
            Ok(value) => { self.replay_entry = Some(Ok(())); value }
            Err(cause) => { self.replay_entry = Some(Err(cause)); return Err(()); }
        };
        let mut cursor = SourcePaidReplayV1::new(native, receiving);
        self.semantics.as_mut().ok_or(())?
            .observe_native_once(&mut cursor, identity, limits)
    }

    /// Moves the same native owner and completed historical remainder once.
    ///
    /// Opaque `selection` remains in the same protected location; it is not
    /// reconstructed or interpreted as native/semantic admission.
    pub fn take_completed_once(
        &mut self,
        selection: P,
    ) -> Option<(SourceNativeJournalOwnerV1<P>, ColdReplayRemainderDataV1)> {
        if !self.attempted || self.taken || self.primary_failure().is_some() {
            return None;
        }
        let coordinator = match self.opening.take_coordinator_after_semantic_replay_once(selection) {
            Ok(value) => { self.handoff = Some(Ok(())); value }
            Err(cause) => { self.handoff = Some(Err(cause)); return None; }
        };
        self.owner = Some(SourceNativeJournalOwnerV1 { coordinator });
        let remainder = self.semantics.as_mut()?.take_remainder_once()?;
        self.taken = true;
        Some((self.owner.take()?, move_cold_remainder_data_v1(remainder)))
    }

    /// Attempts actual Source names then its independently armed C/profile post.
    ///
    /// # Errors
    /// Retains every owed post on any entered outcome; primary errors precede
    /// later name/profile debt, and poison does not suppress the observations.
    pub fn finish_posts(
        &mut self,
        source: Option<&SourceNativeJournalOwnerV1<P>>,
        loan: &mut ControllerSourcePreBankConstructionLoanV1<'_>,
    ) -> Result<(), ()> {
        if self.finished {
            return Err(());
        }
        self.finished = true;
        if self.opening.has_native_entry_v1() {
            self.names = Some(self.opening.finish_names_post_once(
                source.or(self.owner.as_ref()).map(|source| &source.coordinator),
            ));
        }
        // This same prearmed Source/C post is owed even if an earlier
        // Controller body failed before Source native entry could begin.
        self.post = Some(loan.finish_native_once());
        if self.primary_failure().is_some() || self.postcheck_debt().is_some()
            || !matches!(self.post, Some(Ok(())))
        {
            Err(())
        } else {
            // The actual upper recovery and every Source/C post completed.
            // Keep the same held writer, closing only its finished acquisition
            // ancestors and the completed independent names probe.
            self.disposition = Some(match source.or(self.owner.as_ref()) {
                Some(source) => self.opening
                    .retire_completed_traversal_after_upper_posts_once_v1(&source.coordinator),
                None => Err(SourceNativeErrorV1::Closed),
            });
            if matches!(self.disposition, Some(Ok(()))) { Ok(()) } else { Err(()) }
        }
    }

    /// Borrows the actual first construction or full semantic replay failure.
    pub fn primary_failure(&self) -> Option<&(dyn std::error::Error + 'static)> {
        if !matches!(self.preparation, Some(Ok(()))) {
            return self.opening.failure().or_else(|| error(&self.preparation));
        }
        if let Some(cause) = error(&self.semantic_shape) { return Some(cause); }
        if !matches!(self.semantic_preparation, Some(Ok(()))) {
            return self.opening.failure().or_else(|| error(&self.semantic_preparation));
        }
        if !matches!(self.identity, Some(Ok(_))) {
            return self.opening.failure().or_else(|| error(&self.identity));
        }
        if let Some(cause) = error(&self.replay_entry) {
            return self.opening.failure().or(Some(cause));
        }
        if let Some(original) = self.semantics.as_ref() {
            if semantic::selected_native_cause(original) {
                return self.opening.failure().or_else(|| original.failure());
            }
            if semantic::selected_receiving_cause(original) {
                return self.opening.semantic_receiving_failure_v1().or_else(|| original.failure());
            }
            if let Some(cause) = original.failure() { return Some(cause); }
        }
        self.opening.failure().or_else(|| error(&self.handoff))
    }

    /// Resolves the actual selected C loan cause before its stopping marker.
    pub fn primary_failure_with_loan<'cause>(
        &'cause self,
        loan: &'cause ControllerSourcePreBankConstructionLoanV1<'_>,
    ) -> Option<&'cause (dyn std::error::Error + 'static)> {
        if self.opening.receiving_failure_is_selected_v1() {
            loan.failure().or_else(|| self.primary_failure())
        } else {
            self.primary_failure()
        }
    }

    /// Borrows the later Source-name or independently owed C/profile debt.
    pub fn postcheck_debt(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.opening.names_failure().or_else(|| error(&self.names)).or_else(|| error(&self.post))
            .or_else(|| error(&self.disposition))
    }

    /// Resolves actual Source names before the same C post's stopping marker.
    pub fn postcheck_debt_with_loan<'cause>(
        &'cause self,
        loan: &'cause ControllerSourcePreBankConstructionLoanV1<'_>,
    ) -> Option<&'cause (dyn std::error::Error + 'static)> {
        self.opening.names_failure().or_else(|| error(&self.names))
            .or_else(|| loan.failure()).or_else(|| error(&self.post))
            .or_else(|| error(&self.disposition))
    }
}

fn error<T, E: std::error::Error + 'static>(value: &Option<Result<T, E>>)
    -> Option<&(dyn std::error::Error + 'static)>
{
    value.as_ref()?.as_ref().err().map(|cause| cause as _)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn inert_role_construction_cannot_issue_native_or_semantic_custody() {
        let mut original = SourceJournalConstructionOriginalsV1::<()>::new();

        assert!(original.take_completed_once(()).is_none());
        assert!(original.take_completed_once(()).is_none());

        assert!(original.primary_failure().is_none());
        assert!(!original.opening.has_native_entry_v1());
    }
}
