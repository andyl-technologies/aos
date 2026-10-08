//! Shared protected runtime-activation setup for crate-local regressions.
//!
//! Fixtures retain the real publication and reconciliation path. They create
//! neither a live Host observation nor a current runtime-scope proof.

#![allow(
    clippy::unwrap_used,
    reason = "Fixture construction intentionally panics on unexpected failures."
)]

use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};
use std::path::Path;

use aos_sandbox_core::OperationId;

use crate::publication::{
    AuthorityPublicationDraftV1, AuthorityPublicationStore, PreparedAuthorityPublicationV1,
};
use crate::runtime_authority::RuntimeAuthorityIntentV1;
use crate::{
    AuthorityBoundEffectPlanV1, EffectFailure, EffectObservation, EffectPlan, EffectReceipt,
    IdempotencyKey, Journal, JournalLimits, OperationPlan, Reconciler, SingleNodeEffectExecutor,
};

use super::activation_claim;

/// Rejects every effect call with the consuming test's original diagnostic.
pub(crate) struct NoEffects {
    purpose: &'static str,
}

impl NoEffects {
    /// Constructs a rejecting executor with the consuming fixture's diagnostic.
    pub(crate) const fn new(purpose: &'static str) -> Self {
        Self { purpose }
    }
}

impl SingleNodeEffectExecutor for NoEffects {
    fn observe(
        &mut self,
        _: OperationId,
        _: u32,
        _: &EffectPlan,
    ) -> Result<EffectObservation, EffectFailure> {
        std::panic::panic_any(self.purpose)
    }

    fn apply(
        &mut self,
        _: OperationId,
        _: u32,
        _: &EffectPlan,
    ) -> Result<EffectReceipt, EffectFailure> {
        std::panic::panic_any(self.purpose)
    }
}

/// Opens the named fixture journal with the original protected-directory checks.
///
/// # Panics
///
/// Panics when the fixture directory or protected journal cannot be opened.
pub(crate) fn open_protected(directory: &Path, name: &str) -> Journal {
    std::fs::set_permissions(directory, std::fs::Permissions::from_mode(0o700)).unwrap();
    Journal::open_protected_at_uid(
        directory,
        name,
        JournalLimits::default(),
        std::fs::metadata(directory).unwrap().uid(),
    )
    .unwrap()
    .0
}

/// Activates the original checked publication through genuine reconciliation.
///
/// The borrowed draft and preparation remain owned by the caller. Returning
/// the inert plan keeps its buffers alive through the caller's subsequent
/// binding load, matching the original inline fixture's lifetime.
///
/// # Panics
///
/// Panics when the fixture cannot admit or activate its checked publication.
pub(crate) fn activate(
    reconciler: &mut Reconciler<NoEffects>,
    generation: u8,
    effect: AuthorityBoundEffectPlanV1,
    intent: RuntimeAuthorityIntentV1,
    draft: &AuthorityPublicationDraftV1,
    prepared: &PreparedAuthorityPublicationV1,
) -> OperationPlan {
    let operation = OperationId::from_bytes([generation; 16]);
    let plan = OperationPlan::ownership_gated(
        operation,
        IdempotencyKey::new(vec![generation]).unwrap(),
        [generation; 32],
        vec![generation],
        vec![generation],
        vec![effect],
        activation_claim(draft, u64::from(generation)),
        draft.clone(),
    )
    .unwrap()
    .with_runtime_authority(intent)
    .unwrap();

    reconciler.accept(&plan).unwrap();

    let activation = AuthorityPublicationStore::new(reconciler.journal_mut())
        .prepare_gate_activation(draft, prepared)
        .unwrap();
    reconciler
        .activate_ownership_gate(operation, activation)
        .unwrap();

    plan
}
