//! Authenticates a separate hostile population beside unchanged native controls.
//!
//! Original typed closure and current process enrollment are rechecked at each
//! selected phase. Hostile data and its original premise stay actor-owned even
//! when transmission fails; the guard retains native journals and uncertainty.

use std::{cell::RefCell, rc::Rc};

use crucible::node_adapters::cnp::{
    CnpCompletedLifecycleScope, CnpLaunchGuard, CnpOriginalConflictQualification,
};
use crucible::node_contract::{EffectKnowledge, OperationFailure};
use crucible_node_contract::{ContentRef, Id};
use crucible_node_provider::{ProviderError, client::OriginalConflictObservationHandle};
use serde::Serialize;
use serde_json::{Map, Value};

use super::{
    native::NativePublicEnrollment,
    source_lifecycle_resend_policy::SourceLifecycleResendPolicy,
    source_original_conflict_plan::{
        MAXIMUM_ARCHIVE_BYTES, MAXIMUM_CONFLICTS, SourceOriginalConflictPlan,
    },
};

#[derive(Serialize)]
pub(super) struct OriginalConflictPremise {
    pub(super) request: Id,
    pub(super) original_request: ContentRef,
    pub(super) original_response: ContentRef,
    pub(super) connection: Id,
    pub(super) changed_body: Map<String, Value>,
    pub(super) evidence_roots: Vec<ContentRef>,
    pub(super) native: NativePublicEnrollment,
}

pub(super) struct SourceOriginalConflictPolicy {
    plan: SourceOriginalConflictPlan,
    owner: Id,
    originals: Rc<SourceLifecycleResendPolicy>,
    roots: RefCell<Vec<Vec<ContentRef>>>,
    selected: RefCell<Vec<OriginalConflictPremise>>,
}

impl SourceOriginalConflictPolicy {
    /// Reserves every selected original's evidence slots before native launch.
    ///
    /// # Errors
    /// Refuses failed finite slot reservation. This does not authorize a send.
    pub(super) fn new(
        plan: SourceOriginalConflictPlan,
        owner: Id,
        originals: Rc<SourceLifecycleResendPolicy>,
    ) -> Result<Self, ProviderError> {
        let mut roots = Vec::new();
        roots
            .try_reserve_exact(MAXIMUM_CONFLICTS)
            .map_err(|_| exhausted())?;
        for _ in 0..MAXIMUM_CONFLICTS {
            let mut slot = Vec::new();
            slot.try_reserve_exact(1024).map_err(|_| exhausted())?;
            roots.push(slot);
        }
        let mut selected = Vec::new();
        selected
            .try_reserve_exact(MAXIMUM_CONFLICTS)
            .map_err(|_| exhausted())?;
        Ok(Self {
            plan,
            owner,
            originals,
            roots: RefCell::new(roots),
            selected: RefCell::new(selected),
        })
    }

    pub(super) fn retained(&self) -> Value {
        serde_json::json!({
            "fixture":self.plan.reference,"fixture_bytes":self.plan.bytes,
            "targets":self.plan.target_population(),"selected":&*self.selected.borrow(),"ordinary_qualification":false
        })
    }

    /// Checks actual changed sends and provider refusals against original data.
    ///
    /// # Errors
    /// Refuses an incomplete attempted population or a changed original/hostile
    /// frame, refusal or archive. Failure preserves actor and guarded custody.
    pub(super) fn collect(
        &self,
        observer: &OriginalConflictObservationHandle,
    ) -> Result<Value, ProviderError> {
        let selected = self.selected.borrow();
        if selected.len() != MAXIMUM_CONFLICTS {
            return Err(ProviderError::Correlation(
                "original conflict population incomplete",
            ));
        }
        let wire = serde_json::to_value(observer.snapshot(MAXIMUM_ARCHIVE_BYTES)?)
            .map_err(crucible_node_contract::ContractError::from)?;
        super::source_original_conflict_wire::verify(&wire, &selected)?;
        Ok(serde_json::json!({
            "schema":"crucible.reference.source-original-conflicts.v1",
            "fixture":self.plan.reference,"fixture_bytes":self.plan.bytes,
            "targets":self.plan.target_population(),"original_premises":&*selected,"wire":wire,
            "exclusions":["reconnect","phase-loss-population","whole-clause-credit","ordinary-ready"]
        }))
    }

    fn authenticate_original(
        &self,
        guard: &CnpLaunchGuard,
        scope: &CnpCompletedLifecycleScope,
    ) -> Result<Option<Map<String, Value>>, ProviderError> {
        if !self.plan.selects(scope)? {
            return Ok(None);
        }
        if self
            .selected
            .borrow()
            .iter()
            .any(|row| row.request == scope.request_id)
        {
            return Err(ProviderError::Correlation(
                "original conflict population repeated",
            ));
        }
        let mut roots = self.roots.borrow_mut().pop().ok_or_else(exhausted)?;
        let facts = self
            .originals
            .inspect_original(guard, scope, &mut roots)?
            .ok_or(ProviderError::Correlation(
                "conflict original not source-selected",
            ))?;
        let changed_body = self.plan.changed_body(&facts.body, &self.owner)?;
        // Preserve the exact source proposal before the core can encode or send
        // it. The native original remains in the guard's separate journal.
        self.selected.borrow_mut().push(OriginalConflictPremise {
            request: scope.request_id.clone(),
            original_request: facts.request,
            original_response: facts.response,
            connection: facts.connection,
            changed_body: changed_body.clone(),
            evidence_roots: roots,
            native: facts.native,
        });
        Ok(Some(changed_body))
    }
}

impl CnpOriginalConflictQualification for SourceOriginalConflictPolicy {
    fn authenticate(
        &self,
        guard: &CnpLaunchGuard,
        scope: &CnpCompletedLifecycleScope,
    ) -> Result<Option<Map<String, Value>>, OperationFailure> {
        self.authenticate_original(guard, scope)
            .map_err(|error| OperationFailure {
                effects: EffectKnowledge::Unknown,
                reason: error.to_string(),
            })
    }
}

fn exhausted() -> ProviderError {
    ProviderError::ResourceExhausted("original conflict source slots")
}
