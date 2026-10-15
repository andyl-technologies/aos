//! Installs immutable administrative history in one genuine fresh runtime.
//!
//! Archived attempts never become live capture tickets. Their lifetime IDs and
//! credits remain spent, while the fresh runtime owns its distinct authority and
//! actual independently validated native journals before readiness.

use crate::node_contract::{
    ActivationRecord, NativeRuntimeContinuationVerifier, NodeRoute, NodeRuntime,
    OriginalLineageRestoration, OriginalLineageRestorationLimits, RuntimeError,
};
use crate::node_scheduling::SchedulingSnapshot;
use crate::node_state::CompleteOriginalRestorationSource;
use std::rc::Rc;

impl NodeRuntime {
    /// Attaches the same actual host allocation under a verified restoration source.
    ///
    /// This source-selected route preserves the collecting-only legacy guard.
    /// It permits neither an initialized alternate scheduler nor a caller-selected
    /// host proxy, and attachment failure cannot downgrade to preparation again.
    ///
    /// # Errors
    /// Refuses another archive/node/runtime, active or initialized custody,
    /// exhausted attachment authority or a changed original snapshot.
    pub fn attach_complete_original_host_source(
        &mut self,
        host: &Rc<crate::node_contract::HostSchedulingSource>,
        archive: &CompleteOriginalRestorationSource,
    ) -> Result<(), RuntimeError> {
        archive.inner.authenticate_birth()?;
        host.authenticate_complete_archive_source(&archive.inner)
            .map_err(|_| RuntimeError::ForeignAuthority)?;
        let state = self.scheduling_origin()?;
        if self.activated
            || !self.barrier.can_arm()
            || state.initialized()?
            || self.original_capture_history.is_some()
            || self.barrier.record().world_binding_hash != *host.world()
        {
            return Err(RuntimeError::ForeignAuthority);
        }
        let selected = host.selection();
        let node = self
            .nodes
            .get(&selected.descriptor.id)
            .ok_or(RuntimeError::UnknownNode)?;
        let snapshot = self
            .snapshots
            .get(&selected.descriptor.id)
            .ok_or(RuntimeError::UnknownNode)?;
        let witness = node
            .original_host_scheduling_owner()
            .ok_or(RuntimeError::ForeignAuthority)?;
        if snapshot.descriptor != selected.descriptor
            || snapshot.binding != selected.binding
            || !witness.matches(host)?
        {
            return Err(RuntimeError::ForeignAuthority);
        }
        host.begin_attachment()?;
        let original = state.source();
        if !original.same_original(state) {
            return Err(RuntimeError::ForeignAuthority);
        }
        host.attach(original)
    }

    /// Binds complete signed administrative history before fresh native admission.
    ///
    /// The same source-issued host ticket must have constructed the actual host
    /// node attached to this runtime. Historical owner incarnations and replies
    /// remain unchanged; no old process-local authority is reconstructed.
    ///
    /// # Errors
    /// Refuses an active or reused target, another original host/source,
    /// unsupported native restoration or exhausted original copy credits.
    pub fn prepare_complete_original_lineage_restoration<'a>(
        &mut self,
        source: &'a CompleteOriginalRestorationSource,
        scheduling: &SchedulingSnapshot,
        target: &ActivationRecord,
        verifier: &mut dyn NativeRuntimeContinuationVerifier,
        limits: OriginalLineageRestorationLimits,
    ) -> Result<OriginalLineageRestoration<'a>, RuntimeError> {
        source.inner.authenticate_birth()?;
        let bound_plan = source.inner.collecting_plan()?;
        self.authenticate_complete_restoration_purpose(bound_plan.as_ref())?;
        self.scheduling_origin()?.current()?;
        if self.activated
            || self.barrier.record() != target
            || self.original_capture_history.is_some()
            || !self.original_capture_attempts.is_empty()
            || !self.operations.is_empty()
            || !self.input_batches.is_empty()
        {
            return Err(RuntimeError::ForeignAuthority);
        }
        let mut original_host = false;
        for node in self.nodes.values() {
            if let Some(witness) = node.original_host_scheduling_owner() {
                if original_host {
                    return Err(RuntimeError::ForeignAuthority);
                }
                witness.authenticate_archive_target(&source.inner, &self.authority)?;
                original_host = true;
            }
        }
        if !original_host {
            return Err(RuntimeError::UnsupportedFacet);
        }
        source.inner.bind_target(&self.authority)?;
        // Retain the original archive and full historical ledger before any
        // native callback. A failed attempt cannot renew IDs or try a new target.
        self.original_capture_history = Some(Rc::clone(&source.inner));
        let result = self.prepare_exact_original_lineage_restoration(
            source.runtime_object(),
            source.content(),
            scheduling,
            target,
            verifier,
            limits,
        );
        if result.is_err() {
            self.contain_roster(&NodeRoute {
                node: target.activation_id.clone(),
                owners: target.owners.clone(),
            });
        }
        result
    }
}
