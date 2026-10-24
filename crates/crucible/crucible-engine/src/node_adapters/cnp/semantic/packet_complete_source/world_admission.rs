//! Reuses a completed source-authenticated Admit beneath common graph admission.
//!
//! The nonserializable token retains the same concrete Source allocation and
//! original process custody. It performs no transport operation, assigns no new
//! request, and renews no cut. Graph, collection-plan and native dispatch gates
//! remain independently mandatory in the common node constructor.
//!
//! Comparing bounded original envelope data creates temporary JSON/result
//! allocations. These are separate source validation scratch, not backing credit
//! supplied by this token or by an equal digest.

use std::{rc::Rc, thread::ThreadId};

use super::*;

pub(in crate::node_adapters::cnp::semantic) struct OriginalCompletedCanonicalAckWorldAdmission {
    process: u32,
    thread: ThreadId,
    source: Rc<PacketCompleteSemanticSource>,
    issued: bool,
    spent: bool,
    host_query_issued: std::cell::Cell<bool>,
    fresh_query: Option<crucible_node_transport::client::OriginalFreshRestoreQuery>,
}

impl OriginalCompletedCanonicalAckWorldAdmission {
    fn authenticate_origin(&self) -> Result<(), OperationFailure> {
        if self.process != std::process::id() || self.thread != std::thread::current().id() {
            return Err(refused("completed world admission has another origin"));
        }
        self.source.ensure_origin()
    }

    pub(in crate::node_adapters::cnp::semantic) fn consume(
        &mut self,
        preparation: &CnpSemanticPreparation,
        scope: &CnpSemanticRealizationScope<'_>,
        expected: &AdmitRequest,
    ) -> Result<(), OperationFailure> {
        self.authenticate_origin()?;
        if !self.issued || self.spent {
            return Err(refused(
                "completed world admission is unissued or already spent",
            ));
        }
        // Spending precedes callbacks and validation. Errors and unwind leave
        // the original token, controller and graph attempt held without retry.
        self.spent = true;
        let owner = Rc::clone(&scope.native.read_owner);
        let attempt = WorldAdmissionAttempt {
            process: self.process,
            revoke: Some(move || owner.revoke()),
        };
        authenticate_source_allocation(scope, &self.source)?;
        self.source
            .authenticate_completed_world_admission(scope, expected)?;
        // The final realization callbacks remain inside this same revoke guard.
        // Only the terminal native read follows them; the caller then constructs
        // its node from already retained metadata without another Source getter.
        attempt.finish(
            || preparation.reauthenticate(),
            || preparation.authenticate_native_dispatch(),
        )
    }
}

impl CnpSemanticPreparation {
    /// Retains the same completed protocol Admit for later common graph admission.
    ///
    /// This issues only a one-shot original custody association. It neither
    /// admits a graph nor grants Arm, Capture or fresh-peer permission. The
    /// original completed SDK request/response and Source-held emitter, native
    /// read, Hello and private birth must all agree with the installed world.
    ///
    /// # Errors
    /// Retains an unissued token on failed validation. Refuses another Source,
    /// changed original custody, unfinished Admit, repeated issuance, an already
    /// reserved runtime, or a changed full request, proof, binding or response.
    ///
    /// # Panics
    /// Trusted currentness callbacks may unwind; the token and original native
    /// custody remain held and the same native read occurrence is revoked.
    pub fn retain_original_canonical_ack_world_admission(
        &mut self,
        source: &Rc<PacketCompleteSemanticSource>,
    ) -> Result<(), OperationFailure> {
        source.ensure_origin()?;
        self.reauthenticate()?;
        authenticate_source_allocation(&self.scope()?, source)?;
        let native = self
            .guard
            .custody
            .as_mut()
            .ok_or_else(|| refused("completed world admission custody is absent"))?;
        if !native.completed_ack_protocol_started
            || native.runtime.is_some()
            || native.completed_ack_admission.get_mut().is_some()
        {
            return Err(refused(
                "completed world admission is repeated or follows runtime reservation",
            ));
        }
        *native.completed_ack_admission.get_mut() =
            Some(OriginalCompletedCanonicalAckWorldAdmission {
                process: std::process::id(),
                thread: std::thread::current().id(),
                source: Rc::clone(source),
                issued: false,
                spent: false,
                host_query_issued: std::cell::Cell::new(false),
                fresh_query: None,
            });
        let owner = Rc::clone(&native.read_owner);
        let mut attempt = WorldAdmissionAttempt {
            process: std::process::id(),
            revoke: Some(move || owner.revoke()),
        };
        let installation = source.installation();
        let request = AdmitRequest {
            bindings: vec![installation.binding.clone()],
            world_binding_hash: installation.world_binding_hash.clone(),
            admission_receipt: installation.admission_receipt.clone(),
            extensions: Extensions::new(),
        };
        source.authenticate_completed_world_admission(&self.scope()?, &request)?;
        self.reauthenticate()?;
        source.authenticate_witness_scope(&self.scope()?)?;
        let native = self
            .guard
            .custody
            .as_mut()
            .ok_or_else(|| refused("completed world admission custody disappeared"))?;
        native
            .completed_ack_admission
            .get_mut()
            .as_mut()
            .ok_or_else(|| refused("completed world admission token disappeared"))?
            .issued = true;
        attempt.revoke = None;
        Ok(())
    }
}

fn authenticate_source_allocation(
    scope: &CnpSemanticRealizationScope<'_>,
    source: &Rc<PacketCompleteSemanticSource>,
) -> Result<(), OperationFailure> {
    let installed = scope
        .native
        .source
        .as_ref()
        .ok_or_else(|| refused("completed world admission installed Source absent"))?;
    if !std::ptr::eq(
        Rc::as_ptr(installed).cast::<()>(),
        Rc::as_ptr(source).cast::<()>(),
    ) || !std::ptr::eq(scope.installation, source.installation())
    {
        return Err(refused(
            "completed world admission Source allocation differs",
        ));
    }
    Ok(())
}

struct WorldAdmissionAttempt<F: FnOnce()> {
    process: u32,
    revoke: Option<F>,
}

impl<F: FnOnce()> WorldAdmissionAttempt<F> {
    // Taking the guard by value retains its one-shot cleanup through both
    // callbacks. A successful terminal read permits only callback-free return.
    fn finish(
        mut self,
        reauthenticate: impl FnOnce() -> Result<(), OperationFailure>,
        terminal_native_read: impl FnOnce() -> Result<(), OperationFailure>,
    ) -> Result<(), OperationFailure> {
        reauthenticate()?;
        terminal_native_read()?;
        self.revoke = None;
        Ok(())
    }
}

impl<F: FnOnce()> Drop for WorldAdmissionAttempt<F> {
    fn drop(&mut self) {
        if self.process == std::process::id()
            && let Some(revoke) = self.revoke.take()
        {
            revoke();
        }
    }
}

#[cfg(test)]
#[path = "world_admission_tests.rs"]
mod tests;

impl OriginalCompletedCanonicalAckWorldAdmission {
    pub(in crate::node_adapters::cnp::semantic) fn charge_retained_storage_data(
        &self,
        counter: &mut super::super::retained_storage::Counter,
    ) -> Result<(), OperationFailure> {
        self.authenticate_origin()?;
        counter.rc(&self.source)?;
        // The Source's concrete factory/program/DOM/bank owners are separate
        // obligations. Equal public source labels cannot discharge those heaps.
        counter.unknowns.installed_source_owners = true;
        if let Some(query) = &self.fresh_query {
            counter.metadata(&query.original_retained_metadata_facts().map_err(unknown)?)?;
        }
        self.authenticate_origin()
    }
}

impl OriginalCompletedCanonicalAckWorldAdmission {
    pub(in crate::node_adapters::cnp::semantic) fn charge_retained_storage_precredit_data(
        &self,
        counter: &mut super::super::retained_storage::preparation::PreparationCounter,
    ) -> Result<(), crate::node_contract::RuntimeError> {
        use crate::node_contract::RuntimeError;

        if self.process != std::process::id() || self.thread != std::thread::current().id() {
            return Err(RuntimeError::ForeignAuthority);
        }
        if counter.rc(&self.source)? {
            counter.add(
                self.source
                    .original_complete_retained_nested_precredit_data(counter.remaining())?,
            )?;
        }
        if let Some(query) = &self.fresh_query {
            counter.metadata(
                &query
                    .original_retained_metadata_facts()
                    .map_err(|_| RuntimeError::OwnerUnavailable)?,
            )?;
        }
        if self.process != std::process::id() || self.thread != std::thread::current().id() {
            return Err(RuntimeError::ForeignAuthority);
        }
        Ok(())
    }
}

impl CnpSemanticPreparation {
    /// Authenticates the same original completed-Admit preparation as borrowed data.
    ///
    /// This checks raw origin and actual Source/token identity before any policy
    /// callback. It neither renews kernel currentness nor permits Query or Ready.
    ///
    /// # Errors
    /// Refuses another origin, busy owner, a foreign/unissued/spent token or runtime.
    pub fn authenticate_original_fresh_query_preparation_data(
        &self,
        source: &Rc<PacketCompleteSemanticSource>,
    ) -> Result<(), crate::node_contract::RuntimeError> {
        use crate::node_contract::RuntimeError;
        self.guard.preparation_storage_origin_precredit_data()?;
        source.storage_origin_with_error::<RuntimeError>()?;
        let native = self
            .guard
            .custody
            .as_ref()
            .ok_or(RuntimeError::OwnerUnavailable)?;
        native.read_owner.original_fresh_query_custody_data()?;
        let installed = native
            .source
            .as_ref()
            .ok_or(RuntimeError::OwnerUnavailable)?;
        if !std::ptr::eq(
            Rc::as_ptr(installed).cast::<()>(),
            Rc::as_ptr(source).cast::<()>(),
        ) || !std::ptr::eq(installed.installation(), source.installation())
            || !native.completed_ack_protocol_started
            || native.runtime.is_some()
        {
            return Err(RuntimeError::ForeignAuthority);
        }
        let token = native
            .completed_ack_admission
            .try_borrow()
            .map_err(|_| RuntimeError::OwnerBusy)?;
        let token = token.as_ref().ok_or(RuntimeError::OwnerUnavailable)?;
        if token.process != std::process::id()
            || token.thread != std::thread::current().id()
            || !token.issued
            || token.spent
            || !Rc::ptr_eq(&token.source, source)
        {
            return Err(RuntimeError::ForeignAuthority);
        }
        Ok(())
    }

    pub(crate) fn authenticate_original_fresh_query_plan_data(
        &self,
        plan: &crate::node_admission::InstalledConformancePlan,
    ) -> Result<(), crate::node_contract::RuntimeError> {
        use crate::node_contract::RuntimeError;
        self.guard.preparation_storage_origin_precredit_data()?;
        let native = self
            .guard
            .custody
            .as_ref()
            .ok_or(RuntimeError::OwnerUnavailable)?;
        let own = native
            .collection_plan
            .as_ref()
            .ok_or(RuntimeError::UnsupportedFacet)?;
        let authority = native
            .conformance
            .as_ref()
            .ok_or(RuntimeError::UnsupportedFacet)?;
        if !plan.is_same_original_plan_data(own) || !plan.has_authority(authority.as_ref()) {
            return Err(RuntimeError::ForeignAuthority);
        }
        Ok(())
    }

    pub(crate) fn claim_original_fresh_query_window_data(
        &self,
        source: &Rc<PacketCompleteSemanticSource>,
    ) -> Result<(), crate::node_contract::RuntimeError> {
        use crate::node_contract::RuntimeError;
        self.authenticate_original_fresh_query_preparation_data(source)?;
        let native = self
            .guard
            .custody
            .as_ref()
            .ok_or(RuntimeError::OwnerUnavailable)?;
        let token = native
            .completed_ack_admission
            .try_borrow()
            .map_err(|_| RuntimeError::OwnerBusy)?;
        let token = token.as_ref().ok_or(RuntimeError::OwnerUnavailable)?;
        if token.host_query_issued.replace(true) {
            return Err(RuntimeError::DuplicateOperation);
        }
        Ok(())
    }

    pub(crate) fn original_fresh_query_owner_identity_data(
        &self,
        source: &Rc<PacketCompleteSemanticSource>,
    ) -> Result<*const (), crate::node_contract::RuntimeError> {
        self.authenticate_original_fresh_query_preparation_data(source)?;
        let native = self
            .guard
            .custody
            .as_ref()
            .ok_or(crate::node_contract::RuntimeError::OwnerUnavailable)?;
        Ok(Rc::as_ptr(&native.read_owner).cast())
    }
}

impl OriginalCompletedCanonicalAckWorldAdmission {
    pub(in crate::node_adapters::cnp::semantic) fn fresh_query_slot_data(
        &mut self,
    ) -> &mut Option<crucible_node_transport::client::OriginalFreshRestoreQuery> {
        &mut self.fresh_query
    }
}

impl OriginalCompletedCanonicalAckWorldAdmission {
    pub(in crate::node_adapters::cnp::semantic) fn original_restoration_query_data(
        &self,
        source: &Rc<PacketCompleteSemanticSource>,
    ) -> Result<
        &crucible_node_transport::client::OriginalFreshRestoreQuery,
        crate::node_contract::RuntimeError,
    > {
        use crate::node_contract::RuntimeError;
        if self.process != std::process::id()
            || self.thread != std::thread::current().id()
            || !self.issued
            || !self.spent
            || !self.host_query_issued.get()
            || !Rc::ptr_eq(&self.source, source)
        {
            return Err(RuntimeError::ForeignAuthority);
        }
        self.fresh_query
            .as_ref()
            .ok_or(RuntimeError::OwnerUnavailable)
    }
}

impl OriginalCompletedCanonicalAckWorldAdmission {
    pub(in crate::node_adapters::cnp::semantic) fn original_restoration_query_counter_scratch_data()
    -> usize {
        std::mem::size_of::<std::cell::Ref<'static, Option<Self>>>() + std::mem::size_of::<&Self>()
    }
}

impl OriginalCompletedCanonicalAckWorldAdmission {
    // Reads the actual consumed Admit state. A planned but unissued Query is
    // distinct from the independently completed five-part Query journal.
    pub(in crate::node_adapters::cnp::semantic) fn original_initial_admission_state_data(
        &self,
        source: &Rc<PacketCompleteSemanticSource>,
    ) -> Result<bool, crate::node_contract::RuntimeError> {
        use crate::node_contract::RuntimeError;
        if self.process != std::process::id()
            || self.thread != std::thread::current().id()
            || !self.issued
            || !self.spent
            || !Rc::ptr_eq(&self.source, source)
        {
            return Err(RuntimeError::ForeignAuthority);
        }
        match (self.host_query_issued.get(), self.fresh_query.as_ref()) {
            (false, None) => Ok(false),
            (true, Some(query)) => {
                if query.original_data().is_none()
                    || query.terminal_data().is_none()
                    || query.response_data().is_none()
                    || query.report_data().is_none()
                    || query.allocation_reference_data().is_none()
                {
                    return Err(RuntimeError::OwnerUnavailable);
                }
                Ok(true)
            }
            _ => Err(RuntimeError::OwnerUnavailable),
        }
    }

    pub(in crate::node_adapters::cnp::semantic) fn original_initial_admission_counter_scratch_data()
    -> usize {
        std::mem::size_of::<&Self>()
            + std::mem::size_of::<&Rc<PacketCompleteSemanticSource>>()
            + std::mem::size_of::<Option<&crucible_node_transport::client::OriginalFreshRestoreQuery>>(
            )
            + std::mem::size_of::<(
                bool,
                Option<&crucible_node_transport::client::OriginalFreshRestoreQuery>,
            )>()
            + std::mem::size_of::<Result<bool, crate::node_contract::RuntimeError>>()
            + std::mem::size_of::<bool>()
            + std::mem::size_of::<std::thread::Thread>()
            + std::mem::size_of::<std::thread::ThreadId>()
            + std::mem::size_of::<u32>()
            + std::mem::size_of::<Option<&crucible_node_transport::envelope::Envelope>>() * 2
            + std::mem::size_of::<Option<&crucible_node_transport::bodies::ResponseBody>>()
            + std::mem::size_of::<Option<&crucible_node_transport::reference_packet::service::fresh_restore_allocation::PacketNativeFreshRestoreAllocationReport>>()
            + std::mem::size_of::<Option<&crucible_node_format::ContentRef>>()
    }
}
