//! Preserves every actual execution owner independently of attempt completion.
//!
//! Inline execution headers belong to the enclosing Source allocation. The
//! capacity-only DATA roster retains partial and failed slots; byte admission
//! additionally preserves the existing backend and output-association gates.

use super::*;
use crate::node_contract::restored_owner_history::OriginalOwnerCapacityMetadataData;
use crucible_node_transport::retained_metadata::{
    RetainedCaptureProtocolData, RetainedProtocolMetadataFacts,
    records::PacketRuntimeMetadataRecordBank,
};
use std::cell::{BorrowError, Ref};

impl OriginalCompleteCaptureExecution {
    /// Preserves the association checks used by the original byte observer.
    ///
    /// # Errors
    /// Refuses inconsistent backend or owner/key/participant associations.
    pub(super) fn validate_storage_association_with_error<E: StorageError>(&self) -> Result<(), E> {
        match (&self.backend_bank, &self.backend) {
            (Some(_), None) | (None, Some(_)) => {}
            (None, None) if self.failed || self.transferred => {}
            _ => return Err(E::refused("original backend bank association differs")),
        }
        match (&self.owner, &self.key) {
            (Some(_), Some(_)) => {}
            (None, None) if self.participants.is_empty() => {}
            _ => return Err(E::refused("original output metadata association differs")),
        }
        Ok(())
    }

    /// Visits every retained execution slot without granting capture eligibility.
    ///
    /// # Errors
    /// Refuses foreign bank custody, invalid layout, selected-row exhaustion or
    /// unavailable backing. Earlier physical rows remain retained on refusal.
    fn record_capacity_data(
        &self,
        census: &mut OriginalOwnerCapacityMetadataData<'_>,
    ) -> Result<(), RuntimeError> {
        let Self {
            backend_bank,
            backend,
            allocation_selected,
            allocation_bank,
            allocation,
            evidence,
            born,
            dependency_plan,
            capture_request,
            confirmation_request,
            host_protocol,
            owner,
            participants,
            key,
            retained_protocol_owner,
            started,
            wire_attempted,
            failed,
            transferred,
        } = self;
        census.observe_inline_data(allocation_selected);
        census.observe_inline_data(started);
        census.observe_inline_data(wire_attempted);
        census.observe_inline_data(failed);
        census.observe_inline_data(transferred);

        if let Some(bank) = backend_bank {
            bank.record_capacity_data(census)?;
        }
        census.observe(backend)?;
        census.observe(allocation_bank)?;
        census.observe(allocation)?;
        census.observe(evidence)?;
        census.observe(born)?;
        if let Some(plan) = dependency_plan {
            plan.record_capacity_data(census)?;
        }
        census.observe(capture_request)?;
        census.observe(confirmation_request)?;
        census.observe(host_protocol)?;
        census.observe(owner)?;
        // Even an empty participant Vec can retain spare storage after refusal.
        census.observe(participants)?;
        if let Some(key) = key {
            let NativeStateKey {
                implementation,
                profile,
                schema,
            } = key;
            let SchemaRef {
                id,
                version,
                definition,
                extensions,
            } = schema;
            census.observe(implementation)?;
            census.observe(profile)?;
            census.observe(id)?;
            census.observe_inline_data(version);
            census.observe(definition)?;
            census.observe(extensions)?;
        }
        if let Some(owner) = retained_protocol_owner {
            census
                .observe_capture_protocol_data(RetainedCaptureProtocolData::PayloadOwner(owner))?;
        }
        Ok(())
    }

    /// Returns this exact roster's capacity geometry and optional physical rows.
    ///
    /// # Errors
    /// Refuses the defining walk's origin, layout, traversal or backing failures.
    pub(super) fn capacity_facts_data(
        &self,
        bank: Option<&mut PacketRuntimeMetadataRecordBank>,
    ) -> Result<RetainedProtocolMetadataFacts, RuntimeError> {
        let maximum = bank.as_ref().map_or(usize::MAX, |bank| bank.maximum_rows());
        let mut census = OriginalOwnerCapacityMetadataData::new(maximum, bank);
        self.record_capacity_data(&mut census)?;
        Ok(census.finish())
    }
}

impl PacketCompleteSemanticSource {
    /// Reports all original execution capacities and optionally appends their rows.
    ///
    /// Failed or incomplete slots retain their actual backing without becoming
    /// capture or native authority. Independent bodies, dependency vectors and
    /// moved protocol owners keep separate rows. These facts establish no
    /// whole-Source traversal-work bound. Callers first admit the bank and
    /// [`Self::original_complete_capture_execution_capacity_counter_scratch_data`].
    ///
    /// # Errors
    /// Refuses foreign origins, busy execution custody, invalid layout, SDK
    /// observation failure, exhausted rows or unavailable physical backing.
    pub fn original_complete_capture_execution_capacity_data(
        &self,
        bank: Option<&mut PacketRuntimeMetadataRecordBank>,
    ) -> Result<RetainedProtocolMetadataFacts, RuntimeError> {
        self.storage_origin_with_error::<RuntimeError>()?;
        let slot = self
            .capture_execution
            .try_borrow()
            .map_err(|_| RuntimeError::OwnerBusy)?;
        let facts = match slot.as_ref() {
            Some(execution) => execution.capacity_facts_data(bank)?,
            None => RetainedProtocolMetadataFacts::default(),
        };
        self.storage_origin_with_error::<RuntimeError>()?;
        Ok(facts)
    }

    /// Names actual execution fields, child walks, iterators and census controls.
    pub fn original_complete_capture_execution_capacity_counter_scratch_data() -> usize {
        OriginalOwnerCapacityMetadataData::counter_scratch_data()
            + super::super::super::semantic_snapshot::capacities::capacity_counter_scratch_data()
            + RetainedCaptureProtocolData::capacity_counter_scratch_data()
            + size_of::<&Self>()
            + size_of::<&OriginalCompleteCaptureExecution>()
            + size_of::<Ref<'static, Option<OriginalCompleteCaptureExecution>>>()
            + size_of::<Result<Ref<'static, Option<OriginalCompleteCaptureExecution>>, BorrowError>>(
            )
            + field_view_bytes(|execution: &'static OriginalCompleteCaptureExecution| {
                let OriginalCompleteCaptureExecution {
                    backend_bank,
                    backend,
                    allocation_selected,
                    allocation_bank,
                    allocation,
                    evidence,
                    born,
                    dependency_plan,
                    capture_request,
                    confirmation_request,
                    host_protocol,
                    owner,
                    participants,
                    key,
                    retained_protocol_owner,
                    started,
                    wire_attempted,
                    failed,
                    transferred,
                } = execution;
                (
                    backend_bank,
                    backend,
                    allocation_selected,
                    allocation_bank,
                    allocation,
                    evidence,
                    born,
                    dependency_plan,
                    capture_request,
                    confirmation_request,
                    host_protocol,
                    owner,
                    participants,
                    key,
                    retained_protocol_owner,
                    started,
                    wire_attempted,
                    failed,
                    transferred,
                )
            })
            + size_of::<&born::OriginalBornObject>()
            + size_of::<&born::OriginalBornRole>()
            + size_of::<&ContentRef>()
            + size_of::<&Vec<ContentRef>>()
            + size_of::<std::slice::Iter<'static, ContentRef>>()
            + size_of::<std::slice::Iter<'static, born::OriginalBornObject>>()
            + size_of::<std::slice::Iter<'static, InputPayload>>()
            + size_of::<std::slice::Iter<'static, Id>>()
            + size_of::<&dependency_credit::OriginalDependencyPlan>()
            + size_of::<&dependency_credit::PacketCompleteCaptureDependencyStorageData>()
            + size_of::<(&Id, &Id, &SchemaRef)>()
            + size_of::<(
                &Id,
                &crucible_node_format::Version,
                &ContentRef,
                &crucible_node_format::Extensions,
            )>()
            + size_of::<&NativeStateKey>()
            + size_of::<&SchemaRef>()
            + size_of::<&Id>()
            + size_of::<Option<&mut PacketRuntimeMetadataRecordBank>>()
            + size_of::<RetainedProtocolMetadataFacts>()
            + size_of::<Result<RetainedProtocolMetadataFacts, RuntimeError>>()
            + size_of::<Result<(), RuntimeError>>()
            + size_of::<usize>()
    }
}

fn field_view_bytes<T>(_: impl FnOnce(&'static OriginalCompleteCaptureExecution) -> T) -> usize {
    size_of::<T>()
}

#[cfg(test)]
#[path = "metadata/tests.rs"]
mod tests;
