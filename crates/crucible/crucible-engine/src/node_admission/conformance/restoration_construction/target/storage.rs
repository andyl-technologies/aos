//! Counts every retained target output, including failed partial operations.
//!
//! The window funds the enclosing target/Option headers. These raw owning views
//! charge nested children independently; equality between response, SDK, mapping
//! and archive bytes never supplies a discount. Busy output loans refuse.

use super::*;
use crucible_node_transport::retained_metadata::{
    original_complete_restore_transfer_response_counter_scratch_data,
    original_complete_restore_transfer_response_metadata_data,
};
use std::mem::size_of;

impl CompleteOriginalRestorationTransactionTarget {
    /// Counts actual target children without its enclosing inline root.
    ///
    /// The same conjunction independently walks the real archive, fresh Source,
    /// runtime and SDK. All partial output banks remain counted after refusal.
    ///
    /// # Errors
    /// Refuses another creator, a lost actual shared owner, busy output loans,
    /// unsupported response metadata, overflow or the supplied complete bound.
    pub fn retained_requested_storage_precredit_data(
        &self,
        maximum: usize,
    ) -> Result<usize, RuntimeError> {
        self.origin()?;
        let Self {
            process: _,
            thread: _,
            plan,
            source,
            runtime,
            activation: _,
            inputs,
            phase: _,
            mapping_partial,
            mapping,
            upload_partial,
            upload,
            normalization_started: _,
            normalization_value,
            normalization_partial,
            normalization,
            responses,
            uploaded,
            input_quote,
        } = self;
        let mut total = inputs.group.retained_storage_data(maximum)?;
        if let Some(runtime) = runtime {
            add(&mut total, runtime.retained_shared_storage_data()?, maximum)?;
        }
        add(&mut total, plan.retained_allocation_bytes(), maximum)?;
        if source.upgrade().is_none() {
            return Err(RuntimeError::ForeignAuthority);
        }
        add(
            &mut total,
            crate::node_contract::NodeRuntime::capture_shared_allocation_storage::<
                PacketCompleteSemanticSource,
            >(),
            maximum,
        )?;

        let partial = mapping_partial
            .try_borrow()
            .map_err(|_| RuntimeError::OwnerBusy)?;
        for mapping in partial.iter().chain(mapping.get()) {
            let facts = mapping
                .original_retained_metadata_facts()
                .map_err(|_| RuntimeError::UnsupportedFacet)?;
            add_facts(&mut total, &facts, maximum)?;
        }
        drop(partial);
        let partial = upload_partial
            .try_borrow()
            .map_err(|_| RuntimeError::OwnerBusy)?;
        for upload in partial.iter().chain(upload.get()) {
            let facts = upload
                .original_retained_metadata_facts()
                .map_err(|_| RuntimeError::UnsupportedFacet)?;
            add_facts(&mut total, &facts, maximum)?;
        }
        drop(partial);
        {
            use crate::node_contract::runtime_owned_counter::OwnedStorage;
            let value = normalization_value
                .try_borrow()
                .map_err(|_| RuntimeError::OwnerBusy)?;
            if let Some(value) = value.as_ref() {
                add(&mut total, value.owned_storage()?, maximum)?;
            }
        }
        let partial = normalization_partial
            .try_borrow()
            .map_err(|_| RuntimeError::OwnerBusy)?;
        for bank in partial.iter().chain(normalization.get()) {
            add(&mut total, bank.capacity(), maximum)?;
        }
        drop(partial);
        for slot in responses {
            let response = slot.try_borrow().map_err(|_| RuntimeError::OwnerBusy)?;
            if let Some(response) = response.as_ref() {
                let facts = original_complete_restore_transfer_response_metadata_data(response)
                    .map_err(|_| RuntimeError::UnsupportedFacet)?;
                add_facts(&mut total, &facts, maximum)?;
            }
        }
        let quote = input_quote
            .try_borrow()
            .map_err(|_| RuntimeError::OwnerBusy)?;
        if let Some(quote) = quote.as_ref() {
            let facts = quote
                .original_retained_metadata_facts()
                .map_err(|_| RuntimeError::UnsupportedFacet)?;
            add_facts(&mut total, &facts, maximum)?;
        }
        drop(quote);
        let uploaded = uploaded.try_borrow().map_err(|_| RuntimeError::OwnerBusy)?;
        if let Some(uploaded) = uploaded.as_ref() {
            let facts = uploaded
                .original_retained_metadata_facts()
                .map_err(|_| RuntimeError::UnsupportedFacet)?;
            add_facts(&mut total, &facts, maximum)?;
        }
        self.origin()?;
        Ok(total)
    }

    pub(in crate::node_admission::conformance::restoration_construction) fn counter_scratch_data()
    -> usize {
        use crucible_node_transport::{
            bodies::ResponseBody,
            client::{
                OriginalCompleteRestoreInputUpload,
                OriginalCompleteRestoreInputUploadProspectiveStorageData,
            },
            retained_metadata::RetainedProtocolMetadataFacts,
        };
        super::super::window::observation::owner_loan_result_counter_scratch_data::<Option<PreparedArchivedProtocolMapping>>()
            + super::super::window::observation::owner_loan_result_counter_scratch_data::<Option<OriginalCompleteRestoreInputUploadProspectiveStorageData>>()
            + super::super::window::observation::owner_loan_result_counter_scratch_data::<Option<serde_json::Value>>()
            + super::super::window::observation::owner_loan_result_counter_scratch_data::<Option<Vec<u8>>>()
            + super::super::window::observation::owner_loan_result_counter_scratch_data::<Option<ResponseBody>>()
            + super::super::window::observation::owner_loan_result_counter_scratch_data::<Option<crucible_node_transport::client::OriginalCompleteRestoreInputUploadStorageData>>()
            + super::super::window::observation::owner_loan_result_counter_scratch_data::<Option<OriginalCompleteRestoreInputUpload>>()
            + size_of::<std::cell::Ref<'static, Option<PreparedArchivedProtocolMapping>>>()
            + size_of::<std::cell::RefMut<'static, Option<PreparedArchivedProtocolMapping>>>()
            + size_of::<std::cell::Ref<'static, Option<OriginalCompleteRestoreInputUploadProspectiveStorageData>>>()
            + size_of::<std::cell::RefMut<'static, Option<OriginalCompleteRestoreInputUploadProspectiveStorageData>>>()
            + size_of::<std::cell::Ref<'static, Option<serde_json::Value>>>()
            + size_of::<std::cell::RefMut<'static, Option<serde_json::Value>>>()
            + size_of::<Result<serde_json::Value, serde_json::Error>>()
            + size_of::<Result<Vec<u8>, crucible_node_format::ContractError>>()
            + size_of::<std::cell::Ref<'static, Option<Vec<u8>>>>()
            + size_of::<std::cell::RefMut<'static, Option<Vec<u8>>>>()
            + size_of::<std::cell::Ref<'static, Option<ResponseBody>>>()
            + size_of::<std::cell::RefMut<'static, Option<ResponseBody>>>()
            + size_of::<std::cell::Ref<'static, Option<crucible_node_transport::client::OriginalCompleteRestoreInputUploadStorageData>>>()
            + size_of::<std::cell::RefMut<'static, Option<crucible_node_transport::client::OriginalCompleteRestoreInputUploadStorageData>>>()
            + size_of::<std::cell::Ref<'static, Option<OriginalCompleteRestoreInputUpload>>>()
            + size_of::<std::cell::RefMut<'static, Option<OriginalCompleteRestoreInputUpload>>>()
            + size_of::<std::iter::Chain<std::option::Iter<'static, PreparedArchivedProtocolMapping>, std::option::IntoIter<&'static PreparedArchivedProtocolMapping>>>()
            + size_of::<std::iter::Chain<std::option::Iter<'static, OriginalCompleteRestoreInputUploadProspectiveStorageData>, std::option::IntoIter<&'static OriginalCompleteRestoreInputUploadProspectiveStorageData>>>()
            + size_of::<std::iter::Chain<std::option::Iter<'static, Vec<u8>>, std::option::IntoIter<&'static Vec<u8>>>>()
            + size_of::<std::slice::Iter<'static, RefCell<Option<ResponseBody>>>>()
            + size_of::<RetainedProtocolMetadataFacts>()
            + size_of::<Result<RetainedProtocolMetadataFacts, crucible_node_transport::ProviderError>>()
            + size_of::<Result<usize, RuntimeError>>()
            + size_of::<Result<(), RuntimeError>>()
            + original_complete_restore_transfer_response_counter_scratch_data()
    }
}

fn add(total: &mut usize, bytes: usize, maximum: usize) -> Result<(), RuntimeError> {
    *total = total
        .checked_add(bytes)
        .filter(|sum| *sum <= maximum)
        .ok_or(RuntimeError::ResourceLimit)?;
    Ok(())
}

fn add_facts(
    total: &mut usize,
    facts: &crucible_node_transport::retained_metadata::RetainedProtocolMetadataFacts,
    maximum: usize,
) -> Result<(), RuntimeError> {
    let bytes = PacketCompleteSemanticSource::complete_retained_metadata_storage_precredit_data(
        facts, maximum,
    )?;
    add(total, bytes, maximum)
}
