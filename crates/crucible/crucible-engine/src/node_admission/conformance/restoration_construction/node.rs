//! Borrows the same runtime-owned CNP node for a pre-effect construction quote.
//!
//! These inputs and results are opaque outside Core. Numeric DATA carries no
//! target, restoration window, decoder, allocation or execution permission.

use super::*;
use crucible_node_transport::{
    client::OriginalCompleteRestoreUploadBeforeMappingData,
    connection::OriginalNativeRestoreInputConstructionData,
    reference_packet::service::{
        PacketNative5SourceLaunch, ack_emitter::PacketNativeRestoreCommitConstructionData,
    },
};

/// Borrows original installed inputs for a default-refusing internal node quote.
///
/// Core alone constructs this view. The whole installed window independently
/// authenticates the exact runtime, signed ticket, activation and actual holder
/// launch banks. The same node keeps its existing preparation and controller.
pub struct OriginalRestorationNodeInputs<'a> {
    pub(crate) source: &'a Rc<PacketCompleteSemanticSource>,
    pub(crate) plan: &'a InstalledConformancePlan,
    pub(crate) ticket: &'a CompleteOriginalNativeTicket,
    pub(crate) launch: &'a PacketNative5SourceLaunch,
    pub(crate) encoded_launch: &'a [u8],
    pub(crate) prepare_id: &'a Id,
    pub(crate) maximum_requested_bytes: usize,
    pub(crate) signing: Option<OriginalRestorationSigningCollector<'a>>,
}

/// Borrows already admitted cold owners while the same node quotes its signer.
///
/// There is no controller or Query extractor. The actual node supplies those
/// loans from its own existing custody while its ordinary raw quote runs.
pub(crate) struct OriginalRestorationSigningCollector<'a> {
    pub(crate) inputs: &'a OriginalRestorationConstructionInputs<'a>,
    pub(crate) activation_request_ids: &'a [Id; 2],
    pub(crate) observation_request_id: Option<&'a Id>,
    pub(crate) coordinator: &'a OriginalRestorationCoordinatorConstructionData,
    pub(crate) cold: &'a crate::node_adapters::cnp::OriginalRestorationColdGroup,
    pub(crate) maximum_record_bytes: usize,
    pub(crate) observed_other_retained_bytes: usize,
}

/// Reports the actual same-node protocol and native future rows as DATA.
///
/// There is no public constructor, decoder or conversion to a restoration token.
/// The installed window must independently fund current runtime/Source/holder,
/// mapping and signer owners, callbacks, descriptors and every remaining phase.
pub struct OriginalRestorationNodeConstructionData {
    pub(crate) source: Weak<PacketCompleteSemanticSource>,
    pub(crate) read_owner: *const (),
    pub(crate) upload: OriginalCompleteRestoreUploadBeforeMappingData,
    pub(crate) native_inputs: OriginalNativeRestoreInputConstructionData,
    pub(crate) prepare_binding: crucible_node_transport::client::OriginalFreshRestorePrepareBindingStorageData,
    pub(crate) native_allocation: crucible_node_transport::reference_packet::service::complete_restore::transfer::PacketCompleteRestoreInputAllocation,
    pub(crate) native_commit: PacketNativeRestoreCommitConstructionData,
    pub(crate) host_currentness_bytes: usize,
    pub(crate) mapping_construction_bytes: usize,
    pub(crate) maximum_mapping_bytes: usize,
    pub(crate) signer: Option<crate::node_adapters::cnp::OriginalSourceRestoreSignerConstructionData>,
    pub(crate) installed_custody: Option<crate::node_adapters::cnp::OriginalInstalledRestorationCustodyConstructionData>,
    pub(crate) source_activation: Option<crate::node_adapters::cnp::OriginalSourceRestorationActivationConstructionData>,
    pub(crate) source_observation: Option<crate::node_adapters::cnp::OriginalSourceRestorationObservationConstructionData>,
    pub(crate) restored_suffix: Option<window::OriginalRestoredSuffixConstructionData>,
}

impl OriginalRestorationNodeConstructionData {
    pub(crate) fn retained_association_storage_data(
        &self,
        maximum: usize,
    ) -> Result<usize, RuntimeError> {
        // The same actual Source backing is independently walked by the Core
        // roster after pointer authentication. The SDK quote's real Weak owner
        // view is conservatively repeated; no external alias discount is used.
        let facts = self
            .prepare_binding
            .original_retained_metadata_facts()
            .map_err(|_| RuntimeError::UnsupportedFacet)?;
        let bytes =
            PacketCompleteSemanticSource::complete_retained_metadata_storage_precredit_data(
                &facts, maximum,
            )?;
        if self.source.upgrade().is_none() {
            return Err(RuntimeError::ForeignAuthority);
        }
        Ok(bytes)
    }

    pub(crate) fn authenticate_original_source_data(
        &self,
        source: &Rc<PacketCompleteSemanticSource>,
    ) -> Result<(), RuntimeError> {
        if !self
            .source
            .upgrade()
            .is_some_and(|original| Rc::ptr_eq(&original, source))
        {
            return Err(RuntimeError::ForeignAuthority);
        }
        Ok(())
    }

    pub(crate) fn authenticate_original_owner_data(
        &self,
        source: &Rc<PacketCompleteSemanticSource>,
        read_owner: *const (),
    ) -> Result<(), RuntimeError> {
        if self.read_owner != read_owner
            || !self
                .source
                .upgrade()
                .is_some_and(|original| Rc::ptr_eq(&original, source))
        {
            return Err(RuntimeError::ForeignAuthority);
        }
        Ok(())
    }
}
