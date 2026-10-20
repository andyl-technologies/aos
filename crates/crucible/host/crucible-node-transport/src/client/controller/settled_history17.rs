//! Borrows complete current Controller17 state beside immutable imported ancestry.
//!
//! This logical current component preserves live request journals, raw/typed
//! partials, remaining ceilings and frontier. It neither recursively rebuilds
//! ancestral Rust allocations nor creates fresh authority on decode. The outer
//! signed journal separately binds the verified immutable ancestry DAG.
//!
//! ```text
//! {schema,node,execution_owner,budget_seconds,budget_nanoseconds,fenced,
//!  session,custody,ack_admit,complete_restore,restore_prepare,restore_commit,
//!  activation,uploads,observation,capture,supervisor,protocol_owner_role}
//! ```

use super::*;
use crate::connection::OriginalRetainedSupervisor;
use crate::retained_metadata::{
    MetadataObserver, RetainedProtocolMetadataFacts,
    aliases::{MetadataAliasBank, MetadataSharedKind},
    records::MetadataRecordBank,
};
use serde::{
    Serialize,
    ser::{SerializeSeq, SerializeStruct},
};
use std::mem::size_of;

/// Borrows current owners and their actual known supervisor without a live decoder.
pub struct ControllerSettledHistoryData<'a> {
    controller: &'a CnpController,
    supervisor: &'a OriginalRetainedSupervisor,
    session: crate::client::session::SessionSettledHistoryData<'a>,
}

struct Activations<'a>(
    &'a [Option<installed_activation::AssignedOriginalInstalledRestorationActivation>; 2],
);
struct Uploads<'a>(&'a [Option<installed_activation::AssignedUpload>; 2]);

impl CnpController {
    /// Borrows every selected current owner through its genuine supervisor parent.
    ///
    /// Immutable imports are supplied separately by the enclosing signed DAG.
    /// The old Owned11 mechanical installed slot is not the selected Transfer12
    /// path and remains unsupported rather than silently omitted.
    ///
    /// # Errors
    /// Refuses an unsupported old installed slot or mutable callback, changed
    /// actual supervisor/Session/codec parent, or a conflicting literal-bank loan.
    pub fn borrowed_settled_history_data<'a>(
        &'a self,
        supervisor: &'a OriginalRetainedSupervisor,
    ) -> Result<ControllerSettledHistoryData<'a>, ProviderError> {
        if self.installed_complete_restore.is_some() {
            return Err(refused());
        }
        self.session
            .authenticate_settled_history_supervisor_data(supervisor)?;
        let session = self.session.borrowed_settled_history_data()?;
        Ok(ControllerSettledHistoryData {
            controller: self,
            supervisor,
            session,
        })
    }

    /// Counts the current component and actual known supervisor without effects.
    ///
    /// # Errors
    /// Refuses changed parent identity, an unsupported owner or bounded traversal.
    pub fn settled_history_metadata_data(
        &self,
        supervisor: &OriginalRetainedSupervisor,
    ) -> Result<RetainedProtocolMetadataFacts, ProviderError> {
        self.session
            .authenticate_settled_history_supervisor_data(supervisor)?;
        let mut observer = MetadataObserver::new();
        self.observe_settled_history_metadata_data(&mut observer)?;
        supervisor.observe_settled_history_metadata_data(&mut observer)?;
        Ok(observer.finish())
    }

    /// Records current capacities and real aliases into caller-precharged banks.
    ///
    /// The banks are cleared once. Source aggregate callers use the nonresetting
    /// defining walk and join the actual concrete supervisor through Node/Host.
    ///
    /// # Errors
    /// Refuses invalid parent/unsupported state, overflow or finite bank exhaustion.
    pub fn record_settled_history_metadata_data(
        &self,
        supervisor: &OriginalRetainedSupervisor,
        records: &mut MetadataRecordBank,
        aliases: &mut MetadataAliasBank,
    ) -> Result<RetainedProtocolMetadataFacts, ProviderError> {
        self.session
            .authenticate_settled_history_supervisor_data(supervisor)?;
        let mut observer = MetadataObserver::recording_with_aliases(records, aliases);
        self.observe_settled_history_metadata_data(&mut observer)?;
        supervisor.observe_settled_history_metadata_data(&mut observer)?;
        Ok(observer.finish())
    }

    pub(crate) fn observe_settled_history_metadata_data(
        &self,
        observer: &mut MetadataObserver<'_>,
    ) -> Result<(), ProviderError> {
        let Self {
            session,
            custody,
            route,
            budget: _,
            fenced,
            protocol_owner,
            original_ack_admit,
            original_complete_restore,
            original_complete_restore_prepare,
            original_complete_restore_commit,
            installed_complete_restore,
            original_installed_restoration_activation,
            original_installed_restoration_upload,
            original_installed_restoration_observation,
            original_restored_settled_capture,
        } = self;
        if installed_complete_restore.is_some() {
            return Err(refused());
        }
        observer.observe(&route.node)?;
        observer.observe(&route.execution_owner)?;
        observer.observe(fenced)?;
        observer.shared_original(MetadataSharedKind::ProtocolOwner, protocol_owner.as_ref())?;
        session.observe_settled_history_metadata_data(observer)?;
        custody.observe_owned_metadata(observer)?;
        if let Some(admit) = original_ack_admit {
            admit.observe_settled_history_metadata_data(observer)?;
        }
        for restore in [
            original_complete_restore.as_ref(),
            original_complete_restore_prepare.as_ref(),
            original_complete_restore_commit.as_ref(),
        ]
        .into_iter()
        .flatten()
        {
            restore.observe_settled_history_metadata_data(observer)?;
        }
        for activation in original_installed_restoration_activation.iter().flatten() {
            activation.observe_owned_metadata(observer)?;
        }
        for upload in original_installed_restoration_upload.iter().flatten() {
            upload.observe_settled_history_metadata_data(observer)?;
        }
        if let Some(observation) = original_installed_restoration_observation {
            observation.observe_owned_metadata(observer)?;
        }
        if let Some(capture) = original_restored_settled_capture {
            capture.observe_retained_metadata_data(observer)?;
        }
        Ok(())
    }

    /// Bounds the largest live Bytes serialization temporary separately from output.
    ///
    /// # Errors
    /// Refuses actual metadata traversal or checked base64 extent overflow.
    pub fn settled_history_serialization_transient_bytes_data(
        &self,
        supervisor: &OriginalRetainedSupervisor,
    ) -> Result<usize, ProviderError> {
        crate::retained_metadata::historical_serialization_transient_data(
            self.settled_history_metadata_data(supervisor)?,
        )
    }

    /// Names the defining current owner, bank loans and all SDK fixed views.
    pub fn settled_history_counter_scratch_data() -> usize {
        size_of::<ControllerSettledHistoryData<'static>>()
            +size_of::<Result<ControllerSettledHistoryData<'static>,ProviderError>>()
            +size_of::<Activations<'static>>()
            +size_of::<Uploads<'static>>()
            +size_of::<&Self>()
            +size_of::<&OriginalRetainedSupervisor>()
            +size_of::<MetadataObserver<'static>>()
            +size_of::<RetainedProtocolMetadataFacts>()
            +size_of::<Result<RetainedProtocolMetadataFacts,ProviderError>>()
            +size_of::<Result<usize,ProviderError>>()
            +size_of::<Result<(),ProviderError>>()
            +size_of::<[Option<&assigned_restore::AssignedOriginalCompleteRestore>;3]>()
            +size_of::<std::iter::Flatten<std::array::IntoIter<Option<&assigned_restore::AssignedOriginalCompleteRestore>,3>>>()
            +size_of::<std::slice::Iter<'static,Option<installed_activation::AssignedOriginalInstalledRestorationActivation>>>()
            +size_of::<std::slice::Iter<'static,Option<installed_activation::AssignedUpload>>>()
            +size_of::<u64>()+size_of::<u32>()
            + assigned_admit::AssignedOriginalCanonicalAckAdmit::settled_history_counter_scratch_data()
            + assigned_restore::AssignedOriginalCompleteRestore::settled_history_counter_scratch_data()
            + installed_activation::AssignedOriginalInstalledRestorationActivation::settled_history_counter_scratch_data()
            + installed_activation::AssignedUpload::settled_history_counter_scratch_data()
            + installed_observation::AssignedOriginalInstalledRestorationObservation::settled_history_counter_scratch_data()
            + Self::original_live_host_metadata_counter_scratch_data()
            +Self::original_restored_settled_capture_counter_scratch_data()
            +ClientSession::settled_history_counter_scratch_data()
            +OriginalRetainedSupervisor::settled_history_counter_scratch_data()
    }

    /// Checks a retained mapping's real historical parent without live renewal.
    ///
    /// # Errors
    /// Refuses a foreign Session, registration, actor or codec allocation.
    pub fn authenticate_archived_mapping_history_data(
        &self,
        mapping: &crate::protocol_snapshot::PreparedArchivedProtocolMapping,
    ) -> Result<(), ProviderError> {
        self.session
            .authenticate_archived_mapping_history_data(mapping, &self.protocol_owner)
    }
}

impl Serialize for ControllerSettledHistoryData<'_> {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let CnpController {
            session: _,
            custody,
            route,
            budget,
            fenced,
            protocol_owner: _,
            original_ack_admit,
            original_complete_restore,
            original_complete_restore_prepare,
            original_complete_restore_commit,
            installed_complete_restore,
            original_installed_restoration_activation,
            original_installed_restoration_upload,
            original_installed_restoration_observation,
            original_restored_settled_capture,
        } = self.controller;
        if installed_complete_restore.is_some() {
            return Err(serde::ser::Error::custom(
                "unsupported Owned11 installed Controller slot",
            ));
        }
        let mut fields = serializer.serialize_struct("CurrentController17", 18)?;
        fields.serialize_field("schema", "source-private.host-state-restored-settled/17")?;
        fields.serialize_field("node", &route.node)?;
        fields.serialize_field("execution_owner", &route.execution_owner)?;
        fields.serialize_field("budget_seconds", &budget.as_secs())?;
        fields.serialize_field("budget_nanoseconds", &budget.subsec_nanos())?;
        fields.serialize_field("fenced", fenced)?;
        fields.serialize_field("session", &self.session)?;
        fields.serialize_field("custody", &custody.owned_protocol_view())?;
        fields.serialize_field(
            "ack_admit",
            &original_ack_admit
                .as_ref()
                .map(|value| value.borrowed_settled_history_data()),
        )?;
        fields.serialize_field(
            "complete_restore",
            &original_complete_restore
                .as_ref()
                .map(|value| value.borrowed_settled_history_data()),
        )?;
        fields.serialize_field(
            "restore_prepare",
            &original_complete_restore_prepare
                .as_ref()
                .map(|value| value.borrowed_settled_history_data()),
        )?;
        fields.serialize_field(
            "restore_commit",
            &original_complete_restore_commit
                .as_ref()
                .map(|value| value.borrowed_settled_history_data()),
        )?;
        fields.serialize_field(
            "activation",
            &Activations(original_installed_restoration_activation),
        )?;
        fields.serialize_field("uploads", &Uploads(original_installed_restoration_upload))?;
        fields.serialize_field(
            "observation",
            &original_installed_restoration_observation
                .as_ref()
                .map(|value| value.borrowed_settled_history_data())
                .transpose()
                .map_err(serde::ser::Error::custom)?,
        )?;
        fields.serialize_field(
            "capture",
            &original_restored_settled_capture
                .as_ref()
                .map(|_| self.controller.original_restored_settled_capture_data())
                .transpose()
                .map_err(serde::ser::Error::custom)?,
        )?;
        fields.serialize_field(
            "supervisor",
            &self
                .supervisor
                .borrowed_settled_history_data()
                .map_err(serde::ser::Error::custom)?,
        )?;
        fields.serialize_field("protocol_owner_role", "same-current-controller-actor")?;
        fields.end()
    }
}

impl Serialize for Activations<'_> {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let mut sequence = serializer.serialize_seq(Some(2))?;
        for value in self.0 {
            sequence.serialize_element(
                &value
                    .as_ref()
                    .map(|value| value.borrowed_settled_history_data()),
            )?;
        }
        sequence.end()
    }
}

impl Serialize for Uploads<'_> {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let mut sequence = serializer.serialize_seq(Some(2))?;
        for value in self.0 {
            sequence.serialize_element(
                &value
                    .as_ref()
                    .map(|value| value.borrowed_settled_history_data()),
            )?;
        }
        sequence.end()
    }
}

fn refused() -> ProviderError {
    ProviderError::Correlation("current17 Controller owner differs")
}
