//! Serializes actual Node custody without reconstructing portable authority.
//!
//! The settled family preserves imported admissions separately from genuinely
//! new Producer attempts. Both retained result copies and every failed/pending
//! phase stay present. No synthetic generic Begin or Input is introduced.

use super::*;
use crate::node_adapters::cnp::semantic::semantic_snapshot::{
    ActivationView, BatchView, RestoredBaseCustodyView,
};
use crate::node_adapters::cnp::semantic::state::SemanticRuntimeCustody;
use crate::node_admission::{OriginalRestoredCaptureClaim, OriginalRestoredCaptureRequestData};
use crate::node_contract::restored_owner_history::{
    OriginalRestoredOwnerCapacityAliases, OriginalRestoredOwnerCapacityRows,
    OriginalRestoredOwnerCapacitySink, OriginalRestoredOwnerHistory,
};
use crucible_node_transport::retained_metadata::historical_response_body_data;
use serde::{
    Serialize, Serializer,
    ser::{SerializeSeq, SerializeStruct},
};
use std::cell::RefCell;

/// Borrows the complete current private Node and installed custody.
/// The parent constructor authenticates the actual claim before lending it.
#[derive(Clone, Copy)]
pub(crate) struct OriginalRestoredSettledNodeHistoryView<'a> {
    base: &'a SemanticRuntimeCustody,
    installed: &'a InstalledRestorationCustody,
    route: &'a crate::node_contract::NodeRoute,
    // Never dereference or encode this identity. Retaining a Controller borrow
    // would conflict with the later mutable SDK effect on that same owner.
    controller_identity: *const crucible_node_transport::client::CnpController,
    supervisor: &'a crucible_node_transport::connection::OriginalRetainedSupervisor,
    aliases: Option<&'a RefCell<OriginalRestoredOwnerCapacityAliases>>,
    records: Option<
        &'a RefCell<crucible_node_transport::retained_metadata::records::MetadataRecordBank>,
    >,
    provider_aliases:
        Option<&'a RefCell<crucible_node_transport::retained_metadata::aliases::MetadataAliasBank>>,
}

struct AdmissionView<'a>(
    &'a OperationAdmission,
    &'a RefCell<OriginalRestoredOwnerCapacityAliases>,
);

impl Serialize for AdmissionView<'_> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        OriginalRestoredOwnerHistory::Admission(self.0).serialize(serializer)
    }
}

struct Admissions<'a>(
    &'a [OperationAdmission],
    &'a RefCell<OriginalRestoredOwnerCapacityAliases>,
);

impl Serialize for Admissions<'_> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let mut rows = serializer.serialize_seq(Some(self.0.len()))?;
        for admission in self.0 {
            rows.serialize_element(&AdmissionView(admission, self.1))?;
        }
        rows.end()
    }
}

struct Inputs<'a>(
    &'a [Rc<RuntimeInputBatch>],
    &'a RefCell<OriginalRestoredOwnerCapacityAliases>,
);

impl Serialize for Inputs<'_> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let mut rows = serializer.serialize_seq(Some(self.0.len()))?;
        for input in self.0 {
            rows.serialize_element(&OriginalRestoredOwnerHistory::InputBatch(input))?;
        }
        rows.end()
    }
}

struct AttemptView<'a>(
    &'a Attempt,
    &'a RefCell<OriginalRestoredOwnerCapacityAliases>,
);

impl Serialize for AttemptView<'_> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let attempt = self.0;
        let stage = match attempt.stage {
            Stage::Beginning => "beginning",
            Stage::Begun => "begun",
            Stage::Polling => "polling",
            Stage::Completed => "completed",
            Stage::Retiring => "retiring",
            Stage::Retired => "retired",
            Stage::Observing => "observing",
            Stage::Verified => "verified",
            Stage::Failed => "failed",
        };
        let mut row = serializer.serialize_struct("RestoredHistoricalProducerAttempt", 7)?;
        row.serialize_field("admission", &AdmissionView(&attempt.admission, self.1))?;
        row.serialize_field("slot", &attempt.slot)?;
        row.serialize_field("stage", stage)?;
        row.serialize_field("retained", &attempt.retained)?;
        row.serialize_field("returned", &attempt.returned)?;
        row.serialize_field("scheduling", &attempt.scheduling)?;
        row.serialize_field("scheduling_return", &attempt.scheduling_return)?;
        row.end()
    }
}

struct Attempts<'a>(
    &'a [Attempt],
    &'a RefCell<OriginalRestoredOwnerCapacityAliases>,
);

impl Serialize for Attempts<'_> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let mut rows = serializer.serialize_seq(Some(self.0.len()))?;
        for attempt in self.0 {
            rows.serialize_element(&AttemptView(attempt, self.1))?;
        }
        rows.end()
    }
}

struct CommandView<'a>(
    &'a crucible_node_transport::reference_packet::service::complete_restore::activation::PacketRestorationActivationCommand,
    &'a RefCell<crucible_node_transport::retained_metadata::records::MetadataRecordBank>,
    &'a RefCell<crucible_node_transport::retained_metadata::aliases::MetadataAliasBank>,
);

impl Serialize for CommandView<'_> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        use crucible_node_transport::reference_packet::service::complete_restore::activation::HistoricalRestorationActivationData;
        serialize_activation_owner(
            HistoricalRestorationActivationData::Command(self.0),
            self.1,
            self.2,
            serializer,
        )
    }
}

struct Commands<'a>(
    &'a [Option<crucible_node_transport::reference_packet::service::complete_restore::activation::PacketRestorationActivationCommand>; 2],
    &'a RefCell<crucible_node_transport::retained_metadata::records::MetadataRecordBank>,
    &'a RefCell<crucible_node_transport::retained_metadata::aliases::MetadataAliasBank>,
);

impl Serialize for Commands<'_> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let mut rows = serializer.serialize_seq(Some(2))?;
        for command in self.0 {
            rows.serialize_element(
                &command
                    .as_ref()
                    .map(|body| CommandView(body, self.1, self.2)),
            )?;
        }
        rows.end()
    }
}

struct WorldResultView<'a>(
    &'a crucible_node_transport::bodies::WorldActivateResult,
    &'a RefCell<crucible_node_transport::retained_metadata::records::MetadataRecordBank>,
    &'a RefCell<crucible_node_transport::retained_metadata::aliases::MetadataAliasBank>,
);

impl Serialize for WorldResultView<'_> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        use crucible_node_transport::reference_packet::service::complete_restore::activation::HistoricalRestorationActivationData;
        serialize_activation_owner(
            HistoricalRestorationActivationData::WorldResult(self.0),
            self.1,
            self.2,
            serializer,
        )
    }
}

struct ManifestView<'a>(
    &'a crucible_node_format::ActivationManifest,
    &'a RefCell<crucible_node_transport::retained_metadata::records::MetadataRecordBank>,
    &'a RefCell<crucible_node_transport::retained_metadata::aliases::MetadataAliasBank>,
);

impl Serialize for ManifestView<'_> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        use crucible_node_transport::reference_packet::service::complete_restore::activation::HistoricalRestorationActivationData;
        serialize_activation_owner(
            HistoricalRestorationActivationData::Manifest(self.0),
            self.1,
            self.2,
            serializer,
        )
    }
}

fn serialize_activation_owner<S: Serializer>(
    value: crucible_node_transport::reference_packet::service::complete_restore::activation::HistoricalRestorationActivationData<'_>,
    records: &RefCell<crucible_node_transport::retained_metadata::records::MetadataRecordBank>,
    aliases: &RefCell<crucible_node_transport::retained_metadata::aliases::MetadataAliasBank>,
    serializer: S,
) -> Result<S::Ok, S::Error> {
    use serde::ser::Error;
    {
        let mut records = records
            .try_borrow_mut()
            .map_err(|_| S::Error::custom("node metadata bank is busy"))?;
        let mut aliases = aliases
            .try_borrow_mut()
            .map_err(|_| S::Error::custom("node metadata aliases are busy"))?;
        value
            .record_historical_metadata_data(&mut records, &mut aliases)
            .map_err(|_| S::Error::custom("node activation metadata exceeds its admitted bank"))?;
    }
    let mut row = serializer.serialize_struct("RestoredNodeActivationHistory", 3)?;
    {
        let records = records
            .try_borrow()
            .map_err(|_| S::Error::custom("node metadata bank is busy"))?;
        let aliases = aliases
            .try_borrow()
            .map_err(|_| S::Error::custom("node metadata aliases are busy"))?;
        row.serialize_field("capacities", &records.rows())?;
        row.serialize_field("aliases", &*aliases)?;
    }
    row.serialize_field("value", &value)?;
    row.end()
}

struct ResponseView<'a>(
    &'a crucible_node_transport::bodies::ResponseBody,
    &'a RefCell<crucible_node_transport::retained_metadata::records::MetadataRecordBank>,
    &'a RefCell<crucible_node_transport::retained_metadata::aliases::MetadataAliasBank>,
);

impl Serialize for ResponseView<'_> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        use serde::ser::Error;
        let response = historical_response_body_data(self.0)
            .map_err(|_| S::Error::custom("settled node history response kind is unsupported"))?;
        {
            let mut records = self
                .1
                .try_borrow_mut()
                .map_err(|_| S::Error::custom("node metadata bank is busy"))?;
            let mut aliases = self
                .2
                .try_borrow_mut()
                .map_err(|_| S::Error::custom("node metadata aliases are busy"))?;
            response
                .record_historical_metadata_data(&mut records, &mut aliases)
                .map_err(|_| {
                    S::Error::custom("node response metadata exceeds its admitted bank")
                })?;
        }
        let mut row = serializer.serialize_struct("RestoredNodeResponseHistory", 3)?;
        {
            let records = self
                .1
                .try_borrow()
                .map_err(|_| S::Error::custom("node metadata bank is busy"))?;
            let aliases = self
                .2
                .try_borrow()
                .map_err(|_| S::Error::custom("node metadata aliases are busy"))?;
            row.serialize_field("capacities", &records.rows())?;
            row.serialize_field("aliases", &*aliases)?;
        }
        row.serialize_field("value", &response)?;
        row.end()
    }
}

impl<'a> OriginalRestoredSettledNodeHistoryView<'a> {
    pub(crate) fn with_aliases(
        mut self,
        aliases: &'a RefCell<OriginalRestoredOwnerCapacityAliases>,
    ) -> Self {
        self.aliases = Some(aliases);
        self
    }

    pub(crate) fn with_metadata_banks(
        mut self,
        records: &'a RefCell<
            crucible_node_transport::retained_metadata::records::MetadataRecordBank,
        >,
        aliases: &'a RefCell<
            crucible_node_transport::retained_metadata::aliases::MetadataAliasBank,
        >,
    ) -> Self {
        self.records = Some(records);
        self.provider_aliases = Some(aliases);
        self
    }
}

struct Responses<'a>(
    &'a [Option<crucible_node_transport::bodies::ResponseBody>; 2],
    &'a RefCell<crucible_node_transport::retained_metadata::records::MetadataRecordBank>,
    &'a RefCell<crucible_node_transport::retained_metadata::aliases::MetadataAliasBank>,
);

impl Serialize for Responses<'_> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let mut rows = serializer.serialize_seq(Some(2))?;
        for response in self.0 {
            rows.serialize_element(
                &response
                    .as_ref()
                    .map(|body| ResponseView(body, self.1, self.2)),
            )?;
        }
        rows.end()
    }
}

impl Serialize for OriginalRestoredSettledNodeHistoryView<'_> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        use serde::ser::Error;
        let aliases = self
            .aliases
            .ok_or_else(|| S::Error::custom("settled node history alias bank is absent"))?;
        let records = self
            .records
            .ok_or_else(|| S::Error::custom("settled node metadata bank is absent"))?;
        let provider_aliases = self
            .provider_aliases
            .ok_or_else(|| S::Error::custom("settled node metadata aliases are absent"))?;
        let installed = self.installed;
        let history = &installed.producer_executions;
        let mut row = serializer.serialize_struct("RestoredSettledNodeHistory", 25)?;
        row.serialize_field("schema", "source-owned.packet-restored-node-history/17")?;
        row.serialize_field("base", &RestoredBaseCustodyView(self.base))?;
        row.serialize_field(
            "base_activate_response_history",
            &self
                .base
                .activate_response
                .as_ref()
                .map(|value| WorldResultView(value, records, provider_aliases)),
        )?;
        row.serialize_field("install_started", &installed.install_started)?;
        row.serialize_field("installed", &installed.installed)?;
        row.serialize_field(
            "activation",
            &installed
                .activation
                .as_ref()
                .map(OriginalRestoredOwnerHistory::World),
        )?;
        row.serialize_field(
            "original_operations",
            &Admissions(&installed.operations, aliases),
        )?;
        row.serialize_field("original_inputs", &Inputs(&installed.inputs, aliases))?;
        row.serialize_field(
            "commands",
            &Commands(&installed.commands, records, provider_aliases),
        )?;
        row.serialize_field(
            "completed",
            &Responses(&installed.completed, records, provider_aliases),
        )?;
        row.serialize_field(
            "world_manifest",
            &installed
                .world_manifest
                .as_ref()
                .map(|value| ManifestView(value, records, provider_aliases)),
        )?;
        row.serialize_field("world_value", &installed.world_value)?;
        row.serialize_field("world_bytes", &installed.world_bytes)?;
        row.serialize_field("observation_attempted", &installed.observation_attempted)?;
        row.serialize_field(
            "observation_completed",
            &installed
                .observation_completed
                .as_ref()
                .map(|body| ResponseView(body, records, provider_aliases)),
        )?;
        row.serialize_field("observation", &installed.observation)?;
        row.serialize_field("observation_return", &installed.observation_return)?;
        row.serialize_field("current_observations", &installed.current_observations)?;
        row.serialize_field(
            "producer_pending",
            &history
                .pending
                .as_ref()
                .map(|attempt| AttemptView(attempt, aliases)),
        )?;
        row.serialize_field("producer_attempts", &Attempts(&history.attempts, aliases))?;
        row.serialize_field(
            "original_operations_capacity",
            &installed.operations.capacity(),
        )?;
        row.serialize_field("original_inputs_capacity", &installed.inputs.capacity())?;
        row.serialize_field("producer_attempts_capacity", &history.attempts.capacity())?;
        row.serialize_field(
            "capacities",
            &OriginalRestoredOwnerCapacityRows(&NodeCommonCapacityView(self)).with_aliases(aliases),
        )?;
        // This concrete association is Initial15. Its imported admissions are
        // represented above; it has no settled17 installed-family bank.
        row.serialize_field("restored_families", &None::<&serde_json::Value>)?;
        row.end()
    }
}

impl super::super::super::super::CnpSemanticNode {
    pub(crate) fn original_restored_settled_semantic_history_data<'a>(
        &'a self,
        claim: &OriginalRestoredCaptureClaim<'_>,
    ) -> Result<OriginalRestoredSettledNodeHistoryView<'a>, RuntimeError> {
        self.current().map_err(|_| RuntimeError::OwnerUnavailable)?;
        let native = self
            .preparation
            .guard
            .custody
            .as_ref()
            .ok_or(RuntimeError::OwnerUnavailable)?;
        let base = native
            .runtime
            .as_ref()
            .ok_or(RuntimeError::OwnerUnavailable)?;
        let installed = base
            .installed_restoration
            .as_ref()
            .ok_or(RuntimeError::UnsupportedFacet)?;
        let world = installed
            .activation
            .as_ref()
            .ok_or(RuntimeError::NotActivated)?;
        claim.authenticate_node_data(&self.route, world)?;
        Ok(OriginalRestoredSettledNodeHistoryView {
            base,
            installed,
            route: &self.route,
            controller_identity: native
                .controller
                .as_ref()
                .ok_or(RuntimeError::OwnerUnavailable)?,
            supervisor: self
                .retained_supervisor
                .as_ref()
                .ok_or(RuntimeError::OwnerUnavailable)?,
            aliases: None,
            records: None,
            provider_aliases: None,
        })
    }
}

impl super::super::super::super::CnpSemanticNode {
    // This DATA-only fence precedes admission of historical serialization work.
    // Full process/registry/Source validation follows under its retained credit;
    // it must not be hidden inside the passive owner's metadata walk.
    fn authenticate_restored_capture_metadata_origin_data(&self) -> Result<(), RuntimeError> {
        self.preparation.guard.original_metadata_origin_data()?;
        if !self.affinity.permits_current_thread() {
            return Err(RuntimeError::ForeignAuthority);
        }
        let native = self
            .preparation
            .guard
            .custody
            .as_ref()
            .ok_or(RuntimeError::OwnerUnavailable)?;
        native
            .ensure_origin()
            .map_err(|_| RuntimeError::OwnerUnavailable)?;
        native
            .read_owner
            .authenticate_original_host_startup_data()?;
        let runtime = native
            .runtime
            .as_ref()
            .ok_or(RuntimeError::OwnerUnavailable)?;
        if runtime.quarantined {
            return Err(RuntimeError::OwnerUnavailable);
        }
        Ok(())
    }
}

impl super::super::super::super::CnpSemanticNode {
    pub(in crate::node_adapters::cnp::semantic) fn quote_installed_restored_capture_prequote_data(
        &self,
        launch: &crucible_node_transport::reference_packet::service::PacketNative5SourceLaunch,
        raw5: &[u8],
        request: &OriginalRestoredCaptureRequestData<'_>,
        maximum: usize,
    ) -> Result<(usize, usize, usize), RuntimeError> {
        self.authenticate_restored_capture_metadata_origin_data()?;
        let native = self
            .preparation
            .guard
            .custody
            .as_ref()
            .ok_or(RuntimeError::OwnerUnavailable)?;
        let source = native
            .source
            .as_ref()
            .ok_or(RuntimeError::OwnerUnavailable)?;
        let controller = native
            .controller
            .as_ref()
            .ok_or(RuntimeError::OwnerUnavailable)?;
        let installed = native
            .runtime
            .as_ref()
            .and_then(|state| state.installed_restoration.as_ref())
            .ok_or(RuntimeError::UnsupportedFacet)?;
        if !installed.installed || !installed.observation_attempted {
            return Err(RuntimeError::OutstandingObligations);
        }
        let node_history = OriginalRestoredSettledNodeHistoryView {
            base: native
                .runtime
                .as_ref()
                .ok_or(RuntimeError::OwnerUnavailable)?,
            installed,
            route: &self.route,
            controller_identity: native
                .controller
                .as_ref()
                .ok_or(RuntimeError::OwnerUnavailable)?,
            supervisor: self
                .retained_supervisor
                .as_ref()
                .ok_or(RuntimeError::OwnerUnavailable)?,
            aliases: None,
            records: None,
            provider_aliases: None,
        };
        installed
            .association
            .quote_original_restored_capture_prequote_data(
                source.as_ref(),
                controller,
                Rc::as_ptr(&native.read_owner).cast(),
                launch,
                raw5,
                request,
                &node_history,
                maximum,
            )
    }
}

impl super::super::super::super::CnpSemanticNode {
    pub(in crate::node_adapters::cnp::semantic) fn quote_installed_restored_capture_construction_data(
        &self,
        launch: &crucible_node_transport::reference_packet::service::PacketNative5SourceLaunch,
        raw5: &[u8],
        request: &OriginalRestoredCaptureRequestData<'_>,
        maximum: usize,
    ) -> Result<
        crate::node_adapters::cnp::OriginalSourceRestoredCaptureConstructionData,
        RuntimeError,
    > {
        self.authenticate_restored_capture_metadata_origin_data()?;
        let native = self
            .preparation
            .guard
            .custody
            .as_ref()
            .ok_or(RuntimeError::OwnerUnavailable)?;
        let source = native
            .source
            .as_ref()
            .ok_or(RuntimeError::OwnerUnavailable)?;
        let controller = native
            .controller
            .as_ref()
            .ok_or(RuntimeError::OwnerUnavailable)?;
        let installed = native
            .runtime
            .as_ref()
            .and_then(|state| state.installed_restoration.as_ref())
            .ok_or(RuntimeError::UnsupportedFacet)?;
        if !installed.installed || !installed.observation_attempted {
            return Err(RuntimeError::OutstandingObligations);
        }
        let node_history = OriginalRestoredSettledNodeHistoryView {
            base: native
                .runtime
                .as_ref()
                .ok_or(RuntimeError::OwnerUnavailable)?,
            installed,
            route: &self.route,
            controller_identity: native
                .controller
                .as_ref()
                .ok_or(RuntimeError::OwnerUnavailable)?,
            supervisor: self
                .retained_supervisor
                .as_ref()
                .ok_or(RuntimeError::OwnerUnavailable)?,
            aliases: None,
            records: None,
            provider_aliases: None,
        };
        installed
            .association
            .quote_original_restored_capture_construction_data(
                source.as_ref(),
                controller,
                Rc::as_ptr(&native.read_owner).cast(),
                launch,
                raw5,
                request,
                &node_history,
                maximum,
            )
    }
}

impl super::super::super::super::CnpSemanticNode {
    pub(in crate::node_adapters::cnp::semantic) fn reserve_installed_restored_capture_counting_banks_data(
        &self,
        launch: &crucible_node_transport::reference_packet::service::PacketNative5SourceLaunch,
        raw5: &[u8],
        request: &OriginalRestoredCaptureRequestData<'_>,
        maximum: usize,
    ) -> Result<(), RuntimeError> {
        self.authenticate_restored_capture_metadata_origin_data()?;
        let native = self
            .preparation
            .guard
            .custody
            .as_ref()
            .ok_or(RuntimeError::OwnerUnavailable)?;
        let source = native
            .source
            .as_ref()
            .ok_or(RuntimeError::OwnerUnavailable)?;
        let installed = native
            .runtime
            .as_ref()
            .and_then(|state| state.installed_restoration.as_ref())
            .ok_or(RuntimeError::UnsupportedFacet)?;
        if !installed.installed || !installed.observation_attempted {
            return Err(RuntimeError::OutstandingObligations);
        }
        let node_history = OriginalRestoredSettledNodeHistoryView {
            base: native
                .runtime
                .as_ref()
                .ok_or(RuntimeError::OwnerUnavailable)?,
            installed,
            route: &self.route,
            controller_identity: native
                .controller
                .as_ref()
                .ok_or(RuntimeError::OwnerUnavailable)?,
            supervisor: self
                .retained_supervisor
                .as_ref()
                .ok_or(RuntimeError::OwnerUnavailable)?,
            aliases: None,
            records: None,
            provider_aliases: None,
        };
        installed
            .association
            .reserve_original_restored_capture_counting_banks_data(
                source.as_ref(),
                Rc::as_ptr(&native.read_owner).cast(),
                launch,
                raw5,
                request,
                &node_history,
                maximum,
            )
    }
}

/// Reports only actual borrowed traversal demand before any metadata bank exists.
#[derive(Clone, Copy, Default)]
pub(crate) struct NodeHistoryPrequoteData {
    common_rows: usize,
    common_shared: usize,
    provider_records: usize,
    provider_shared: usize,
    provider_owners: usize,
    transient: usize,
}

impl NodeHistoryPrequoteData {
    pub(crate) fn common_rows_data(&self) -> usize {
        self.common_rows
    }

    pub(crate) fn common_shared_occurrences_data(&self) -> usize {
        self.common_shared
    }

    pub(crate) fn provider_metadata_records_data(&self) -> usize {
        self.provider_records
    }

    pub(crate) fn provider_shared_occurrences_data(&self) -> usize {
        self.provider_shared
    }

    pub(crate) fn provider_owners_data(&self) -> usize {
        self.provider_owners
    }

    pub(crate) fn historical_serialization_transient_bytes_data(&self) -> usize {
        self.transient
    }

    pub(crate) fn counter_scratch_bytes_data(&self) -> usize {
        original_restored_settled_semantic_history_counter_scratch_data()
    }
}

impl OriginalRestoredSettledNodeHistoryView<'_> {
    pub(crate) fn metadata_demand_data(&self) -> Result<NodeHistoryPrequoteData, RuntimeError> {
        if !self.base.inputs.is_empty() || !self.base.operations.is_empty() {
            // The selected restored route cannot create ordinary legacy action
            // owners. A future input/operation family needs its own declaration
            // and complete typed metadata support before it can select Capture.
            return Err(RuntimeError::UnsupportedFacet);
        }
        let (common_rows, common_shared) =
            OriginalRestoredOwnerCapacityRows(&NodeCommonCapacityView(self))
                .metadata_demand_data()?;
        let mut demand = NodeHistoryPrequoteData {
            common_rows,
            common_shared,
            ..Default::default()
        };
        for response in self
            .installed
            .completed
            .iter()
            .chain(std::iter::once(&self.installed.observation_completed))
            .flatten()
        {
            let historical = historical_response_body_data(response)
                .map_err(|_| RuntimeError::UnsupportedFacet)?;
            let facts = historical
                .retained_metadata_data()
                .map_err(|_| RuntimeError::ResourceLimit)?;
            demand.provider_records = demand
                .provider_records
                .checked_add(facts.capacity_records)
                .ok_or(RuntimeError::ResourceLimit)?;
            demand.provider_shared = demand
                .provider_shared
                .checked_add(facts.shared_backing_views)
                .ok_or(RuntimeError::ResourceLimit)?;
            demand.provider_owners = demand
                .provider_owners
                .checked_add(1)
                .ok_or(RuntimeError::ResourceLimit)?;
            demand.transient = demand
                .transient
                .checked_add(
                    historical
                        .historical_serialization_transient_bytes_data()
                        .map_err(|_| RuntimeError::ResourceLimit)?,
                )
                .ok_or(RuntimeError::ResourceLimit)?;
        }
        use crucible_node_transport::reference_packet::service::complete_restore::activation::HistoricalRestorationActivationData as Activation;
        if let Some(value) = &self.base.activate_response {
            demand.add_provider_owner_data(
                Activation::WorldResult(value)
                    .retained_metadata_data()
                    .map_err(|_| RuntimeError::ResourceLimit)?,
                Activation::WorldResult(value)
                    .historical_serialization_transient_bytes_data()
                    .map_err(|_| RuntimeError::ResourceLimit)?,
            )?;
        }
        for command in self.installed.commands.iter().flatten() {
            demand.add_provider_owner_data(
                Activation::Command(command)
                    .retained_metadata_data()
                    .map_err(|_| RuntimeError::ResourceLimit)?,
                Activation::Command(command)
                    .historical_serialization_transient_bytes_data()
                    .map_err(|_| RuntimeError::ResourceLimit)?,
            )?;
        }
        if let Some(manifest) = &self.installed.world_manifest {
            demand.add_provider_owner_data(
                Activation::Manifest(manifest)
                    .retained_metadata_data()
                    .map_err(|_| RuntimeError::ResourceLimit)?,
                Activation::Manifest(manifest)
                    .historical_serialization_transient_bytes_data()
                    .map_err(|_| RuntimeError::ResourceLimit)?,
            )?;
        }
        Ok(demand)
    }
}

impl NodeHistoryPrequoteData {
    fn add_provider_owner_data(
        &mut self,
        facts: crucible_node_transport::retained_metadata::RetainedProtocolMetadataFacts,
        transient: usize,
    ) -> Result<(), RuntimeError> {
        self.provider_records = self
            .provider_records
            .checked_add(facts.capacity_records)
            .ok_or(RuntimeError::ResourceLimit)?;
        self.provider_shared = self
            .provider_shared
            .checked_add(facts.shared_backing_views)
            .ok_or(RuntimeError::ResourceLimit)?;
        self.provider_owners = self
            .provider_owners
            .checked_add(1)
            .ok_or(RuntimeError::ResourceLimit)?;
        self.transient = self
            .transient
            .checked_add(transient)
            .ok_or(RuntimeError::ResourceLimit)?;
        Ok(())
    }
}

struct NodeCommonCapacityView<'a>(&'a OriginalRestoredSettledNodeHistoryView<'a>);

impl crate::node_contract::restored_owner_history::OriginalRestoredOwnerCapacityWalk
    for NodeCommonCapacityView<'_>
{
    fn capacities(
        &self,
        depth: usize,
        sink: &mut dyn OriginalRestoredOwnerCapacitySink,
    ) -> Result<(), RuntimeError> {
        sink.visit_work(1)?;
        use crate::node_contract::restored_owner_history::{
            OriginalRestoredOwnerCapacityRow, OriginalRestoredOwnerCapacityWalk,
        };
        let base = self.0.base;
        let installed = self.0.installed;
        base.arm_attempt.capacities(depth, sink)?;
        base.ready.capacities(depth, sink)?;
        base.prepared_owner.capacities(depth, sink)?;
        base.activation_attempt.capacities(depth, sink)?;
        base.active.capacities(depth, sink)?;
        sink.capacity_row(OriginalRestoredOwnerCapacityRow::tree_population_data::<
            crucible_node_format::Id,
            crate::node_adapters::cnp::semantic::state::OriginalOperation,
        >(base.operations.len()))?;
        sink.capacity_row(OriginalRestoredOwnerCapacityRow::tree_population_data::<
            crucible_node_format::Id,
            crate::node_adapters::cnp::semantic::state::OriginalInput,
        >(base.inputs.len()))?;
        for (key, value) in &base.operations {
            key.capacities(depth, sink)?;
            value.capacities(depth, sink)?;
        }
        for (key, value) in &base.inputs {
            key.capacities(depth, sink)?;
            value.capacities(depth, sink)?;
        }
        if let Some((world, observation)) = &base.observation {
            world.capacities(depth, sink)?;
            observation.capacities(depth, sink)?;
        }
        if let Some(reclaimed) = &base.reclaimed {
            reclaimed.owner.capacities(depth, sink)?;
            reclaimed.receipt.capacities(depth, sink)?;
        }
        installed.activation.capacities(depth, sink)?;
        installed.operations.capacities(depth, sink)?;
        installed.inputs.capacities(depth, sink)?;
        installed.world_value.capacities(depth, sink)?;
        installed.world_bytes.capacities(depth, sink)?;
        installed.observation.capacities(depth, sink)?;
        installed.observation_return.capacities(depth, sink)?;
        installed.current_observations.capacities(depth, sink)?;
        installed.producer_executions.capacities(depth, sink)?;
        Ok(())
    }
}

impl crate::node_contract::restored_owner_history::OriginalRestoredOwnerCapacityWalk for Attempt {
    fn capacities(
        &self,
        depth: usize,
        sink: &mut dyn OriginalRestoredOwnerCapacitySink,
    ) -> Result<(), RuntimeError> {
        sink.visit_work(1)?;
        use crate::node_contract::restored_owner_history::OriginalRestoredOwnerCapacityWalk;
        self.admission.capacities(depth, sink)?;
        self.retained.capacities(depth, sink)?;
        self.returned.capacities(depth, sink)?;
        self.scheduling.capacities(depth, sink)?;
        self.scheduling_return.capacities(depth, sink)
    }
}

impl crate::node_contract::restored_owner_history::OriginalRestoredOwnerCapacityWalk
    for ProducerNodeHistory
{
    fn capacities(
        &self,
        depth: usize,
        sink: &mut dyn OriginalRestoredOwnerCapacitySink,
    ) -> Result<(), RuntimeError> {
        sink.visit_work(1)?;
        use crate::node_contract::restored_owner_history::OriginalRestoredOwnerCapacityWalk;
        self.pending.capacities(depth, sink)?;
        self.attempts.capacities(depth, sink)
    }
}

pub(crate) fn original_restored_settled_semantic_history_counter_scratch_data() -> usize {
    use crate::node_contract::restored_owner_history::original_restored_owner_capacity_counter_scratch_data;
    use crucible_node_transport::retained_metadata::{
        HistoricalResponseBodyData, RetainedProtocolMetadataFacts, aliases::MetadataAliasBank,
        records::MetadataRecordBank,
    };
    use std::cell::{Ref, RefMut};
    original_restored_owner_capacity_counter_scratch_data()
        + super::capture17::counter_scratch_data()
        + crate::node_contract::OriginalInstalledRestorationNodeAssociation::original_capture17_bridge_counter_scratch_data()
        + crucible_node_transport::retained_metadata::historical_response_body_counter_scratch_data()
        + super::counter_scratch_data()
        + OriginalRestoredSettledNodeHistoryView::original_controller_history_counter_scratch_data()
        + crate::node_adapters::cnp::semantic::CnpSemanticLaunchGuard::original_metadata_origin_counter_scratch_data()
        + crate::node_adapters::cnp::semantic::semantic_snapshot::restored_base17_counter_scratch_data()
        + size_of::<Option<&'static serde_json::Value>>()
        + size_of::<ActivationView<'static>>()
        + size_of::<OriginalRestoredSettledNodeHistoryView<'static>>()
        + size_of::<NodeCommonCapacityView<'static>>()
        + size_of::<NodeHistoryPrequoteData>()
        + size_of::<AdmissionView<'static>>()
        + size_of::<Admissions<'static>>()
        + size_of::<Inputs<'static>>()
        + size_of::<AttemptView<'static>>()
        + size_of::<Attempts<'static>>()
        + crucible_node_transport::reference_packet::service::complete_restore::activation::HistoricalRestorationActivationData::historical_counter_scratch_data()
        + size_of::<WorldResultView<'static>>()
        + size_of::<ManifestView<'static>>()
        + size_of::<CommandView<'static>>()
        + size_of::<Commands<'static>>()
        + size_of::<ResponseView<'static>>()
        + size_of::<Responses<'static>>()
        + size_of::<std::slice::Iter<'static, OperationAdmission>>()
        + size_of::<std::slice::Iter<'static, Rc<RuntimeInputBatch>>>()
        + size_of::<std::slice::Iter<'static, Attempt>>()
        + size_of::<std::slice::Iter<'static, Option<crucible_node_transport::bodies::ResponseBody>>>()
        + size_of::<std::iter::Chain<std::slice::Iter<'static, Option<crucible_node_transport::bodies::ResponseBody>>, std::iter::Once<&'static Option<crucible_node_transport::bodies::ResponseBody>>>>()
        + size_of::<Ref<'static, MetadataRecordBank>>()
        + size_of::<RefMut<'static, MetadataRecordBank>>()
        + size_of::<Ref<'static, MetadataAliasBank>>()
        + size_of::<RefMut<'static, MetadataAliasBank>>()
        + size_of::<Result<Ref<'static, MetadataRecordBank>, std::cell::BorrowError>>()
        + size_of::<Result<RefMut<'static, MetadataRecordBank>, std::cell::BorrowMutError>>()
        + size_of::<Result<Ref<'static, MetadataAliasBank>, std::cell::BorrowError>>()
        + size_of::<Result<RefMut<'static, MetadataAliasBank>, std::cell::BorrowMutError>>()
        + size_of::<Result<HistoricalResponseBodyData<'static>, crucible_node_transport::ProviderError>>()
        + size_of::<Result<RetainedProtocolMetadataFacts, crucible_node_transport::ProviderError>>()
        + size_of::<Result<usize, crucible_node_transport::ProviderError>>()
        + size_of::<Result<NodeHistoryPrequoteData, RuntimeError>>()
        + size_of::<Result<OriginalRestoredSettledNodeHistoryView<'static>, RuntimeError>>()
        + size_of::<Result<(usize, usize), RuntimeError>>()
        + size_of::<Result<(), RuntimeError>>()
}

/// Lends real private custody inside the already-held Source Capture scope.
/// This does not acquire the generic read owner again while SourceRead is live.
pub(in crate::node_adapters::cnp::semantic) fn view_for_current_capture_scope_data<'a>(
    base: &'a SemanticRuntimeCustody,
    route: &'a crate::node_contract::NodeRoute,
    controller: &crucible_node_transport::client::CnpController,
    supervisor: &'a crucible_node_transport::connection::OriginalRetainedSupervisor,
    claim: &OriginalRestoredCaptureClaim<'_>,
) -> Result<OriginalRestoredSettledNodeHistoryView<'a>, RuntimeError> {
    let installed = base
        .installed_restoration
        .as_ref()
        .ok_or(RuntimeError::UnsupportedFacet)?;
    let world = installed
        .activation
        .as_ref()
        .ok_or(RuntimeError::NotActivated)?;
    claim.authenticate_node_data(route, world)?;
    Ok(OriginalRestoredSettledNodeHistoryView {
        base,
        installed,
        route,
        controller_identity: controller,
        supervisor,
        aliases: None,
        records: None,
        provider_aliases: None,
    })
}

impl super::super::super::super::CnpSemanticNode {
    /// Reports complete current17 common custody before its Source row is admitted.
    ///
    /// No Capture claim is issued here. The actual17 administrative caller
    /// independently authenticates the same loan and consumes these axes only
    /// in its whole constructor/capture row.
    ///
    /// # Errors
    /// Refuses foreign current metadata origin, absent custody, unknown layouts
    /// or the independently supplied requested-byte ceiling.
    pub(crate) fn original_restored_settled_node_storage17_prequote_data(
        &self,
        maximum: usize,
    ) -> Result<crate::node_adapters::cnp::CnpRestoredNode17RawStorageData, RuntimeError> {
        self.authenticate_restored_capture_metadata_origin_data()?;
        self.preparation
            .guard
            .custody
            .as_ref()
            .and_then(|native| native.runtime.as_ref())
            .ok_or(RuntimeError::OwnerUnavailable)?
            .retained_current17_runtime_storage_data(maximum)
    }
}

#[path = "capture_history/metadata17.rs"]
mod metadata17;

#[path = "capture_history/controller_baseline17.rs"]
mod controller_baseline17;
#[path = "capture_history/source17.rs"]
mod source17;
