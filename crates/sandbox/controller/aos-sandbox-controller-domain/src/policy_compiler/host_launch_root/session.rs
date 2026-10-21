//! Joins the signed resource result and fresh inventory to one actual Session cut.
//!
//! The finite historical verifier retains both complete exchanges. Their bytes
//! must equal the final proof and the exact Root-issued canonical body and plan;
//! only the independently reread protected Session supplies the transcript.

use aos_sandbox_protocol::domain_ledger::readonly::FixedJournalReadbackDataV1 as RootFixedNativeReadbackV1;

use super::session_inventory_origin::{CurrentInventoryOriginV2, FinalResourceOriginV3};
use super::{
    compiler::RootStartResourceCompilerOriginalV2, plan::RootStartResourceUnsignedPlanOriginalV2,
};
use crate::journal::{JournalError, RecordNamespace};
use crate::policy_compiler::create_storage_current::controller_readonly::{
    storage_inventory::verify_start_resource_session_retaining_v2,
};
use aos_sandbox_broker_session_protocol::hello_message::BrokerMethod;
use aos_sandbox_broker_session_protocol::manifest::BrokerSessionManifestV1;
use aos_sandbox_broker_session_protocol::{
    BrokerSessionDurableHistoryV1, BrokerSessionDurablePhaseV1, BrokerSessionDurableRecordV1,
    BrokerSessionProtocolV1, BrokerSessionTrafficStateV1,
    ProtectedBrokerSessionVerificationContextV1, VerifiedBrokerSessionTranscriptV1,
};
use aos_sandbox_model::format::decode_signature;
use aos_sandbox_model::{
    BrokerPlanExpectation, DecodeLimits, RawPairedClockSample, ResourceDimension as D,
    ResourceVector, VerifiedBrokerPlan,
};
use aos_sandbox_ownership_protocol::SignedOwnershipLease;
use aos_sandbox_protocol::authenticated_session::{
    all_methods::{
        outcome_capture::AuthenticatedBrokerMethodOutcomeCaptureV1 as OutcomeCapture,
        request_capture::AuthenticatedBrokerMethodRequestCaptureV1 as RequestCapture,
    },
    historical_method::HistoricalStartResourceMethodCaptureV2,
    stored_history::{
        StoredBrokerSessionHistoryDecodeCaptureV1, StoredBrokerSessionHistoryV1,
        canonical_protocol_key_v1,
    },
};
use aos_sandbox_protocol::domain_ledger::provisioning_root::host_launch::completion::ResourceCompletionProofDataV2;
use std::error::Error;
use std::mem::size_of;

type Cause = Box<dyn Error>;

enum SessionHistorySelectionV2<'packet> {
    Exact(&'packet [u8], &'packet [u8]),
    MaintenanceStorageExact(&'packet [u8], &'packet [u8]),
    StartCurrentInventory,
    MaintenanceStorageCurrentInventory,
}
type SessionValues = (
    ProtectedBrokerSessionVerificationContextV1,
    VerifiedBrokerSessionTranscriptV1,
    BrokerSessionDurableHistoryV1,
    BrokerSessionTrafficStateV1,
);

pub(in crate::policy_compiler) struct RootStartResourceFinalSessionOriginalV2 {
    stored: StoredBrokerSessionHistoryDecodeCaptureV1,
    verified: Option<Result<SessionValues, Cause>>,
    checkpoint: aos_sandbox_protocol::authenticated_session::historical_checkpoint::HistoricalSessionCheckpointVerifyCaptureV1,
    traffic: aos_sandbox_broker_session_protocol::HistoricalTrafficReplayCaptureV1,
    resource: HistoricalStartResourceMethodCaptureV2,
    inventory: HistoricalStartResourceMethodCaptureV2,
    signature: Option<Result<aos_sandbox_model::model::Signature, aos_sandbox_model::format::CanonicalCborError>>,
    plan: Option<Result<VerifiedBrokerPlan, aos_sandbox_model::BrokerPlanVerificationError>>,
    guardian_signature: Option<Result<aos_sandbox_model::model::Signature, aos_sandbox_model::format::CanonicalCborError>>,
    guardian_plan: Option<Result<VerifiedBrokerPlan, aos_sandbox_model::BrokerPlanVerificationError>>,
    host_live: Option<Result<Vec<u8>, Box<dyn std::error::Error>>>,
    result: Option<Result<(), Cause>>,
    closed: bool,
}

impl RootStartResourceFinalSessionOriginalV2 {
    pub(super) fn new() -> Self {
        Self {
            stored: Default::default(),
            verified: None,
            checkpoint: Default::default(),
            traffic: Default::default(),
            resource: Default::default(),
            inventory: Default::default(),
            signature: None,
            plan: None,
            guardian_signature: None,
            guardian_plan: None,
            host_live: None,
            result: None,
            closed: false,
        }
    }

    pub(in crate::policy_compiler) fn receiving_demand_v2(
        prefix: usize,
        kind: super::kind::ResourceKindV2,
    ) -> Result<ResourceVector, JournalError> {
        let request = RequestCapture::dynamic_receiving_demand_v1(prefix)
            .ok_or(JournalError::JournalTooLarge)?;
        let outcome = OutcomeCapture::controller_inventory_dynamic_receiving_demand_v1(
            kind.inventory_method_v2(),
            prefix,
        )
        .ok_or(JournalError::JournalTooLarge)?;
        // Stored decode and owned history each retain record vectors. One byte
        // per record dominates the canonical nonempty record framing; three
        // capacities cover construction/growth and the retained error prefix.
        let rows = prefix
            .checked_mul(size_of::<BrokerSessionDurableRecordV1>())
            .and_then(|bytes| bytes.checked_mul(3))
            .ok_or(JournalError::JournalTooLarge)?;
        // Complete stored/checkpoint/history copies, HELLO/context/transcript,
        // and the two prior/pending traffic owners have distinct backing lanes.
        let raw_planes = [prefix; 3 + 2 + 2 + 4]
            .into_iter()
            .try_fold(0usize, |sum, bytes| sum.checked_add(bytes))
            .ok_or(JournalError::JournalTooLarge)?;
        let fixed = size_of::<Self>()
            .checked_mul(3)
            .and_then(|bytes| bytes.checked_add(2 * size_of::<CurrentInventoryOriginV2<'_>>()))
            .and_then(|bytes| bytes.checked_add(rows))
            .and_then(|bytes| bytes.checked_add(raw_planes))
            .and_then(|bytes| u64::try_from(bytes).ok())
            .ok_or(JournalError::JournalTooLarge)?;
        // Two complete retained method captures coexist. Prefix replay uses
        // the same canonical packet schema and one selected exchange scratch.
        let resource_result = match kind {
            super::kind::ResourceKindV2::Network => ResourceVector::ZERO,
            super::kind::ResourceKindV2::Host => {
                // The embedded Guardian is a second independently decoded
                // signature/plan, beside the ordinary Host authorization.
                // Decoder fields are Memory, not namespace entries.
                let (guardian, _) = aos_sandbox_model::format::authorization_capture::
                    authorization_artifact_dynamic_footprint_v1(prefix)
                    .ok_or(JournalError::JournalTooLarge)?;
                let encoded = u64::try_from(prefix).map_err(|_| JournalError::JournalTooLarge)?;
                let body = encoded.checked_mul(3).ok_or(JournalError::JournalTooLarge)?;
                let live_encoder = aos_sandbox_broker_session_protocol::receiving_geometry::
                    schema_protobuf_carriers_v1(encoded, 1)
                    .map_err(|_| JournalError::JournalTooLarge)?
                    .checked_mul(3).ok_or(JournalError::JournalTooLarge)?;
                ResourceVector::ZERO.with(D::MemoryBytes,
                    guardian.checked_add(body).and_then(|bytes| bytes.checked_add(live_encoder))
                        .ok_or(JournalError::JournalTooLarge)?)
            }
            super::kind::ResourceKindV2::StorageGuestRoot => {
                let arguments = aos_sandbox_protocol::semantics::storage_guest_root::
                    CanonicalStorageGuestRootArgumentsV1::deadline_free_request_receiving_bytes_v2()
                    .and_then(|bytes| u64::try_from(bytes).ok())
                    .ok_or(JournalError::JournalTooLarge)?;
                crate::cold_launch_publication::completion::
                    create_workspace_comparison_receiving_demand_v1()
                    .ok_or(JournalError::JournalTooLarge)?
                    .checked_add(ResourceVector::ZERO.with(D::MemoryBytes, arguments))?
            }
            super::kind::ResourceKindV2::Mount => {
                // Mount62 retains the decoded resource and its descriptor text;
                // the decoder also owns its transient validated model. The
                // enclosing capture's inline slots are already in Self.
                let bytes = size_of::<aos_sandbox_protocol::mount_attachment_anchor::ValidatedAttachmentAnchorResourceV1>()
                    .checked_add(prefix.min(aos_sandbox_protocol::mount_attachment_anchor::MAXIMUM_ATTACHMENT_ANCHOR_RECORD_BYTES_V1))
                    .and_then(|bytes| bytes.checked_mul(2))
                    .and_then(|bytes| u64::try_from(bytes).ok())
                    .ok_or(JournalError::JournalTooLarge)?;
                ResourceVector::ZERO.with(D::MemoryBytes, bytes)
            }
        };
        let one = request.checked_add(outcome)?;
        one.checked_add(one)?
            .checked_add(one)?
            .checked_add(resource_result)?
            .checked_add(ResourceVector::ZERO.with(D::MemoryBytes, fixed))
            .map_err(JournalError::ReceivingAccounting)
    }

    pub(super) fn observe_once_v2(
        &mut self,
        native: RootFixedNativeReadbackV1<'_>,
        kind: super::kind::ResourceKindV2,
        manifest: &BrokerSessionManifestV1,
        compiler: &RootStartResourceCompilerOriginalV2,
        issued: &RootStartResourceUnsignedPlanOriginalV2,
        historical: &super::history::RootHostHistoricalCreateOriginalV2,
        lease: &SignedOwnershipLease,
        proof: ResourceCompletionProofDataV2<'_>,
        sample: RawPairedClockSample,
        cutoff: u64,
    ) -> Result<(), JournalError> {
        if self.result.is_some() {
            self.closed = true;
            return Err(JournalError::ProtectedBoundary);
        }
        self.result = Some(self.observe_inner_v3(
            native, kind, manifest, FinalResourceOriginV3::Start { compiler, historical },
            issued, lease, proof, sample, cutoff,
        ));
        self.require_complete_v2()
    }

    pub(super) fn observe_maintenance_storage_final_once_v3(
        &mut self, native: RootFixedNativeReadbackV1<'_>, manifest: &BrokerSessionManifestV1,
        assignment: &super::maintenance_assignment::RootMaintenanceAssignmentOriginalV2,
        request: &super::maintenance_request::RootMaintenanceStorageRequestOriginalV2,
        issued: &RootStartResourceUnsignedPlanOriginalV2, lease: &SignedOwnershipLease,
        proof: ResourceCompletionProofDataV2<'_>, sample: RawPairedClockSample, cutoff: u64,
    ) -> Result<(), JournalError> {
        if self.result.is_some() {
            self.closed = true;
            return Err(JournalError::ProtectedBoundary);
        }
        self.result = Some(self.observe_inner_v3(native,
            super::kind::ResourceKindV2::StorageGuestRoot, manifest,
            FinalResourceOriginV3::MaintenanceStorage { assignment, request },
            issued, lease, proof, sample, cutoff));
        self.require_complete_v2()
    }

    fn observe_inner_v3(
        &mut self,
        native: RootFixedNativeReadbackV1<'_>,
        kind: super::kind::ResourceKindV2,
        manifest: &BrokerSessionManifestV1,
        origin: FinalResourceOriginV3<'_>,
        issued: &RootStartResourceUnsignedPlanOriginalV2,
        lease: &SignedOwnershipLease,
        proof: ResourceCompletionProofDataV2<'_>,
        sample: RawPairedClockSample,
        cutoff: u64,
    ) -> Result<(), Cause> {
        use aos_sandbox_protocol::domain_ledger::provisioning_root::host_launch::completion::
            ResourceCompletionPurposeDataV3;
        let assignment = origin.manifest_v3()?;
        let expected = match &origin {
            FinalResourceOriginV3::Start { .. } => ResourceCompletionPurposeDataV3::Start(kind.purpose_v2()),
            FinalResourceOriginV3::MaintenanceStorage { assignment, .. } => {
                if kind != super::kind::ResourceKindV2::StorageGuestRoot {
                    return Err(JournalError::ProtectedBoundary.into());
                }
                assignment.require_inventory_cutoff_data_v2(sample, cutoff)?;
                ResourceCompletionPurposeDataV3::MaintenanceStorage
            }
        };
        if proof.binding.purpose != expected {
            return Err(JournalError::ProtectedBoundary.into());
        }
        self.observe_history_v2(
            native,
            kind,
            manifest,
            *assignment.manifest().node().as_bytes(),
            sample,
            if matches!(&origin, FinalResourceOriginV3::MaintenanceStorage { .. }) {
                SessionHistorySelectionV2::MaintenanceStorageExact(proof.inventory_request, proof.inventory_outcome)
            } else {
                SessionHistorySelectionV2::Exact(proof.inventory_request, proof.inventory_outcome)
            },
        )?;
        let checkpoint = self
            .stored
            .stored()
            .and_then(|stored| stored.checkpoint.as_ref())
            .ok_or(JournalError::ProtectedBoundary)?;
        let (_, transcript, history, _) = self
            .verified
            .as_ref()
            .and_then(|value| value.as_ref().ok())
            .ok_or(JournalError::ProtectedBoundary)?;
        // This flight owns the final resource exchange and its distinct final
        // inventory. Earlier operations remain verified by the same complete
        // transcript/profile/traffic replay above; they are never reinterpreted
        // as authority for the current Root-issued request.
        let index = history
            .records()
            .len()
            .checked_sub(3)
            .ok_or(JournalError::ProtectedBoundary)?;
        let resource = history
            .records()
            .get(index)
            .ok_or(JournalError::ProtectedBoundary)?;
        if index == 0
            || resource.phase() != BrokerSessionDurablePhaseV1::Terminal
            || resource.method() != kind.resource_method_v2()
            || resource.request_packet() != proof.resource_request
            || resource.outcome_packet() != Some(proof.resource_outcome)
        {
            return Err(JournalError::ProtectedBoundary.into());
        }
        match kind {
            super::kind::ResourceKindV2::Host => {
                self.resource.observe_host_once_v2(history.records(), index, checkpoint, transcript)?;
                self.inventory.observe_host_once_v2(history.records(), history.records().len() - 1,
                    checkpoint, transcript)?;
            }
            super::kind::ResourceKindV2::Network => {
                self.resource.observe_network_once_v2(
                    history.records(),
                    index,
                    checkpoint,
                    transcript,
                )?;
                self.inventory.observe_network_once_v2(
                    history.records(),
                    history.records().len() - 1,
                    checkpoint,
                    transcript,
                )?;
            }
            super::kind::ResourceKindV2::StorageGuestRoot => {
                self.resource.observe_storage_once_v2(
                    history.records(),
                    index,
                    checkpoint,
                    transcript,
                )?;
                self.inventory.observe_storage_once_v2(
                    history.records(),
                    history.records().len() - 1,
                    checkpoint,
                    transcript,
                )?;
            }
            super::kind::ResourceKindV2::Mount => {
                self.resource.observe_mount_once_v2(
                    history.records(),
                    index,
                    checkpoint,
                    transcript,
                )?;
                self.inventory.observe_mount_once_v2(
                    history.records(),
                    history.records().len() - 1,
                    checkpoint,
                    transcript,
                )?;
            }
        }
        let request = self
            .resource
            .request_v2()
            .ok_or(JournalError::ProtectedBoundary)?;
        let inventory_request = self
            .inventory
            .request_v2()
            .ok_or(JournalError::ProtectedBoundary)?;
        let authorization = request
            .authorization()
            .ok_or(JournalError::ProtectedBoundary)?;
        let prepared = issued.preparation_v2()?;
        if (kind != super::kind::ResourceKindV2::Host
                && request.exact_body() != issued.request_body_v2()?)
            || authorization.broker_plan() != prepared.canonical_plan()
            || authorization.ownership_lease() != lease.canonical_lease()
            || authorization.ownership_lease_signature() != lease.canonical_signature()
            || request.deadline_boottime_nanoseconds() > cutoff
            || inventory_request.deadline_boottime_nanoseconds() > cutoff
            || inventory_request.deadline_boottime_nanoseconds() <= sample.boottime_nanoseconds()
        {
            return Err(JournalError::ProtectedBoundary.into());
        }
        self.signature = Some(decode_signature(
            authorization.broker_plan_signature(),
            DecodeLimits::default(),
        ));
        let signature = self
            .signature
            .as_ref()
            .and_then(|value| value.as_ref().ok())
            .ok_or(JournalError::ProtectedBoundary)?;
        if signature.statement() != prepared.signing_request().statement() {
            return Err(JournalError::ProtectedBoundary.into());
        }
        let expected = prepared.plan_data_v1();
        self.plan = Some(aos_sandbox_model::verify_broker_plan(
            prepared.canonical_plan(),
            signature,
            issued.anchor_v2()?,
            BrokerPlanExpectation {
                audience: expected.audience(),
                protocol: expected.protocol(),
                protocol_version: expected.protocol_version(),
                assignment: expected.assignment(),
                node: expected.node(),
                now_seconds: sample.wall_seconds(),
            },
            DecodeLimits::default(),
        ));
        let plan = self
            .plan
            .as_ref()
            .and_then(|value| value.as_ref().ok())
            .ok_or(JournalError::ProtectedBoundary)?;
        let grant = expected
            .grants()
            .first()
            .ok_or(JournalError::ProtectedBoundary)?;
        let (commitment, descriptors) = match kind {
            super::kind::ResourceKindV2::Host => (
                aos_sandbox_protocol::semantics::host::canonical_host_semantics_v1(
                    self.resource.host_apply_request_v2().ok_or(JournalError::ProtectedBoundary)?,
                )?.commitment(), 0,
            ),
            super::kind::ResourceKindV2::Network => (request.network_preparation_data_v2()
                .ok_or(JournalError::ProtectedBoundary)?.argument_commitment(), 1),
            super::kind::ResourceKindV2::StorageGuestRoot => (
                request.storage_guest_root_data_v2()
                    .ok_or(JournalError::ProtectedBoundary)?.argument_commitment(), 0,
            ),
            super::kind::ResourceKindV2::Mount => (aos_sandbox_protocol::mount_attachment_anchor::
                canonical_attachment_anchor_semantics_v1(request.mount_attachment_anchor_data_v2()
                    .ok_or(JournalError::ProtectedBoundary)?)?.commitment(), 0),
        };
        plan.match_request(aos_sandbox_model::BrokerPlanRequest {
            verb: grant.verb(),
            target: grant.target(),
            argument_commitment: commitment,
            request_bytes: u32::try_from(request.exact_body().len())
                .map_err(|_| JournalError::ProtectedBoundary)?,
            descriptor_count: descriptors,
        })?;
        match kind {
            super::kind::ResourceKindV2::Host => self.require_host_result_v2(issued, sample),
            super::kind::ResourceKindV2::Network => {
                self.require_network_result_v2(assignment, sample)
            }
            super::kind::ResourceKindV2::Mount => self.require_mount_result_v2(assignment, sample),
            super::kind::ResourceKindV2::StorageGuestRoot => match origin {
                FinalResourceOriginV3::Start { compiler, historical } => self.require_storage_result_v2(
                    assignment, compiler.compiled_v2()?.source_v2().operation_v2(),
                    historical, lease, sample,
                ),
                FinalResourceOriginV3::MaintenanceStorage { request, .. } =>
                    self.require_maintenance_storage_result_v3(assignment, request, lease, sample),
            },
        }
    }

    // The same sole carrier/HELLO/checkpoint/profile/full-traffic engine is
    // used by final four-packet comparison and preparatory current Inventory.
    // Earlier completed operations remain fully verified in either entrance.
    fn observe_history_v2(
        &mut self,
        native: RootFixedNativeReadbackV1<'_>,
        kind: super::kind::ResourceKindV2,
        manifest: &BrokerSessionManifestV1,
        node: [u8; 16],
        sample: RawPairedClockSample,
        selection: SessionHistorySelectionV2<'_>,
    ) -> Result<(), Cause> {
        let key = canonical_protocol_key_v1(kind.protocol_v2());
        for ((namespace, actual_key), _) in native.state {
            if *namespace == RecordNamespace::BrokerSessionTraffic && actual_key != &key {
                return Err(JournalError::ProtectedBoundary.into());
            }
        }
        let bytes = native
            .state
            .get(&(RecordNamespace::BrokerSessionTraffic, key.clone()))
            .ok_or(JournalError::ProtectedBoundary)?;
        StoredBrokerSessionHistoryV1::decode_retaining(&key, bytes, &mut self.stored)?;
        let stored = self
            .stored
            .stored()
            .ok_or(JournalError::ProtectedBoundary)?;
        let checkpoint = stored
            .checkpoint
            .as_ref()
            .ok_or(JournalError::ProtectedBoundary)?;
        self.verified = Some(match selection {
            SessionHistorySelectionV2::Exact(request, outcome) => verify_start_resource_session_retaining_v2(
            kind,
            manifest,
            stored,
            checkpoint.client_hello_bytes(),
            checkpoint.broker_hello_bytes(),
            node,
            sample.host_boot_id(),
            request, outcome,
            &mut self.checkpoint,
            &mut self.traffic,
        ),
            SessionHistorySelectionV2::MaintenanceStorageExact(request, outcome) =>
                crate::policy_compiler::create_storage_current::controller_readonly::
                    storage_inventory::verify_maintenance_storage_session_retaining_v3(
                        manifest, stored, checkpoint.client_hello_bytes(),
                        checkpoint.broker_hello_bytes(), node, sample.host_boot_id(),
                        request, outcome, &mut self.checkpoint, &mut self.traffic,
                    ),
            SessionHistorySelectionV2::StartCurrentInventory => crate::policy_compiler::create_storage_current::controller_readonly::
                storage_inventory::verify_current_start_resource_inventory_retaining_v2(
                    kind, manifest, stored, checkpoint.client_hello_bytes(),
                    checkpoint.broker_hello_bytes(), node, sample.host_boot_id(),
                    &mut self.checkpoint, &mut self.traffic,
                ),
            SessionHistorySelectionV2::MaintenanceStorageCurrentInventory =>
                crate::policy_compiler::create_storage_current::controller_readonly::
                    storage_inventory::verify_current_maintenance_storage_inventory_retaining_v2(
                        manifest, stored, checkpoint.client_hello_bytes(),
                        checkpoint.broker_hello_bytes(), node, sample.host_boot_id(),
                        &mut self.checkpoint, &mut self.traffic,
                    ),
        });
        self.verified
            .as_ref()
            .and_then(|result| result.as_ref().ok())
            .map(|_| ())
            .ok_or_else(|| JournalError::ProtectedBoundary.into())
    }

    /// Captures the actual final signed Inventory of this independently read Session.
    ///
    /// This is a private comparison entrance, never a resource-plan factory.
    /// The genuine Root preparation reader must have paid this same model
    /// recipe before parsing. Its actual native cut and independent posts stay
    /// separate conjunctions in the enclosing Root purpose.
    pub(in crate::policy_compiler) fn observe_current_inventory_once_v2(
        &mut self, native: RootFixedNativeReadbackV1<'_>,
        kind: super::kind::ResourceKindV2, manifest: &BrokerSessionManifestV1,
        compiler: &RootStartResourceCompilerOriginalV2,
        sample: RawPairedClockSample, cutoff: u64,
    ) -> Result<(), JournalError> {
        self.observe_current_inventory_from_origin_once_v2(native, kind, manifest,
            CurrentInventoryOriginV2::Start(compiler), sample, cutoff)
    }

    pub(super) fn observe_maintenance_storage_inventory_once_v2(
        &mut self, native: RootFixedNativeReadbackV1<'_>,
        manifest: &BrokerSessionManifestV1,
        assignment: &super::maintenance_assignment::RootMaintenanceAssignmentOriginalV2,
        sample: RawPairedClockSample, cutoff: u64,
    ) -> Result<(), JournalError> {
        self.observe_current_inventory_from_origin_once_v2(native,
            super::kind::ResourceKindV2::StorageGuestRoot, manifest,
            CurrentInventoryOriginV2::MaintenanceStorage(assignment), sample, cutoff)
    }

    fn observe_current_inventory_from_origin_once_v2(
        &mut self, native: RootFixedNativeReadbackV1<'_>,
        kind: super::kind::ResourceKindV2, manifest: &BrokerSessionManifestV1,
        origin: CurrentInventoryOriginV2<'_>, sample: RawPairedClockSample, cutoff: u64,
    ) -> Result<(), JournalError> {
        if self.result.is_some() {
            self.closed = true;
            return Err(JournalError::ProtectedBoundary);
        }
        self.result =
            Some((|| {
                let assignment = origin.manifest_v2()?;
                origin.require_cutoff_v2(sample, cutoff)?;
                self.observe_history_v2(
                    native,
                    kind,
                    manifest,
                    *assignment.manifest().node().as_bytes(),
                    sample,
                    if origin.permits_storage_inventory_v2() {
                        SessionHistorySelectionV2::MaintenanceStorageCurrentInventory
                    } else {
                        SessionHistorySelectionV2::StartCurrentInventory
                    },
                )?;
                let stored = self
                    .stored
                    .stored()
                    .ok_or(JournalError::ProtectedBoundary)?;
                let checkpoint = stored
                    .checkpoint
                    .as_ref()
                    .ok_or(JournalError::ProtectedBoundary)?;
                let (_, transcript, history, _) = self
                    .verified
                    .as_ref()
                    .and_then(|value| value.as_ref().ok())
                    .ok_or(JournalError::ProtectedBoundary)?;
                let last = history
                    .records()
                    .len()
                    .checked_sub(1)
                    .ok_or(JournalError::ProtectedBoundary)?;
                match kind {
                    super::kind::ResourceKindV2::Mount => self.inventory.observe_mount_once_v2(
                        history.records(),
                        last,
                        checkpoint,
                        transcript,
                    )?,
                    super::kind::ResourceKindV2::Network => self
                        .inventory
                        .observe_network_once_v2(history.records(), last, checkpoint, transcript)?,
                    super::kind::ResourceKindV2::StorageGuestRoot if origin.permits_storage_inventory_v2() => {
                        self.inventory.observe_storage_once_v2(history.records(), last, checkpoint, transcript)?;
                    }
                    super::kind::ResourceKindV2::StorageGuestRoot | super::kind::ResourceKindV2::Host => {
                        return Err(JournalError::ProtectedBoundary.into());
                    }
                }
                let request = self
                    .inventory
                    .request_v2()
                    .ok_or(JournalError::ProtectedBoundary)?;
                if request.method() != kind.inventory_method_v2()
                    || request.deadline_boottime_nanoseconds() <= sample.boottime_nanoseconds()
                {
                    return Err(JournalError::ProtectedBoundary.into());
                }
                origin.require_cutoff_v2(sample, request.deadline_boottime_nanoseconds())?;
                let boot = match kind {
                    super::kind::ResourceKindV2::Mount => self
                        .inventory
                        .mount_inventory_v2()
                        .ok_or(JournalError::ProtectedBoundary)?
                        .kernel_boot_id(),
                    super::kind::ResourceKindV2::Network => self
                        .inventory
                        .inventory_response_v2()
                        .ok_or(JournalError::ProtectedBoundary)?
                        .kernel_boot_id(),
                    super::kind::ResourceKindV2::StorageGuestRoot if origin.permits_storage_inventory_v2() => self
                        .inventory
                        .storage_inventory_response_v2()
                        .ok_or(JournalError::ProtectedBoundary)?
                        .kernel_boot_id(),
                    super::kind::ResourceKindV2::StorageGuestRoot | super::kind::ResourceKindV2::Host => {
                        return Err(JournalError::ProtectedBoundary.into());
                    }
                };
                if boot != &sample.host_boot_id() {
                    return Err(JournalError::ProtectedBoundary.into());
                }
                Ok(())
            })());
        self.require_complete_v2()
    }

    /// Compares query DATA to the exact signed Storage18 native Session head.
    pub(super) fn require_current_storage_exchange_data_v2(&self,
        request: &[u8], outcome: &[u8],
    ) -> Result<(), JournalError> {
        self.require_complete_v2()?;
        self.current_storage_inventory_v2()?;
        let actual_request = self.inventory.request_v2().ok_or(JournalError::ProtectedBoundary)?;
        let actual_outcome = self.inventory.outcome_v2().ok_or(JournalError::ProtectedBoundary)?;
        if actual_request.method() != BrokerMethod::BROKER_METHOD_STORAGE_INVENTORY_RESOURCES
            || actual_request.canonical_packet() != request
            || actual_outcome.canonical_packet() != outcome {
            return Err(JournalError::ProtectedBoundary);
        }
        Ok(())
    }

    pub(super) fn current_storage_inventory_v2(&self)
        -> Result<&aos_sandbox_protocol::ValidatedStorageInventory, JournalError> {
        self.require_complete_v2()?;
        self.inventory.storage_inventory_response_v2().ok_or(JournalError::ProtectedBoundary)
    }

    pub(super) fn current_network_inventory_v2(&self)
        -> Result<&aos_sandbox_protocol::ValidatedNetworkInventory, JournalError> {
        self.require_complete_v2()?;
        self.inventory.inventory_response_v2().ok_or(JournalError::ProtectedBoundary)
    }

    pub(super) fn current_mount_inventory_v2(&self)
        -> Result<&aos_sandbox_protocol::ValidatedDestinationSlotInventory, JournalError> {
        self.require_complete_v2()?;
        self.inventory.mount_inventory_v2().ok_or(JournalError::ProtectedBoundary)
    }

    pub(super) fn require_mount_absent_before_prepare_v2(
        &self,
        assignment: &aos_sandbox_model::CanonicalAssignmentManifestV1,
    ) -> Result<(), JournalError> {
        self.require_complete_v2()?;
        let inventory = self
            .inventory
            .mount_inventory_v2()
            .ok_or(JournalError::ProtectedBoundary)?;
        let mut key = [0; 40];
        key[..16].copy_from_slice(assignment.manifest().sandbox().as_bytes());
        key[16..32].copy_from_slice(assignment.manifest().incarnation().as_bytes());
        key[32..].copy_from_slice(
            &assignment
                .manifest()
                .namespace_generation()
                .get()
                .to_be_bytes(),
        );
        // Ready and Reaped are both occupied durable keys. No lifecycle or
        // attachment-list heuristic may turn either into a fresh namespace.
        if inventory
            .namespace_anchors_v1()
            .iter()
            .any(|row| row.key_v1() == key)
        {
            return Err(JournalError::ProtectedBoundary);
        }
        Ok(())
    }

    fn require_host_result_v2(
        &mut self,
        issued: &RootStartResourceUnsignedPlanOriginalV2,
        sample: RawPairedClockSample,
    ) -> Result<(), Cause> {
        let actual = self.resource.host_apply_request_v2().ok_or(JournalError::ProtectedBoundary)?;
        let companion = actual.guardian_arm().ok_or(JournalError::ProtectedBoundary)?;
        let pair = issued.host_pair_v2()?;
        if actual.action() != aos_sandbox_api::aos::sandbox::local::v1::RuntimeAction::RUNTIME_ACTION_LAUNCH
            || companion.broker_plan() != pair.guardian.canonical_plan() {
            return Err(JournalError::ProtectedBoundary.into());
        }
        self.guardian_signature = Some(decode_signature(companion.broker_plan_signature(), DecodeLimits::default()));
        let signature = self.guardian_signature.as_ref().and_then(|value| value.as_ref().ok())
            .ok_or(JournalError::ProtectedBoundary)?;
        if signature.statement() != pair.guardian.signing_request().statement() {
            return Err(JournalError::ProtectedBoundary.into());
        }
        let expected = pair.guardian.plan_data_v1();
        self.guardian_plan = Some(aos_sandbox_model::verify_broker_plan(pair.guardian.canonical_plan(),
            signature, issued.anchor_v2()?, BrokerPlanExpectation {
                audience: expected.audience(), protocol: expected.protocol(),
                protocol_version: expected.protocol_version(), assignment: expected.assignment(),
                node: expected.node(), now_seconds: sample.wall_seconds(),
            }, DecodeLimits::default()));
        if !matches!(self.guardian_plan, Some(Ok(_))) {
            return Err(JournalError::ProtectedBoundary.into());
        }
        self.host_live = Some((|| -> Result<_, Cause> {
            let body = aos_sandbox_protocol::dispatch_template::inject_deadline(
                issued.request_body_v2()?, actual.header().deadline_boottime_nanoseconds())?;
            Ok(aos_sandbox_protocol::encode_host_guardian_companion_v1(&body,
                pair.guardian.canonical_plan(), companion.broker_plan_signature())?)
        })());
        let body = self.host_live.as_ref().and_then(|value| value.as_ref().ok())
            .ok_or(JournalError::ProtectedBoundary)?;
        if self.resource.request_v2().ok_or(JournalError::ProtectedBoundary)?.exact_body() != body.as_slice() {
            return Err(JournalError::ProtectedBoundary.into());
        }
        // Host owns private GuardianLaunchPhase and enforces GuardianReady
        // before payload Ready. Root independently authenticates that signed
        // Host1 attestation, its exact Guardian plan, fresh3 and native cuts;
        // it does not claim an independent replay of private Host State.
        require_host_ready_pair_data_v2(
            self.resource.host_apply_observation_v2().ok_or(JournalError::ProtectedBoundary)?,
            self.inventory.host_inventory_v2().ok_or(JournalError::ProtectedBoundary)?,
        ).map_err(Into::into)
    }

    fn require_network_result_v2(
        &self,
        assignment: &aos_sandbox_model::CanonicalAssignmentManifestV1,
        sample: RawPairedClockSample,
    ) -> Result<(), Cause> {
        let result = self
            .resource
            .prepare_response_v2()
            .ok_or(JournalError::ProtectedBoundary)?;
        let inventory = self
            .inventory
            .inventory_response_v2()
            .ok_or(JournalError::ProtectedBoundary)?;
        if inventory.kernel_boot_id() != &sample.host_boot_id()
            || result.lease_generation != 0
            || result.state.as_known()
                != Some(
                    aos_sandbox_api::aos::sandbox::local::v1::NetworkState::NETWORK_STATE_DEFAULT_DROP,
                )
        {
            return Err(JournalError::ProtectedBoundary.into());
        }
        let mut rows = inventory
            .networks()
            .iter()
            .filter(|row| row.network_handle().as_slice() == result.network_handle.as_slice());
        let row = rows.next().ok_or(JournalError::ProtectedBoundary)?;
        if rows.next().is_some()
            || row.fence().broker_assignment()? != assignment.broker_assignment()?
            || row.resource_kernel_boot_id() != &sample.host_boot_id()
            || !row.is_launchable()
            || Some(row.state()) != result.state.as_known()
            || row.lease_generation() != 0
            || row.fail_stop_boottime_nanoseconds() != 0
        {
            return Err(JournalError::ProtectedBoundary.into());
        }
        Ok(())
    }

    fn require_maintenance_storage_result_v3(&self,
        manifest: &aos_sandbox_model::CanonicalAssignmentManifestV1,
        request: &super::maintenance_request::RootMaintenanceStorageRequestOriginalV2,
        lease: &SignedOwnershipLease, sample: RawPairedClockSample,
    ) -> Result<(), Cause> {
        let response = self.resource.storage_guest_root_response_v2().ok_or(JournalError::ProtectedBoundary)?;
        request.require_response_data_v2(response)?;
        let inventory = self.inventory.storage_inventory_response_v2().ok_or(JournalError::ProtectedBoundary)?;
        let actual_request = self.resource.request_v2().ok_or(JournalError::ProtectedBoundary)?;
        if inventory.kernel_boot_id() != &sample.host_boot_id()
            || actual_request.request_id() != request.request_id_v2()? {
            return Err(JournalError::ProtectedBoundary.into());
        }
        let workspace = super::current_storage::selected_current_storage_workspace_data_v2(manifest, inventory)?;
        super::current_storage::require_current_storage_workspace_publication_data_v2(
            workspace, manifest, request.arguments_v2()?, response, lease, &request.request_id_v2()?)
    }

    fn require_storage_result_v2(
        &self,
        manifest: &aos_sandbox_model::CanonicalAssignmentManifestV1,
        operation: aos_sandbox_model::OperationId,
        historical: &super::history::RootHostHistoricalCreateOriginalV2,
        lease: &SignedOwnershipLease,
        sample: RawPairedClockSample,
    ) -> Result<(), Cause> {
        let response = self
            .resource
            .storage_guest_root_response_v2()
            .ok_or(JournalError::ProtectedBoundary)?;
        let inventory = self
            .inventory
            .storage_inventory_response_v2()
            .ok_or(JournalError::ProtectedBoundary)?;
        if inventory.kernel_boot_id() != &sample.host_boot_id() {
            return Err(JournalError::ProtectedBoundary.into());
        }
        let (handle, creation_operation) = historical.creation_workspace_selectors_v2()?;
        let arguments = aos_sandbox_protocol::semantics::storage_guest_root::
            CanonicalStorageGuestRootArgumentsV1::from_protected_assignment(
                manifest.broker_assignment()?, operation.into_bytes(), handle, creation_operation,
            )?;
        super::current_storage::require_current_storage_publication_data_v2(
            historical,
            manifest,
            &arguments,
            response,
            inventory,
            lease,
            &operation.into_bytes(),
        )
    }

    fn require_mount_result_v2(
        &self,
        assignment: &aos_sandbox_model::CanonicalAssignmentManifestV1,
        sample: RawPairedClockSample,
    ) -> Result<(), Cause> {
        let result = self
            .resource
            .mount_response_v2()
            .ok_or(JournalError::ProtectedBoundary)?;
        let inventory = self
            .inventory
            .mount_inventory_v2()
            .ok_or(JournalError::ProtectedBoundary)?;
        if inventory.kernel_boot_id() != &sample.host_boot_id()
            || result.fence().broker_assignment()? != assignment.broker_assignment()?
            || result.namespace_generation() != assignment.manifest().namespace_generation().get()
            || result.sandbox_spec() != assignment.manifest().sandbox_spec()
            || result.lifecycle() != aos_sandbox_api::aos::sandbox::local::v1::AttachmentAnchorLifecycleV1::ATTACHMENT_ANCHOR_LIFECYCLE_V1_READY
            || result.resource_kernel_boot_id() != &sample.host_boot_id()
            || result.physical_identity_v1().is_none()
            || result.reap_v1().is_some() {
            return Err(JournalError::ProtectedBoundary.into());
        }
        let mut rows = inventory
            .namespace_anchors_v1()
            .iter()
            .filter(|row| row.key_v1() == result.key_v1());
        let row = rows.next().ok_or(JournalError::ProtectedBoundary)?;
        if rows.next().is_some() || row != result {
            return Err(JournalError::ProtectedBoundary.into());
        }
        Ok(())
    }

    pub(super) fn require_complete_v2(&self) -> Result<(), JournalError> {
        if !self.closed && matches!(self.result, Some(Ok(()))) && self.failure().is_none() {
            Ok(())
        } else {
            Err(JournalError::ProtectedBoundary)
        }
    }

    pub(super) fn completed_host_comparison_data_v2(&self)
        -> Result<(&[u8], &[u8], &[u8], &[u8]), JournalError> {
        self.require_complete_v2()?;
        let request = self.resource.request_v2().ok_or(JournalError::ProtectedBoundary)?;
        if request.method() != BrokerMethod::BROKER_METHOD_HOST_APPLY_RUNTIME {
            return Err(JournalError::ProtectedBoundary);
        }
        let authorization = request.authorization().ok_or(JournalError::ProtectedBoundary)?;
        let aos_sandbox_protocol::authenticated_session::all_methods::
            AuthenticatedBrokerMethodResultV1::Success { exact_body, .. } =
            self.resource.outcome_v2().ok_or(JournalError::ProtectedBoundary)?.result()
        else { return Err(JournalError::ProtectedBoundary); };
        Ok((authorization.broker_plan(), authorization.broker_plan_signature(),
            request.exact_body(), exact_body.as_slice()))
    }

    pub(super) fn local_cutoff_v2(&self) -> Result<u64, JournalError> {
        self.require_complete_v2()?;
        let resource = self
            .resource
            .request_v2()
            .ok_or(JournalError::ProtectedBoundary)?;
        let inventory = self
            .inventory
            .request_v2()
            .ok_or(JournalError::ProtectedBoundary)?;
        Ok(resource
            .deadline_boottime_nanoseconds()
            .min(inventory.deadline_boottime_nanoseconds()))
    }

    pub(super) fn failure(&self) -> Option<&(dyn Error + 'static)> {
        self.stored
            .failure()
            .map(|cause| cause as _)
            .or_else(|| self.checkpoint.failure().map(|cause| cause as _))
            .or_else(|| self.traffic.cause())
            .or_else(|| {
                self.verified
                    .as_ref()?
                    .as_ref()
                    .err()
                    .map(|cause| cause.as_ref())
            })
            .or_else(|| self.resource.failure_v2())
            .or_else(|| self.inventory.failure_v2())
            .or_else(|| self.guardian_signature.as_ref()?.as_ref().err().map(|cause| cause as _))
            .or_else(|| self.guardian_plan.as_ref()?.as_ref().err().map(|cause| cause as _))
            .or_else(|| self.host_live.as_ref()?.as_ref().err().map(|cause| cause.as_ref()))
            .or_else(|| {
                self.signature
                    .as_ref()?
                    .as_ref()
                    .err()
                    .map(|cause| cause as _)
            })
            .or_else(|| self.plan.as_ref()?.as_ref().err().map(|cause| cause as _))
            .or_else(|| {
                self.result
                    .as_ref()?
                    .as_ref()
                    .err()
                    .map(|cause| cause.as_ref())
            })
    }
}


fn require_host_ready_pair_data_v2(
    receipt: &aos_sandbox_api::aos::sandbox::local::v1::RuntimeObservation,
    inventory: &aos_sandbox_api::aos::sandbox::local::v1::InventoryRuntimeResponse,
) -> Result<(), JournalError> {
    use aos_sandbox_api::aos::sandbox::local::v1::RuntimeState;
    let mut matches = inventory.runtimes.iter()
        .filter(|row| row.runtime_handle == receipt.runtime_handle);
    let current = matches.next().ok_or(JournalError::ProtectedBoundary)?;
    if matches.next().is_some()
        || receipt.state.as_known() != Some(RuntimeState::RUNTIME_STATE_READY)
        || current.state.as_known() != Some(RuntimeState::RUNTIME_STATE_READY)
        || receipt.runtime_handle.len() != 32 || receipt.leader_handle.len() != 32
        || current.leader_handle != receipt.leader_handle || current.fence != receipt.fence
        || current.observation_sequence < receipt.observation_sequence
        || receipt.observation_sequence == 0
        || receipt.error.as_option().is_some() || current.error.as_option().is_some()
        || !receipt.capture_stop_residual_v4.is_empty() || !current.capture_stop_residual_v4.is_empty()
    {
        return Err(JournalError::ProtectedBoundary);
    }
    Ok(())
}

#[cfg(test)]
mod host_ready_tests {
    use super::*;
    use aos_sandbox_api::aos::sandbox::local::v1::{InventoryRuntimeResponse, RuntimeObservation, RuntimeState};

    fn ready() -> RuntimeObservation {
        RuntimeObservation { runtime_handle: vec![1; 32], leader_handle: vec![2; 32],
            observation_sequence: 7, state: RuntimeState::RUNTIME_STATE_READY.into(),
            ..Default::default() }
    }

    #[test]
    fn ready_relation_refuses_non_ready_stale_or_foreign_inventory() {
        let receipt = ready();
        let mut inventory = InventoryRuntimeResponse { runtimes: vec![receipt.clone()], ..Default::default() };
        assert!(require_host_ready_pair_data_v2(&receipt, &inventory).is_ok());

        inventory.runtimes[0].observation_sequence = 6;
        assert!(require_host_ready_pair_data_v2(&receipt, &inventory).is_err());
        inventory.runtimes[0] = receipt.clone();
        inventory.runtimes[0].leader_handle[0] ^= 1;
        assert!(require_host_ready_pair_data_v2(&receipt, &inventory).is_err());
        inventory.runtimes[0] = receipt.clone();
        inventory.runtimes[0].state = RuntimeState::RUNTIME_STATE_STARTING.into();
        assert!(require_host_ready_pair_data_v2(&receipt, &inventory).is_err());
        inventory.runtimes[0] = receipt.clone();
        let mut non_ready = receipt;
        non_ready.state = RuntimeState::RUNTIME_STATE_STARTING.into();
        assert!(require_host_ready_pair_data_v2(&non_ready, &inventory).is_err());
    }
}
