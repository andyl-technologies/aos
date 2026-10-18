//! Defines the closed inert wire of the actual current Node17 custody writer.
//!
//! Historical worlds, admissions and batches are data records. Their owned
//! representation contains no Runtime authority, Source key, Window, operation
//! token or native owner. The separate signed-source validator supplies their
//! correspondence before a fresh real constructor receives an opaque handle.
//!
//! ```text
//! {schema:"source-owned.packet-restored-node-history/17",base:{...},
//!  original_operations:[],original_inputs:[],producer_attempts:[],...}
//! ```

use std::collections::BTreeMap;

use crucible_node_contract::{
    ActivationManifest, ContentRef, Extensions, Id, Position, PreparedOwner, U64,
};
use crucible_node_provider::bodies::*;
use serde::{Deserialize, Serialize};

use crate::node_contract::{
    NodeRoute, OperationFailure, OperationOutcome, OperationRequest, OwnerIdentity,
    SavedRuntimeActivation as ActivationRecord,
};
use crate::node_scheduling::{
    InputPayload, NativeInputAcknowledgement, NativeSchedulingObservation,
};

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct NodeRecord17 {
    pub(super) schema: String,
    pub(super) base: BaseRecord17,
    pub(super) base_activate_response_history: Option<ActivationOwnerWrapper17>,
    pub(super) install_started: bool,
    pub(super) installed: bool,
    pub(super) activation: Option<HistoricalWorld17>,
    pub(super) original_operations: Vec<HistoricalAdmission17>,
    pub(super) original_inputs: Vec<HistoricalBatch17>,
    pub(super) commands: [Option<ActivationOwnerWrapper17>; 2],
    pub(super) completed: [Option<ResponseWrapper17>; 2],
    pub(super) world_manifest: Option<ActivationOwnerWrapper17>,
    pub(super) world_value: Option<serde_json::Value>,
    pub(super) world_bytes: Option<Vec<u8>>,
    pub(super) observation_attempted: bool,
    pub(super) observation_completed: Option<ResponseWrapper17>,
    pub(super) observation: Option<NativeSchedulingObservation>,
    pub(super) observation_return: Option<NativeSchedulingObservation>,
    pub(super) current_observations: Vec<CurrentObservation17>,
    pub(super) producer_pending: Option<ProducerAttempt17>,
    pub(super) producer_attempts: Vec<ProducerAttempt17>,
    pub(super) original_operations_capacity: usize,
    pub(super) original_inputs_capacity: usize,
    pub(super) producer_attempts_capacity: usize,
    pub(super) capacities: Vec<CommonCapacity17>,
    pub(super) restored_families: Option<RestoredFamilies17>,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct BaseRecord17 {
    pub(super) schema: String,
    pub(super) arm_attempt: Option<ActivationRecord>,
    pub(super) ready: Option<Readiness17>,
    pub(super) prepared_owner: Option<PreparedOwner>,
    pub(super) activate_response: Option<WorldActivateResult>,
    pub(super) observe_sequence: U64,
    pub(super) activation_attempt: Option<ActivationRecord>,
    pub(super) active: Option<ActivationRecord>,
    pub(super) inputs: BTreeMap<Id, OriginalInput17>,
    pub(super) operations: BTreeMap<Id, OriginalOperation17>,
    pub(super) watermark: U64,
    pub(super) observation: Option<(ActivationRecord, NativeSchedulingObservation)>,
    pub(super) reclaimed: Option<(OwnerIdentity, ContentRef)>,
    pub(super) retained_credit: usize,
    pub(super) quarantined: bool,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Readiness17 {
    pub(super) owners: Vec<OwnerIdentity>,
    pub(super) boundary: Position,
    pub(super) state_inventory: ContentRef,
    pub(super) ready_receipt: ContentRef,
}

#[derive(Serialize, Deserialize)]
#[serde(tag = "kind", content = "value", deny_unknown_fields)]
pub(super) enum HistoricalWorld17 {
    #[serde(rename = "world")]
    World(WorldRecord17),
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct WorldRecord17 {
    pub(super) record: ActivationRecord,
    pub(super) nodes: Vec<NodePreparation17>,
    pub(super) preparation: Option<WorldPublication17>,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct NodePreparation17 {
    pub(super) node: Id,
    pub(super) readiness: Readiness17,
    pub(super) prepared_owners: Option<Vec<PreparedOwner>>,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct WorldPublication17 {
    pub(super) nodes: Vec<NodePreparation17>,
    pub(super) owners: Vec<PreparedOwner>,
    pub(super) coordinator: InputPayload,
}

#[derive(Serialize, Deserialize)]
#[serde(tag = "kind", content = "value", deny_unknown_fields)]
pub(super) enum HistoricalAdmission17 {
    #[serde(rename = "admission")]
    Admission(AdmissionRecord17),
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct AdmissionRecord17 {
    pub(super) operation: Id,
    pub(super) route: NodeRoute,
    pub(super) request: OperationRequest,
    pub(super) activation: WorldRecord17,
    pub(super) inputs: Option<BatchRecord17>,
}

#[derive(Serialize, Deserialize)]
#[serde(tag = "kind", content = "value", deny_unknown_fields)]
pub(super) enum HistoricalBatch17 {
    #[serde(rename = "input_batch")]
    InputBatch(BatchRecord17),
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct BatchRecord17 {
    pub(super) activation: WorldRecord17,
    pub(super) node: Id,
    pub(super) stage_operation: Id,
    pub(super) batch: Id,
    pub(super) owners: Vec<OwnerIdentity>,
    pub(super) cutoff: Position,
    pub(super) inventory: ContentRef,
    pub(super) deliveries: Vec<crate::node_scheduling::event::Delivery>,
    pub(super) payloads: Vec<InputPayload>,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct OriginalBatch17 {
    pub(super) activation: ActivationRecord,
    pub(super) node: Id,
    pub(super) stage_operation: Id,
    pub(super) batch: Id,
    pub(super) owners: Vec<OwnerIdentity>,
    pub(super) cutoff: Position,
    pub(super) inventory: ContentRef,
    pub(super) deliveries: Vec<crate::node_scheduling::event::Delivery>,
    pub(super) payloads: Vec<InputPayload>,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct OriginalOperation17 {
    pub(super) operation: Id,
    pub(super) route: NodeRoute,
    pub(super) request: OperationRequest,
    pub(super) activation: ActivationRecord,
    pub(super) inputs: Option<OriginalBatch17>,
    pub(super) begin: BeginRequest,
    pub(super) outcome: Option<OperationOutcome>,
    pub(super) failure: Option<OperationFailure>,
    pub(super) polls: U64,
    pub(super) begin_acknowledged: bool,
    pub(super) cancellation: (String, Option<OperationFailure>),
    pub(super) acknowledged: bool,
    pub(super) retirement: Option<InputPayload>,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct OriginalInput17 {
    pub(super) original: OriginalBatch17,
    pub(super) acknowledgement: Option<NativeInputAcknowledgement>,
    pub(super) watermark: U64,
    pub(super) request: InputRequest,
    pub(super) commitment: Option<InputCommitment17>,
    pub(super) response: Option<InputResult>,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct InputCommitment17 {
    pub(super) original: InputCommit17,
    pub(super) request_id: Id,
    pub(super) extensions: Extensions,
    pub(super) context: Vec<InputPayload>,
    pub(super) response: Option<InputResult>,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct InputCommit17 {
    pub(super) activation: ActivationRecord,
    pub(super) node: Id,
    pub(super) stage_operation: Id,
    pub(super) batch: Id,
    pub(super) inventory: ContentRef,
    pub(super) cutoff: Position,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct CurrentObservation17 {
    pub(super) ordinal: u64,
    pub(super) retained: Option<NativeSchedulingObservation>,
    pub(super) returned: Option<NativeSchedulingObservation>,
}

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub(super) enum ProducerStage17 {
    Beginning,
    Begun,
    Polling,
    Completed,
    Retiring,
    Retired,
    Observing,
    Verified,
    Failed,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct ProducerAttempt17 {
    pub(super) admission: HistoricalAdmission17,
    pub(super) slot: usize,
    pub(super) stage: ProducerStage17,
    pub(super) retained: Option<OperationOutcome>,
    pub(super) returned: Option<OperationOutcome>,
    pub(super) scheduling: Option<NativeSchedulingObservation>,
    pub(super) scheduling_return: Option<NativeSchedulingObservation>,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct ActivationOwnerWrapper17 {
    pub(super) capacities: Vec<ProviderCapacity17>,
    pub(super) aliases: Vec<ProviderAlias17>,
    pub(super) value: ActivationOwner17,
}

#[derive(Serialize, Deserialize)]
#[serde(tag = "kind", content = "data", deny_unknown_fields)]
pub(super) enum ActivationOwner17 {
    #[serde(rename = "command")]
    Command(Command17),
    #[serde(rename = "manifest")]
    Manifest(ActivationManifest),
    #[serde(rename = "world_result")]
    WorldResult(WorldActivateResult),
}

#[derive(Serialize, Deserialize)]
#[serde(tag = "kind", content = "data", deny_unknown_fields)]
pub(super) enum Command17 {
    #[serde(rename = "arm")]
    Arm(ActivateRequest),
    #[serde(rename = "world_activate")]
    WorldActivate(WorldActivateRequest),
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct ResponseWrapper17 {
    pub(super) capacities: Vec<ProviderCapacity17>,
    pub(super) aliases: Vec<ProviderAlias17>,
    pub(super) value: ResponseRecord17,
}

pub(super) struct ResponseRecord17 {
    pub(super) body: ResponseBody,
}

impl Serialize for ResponseRecord17 {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        use serde::ser::Error;
        crucible_node_provider::retained_metadata::historical_response_body_data(&self.body)
            .map_err(S::Error::custom)?
            .serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for ResponseRecord17 {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct Wire {
            shape: ResponseShape,
            result: Option<MethodResult17>,
        }
        let wire = Wire::deserialize(deserializer)?;
        Ok(Self {
            body: ResponseBody {
                shape: wire.shape,
                result: wire.result.map(Into::into),
            },
        })
    }
}

#[derive(Serialize, Deserialize)]
#[serde(tag = "kind", content = "data", deny_unknown_fields)]
pub(super) enum MethodResult17 {
    #[serde(rename = "admit")]
    Admit(AdmitResult),
    #[serde(rename = "activate")]
    Activate(ActivateResult),
    #[serde(rename = "world_activate")]
    WorldActivate(WorldActivateResult),
    #[serde(rename = "prepare_restore")]
    PrepareRestore(PrepareRestoreResult),
    #[serde(rename = "capture")]
    Capture(CaptureResult),
    #[serde(rename = "begin_accepted")]
    BeginAccepted(BeginAccepted),
    #[serde(rename = "input")]
    Input(InputResult),
    #[serde(rename = "observe")]
    Observe(ObserveResult),
    #[serde(rename = "poll")]
    Poll(PollResult),
    #[serde(rename = "exact_run")]
    ExactRun(ExactRunResult),
    #[serde(rename = "boundary_settle")]
    BoundarySettle(ExactRunResult),
    #[serde(rename = "retire")]
    Retire(RetireResult),
    #[serde(rename = "blob_begin")]
    BlobBegin(BlobBeginResult),
    #[serde(rename = "blob_chunk")]
    BlobChunk(BlobChunkResult),
    #[serde(rename = "blob_finish")]
    BlobFinish(BlobFinishResult),
}

impl From<MethodResult17> for MethodResult {
    fn from(value: MethodResult17) -> Self {
        match value {
            MethodResult17::Admit(value) => Self::Admit(value),
            MethodResult17::Activate(value) => Self::Activate(value),
            MethodResult17::WorldActivate(value) => Self::WorldActivate(value),
            MethodResult17::PrepareRestore(value) => Self::PrepareRestore(value),
            MethodResult17::Capture(value) => Self::Capture(value),
            MethodResult17::BeginAccepted(value) => Self::BeginAccepted(value),
            MethodResult17::Input(value) => Self::Input(value),
            MethodResult17::Observe(value) => Self::Observe(value),
            MethodResult17::Poll(value) => Self::Poll(value),
            MethodResult17::ExactRun(value) => Self::ExactRun(value),
            MethodResult17::BoundarySettle(value) => Self::BoundarySettle(value),
            MethodResult17::Retire(value) => Self::Retire(value),
            MethodResult17::BlobBegin(value) => Self::BlobBegin(value),
            MethodResult17::BlobChunk(value) => Self::BlobChunk(value),
            MethodResult17::BlobFinish(value) => Self::BlobFinish(value),
        }
    }
}
/// Preserves historical exposed capacity facts without recreating allocation authority.
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct CommonCapacity17 {
    pub(super) kind: CommonCapacityKind17,
    pub(super) length: usize,
    pub(super) capacity: Option<usize>,
    pub(super) element_bytes: usize,
    pub(super) alignment: usize,
    pub(super) shared_group: Option<usize>,
}

#[derive(Clone, Copy, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub(super) enum CommonCapacityKind17 {
    String,
    Vector,
    Tree,
    Shared,
}

/// Uses the defining Provider four-field tuple, including actual alignment.
#[derive(Serialize, Deserialize)]
pub(super) struct ProviderCapacity17(
    pub(super) ProviderCapacityKind17,
    pub(super) usize,
    pub(super) usize,
    pub(super) usize,
);

#[derive(Clone, Copy, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub(super) enum ProviderCapacityKind17 {
    String,
    Vector,
    Tree,
    Shared,
    Boxed,
}

/// Retains historical numeric groups without accepting process addresses.
#[derive(Serialize, Deserialize)]
pub(super) struct ProviderAlias17(pub(super) ProviderSharedKind17, pub(super) usize);

#[derive(Clone, Copy, Serialize, Deserialize)]
pub(super) enum ProviderSharedKind17 {
    #[serde(rename = "native-restored-physical-hold")]
    NativeRestoredPhysicalHold,
    #[serde(rename = "native-restore-commit-attempt")]
    NativeRestoreCommitAttempt,
    #[serde(rename = "native-restore-input-custody")]
    NativeRestoreInputCustody,
    #[serde(rename = "native-restoration-observation-attempt")]
    NativeRestorationObservationAttempt,
    #[serde(rename = "native-restored-suffix-observe-attempt")]
    NativeRestoredSuffixObservationAttempt,
    #[serde(rename = "native-restored-producer-attempt")]
    NativeRestoredProducerAttempt,
    #[serde(rename = "protocol-owner")]
    ProtocolOwner,
    #[serde(rename = "registrar-epoch")]
    RegistrarEpoch,
    #[serde(rename = "registrar-gate")]
    RegistrarGate,
    #[serde(rename = "selected-extensions")]
    SelectedExtensions,
    #[serde(rename = "codec")]
    Codec,
    #[serde(rename = "native-policy")]
    NativePolicy,
    #[serde(rename = "hello-bank")]
    HelloBank,
    #[serde(rename = "content-bytes")]
    ContentBytes,
    #[serde(rename = "frame-bank")]
    FrameBank,
    #[serde(rename = "native-boot")]
    NativeBoot,
    #[serde(rename = "private-bootstrap-bank")]
    PrivateBootstrapBank,
    #[serde(rename = "installed-registry")]
    InstalledRegistry,
    #[serde(rename = "native-supervisor")]
    NativeSupervisor,
    #[serde(rename = "blob-ledger")]
    BlobLedger,
    #[serde(rename = "host-supervisor")]
    HostSupervisor,
    #[serde(rename = "operational-deadline")]
    OperationalDeadline,
    #[serde(rename = "archived-mapping")]
    ArchivedMapping,
    #[serde(rename = "native-control-identity")]
    NativeControlIdentity,
    #[serde(rename = "native-fresh-report-attempt")]
    NativeFreshReportAttempt,
    #[serde(rename = "native-restore-prepare-attempt")]
    NativeRestorePrepareAttempt,
    #[serde(rename = "native-restoration-activation-attempt")]
    NativeRestorationActivationAttempt,
    #[serde(rename = "native-restoration-upload-attempt")]
    NativeRestorationUploadAttempt,
}

/// Records current fresh handles separately from their immutable inherited bodies.
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct RestoredFamilies17 {
    pub(super) schema: String,
    pub(super) inherited: Option<ContentRef>,
    pub(super) started: bool,
    pub(super) installed: bool,
    pub(super) imported_operations: BTreeMap<Id, HistoricalAdmission17>,
    pub(super) base_operations: BTreeMap<Id, HistoricalAdmission17>,
    pub(super) producer_operations: BTreeMap<Id, HistoricalAdmission17>,
    pub(super) imported_inputs: BTreeMap<Id, HistoricalBatch17>,
    pub(super) base_inputs: BTreeMap<Id, HistoricalBatch17>,
}
