//! Host-owned installed providers and native enrollment before graph sealing.

mod acceptance;
mod archive_artifacts;
mod arm_root;
mod cached_artifacts;
mod capabilities;
mod clock_label;
mod complete_scene;
mod gem5_profile;
mod host_state;
mod io;
mod kvm;
mod mixed_vendor_selection;
pub(super) mod recorded_ingress;
mod vendor_selection;
mod vendors;
mod vendors_mixed;
mod x86_root;

mod condition_debug;
mod controlled;
mod faulted;
mod native_state;
mod normal_clock;
mod prepared_models;
mod profile;
#[cfg(test)]
mod reference_lineage_reader;
mod reference_public;
mod scripted;
mod seeded;
mod semantics;
pub use condition_debug::InstalledConditionDebugProfile;
mod transcript;
mod trust;
mod typed_reader;

pub use normal_clock::{
    ClockAdmissionObservationData, ClockStateObservationData, InstalledNormalClockProfile,
    InstalledNormalClockStateFactory, NormalClockProgramme, OriginalClockAdverseWitness,
    OriginalClockAggregateResources, OriginalClockFailureWitness, OriginalClockProcessBootstrap,
    OriginalClockQualificationRun, OriginalClockStateProgramme, OriginalClockStateWitness,
};

pub use typed_reader::{
    InstalledTypedReaderCatalog, InstalledTypedReaderCatalogPolicy,
    InstalledTypedReaderConfiguration, InstalledTypedReaderFixtureAuthority,
    InstalledTypedReaderHostInvocation, InstalledTypedReaderOwningPolicy,
    InstalledTypedReaderPackage, InstalledTypedReaderPreparation,
    InstalledTypedReaderPreparedParts, InstalledTypedReaderSourceFixture,
    LaunchedTypedReaderProvider, LaunchedTypedReaderSession, OriginalTypedWindowSeal,
    PreparedTypedReaderCohort, PreparedTypedReaderHostCollection,
    PreparedTypedReaderHostInvocation, PreparedTypedReaderHostSources, PreparedTypedReaderSession,
    ReclaimedTypedReaderHostCollection, ReclaimedTypedReaderHostSources,
    SelectedTypedReaderHostSource, SelectedTypedReaderPublicRole, StoredTypedReaderResultPublisher,
    TypedReaderAdoptionFailure, TypedReaderCohortReservation, TypedReaderCollectingDriver,
    TypedReaderCollectingExtensionPolicy, TypedReaderCollectionWorld, TypedReaderCustodyPair,
    TypedReaderCustodySupervisor, TypedReaderDrivingError, TypedReaderFixtureAudit,
    TypedReaderFixtureLaunchRequest, TypedReaderFixtureLaunches, TypedReaderHostCollection,
    TypedReaderHostExecution, TypedReaderHostIncidents, TypedReaderHostInvocationFailure,
    TypedReaderHostInvocationRequest, TypedReaderHostPreparationRequest, TypedReaderHostReport,
    TypedReaderHostSchemas, TypedReaderHostServices, TypedReaderHostSessionScope,
    TypedReaderHostSourceFailure, TypedReaderHostSourcesExecution, TypedReaderHostSourcesRequest,
    TypedReaderHostStartFailure, TypedReaderLaunchError, TypedReaderLaunchFailure,
    TypedReaderNativeOracles, TypedReaderOriginalRow, TypedReaderPrivateAuthorization,
    TypedReaderProgramme, TypedReaderProgrammePeer, TypedReaderProgrammeWindow,
    TypedReaderSessionFailure, TypedReaderSessionLaunchFailure,
    TypedReaderSessionPreparationFailure, TypedReaderSessionRequest, TypedReaderSourceHandshake,
    TypedReaderWindowDisposition, TypedReaderWindowTicket, TypedReaderWitnessAuthority,
};

#[cfg(test)]
mod artifact_tests;

#[cfg(test)]
mod semantic_terminal_tests;

#[cfg(test)]
mod semantic_profile_tests;

pub(super) use transcript::replay_stepper::{ReplayStep, ReplayStepper};

pub use x86_root::public_catalog::{
    InstalledPreparedX86RootWorld, InstalledX86RootPreservation, InstalledX86RootRestore,
    X86RootInitialRetirementFailure, X86RootRestoredRetirementFailure,
    X86RootUnstartedRetirementFailure,
};
pub use x86_root::{
    InstalledX86RootCleanupFailure, InstalledX86RootCleanupStatus, InstalledX86RootRetirement,
    X86RootNamespaceReleaseFailure,
};

pub use arm_root::public_catalog::{
    InstalledPreparedRootWorld, InstalledRootPreservation, InstalledRootRestore,
    RootInitialRetirementFailure, RootRestoredRetirementFailure, RootUnstartedRetirementFailure,
};
pub use arm_root::{
    InstalledRootCleanupFailure, InstalledRootCleanupStatus, InstalledRootRetirement,
    RootNamespaceReleaseFailure,
};
pub use capabilities::{
    InstalledCapabilityCandidate, InstalledCapabilityClockFactory, ResolvedCapabilityWorld,
};
pub use clock_label::{InstalledClockLabelFactory, InstalledClockLabelProfile};
pub use controlled::InstalledControlledFaultProfile;
pub use faulted::InstalledFaultedLinkProfile;
pub use gem5_profile::InstalledGem5ClosedProfile;
pub use host_state::InstalledHostStateFactory;
pub use io::{InstalledHostIoProfile, InstalledIoArtifact, InstalledIoArtifactSource};
pub use kvm::{
    MAX_KVM_CANDIDATE_POLICY_BYTES, load_installed_kvm_candidate, prepare_installed_kvm_candidate,
};
pub use mixed_vendor_selection::{InstalledMixedVendorWorldRequest, InstalledVendorContribution};
pub use native_state::behavioral::{
    Gem5BehavioralCase, Gem5BehavioralReport, Gem5BehavioralRequest, Gem5BehavioralRun,
    InstalledGem5BehavioralAcceptance,
};
pub use native_state::public_catalog::{InstalledNativePreservation, InstalledPreparedNativeWorld};
pub use native_state::public_group::{
    InstalledIndependentNativePreservation, InstalledIndependentNativeRestore,
    InstalledPreparedIndependentNativeWorld,
};

pub(crate) use native_state::public_group::{
    FailureRetirementSummary, OriginalFailedNativeRelease, OriginalFailedSupervision,
    OriginalNativeSupervision, PreparedFailureRetirement,
};
pub use native_state::{
    InstalledGem5Isa, NativeCapturePoint, NativeWorldOutcome, NativeWorldRecord,
    NativeWorldRequest, NativeWorldRetention, NativeWorldService,
};
pub use recorded_ingress::InstalledRecordedIngressProfile;
pub use reference_public::{
    InstalledPublicReferencePackage, InstalledReferenceQualifier, InstalledSingletonCollector,
    OriginalSingletonCollection, PublicReferenceVendorProfile, PublicReferenceVendorSelection,
    QualificationRunError, ReferenceQualificationObservation, ReferenceQualificationRun,
    ReferenceVendorInstallation, ReferenceVendorInstallationRequest,
    SingletonCollectionObservation,
};
pub use scripted::InstalledScriptedSourceProfile;
pub use seeded::InstalledSeededLinkProfile;
pub use semantics::InstalledHostSemanticProfile;
pub use transcript::{
    InstalledConditionalReplay, InstalledOriginalLineageAuthority, InstalledOriginalLineagePlan,
    InstalledOriginalLineagePreparation, InstalledOriginalLineageSourcePolicy,
    InstalledRecordedWorld, InstalledReferenceRecording, InstalledReplayRecipe,
};

use std::{
    collections::BTreeMap,
    fs::File,
    io::Read,
    path::{Path, PathBuf},
    rc::Rc,
    sync::Arc,
    time::Duration,
};

use crucible_campaign::ExecutionId;
use crucible_engine::{
    node_adapters::{HostModelNode, HostModelResources, ReferenceDeviceNode},
    node_admission::{AdmissionLimits, AdmittedGraph},
    node_contract::{
        ActivationRecord, OwnerIdentity, PreparedRealization, RuntimeCustodyQueue,
        RuntimeCustodySupervisor, RuntimeLimits,
    },
};
use crucible_node_format::{
    ContentRef, HashRef, Id, LiveAuthority, NodeBinding, Phase, Position, U64, Validate, canonical,
};
use crucible_node_transport::reference_device::ReferenceDevice;
use crucible_store::content_store::{
    BlobHandle, ContentId, ImmutableBlobBackend, MutableRefBackend, ObjectKind, RefName,
};
use serde::{Deserialize, Serialize};

use super::{NodeObservedBackend, NodeObservedError, StoredWorldActivationPublisher};
use crate::node_scenario::{NodeRunConfiguration, NodeScenario};

/// Selects an actual implementation supported by the local installed catalog.
#[derive(Clone, Debug, Serialize)]
#[serde(tag = "implementation", rename_all = "snake_case", deny_unknown_fields)]
pub enum InstalledNodeKind {
    /// Names a trusted installed ordinary vendor world; configuration grants no authority.
    InstalledVendor {
        /// Selects the installed provider identity.
        provider: Id,
        /// Selects its independently inspected source profile.
        profile: Id,
        /// Binds the full source-installed immutable configuration.
        configuration: ContentRef,
    },
    /// Runs the owned host integer clock with no timers or autonomous work.
    HostClock,
    /// Runs a distinct causal rational counter and original alarm/response inventory.
    HostRateAlarmClock {
        /// Binds checked immutable rate, epoch, counter and fixed drift.
        definition: crucible_engine::node_adapters::RateAlarmClockDefinition,
    },
    /// Runs the separately selected rational clock with retained producer receipts.
    HostRateAlarmClockProducer {
        /// Binds the checked fixed counter and future alarm policy.
        definition: crucible_engine::node_adapters::RateAlarmClockDefinition,
    },
    /// Runs an independently enrolled host assertion program and original state.
    HostSemantics {
        /// Binds immutable compact properties and qualified input projections.
        profile: InstalledHostSemanticProfile,
    },
    /// Selects the fixed parent-zero ARM Linux Root/Clock model and its distinct codec.
    Gem5ArmRoot,
    /// Selects the distinct parent-zero fixed PC Linux Root/Clock model.
    Gem5X86Root,
    /// Runs a separately selected genuine native event-condition control observer.
    HostConditionDebug {
        /// Binds the independently enrolled compact condition and native route.
        profile: InstalledConditionDebugProfile,
    },
    /// Selects separately qualified whole-world original stopped-condition custody.
    HostConditionDebugPreserving {
        /// Binds the independently installed condition program and exact native route.
        profile: InstalledConditionDebugProfile,
    },
    /// Runs the installed closed gem5 model with original live public readiness.
    /// Preservation remains unsupported in this distinct initial edition.
    Gem5Closed {
        /// Selects the independently installed fixed guest and native poll policy.
        isa: InstalledGem5Isa,
    },
    /// Selects the distinct preparation-bearing signed native continuation codec.
    Gem5ClosedPreserving {
        /// Selects the independently installed fixed guest and native poll policy.
        isa: InstalledGem5Isa,
    },
    /// Selects original pending-permission ancestry in the closed public native codec.
    Gem5ClosedEpochPreserving {
        /// Selects the independently installed fixed guest and native poll policy.
        isa: InstalledGem5Isa,
    },
    /// Runs native block or 9p storage with independently enrolled immutable input.
    HostIo {
        /// Binds the native storage codec, immutable input and positive timing.
        profile: InstalledHostIoProfile,
    },
    /// Runs exact Block requests from an independently enrolled finite logical source.
    HostRecordedBlock {
        /// Binds the complete source file, native storage and precise run context.
        profile: InstalledRecordedIngressProfile,
    },
    /// Selects the separate signed recorded Block cursor-preservation codec.
    HostRecordedBlockPreserving {
        /// Binds independently installed original source and immutable Block base.
        profile: InstalledRecordedIngressProfile,
    },
    /// Evaluates the exact independently enrolled finite native request script.
    HostScripted {
        /// Binds the complete source script and its ordinary public consumer.
        profile: InstalledScriptedSourceProfile,
    },
    /// Owns a separately selected opaque delayed packet echo receiver.
    HostPacketReceiver {
        /// Binds native response delivery identity.
        source_node: u32,
        /// Selects the positive fixed response delay in picoseconds.
        latency_ps: U64,
    },
    /// Runs the unchanged independently selected jitter/reorder program.
    HostSeededLink {
        /// Binds original endpoints and the complete immutable RNG/fault program.
        profile: InstalledSeededLinkProfile,
    },
    /// Runs a separately selected recorded native coefficient controller.
    HostControlledFaultLink {
        /// Binds the complete original program and unchanged endpoint/timing scope.
        profile: InstalledControlledFaultProfile,
    },
    /// Runs a distinct independently selected adverse byte fault program.
    HostFaultedLink {
        /// Binds original endpoints and the complete immutable RNG/fault program.
        profile: InstalledFaultedLinkProfile,
    },
    /// Runs a fault-free byte-preserving exact host link between named nodes.
    HostNetLink {
        /// Names the public checksum producer whose output feeds the link.
        producer: Id,
        /// Names the public checksum consumer fed by the link output.
        consumer: Id,
        /// Binds the native frame source identifier without truncation.
        source_node: u32,
        /// Selects positive exact native delivery latency in picoseconds.
        latency_ps: U64,
        /// Selects the positive conservative native latency floor.
        floor_ps: U64,
    },
    /// Runs native checksum windows with a shared byte-preserving public schema.
    ReferenceNativeLinked {
        /// Selects the positive fixed simulation window in picoseconds.
        quantum_ps: U64,
        /// Selects the finite physical host execution budget in nanoseconds.
        host_budget_ns: U64,
        /// Selects a source with no ingress or a causally admitted consumer.
        closed_ingress: bool,
    },
    /// Runs output-only controlled checksum windows with permanently closed ingress.
    ReferenceDevice {
        /// Selects the positive simulated window duration in picoseconds.
        quantum_ps: U64,
        /// Selects the positive physical host budget in nanoseconds.
        host_budget_ns: U64,
    },
}

impl<'de> Deserialize<'de> for InstalledNodeKind {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let wire = InstalledNodeKindWire::deserialize(deserializer)?;
        Ok(match wire {
            InstalledNodeKindWire::InstalledVendor {
                provider,
                profile,
                configuration,
            } => Self::InstalledVendor {
                provider,
                profile,
                configuration,
            },
            InstalledNodeKindWire::HostClock {} => Self::HostClock,
            InstalledNodeKindWire::HostRateAlarmClock { definition } => {
                Self::HostRateAlarmClock { definition }
            }
            InstalledNodeKindWire::HostRateAlarmClockProducer { definition } => {
                Self::HostRateAlarmClockProducer { definition }
            }
            InstalledNodeKindWire::HostSemantics { profile } => Self::HostSemantics { profile },
            InstalledNodeKindWire::Gem5ArmRoot {} => Self::Gem5ArmRoot,
            InstalledNodeKindWire::Gem5X86Root {} => Self::Gem5X86Root,
            InstalledNodeKindWire::HostConditionDebugPreserving { profile } => {
                Self::HostConditionDebugPreserving { profile }
            }
            InstalledNodeKindWire::HostConditionDebug { profile } => {
                Self::HostConditionDebug { profile }
            }
            InstalledNodeKindWire::Gem5Closed { isa } => Self::Gem5Closed { isa },
            InstalledNodeKindWire::Gem5ClosedPreserving { isa } => {
                Self::Gem5ClosedPreserving { isa }
            }
            InstalledNodeKindWire::Gem5ClosedEpochPreserving { isa } => {
                Self::Gem5ClosedEpochPreserving { isa }
            }
            InstalledNodeKindWire::HostIo { profile } => Self::HostIo { profile },
            InstalledNodeKindWire::HostRecordedBlock { profile } => {
                Self::HostRecordedBlock { profile }
            }
            InstalledNodeKindWire::HostRecordedBlockPreserving { profile } => {
                Self::HostRecordedBlockPreserving { profile }
            }
            InstalledNodeKindWire::HostScripted { profile } => Self::HostScripted { profile },
            InstalledNodeKindWire::HostPacketReceiver {
                source_node,
                latency_ps,
            } => Self::HostPacketReceiver {
                source_node,
                latency_ps,
            },
            InstalledNodeKindWire::HostSeededLink { profile } => Self::HostSeededLink { profile },
            InstalledNodeKindWire::HostFaultedLink { profile } => Self::HostFaultedLink { profile },
            InstalledNodeKindWire::HostControlledFaultLink { profile } => {
                Self::HostControlledFaultLink { profile }
            }
            InstalledNodeKindWire::ReferenceDevice {
                quantum_ps,
                host_budget_ns,
            } => Self::ReferenceDevice {
                quantum_ps,
                host_budget_ns,
            },
            InstalledNodeKindWire::ReferenceNativeLinked {
                quantum_ps,
                host_budget_ns,
                closed_ingress,
            } => Self::ReferenceNativeLinked {
                quantum_ps,
                host_budget_ns,
                closed_ingress,
            },
            InstalledNodeKindWire::HostNetLink {
                producer,
                consumer,
                source_node,
                latency_ps,
                floor_ps,
            } => Self::HostNetLink {
                producer,
                consumer,
                source_node,
                latency_ps,
                floor_ps,
            },
        })
    }
}

#[derive(Deserialize)]
#[serde(tag = "implementation", rename_all = "snake_case", deny_unknown_fields)]
enum InstalledNodeKindWire {
    InstalledVendor {
        provider: Id,
        profile: Id,
        configuration: ContentRef,
    },
    /// Runs the owned host integer clock with no timers or autonomous work.
    HostClock {},
    HostRateAlarmClock {
        definition: crucible_engine::node_adapters::RateAlarmClockDefinition,
    },
    HostRateAlarmClockProducer {
        definition: crucible_engine::node_adapters::RateAlarmClockDefinition,
    },
    HostSemantics {
        profile: InstalledHostSemanticProfile,
    },
    Gem5ArmRoot {},
    /// Selects the separate fixed PC root model without ARM or SE fallback.
    Gem5X86Root {},
    HostConditionDebug {
        profile: InstalledConditionDebugProfile,
    },
    HostConditionDebugPreserving {
        profile: InstalledConditionDebugProfile,
    },
    Gem5Closed {
        isa: InstalledGem5Isa,
    },
    Gem5ClosedPreserving {
        isa: InstalledGem5Isa,
    },
    Gem5ClosedEpochPreserving {
        isa: InstalledGem5Isa,
    },
    HostIo {
        profile: InstalledHostIoProfile,
    },
    /// Runs exact Block requests from an independently enrolled finite logical source.
    HostRecordedBlock {
        /// Binds the complete source file, native storage and precise run context.
        profile: InstalledRecordedIngressProfile,
    },
    /// Selects the separate signed recorded Block cursor-preservation codec.
    HostRecordedBlockPreserving {
        /// Binds independently installed original source and immutable Block base.
        profile: InstalledRecordedIngressProfile,
    },
    HostScripted {
        profile: InstalledScriptedSourceProfile,
    },
    /// Owns a separately selected opaque delayed packet echo receiver.
    HostPacketReceiver {
        /// Binds native response delivery identity.
        source_node: u32,
        /// Selects the positive fixed response delay in picoseconds.
        latency_ps: U64,
    },
    /// Runs the unchanged independently selected jitter/reorder program.
    HostSeededLink {
        /// Binds original endpoints and the complete immutable RNG/fault program.
        profile: InstalledSeededLinkProfile,
    },
    /// Runs a separately selected recorded native coefficient controller.
    HostControlledFaultLink {
        /// Binds the complete original program and unchanged endpoint/timing scope.
        profile: InstalledControlledFaultProfile,
    },
    /// Runs a distinct independently selected adverse byte fault program.
    HostFaultedLink {
        /// Binds original endpoints and the complete immutable RNG/fault program.
        profile: InstalledFaultedLinkProfile,
    },
    /// Runs a fault-free byte-preserving exact host link between named nodes.
    HostNetLink {
        /// Names the public checksum producer whose output feeds the link.
        producer: Id,
        /// Names the public checksum consumer fed by the link output.
        consumer: Id,
        /// Binds the native frame source identifier without truncation.
        source_node: u32,
        /// Selects positive exact native delivery latency in picoseconds.
        latency_ps: U64,
        /// Selects the positive conservative native latency floor.
        floor_ps: U64,
    },
    /// Runs native checksum windows with a shared byte-preserving public schema.
    ReferenceNativeLinked {
        /// Selects the positive fixed simulation window in picoseconds.
        quantum_ps: U64,
        /// Selects the finite physical host execution budget in nanoseconds.
        host_budget_ns: U64,
        /// Selects a source with no ingress or a causally admitted consumer.
        closed_ingress: bool,
    },
    /// Runs output-only controlled checksum windows with permanently closed ingress.
    ReferenceDevice {
        /// Selects the positive simulated window duration in picoseconds.
        quantum_ps: U64,
        /// Selects the positive physical host budget in nanoseconds.
        host_budget_ns: U64,
    },
}

/// Associates one semantic node and indivisible owner with an installed profile.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InstalledNodeSelection {
    /// Names the public logical node.
    pub node: Id,
    /// Names its complete execution and capture owner.
    pub owner: Id,
    /// Selects one actual implemented profile and its bounded timing parameters.
    pub kind: InstalledNodeKind,
}

/// Owns one genuinely inactive installed world and its authenticated definition.
///
/// Preparation alone grants no RUN or reconstruction authority. The consumer
/// must retain its reserved retirement custody and use the common all-owner
/// readiness/activation barrier before any modeled execution.
pub struct InstalledPreparedWorld {
    /// Retains the exact immutable authored definition authenticated by admission.
    pub scenario: NodeScenario,
    /// Seals the complete measured native owner and implementation inventory.
    pub graph: AdmittedGraph,
    /// Owns all original inactive native resources and their retirement slot.
    pub realization: PreparedRealization,
}

#[derive(Default)]
struct PreparationSource<'a> {
    activation: Option<&'a crucible_engine::node_contract::SavedRuntimeActivation>,
    preserved_cut: Option<Position>,
}

// Keeps original preservation lineage and its optional installed semantic
// selection together; neither may be substituted during native enrollment.
struct SelectedPreparation<'a> {
    source: PreparationSource<'a>,
    label: Option<&'a clock_label::ClockLabelPolicy>,
    capabilities: Option<&'a capabilities::ResolvedCapabilityWorld>,
    normal_clock: Option<&'a normal_clock::InstalledNormalClockProfile>,
}

/// Owns trusted local installation measurements and finite world retirement slots.
///
/// This catalog is host configuration, never a provider-supplied claim. The
/// expected device identity must come from the operator's qualified source-built
/// package inventory. The host implementation is measured from `/proc/self/exe`.
/// The catalog regenerates every selected closed profile from installed code and
/// accepts only its exact immutable world, rather than arbitrary proof strings.
pub struct InstalledNodeCatalog {
    host_executable: PathBuf,
    host_identity: ContentRef,
    device_executable: PathBuf,
    device_identity: ContentRef,
    socket_parent: PathBuf,
    control_timeout: Duration,
    custody: RuntimeCustodyQueue,
    runtime_wake: Option<crucible_engine::node_contract::RuntimeCustodyWakeReader>,
    artifacts: BTreeMap<String, InstalledIoArtifact>,
    behavioral_acceptance: Option<acceptance::InstalledBehavioralAcceptance>,
    vendor_providers: Option<crucible_engine::node_contract::InstalledProviderRegistry>,
    vendor_worlds: BTreeMap<Id, vendor_selection::InstalledVendorWorld>,
    mixed_vendor_worlds: BTreeMap<Vec<u8>, Rc<mixed_vendor_selection::InstalledMixedVendorWorld>>,
    original_lineage: transcript::original_lineage::selection::Installation,
    complete_scene: Option<crate::node_qualification::InstalledCompleteScene>,
}

impl InstalledNodeCatalog {
    /// Opens a measured source-qualified device installation on the owner thread.
    ///
    /// # Errors
    /// Refuses a relative executable/socket path, absent or changed executable,
    /// zero/excessive control timeout, malformed expected identity, or unavailable
    /// finite retirement capacity. Expected hashes are installed host policy.
    pub fn new(
        device_executable: PathBuf,
        expected_device: ContentRef,
        socket_parent: PathBuf,
        control_timeout: Duration,
        maximum_worlds: usize,
    ) -> Result<Self, NodeObservedError> {
        Self::new_with_runtime_wake(
            device_executable,
            expected_device,
            socket_parent,
            control_timeout,
            maximum_worlds,
            false,
        )
    }

    /// Opens the same catalog with its concrete retained runtime wake owner.
    ///
    /// This selects the existing Core bounded-wake queue at actual construction.
    /// Source owning observations can then account for its real retained waker;
    /// no pointer classification or generic opaque-waker exemption is used.
    /// Native/model/source qualification and all admission gates stay separate.
    ///
    /// # Errors
    /// Refuses ordinary catalog validation, descriptor resources or wake setup.
    pub fn new_with_bounded_runtime_wake(
        device_executable: PathBuf,
        expected_device: ContentRef,
        socket_parent: PathBuf,
        control_timeout: Duration,
        maximum_worlds: usize,
    ) -> Result<Self, NodeObservedError> {
        Self::new_with_runtime_wake(
            device_executable,
            expected_device,
            socket_parent,
            control_timeout,
            maximum_worlds,
            true,
        )
    }

    fn new_with_runtime_wake(
        device_executable: PathBuf,
        expected_device: ContentRef,
        socket_parent: PathBuf,
        control_timeout: Duration,
        maximum_worlds: usize,
        bounded_wake: bool,
    ) -> Result<Self, NodeObservedError> {
        if !device_executable.is_absolute()
            || !socket_parent.is_absolute()
            || control_timeout.is_zero()
            || control_timeout > Duration::from_secs(60)
        {
            return Err(refused(
                "invalid installed provider paths or control timeout",
            ));
        }
        expected_device.validate()?;
        let device_identity = measure_executable(&device_executable)?;
        if device_identity != expected_device {
            return Err(refused(
                "installed device differs from qualified package identity",
            ));
        }
        let host_executable = PathBuf::from("/proc/self/exe");
        let host_identity = measure_executable(&host_executable)?;
        let (custody, runtime_wake) = if bounded_wake {
            let (queue, reader) =
                RuntimeCustodyQueue::new_with_bounded_wake(maximum_worlds).map_err(native)?;
            (queue, Some(reader))
        } else {
            (
                RuntimeCustodyQueue::new(maximum_worlds).map_err(native)?,
                None,
            )
        };
        Ok(Self {
            host_executable,
            host_identity,
            device_executable,
            device_identity,
            socket_parent,
            control_timeout,
            custody,
            runtime_wake,
            artifacts: BTreeMap::new(),
            behavioral_acceptance: None,
            vendor_providers: None,
            vendor_worlds: BTreeMap::new(),
            mixed_vendor_worlds: BTreeMap::new(),
            original_lineage: transcript::original_lineage::selection::Installation::new(),
            complete_scene: None,
        })
    }

    /// Enrolls independently qualified immutable host artifacts before admission.
    ///
    /// Paths are private operator configuration. Portable node selections only
    /// refer to their content identities and cannot install or replace artifacts.
    /// Path entries are opened without following their final symlink and measured
    /// before any registry entry changes. Explicit archive-only entries enroll
    /// expected identities for signed recovery; they cannot construct fresh
    /// native resources. Recovery independently authenticates complete archive
    /// bytes against these expected identities before native allocation.
    ///
    /// # Errors
    /// Refuses changed files, malformed references, reused identities with another
    /// source, any artifact exceeding 4 MiB, more than 64 artifacts, or an
    /// aggregate exceeding 16 MiB. A refusal leaves the installed registry
    /// unchanged. Missing path entries never become archive-only enrollment.
    pub fn install_artifacts(
        &mut self,
        artifacts: Vec<InstalledIoArtifact>,
    ) -> Result<(), NodeObservedError> {
        if artifacts.len() > 64 {
            return Err(refused(
                "installed artifact enrollment exceeds its finite count ceiling",
            ));
        }
        let mut installed = self.artifacts.clone();
        for artifact in artifacts {
            artifact.expected.validate()?;
            if artifact.expected.length.get() > io::MAXIMUM_IO_ARTIFACT_BYTES as u64 {
                return Err(refused(
                    "installed artifact exceeds its finite byte ceiling",
                ));
            }
            let key = artifact.expected.hash.digest.clone();
            if let Some(original) = installed.get(&key) {
                if original.expected != artifact.expected || original.source != artifact.source {
                    return Err(refused("installed artifact identity cannot be replaced"));
                }
            } else {
                installed.insert(key, artifact);
            }
        }
        let total = installed
            .values()
            .try_fold(0u64, |total, artifact| {
                total.checked_add(artifact.expected.length.get())
            })
            .ok_or_else(|| refused("installed immutable artifact byte count overflowed"))?;
        if installed.len() > 64 || total > 16 * 1024 * 1024 {
            return Err(refused(
                "installed immutable artifact registry exceeds its finite ceiling",
            ));
        }
        for artifact in installed.values() {
            if matches!(artifact.source, InstalledIoArtifactSource::Path(_)) {
                io::read_artifact(artifact)?;
            }
        }
        self.artifacts = installed;
        Ok(())
    }

    /// Resolves selected actual implementations into a complete immutable scenario.
    ///
    /// Installed profiles include clocks, checksum windows, byte-preserving links
    /// and finite scripted requests feeding native storage. Guest CPUs and
    /// external ingress require independently qualified catalog entries.
    ///
    /// # Errors
    /// Refuses duplicate/oversized owner rosters or invalid profile parameters.
    pub fn scenario(
        &self,
        selections: &[InstalledNodeSelection],
    ) -> Result<NodeScenario, NodeObservedError> {
        if let Some(original) = mixed_vendor_selection::selected(self, selections)? {
            return mixed_vendor_selection::scenario(&original);
        }
        if vendor_selection::is_selected(selections) {
            return vendor_selection::scenario(self, selections);
        }
        if selections
            .iter()
            .any(|selection| matches!(selection.kind, InstalledNodeKind::Gem5X86Root))
        {
            return x86_root::public_catalog::scenario(self, selections);
        }
        if selections
            .iter()
            .any(|selection| matches!(selection.kind, InstalledNodeKind::Gem5ArmRoot))
        {
            return arm_root::public_catalog::scenario(self, selections);
        }
        if selections.iter().any(|selection| {
            matches!(
                selection.kind,
                InstalledNodeKind::Gem5Closed { .. }
                    | InstalledNodeKind::Gem5ClosedPreserving { .. }
                    | InstalledNodeKind::Gem5ClosedEpochPreserving { .. }
            )
        }) {
            return native_state::public_catalog::scenario(self, selections);
        }
        let original = profile::build_world(
            selections,
            &self.host_identity,
            &self.device_identity,
            &self.artifacts,
        )?
        .scenario;
        self.project_ordinary_accepted_world(selections, original, &self.artifacts)
            .map(|(scenario, _)| scenario)
    }

    /// Prepares actual inactive resources and seals their complete mixed graph.
    ///
    /// One complete retirement slot is reserved before any native child exists.
    /// All implementation identities and native owners are measured and enrolled
    /// before graph sealing. Native RUN remains disabled until the observed worker
    /// reserves the execution nonce and durably publishes the all-owner barrier.
    ///
    /// # Errors
    /// Refuses changed authored bytes, unavailable custody, stale installations,
    /// native startup, complete graph qualification, or activation-storage setup.
    pub fn prepare(
        &mut self,
        selections: &[InstalledNodeSelection],
        scenario: NodeScenario,
        configuration: NodeRunConfiguration,
        execution: ExecutionId,
        blobs: Arc<dyn ImmutableBlobBackend>,
        refs: Arc<dyn MutableRefBackend>,
    ) -> Result<NodeObservedBackend, NodeObservedError> {
        let prepared = self.prepare_world(selections, scenario, execution)?;
        self.finish_observed(prepared, selections, configuration, execution, blobs, refs)
    }

    fn finish_observed(
        &self,
        prepared_world: InstalledPreparedWorld,
        selections: &[InstalledNodeSelection],
        configuration: NodeRunConfiguration,
        execution: ExecutionId,
        blobs: Arc<dyn ImmutableBlobBackend>,
        refs: Arc<dyn MutableRefBackend>,
    ) -> Result<NodeObservedBackend, NodeObservedError> {
        let InstalledPreparedWorld {
            scenario,
            graph,
            realization: prepared,
        } = prepared_world;
        let context = super::backend::input_context_bytes(&scenario, &configuration)?;
        let inputs = ContentId::for_bytes(ObjectKind::Trace, 1, &context);
        let receipt = blobs.put_if_absent(inputs, &BlobHandle::from_bytes(context))?;
        if !receipt.is_durable() {
            return Err(refused("input context is not durably retained"));
        }
        let reference = RefName::new(format!(
            "node-world-activations/{}",
            execution_text(execution)
        ))?;
        let stored = StoredWorldActivationPublisher::new(Arc::clone(&blobs), refs, reference)?;
        let publisher: Box<dyn crucible_engine::node_contract::ActivationPublisher> =
            if selections.iter().any(|selection| {
                matches!(
                    selection.kind,
                    InstalledNodeKind::Gem5Closed { .. }
                        | InstalledNodeKind::Gem5ClosedPreserving { .. }
                        | InstalledNodeKind::Gem5ClosedEpochPreserving { .. }
                )
            }) {
                native_state::public_catalog::publisher(stored)?
            } else if selections
                .iter()
                .any(|selection| matches!(selection.kind, InstalledNodeKind::Gem5X86Root))
            {
                x86_root::public_catalog::publisher(stored)?
            } else if selections
                .iter()
                .any(|selection| matches!(selection.kind, InstalledNodeKind::Gem5ArmRoot))
            {
                arm_root::public_catalog::publisher(stored)?
            } else if vendor_selection::is_selected(selections) {
                if mixed_vendor_selection::selected(self, selections)?.is_some() {
                    Box::new(stored)
                } else {
                    vendor_selection::publisher(self, selections, stored)?
                }
            } else {
                Box::new(stored)
            };
        NodeObservedBackend::from_prepared(
            InstalledPreparedWorld {
                scenario,
                graph,
                realization: prepared,
            },
            configuration,
            publisher,
            blobs,
            inputs,
            execution,
        )
    }

    /// Allocates actual inactive resources and seals their complete native graph.
    ///
    /// This preparation boundary is reusable by observed execution and installed
    /// host-state bridges. It performs no activation, grants no observed nonce
    /// permit, and accepts no imported native capture as authority. Original
    /// native custody always owns its pre-reserved complete retirement slot.
    ///
    /// # Errors
    /// Refuses mismatched authored profiles, changed installed artifacts, native
    /// allocation or enrollment failures, incomplete graph qualification, and
    /// unavailable finite retirement capacity.
    pub fn prepare_world(
        &mut self,
        selections: &[InstalledNodeSelection],
        scenario: NodeScenario,
        execution: ExecutionId,
    ) -> Result<InstalledPreparedWorld, NodeObservedError> {
        if let Some(original) = mixed_vendor_selection::selected(self, selections)? {
            return mixed_vendor_selection::prepare(self, &original, scenario, execution);
        }
        if vendor_selection::is_selected(selections) {
            return vendor_selection::prepare(self, selections, scenario, execution);
        }
        if selections
            .iter()
            .any(|selection| matches!(selection.kind, InstalledNodeKind::Gem5X86Root))
        {
            self.require_behavioral_host_scope()?;
            return Ok(x86_root::public_catalog::prepare_native(
                self, selections, scenario, execution,
            )?
            .world);
        }
        if selections
            .iter()
            .any(|selection| matches!(selection.kind, InstalledNodeKind::Gem5ArmRoot))
        {
            self.require_behavioral_host_scope()?;
            return Ok(arm_root::public_catalog::prepare_native(
                self, selections, scenario, execution,
            )?
            .world);
        }
        if selections.iter().any(|selection| {
            matches!(
                selection.kind,
                InstalledNodeKind::Gem5Closed { .. }
                    | InstalledNodeKind::Gem5ClosedPreserving { .. }
                    | InstalledNodeKind::Gem5ClosedEpochPreserving { .. }
            )
        }) {
            if !native_state::host_group::selection::selected(selections) {
                self.require_behavioral_host_scope()?;
            }
            return native_state::public_catalog::prepare(self, selections, scenario, execution);
        }
        let artifacts = self.artifacts.clone();
        Ok(self
            .prepare_world_with_source(
                selections,
                scenario,
                execution,
                PreparationSource::default(),
                &artifacts,
                None,
            )?
            .0)
    }

    /// Prepares the distinct preserving native selection with its installed signer.
    ///
    /// The returned inactive realization still requires genuine complete native
    /// readiness and durable public activation before execution or capture. The
    /// policy cannot convert public data into native seals or allocate a cold
    /// owner without an independently authenticated source reservation.
    ///
    /// # Errors
    /// Refuses live-only selections, changed authored worlds or installed assets,
    /// unavailable finite custody, native startup or actual closure qualification.
    pub fn prepare_native_world(
        &mut self,
        selections: &[InstalledNodeSelection],
        scenario: NodeScenario,
        execution: ExecutionId,
    ) -> Result<InstalledPreparedNativeWorld, NodeObservedError> {
        self.require_behavioral_host_scope()?;
        native_state::public_catalog::prepare_native(self, selections, scenario, execution)
    }

    /// Prepares the distinct fixed ARM Root world with original native custody.
    ///
    /// The complete public barrier still requires actual native Ready and current
    /// opaque qualification. The returned signer retains only installed policy.
    ///
    /// # Errors
    /// Refuses a foreign roster or authored world, changed installed artifacts,
    /// unavailable finite custody, startup or current native audit failure.
    pub fn prepare_root_native_world(
        &mut self,
        selections: &[InstalledNodeSelection],
        scenario: NodeScenario,
        execution: ExecutionId,
    ) -> Result<InstalledPreparedRootWorld, NodeObservedError> {
        self.require_behavioral_host_scope()?;
        arm_root::public_catalog::prepare_native(self, selections, scenario, execution)
    }

    /// Reserves an ordinary Root restore plan from its complete authenticated archive.
    ///
    /// The returned plan owns inactive source backing and fresh owner identities.
    /// Its driver must independently reconstruct, recapture and audit each native
    /// peer before the complete publisher can activate the world.
    ///
    /// # Errors
    /// Refuses a foreign selection/source, changed installed assets, unsupported
    /// native codecs, exhausted custody, or mismatched original preparation.
    pub fn prepare_root_native_restore(
        &mut self,
        selections: &[InstalledNodeSelection],
        archive: crucible_engine::node_state::NativeArchiveRecord,
    ) -> Result<InstalledRootRestore, NodeObservedError> {
        self.require_behavioral_host_scope()?;
        arm_root::public_catalog::prepare_restore(self, selections, archive)
    }

    /// Prepares the distinct fixed x86 Linux Root world beneath original custody.
    ///
    /// Source-installed constructor bytes supply no native readiness. Preparation
    /// requires the actual parked child, full current image audit and complete
    /// common owner barrier; only the declared no-ingress Serial facet is selected.
    ///
    /// # Errors
    /// Refuses foreign selections, absent source binding, unavailable finite
    /// custody, changed installed bytes or original native/current audit failures.
    pub fn prepare_x86_root_native_world(
        &mut self,
        selections: &[InstalledNodeSelection],
        scenario: NodeScenario,
        execution: ExecutionId,
    ) -> Result<InstalledPreparedX86RootWorld, NodeObservedError> {
        self.require_behavioral_host_scope()?;
        x86_root::public_catalog::prepare_native(self, selections, scenario, execution)
    }

    /// Reserves x86 Root restoration from its separately authenticated source codec.
    ///
    /// Historical Ready and image metadata remain inert. Each fresh owner must
    /// reconstruct, recapture and audit its actual current closure before the
    /// complete world can publish or receive execution permission.
    ///
    /// # Errors
    /// Refuses another model/codec, changed source, stale fencing, unavailable
    /// original custody or incomplete signed public preparation ancestry.
    pub fn prepare_x86_root_native_restore(
        &mut self,
        selections: &[InstalledNodeSelection],
        archive: crucible_engine::node_state::NativeArchiveRecord,
    ) -> Result<InstalledX86RootRestore, NodeObservedError> {
        self.require_behavioral_host_scope()?;
        x86_root::public_catalog::prepare_restore(self, selections, archive)
    }

    /// Seals fresh installed host authority for an authenticated complete source.
    ///
    /// This method measures the original installed profiles again and enrolls
    /// actual inactive native models before graph admission. It derives fresh
    /// incarnations from the new execution nonce and advances each original
    /// owner/world generation. It grants no restoration or activation token.
    /// Temporary enrollment resources remain in the owning retirement queue.
    ///
    /// # Errors
    /// Refuses unsupported selections, foreign signed source compatibility, reused
    /// incarnations, generation overflow, changed installations or admission.
    pub fn prepare_host_restore_graph(
        &mut self,
        selections: &[InstalledNodeSelection],
        scenario: &NodeScenario,
        record: &crucible_engine::node_state::HostArchiveRecord,
        execution: ExecutionId,
    ) -> Result<(AdmittedGraph, ActivationRecord), NodeObservedError> {
        if selections.iter().any(|selection| {
            !matches!(
                selection.kind,
                InstalledNodeKind::HostClock
                    | InstalledNodeKind::HostRateAlarmClock { .. }
                    | InstalledNodeKind::HostRateAlarmClockProducer { .. }
                    | InstalledNodeKind::HostIo { .. }
                    | InstalledNodeKind::HostRecordedBlockPreserving { .. }
                    | InstalledNodeKind::HostScripted { .. }
                    | InstalledNodeKind::HostSeededLink { .. }
                    | InstalledNodeKind::HostFaultedLink { .. }
                    | InstalledNodeKind::HostControlledFaultLink { .. }
                    | InstalledNodeKind::HostPacketReceiver { .. }
                    | InstalledNodeKind::HostSemantics { .. }
                    | InstalledNodeKind::HostConditionDebugPreserving { .. }
            )
        }) || record.manifest().world_binding_hash != scenario.world.identity()?
            || record.manifest().scenario_ref != scenario.world.scenario_ref
        {
            return Err(refused(
                "signed source is not the exact supported installed host world",
            ));
        }
        let source = record.source_activation(4 * 1024 * 1024).map_err(native)?;
        let artifacts = archive_artifacts::materialize(&self.artifacts, selections, record)?;
        let (prepared, target) = self.prepare_world_with_source(
            selections,
            scenario.clone(),
            execution,
            PreparationSource {
                activation: Some(&source),
                preserved_cut: Some(record.manifest().cut),
            },
            artifacts.registry(),
            None,
        )?;
        drop(prepared.realization);
        Ok((prepared.graph, target))
    }

    fn prepare_world_with_source(
        &mut self,
        selections: &[InstalledNodeSelection],
        scenario: NodeScenario,
        execution: ExecutionId,
        source: PreparationSource<'_>,
        artifacts: &BTreeMap<String, InstalledIoArtifact>,
        recorder: Option<&mut transcript::ReferenceRecorder<'_>>,
    ) -> Result<(InstalledPreparedWorld, ActivationRecord), NodeObservedError> {
        self.prepare_world_with_selected_label(
            selections,
            scenario,
            execution,
            artifacts,
            recorder,
            SelectedPreparation {
                source,
                label: None,
                capabilities: None,
                normal_clock: None,
            },
        )
    }

    fn prepare_world_with_selected_label(
        &mut self,
        selections: &[InstalledNodeSelection],
        scenario: NodeScenario,
        execution: ExecutionId,
        artifacts: &BTreeMap<String, InstalledIoArtifact>,
        mut recorder: Option<&mut transcript::ReferenceRecorder<'_>>,
        preparation: SelectedPreparation<'_>,
    ) -> Result<(InstalledPreparedWorld, ActivationRecord), NodeObservedError> {
        let SelectedPreparation {
            source,
            label,
            capabilities,
            normal_clock,
        } = preparation;
        if label.is_some() && self.behavioral_acceptance.is_some() {
            return Err(refused(
                "behavioral and metadata-label selection require a separately qualified composed policy",
            ));
        }
        let mut resolved = profile::build_world(
            selections,
            &self.host_identity,
            &self.device_identity,
            artifacts,
        )?;
        if let Some(clock) = normal_clock {
            if label.is_some()
                || capabilities.is_some()
                || resolved.scenario.canonical_bytes()? != clock.baseline.canonical_bytes()?
            {
                return Err(refused(
                    "normal Clock source has foreign or composed preparation scope",
                ));
            }
            resolved.scenario = normal_clock::profile::regenerate_selected(&resolved.scenario)?;
            if source.activation.is_some() != source.preserved_cut.is_some() {
                return Err(refused("normal Clock restore source/cut scope differs"));
            }
            if let Some(original) = source.activation
                && original.world_binding_hash != resolved.scenario.world.identity()?
            {
                return Err(refused("normal Clock restore source world differs"));
            }
        }
        if let Some(label) = label {
            if resolved.scenario.canonical_bytes()? != label.base.canonical_bytes()? {
                return Err(refused(
                    "Clock label differs from actual installed baseline",
                ));
            }
            resolved.scenario = label.labeled.clone();
        }
        if let Some(capabilities) = capabilities {
            if label.is_some() {
                return Err(refused(
                    "capability and label selection require a separately qualified composed candidate",
                ));
            }
            capabilities::policy::matches(
                selections,
                &resolved.scenario,
                &capabilities.requirements,
            )?;
            resolved.scenario = capabilities::bind_original_requirements(
                resolved.scenario,
                &capabilities.requirements,
                &capabilities.requirements_bytes,
            )?;
        }
        let (accepted, public_clock_nodes) =
            self.project_ordinary_accepted_world(selections, resolved.scenario, artifacts)?;
        resolved.scenario = accepted;
        if scenario.canonical_bytes()? != resolved.scenario.canonical_bytes()? {
            return Err(refused(
                "authored world differs from complete installed profile selection",
            ));
        }
        if measure_executable(&self.host_executable)? != self.host_identity
            || measure_executable(&self.device_executable)? != self.device_identity
        {
            return Err(refused(
                "installed implementation changed before native preparation",
            ));
        }
        self.preflight_behavioral_acceptance(selections, &scenario)?;
        let session = Id::new(format!("session/{}", execution_text(execution)))?;
        let activation_id = Id::new(format!("activation/{}", execution_text(execution)))?;
        let host_receipt_bytes = canonical::canonical_json(&serde_json::json!({
            "format":"crucible.local-node-enrollment","version":1,"execution":execution_text(execution),
            "host":self.host_identity,"device":self.device_identity}))?;
        let host_receipt = canonical::content_ref(&host_receipt_bytes, "application/json")?;
        let mut bindings = Vec::new();
        let mut owners = Vec::new();
        for selected in &scenario.compatibility {
            let incarnation = Id::new(format!(
                "incarnation/{}",
                canonical::hash(
                    "crucible.local-owner-incarnation.v1",
                    format!(
                        "{}:{}",
                        execution_text(execution),
                        selected.execution_owner.id
                    )
                    .as_bytes()
                )?
                .digest
            ))?;
            let generation = match source.activation {
                Some(source) => {
                    let original = source
                        .owners
                        .iter()
                        .find(|owner| owner.owner == selected.execution_owner.id)
                        .ok_or_else(|| {
                            refused("signed source owner roster differs from installed graph")
                        })?;
                    if incarnation == original.incarnation {
                        return Err(refused(
                            "restore execution reuses original owner incarnation",
                        ));
                    }
                    original.generation.checked_add(U64::new(1))?
                }
                None => U64::new(1),
            };
            owners.push(OwnerIdentity {
                owner: selected.execution_owner.id.clone(),
                incarnation: incarnation.clone(),
                generation,
            });
            bindings.push(NodeBinding {
                compatibility: selected.clone(),
                authority: LiveAuthority {
                    schema_version: 1,
                    session_id: session.clone(),
                    incarnation_id: incarnation,
                    realization_id: session.clone(),
                    activation_id: None,
                    world_generation: U64::new(0),
                    owner_generation: generation,
                    input_epoch: session.clone(),
                    host_receipt: host_receipt.clone(),
                    extensions: Default::default(),
                },
                extensions: Default::default(),
            });
        }
        owners.sort();
        let target = ActivationRecord {
            generation: match source.activation {
                Some(source) => source.generation.checked_add(U64::new(1))?,
                None => U64::new(1),
            },
            activation_id,
            world_binding_hash: scenario.world.identity()?,
            owners,
            boundary: source.preserved_cut.unwrap_or(Position::new(
                U64::new(0),
                U64::new(0),
                Phase::BoundaryControl,
            )),
        };
        let limits = RuntimeLimits {
            maximum_nodes: selections.len(),
            maximum_owners: selections.len(),
            maximum_operations: 65_536,
            maximum_retained_outputs: 65_536,
        };
        let slot = self
            .custody
            .reserve_world(&target, limits)
            .map_err(native)?;
        let (mut models, mut nodes) =
            prepared_models::PreparedModelRoster::new(selections, &scenario, artifacts)?
                .into_parts();
        let mut devices = BTreeMap::new();
        for (selection, binding) in selections.iter().zip(&bindings) {
            if matches!(
                selection.kind,
                InstalledNodeKind::ReferenceDevice { .. }
                    | InstalledNodeKind::ReferenceNativeLinked { .. }
            ) {
                let child = ReferenceDevice::spawn(
                    &self.device_executable,
                    &self.socket_parent,
                    selection.owner.clone(),
                    binding.authority.incarnation_id.clone(),
                    binding.authority.owner_generation,
                    self.control_timeout,
                )
                .map_err(native)?;
                devices.insert(selection.node.clone(), child);
            }
        }
        let mut content = scenario
            .content
            .iter()
            .map(|entry| {
                (
                    entry.reference.hash.digest.clone(),
                    (entry.reference.clone(), entry.bytes.clone()),
                )
            })
            .collect::<BTreeMap<_, _>>();
        content.insert(
            host_receipt.hash.digest.clone(),
            (host_receipt, host_receipt_bytes),
        );
        let mut installed = BTreeMap::new();
        installed.insert(
            self.host_identity.hash.digest.clone(),
            (self.host_identity.clone(), self.host_executable.clone()),
        );
        installed.insert(
            self.device_identity.hash.digest.clone(),
            (self.device_identity.clone(), self.device_executable.clone()),
        );
        let evidence = trust::InstalledEvidence::new(
            &scenario, &bindings, &devices, &models, content, installed,
        )?;
        let admission_limits = AdmissionLimits {
            maximum_content_bytes: 512 * 1024 * 1024,
            maximum_total_content_bytes: 2 * 1024 * 1024 * 1024,
            ..AdmissionLimits::default()
        };
        let selected_policy = self.behavioral_acceptance.as_ref().map(|installed| {
            acceptance::SourceBindingPolicy::new(installed.policy.as_ref(), &scenario)
        });
        let behavioral = self
            .behavioral_acceptance
            .as_ref()
            .zip(selected_policy.as_ref())
            .map(|(installed, selected)| {
                crate::node_qualification::BehavioralAdmissionEvidence::new(
                    &evidence,
                    selected,
                    installed.limits,
                )
            });
        let graph_evidence: &dyn crucible_engine::node_admission::AdmissionEvidence =
            match &behavioral {
                Some(behavioral) => behavioral,
                None => &evidence,
            };
        let graph = if let Some(label) = label {
            let profile = self.clock_label_profile()?;
            if label.labeled.canonical_bytes()? != profile.labeled.canonical_bytes()? {
                return Err(refused("installed Clock label changed before admission"));
            }
            let registry = profile.registry()?;
            scenario.admit(
                &bindings,
                &clock_label::LabelAdmission {
                    original: &evidence,
                    registry: &registry,
                },
                admission_limits,
            )?
        } else if let Some(capabilities) = capabilities {
            scenario.admit(
                &bindings,
                &capabilities::admission::CapabilityAdmission {
                    original: graph_evidence,
                    resolved: capabilities,
                },
                admission_limits,
            )?
        } else {
            scenario.admit(&bindings, graph_evidence, admission_limits)?
        };
        for selection in selections {
            match &selection.kind {
                InstalledNodeKind::InstalledVendor { .. } => {
                    return Err(refused(
                        "installed vendor custody cannot become a host model",
                    ));
                }
                InstalledNodeKind::Gem5ArmRoot
                | InstalledNodeKind::Gem5X86Root
                | InstalledNodeKind::Gem5Closed { .. }
                | InstalledNodeKind::Gem5ClosedPreserving { .. }
                | InstalledNodeKind::Gem5ClosedEpochPreserving { .. } => {
                    return Err(refused(
                        "closed gem5 native custody cannot become a host model",
                    ));
                }
                InstalledNodeKind::HostRecordedBlock { profile }
                | InstalledNodeKind::HostRecordedBlockPreserving { profile } => {
                    let model = models.remove(&selection.node).ok_or_else(|| {
                        refused("recorded Block original native custody disappeared")
                    })?;
                    let definition = recorded_ingress::from_scenario(&scenario, &selection.node)?;
                    recorded_ingress::check_configuration(&profile.configuration, &definition)?;
                    let actual = HostModelNode::new(
                        &graph,
                        &selection.node,
                        model,
                        &evidence,
                        HostModelResources::default(),
                    )
                    .map_err(native)?;
                    let actual = if matches!(
                        &selection.kind,
                        InstalledNodeKind::HostRecordedBlockPreserving { .. }
                    ) {
                        actual.with_preservable_recorded_ingress(&graph, definition, &evidence)
                    } else {
                        actual.with_recorded_ingress(&graph, definition, &evidence)
                    }
                    .map_err(native)?;
                    nodes.push(Box::new(actual));
                }
                InstalledNodeKind::HostClock
                | InstalledNodeKind::HostRateAlarmClock { .. }
                | InstalledNodeKind::HostRateAlarmClockProducer { .. }
                | InstalledNodeKind::HostSemantics { .. }
                | InstalledNodeKind::HostConditionDebug { .. }
                | InstalledNodeKind::HostConditionDebugPreserving { .. }
                | InstalledNodeKind::HostNetLink { .. }
                | InstalledNodeKind::HostIo { .. }
                | InstalledNodeKind::HostScripted { .. }
                | InstalledNodeKind::HostSeededLink { .. }
                | InstalledNodeKind::HostFaultedLink { .. }
                | InstalledNodeKind::HostControlledFaultLink { .. }
                | InstalledNodeKind::HostPacketReceiver { .. } => {
                    let model = models
                        .remove(&selection.node)
                        .ok_or_else(|| refused("enrolled host model custody disappeared"))?;
                    let actual = HostModelNode::new(
                        &graph,
                        &selection.node,
                        model,
                        &evidence,
                        HostModelResources::default(),
                    )
                    .map_err(native)?;
                    let mut actual = actual;
                    if normal_clock.is_some() || public_clock_nodes.contains(&selection.node) {
                        actual
                            .qualify_public_preserving_initial_clock(&graph, &evidence)
                            .map_err(native)?;
                    }
                    let actual = if selections.iter().any(|selected| {
                        matches!(
                            selected.kind,
                            InstalledNodeKind::HostConditionDebugPreserving { .. }
                        )
                    }) {
                        actual
                            .with_preservable_condition(&evidence)
                            .map_err(native)?
                    } else {
                        actual
                    };
                    nodes.push(Box::new(actual));
                }
                InstalledNodeKind::ReferenceDevice { .. }
                | InstalledNodeKind::ReferenceNativeLinked { .. } => {
                    let child = devices
                        .remove(&selection.node)
                        .ok_or_else(|| refused("enrolled child custody disappeared"))?;
                    nodes.push(Box::new(
                        ReferenceDeviceNode::from_prepared(
                            &graph,
                            &selection.node,
                            child,
                            &evidence,
                            limits.maximum_operations,
                        )
                        .map_err(native)?,
                    ));
                }
            }
        }
        if let Some(recorder) = recorder.as_mut() {
            let mut wrapped = Vec::new();
            if let Err(error) = wrapped.try_reserve_exact(nodes.len()) {
                drop(PreparedRealization::new(nodes, target, limits, slot));
                return Err(native(error));
            }
            let mut remaining = nodes.into_iter();
            while let Some(node) = remaining.next() {
                match recorder.wrap(&graph, &target, node, &evidence) {
                    Ok(node) => wrapped.push(node),
                    Err(failure) => {
                        wrapped.push(failure.node);
                        wrapped.extend(remaining);
                        // Construction refusal transfers every native handle,
                        // including earlier wrappers, to the original reserved
                        // world slot. No standalone drop loses its roster.
                        drop(PreparedRealization::new(wrapped, target, limits, slot));
                        return Err(failure.error);
                    }
                }
            }
            nodes = wrapped;
        }
        let prepared = PreparedRealization::new(nodes, target.clone(), limits, slot);
        Ok((
            InstalledPreparedWorld {
                scenario,
                graph,
                realization: prepared,
            },
            target,
        ))
    }

    /// Returns owning cleanup supervision for polling on every daemon actor turn.
    pub fn custody(&self) -> &RuntimeCustodyQueue {
        &self.custody
    }

    fn poll_original_runtime_custody(
        &self,
        context: &mut std::task::Context<'_>,
    ) -> Result<
        std::task::Poll<Result<(), crucible_engine::node_contract::RuntimePollFailure>>,
        NodeObservedError,
    > {
        match &self.runtime_wake {
            Some(reader) => self
                .custody
                .poll_reclamation_with_original_wake(reader)
                .map_err(native),
            None => Ok(self.custody.poll_reclamation(context)),
        }
    }

    pub(super) fn authenticate_cache_selection(
        &self,
        selections: &[InstalledNodeSelection],
        scenario: &NodeScenario,
    ) -> Result<(), NodeObservedError> {
        if measure_executable(&self.host_executable)? != self.host_identity
            || measure_executable(&self.device_executable)? != self.device_identity
        {
            return Err(refused(
                "installed implementation changed before cache reuse",
            ));
        }
        let artifacts = cached_artifacts::materialize(&self.artifacts, selections, scenario)?;
        let selected = profile::build_world(
            selections,
            &self.host_identity,
            &self.device_identity,
            artifacts.registry(),
        )?
        .scenario;
        if selected.canonical_bytes()? != scenario.canonical_bytes()? {
            return Err(refused(
                "cached scenario differs from exact installed implementation/model",
            ));
        }
        Ok(())
    }

    pub(super) fn authenticate_recorded(
        &self,
        scenario: &NodeScenario,
        configuration: &NodeRunConfiguration,
        request: &crucible_campaign::observed_node_attempt::ObservedAttemptRequest,
    ) -> Result<(), NodeObservedError> {
        profile::authenticate_recorded(scenario, configuration, request)
    }
}

pub(super) fn measure_executable(path: &Path) -> Result<ContentRef, NodeObservedError> {
    let mut file = File::open(path).map_err(native)?;
    let length = file.metadata().map_err(native)?.len();
    if length == 0 || length > 512 * 1024 * 1024 {
        return Err(refused(
            "installed executable exceeds bounded measurement limit",
        ));
    }
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"CNP/1\0");
    hasher.update(&("cnp.blob.v1".len() as u32).to_be_bytes());
    hasher.update(b"cnp.blob.v1");
    hasher.update(&length.to_be_bytes());
    let mut buffer = [0u8; 8192];
    let mut consumed = 0u64;
    loop {
        let count = file.read(&mut buffer).map_err(native)?;
        if count == 0 {
            break;
        }
        consumed = consumed
            .checked_add(count as u64)
            .filter(|total| *total <= length)
            .ok_or_else(|| refused("installed executable changed during measurement"))?;
        hasher.update(&buffer[..count]);
    }
    if consumed != length {
        return Err(refused("installed executable changed during measurement"));
    }
    Ok(ContentRef {
        hash: HashRef {
            algorithm: "blake3-256".into(),
            domain: "cnp.blob.v1".into(),
            digest: hasher.finalize().to_hex().to_string(),
        },
        length: U64::new(length),
        media_type: "application/octet-stream".into(),
    })
}

fn native(error: impl std::fmt::Debug) -> NodeObservedError {
    NodeObservedError::Native(format!("{error:?}"))
}

fn refused(reason: &str) -> NodeObservedError {
    NodeObservedError::Native(reason.to_owned())
}

fn execution_text(execution: ExecutionId) -> String {
    execution
        .as_bytes()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

impl crate::node_qualification::RetainedMetadataOwned for InstalledNodeSelection {
    fn charge(
        &self,
        counter: &mut crate::node_qualification::RetainedMetadataCounter,
    ) -> Result<(), crate::node_qualification::QualificationError> {
        let Self { node, owner, kind } = self;
        if !matches!(kind, InstalledNodeKind::HostClock) {
            return Err(crate::node_qualification::QualificationError::Refused(
                "unsupported Clock selection storage",
            ));
        }
        counter.charge(node)?;
        counter.charge(owner)
    }
}

impl crate::node_qualification::RetainedMetadataOwned for InstalledNodeCatalog {
    fn charge(
        &self,
        counter: &mut crate::node_qualification::RetainedMetadataCounter,
    ) -> Result<(), crate::node_qualification::QualificationError> {
        use crate::node_qualification::QualificationError;
        use crucible_engine::node_state::borrowed_btree_map_requested_storage_precredit_data;
        let Self {
            host_executable,
            host_identity,
            device_executable,
            device_identity,
            socket_parent,
            control_timeout: _,
            custody,
            runtime_wake,
            artifacts,
            behavioral_acceptance,
            vendor_providers,
            vendor_worlds,
            mixed_vendor_worlds,
            original_lineage,
            complete_scene,
        } = self;
        // Fresh Clock catalogues do not install another erased provider family.
        // Preserve those actual owners and refuse instead of counting them zero.
        if behavioral_acceptance.is_some()
            || vendor_providers.is_some()
            || !vendor_worlds.is_empty()
            || !mixed_vendor_worlds.is_empty()
            || original_lineage.authority.is_some()
            || !original_lineage.preparations.is_empty()
            || complete_scene.is_some()
        {
            return Err(QualificationError::Refused(
                "unsupported non-Clock catalog owner",
            ));
        }
        counter.charge(host_executable)?;
        counter.charge(host_identity)?;
        counter.charge(device_executable)?;
        counter.charge(device_identity)?;
        counter.charge(socket_parent)?;
        counter.charge(artifacts)?;
        let queue = custody
            .retained_requested_storage_data(counter.remaining())
            .map_err(|_| QualificationError::Refused("Clock custody storage unavailable"))?
            .ok_or(QualificationError::Refused(
                "Clock custody owns unknown transferred world",
            ))?;
        counter.add(queue)?;
        if let Some(wake) = runtime_wake {
            counter.add(
                wake.retained_requested_storage_data(counter.remaining())
                    .map_err(|_| QualificationError::Refused("Clock wake storage unavailable"))?,
            )?;
        }
        counter.charge(&original_lineage.used)?;
        for bytes in [
            borrowed_btree_map_requested_storage_precredit_data(vendor_worlds, counter.remaining()),
            borrowed_btree_map_requested_storage_precredit_data(
                mixed_vendor_worlds,
                counter.remaining(),
            ),
            borrowed_btree_map_requested_storage_precredit_data(
                &original_lineage.preparations,
                counter.remaining(),
            ),
        ] {
            counter.add(bytes.map_err(|_| {
                QualificationError::Refused("Clock catalog map storage overflow")
            })?)?;
        }
        Ok(())
    }
}
