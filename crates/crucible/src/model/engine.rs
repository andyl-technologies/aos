//! Engine errors, replay reconstruction, reduction, and symmetry helpers.

use super::*;

/// An engine-spine error.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum EngineError {
    /// The operation's signature is fixed but its behavior is not implemented.
    NotImplemented {
        /// The operation whose implementation is deferred.
        operation: &'static str,
    },
    /// A cached checkpoint is not a fat loadable snapshot.
    CheckpointNotLoadable {
        /// The checkpoint that cannot be loaded.
        checkpoint: ContentHash,
        /// The checkpoint storage kind.
        kind: CheckpointKind,
    },
    /// A cached checkpoint names a different configuration than requested.
    CheckpointConfigurationMismatch {
        /// The checkpoint whose metadata was invalid.
        checkpoint: ContentHash,
        /// The requested configuration id.
        expected: ContentHash,
        /// The configuration id recorded by the checkpoint.
        actual: ContentHash,
    },
    /// A checkpoint's recorded node id does not match its configuration id.
    CheckpointIdentityMismatch {
        /// The checkpoint whose identity was invalid.
        checkpoint: ContentHash,
        /// The expected checkpoint id.
        expected: ContentHash,
        /// The actual checkpoint id.
        actual: ContentHash,
    },
    /// A checkpoint's parent/delta/scenario fields do not match its configuration.
    CheckpointTopologyMismatch {
        /// The checkpoint whose topology was invalid.
        checkpoint: ContentHash,
        /// Stable reason for the topology rejection.
        reason: &'static str,
    },
    /// A fat checkpoint does not carry enough materialized state for `loadvm`.
    CheckpointMaterializedStateIncomplete {
        /// The checkpoint whose materialized state is incomplete.
        checkpoint: ContentHash,
        /// Stable reason for the state rejection.
        reason: &'static str,
    },
    /// A checkpoint DAG node was requested before it was recorded.
    CheckpointNotRecorded {
        /// The absent checkpoint id.
        checkpoint: ContentHash,
    },
    /// No baked genesis checkpoint exists for the scenario.
    MissingBakedGenesis {
        /// The scenario id missing a baked genesis checkpoint.
        scenario: ContentHash,
    },
    /// A genesis snapshot was registered through the ordinary snapshot cache.
    GenesisSnapshotMustBeBaked {
        /// The genesis configuration that must use the baked genesis cache.
        configuration: ContentHash,
    },
    /// A world contains duplicate node identifiers.
    DuplicateWorldNodeId {
        /// The duplicate node id.
        node: NodeId,
    },
    /// A world link connects a node to itself.
    WorldLinkSelfLoop {
        /// The repeated endpoint node.
        node: NodeId,
    },
    /// A world link references a node that is not declared in the world.
    WorldLinkUnknownNode {
        /// The invalid link.
        link: LinkDef,
        /// The undeclared endpoint.
        node: NodeId,
    },
    /// A world link references an I/O scheduling node instead of a VM endpoint.
    WorldLinkNonVmEndpoint {
        /// The invalid link.
        link: LinkDef,
        /// The declared non-VM endpoint.
        node: NodeId,
    },
    /// A world contains duplicate canonical links.
    DuplicateWorldLink {
        /// The duplicated link.
        link: LinkDef,
    },
    /// A world contains duplicate device identifiers across its I/O families.
    DuplicateWorldDeviceId {
        /// The duplicate device id.
        device: DeviceId,
    },
    /// A world I/O node names an owner that is not a declared VM node.
    WorldIoNodeUnknownOwner {
        /// The invalid I/O node.
        node: NodeId,
        /// The undeclared or non-VM owner.
        owner: NodeId,
    },
    /// A world I/O node configures an invalid virtual-clock shift.
    WorldIoNodeClockShiftTooLarge {
        /// The invalid I/O node.
        node: NodeId,
        /// The invalid shift.
        shift: u8,
    },
    /// A link's one-way base latency is below the model floor.
    WorldLinkLatencyBelowFloor {
        /// The invalid link.
        link: LinkDef,
        /// The configured one-way base latency.
        latency: SimDuration,
        /// The minimum legal link latency.
        minimum: SimDuration,
    },
    /// A link's configured jitter can drive effective latency below the floor.
    WorldLinkJitterBelowLatencyFloor {
        /// The invalid link.
        link: LinkDef,
        /// The configured one-way base latency.
        latency: SimDuration,
        /// The configured maximum jitter.
        jitter: SimDuration,
        /// The minimum legal effective link latency.
        minimum: SimDuration,
    },
    /// A fixed-point link loss probability is outside `[0.0, 1.0]`.
    LinkLossProbabilityOutOfRange {
        /// The invalid probability in millionths.
        millionths: u32,
        /// The maximum legal probability in millionths.
        maximum: u32,
    },
    /// An agent-signal ready point was configured without white-box opt-in.
    WhiteBoxReadyPointWithoutOptIn {
        /// The node whose ready-point configuration is invalid.
        node: NodeId,
    },
    /// A network-idle ready point configured an empty idle window.
    ReadyPointNetworkIdleWindowZero {
        /// The node whose ready-point configuration is invalid.
        node: NodeId,
    },
    /// A network-idle ready point has no incident world link to observe.
    ReadyPointNetworkIdleWithoutLinks {
        /// The node whose ready-point configuration is invalid.
        node: NodeId,
    },
    /// A console-marker ready point configured an empty marker.
    ReadyPointConsoleMarkerEmpty {
        /// The node whose ready-point configuration is invalid.
        node: NodeId,
    },
    /// A world node has no vCPUs.
    WorldNodeSmpVcpuCountZero {
        /// The invalid node.
        node: NodeId,
    },
    /// A world node has no guest memory.
    WorldNodeMemoryMibZero {
        /// The invalid node.
        node: NodeId,
    },
    /// A world node has an unsupported fixed icount shift.
    WorldNodeIcountShiftTooLarge {
        /// The invalid node.
        node: NodeId,
        /// The configured shift value.
        shift: u8,
        /// The maximum legal shift value.
        maximum: u8,
    },
    /// A world node selected an unsupported reserved workload value.
    WorldNodeUnsupportedWorkload {
        /// The invalid node.
        node: NodeId,
        /// The unsupported workload scenario-parameter value.
        value: String,
    },
    /// A world node selected more than one reserved workload value.
    WorldNodeDuplicateWorkload {
        /// The invalid node.
        node: NodeId,
    },
    /// A world node configured an invalid explicit workload seed.
    WorldNodeInvalidWorkloadSeed {
        /// The invalid node.
        node: NodeId,
        /// The invalid workload-seed scenario-parameter value.
        value: String,
    },
    /// A world node selected more than one explicit workload seed.
    WorldNodeDuplicateWorkloadSeed {
        /// The invalid node.
        node: NodeId,
    },
    /// A scalar workload parameter carried an invalid command-line value.
    WorkloadParameterInvalidValue {
        /// The invalid parameter key.
        parameter: String,
        /// The invalid parameter value.
        value: String,
    },
    /// A world node selected more than one value for a scalar workload parameter.
    WorldNodeDuplicateWorkloadParameter {
        /// The invalid node.
        node: NodeId,
        /// The duplicated workload parameter key.
        parameter: String,
    },
    /// A world node selected an invalid scalar workload-parameter value.
    WorldNodeInvalidWorkloadParameterValue {
        /// The invalid node.
        node: NodeId,
        /// The invalid workload parameter key.
        parameter: String,
        /// The invalid workload parameter value.
        value: String,
    },
    /// A structured workload config tree used a non-portable guest mount path.
    WorkloadConfigTreeInvalidMount {
        /// The invalid guest mount path.
        mount: String,
    },
    /// A world node selected an invalid workload config-tree reference.
    WorldNodeUnsupportedWorkloadConfigTree {
        /// The invalid node.
        node: NodeId,
        /// The unsupported config-tree scenario-parameter value.
        value: String,
    },
    /// A world node selected more than one structured workload config tree.
    WorldNodeDuplicateWorkloadConfigTree {
        /// The invalid node.
        node: NodeId,
    },
    /// A rootfs-backed workload config tree had no matching root image.
    WorldNodeWorkloadConfigTreeRootfsMissingRootImage {
        /// The invalid node.
        node: NodeId,
        /// The content-addressed config tree that must be the node root image.
        export: ContentAddressedBlobRef,
    },
    /// A rootfs-backed workload config tree did not match the node root image.
    WorldNodeWorkloadConfigTreeRootfsMismatchedRootImage {
        /// The invalid node.
        node: NodeId,
        /// The content-addressed config tree declared by `wcfg`.
        export: ContentAddressedBlobRef,
        /// The node root image actually configured.
        root_image: ContentAddressedBlobRef,
    },
    /// A world node selected an unsupported load-pattern value.
    WorldNodeUnsupportedWorkloadPattern {
        /// The invalid node.
        node: NodeId,
        /// The unsupported load-pattern scenario-parameter value.
        value: String,
    },
    /// A world node selected more than one load-pattern value.
    WorldNodeDuplicateWorkloadPattern {
        /// The invalid node.
        node: NodeId,
    },
    /// A world node selected an unsupported spike-mode value.
    WorldNodeUnsupportedWorkloadSpikeMode {
        /// The invalid node.
        node: NodeId,
        /// The unsupported spike-mode scenario-parameter value.
        value: String,
    },
    /// A world node selected more than one spike-mode value.
    WorldNodeDuplicateWorkloadSpikeMode {
        /// The invalid node.
        node: NodeId,
    },
    /// A world node selected `load_pattern=spike` without selecting a spike mode.
    WorldNodeWorkloadSpikePatternMissingMode {
        /// The invalid node.
        node: NodeId,
    },
    /// A world node selected a spike mode without selecting `load_pattern=spike`.
    WorldNodeWorkloadSpikeModeWithoutSpikePattern {
        /// The invalid node.
        node: NodeId,
    },
    /// A world node selected an unsupported load-shape time source.
    WorldNodeUnsupportedWorkloadTimeSource {
        /// The invalid node.
        node: NodeId,
        /// The unsupported load-shape time-source scenario-parameter value.
        value: String,
    },
    /// A world node selected more than one load-shape time source.
    WorldNodeDuplicateWorkloadTimeSource {
        /// The invalid node.
        node: NodeId,
    },
    /// A time-varying load pattern omitted its virtual-time source declaration.
    WorldNodeWorkloadTimeVaryingPatternMissingVirtualTimeSource {
        /// The invalid node.
        node: NodeId,
    },
    /// A non-time-varying load pattern selected a load-shape time source.
    WorldNodeWorkloadTimeSourceWithoutTimeVaryingPattern {
        /// The invalid node.
        node: NodeId,
    },
    /// A properties bundle contains duplicate assertion identifiers.
    PropertyDuplicateAssertionId {
        /// The duplicated assertion id.
        id: AssertionId,
    },
    /// A property predicate references an undeclared node.
    PropertyPredicateUnknownNode {
        /// The undeclared node.
        node: NodeId,
    },
    /// A property predicate references an undeclared assertion.
    PropertyPredicateUnknownAssertion {
        /// The undeclared assertion.
        assertion: AssertionId,
    },
    /// A property predicate uses `GuestMarker` without any white-box-enabled node.
    PropertyPredicateGuestMarkerRequiresWhiteBoxOptIn {
        /// The guest marker that requires a white-box-enabled node.
        marker: MarkerId,
    },
    /// A compound property predicate has no child predicates.
    PropertyPredicateEmptyCompound {
        /// Stable name of the empty compound predicate kind.
        kind: &'static str,
    },
    /// A property predicate uses a trigger-only edge-shaped predicate.
    PropertyPredicateTriggerOnly {
        /// Stable name of the trigger-only predicate kind.
        kind: &'static str,
    },
    /// A property predicate contains an invalid regex program.
    PropertyPredicateInvalidRegex {
        /// Regex pattern that failed validation.
        pattern: String,
        /// Stable validation failure text from the regex compiler.
        reason: String,
    },
    /// A scenario-builder node template reference names no concrete node.
    ScenarioBuilderUnknownNodeTemplate {
        /// The node that requested a copied template.
        node: NodeId,
        /// The missing template node name.
        template: NodeId,
    },
    /// A serialized scenario form is malformed.
    ScenarioSerialization {
        /// Stable reason for the serialization failure.
        reason: String,
    },
    /// A serialized image/kernel/initrd reference is not content-addressed.
    ScenarioImageReferenceNotContentAddressed {
        /// The serialized field being validated.
        field: &'static str,
        /// The non-portable reference value.
        value: String,
    },
    /// A serialized content address did not match the parsed component content.
    ScenarioSerializedIdMismatch {
        /// The component whose serialized id was invalid.
        component: &'static str,
        /// The content address carried in the serialized form.
        expected: ContentHash,
        /// The content address recomputed from parsed content.
        actual: ContentHash,
    },
    /// A reproduction artifact was captured with the wrong scenario form.
    ReproductionScenarioMismatch {
        /// Scenario id required by the configuration.
        expected: ContentHash,
        /// Scenario id carried by the supplied form.
        actual: ContentHash,
    },
    /// A schedule contains more app-random decisions than its scenario admits.
    AppRandomDrawCapExceeded {
        /// The scenario whose app-random cap was exceeded.
        scenario: ContentHash,
        /// The configured per-scenario draw cap.
        cap: u64,
        /// The number of app-random decisions present in the schedule.
        actual: u64,
    },
    /// A debugger gdb-protocol endpoint was not stable non-empty text.
    DebugGdbEndpointInvalid {
        /// Endpoint field being validated.
        field: &'static str,
        /// Rejected endpoint value.
        value: String,
    },
    /// A debug attach requested a node absent from the instantiated runtime.
    DebugAttachUnknownNode {
        /// Requested node.
        node: NodeId,
        /// Configuration being attached to.
        configuration: ContentHash,
    },
    /// A canonical breakpoint would require guest-memory mutation.
    DebugBreakpointRequiresAllowMutate {
        /// Requested node.
        node: NodeId,
        /// Breakpoint target that has no canonical out-of-band mechanism.
        target: DebugBreakpointTarget,
        /// Client breakpoint kind that could not be satisfied canonically.
        requested_client_kind: DebugBreakpointClientKind,
    },
    /// A non-canonical debug branch trigger lacked a matching first recorded action.
    DebugNonCanonicalBranchMissingTriggerEvidence {
        /// Trigger that was not backed by an action.
        trigger: DebugNonCanonicalBranchTrigger,
        /// Configuration where the branch was requested.
        configuration: ContentHash,
    },
    /// `--at-failure` found no assertion violation in the supplied event log.
    DebugTargetResolverFailureNotFound {
        /// Configuration where the target was requested.
        configuration: ContentHash,
    },
    /// A debug `goto` request did not start at the attached configuration.
    DebugGotoAttachMismatch {
        /// Configuration currently attached.
        attached: ContentHash,
        /// Configuration supplied as the request's current coordinate.
        requested_current: ContentHash,
    },
    /// A debug `goto` target belongs to a different scenario than the current coordinate.
    DebugGotoScenarioMismatch {
        /// Current configuration.
        current: ContentHash,
        /// Target configuration.
        target: ContentHash,
    },
    /// A debug `goto` replay-oracle mismatch with bisection coordinates.
    DebugGotoReplayOracleMismatch {
        /// Bisection request localizing the first differing prefix.
        bisection: Box<DebugReplayOracleBisectionRequest>,
        /// The fat checkpoint under test.
        checkpoint: ContentHash,
        /// The materialized-state identity reconstructed by thin replay.
        expected: ContentHash,
        /// The supplied checkpoint's materialized-state identity.
        actual: ContentHash,
    },
    /// A reverse operation had no earlier coordinate for the requested grain.
    DebugTimeTravelNoEarlierCoordinate {
        /// Reverse-step grain being resolved.
        grain: DebugReverseStepGrain,
        /// Current configuration.
        current: ContentHash,
    },
    /// A reverse operation selected an event-log entry without a coordinate mapping.
    DebugTimeTravelMissingEventCoordinate {
        /// Event-log sequence that lacked a mapping.
        sequence: u64,
    },
    /// A debug coordinate could not be resolved in the temporal graph.
    DebugTimeTravelCoordinateNotFound {
        /// Coordinate that had no graph checkpoint at or before it.
        coordinate: DebugCoordinate,
    },
    /// A debug time-travel operation named a node absent from the runtime.
    DebugTimeTravelUnknownNode {
        /// Node that lacked runtime material.
        node: NodeId,
        /// Configuration whose runtime was inspected.
        configuration: ContentHash,
    },
    /// A reverse-continue scan could not build a checked condition prefix.
    DebugReverseContinueInvalidPrefix {
        /// Event-log sequence at the attempted prefix boundary.
        sequence: u64,
        /// Stable debug rendering of the prefix validation error.
        reason: String,
    },
    /// A scenario family has an invalid finite parameter space.
    ScenarioFamilyInvalidSpace {
        /// Stable reason for the parameter-space rejection.
        reason: &'static str,
    },
    /// A requested family parameter point is outside the family space.
    ScenarioFamilyParameterOutOfSpace {
        /// Stable parameter axis name.
        parameter: &'static str,
    },
    /// A runtime was replayed from a configuration it does not materialize.
    RuntimeConfigurationMismatch {
        /// The runtime-state id whose metadata was invalid.
        runtime: ContentHash,
        /// The configuration expected by the replay start.
        expected: ContentHash,
        /// The configuration recorded by the runtime state.
        actual: ContentHash,
    },
    /// Replaying a suffix did not reconstruct the requested configuration.
    ReplayTargetMismatch {
        /// The requested target configuration.
        expected: ContentHash,
        /// The configuration produced by replaying the suffix.
        actual: ContentHash,
    },
    /// Typed operation evidence did not match the operation output it claims.
    UnifiedOperationEvidenceMismatch {
        /// Stable operation label.
        operation: &'static str,
        /// Stable reason for the evidence rejection.
        reason: &'static str,
    },
    /// Pure temporal replay cannot advance a retained event-log offset.
    EventLogReplayUnsupported {
        /// The configuration replay started from.
        start: ContentHash,
        /// The requested target configuration.
        target: ContentHash,
        /// Event-log entries already retained at the replay start.
        events: u64,
    },
    /// A fat checkpoint did not match its thin replay derivation.
    ReplayOracleMismatch {
        /// The fat checkpoint under test.
        checkpoint: ContentHash,
        /// The materialized-state identity reconstructed by thin replay.
        expected: ContentHash,
        /// The supplied fat checkpoint's materialized-state identity.
        actual: ContentHash,
    },
    /// A sampled search materialization failed the replay oracle and needs bisection.
    SearchReplayOracleMismatch {
        /// Bisection request for the fat/thin reconstruction pair.
        bisection: Box<SearchReplayOracleBisectionRequest>,
        /// The fat checkpoint under test.
        checkpoint: ContentHash,
        /// The materialized-state identity reconstructed by thin replay.
        expected: ContentHash,
        /// The supplied fat checkpoint's materialized-state identity.
        actual: ContentHash,
    },
    /// A self-contained reproduction artifact did not replay to its recorded state.
    ReproductionArtifactReplayMismatch {
        /// The artifact whose replay failed.
        artifact: ContentHash,
        /// The reduced state recorded in the artifact.
        expected: ContentHash,
        /// The reduced state reached by replaying the embedded scenario/schedule.
        actual: ContentHash,
    },
    /// Active-search replay-oracle sampling was configured with an invalid rate.
    InvalidSearchReplayOracleSamplingConfig {
        /// Stable reason for the validation failure.
        reason: &'static str,
    },
    /// A schedule prefix or suffix could not be constructed.
    SchedulePrefix(
        /// The schedule prefix error.
        ScheduleError,
    ),
}

impl fmt::Display for EngineError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NotImplemented { operation } => {
                write!(f, "{operation} is not implemented yet")
            }
            Self::CheckpointNotLoadable { kind, .. } => {
                write!(
                    f,
                    "checkpoint is not loadable because it is {}",
                    checkpoint_kind_label(*kind)
                )
            }
            Self::CheckpointConfigurationMismatch { .. } => {
                f.write_str("checkpoint configuration does not match requested configuration")
            }
            Self::CheckpointIdentityMismatch { .. } => {
                f.write_str("checkpoint id does not match requested configuration")
            }
            Self::CheckpointTopologyMismatch { reason, .. } => {
                write!(f, "checkpoint topology is invalid: {reason}")
            }
            Self::CheckpointMaterializedStateIncomplete { reason, .. } => {
                write!(f, "checkpoint materialized state is incomplete: {reason}")
            }
            Self::CheckpointNotRecorded { .. } => {
                f.write_str("checkpoint is not recorded in the temporal graph")
            }
            Self::MissingBakedGenesis { .. } => {
                f.write_str("missing baked genesis checkpoint for scenario")
            }
            Self::GenesisSnapshotMustBeBaked { .. } => {
                f.write_str("genesis snapshots must be registered as baked genesis checkpoints")
            }
            Self::DuplicateWorldNodeId { .. } => f.write_str("world contains a duplicate node id"),
            Self::WorldLinkSelfLoop { .. } => f.write_str("world link endpoints must be distinct"),
            Self::WorldLinkUnknownNode { .. } => {
                f.write_str("world link references an undeclared node")
            }
            Self::WorldLinkNonVmEndpoint { .. } => {
                f.write_str("world link endpoints must be declared VM nodes")
            }
            Self::DuplicateWorldLink { .. } => {
                f.write_str("world contains a duplicate canonical link")
            }
            Self::DuplicateWorldDeviceId { .. } => {
                f.write_str("world contains a duplicate device id")
            }
            Self::WorldIoNodeUnknownOwner { .. } => {
                f.write_str("world I/O node references an undeclared or non-VM owner node")
            }
            Self::WorldIoNodeClockShiftTooLarge { .. } => {
                f.write_str("world I/O node clock shift must be less than 64")
            }
            Self::WorldLinkLatencyBelowFloor { .. } => {
                f.write_str("world link latency is below the minimum floor")
            }
            Self::WorldLinkJitterBelowLatencyFloor { .. } => {
                f.write_str("world link jitter can drive latency below the minimum floor")
            }
            Self::LinkLossProbabilityOutOfRange { .. } => {
                f.write_str("world link loss probability is outside the legal range")
            }
            Self::WhiteBoxReadyPointWithoutOptIn { .. } => {
                f.write_str("agent-signal ready point requires white-box opt-in")
            }
            Self::ReadyPointNetworkIdleWindowZero { .. } => {
                f.write_str("network-idle ready point requires a nonzero idle window")
            }
            Self::ReadyPointNetworkIdleWithoutLinks { .. } => {
                f.write_str("network-idle ready point requires at least one world link")
            }
            Self::ReadyPointConsoleMarkerEmpty { .. } => {
                f.write_str("console-marker ready point requires a nonempty marker")
            }
            Self::WorldNodeSmpVcpuCountZero { .. } => {
                f.write_str("world node fixed vCPU count must be at least one")
            }
            Self::WorldNodeMemoryMibZero { .. } => {
                f.write_str("world node memory size must be at least one MiB")
            }
            Self::WorldNodeIcountShiftTooLarge { .. } => {
                f.write_str("world node fixed icount shift is outside the legal range")
            }
            Self::WorldNodeUnsupportedWorkload { value, .. } => {
                write!(f, "world node workload value {value} is unsupported")
            }
            Self::WorldNodeDuplicateWorkload { .. } => {
                f.write_str("world node selects more than one workload")
            }
            Self::WorldNodeInvalidWorkloadSeed { value, .. } => {
                write!(f, "world node workload seed value {value} is invalid")
            }
            Self::WorldNodeDuplicateWorkloadSeed { .. } => {
                f.write_str("world node selects more than one workload seed")
            }
            Self::WorkloadParameterInvalidValue {
                parameter, value, ..
            } => {
                write!(
                    f,
                    "workload parameter {parameter} value {value} is invalid"
                )
            }
            Self::WorldNodeDuplicateWorkloadParameter { parameter, .. } => {
                write!(
                    f,
                    "world node selects more than one value for workload parameter {parameter}"
                )
            }
            Self::WorldNodeInvalidWorkloadParameterValue {
                parameter, value, ..
            } => {
                write!(
                    f,
                    "world node workload parameter {parameter} value {value} is invalid"
                )
            }
            Self::WorkloadConfigTreeInvalidMount { mount } => {
                write!(f, "workload config tree mount path {mount} is invalid")
            }
            Self::WorldNodeUnsupportedWorkloadConfigTree { value, .. } => {
                write!(
                    f,
                    "world node workload config tree value {value} is unsupported"
                )
            }
            Self::WorldNodeDuplicateWorkloadConfigTree { .. } => {
                f.write_str("world node selects more than one workload config tree")
            }
            Self::WorldNodeWorkloadConfigTreeRootfsMissingRootImage { export, .. } => {
                write!(
                    f,
                    "world node rootfs workload config tree {} has no matching root image",
                    export.to_uri()
                )
            }
            Self::WorldNodeWorkloadConfigTreeRootfsMismatchedRootImage {
                export,
                root_image,
                ..
            } => {
                write!(
                    f,
                    "world node rootfs workload config tree {} does not match root image {}",
                    export.to_uri(),
                    root_image.to_uri()
                )
            }
            Self::WorldNodeUnsupportedWorkloadPattern { value, .. } => {
                write!(
                    f,
                    "world node workload pattern value {value} is unsupported"
                )
            }
            Self::WorldNodeDuplicateWorkloadPattern { .. } => {
                f.write_str("world node selects more than one workload pattern")
            }
            Self::WorldNodeUnsupportedWorkloadSpikeMode { value, .. } => {
                write!(
                    f,
                    "world node workload spike mode value {value} is unsupported"
                )
            }
            Self::WorldNodeDuplicateWorkloadSpikeMode { .. } => {
                f.write_str("world node selects more than one workload spike mode")
            }
            Self::WorldNodeWorkloadSpikePatternMissingMode { .. } => {
                f.write_str("world node selects a spike workload pattern without a spike mode")
            }
            Self::WorldNodeWorkloadSpikeModeWithoutSpikePattern { .. } => {
                f.write_str("world node selects a workload spike mode without a spike pattern")
            }
            Self::WorldNodeUnsupportedWorkloadTimeSource { value, .. } => {
                write!(
                    f,
                    "world node workload time source value {value} is unsupported"
                )
            }
            Self::WorldNodeDuplicateWorkloadTimeSource { .. } => {
                f.write_str("world node selects more than one workload time source")
            }
            Self::WorldNodeWorkloadTimeVaryingPatternMissingVirtualTimeSource { .. } => f.write_str(
                "world node selects a time-varying workload pattern without virtual-time source",
            ),
            Self::WorldNodeWorkloadTimeSourceWithoutTimeVaryingPattern { .. } => {
                f.write_str(
                    "world node selects a workload time source without a time-varying pattern",
                )
            }
            Self::PropertyDuplicateAssertionId { .. } => {
                f.write_str("properties bundle contains a duplicate assertion id")
            }
            Self::PropertyPredicateUnknownNode { .. } => {
                f.write_str("property predicate references an undeclared node")
            }
            Self::PropertyPredicateUnknownAssertion { .. } => {
                f.write_str("property predicate references an undeclared assertion")
            }
            Self::PropertyPredicateGuestMarkerRequiresWhiteBoxOptIn { .. } => {
                f.write_str("property predicate guest marker requires white-box opt-in")
            }
            Self::PropertyPredicateEmptyCompound { kind } => {
                write!(f, "property predicate compound {kind} has no children")
            }
            Self::PropertyPredicateTriggerOnly { kind } => {
                write!(f, "property predicate {kind} is trigger-only")
            }
            Self::PropertyPredicateInvalidRegex { reason, .. } => {
                write!(f, "property predicate regex is invalid: {reason}")
            }
            Self::ScenarioBuilderUnknownNodeTemplate { .. } => {
                f.write_str("scenario builder node template is unknown")
            }
            Self::ScenarioSerialization { reason } => {
                write!(f, "scenario serialized form is invalid: {reason}")
            }
            Self::ScenarioImageReferenceNotContentAddressed { field, .. } => {
                write!(
                    f,
                    "scenario serialized {field} reference is not content-addressed"
                )
            }
            Self::ScenarioSerializedIdMismatch {
                component,
                expected,
                actual,
            } => {
                write!(
                    f,
                    "scenario serialized {component} id {} does not match recomputed {}",
                    format_content_hash_ref(*expected),
                    format_content_hash_ref(*actual)
                )
            }
            Self::ReproductionScenarioMismatch { .. } => {
                f.write_str("reproduction scenario form does not match configuration")
            }
            Self::AppRandomDrawCapExceeded { cap, actual, .. } => {
                write!(
                    f,
                    "app-random draw count {actual} exceeds scenario cap {cap}"
                )
            }
            Self::DebugGdbEndpointInvalid { field, .. } => {
                write!(f, "debug gdb endpoint {field} is invalid")
            }
            Self::DebugAttachUnknownNode { .. } => {
                f.write_str("debug attach requested an unknown runtime node")
            }
            Self::DebugBreakpointRequiresAllowMutate { .. } => f.write_str(
                "canonical debug breakpoint requires guest-memory mutation; rerun with --allow-mutate to fork a non-canonical debug branch",
            ),
            Self::DebugNonCanonicalBranchMissingTriggerEvidence { .. } => f.write_str(
                "non-canonical debug branch trigger is missing matching first operator action evidence",
            ),
            Self::DebugTargetResolverFailureNotFound { .. } => {
                f.write_str("debug target resolver found no assertion violation for --at-failure")
            }
            Self::DebugGotoAttachMismatch { .. } => {
                f.write_str("debug goto current coordinate does not match attached configuration")
            }
            Self::DebugGotoScenarioMismatch { .. } => {
                f.write_str("debug goto target belongs to a different scenario")
            }
            Self::DebugGotoReplayOracleMismatch { .. } => f.write_str(
                "debug goto replay oracle mismatch localized by bisection",
            ),
            Self::DebugTimeTravelNoEarlierCoordinate { .. } => {
                f.write_str("debug reverse operation found no earlier coordinate")
            }
            Self::DebugTimeTravelMissingEventCoordinate { sequence } => {
                write!(
                    f,
                    "debug reverse operation has no temporal coordinate for event-log sequence {sequence}"
                )
            }
            Self::DebugTimeTravelCoordinateNotFound { .. } => {
                f.write_str("debug coordinate did not resolve to a temporal graph checkpoint")
            }
            Self::DebugTimeTravelUnknownNode { .. } => {
                f.write_str("debug time-travel node is absent from runtime material")
            }
            Self::DebugReverseContinueInvalidPrefix { reason, .. } => {
                write!(f, "debug reverse-continue condition prefix is invalid: {reason}")
            }
            Self::ScenarioFamilyInvalidSpace { reason } => {
                write!(f, "scenario family parameter space is invalid: {reason}")
            }
            Self::ScenarioFamilyParameterOutOfSpace { parameter } => {
                write!(
                    f,
                    "scenario family parameter {parameter} is outside the space"
                )
            }
            Self::RuntimeConfigurationMismatch { .. } => {
                f.write_str("runtime configuration does not match replay start configuration")
            }
            Self::ReplayTargetMismatch { .. } => {
                f.write_str("replayed suffix did not produce requested configuration")
            }
            Self::UnifiedOperationEvidenceMismatch { operation, reason } => {
                write!(
                    f,
                    "unified {operation} operation evidence is inconsistent: {reason}"
                )
            }
            Self::EventLogReplayUnsupported { events, .. } => {
                write!(
                    f,
                    "pure replay cannot advance retained event-log offset with {events} events"
                )
            }
            Self::ReplayOracleMismatch { .. } => {
                f.write_str("replay oracle mismatch between fat checkpoint and thin derivation")
            }
            Self::SearchReplayOracleMismatch { .. } => {
                f.write_str("sampled search checkpoint does not match thin replay derivation")
            }
            Self::ReproductionArtifactReplayMismatch { .. } => {
                f.write_str("reproduction artifact did not replay to its recorded state")
            }
            Self::InvalidSearchReplayOracleSamplingConfig { reason } => {
                write!(f, "invalid search replay-oracle sampling config: {reason}")
            }
            Self::SchedulePrefix(error) => write!(f, "schedule prefix failed: {error}"),
        }
    }
}

impl Error for EngineError {}

pub(super) fn load_snapshot(
    configuration: &Configuration,
    checkpoint: &Checkpoint,
) -> Result<RuntimeState, EngineError> {
    validate_loadable_checkpoint(checkpoint, configuration)?;
    let scheduler = checkpoint
        .state
        .as_ref()
        .map(|state| state.scheduler.clone())
        .unwrap_or_else(|| scheduler_state_for_configuration(configuration));
    let event_log = checkpoint
        .state
        .as_ref()
        .map(|state| state.event_log)
        .unwrap_or_default();
    runtime_for_configuration_with_scheduler(
        configuration,
        checkpoint.node_blobs.clone(),
        checkpoint.node_icounts.clone(),
        scheduler,
        event_log,
    )
}

pub(super) fn runtime_for_configuration_with_scheduler(
    configuration: &Configuration,
    node_blobs: BTreeMap<NodeId, NodeBlobRef>,
    node_icounts: BTreeMap<NodeId, Icount>,
    scheduler: SchedulerState,
    event_log: EventLogOffset,
) -> Result<RuntimeState, EngineError> {
    Ok(RuntimeState {
        id: reduce(&configuration.def, &configuration.schedule)?.id,
        configuration: configuration.id(),
        node_blobs,
        node_icounts,
        scheduler,
        event_log,
    })
}

pub(super) fn replay_suffix(
    runtime: RuntimeState,
    start: &Configuration,
    suffix: &Schedule,
    target: &Configuration,
) -> Result<RuntimeState, EngineError> {
    if runtime.configuration != start.id() {
        return Err(EngineError::RuntimeConfigurationMismatch {
            runtime: runtime.id,
            expected: start.id(),
            actual: runtime.configuration,
        });
    }

    let mut replayed = start.clone();
    for decision in suffix.decisions() {
        replayed = try_step(&replayed, decision.clone())?;
    }

    if replayed.id() != target.id() {
        return Err(EngineError::ReplayTargetMismatch {
            expected: target.id(),
            actual: replayed.id(),
        });
    }

    if !suffix.is_empty()
        && (runtime.event_log.events != 0
            || runtime.event_log.bytes != 0
            || runtime.event_log.appended_segment.is_some())
    {
        return Err(EngineError::EventLogReplayUnsupported {
            start: start.id(),
            target: target.id(),
            events: runtime.event_log.events,
        });
    }

    let node_blobs = replayed_node_blobs(&runtime.node_blobs, start, suffix, target);
    let node_icounts = replayed_node_icounts(&runtime.node_icounts, suffix);
    let mut scheduler = runtime.scheduler;
    if !suffix.is_empty() {
        scheduler.search_frontier = SearchFrontierChoices::empty();
    }
    let event_log = runtime.event_log;
    scheduler.apply_decisions(suffix.decisions());
    runtime_for_configuration_with_scheduler(
        &replayed,
        node_blobs,
        node_icounts,
        scheduler,
        event_log,
    )
}

pub(super) fn scheduler_state_for_configuration(configuration: &Configuration) -> SchedulerState {
    SchedulerState::from_schedule(&configuration.schedule)
}

pub(super) fn configuration_virtual_time(configuration: &Configuration) -> VirtualTime {
    configuration
        .schedule
        .recorded_virtual_time()
        .unwrap_or(VirtualTime {
            ticks: u64::try_from(configuration.schedule.len()).unwrap_or(u64::MAX),
        })
}

pub(super) fn instantiate_thin_replay(
    graph: &TemporalGraph,
    config: &Configuration,
) -> Result<RuntimeState, EngineError> {
    if config.is_genesis() {
        let genesis =
            graph
                .genesis_snapshot(&config.def)
                .ok_or(EngineError::MissingBakedGenesis {
                    scenario: config.def.id,
                })?;
        return load_snapshot(config, &genesis.checkpoint);
    }

    if let Some(ancestor) = graph.nearest_cached_ancestor(config)? {
        let ancestor_runtime = instantiate(graph, &ancestor)?;
        let suffix = config
            .schedule
            .suffix_from(ancestor.schedule.len())
            .map_err(EngineError::SchedulePrefix)?;
        return replay_suffix(ancestor_runtime, &ancestor, &suffix, config);
    }

    let genesis = Configuration::genesis(config.def.clone());
    let genesis_runtime = instantiate(graph, &genesis)?;
    let suffix = config
        .schedule
        .suffix_from(genesis.schedule.len())
        .map_err(EngineError::SchedulePrefix)?;
    replay_suffix(genesis_runtime, &genesis, &suffix, config)
}

pub(super) fn materialized_checkpoint_for_runtime(
    configuration: &Configuration,
    runtime: RuntimeState,
) -> Result<Checkpoint, EngineError> {
    if runtime.configuration != configuration.id() {
        return Err(EngineError::RuntimeConfigurationMismatch {
            runtime: runtime.id,
            expected: configuration.id(),
            actual: runtime.configuration,
        });
    }
    let parent = immediate_parent_configuration(configuration)?;
    let state = MaterializedState::from_components(
        materialized_vm_snapshots(&runtime.node_icounts, &runtime.node_blobs),
        BTreeMap::new(),
        runtime.scheduler.clone(),
        DecisionRngState::empty(),
        runtime.event_log,
    );
    let mut checkpoint = Checkpoint::from_recorded_configuration(
        configuration,
        parent.as_ref(),
        configuration_virtual_time(configuration),
        runtime.node_icounts,
        CheckpointKind::Fat,
        runtime.node_blobs,
    )?;
    checkpoint.state = Some(state);
    Ok(checkpoint)
}

pub(super) fn validate_loadable_checkpoint(
    checkpoint: &Checkpoint,
    configuration: &Configuration,
) -> Result<(), EngineError> {
    if checkpoint.kind != CheckpointKind::Fat {
        return Err(EngineError::CheckpointNotLoadable {
            checkpoint: checkpoint.id,
            kind: checkpoint.kind,
        });
    }
    if checkpoint.configuration != configuration.id() {
        return Err(EngineError::CheckpointConfigurationMismatch {
            checkpoint: checkpoint.id,
            expected: configuration.id(),
            actual: checkpoint.configuration,
        });
    }
    if checkpoint.id != configuration.id() {
        return Err(EngineError::CheckpointIdentityMismatch {
            checkpoint: checkpoint.id,
            expected: configuration.id(),
            actual: checkpoint.id,
        });
    }
    if checkpoint.scenario_ref != configuration.def.id {
        return Err(EngineError::CheckpointTopologyMismatch {
            checkpoint: checkpoint.id,
            reason: "scenario-ref-mismatch",
        });
    }

    let expected_parent_config = immediate_parent_configuration(configuration)?;
    let (expected_parent, expected_delta) =
        checkpoint_edge(configuration, expected_parent_config.as_ref())?;
    if checkpoint.parent != expected_parent {
        return Err(EngineError::CheckpointTopologyMismatch {
            checkpoint: checkpoint.id,
            reason: "parent-mismatch",
        });
    }
    if checkpoint.schedule_delta != expected_delta {
        return Err(EngineError::CheckpointTopologyMismatch {
            checkpoint: checkpoint.id,
            reason: "schedule-delta-mismatch",
        });
    }
    validate_materialized_state(checkpoint)?;

    Ok(())
}

pub(super) fn replay_oracle_failure_rejects_cache(error: &EngineError) -> bool {
    !matches!(error, EngineError::MissingBakedGenesis { .. })
}

pub(super) fn sample_search_replay_oracle_checkpoint(
    graph: &TemporalGraph,
    configuration: &Configuration,
    checkpoint: &Checkpoint,
    sequence: u64,
    config: &SearchReplayOracleSamplingConfig,
    report: &mut SearchReplayOracleSamplingReport,
) -> Result<(), EngineError> {
    if checkpoint.kind != CheckpointKind::Fat {
        return Ok(());
    }

    report.considered += 1;
    if !config.samples(sequence, checkpoint.id) {
        report.skipped += 1;
        return Ok(());
    }

    report.sampled += 1;
    report.sampled_checkpoints.push(checkpoint.id);
    graph
        .replay_checkpoint(configuration, checkpoint)
        .map(|_| ())
        .map_err(|error| search_replay_oracle_error(sequence, error))
}

pub(super) fn merge_search_replay_oracle_sampling_report(
    total: &mut SearchReplayOracleSamplingReport,
    frontier: &SearchReplayOracleSamplingReport,
) {
    total.considered += frontier.considered;
    total.sampled += frontier.sampled;
    total.skipped += frontier.skipped;
    total
        .sampled_checkpoints
        .extend(frontier.sampled_checkpoints.iter().copied());
}

pub(super) fn search_replay_oracle_error(sequence: u64, error: EngineError) -> EngineError {
    match error {
        EngineError::ReplayOracleMismatch {
            checkpoint,
            expected,
            actual,
        } => EngineError::SearchReplayOracleMismatch {
            bisection: Box::new(SearchReplayOracleBisectionRequest {
                sequence,
                checkpoint,
                reason: "sampled fat checkpoint differs from thin reconstruction",
            }),
            checkpoint,
            expected,
            actual,
        },
        other => other,
    }
}

pub(super) fn sampled_search_replay_oracle_error(
    sequence: u64,
    config: &SearchReplayOracleSamplingConfig,
    error: EngineError,
) -> EngineError {
    match error {
        EngineError::ReplayOracleMismatch {
            checkpoint,
            expected,
            actual,
        } if config.samples(sequence, checkpoint) => EngineError::SearchReplayOracleMismatch {
            bisection: Box::new(SearchReplayOracleBisectionRequest {
                sequence,
                checkpoint,
                reason: "sampled fat checkpoint differs from thin reconstruction",
            }),
            checkpoint,
            expected,
            actual,
        },
        EngineError::ReplayOracleMismatch {
            checkpoint,
            expected,
            actual,
        } => EngineError::ReplayOracleMismatch {
            checkpoint,
            expected,
            actual,
        },
        other => other,
    }
}

pub(super) fn validate_materialized_state(checkpoint: &Checkpoint) -> Result<(), EngineError> {
    let state =
        checkpoint
            .state
            .as_ref()
            .ok_or(EngineError::CheckpointMaterializedStateIncomplete {
                checkpoint: checkpoint.id,
                reason: "missing-state",
            })?;
    let expected_state_id = canonical::materialized_state_hash(
        &state.vm_snapshots,
        &state.device_overlays,
        &state.scheduler,
        &state.decision_rng,
        state.event_log,
    );
    if state.id != expected_state_id {
        return Err(EngineError::CheckpointMaterializedStateIncomplete {
            checkpoint: checkpoint.id,
            reason: "materialized-state-id-mismatch",
        });
    }

    for (node, blob) in &checkpoint.node_blobs {
        let snapshot = state.vm_snapshots.get(node).ok_or(
            EngineError::CheckpointMaterializedStateIncomplete {
                checkpoint: checkpoint.id,
                reason: "missing-vm-snapshot",
            },
        )?;
        if &snapshot.blob != blob {
            return Err(EngineError::CheckpointMaterializedStateIncomplete {
                checkpoint: checkpoint.id,
                reason: "vm-snapshot-blob-mismatch",
            });
        }
        let expected_icount = checkpoint
            .node_icounts
            .get(node)
            .copied()
            .unwrap_or_default();
        if snapshot.icount != expected_icount {
            return Err(EngineError::CheckpointMaterializedStateIncomplete {
                checkpoint: checkpoint.id,
                reason: "vm-snapshot-icount-mismatch",
            });
        }
    }

    for node in checkpoint.node_icounts.keys() {
        if !state.vm_snapshots.contains_key(node) {
            return Err(EngineError::CheckpointMaterializedStateIncomplete {
                checkpoint: checkpoint.id,
                reason: "missing-icount-vm-snapshot",
            });
        }
    }
    for node in state.vm_snapshots.keys() {
        if !checkpoint.node_blobs.contains_key(node) {
            return Err(EngineError::CheckpointMaterializedStateIncomplete {
                checkpoint: checkpoint.id,
                reason: "extra-vm-snapshot",
            });
        }
    }

    Ok(())
}

pub(super) fn checkpoint_kind_label(kind: CheckpointKind) -> &'static str {
    match kind {
        CheckpointKind::Fat => "fat",
        CheckpointKind::Thin => "thin",
    }
}

pub(super) fn materialized_state_for_kind(
    kind: CheckpointKind,
    node_icounts: &BTreeMap<NodeId, Icount>,
    node_blobs: &BTreeMap<NodeId, NodeBlobRef>,
) -> Option<MaterializedState> {
    materialized_state_for_kind_with_scheduler(
        kind,
        node_icounts,
        node_blobs,
        SchedulerState::empty(),
    )
}

pub(super) fn materialized_state_for_kind_with_scheduler(
    kind: CheckpointKind,
    node_icounts: &BTreeMap<NodeId, Icount>,
    node_blobs: &BTreeMap<NodeId, NodeBlobRef>,
    scheduler: SchedulerState,
) -> Option<MaterializedState> {
    match kind {
        CheckpointKind::Fat => Some(MaterializedState::from_components(
            materialized_vm_snapshots(node_icounts, node_blobs),
            BTreeMap::new(),
            scheduler,
            DecisionRngState::empty(),
            EventLogOffset::default(),
        )),
        CheckpointKind::Thin => None,
    }
}

pub(super) fn materialized_vm_snapshots(
    node_icounts: &BTreeMap<NodeId, Icount>,
    node_blobs: &BTreeMap<NodeId, NodeBlobRef>,
) -> BTreeMap<NodeId, VmSnapshotRef> {
    node_blobs
        .iter()
        .map(|(node, blob)| {
            let icount = node_icounts.get(node).copied().unwrap_or_default();
            (node.clone(), VmSnapshotRef::new(blob.clone(), icount))
        })
        .collect()
}

pub(super) fn replayed_node_blobs(
    ancestor_blobs: &BTreeMap<NodeId, NodeBlobRef>,
    start: &Configuration,
    suffix: &Schedule,
    target: &Configuration,
) -> BTreeMap<NodeId, NodeBlobRef> {
    ancestor_blobs
        .iter()
        .map(|(node, blob)| {
            let parent = blob.content_hash();
            let delta = ContentHash::from_canonical_material(
                "crucible.model.replayed-node-blob.delta.v1",
                &format!(
                    "node={}\nstart={}\ntarget={}\nsuffix={}",
                    node.name,
                    content_hash_hex(start.id()),
                    content_hash_hex(target.id()),
                    content_hash_hex(suffix.content_hash())
                ),
            );
            let resolved = ContentHash::from_canonical_material(
                "crucible.model.replayed-node-blob.resolved.v1",
                &format!(
                    "node={}\nparent={}\ndelta={}",
                    node.name,
                    content_hash_hex(parent),
                    content_hash_hex(delta)
                ),
            );
            (
                node.clone(),
                NodeBlobRef::cow_delta(parent, delta, resolved),
            )
        })
        .collect()
}

pub(super) fn replayed_node_icounts(
    ancestor_icounts: &BTreeMap<NodeId, Icount>,
    suffix: &Schedule,
) -> BTreeMap<NodeId, Icount> {
    let delta = suffix.len() as u64;
    ancestor_icounts
        .iter()
        .map(|(node, icount)| {
            (
                node.clone(),
                Icount {
                    retired: icount.retired.saturating_add(delta),
                },
            )
        })
        .collect()
}

pub(super) fn decision_touched_nodes(decision: &Decision) -> Option<BTreeSet<NodeId>> {
    match decision {
        Decision::Preemption(preemption) => Some(BTreeSet::from([preemption.node.clone()])),
        Decision::AppRandom(random) => Some(BTreeSet::from([random.node.clone()])),
        Decision::DeliveryOrder(_)
        | Decision::RngDraw(_)
        | Decision::Override(_)
        | Decision::Selection(_) => None,
    }
}

pub(super) fn decisions_are_independent(
    left: &Decision,
    right: &Decision,
    policy: &PartialOrderReductionPolicy,
) -> bool {
    if !policy.proves_independent(left, right) {
        return false;
    }
    let (Some(left_nodes), Some(right_nodes)) =
        (decision_touched_nodes(left), decision_touched_nodes(right))
    else {
        return false;
    };
    if !left_nodes.is_disjoint(&right_nodes) {
        return false;
    }
    decisions_have_commuting_resources(left, right)
}

pub(super) fn decisions_have_commuting_resources(left: &Decision, right: &Decision) -> bool {
    match (left, right) {
        (Decision::Preemption(_), Decision::Preemption(_))
        | (Decision::Preemption(_), Decision::AppRandom(_))
        | (Decision::AppRandom(_), Decision::Preemption(_)) => true,
        (Decision::AppRandom(left), Decision::AppRandom(right)) => left.stream != right.stream,
        _ => false,
    }
}

pub(super) fn decision_reduction_order_key(decision: &Decision) -> ContentHash {
    Schedule::empty().appended(decision.clone()).content_hash()
}

pub(super) fn partial_order_cover(
    graph: &mut TemporalGraph,
    decision: Decision,
    configuration: Configuration,
    policy: &FrontierReductionPolicy,
) -> Result<Option<FrontierCoveredChild>, EngineError> {
    let Some(representative) =
        partial_order_canonical_representative(&configuration, &policy.partial_order)
    else {
        return Ok(None);
    };
    graph.record_checkpoint_closure(&representative)?;
    let reduction_key = partial_order_reduction_key(&representative, &configuration);
    Ok(Some(FrontierCoveredChild {
        decision,
        configuration,
        representative: representative.id(),
        reason: FrontierReductionReason::PartialOrder,
        reduction_key: reduction_key.fingerprint,
    }))
}

pub(super) fn partial_order_canonical_representative(
    configuration: &Configuration,
    policy: &PartialOrderReductionPolicy,
) -> Option<Configuration> {
    let mut decisions = configuration.schedule.decisions().to_vec();
    let mut changed = false;
    let mut swapped = true;
    while swapped {
        swapped = false;
        for index in 1..decisions.len() {
            let left = &decisions[index - 1];
            let right = &decisions[index];
            if right.reduction_order_key() < left.reduction_order_key()
                && right.is_independent_from(left, policy)
            {
                decisions.swap(index - 1, index);
                changed = true;
                swapped = true;
            }
        }
    }
    changed.then(|| Configuration {
        def: configuration.def.clone(),
        schedule: schedule_from_decisions(decisions),
    })
}

pub(super) fn schedule_from_decisions(decisions: Vec<Decision>) -> Schedule {
    Schedule::from_decisions(decisions)
}

pub(super) fn minimization_candidates(
    seed: Seed,
    artifact: ContentHash,
    schedule: &Schedule,
) -> Vec<MinimizationCandidate> {
    let decisions = schedule.decisions();
    let mut candidates = Vec::new();
    for kept_len in 0..decisions.len() {
        collect_minimization_candidates_for_len(
            seed,
            artifact,
            decisions,
            kept_len,
            0,
            &mut Vec::new(),
            &mut candidates,
        );
    }
    candidates.sort_by_key(|candidate| {
        (
            candidate.schedule.len(),
            candidate.order_key,
            candidate.removed_indices.clone(),
        )
    });
    candidates
}

pub(super) fn collect_minimization_candidates_for_len(
    seed: Seed,
    artifact: ContentHash,
    decisions: &[Decision],
    kept_len: usize,
    start: usize,
    kept_indices: &mut Vec<usize>,
    candidates: &mut Vec<MinimizationCandidate>,
) {
    if kept_indices.len() == kept_len {
        candidates.push(minimization_candidate_from_kept_indices(
            seed,
            artifact,
            decisions,
            kept_indices,
        ));
        return;
    }
    let remaining = kept_len - kept_indices.len();
    let max_start = decisions.len().saturating_sub(remaining);
    for index in start..=max_start {
        kept_indices.push(index);
        collect_minimization_candidates_for_len(
            seed,
            artifact,
            decisions,
            kept_len,
            index + 1,
            kept_indices,
            candidates,
        );
        kept_indices.pop();
    }
}

pub(super) fn minimization_candidate_from_kept_indices(
    seed: Seed,
    artifact: ContentHash,
    decisions: &[Decision],
    kept_indices: &[usize],
) -> MinimizationCandidate {
    let kept = kept_indices.iter().copied().collect::<BTreeSet<_>>();
    let schedule = Schedule::from_decisions(
        kept_indices
            .iter()
            .copied()
            .map(|index| decisions[index].clone()),
    );
    let removed_indices = (0..decisions.len())
        .filter(|index| !kept.contains(index))
        .collect::<Vec<_>>();
    let removed_decisions = removed_indices
        .iter()
        .copied()
        .map(|index| decisions[index].clone())
        .collect::<Vec<_>>();
    MinimizationCandidate {
        order_key: minimization_candidate_key(seed, artifact, &schedule, &removed_indices),
        removed_indices,
        removed_decisions,
        schedule,
    }
}

pub(super) fn minimization_candidate_key(
    seed: Seed,
    artifact: ContentHash,
    schedule: &Schedule,
    removed_indices: &[usize],
) -> ContentHash {
    let removed = removed_indices
        .iter()
        .map(|index| index.to_string())
        .collect::<Vec<_>>()
        .join(",");
    ContentHash::from_canonical_material(
        "crucible.minimization.candidate.v1",
        &format!(
            "seed={}\nartifact={}\nkept_schedule={}\nremoved={removed}",
            seed.to_hex(),
            content_hash_hex(artifact),
            content_hash_hex(schedule.content_hash())
        ),
    )
}

pub(super) fn partial_order_reduction_key(
    representative: &Configuration,
    covered: &Configuration,
) -> PartialOrderReductionKey {
    PartialOrderReductionKey {
        fingerprint: ContentHash::from_canonical_material(
            "crucible.model.partial-order-reduction.v1",
            &format!(
                "representative={}\ncovered={}",
                content_hash_hex(representative.id()),
                content_hash_hex(covered.id())
            ),
        ),
    }
}

pub(super) fn checkpoint_symmetry_reduction_key(
    checkpoint: &Checkpoint,
    classes: &SymmetryReductionClasses,
) -> Option<SymmetryReductionKey> {
    if checkpoint.coverage_fingerprint == ContentHash::default() || classes.is_empty() {
        return None;
    }
    let state = checkpoint.state.as_ref()?;
    let labels = canonical_symmetry_node_labels(checkpoint, state, classes)?;

    let mut lines = vec![
        format!("scenario_ref={}", content_hash_hex(checkpoint.scenario_ref)),
        format!(
            "coverage_fingerprint={}",
            content_hash_hex(checkpoint.coverage_fingerprint)
        ),
        format!("virtual_time_ticks={}", checkpoint.virtual_time.ticks),
    ];
    push_symmetry_checkpoint_lines(checkpoint, &labels, &mut lines)?;
    push_symmetry_materialized_state_lines(state, &labels, &mut lines)?;
    Some(SymmetryReductionKey {
        fingerprint: ContentHash::from_canonical_material(
            "crucible.model.symmetry-reduction.v1",
            &lines.join("\n"),
        ),
    })
}

pub(super) fn canonical_symmetry_node_labels(
    checkpoint: &Checkpoint,
    state: &MaterializedState,
    classes: &SymmetryReductionClasses,
) -> Option<BTreeMap<NodeId, String>> {
    let mut labels = BTreeMap::new();
    let mut class_members: BTreeMap<&SymmetryClassId, Vec<(String, NodeId)>> = BTreeMap::new();
    for node in symmetry_nodes(checkpoint, state) {
        if let Some(class) = classes.classes.get(&node) {
            class_members.entry(class).or_default().push((
                symmetry_node_local_signature(checkpoint, state, &node),
                node,
            ));
        } else {
            labels.insert(
                node.clone(),
                format!("node:{}:{}", node.name.len(), node.name),
            );
        }
    }

    for (class, mut members) in class_members {
        members.sort_by(|left, right| left.0.cmp(&right.0).then_with(|| left.1.cmp(&right.1)));
        for pair in members.windows(2) {
            if pair[0].0 == pair[1].0 {
                return None;
            }
        }
        for (index, (_, node)) in members.into_iter().enumerate() {
            labels.insert(
                node,
                format!("class:{}:{}:{index}", class.name.len(), class.name),
            );
        }
    }

    Some(labels)
}

pub(super) fn symmetry_nodes(
    checkpoint: &Checkpoint,
    state: &MaterializedState,
) -> BTreeSet<NodeId> {
    let mut nodes = BTreeSet::new();
    nodes.extend(checkpoint.node_blobs.keys().cloned());
    nodes.extend(checkpoint.node_icounts.keys().cloned());
    nodes.extend(state.vm_snapshots.keys().cloned());
    nodes.extend(state.scheduler.horizons.keys().cloned());
    nodes.extend(state.scheduler.pending_frames.keys().cloned());
    for frames in state.scheduler.pending_frames.values() {
        nodes.extend(frames.iter().map(|frame| frame.source.clone()));
    }
    for sequence in state.scheduler.event_sequences.next.keys() {
        nodes.insert(sequence.producer.node.clone());
        nodes.insert(sequence.consumer.node.clone());
    }
    for edge in &state.scheduler.effective_topology_edges {
        nodes.insert(edge.from.node.clone());
        nodes.insert(edge.to.node.clone());
    }
    for change in &state.scheduler.pending_topology_changes {
        use crate::scheduler::SchedulerTopologyChangeEffect;
        match &change.effect {
            SchedulerTopologyChangeEffect::ReplaceEffectiveEdges(edges)
            | SchedulerTopologyChangeEffect::UpdateEffectiveEdges(edges)
            | SchedulerTopologyChangeEffect::RestoreEffectiveEdges(edges) => {
                for edge in edges {
                    nodes.insert(edge.from.node.clone());
                    nodes.insert(edge.to.node.clone());
                }
            }
            SchedulerTopologyChangeEffect::RemoveEffectiveEdges(endpoints) => {
                for endpoint in endpoints {
                    nodes.insert(endpoint.from.node.clone());
                    nodes.insert(endpoint.to.node.clone());
                }
            }
        }
    }
    nodes.extend(
        state
            .scheduler
            .timers
            .timers
            .values()
            .map(|timer| timer.owner.clone()),
    );
    nodes
}

pub(super) fn symmetry_node_local_signature(
    checkpoint: &Checkpoint,
    state: &MaterializedState,
    node: &NodeId,
) -> String {
    let mut lines = Vec::new();
    match checkpoint.node_icounts.get(node) {
        Some(icount) => lines.push(format!("checkpoint.icount={}", icount.retired)),
        None => lines.push(String::from("checkpoint.icount=none")),
    }
    match checkpoint.node_blobs.get(node) {
        Some(blob) => push_node_blob_ref_lines("checkpoint.blob", blob, &mut lines),
        None => lines.push(String::from("checkpoint.blob=none")),
    }
    match state.vm_snapshots.get(node) {
        Some(snapshot) => {
            push_node_blob_ref_lines("state.vm.blob", &snapshot.blob, &mut lines);
            lines.push(format!("state.vm.icount={}", snapshot.icount.retired));
        }
        None => lines.push(String::from("state.vm=none")),
    }
    lines.join("\n")
}

pub(super) fn push_symmetry_checkpoint_lines(
    checkpoint: &Checkpoint,
    labels: &BTreeMap<NodeId, String>,
    lines: &mut Vec<String>,
) -> Option<()> {
    let mut icount_lines = Vec::new();
    for (node, icount) in &checkpoint.node_icounts {
        icount_lines.push(format!(
            "checkpoint.icount.node={}\ncheckpoint.icount.retired={}",
            labels.get(node)?,
            icount.retired
        ));
    }
    icount_lines.sort();
    lines.push(format!("checkpoint.icounts={}", icount_lines.len()));
    lines.extend(icount_lines);

    let mut blob_lines = Vec::new();
    for (node, blob) in &checkpoint.node_blobs {
        let mut entry = vec![format!("checkpoint.blob.node={}", labels.get(node)?)];
        push_node_blob_ref_lines("checkpoint.blob", blob, &mut entry);
        blob_lines.push(entry.join("\n"));
    }
    blob_lines.sort();
    lines.push(format!("checkpoint.blobs={}", blob_lines.len()));
    lines.extend(blob_lines);
    Some(())
}

pub(super) fn push_symmetry_materialized_state_lines(
    state: &MaterializedState,
    labels: &BTreeMap<NodeId, String>,
    lines: &mut Vec<String>,
) -> Option<()> {
    let mut vm_lines = Vec::new();
    for (node, snapshot) in &state.vm_snapshots {
        let mut entry = vec![format!("state.vm.node={}", labels.get(node)?)];
        push_node_blob_ref_lines("state.vm.blob", &snapshot.blob, &mut entry);
        entry.push(format!("state.vm.icount={}", snapshot.icount.retired));
        vm_lines.push(entry.join("\n"));
    }
    vm_lines.sort();
    lines.push(format!("state.vm_snapshots={}", vm_lines.len()));
    lines.extend(vm_lines);

    let mut overlay_lines = Vec::new();
    for (device, overlay) in &state.device_overlays {
        let mut entry = vec![
            format!("state.overlay.device_len={}", device.name.len()),
            format!("state.overlay.device={}", device.name),
            format!("state.overlay.parent={}", content_hash_hex(overlay.parent)),
            format!("state.overlay.delta={}", content_hash_hex(overlay.delta)),
            format!(
                "state.overlay.resolved={}",
                content_hash_hex(overlay.resolved)
            ),
        ];
        push_symmetry_device_rng_lines("state.overlay.rng", &overlay.rng, &mut entry);
        overlay_lines.push(entry.join("\n"));
    }
    overlay_lines.sort();
    lines.push(format!("state.device_overlays={}", overlay_lines.len()));
    lines.extend(overlay_lines);

    push_symmetry_scheduler_lines(&state.scheduler, labels, lines)?;
    push_symmetry_decision_rng_lines("state.decision_rng", &state.decision_rng, lines);
    push_symmetry_event_log_lines(state.event_log, lines);
    Some(())
}

pub(super) fn scheduling_node_kind_label(kind: SchedulingNodeKind) -> &'static str {
    match kind {
        SchedulingNodeKind::Vm => "vm",
        SchedulingNodeKind::Disk => "disk",
        SchedulingNodeKind::NineP => "ninep",
        SchedulingNodeKind::Network => "network",
        SchedulingNodeKind::ControlPlane => "control-plane",
    }
}

pub(super) fn push_symmetry_scheduler_lines(
    scheduler: &SchedulerState,
    labels: &BTreeMap<NodeId, String>,
    lines: &mut Vec<String>,
) -> Option<()> {
    let mut horizon_lines = Vec::new();
    for (node, horizon) in &scheduler.horizons {
        horizon_lines.push(format!(
            "scheduler.horizon.node={}\nscheduler.horizon.ticks={}",
            labels.get(node)?,
            horizon.ticks
        ));
    }
    horizon_lines.sort();
    lines.push(format!("scheduler.horizons={}", horizon_lines.len()));
    lines.extend(horizon_lines);

    let mut pending_lines = Vec::new();
    for (node, frames) in &scheduler.pending_frames {
        let mut entry = vec![
            format!("scheduler.pending.node={}", labels.get(node)?),
            format!("scheduler.pending.frames={}", frames.len()),
        ];
        for frame in frames {
            entry.push(format!(
                "scheduler.pending.source={}",
                labels.get(&frame.source)?
            ));
            entry.push(format!("scheduler.pending.sequence={}", frame.sequence));
            entry.push(format!(
                "scheduler.pending.delivery_icount={}",
                frame.delivery_icount.retired
            ));
            entry.push(format!(
                "scheduler.pending.payload={}",
                content_hash_hex(frame.payload)
            ));
        }
        pending_lines.push(entry.join("\n"));
    }
    pending_lines.sort();
    lines.push(format!("scheduler.pending={}", pending_lines.len()));
    lines.extend(pending_lines);

    lines.push(format!(
        "scheduler.network_link_cursors={}",
        scheduler.network_link_cursors.len()
    ));
    for (link, cursor) in &scheduler.network_link_cursors {
        lines.push(format!(
            "scheduler.network_link.name_len={}\nscheduler.network_link.name={}\nscheduler.network_link.current_icount={}\nscheduler.network_link.next_sequence={}\nscheduler.network_link.rng_position={}\nscheduler.network_link.inflight={}",
            link.name.len(),
            link.name,
            cursor.current_icount,
            cursor.next_sequence,
            cursor.rng_position,
            cursor.inflight.len(),
        ));
        for pending in &cursor.inflight {
            lines.push(format!(
                "scheduler.network_link.pending.sequence={}\nscheduler.network_link.pending.delivery_icount={}\nscheduler.network_link.pending.frame_id={}\nscheduler.network_link.pending.payload={}",
                pending.sequence,
                pending.delivery_icount.retired,
                pending.frame_id,
                content_hash_hex(pending.payload),
            ));
        }
    }

    lines.push(format!(
        "scheduler.pending_device_decisions={}",
        scheduler.pending_device_decisions.len()
    ));
    for (index, decision) in scheduler.pending_device_decisions.iter().enumerate() {
        push_decision_lines(index, decision, lines);
    }

    let mut sequence_lines = Vec::new();
    for (key, next) in &scheduler.event_sequences.next {
        sequence_lines.push(format!(
            "scheduler.sequence.producer={}:{}\nscheduler.sequence.consumer={}:{}\nscheduler.sequence.next={}",
            labels.get(&key.producer.node)?,
            scheduling_node_kind_label(key.producer.kind),
            labels.get(&key.consumer.node)?,
            scheduling_node_kind_label(key.consumer.kind),
            next
        ));
    }
    sequence_lines.sort();
    lines.push(format!(
        "scheduler.event_sequences={}",
        sequence_lines.len()
    ));
    lines.extend(sequence_lines);
    lines.push(format!(
        "scheduler.topology_epoch={}",
        scheduler.topology_epoch
    ));
    lines.push(format!(
        "scheduler.effective_topology_edges={}",
        scheduler.effective_topology_edges.len()
    ));
    for edge in &scheduler.effective_topology_edges {
        push_symmetry_topology_edge_lines("scheduler.effective_topology", edge, labels, lines)?;
    }
    lines.push(format!(
        "scheduler.pending_topology_changes={}",
        scheduler.pending_topology_changes.len()
    ));
    for change in &scheduler.pending_topology_changes {
        push_symmetry_topology_change_lines(change, labels, lines)?;
    }

    let mut timer_lines = Vec::new();
    for (timer, state) in &scheduler.timers.timers {
        timer_lines.push(format!(
            "scheduler.timer.name_len={}\nscheduler.timer.name={}\nscheduler.timer.owner={}\nscheduler.timer.armed_at={}\nscheduler.timer.fire_at={}\nscheduler.timer.fire_icount={}",
            timer.name.len(),
            timer.name,
            labels.get(&state.owner)?,
            state.armed_at.ticks,
            state.fire_at.ticks,
            state.fire_icount.retired
        ));
    }
    timer_lines.sort();
    lines.push(format!("scheduler.timers={}", timer_lines.len()));
    lines.extend(timer_lines);

    let mut search_frontier_lines = Vec::new();
    for (index, choice) in scheduler.search_frontier.choices().iter().enumerate() {
        let mut entry = Vec::new();
        entry.push(format!(
            "choice[{index}].decisions={}",
            choice.decisions().len()
        ));
        for (decision_index, decision) in choice.decisions().iter().enumerate() {
            push_decision_lines(decision_index, decision, &mut entry);
        }
        search_frontier_lines.push(entry.join("\n"));
    }
    search_frontier_lines.sort();
    lines.push(format!(
        "scheduler.search_frontier.decisions={}",
        search_frontier_lines.len()
    ));
    lines.extend(search_frontier_lines);
    Some(())
}

pub(super) fn push_symmetry_topology_edge_lines(
    prefix: &str,
    edge: &crate::scheduler::SchedulerLookaheadEdge,
    labels: &BTreeMap<NodeId, String>,
    lines: &mut Vec<String>,
) -> Option<()> {
    lines.push(format!(
        "{prefix}.from={}:{}\n{prefix}.to={}:{}\n{prefix}.minimum_latency_ns={}",
        labels.get(&edge.from.node)?,
        scheduling_node_kind_label(edge.from.kind),
        labels.get(&edge.to.node)?,
        scheduling_node_kind_label(edge.to.kind),
        edge.minimum_latency.nanos,
    ));
    Some(())
}

pub(super) fn push_symmetry_topology_change_lines(
    change: &crate::scheduler::SchedulerTopologyChange,
    labels: &BTreeMap<NodeId, String>,
    lines: &mut Vec<String>,
) -> Option<()> {
    use crate::scheduler::{SchedulerTopologyChangeEffect, SchedulerTopologyChangeTrigger};

    lines.push(format!(
        "scheduler.pending_topology.sequence={}\nscheduler.pending_topology.trigger={}\nscheduler.pending_topology.activation_ns={}",
        change.sequence,
        match change.trigger {
            SchedulerTopologyChangeTrigger::EdgeRemoval => "edge-removal",
            SchedulerTopologyChangeTrigger::EdgeRestore => "edge-restore",
            SchedulerTopologyChangeTrigger::LatencyChange => "latency-change",
        },
        change
            .activation_time
            .map_or_else(|| String::from("none"), |at| at.nanos.to_string()),
    ));
    match &change.effect {
        SchedulerTopologyChangeEffect::ReplaceEffectiveEdges(edges)
        | SchedulerTopologyChangeEffect::UpdateEffectiveEdges(edges)
        | SchedulerTopologyChangeEffect::RestoreEffectiveEdges(edges) => {
            lines.push(format!(
                "scheduler.pending_topology.effect={}\nscheduler.pending_topology.edges={}",
                match &change.effect {
                    SchedulerTopologyChangeEffect::ReplaceEffectiveEdges(_) => "replace",
                    SchedulerTopologyChangeEffect::UpdateEffectiveEdges(_) => "update",
                    SchedulerTopologyChangeEffect::RestoreEffectiveEdges(_) => "restore",
                    SchedulerTopologyChangeEffect::RemoveEffectiveEdges(_) => return None,
                },
                edges.len(),
            ));
            for edge in edges {
                push_symmetry_topology_edge_lines(
                    "scheduler.pending_topology.edge",
                    edge,
                    labels,
                    lines,
                )?;
            }
        }
        SchedulerTopologyChangeEffect::RemoveEffectiveEdges(endpoints) => {
            lines.push(format!(
                "scheduler.pending_topology.effect=remove\nscheduler.pending_topology.edges={}",
                endpoints.len()
            ));
            for endpoint in endpoints {
                lines.push(format!(
                    "scheduler.pending_topology.edge.from={}:{}\nscheduler.pending_topology.edge.to={}:{}",
                    labels.get(&endpoint.from.node)?,
                    scheduling_node_kind_label(endpoint.from.kind),
                    labels.get(&endpoint.to.node)?,
                    scheduling_node_kind_label(endpoint.to.kind),
                ));
            }
        }
    }
    Some(())
}

pub(super) fn push_symmetry_device_rng_lines(
    prefix: &str,
    state: &DeviceRngState,
    lines: &mut Vec<String>,
) {
    lines.push(format!("{prefix}.streams={}", state.streams.len()));
    for (stream, position) in &state.streams {
        push_rng_stream_lines(prefix, stream, lines);
        lines.push(format!("{prefix}.draws={}", position.draws));
    }
}

pub(super) fn push_symmetry_decision_rng_lines(
    prefix: &str,
    state: &DecisionRngState,
    lines: &mut Vec<String>,
) {
    lines.push(format!("{prefix}.positions={}", state.positions.len()));
    for (stream, position) in &state.positions {
        push_rng_stream_lines(prefix, stream, lines);
        lines.push(format!("{prefix}.draws={}", position.draws));
    }
}

pub(super) fn push_rng_stream_lines(prefix: &str, stream: &RngStreamId, lines: &mut Vec<String>) {
    lines.push(format!(
        "{prefix}.stream_domain_len={}",
        stream.domain.len()
    ));
    lines.push(format!("{prefix}.stream_domain={}", stream.domain));
    lines.push(format!("{prefix}.stream_len={}", stream.name.len()));
    lines.push(format!("{prefix}.stream={}", stream.name));
}

pub(super) fn push_symmetry_event_log_lines(event_log: EventLogOffset, lines: &mut Vec<String>) {
    lines.push(format!(
        "event_log.prefix={}",
        content_hash_hex(event_log.prefix)
    ));
    lines.push(format!(
        "event_log.appended_segment={}",
        event_log
            .appended_segment
            .map(content_hash_hex)
            .unwrap_or_else(|| String::from("none"))
    ));
    lines.push(format!("event_log.bytes={}", event_log.bytes));
    lines.push(format!("event_log.events={}", event_log.events));
}

mod reduction_helpers;

pub(in crate::model) use reduction_helpers::*;
