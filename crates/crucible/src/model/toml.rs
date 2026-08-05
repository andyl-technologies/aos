//! TOML schema types and semantic conversion helpers.

use super::*;
pub(super) fn validate_link_transport(link: &LinkDef) -> Result<(), EngineError> {
    let latency = link.latency();
    let jitter = link.jitter();
    if latency < MIN_LINK_LATENCY {
        return Err(EngineError::WorldLinkLatencyBelowFloor {
            link: link.clone(),
            latency,
            minimum: MIN_LINK_LATENCY,
        });
    }
    if latency
        .nanos
        .checked_sub(jitter.nanos)
        .is_none_or(|effective| effective < MIN_LINK_LATENCY.nanos)
    {
        return Err(EngineError::WorldLinkJitterBelowLatencyFloor {
            link: link.clone(),
            latency,
            jitter,
            minimum: MIN_LINK_LATENCY,
        });
    }

    Ok(())
}

pub(super) const SCENARIO_FORM_BINARY_MAGIC_V3: &[u8] = b"crucible.scenario-def-form.v3\0";
pub(super) const REPRODUCTION_ARTIFACT_BINARY_MAGIC_V3: &[u8] =
    b"crucible.reproduction-artifact.v3\0";
pub(super) const SCHEDULE_BINARY_MAGIC: &[u8] = b"crucible.schedule.v1\0";
pub(super) const WORLD_BINARY_MAGIC_V3: &[u8] = b"crucible.world.v3\0";
pub(super) const PLAN_BINARY_MAGIC: &[u8] = b"crucible.plan.v3\0";
pub(super) const PROPERTIES_BINARY_MAGIC: &[u8] = b"crucible.properties.v1\0";
pub(super) const PREDICATE_BINARY_MAGIC: &[u8] = b"crucible.predicate.v1\0";
pub(super) const ACTION_BINARY_MAGIC: &[u8] = b"crucible.action.v1\0";
pub(super) const CONTROL_OPERATION_KIND_BINARY_MAGIC: &[u8] =
    b"crucible.control-operation-kind.v1\0";
pub(super) const SEED_BINARY_MAGIC: &[u8] = b"crucible.seed.v1\0";
pub(super) const CHECKPOINT_BINARY_MAGIC: &[u8] = b"crucible.checkpoint.v1\0";
pub(super) const MAX_SCENARIO_BINARY_COLLECTION_ITEMS: usize = 1_000_000;
pub(super) const MAX_SCENARIO_BINARY_STRING_BYTES: usize = 16 * 1024 * 1024;
pub(super) const MAX_SCENARIO_BINARY_BLOB_BYTES: usize = 256 * 1024 * 1024;
pub(super) const MAX_REPRODUCTION_SCENARIO_BLOB_BYTES: usize =
    MAX_SCENARIO_BINARY_BLOB_BYTES + HARD_FAULT_SIGNAL_PLAN_WIRE_BYTES;
pub(super) const MAX_SCENARIO_TOML_BYTES: usize = 256 * 1024 * 1024;

pub(super) fn validate_scenario_toml_size(input: &str) -> Result<(), EngineError> {
    if input.len() > MAX_SCENARIO_TOML_BYTES {
        return Err(scenario_serialization_error(format!(
            "scenario TOML contains {} bytes, hard limit is {MAX_SCENARIO_TOML_BYTES}",
            input.len()
        )));
    }
    Ok(())
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct ScenarioDefToml {
    pub(super) schema: ScenarioSchemaToml,
    pub(super) scenario: ScenarioHeaderToml,
    pub(super) world: WorldToml,
    pub(super) plan: PlanToml,
    pub(super) properties: PropertiesToml,
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize)]
pub(super) enum ScenarioSchemaToml {
    #[serde(rename = "crucible.scenario.v2")]
    V2,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct ScenarioHeaderToml {
    pub(super) id: String,
    pub(super) seed: String,
    #[serde(
        deserialize_with = "deserialize_u64_toml_number_or_string",
        serialize_with = "serialize_u64_toml_number_or_string"
    )]
    pub(super) app_random_draw_cap: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct WorldToml {
    pub(super) id: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub(super) node: Vec<WorldNodeDefToml>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub(super) link: Vec<LinkToml>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub(super) fault_domain: Vec<WorldFaultDomain>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub(super) network_interface: Vec<WorldNetworkInterface>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub(super) network_segment: Vec<WorldNetworkSegment>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub(super) network_medium: Vec<WorldNetworkMedium>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub(super) network_forwarder: Vec<WorldNetworkForwarder>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub(super) network_queue: Vec<WorldNetworkQueue>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub(super) network_path: Vec<WorldNetworkPath>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub(super) network_attachment: Vec<WorldNetworkAttachment>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub(super) network_contact_plan: Vec<WorldNetworkContactPlan>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub(super) mobile_endpoint: Vec<WorldMobileEndpoint>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub(super) storage_device: Vec<WorldStorageFaultDevice>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub(super) node_fault_capabilities: Vec<WorldNodeFaultCapabilities>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(untagged)]
pub(super) enum WorldNodeDefToml {
    Vm(WorldNodeToml),
    Io(WorldIoNodeToml),
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub(super) enum WorldIoNodeToml {
    Block {
        id: String,
        owner: String,
        shift_bits: u8,
        artifact: String,
        artifact_length: u64,
        read_base_ns: u64,
        write_base_ns: u64,
        flush_ns: u64,
        get_length_ns: u64,
        per_byte_ns: u64,
    },
    NineP {
        id: String,
        owner: String,
        shift_bits: u8,
        artifact: String,
        control_ns: u64,
        data_ns: u64,
        per_byte_ns: u64,
    },
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct WorldNodeToml {
    pub(super) id: String,
    #[serde(default = "default_vm_arch_toml")]
    pub(super) arch: VmArchitectureToml,
    #[serde(default = "default_world_node_memory_mib")]
    pub(super) memory_mib: u32,
    #[serde(default)]
    pub(super) cmdline: String,
    pub(super) smp_vcpus: u16,
    pub(super) icount_shift: u8,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(super) kernel: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(super) root_image: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(super) initrd: Option<String>,
    pub(super) ready_point: ReadyPointToml,
    pub(super) white_box: WhiteBoxToml,
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[serde(rename_all = "snake_case")]
pub(super) enum VmArchitectureToml {
    X86_64,
    Aarch64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub(super) enum ReadyPointToml {
    FixedIcount { retired: u64 },
    NetworkIdle { window_nanos: u64 },
    ConsoleMarker { marker: String },
    AgentSignal,
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[serde(rename_all = "snake_case")]
pub(super) enum WhiteBoxToml {
    Disabled,
    Enabled,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct LinkToml {
    pub(super) endpoint_a: String,
    pub(super) endpoint_b: String,
    pub(super) latency_nanos: u64,
    pub(super) jitter_nanos: u64,
    pub(super) loss_millionths: u32,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(super) bandwidth_bps: Option<u64>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct PlanToml {
    pub(super) id: String,
    pub(super) fault_model: FaultModelToml,
    pub(super) fault_signal_semantic_version: u16,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub(super) signal: Vec<toml::Value>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub(super) fault_binding: Vec<toml::Value>,
    #[serde(default)]
    pub(super) resource_limits: SignalResourceLimits,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(super) kind: Option<PlanKindToml>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub(super) entry: Vec<PlanEntryToml>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub(super) fault_entry: Vec<FaultPlanEntryToml>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub(super) event: Vec<EventToml>,
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(super) enum FaultModelToml {
    SignalBindingsV1,
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[serde(rename_all = "snake_case")]
pub(super) enum PlanKindToml {
    Entries,
    FaultPlan,
    EventGraph,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub(super) enum PlanEntryToml {
    Activate {
        at_ticks: u64,
        tag: String,
        fault: MembershipFaultToml,
    },
    Heal {
        at_ticks: u64,
        tag: String,
    },
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub(super) enum FaultPlanEntryToml {
    At {
        at_ticks: u64,
        duration_nanos: u64,
        tag: String,
        fault: FaultToml,
    },
    PermanentAt {
        at_ticks: u64,
        tag: String,
        fault: FaultToml,
    },
    Heal {
        at_ticks: u64,
        tag: String,
    },
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct EventToml {
    pub(super) id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(super) trigger: Option<PredicateToml>,
    pub(super) action: ActionToml,
    #[serde(default = "default_fire_policy_toml")]
    pub(super) policy: FirePolicyToml,
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[serde(rename_all = "snake_case")]
pub(super) enum FirePolicyToml {
    Once,
    Repeatable,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub(super) enum ActionToml {
    InjectFault {
        tag: String,
        fault: MembershipFaultToml,
    },
    HealFault {
        tag: String,
    },
    ArmTimer {
        name: String,
        after_nanos: u64,
    },
    CancelTimer {
        name: String,
    },
    StartNode {
        node: String,
    },
    StopNode {
        node: String,
    },
    CreateSavepoint {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        label: Option<String>,
    },
    Fork {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        label: Option<String>,
    },
    Pass,
    Fail {
        reason: String,
    },
    Log {
        level: LogLevelToml,
        message: String,
    },
    Group {
        actions: Vec<ActionToml>,
    },
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[serde(rename_all = "snake_case")]
pub(super) enum LogLevelToml {
    Debug,
    Info,
    Warn,
    Error,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub(super) enum MembershipFaultToml {
    Crash {
        node: String,
        restart: RestartToml,
    },
    Partition {
        endpoint_a: String,
        endpoint_b: String,
        direction: PartitionDirectionToml,
    },
    Isolate {
        node: String,
    },
    NotYetJoined {
        node: String,
    },
    Taxonomy {
        fault: FaultToml,
    },
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub(super) enum FaultToml {
    NetworkPartition {
        link: String,
        direction: PartitionDirectionToml,
    },
    NetworkLoss {
        link: String,
        rate_basis_points: u32,
    },
    NetworkReorder {
        link: String,
        window_nanos: u64,
    },
    NetworkDuplicate {
        link: String,
        rate_basis_points: u32,
        gap_nanos: u64,
    },
    NetworkCorruptionBitFlip {
        link: String,
        rate_basis_points: u32,
        max_bits: u32,
    },
    NetworkCorruptionFieldMutation {
        link: String,
        rate_basis_points: u32,
    },
    NetworkCorruptionTruncation {
        link: String,
        rate_basis_points: u32,
        max_bytes: u64,
    },
    NetworkBandwidth {
        link: String,
        bits_per_second: u64,
    },
    NetworkLatencyBump {
        link: String,
        extra_nanos: u64,
    },
    NodeCrash {
        node: String,
        restart: RestartToml,
    },
    NodeSlow {
        node: String,
        factor_basis_points: u32,
    },
    NodeClockSkew {
        node: String,
        offset_nanos: i64,
    },
    BlockLatency {
        device: String,
        extra_nanos: u64,
        jitter_nanos: u64,
    },
    BlockFailure {
        device: String,
        rate_basis_points: u32,
        mode: IoFailureModeToml,
    },
    BlockReorder {
        device: String,
        window_nanos: u64,
    },
    BlockDuplicate {
        device: String,
        rate_basis_points: u32,
        gap_nanos: u64,
    },
    BlockCorruption {
        device: String,
        rate_basis_points: u32,
        bit_flips: u32,
    },
    BlockBandwidth {
        device: String,
        bits_per_second: u64,
    },
    NinePLatency {
        device: String,
        extra_nanos: u64,
        jitter_nanos: u64,
    },
    NinePFailure {
        device: String,
        rate_basis_points: u32,
        errno_code: i32,
    },
    NinePReorder {
        device: String,
        window_nanos: u64,
    },
    NinePDuplicate {
        device: String,
        rate_basis_points: u32,
        gap_nanos: u64,
    },
    NinePCorruption {
        device: String,
        rate_basis_points: u32,
        bit_flips: u32,
    },
    NinePBandwidth {
        device: String,
        bits_per_second: u64,
    },
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[serde(rename_all = "snake_case")]
pub(super) enum IoFailureModeToml {
    Drop,
    ErrorStatus,
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[serde(rename_all = "snake_case")]
pub(super) enum RestartToml {
    FromReadyPoint,
    FromLastCheckpoint,
    StayDown,
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[serde(rename_all = "snake_case")]
pub(super) enum PartitionDirectionToml {
    Bidirectional,
    EndpointAToEndpointB,
    EndpointBToEndpointA,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct PropertiesToml {
    pub(super) id: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub(super) assertion: Vec<AssertionToml>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct AssertionToml {
    pub(super) id: String,
    pub(super) message: String,
    pub(super) property: PropertyToml,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct PropertyToml {
    pub(super) kind: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(super) predicate: Option<PredicateToml>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(super) trigger: Option<PredicateToml>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(super) property: Option<PredicateToml>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(super) deadline_ticks: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(super) expectation: Option<ReachabilityExpectationToml>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(untagged)]
pub(super) enum PredicateToml {
    Dsl(String),
    Structured(PredicateTomlKind),
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub(super) enum PredicateTomlKind {
    At {
        at_ticks: u64,
    },
    After {
        duration_nanos: u64,
        of: String,
    },
    Timer {
        name: String,
    },
    NetworkMatch {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        link: Option<String>,
        predicate: FramePredicateToml,
    },
    ConsoleMatch {
        node: String,
        regex: String,
    },
    CoveragePoint {
        node: String,
        point: CodePointToml,
    },
    MemoryPredicate {
        node: String,
        place: MemPlaceToml,
        cmp: MemoryCmpToml,
        value: u64,
    },
    IoPattern {
        node: String,
        io_kind: IoEventKindToml,
    },
    NodeState {
        node: String,
        state: NodeLifecycleToml,
    },
    AssertionState {
        name: String,
        state: AssertionPhaseToml,
    },
    Quiescent,
    FaultActive {
        tag: String,
    },
    Named {
        name: String,
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        nodes: Vec<String>,
    },
    GuestMarker {
        marker: String,
    },
    AllOf {
        predicates: Vec<PredicateToml>,
    },
    AnyOf {
        predicates: Vec<PredicateToml>,
    },
    Once {
        predicate: Box<PredicateToml>,
    },
    Not {
        predicate: Box<PredicateToml>,
    },
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub(super) enum FramePredicateToml {
    Any,
    Exact { bytes_hex: String },
    Contains { needle_hex: String },
    Prefix { prefix_hex: String },
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub(super) enum CodePointToml {
    GuestAddress { address: u64 },
    Symbol { name: String },
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub(super) enum MemPlaceToml {
    PhysicalAddress {
        address: u64,
        width: MemoryWidthToml,
    },
    VirtualAddress {
        address: u64,
        width: MemoryWidthToml,
    },
    Symbol {
        name: String,
        width: MemoryWidthToml,
    },
    Register {
        name: String,
        width: MemoryWidthToml,
    },
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[serde(rename_all = "snake_case")]
pub(super) enum MemoryWidthToml {
    U8,
    U16,
    U32,
    U64,
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[serde(rename_all = "snake_case")]
pub(super) enum MemoryCmpToml {
    Eq,
    Ne,
    Lt,
    Le,
    Gt,
    Ge,
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[serde(rename_all = "snake_case")]
pub(super) enum IoEventKindToml {
    Any,
    BlockRead,
    BlockWrite,
    Fsync,
    NineP,
    Network,
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[serde(rename_all = "snake_case")]
pub(super) enum NodeLifecycleToml {
    Started,
    Crashed,
    Hung,
    Exited,
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[serde(rename_all = "snake_case")]
pub(super) enum AssertionPhaseToml {
    Satisfied,
    Violated,
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub(super) enum ReachabilityExpectationToml {
    Reachable {
        #[serde(default = "reachable_disposition_warn_toml")]
        on_unreached: ReachableDispositionToml,
    },
    Unreachable,
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[serde(rename_all = "snake_case")]
pub(super) enum ReachableDispositionToml {
    Warn,
    Fail,
}

pub(super) fn reachable_disposition_warn_toml() -> ReachableDispositionToml {
    ReachableDispositionToml::Warn
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct SeedToml {
    pub(super) bytes: String,
}

pub(super) fn serialize_u64_toml_number_or_string<S>(
    value: &u64,
    serializer: S,
) -> Result<S::Ok, S::Error>
where
    S: serde::Serializer,
{
    if *value <= i64::MAX as u64 {
        serializer.serialize_u64(*value)
    } else {
        serializer.serialize_str(&value.to_string())
    }
}

pub(super) fn deserialize_u64_toml_number_or_string<'de, D>(
    deserializer: D,
) -> Result<u64, D::Error>
where
    D: serde::Deserializer<'de>,
{
    struct NumberOrStringVisitor;

    impl de::Visitor<'_> for NumberOrStringVisitor {
        type Value = u64;

        fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
            formatter.write_str("a non-negative integer or decimal u64 string")
        }

        fn visit_u64<E>(self, value: u64) -> Result<Self::Value, E>
        where
            E: de::Error,
        {
            Ok(value)
        }

        fn visit_i64<E>(self, value: i64) -> Result<Self::Value, E>
        where
            E: de::Error,
        {
            u64::try_from(value).map_err(|_| E::custom("integer must be non-negative"))
        }

        fn visit_str<E>(self, value: &str) -> Result<Self::Value, E>
        where
            E: de::Error,
        {
            value
                .parse::<u64>()
                .map_err(|error| E::custom(format!("invalid u64 string `{value}`: {error}")))
        }
    }

    deserializer.deserialize_any(NumberOrStringVisitor)
}

pub(super) fn scenario_form_to_toml(
    form: &ScenarioDefForm,
) -> Result<ScenarioDefToml, EngineError> {
    Ok(ScenarioDefToml {
        schema: ScenarioSchemaToml::V2,
        scenario: ScenarioHeaderToml {
            id: format_content_hash_ref(form.id()),
            seed: format_seed_ref(form.seed),
            app_random_draw_cap: form.app_random_draw_cap,
        },
        world: world_to_toml(&form.world),
        plan: plan_to_toml(&form.plan)?,
        properties: properties_to_toml(&form.properties),
    })
}

pub(super) fn scenario_form_from_toml(
    toml: ScenarioDefToml,
) -> Result<ScenarioDefForm, EngineError> {
    let world = world_from_toml(toml.world)?;
    let (properties_id, assertions) = properties_assertions_from_toml(toml.properties)?;
    let plan = plan_from_toml_with_assertions(
        &world,
        assertions.iter().map(|assertion| assertion.id.clone()),
        toml.plan,
    )?;
    let raw_properties = Properties::from_assertions_for_world(&world, assertions)?;
    let properties = resolve_properties_dsl_for_context(&world, &plan, &raw_properties)?;
    validate_serialized_id("properties", properties_id, properties.content_hash())?;
    let seed = parse_seed_ref(&toml.scenario.seed)?;
    let form = ScenarioDefForm::from_components_with_app_random_draw_cap(
        &world,
        &plan,
        &properties,
        seed,
        toml.scenario.app_random_draw_cap,
    )?;
    let expected = parse_content_hash_ref(&toml.scenario.id)?;
    validate_serialized_id("scenario", expected, form.id())?;
    Ok(form)
}

pub(super) fn world_to_toml(world: &World) -> WorldToml {
    let fault_topology = world.fault_topology();
    WorldToml {
        id: format_content_hash_ref(world.id()),
        node: world
            .topology_nodes()
            .iter()
            .map(world_node_def_to_toml)
            .collect(),
        link: world.links().iter().map(link_to_toml).collect(),
        fault_domain: fault_topology.fault_domains.clone(),
        network_interface: fault_topology.network_interfaces.clone(),
        network_segment: fault_topology.network_segments.clone(),
        network_medium: fault_topology.network_media.clone(),
        network_forwarder: fault_topology.network_forwarders.clone(),
        network_queue: fault_topology.network_queues.clone(),
        network_path: fault_topology.network_paths.clone(),
        network_attachment: fault_topology.network_attachments.clone(),
        network_contact_plan: fault_topology.network_contact_plans.clone(),
        mobile_endpoint: fault_topology.mobile_endpoints.clone(),
        storage_device: fault_topology.storage_devices.clone(),
        node_fault_capabilities: fault_topology.node_capabilities.clone(),
    }
}

pub(super) fn world_from_toml(toml: WorldToml) -> Result<World, EngineError> {
    let fault_topology = WorldFaultTopology {
        fault_domains: toml.fault_domain,
        network_interfaces: toml.network_interface,
        network_segments: toml.network_segment,
        network_media: toml.network_medium,
        network_forwarders: toml.network_forwarder,
        network_queues: toml.network_queue,
        network_paths: toml.network_path,
        network_attachments: toml.network_attachment,
        network_contact_plans: toml.network_contact_plan,
        mobile_endpoints: toml.mobile_endpoint,
        storage_devices: toml.storage_device,
        node_capabilities: toml.node_fault_capabilities,
    };
    let id = parse_content_hash_ref(&toml.id)?;
    let topology_nodes = toml
        .node
        .into_iter()
        .map(world_node_def_from_toml)
        .collect::<Result<Vec<_>, _>>()?;
    let links = toml
        .link
        .into_iter()
        .map(link_from_toml)
        .collect::<Result<Vec<_>, _>>()?;
    let world = World::from_recorded_node_defs_and_links(id, topology_nodes, links)?
        .with_fault_topology(fault_topology)
        .map_err(|error| scenario_serialization_error(error.to_string()))?;
    validate_serialized_id("world", id, serialized_world_identity(&world))?;
    Ok(world)
}

pub(super) fn world_node_def_to_toml(node: &WorldNodeDef) -> WorldNodeDefToml {
    match node {
        WorldNodeDef::Vm(node) => WorldNodeDefToml::Vm(world_node_to_toml(node)),
        WorldNodeDef::Io(node) => WorldNodeDefToml::Io(world_io_node_to_toml(node)),
    }
}

pub(super) fn world_node_def_from_toml(
    toml: WorldNodeDefToml,
) -> Result<WorldNodeDef, EngineError> {
    match toml {
        WorldNodeDefToml::Vm(node) => world_node_from_toml(node).map(WorldNodeDef::Vm),
        WorldNodeDefToml::Io(node) => world_io_node_from_toml(node).map(WorldNodeDef::Io),
    }
}

pub(super) fn world_io_node_to_toml(node: &WorldIoNode) -> WorldIoNodeToml {
    let core = node.core;
    match &node.kind {
        WorldIoNodeKind::Block {
            base_image,
            base_length,
            latency,
        } => WorldIoNodeToml::Block {
            id: node.id.name.clone(),
            owner: node.owner.name.clone(),
            shift_bits: core.shift_bits,
            artifact: base_image.to_uri(),
            artifact_length: *base_length,
            read_base_ns: latency.read_base_ns,
            write_base_ns: latency.write_base_ns,
            flush_ns: latency.flush_ns,
            get_length_ns: latency.get_length_ns,
            per_byte_ns: latency.per_byte_ns,
        },
        WorldIoNodeKind::NineP { tree, latency } => WorldIoNodeToml::NineP {
            id: node.id.name.clone(),
            owner: node.owner.name.clone(),
            shift_bits: core.shift_bits,
            artifact: tree.to_uri(),
            control_ns: latency.control_ns,
            data_ns: latency.data_ns,
            per_byte_ns: latency.per_byte_ns,
        },
    }
}

pub(super) fn world_io_node_from_toml(toml: WorldIoNodeToml) -> Result<WorldIoNode, EngineError> {
    Ok(match toml {
        WorldIoNodeToml::Block {
            id,
            owner,
            shift_bits,
            artifact,
            artifact_length,
            read_base_ns,
            write_base_ns,
            flush_ns,
            get_length_ns,
            per_byte_ns,
        } => WorldIoNode::block(
            NodeId { name: id },
            NodeId { name: owner },
            WorldIoCoreConfig::new(shift_bits),
            ContentAddressedBlobRef::parse("world.node.block.artifact", &artifact)?,
            artifact_length,
            WorldBlockLatency::new(
                read_base_ns,
                write_base_ns,
                flush_ns,
                get_length_ns,
                per_byte_ns,
            ),
        ),
        WorldIoNodeToml::NineP {
            id,
            owner,
            shift_bits,
            artifact,
            control_ns,
            data_ns,
            per_byte_ns,
        } => WorldIoNode::ninep(
            NodeId { name: id },
            NodeId { name: owner },
            WorldIoCoreConfig::new(shift_bits),
            ContentAddressedBlobRef::parse("world.node.ninep.artifact", &artifact)?,
            WorldNinePLatency::new(control_ns, data_ns, per_byte_ns),
        ),
    })
}

pub(super) fn world_node_to_toml(node: &WorldNode) -> WorldNodeToml {
    WorldNodeToml {
        id: node.id.name.clone(),
        arch: vm_arch_to_toml(node.arch),
        memory_mib: node.memory_mib,
        cmdline: node.cmdline.clone(),
        smp_vcpus: node.smp_vcpus,
        icount_shift: node.icount_shift,
        kernel: node.kernel.map(ContentAddressedBlobRef::to_uri),
        root_image: node.root_image.map(ContentAddressedBlobRef::to_uri),
        initrd: node.initrd.map(ContentAddressedBlobRef::to_uri),
        ready_point: ready_point_to_toml(&node.ready_point),
        white_box: white_box_to_toml(node.white_box),
    }
}

pub(super) fn world_node_from_toml(toml: WorldNodeToml) -> Result<WorldNode, EngineError> {
    let kernel = parse_optional_blob_ref("kernel", toml.kernel)?;
    let root_image = parse_optional_blob_ref("root_image", toml.root_image)?;
    let initrd = parse_optional_blob_ref("initrd", toml.initrd)?;
    Ok(WorldNode {
        id: NodeId { name: toml.id },
        arch: vm_arch_from_toml(toml.arch),
        memory_mib: toml.memory_mib,
        cmdline: toml.cmdline,
        ready_point: ready_point_from_toml(toml.ready_point),
        white_box: white_box_from_toml(toml.white_box),
        smp_vcpus: toml.smp_vcpus,
        icount_shift: toml.icount_shift,
        kernel,
        root_image,
        initrd,
    })
}

pub(super) fn default_vm_arch_toml() -> VmArchitectureToml {
    vm_arch_to_toml(NodeTemplate::DEFAULT_ARCH)
}

pub(super) fn default_world_node_memory_mib() -> u32 {
    NodeTemplate::DEFAULT_MEMORY_MIB
}

pub(super) fn vm_arch_to_toml(arch: VmArchitecture) -> VmArchitectureToml {
    match arch {
        VmArchitecture::X86_64 => VmArchitectureToml::X86_64,
        VmArchitecture::Aarch64 => VmArchitectureToml::Aarch64,
    }
}

pub(super) fn vm_arch_from_toml(toml: VmArchitectureToml) -> VmArchitecture {
    match toml {
        VmArchitectureToml::X86_64 => VmArchitecture::X86_64,
        VmArchitectureToml::Aarch64 => VmArchitecture::Aarch64,
    }
}

pub(super) fn ready_point_to_toml(ready_point: &ReadyPoint) -> ReadyPointToml {
    match ready_point {
        ReadyPoint::FixedIcount { icount } => ReadyPointToml::FixedIcount {
            retired: icount.retired,
        },
        ReadyPoint::NetworkIdle { window } => ReadyPointToml::NetworkIdle {
            window_nanos: window.nanos,
        },
        ReadyPoint::ConsoleMarker { marker } => ReadyPointToml::ConsoleMarker {
            marker: marker.clone(),
        },
        ReadyPoint::AgentSignal => ReadyPointToml::AgentSignal,
    }
}

pub(super) fn ready_point_from_toml(toml: ReadyPointToml) -> ReadyPoint {
    match toml {
        ReadyPointToml::FixedIcount { retired } => ReadyPoint::FixedIcount {
            icount: Icount { retired },
        },
        ReadyPointToml::NetworkIdle { window_nanos } => ReadyPoint::NetworkIdle {
            window: SimDuration {
                nanos: window_nanos,
            },
        },
        ReadyPointToml::ConsoleMarker { marker } => ReadyPoint::ConsoleMarker { marker },
        ReadyPointToml::AgentSignal => ReadyPoint::AgentSignal,
    }
}

pub(super) fn white_box_to_toml(policy: WhiteBoxPolicy) -> WhiteBoxToml {
    match policy {
        WhiteBoxPolicy::Disabled => WhiteBoxToml::Disabled,
        WhiteBoxPolicy::Enabled => WhiteBoxToml::Enabled,
    }
}

pub(super) fn white_box_from_toml(toml: WhiteBoxToml) -> WhiteBoxPolicy {
    match toml {
        WhiteBoxToml::Disabled => WhiteBoxPolicy::Disabled,
        WhiteBoxToml::Enabled => WhiteBoxPolicy::Enabled,
    }
}

pub(super) fn link_to_toml(link: &LinkDef) -> LinkToml {
    let (endpoint_a, endpoint_b) = link.endpoints();
    LinkToml {
        endpoint_a: endpoint_a.name.clone(),
        endpoint_b: endpoint_b.name.clone(),
        latency_nanos: link.latency().nanos,
        jitter_nanos: link.jitter().nanos,
        loss_millionths: link.loss().millionths(),
        bandwidth_bps: link.bandwidth_bps(),
    }
}

pub(super) fn link_from_toml(toml: LinkToml) -> Result<LinkDef, EngineError> {
    LinkDef::with_transport(
        NodeId {
            name: toml.endpoint_a,
        },
        NodeId {
            name: toml.endpoint_b,
        },
        SimDuration {
            nanos: toml.latency_nanos,
        },
        SimDuration {
            nanos: toml.jitter_nanos,
        },
        LinkLossProbability::from_millionths(toml.loss_millionths)?,
        toml.bandwidth_bps,
    )
}

pub(super) fn plan_to_toml(plan: &Plan) -> Result<PlanToml, EngineError> {
    let fault_signals = FaultSignalAuthoringRows::from_plan(plan.fault_signals())
        .map_err(|error| scenario_serialization_error(error.to_string()))?;
    Ok(match &plan.kind {
        PlanKind::ScheduledEntries { entries } => PlanToml {
            id: format_content_hash_ref(plan.content_hash()),
            fault_model: FaultModelToml::SignalBindingsV1,
            fault_signal_semantic_version: fault_signals.semantic_version,
            signal: fault_signals.signals,
            fault_binding: fault_signals.bindings,
            resource_limits: fault_signals.resource_limits,
            kind: None,
            entry: entries.iter().map(plan_entry_to_toml).collect(),
            fault_entry: Vec::new(),
            event: Vec::new(),
        },
        PlanKind::FaultPlan { plan: fault_plan } => PlanToml {
            id: format_content_hash_ref(plan.content_hash()),
            fault_model: FaultModelToml::SignalBindingsV1,
            fault_signal_semantic_version: fault_signals.semantic_version,
            signal: fault_signals.signals,
            fault_binding: fault_signals.bindings,
            resource_limits: fault_signals.resource_limits,
            kind: Some(PlanKindToml::FaultPlan),
            entry: Vec::new(),
            fault_entry: fault_plan
                .entries()
                .iter()
                .map(fault_plan_entry_to_toml)
                .collect(),
            event: Vec::new(),
        },
        PlanKind::EventGraph { graph } => PlanToml {
            id: format_content_hash_ref(plan.content_hash()),
            fault_model: FaultModelToml::SignalBindingsV1,
            fault_signal_semantic_version: fault_signals.semantic_version,
            signal: fault_signals.signals,
            fault_binding: fault_signals.bindings,
            resource_limits: fault_signals.resource_limits,
            kind: Some(PlanKindToml::EventGraph),
            entry: Vec::new(),
            fault_entry: Vec::new(),
            event: graph.events().iter().map(event_to_toml).collect(),
        },
    })
}

pub(super) fn plan_from_toml(world: &World, toml: PlanToml) -> Result<Plan, EngineError> {
    plan_from_toml_with_assertions(world, [], toml)
}

pub(super) fn plan_from_toml_with_assertions(
    world: &World,
    assertions: impl IntoIterator<Item = AssertionId>,
    toml: PlanToml,
) -> Result<Plan, EngineError> {
    let id = parse_content_hash_ref(&toml.id)?;
    let serialized_kind = serialized_plan_kind(&toml)?;
    let fault_signals = FaultSignalAuthoringRows {
        semantic_version: toml.fault_signal_semantic_version,
        resource_limits: toml.resource_limits,
        signals: toml.signal,
        bindings: toml.fault_binding,
    }
    .admit(world)
    .map_err(|error| scenario_serialization_error(error.to_string()))?;
    let plan = match serialized_kind {
        SerializedPlanKind::ScheduledEntries => {
            let entries = toml
                .entry
                .into_iter()
                .map(plan_entry_from_toml)
                .collect::<Result<Vec<_>, _>>()?;
            Plan::from_entries_for_world(world, entries)?
        }
        SerializedPlanKind::FaultPlan => {
            let entries = toml
                .fault_entry
                .into_iter()
                .map(fault_plan_entry_from_toml)
                .collect::<Result<Vec<_>, _>>()?;
            Plan::from_fault_plan_for_world(world, FaultPlan::from_entries(entries))?
        }
        SerializedPlanKind::EventGraph => {
            let events = toml
                .event
                .into_iter()
                .map(event_from_toml)
                .collect::<Result<Vec<_>, _>>()?;
            let graph = EventGraph::from_unchecked_events_for_model(events);
            Plan::from_event_graph_with_assertions_for_world(world, assertions, graph)?
        }
    }
    .with_fault_signals(fault_signals);
    validate_serialized_id("plan", id, plan.content_hash())?;
    Ok(plan)
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum SerializedPlanKind {
    ScheduledEntries,
    FaultPlan,
    EventGraph,
}

pub(super) fn serialized_plan_kind(toml: &PlanToml) -> Result<SerializedPlanKind, EngineError> {
    match toml.kind {
        Some(PlanKindToml::Entries) => {
            if !toml.event.is_empty() || !toml.fault_entry.is_empty() {
                return Err(scenario_serialization_error(
                    "entries plan must not carry fault-plan or event graph rows",
                ));
            }
            Ok(SerializedPlanKind::ScheduledEntries)
        }
        Some(PlanKindToml::FaultPlan) => {
            if !toml.entry.is_empty() || !toml.event.is_empty() {
                return Err(scenario_serialization_error(
                    "fault plan must not carry legacy entries or event graph rows",
                ));
            }
            Ok(SerializedPlanKind::FaultPlan)
        }
        Some(PlanKindToml::EventGraph) => {
            if !toml.entry.is_empty() || !toml.fault_entry.is_empty() {
                return Err(scenario_serialization_error(
                    "event graph plan must not carry scheduled entries or fault-plan rows",
                ));
            }
            Ok(SerializedPlanKind::EventGraph)
        }
        None if toml.event.is_empty() && toml.fault_entry.is_empty() => {
            Ok(SerializedPlanKind::ScheduledEntries)
        }
        None => {
            if !toml.entry.is_empty() || (!toml.event.is_empty() && !toml.fault_entry.is_empty()) {
                return Err(scenario_serialization_error(
                    "plan must not mix scheduled entries, fault-plan rows, and event graph rows",
                ));
            }
            if toml.fault_entry.is_empty() {
                Ok(SerializedPlanKind::EventGraph)
            } else {
                Ok(SerializedPlanKind::FaultPlan)
            }
        }
    }
}

pub(super) fn plan_entry_to_toml(entry: &PlanEntry) -> PlanEntryToml {
    match entry {
        PlanEntry::Activate { at, tag, fault } => PlanEntryToml::Activate {
            at_ticks: at.ticks,
            tag: tag.name.clone(),
            fault: membership_fault_to_toml(fault),
        },
        PlanEntry::Heal { at, tag } => PlanEntryToml::Heal {
            at_ticks: at.ticks,
            tag: tag.name.clone(),
        },
    }
}

pub(super) fn plan_entry_from_toml(toml: PlanEntryToml) -> Result<PlanEntry, EngineError> {
    Ok(match toml {
        PlanEntryToml::Activate {
            at_ticks,
            tag,
            fault,
        } => PlanEntry::Activate {
            at: VirtualTime { ticks: at_ticks },
            tag: FaultTag { name: tag },
            fault: membership_fault_from_toml(fault)?,
        },
        PlanEntryToml::Heal { at_ticks, tag } => PlanEntry::Heal {
            at: VirtualTime { ticks: at_ticks },
            tag: FaultTag { name: tag },
        },
    })
}

pub(super) fn fault_plan_entry_to_toml(entry: &FaultPlanEntry) -> FaultPlanEntryToml {
    match entry {
        FaultPlanEntry::At {
            at,
            duration,
            tag,
            fault,
        } => FaultPlanEntryToml::At {
            at_ticks: at.ticks,
            duration_nanos: duration.nanos(),
            tag: tag.name.clone(),
            fault: fault_to_toml(fault),
        },
        FaultPlanEntry::PermanentAt { at, tag, fault } => FaultPlanEntryToml::PermanentAt {
            at_ticks: at.ticks,
            tag: tag.name.clone(),
            fault: fault_to_toml(fault),
        },
        FaultPlanEntry::Heal { at, tag } => FaultPlanEntryToml::Heal {
            at_ticks: at.ticks,
            tag: tag.name.clone(),
        },
    }
}

pub(super) fn fault_plan_entry_from_toml(
    toml: FaultPlanEntryToml,
) -> Result<FaultPlanEntry, EngineError> {
    Ok(match toml {
        FaultPlanEntryToml::At {
            at_ticks,
            duration_nanos,
            tag,
            fault,
        } => FaultPlanEntry::At {
            at: VirtualTime { ticks: at_ticks },
            duration: FaultDuration::from_nanos(duration_nanos),
            tag: FaultTag { name: tag },
            fault: fault_from_toml(fault)?,
        },
        FaultPlanEntryToml::PermanentAt {
            at_ticks,
            tag,
            fault,
        } => FaultPlanEntry::PermanentAt {
            at: VirtualTime { ticks: at_ticks },
            tag: FaultTag { name: tag },
            fault: fault_from_toml(fault)?,
        },
        FaultPlanEntryToml::Heal { at_ticks, tag } => FaultPlanEntry::Heal {
            at: VirtualTime { ticks: at_ticks },
            tag: FaultTag { name: tag },
        },
    })
}

pub(super) fn event_to_toml(event: &Event) -> EventToml {
    EventToml {
        id: event.id.name.clone(),
        trigger: event.trigger.as_ref().map(predicate_to_toml),
        action: action_to_toml(&event.action),
        policy: fire_policy_to_toml(event.policy),
    }
}

pub(super) fn event_from_toml(toml: EventToml) -> Result<Event, EngineError> {
    Ok(Event {
        id: EventId { name: toml.id },
        trigger: toml.trigger.map(predicate_from_toml).transpose()?,
        action: action_from_toml(toml.action)?,
        policy: fire_policy_from_toml(toml.policy),
    })
}

pub(super) fn default_fire_policy_toml() -> FirePolicyToml {
    FirePolicyToml::Once
}

pub(super) fn fire_policy_to_toml(policy: FirePolicy) -> FirePolicyToml {
    match policy {
        FirePolicy::Once => FirePolicyToml::Once,
        FirePolicy::Repeatable => FirePolicyToml::Repeatable,
    }
}

pub(super) fn fire_policy_from_toml(toml: FirePolicyToml) -> FirePolicy {
    match toml {
        FirePolicyToml::Once => FirePolicy::Once,
        FirePolicyToml::Repeatable => FirePolicy::Repeatable,
    }
}

pub(super) fn action_to_toml(action: &Action) -> ActionToml {
    match action {
        Action::InjectFault { tag, fault } => ActionToml::InjectFault {
            tag: tag.name.clone(),
            fault: membership_fault_to_toml(fault),
        },
        Action::HealFault { tag } => ActionToml::HealFault {
            tag: tag.name.clone(),
        },
        Action::ArmTimer { name, after } => ActionToml::ArmTimer {
            name: name.name.clone(),
            after_nanos: after.nanos,
        },
        Action::CancelTimer { name } => ActionToml::CancelTimer {
            name: name.name.clone(),
        },
        Action::StartNode { node } => ActionToml::StartNode {
            node: node.name.clone(),
        },
        Action::StopNode { node } => ActionToml::StopNode {
            node: node.name.clone(),
        },
        Action::CreateSavepoint { label } => ActionToml::CreateSavepoint {
            label: label.clone(),
        },
        Action::Fork { label } => ActionToml::Fork {
            label: label.clone(),
        },
        Action::Pass => ActionToml::Pass,
        Action::Fail { reason } => ActionToml::Fail {
            reason: reason.clone(),
        },
        Action::Log { level, message } => ActionToml::Log {
            level: log_level_to_toml(*level),
            message: message.clone(),
        },
        Action::Group(actions) => ActionToml::Group {
            actions: actions.iter().map(action_to_toml).collect(),
        },
    }
}

pub(super) fn action_from_toml(toml: ActionToml) -> Result<Action, EngineError> {
    Ok(match toml {
        ActionToml::InjectFault { tag, fault } => Action::InjectFault {
            tag: FaultTag { name: tag },
            fault: membership_fault_from_toml(fault)?,
        },
        ActionToml::HealFault { tag } => Action::HealFault {
            tag: FaultTag { name: tag },
        },
        ActionToml::ArmTimer { name, after_nanos } => Action::ArmTimer {
            name: TimerId { name },
            after: SimDuration { nanos: after_nanos },
        },
        ActionToml::CancelTimer { name } => Action::CancelTimer {
            name: TimerId { name },
        },
        ActionToml::StartNode { node } => Action::StartNode {
            node: NodeId { name: node },
        },
        ActionToml::StopNode { node } => Action::StopNode {
            node: NodeId { name: node },
        },
        ActionToml::CreateSavepoint { label } => Action::CreateSavepoint { label },
        ActionToml::Fork { label } => Action::Fork { label },
        ActionToml::Pass => Action::Pass,
        ActionToml::Fail { reason } => Action::Fail { reason },
        ActionToml::Log { level, message } => Action::Log {
            level: log_level_from_toml(level),
            message,
        },
        ActionToml::Group { actions } => Action::Group(
            actions
                .into_iter()
                .map(action_from_toml)
                .collect::<Result<Vec<_>, _>>()?,
        ),
    })
}

pub(super) fn log_level_to_toml(level: LogLevel) -> LogLevelToml {
    match level {
        LogLevel::Debug => LogLevelToml::Debug,
        LogLevel::Info => LogLevelToml::Info,
        LogLevel::Warn => LogLevelToml::Warn,
        LogLevel::Error => LogLevelToml::Error,
    }
}

pub(super) fn log_level_from_toml(toml: LogLevelToml) -> LogLevel {
    match toml {
        LogLevelToml::Debug => LogLevel::Debug,
        LogLevelToml::Info => LogLevel::Info,
        LogLevelToml::Warn => LogLevel::Warn,
        LogLevelToml::Error => LogLevel::Error,
    }
}

pub(super) fn membership_fault_to_toml(fault: &MembershipFault) -> MembershipFaultToml {
    match fault {
        MembershipFault::Crash { node, restart } => MembershipFaultToml::Crash {
            node: node.name.clone(),
            restart: restart_to_toml(*restart),
        },
        MembershipFault::Partition {
            endpoint_a,
            endpoint_b,
            direction,
        } => MembershipFaultToml::Partition {
            endpoint_a: endpoint_a.name.clone(),
            endpoint_b: endpoint_b.name.clone(),
            direction: partition_direction_to_toml(*direction),
        },
        MembershipFault::Isolate { node } => MembershipFaultToml::Isolate {
            node: node.name.clone(),
        },
        MembershipFault::NotYetJoined { node } => MembershipFaultToml::NotYetJoined {
            node: node.name.clone(),
        },
        MembershipFault::Taxonomy { fault } => MembershipFaultToml::Taxonomy {
            fault: fault_to_toml(fault),
        },
    }
}

pub(super) fn membership_fault_from_toml(
    toml: MembershipFaultToml,
) -> Result<MembershipFault, EngineError> {
    Ok(match toml {
        MembershipFaultToml::Crash { node, restart } => MembershipFault::Crash {
            node: NodeId { name: node },
            restart: restart_from_toml(restart),
        },
        MembershipFaultToml::Partition {
            endpoint_a,
            endpoint_b,
            direction,
        } => MembershipFault::Partition {
            endpoint_a: NodeId { name: endpoint_a },
            endpoint_b: NodeId { name: endpoint_b },
            direction: partition_direction_from_toml(direction),
        },
        MembershipFaultToml::Isolate { node } => MembershipFault::Isolate {
            node: NodeId { name: node },
        },
        MembershipFaultToml::NotYetJoined { node } => MembershipFault::NotYetJoined {
            node: NodeId { name: node },
        },
        MembershipFaultToml::Taxonomy { fault } => MembershipFault::Taxonomy {
            fault: fault_from_toml(fault)?,
        },
    })
}

pub(super) fn fault_to_toml(fault: &Fault) -> FaultToml {
    match fault {
        Fault::Network(fault) => network_fault_to_toml(fault),
        Fault::Node(fault) => node_fault_to_toml(fault),
        Fault::Block(fault) => block_fault_to_toml(fault),
        Fault::NineP(fault) => ninep_fault_to_toml(fault),
    }
}

pub(super) fn fault_from_toml(toml: FaultToml) -> Result<Fault, EngineError> {
    Ok(match toml {
        FaultToml::NetworkPartition { link, direction } => {
            Fault::Network(NetworkFault::Partition {
                link: LinkId { name: link },
                direction: partition_direction_from_toml(direction),
            })
        }
        FaultToml::NetworkLoss {
            link,
            rate_basis_points,
        } => Fault::Network(NetworkFault::Loss {
            link: LinkId { name: link },
            rate: FaultRateBasisPoints::from_basis_points(rate_basis_points)?,
        }),
        FaultToml::NetworkReorder { link, window_nanos } => Fault::Network(NetworkFault::Reorder {
            link: LinkId { name: link },
            window: FaultDuration::from_nanos(window_nanos),
        }),
        FaultToml::NetworkDuplicate {
            link,
            rate_basis_points,
            gap_nanos,
        } => Fault::Network(NetworkFault::Duplicate {
            link: LinkId { name: link },
            rate: FaultRateBasisPoints::from_basis_points(rate_basis_points)?,
            gap: FaultDuration::from_nanos(gap_nanos),
        }),
        FaultToml::NetworkCorruptionBitFlip {
            link,
            rate_basis_points,
            max_bits,
        } => Fault::Network(NetworkFault::Corruption {
            link: LinkId { name: link },
            kind: NetworkCorruptionFault::BitFlip {
                rate: FaultRateBasisPoints::from_basis_points(rate_basis_points)?,
                max_bits,
            },
        }),
        FaultToml::NetworkCorruptionFieldMutation {
            link,
            rate_basis_points,
        } => Fault::Network(NetworkFault::Corruption {
            link: LinkId { name: link },
            kind: NetworkCorruptionFault::FieldMutation {
                rate: FaultRateBasisPoints::from_basis_points(rate_basis_points)?,
            },
        }),
        FaultToml::NetworkCorruptionTruncation {
            link,
            rate_basis_points,
            max_bytes,
        } => Fault::Network(NetworkFault::Corruption {
            link: LinkId { name: link },
            kind: NetworkCorruptionFault::Truncation {
                rate: FaultRateBasisPoints::from_basis_points(rate_basis_points)?,
                max_bytes,
            },
        }),
        FaultToml::NetworkBandwidth {
            link,
            bits_per_second,
        } => Fault::Network(NetworkFault::Bandwidth {
            link: LinkId { name: link },
            limit: FaultBandwidthBitsPerSecond::new(bits_per_second)?,
        }),
        FaultToml::NetworkLatencyBump { link, extra_nanos } => {
            Fault::Network(NetworkFault::LatencyBump {
                link: LinkId { name: link },
                extra: FaultDuration::from_nanos(extra_nanos),
            })
        }
        FaultToml::NodeCrash { node, restart } => Fault::Node(NodeFault::Crash {
            node: NodeId { name: node },
            restart: restart_from_toml(restart),
        }),
        FaultToml::NodeSlow {
            node,
            factor_basis_points,
        } => Fault::Node(NodeFault::Slow {
            node: NodeId { name: node },
            factor: FaultSlowdownFactorBasisPoints::from_basis_points(factor_basis_points)?,
        }),
        FaultToml::NodeClockSkew { node, offset_nanos } => Fault::Node(NodeFault::ClockSkew {
            node: NodeId { name: node },
            offset: SimOffset {
                nanos: offset_nanos,
            },
        }),
        FaultToml::BlockLatency {
            device,
            extra_nanos,
            jitter_nanos,
        } => Fault::Block(BlockFault::Latency {
            device: DeviceId { name: device },
            extra: FaultDuration::from_nanos(extra_nanos),
            jitter: FaultDuration::from_nanos(jitter_nanos),
        }),
        FaultToml::BlockFailure {
            device,
            rate_basis_points,
            mode,
        } => Fault::Block(BlockFault::Failure {
            device: DeviceId { name: device },
            rate: FaultRateBasisPoints::from_basis_points(rate_basis_points)?,
            mode: io_failure_mode_from_toml(mode),
        }),
        FaultToml::BlockReorder {
            device,
            window_nanos,
        } => Fault::Block(BlockFault::Reorder {
            device: DeviceId { name: device },
            window: FaultDuration::from_nanos(window_nanos),
        }),
        FaultToml::BlockDuplicate {
            device,
            rate_basis_points,
            gap_nanos,
        } => Fault::Block(BlockFault::Duplicate {
            device: DeviceId { name: device },
            rate: FaultRateBasisPoints::from_basis_points(rate_basis_points)?,
            gap: FaultDuration::from_nanos(gap_nanos),
        }),
        FaultToml::BlockCorruption {
            device,
            rate_basis_points,
            bit_flips,
        } => Fault::Block(BlockFault::Corruption {
            device: DeviceId { name: device },
            rate: FaultRateBasisPoints::from_basis_points(rate_basis_points)?,
            bit_flips,
        }),
        FaultToml::BlockBandwidth {
            device,
            bits_per_second,
        } => Fault::Block(BlockFault::Bandwidth {
            device: DeviceId { name: device },
            limit: FaultBandwidthBitsPerSecond::new(bits_per_second)?,
        }),
        FaultToml::NinePLatency {
            device,
            extra_nanos,
            jitter_nanos,
        } => Fault::NineP(NinePFault::Latency {
            device: DeviceId { name: device },
            extra: FaultDuration::from_nanos(extra_nanos),
            jitter: FaultDuration::from_nanos(jitter_nanos),
        }),
        FaultToml::NinePFailure {
            device,
            rate_basis_points,
            errno_code,
        } => Fault::NineP(NinePFault::Failure {
            device: DeviceId { name: device },
            rate: FaultRateBasisPoints::from_basis_points(rate_basis_points)?,
            errno: NinePErrno::from_code(errno_code)?,
        }),
        FaultToml::NinePReorder {
            device,
            window_nanos,
        } => Fault::NineP(NinePFault::Reorder {
            device: DeviceId { name: device },
            window: FaultDuration::from_nanos(window_nanos),
        }),
        FaultToml::NinePDuplicate {
            device,
            rate_basis_points,
            gap_nanos,
        } => Fault::NineP(NinePFault::Duplicate {
            device: DeviceId { name: device },
            rate: FaultRateBasisPoints::from_basis_points(rate_basis_points)?,
            gap: FaultDuration::from_nanos(gap_nanos),
        }),
        FaultToml::NinePCorruption {
            device,
            rate_basis_points,
            bit_flips,
        } => Fault::NineP(NinePFault::Corruption {
            device: DeviceId { name: device },
            rate: FaultRateBasisPoints::from_basis_points(rate_basis_points)?,
            bit_flips,
        }),
        FaultToml::NinePBandwidth {
            device,
            bits_per_second,
        } => Fault::NineP(NinePFault::Bandwidth {
            device: DeviceId { name: device },
            limit: FaultBandwidthBitsPerSecond::new(bits_per_second)?,
        }),
    })
}

pub(super) fn network_fault_to_toml(fault: &NetworkFault) -> FaultToml {
    match fault {
        NetworkFault::Partition { link, direction } => FaultToml::NetworkPartition {
            link: link.name.clone(),
            direction: partition_direction_to_toml(*direction),
        },
        NetworkFault::Loss { link, rate } => FaultToml::NetworkLoss {
            link: link.name.clone(),
            rate_basis_points: u32::from(rate.basis_points()),
        },
        NetworkFault::Reorder { link, window } => FaultToml::NetworkReorder {
            link: link.name.clone(),
            window_nanos: window.nanos(),
        },
        NetworkFault::Duplicate { link, rate, gap } => FaultToml::NetworkDuplicate {
            link: link.name.clone(),
            rate_basis_points: u32::from(rate.basis_points()),
            gap_nanos: gap.nanos(),
        },
        NetworkFault::Corruption { link, kind } => network_corruption_fault_to_toml(link, kind),
        NetworkFault::Bandwidth { link, limit } => FaultToml::NetworkBandwidth {
            link: link.name.clone(),
            bits_per_second: limit.bits_per_second(),
        },
        NetworkFault::LatencyBump { link, extra } => FaultToml::NetworkLatencyBump {
            link: link.name.clone(),
            extra_nanos: extra.nanos(),
        },
    }
}

pub(super) fn network_corruption_fault_to_toml(
    link: &LinkId,
    fault: &NetworkCorruptionFault,
) -> FaultToml {
    match fault {
        NetworkCorruptionFault::BitFlip { rate, max_bits } => FaultToml::NetworkCorruptionBitFlip {
            link: link.name.clone(),
            rate_basis_points: u32::from(rate.basis_points()),
            max_bits: *max_bits,
        },
        NetworkCorruptionFault::FieldMutation { rate } => {
            FaultToml::NetworkCorruptionFieldMutation {
                link: link.name.clone(),
                rate_basis_points: u32::from(rate.basis_points()),
            }
        }
        NetworkCorruptionFault::Truncation { rate, max_bytes } => {
            FaultToml::NetworkCorruptionTruncation {
                link: link.name.clone(),
                rate_basis_points: u32::from(rate.basis_points()),
                max_bytes: *max_bytes,
            }
        }
    }
}

pub(super) fn node_fault_to_toml(fault: &NodeFault) -> FaultToml {
    match fault {
        NodeFault::Crash { node, restart } => FaultToml::NodeCrash {
            node: node.name.clone(),
            restart: restart_to_toml(*restart),
        },
        NodeFault::Slow { node, factor } => FaultToml::NodeSlow {
            node: node.name.clone(),
            factor_basis_points: factor.basis_points(),
        },
        NodeFault::ClockSkew { node, offset } => FaultToml::NodeClockSkew {
            node: node.name.clone(),
            offset_nanos: offset.nanos,
        },
    }
}

pub(super) fn block_fault_to_toml(fault: &BlockFault) -> FaultToml {
    match fault {
        BlockFault::Latency {
            device,
            extra,
            jitter,
        } => FaultToml::BlockLatency {
            device: device.name.clone(),
            extra_nanos: extra.nanos(),
            jitter_nanos: jitter.nanos(),
        },
        BlockFault::Failure { device, rate, mode } => FaultToml::BlockFailure {
            device: device.name.clone(),
            rate_basis_points: u32::from(rate.basis_points()),
            mode: io_failure_mode_to_toml(*mode),
        },
        BlockFault::Reorder { device, window } => FaultToml::BlockReorder {
            device: device.name.clone(),
            window_nanos: window.nanos(),
        },
        BlockFault::Duplicate { device, rate, gap } => FaultToml::BlockDuplicate {
            device: device.name.clone(),
            rate_basis_points: u32::from(rate.basis_points()),
            gap_nanos: gap.nanos(),
        },
        BlockFault::Corruption {
            device,
            rate,
            bit_flips,
        } => FaultToml::BlockCorruption {
            device: device.name.clone(),
            rate_basis_points: u32::from(rate.basis_points()),
            bit_flips: *bit_flips,
        },
        BlockFault::Bandwidth { device, limit } => FaultToml::BlockBandwidth {
            device: device.name.clone(),
            bits_per_second: limit.bits_per_second(),
        },
    }
}

pub(super) fn ninep_fault_to_toml(fault: &NinePFault) -> FaultToml {
    match fault {
        NinePFault::Latency {
            device,
            extra,
            jitter,
        } => FaultToml::NinePLatency {
            device: device.name.clone(),
            extra_nanos: extra.nanos(),
            jitter_nanos: jitter.nanos(),
        },
        NinePFault::Failure {
            device,
            rate,
            errno,
        } => FaultToml::NinePFailure {
            device: device.name.clone(),
            rate_basis_points: u32::from(rate.basis_points()),
            errno_code: errno.code(),
        },
        NinePFault::Reorder { device, window } => FaultToml::NinePReorder {
            device: device.name.clone(),
            window_nanos: window.nanos(),
        },
        NinePFault::Duplicate { device, rate, gap } => FaultToml::NinePDuplicate {
            device: device.name.clone(),
            rate_basis_points: u32::from(rate.basis_points()),
            gap_nanos: gap.nanos(),
        },
        NinePFault::Corruption {
            device,
            rate,
            bit_flips,
        } => FaultToml::NinePCorruption {
            device: device.name.clone(),
            rate_basis_points: u32::from(rate.basis_points()),
            bit_flips: *bit_flips,
        },
        NinePFault::Bandwidth { device, limit } => FaultToml::NinePBandwidth {
            device: device.name.clone(),
            bits_per_second: limit.bits_per_second(),
        },
    }
}

pub(super) fn io_failure_mode_to_toml(mode: IoFailureMode) -> IoFailureModeToml {
    match mode {
        IoFailureMode::Drop => IoFailureModeToml::Drop,
        IoFailureMode::ErrorStatus => IoFailureModeToml::ErrorStatus,
    }
}

pub(super) fn io_failure_mode_from_toml(toml: IoFailureModeToml) -> IoFailureMode {
    match toml {
        IoFailureModeToml::Drop => IoFailureMode::Drop,
        IoFailureModeToml::ErrorStatus => IoFailureMode::ErrorStatus,
    }
}

pub(super) fn restart_to_toml(policy: RestartPolicy) -> RestartToml {
    match policy {
        RestartPolicy::FromReadyPoint => RestartToml::FromReadyPoint,
        RestartPolicy::FromLastCheckpoint => RestartToml::FromLastCheckpoint,
        RestartPolicy::StayDown => RestartToml::StayDown,
    }
}

pub(super) fn restart_from_toml(toml: RestartToml) -> RestartPolicy {
    match toml {
        RestartToml::FromReadyPoint => RestartPolicy::FromReadyPoint,
        RestartToml::FromLastCheckpoint => RestartPolicy::FromLastCheckpoint,
        RestartToml::StayDown => RestartPolicy::StayDown,
    }
}

pub(super) fn partition_direction_to_toml(direction: PartitionDirection) -> PartitionDirectionToml {
    match direction {
        PartitionDirection::Bidirectional => PartitionDirectionToml::Bidirectional,
        PartitionDirection::EndpointAToEndpointB => PartitionDirectionToml::EndpointAToEndpointB,
        PartitionDirection::EndpointBToEndpointA => PartitionDirectionToml::EndpointBToEndpointA,
    }
}

pub(super) fn partition_direction_from_toml(toml: PartitionDirectionToml) -> PartitionDirection {
    match toml {
        PartitionDirectionToml::Bidirectional => PartitionDirection::Bidirectional,
        PartitionDirectionToml::EndpointAToEndpointB => PartitionDirection::EndpointAToEndpointB,
        PartitionDirectionToml::EndpointBToEndpointA => PartitionDirection::EndpointBToEndpointA,
    }
}

pub(super) fn properties_to_toml(properties: &Properties) -> PropertiesToml {
    PropertiesToml {
        id: format_content_hash_ref(properties.content_hash()),
        assertion: properties
            .assertions()
            .iter()
            .map(assertion_to_toml)
            .collect(),
    }
}

pub(super) fn properties_from_toml(
    world: &World,
    toml: PropertiesToml,
) -> Result<Properties, EngineError> {
    let (id, assertions) = properties_assertions_from_toml(toml)?;
    let properties = Properties::from_assertions_for_world(world, assertions)?;
    validate_serialized_id("properties", id, properties.content_hash())?;
    Ok(properties)
}

pub(super) fn properties_from_toml_with_plan(
    world: &World,
    plan: &Plan,
    toml: PropertiesToml,
) -> Result<Properties, EngineError> {
    let (id, assertions) = properties_assertions_from_toml(toml)?;
    let properties = Properties::from_assertions_for_world_and_plan(world, plan, assertions)?;
    validate_serialized_id("properties", id, properties.content_hash())?;
    Ok(properties)
}

pub(super) fn properties_assertions_from_toml(
    toml: PropertiesToml,
) -> Result<(ContentHash, Vec<AssertionDef>), EngineError> {
    let id = parse_content_hash_ref(&toml.id)?;
    let assertions = toml
        .assertion
        .into_iter()
        .map(assertion_from_toml)
        .collect::<Result<Vec<_>, _>>()?;
    Ok((id, assertions))
}

pub(super) fn assertion_to_toml(assertion: &AssertionDef) -> AssertionToml {
    AssertionToml {
        id: assertion.id.name.clone(),
        message: assertion.message.clone(),
        property: property_to_toml(&assertion.property),
    }
}

pub(super) fn assertion_from_toml(toml: AssertionToml) -> Result<AssertionDef, EngineError> {
    Ok(AssertionDef {
        id: AssertionId { name: toml.id },
        message: toml.message,
        property: property_from_toml(toml.property)?,
    })
}

pub(super) fn property_to_toml(property: &Property) -> PropertyToml {
    match property {
        Property::Always { predicate } => PropertyToml {
            kind: property.kind().toml_kind().to_owned(),
            predicate: Some(predicate_to_toml(predicate)),
            trigger: None,
            property: None,
            deadline_ticks: None,
            expectation: None,
        },
        Property::Sometimes { predicate } => PropertyToml {
            kind: property.kind().toml_kind().to_owned(),
            predicate: Some(predicate_to_toml(predicate)),
            trigger: None,
            property: None,
            deadline_ticks: None,
            expectation: None,
        },
        Property::Eventually {
            trigger,
            property,
            deadline,
        } => PropertyToml {
            kind: PropertyKind::Eventually.toml_kind().to_owned(),
            predicate: None,
            trigger: Some(predicate_to_toml(trigger)),
            property: Some(predicate_to_toml(property)),
            deadline_ticks: Some(deadline.ticks),
            expectation: None,
        },
        Property::AfterQuiescence { predicate } => PropertyToml {
            kind: property.kind().toml_kind().to_owned(),
            predicate: Some(predicate_to_toml(predicate)),
            trigger: None,
            property: None,
            deadline_ticks: None,
            expectation: None,
        },
        Property::Reachable {
            predicate,
            expectation,
        } => PropertyToml {
            kind: property.kind().toml_kind().to_owned(),
            predicate: Some(predicate_to_toml(predicate)),
            trigger: None,
            property: None,
            deadline_ticks: None,
            expectation: Some(reachability_expectation_to_toml(*expectation)),
        },
    }
}

pub(super) fn property_from_toml(toml: PropertyToml) -> Result<Property, EngineError> {
    let PropertyToml {
        kind,
        predicate,
        trigger,
        property,
        deadline_ticks,
        expectation,
    } = toml;
    let kind = PropertyKind::from_toml_kind(&kind)
        .ok_or_else(|| scenario_serialization_error(format!("invalid property kind `{kind}`")))?;
    Ok(match kind {
        PropertyKind::Always => {
            reject_property_toml_field(kind, "trigger", trigger)?;
            reject_property_toml_field(kind, "property", property)?;
            reject_property_toml_field(kind, "deadline_ticks", deadline_ticks)?;
            reject_property_toml_field(kind, "expectation", expectation)?;
            Property::Always {
                predicate: predicate_from_toml(require_property_toml_field(
                    kind,
                    "predicate",
                    predicate,
                )?)?,
            }
        }
        PropertyKind::Sometimes => {
            reject_property_toml_field(kind, "trigger", trigger)?;
            reject_property_toml_field(kind, "property", property)?;
            reject_property_toml_field(kind, "deadline_ticks", deadline_ticks)?;
            reject_property_toml_field(kind, "expectation", expectation)?;
            Property::Sometimes {
                predicate: predicate_from_toml(require_property_toml_field(
                    kind,
                    "predicate",
                    predicate,
                )?)?,
            }
        }
        PropertyKind::Eventually => {
            reject_property_toml_field(kind, "predicate", predicate)?;
            reject_property_toml_field(kind, "expectation", expectation)?;
            Property::Eventually {
                trigger: predicate_from_toml(require_property_toml_field(
                    kind, "trigger", trigger,
                )?)?,
                property: predicate_from_toml(require_property_toml_field(
                    kind, "property", property,
                )?)?,
                deadline: VirtualTime {
                    ticks: require_property_toml_field(kind, "deadline_ticks", deadline_ticks)?,
                },
            }
        }
        PropertyKind::AfterQuiescence => {
            reject_property_toml_field(kind, "trigger", trigger)?;
            reject_property_toml_field(kind, "property", property)?;
            reject_property_toml_field(kind, "deadline_ticks", deadline_ticks)?;
            reject_property_toml_field(kind, "expectation", expectation)?;
            Property::AfterQuiescence {
                predicate: predicate_from_toml(require_property_toml_field(
                    kind,
                    "predicate",
                    predicate,
                )?)?,
            }
        }
        PropertyKind::Reachable => {
            reject_property_toml_field(kind, "trigger", trigger)?;
            reject_property_toml_field(kind, "property", property)?;
            reject_property_toml_field(kind, "deadline_ticks", deadline_ticks)?;
            Property::Reachable {
                predicate: predicate_from_toml(require_property_toml_field(
                    kind,
                    "predicate",
                    predicate,
                )?)?,
                expectation: reachability_expectation_from_toml(require_property_toml_field(
                    kind,
                    "expectation",
                    expectation,
                )?),
            }
        }
    })
}

pub(super) fn require_property_toml_field<T>(
    kind: PropertyKind,
    field_name: &'static str,
    value: Option<T>,
) -> Result<T, EngineError> {
    value.ok_or_else(|| {
        scenario_serialization_error(format!(
            "property kind `{}` missing `{field_name}`",
            kind.toml_kind()
        ))
    })
}

pub(super) fn reject_property_toml_field<T>(
    kind: PropertyKind,
    field_name: &'static str,
    value: Option<T>,
) -> Result<(), EngineError> {
    if value.is_some() {
        Err(scenario_serialization_error(format!(
            "property kind `{}` has unexpected `{field_name}`",
            kind.toml_kind()
        )))
    } else {
        Ok(())
    }
}

pub(super) fn predicate_to_toml(predicate: &Predicate) -> PredicateToml {
    PredicateToml::Structured(match predicate {
        Predicate::At { at } => PredicateTomlKind::At { at_ticks: at.ticks },
        Predicate::After { duration, of } => PredicateTomlKind::After {
            duration_nanos: duration.nanos,
            of: of.name.clone(),
        },
        Predicate::Timer { name } => PredicateTomlKind::Timer {
            name: name.name.clone(),
        },
        Predicate::NetworkMatch { link, predicate } => PredicateTomlKind::NetworkMatch {
            link: link.as_ref().map(|link| link.name.clone()),
            predicate: frame_predicate_to_toml(predicate),
        },
        Predicate::ConsoleMatch { node, regex } => PredicateTomlKind::ConsoleMatch {
            node: node.name.clone(),
            regex: regex.pattern.clone(),
        },
        Predicate::CoveragePoint { node, point } => PredicateTomlKind::CoveragePoint {
            node: node.name.clone(),
            point: code_point_to_toml(point),
        },
        Predicate::MemoryPredicate {
            node,
            place,
            cmp,
            value,
        } => PredicateTomlKind::MemoryPredicate {
            node: node.name.clone(),
            place: mem_place_to_toml(place),
            cmp: memory_cmp_to_toml(*cmp),
            value: *value,
        },
        Predicate::IoPattern { node, kind } => PredicateTomlKind::IoPattern {
            node: node.name.clone(),
            io_kind: io_event_kind_to_toml(*kind),
        },
        Predicate::NodeState { node, state } => PredicateTomlKind::NodeState {
            node: node.name.clone(),
            state: node_lifecycle_to_toml(*state),
        },
        Predicate::AssertionState { name, state } => PredicateTomlKind::AssertionState {
            name: name.name.clone(),
            state: assertion_phase_to_toml(*state),
        },
        Predicate::Quiescent => PredicateTomlKind::Quiescent,
        Predicate::FaultActive { tag } => PredicateTomlKind::FaultActive {
            tag: tag.name.clone(),
        },
        Predicate::Named { name, nodes } => PredicateTomlKind::Named {
            name: name.clone(),
            nodes: nodes.iter().map(|node| node.name.clone()).collect(),
        },
        Predicate::GuestMarker { marker } => PredicateTomlKind::GuestMarker {
            marker: marker.name.clone(),
        },
        Predicate::AllOf { predicates } => PredicateTomlKind::AllOf {
            predicates: predicates.iter().map(predicate_to_toml).collect(),
        },
        Predicate::AnyOf { predicates } => PredicateTomlKind::AnyOf {
            predicates: predicates.iter().map(predicate_to_toml).collect(),
        },
        Predicate::Once { predicate } => PredicateTomlKind::Once {
            predicate: Box::new(predicate_to_toml(predicate)),
        },
        Predicate::Not { predicate } => PredicateTomlKind::Not {
            predicate: Box::new(predicate_to_toml(predicate)),
        },
    })
}

pub(super) fn predicate_from_toml(toml: PredicateToml) -> Result<Predicate, EngineError> {
    let toml = match toml {
        PredicateToml::Dsl(name) => {
            return Ok(Predicate::Named {
                name,
                nodes: Vec::new(),
            });
        }
        PredicateToml::Structured(toml) => toml,
    };
    Ok(match toml {
        PredicateTomlKind::At { at_ticks } => Predicate::At {
            at: VirtualTime { ticks: at_ticks },
        },
        PredicateTomlKind::After { duration_nanos, of } => Predicate::After {
            duration: SimDuration {
                nanos: duration_nanos,
            },
            of: EventId { name: of },
        },
        PredicateTomlKind::Timer { name } => Predicate::Timer {
            name: TimerId { name },
        },
        PredicateTomlKind::NetworkMatch { link, predicate } => Predicate::NetworkMatch {
            link: link.map(|name| LinkId { name }),
            predicate: frame_predicate_from_toml(predicate)?,
        },
        PredicateTomlKind::ConsoleMatch { node, regex } => Predicate::ConsoleMatch {
            node: NodeId { name: node },
            regex: RegexProgram { pattern: regex },
        },
        PredicateTomlKind::CoveragePoint { node, point } => Predicate::CoveragePoint {
            node: NodeId { name: node },
            point: code_point_from_toml(point),
        },
        PredicateTomlKind::MemoryPredicate {
            node,
            place,
            cmp,
            value,
        } => Predicate::MemoryPredicate {
            node: NodeId { name: node },
            place: mem_place_from_toml(place),
            cmp: memory_cmp_from_toml(cmp),
            value,
        },
        PredicateTomlKind::IoPattern { node, io_kind } => Predicate::IoPattern {
            node: NodeId { name: node },
            kind: io_event_kind_from_toml(io_kind),
        },
        PredicateTomlKind::NodeState { node, state } => Predicate::NodeState {
            node: NodeId { name: node },
            state: node_lifecycle_from_toml(state),
        },
        PredicateTomlKind::AssertionState { name, state } => Predicate::AssertionState {
            name: AssertionId { name },
            state: assertion_phase_from_toml(state),
        },
        PredicateTomlKind::Quiescent => Predicate::Quiescent,
        PredicateTomlKind::FaultActive { tag } => Predicate::FaultActive {
            tag: FaultTag { name: tag },
        },
        PredicateTomlKind::Named { name, nodes } => Predicate::Named {
            name,
            nodes: nodes.into_iter().map(|name| NodeId { name }).collect(),
        },
        PredicateTomlKind::GuestMarker { marker } => Predicate::GuestMarker {
            marker: MarkerId { name: marker },
        },
        PredicateTomlKind::AllOf { predicates } => Predicate::AllOf {
            predicates: predicates
                .into_iter()
                .map(predicate_from_toml)
                .collect::<Result<Vec<_>, _>>()?,
        },
        PredicateTomlKind::AnyOf { predicates } => Predicate::AnyOf {
            predicates: predicates
                .into_iter()
                .map(predicate_from_toml)
                .collect::<Result<Vec<_>, _>>()?,
        },
        PredicateTomlKind::Once { predicate } => Predicate::Once {
            predicate: Box::new(predicate_from_toml(*predicate)?),
        },
        PredicateTomlKind::Not { predicate } => Predicate::Not {
            predicate: Box::new(predicate_from_toml(*predicate)?),
        },
    })
}

pub(super) fn frame_predicate_to_toml(predicate: &FramePredicate) -> FramePredicateToml {
    match predicate {
        FramePredicate::Any => FramePredicateToml::Any,
        FramePredicate::Exact(bytes) => FramePredicateToml::Exact {
            bytes_hex: bytes_hex(bytes),
        },
        FramePredicate::Contains(bytes) => FramePredicateToml::Contains {
            needle_hex: bytes_hex(bytes),
        },
        FramePredicate::Prefix(bytes) => FramePredicateToml::Prefix {
            prefix_hex: bytes_hex(bytes),
        },
    }
}

pub(super) fn frame_predicate_from_toml(
    toml: FramePredicateToml,
) -> Result<FramePredicate, EngineError> {
    Ok(match toml {
        FramePredicateToml::Any => FramePredicate::Any,
        FramePredicateToml::Exact { bytes_hex } => {
            FramePredicate::Exact(parse_hex_bytes("frame exact bytes", &bytes_hex)?)
        }
        FramePredicateToml::Contains { needle_hex } => {
            FramePredicate::Contains(parse_hex_bytes("frame contains bytes", &needle_hex)?)
        }
        FramePredicateToml::Prefix { prefix_hex } => {
            FramePredicate::Prefix(parse_hex_bytes("frame prefix bytes", &prefix_hex)?)
        }
    })
}

pub(super) fn code_point_to_toml(point: &CodePoint) -> CodePointToml {
    match point {
        CodePoint::GuestAddress { address } => CodePointToml::GuestAddress { address: *address },
        CodePoint::Symbol { name } => CodePointToml::Symbol { name: name.clone() },
    }
}

pub(super) fn code_point_from_toml(toml: CodePointToml) -> CodePoint {
    match toml {
        CodePointToml::GuestAddress { address } => CodePoint::GuestAddress { address },
        CodePointToml::Symbol { name } => CodePoint::Symbol { name },
    }
}

pub(super) fn mem_place_to_toml(place: &MemPlace) -> MemPlaceToml {
    match place {
        MemPlace::PhysicalAddress { address, width } => MemPlaceToml::PhysicalAddress {
            address: *address,
            width: memory_width_to_toml(*width),
        },
        MemPlace::VirtualAddress { address, width } => MemPlaceToml::VirtualAddress {
            address: *address,
            width: memory_width_to_toml(*width),
        },
        MemPlace::Symbol { name, width } => MemPlaceToml::Symbol {
            name: name.clone(),
            width: memory_width_to_toml(*width),
        },
        MemPlace::Register { name, width } => MemPlaceToml::Register {
            name: name.clone(),
            width: memory_width_to_toml(*width),
        },
    }
}

pub(super) fn mem_place_from_toml(toml: MemPlaceToml) -> MemPlace {
    match toml {
        MemPlaceToml::PhysicalAddress { address, width } => MemPlace::PhysicalAddress {
            address,
            width: memory_width_from_toml(width),
        },
        MemPlaceToml::VirtualAddress { address, width } => MemPlace::VirtualAddress {
            address,
            width: memory_width_from_toml(width),
        },
        MemPlaceToml::Symbol { name, width } => MemPlace::Symbol {
            name,
            width: memory_width_from_toml(width),
        },
        MemPlaceToml::Register { name, width } => MemPlace::Register {
            name,
            width: memory_width_from_toml(width),
        },
    }
}

pub(super) fn memory_width_to_toml(width: MemoryWidth) -> MemoryWidthToml {
    match width {
        MemoryWidth::U8 => MemoryWidthToml::U8,
        MemoryWidth::U16 => MemoryWidthToml::U16,
        MemoryWidth::U32 => MemoryWidthToml::U32,
        MemoryWidth::U64 => MemoryWidthToml::U64,
    }
}

pub(super) fn memory_width_from_toml(toml: MemoryWidthToml) -> MemoryWidth {
    match toml {
        MemoryWidthToml::U8 => MemoryWidth::U8,
        MemoryWidthToml::U16 => MemoryWidth::U16,
        MemoryWidthToml::U32 => MemoryWidth::U32,
        MemoryWidthToml::U64 => MemoryWidth::U64,
    }
}

pub(super) fn memory_cmp_to_toml(cmp: MemoryCmp) -> MemoryCmpToml {
    match cmp {
        MemoryCmp::Eq => MemoryCmpToml::Eq,
        MemoryCmp::Ne => MemoryCmpToml::Ne,
        MemoryCmp::Lt => MemoryCmpToml::Lt,
        MemoryCmp::Le => MemoryCmpToml::Le,
        MemoryCmp::Gt => MemoryCmpToml::Gt,
        MemoryCmp::Ge => MemoryCmpToml::Ge,
    }
}

pub(super) fn memory_cmp_from_toml(toml: MemoryCmpToml) -> MemoryCmp {
    match toml {
        MemoryCmpToml::Eq => MemoryCmp::Eq,
        MemoryCmpToml::Ne => MemoryCmp::Ne,
        MemoryCmpToml::Lt => MemoryCmp::Lt,
        MemoryCmpToml::Le => MemoryCmp::Le,
        MemoryCmpToml::Gt => MemoryCmp::Gt,
        MemoryCmpToml::Ge => MemoryCmp::Ge,
    }
}

pub(super) fn io_event_kind_to_toml(kind: IoEventKind) -> IoEventKindToml {
    match kind {
        IoEventKind::Any => IoEventKindToml::Any,
        IoEventKind::BlockRead => IoEventKindToml::BlockRead,
        IoEventKind::BlockWrite => IoEventKindToml::BlockWrite,
        IoEventKind::Fsync => IoEventKindToml::Fsync,
        IoEventKind::NineP => IoEventKindToml::NineP,
        IoEventKind::Network => IoEventKindToml::Network,
    }
}

pub(super) fn io_event_kind_from_toml(toml: IoEventKindToml) -> IoEventKind {
    match toml {
        IoEventKindToml::Any => IoEventKind::Any,
        IoEventKindToml::BlockRead => IoEventKind::BlockRead,
        IoEventKindToml::BlockWrite => IoEventKind::BlockWrite,
        IoEventKindToml::Fsync => IoEventKind::Fsync,
        IoEventKindToml::NineP => IoEventKind::NineP,
        IoEventKindToml::Network => IoEventKind::Network,
    }
}

pub(super) fn node_lifecycle_to_toml(state: NodeLifecycle) -> NodeLifecycleToml {
    match state {
        NodeLifecycle::Started => NodeLifecycleToml::Started,
        NodeLifecycle::Crashed => NodeLifecycleToml::Crashed,
        NodeLifecycle::Hung => NodeLifecycleToml::Hung,
        NodeLifecycle::Exited => NodeLifecycleToml::Exited,
    }
}

pub(super) fn node_lifecycle_from_toml(toml: NodeLifecycleToml) -> NodeLifecycle {
    match toml {
        NodeLifecycleToml::Started => NodeLifecycle::Started,
        NodeLifecycleToml::Crashed => NodeLifecycle::Crashed,
        NodeLifecycleToml::Hung => NodeLifecycle::Hung,
        NodeLifecycleToml::Exited => NodeLifecycle::Exited,
    }
}

pub(super) fn assertion_phase_to_toml(state: AssertionPhase) -> AssertionPhaseToml {
    match state {
        AssertionPhase::Satisfied => AssertionPhaseToml::Satisfied,
        AssertionPhase::Violated => AssertionPhaseToml::Violated,
    }
}

pub(super) fn assertion_phase_from_toml(toml: AssertionPhaseToml) -> AssertionPhase {
    match toml {
        AssertionPhaseToml::Satisfied => AssertionPhase::Satisfied,
        AssertionPhaseToml::Violated => AssertionPhase::Violated,
    }
}

pub(super) fn reachability_expectation_to_toml(
    expectation: ReachabilityExpectation,
) -> ReachabilityExpectationToml {
    match expectation {
        ReachabilityExpectation::Reachable { on_unreached } => {
            ReachabilityExpectationToml::Reachable {
                on_unreached: reachable_disposition_to_toml(on_unreached),
            }
        }
        ReachabilityExpectation::Unreachable => ReachabilityExpectationToml::Unreachable,
    }
}

pub(super) fn reachability_expectation_from_toml(
    toml: ReachabilityExpectationToml,
) -> ReachabilityExpectation {
    match toml {
        ReachabilityExpectationToml::Reachable { on_unreached } => {
            ReachabilityExpectation::Reachable {
                on_unreached: reachable_disposition_from_toml(on_unreached),
            }
        }
        ReachabilityExpectationToml::Unreachable => ReachabilityExpectation::Unreachable,
    }
}

pub(super) fn reachable_disposition_to_toml(
    disposition: ReachableDisposition,
) -> ReachableDispositionToml {
    match disposition {
        ReachableDisposition::Warn => ReachableDispositionToml::Warn,
        ReachableDisposition::Fail => ReachableDispositionToml::Fail,
    }
}

pub(super) fn reachable_disposition_from_toml(
    toml: ReachableDispositionToml,
) -> ReachableDisposition {
    match toml {
        ReachableDispositionToml::Warn => ReachableDisposition::Warn,
        ReachableDispositionToml::Fail => ReachableDisposition::Fail,
    }
}

pub(super) fn seed_to_toml(seed: Seed) -> SeedToml {
    SeedToml {
        bytes: format_seed_ref(seed),
    }
}

pub(super) fn seed_from_toml(toml: &SeedToml) -> Result<Seed, EngineError> {
    parse_seed_ref(&toml.bytes)
}
