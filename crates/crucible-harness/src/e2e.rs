//! Mock-backend end-to-end determinism gate support.
//!
//! This module owns the shared mock backend used by the phase4 scheduler gate
//! and the CLI-owned phase7 acceptance target: a self-contained multi-node,
//! fault-injected reproduction artifact is replayed under adversarial host
//! profiles and reduced to a canonical log plus final fingerprint. Later
//! artifact-format, CLI produce/reproduce, and AOS VM/fleet tasks replace this
//! mock artifact route with real VM artifacts.

use std::error::Error;
use std::fmt;

use crate::adversarial::{
    AdversarialComparisonError, AdversarialRun, HostAdversaryError, HostAdversaryProfile,
    HostileProfile, ProducerConsumerPair, compare_adversarial_runs,
    run_profiled_producer_consumer_tasks,
};

/// A VM node in a mock e2e scenario.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct E2eNode {
    /// Stable node name.
    pub name: String,
    /// Scenario role such as `client`, `server`, or `database`.
    pub role: String,
}

/// An I/O sub-node attached to a VM node in a mock e2e scenario.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct E2eIoSubnode {
    /// Stable I/O sub-node name.
    pub name: String,
    /// VM node that owns the sub-node.
    pub attached_to: String,
    /// Sub-node family such as `blk` or `9p`.
    pub kind: String,
}

/// A directed network link in a mock e2e scenario.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct E2eLink {
    /// Stable link name.
    pub name: String,
    /// Source node name.
    pub from: String,
    /// Destination node name.
    pub to: String,
    /// Deterministic modeled latency in virtual ticks.
    pub latency_ticks: u64,
}

/// A representative fault class in a mock e2e scenario.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum E2eFaultKind {
    /// A connectivity partition fault.
    Partition,
    /// A packet or operation loss fault.
    Loss,
    /// A latency injection fault.
    Latency,
    /// A node or sub-node crash fault.
    Crash,
}

impl E2eFaultKind {
    fn as_str(self) -> &'static str {
        match self {
            Self::Partition => "partition",
            Self::Loss => "loss",
            Self::Latency => "latency",
            Self::Crash => "crash",
        }
    }
}

/// A deterministic fault available to a mock e2e scenario.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct E2eFault {
    /// Stable fault name.
    pub name: String,
    /// Fault class represented by the fault.
    pub kind: E2eFaultKind,
    /// Link or node affected by the fault.
    pub target: String,
    /// Virtual tick at which the fault is eligible.
    pub at_tick: u64,
    /// Canonical action description.
    pub action: String,
}

/// A property assertion class in a mock e2e scenario.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum E2ePropertyKind {
    /// A property that must hold for the whole run.
    Always,
    /// A property that must eventually become true.
    Eventually,
    /// A property that must be true at least once.
    Sometimes,
}

impl E2ePropertyKind {
    fn as_str(self) -> &'static str {
        match self {
            Self::Always => "always",
            Self::Eventually => "eventually",
            Self::Sometimes => "sometimes",
        }
    }
}

/// A property assertion in a mock e2e scenario.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct E2eProperty {
    /// Stable property name.
    pub name: String,
    /// Assertion class represented by the property.
    pub kind: E2ePropertyKind,
    /// Canonical subject or predicate description.
    pub subject: String,
}

/// A representative mock e2e scenario.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct E2eScenario {
    /// Stable scenario name.
    pub name: String,
    /// VM nodes participating in the run.
    pub nodes: Vec<E2eNode>,
    /// I/O sub-nodes participating in the run.
    pub io_subnodes: Vec<E2eIoSubnode>,
    /// Directed links between nodes.
    pub links: Vec<E2eLink>,
    /// Faults that can be injected into the run.
    pub faults: Vec<E2eFault>,
    /// Property assertions checked against the canonical log.
    pub properties: Vec<E2eProperty>,
}

/// One recorded mock e2e schedule decision.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum E2eDecision {
    /// A message delivery between two nodes.
    Deliver {
        /// Virtual tick at which the message is delivered.
        at_tick: u64,
        /// Source node name.
        from: String,
        /// Destination node name.
        to: String,
        /// Stable message sequence number.
        sequence: u64,
    },
    /// A fault outcome at a deterministic virtual tick.
    Fault {
        /// Virtual tick at which the fault outcome is resolved.
        at_tick: u64,
        /// Fault name.
        fault: String,
        /// Whether the probabilistic fault fired.
        fired: bool,
    },
    /// A deterministic application-random draw served to a node.
    AppRandom {
        /// Node that requested randomness.
        node: String,
        /// Named random stream.
        stream: String,
        /// Stable request id.
        request_id: u64,
        /// Recorded random value.
        value: u64,
    },
    /// A deterministic I/O completion from a sub-node.
    IoCompletion {
        /// Virtual tick at which the I/O completion is observed.
        at_tick: u64,
        /// I/O sub-node that completed the request.
        subnode: String,
        /// Stable request id.
        request_id: u64,
        /// Deterministic completed byte count.
        bytes: u64,
    },
    /// A property observation recorded into the canonical event log.
    PropertyObservation {
        /// Virtual tick at which the property was observed.
        at_tick: u64,
        /// Property name.
        property: String,
        /// Whether the property was satisfied by this observation.
        satisfied: bool,
    },
}

/// A recorded mock e2e schedule.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct E2eSchedule {
    /// Decisions in canonical replay order.
    pub decisions: Vec<E2eDecision>,
}

impl E2eSchedule {
    /// Returns the number of decisions in the schedule.
    #[must_use]
    pub fn len(&self) -> usize {
        self.decisions.len()
    }

    /// Returns whether the schedule is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.decisions.is_empty()
    }
}

/// Build identity pinned into a mock e2e reproduction artifact.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct E2eBuildIdentity {
    /// Crucible software version that produced the artifact.
    pub crucible_version: String,
    /// Harness ABI or schema version.
    pub harness_abi: String,
    /// Backend family used to produce the run.
    pub backend: String,
    /// Deterministic mock backend build id.
    pub backend_build_id: String,
    /// Hash of the ordered QEMU patch series applied to the producer backend.
    pub qemu_patch_series_hash: String,
    /// Shared-memory ABI version used by the producer backend.
    pub shmem_abi_version: String,
    /// Guest-host channel protocol version used by the producer backend.
    pub guest_host_protocol_version: String,
    /// Control-plane RPC ABI semantic version used by the producer backend.
    pub rpc_abi_version: String,
    /// Control-plane RPC ABI build tag used by the producer backend.
    pub rpc_abi_build: String,
    /// Plugin ABI version used by the producer backend.
    pub plugin_abi: String,
}

/// A self-contained mock e2e reproduction artifact.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct E2eReproductionArtifact {
    /// Deterministic campaign seed.
    pub seed: u64,
    /// Scenario definition.
    pub scenario: E2eScenario,
    /// Recorded schedule.
    pub schedule: E2eSchedule,
    /// Pinned build identity.
    pub build_identity: E2eBuildIdentity,
}

/// One completed mock e2e run under a host profile.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct E2eRun {
    /// Host profile name.
    pub profile: String,
    /// Canonical causal log bytes.
    pub canonical_log: Vec<u8>,
    /// Final deterministic fingerprint bytes.
    pub final_fingerprint: Vec<u8>,
    /// Digest of the reproduction artifact used for the run.
    pub artifact_digest: Vec<u8>,
}

/// A successful mock e2e gate report.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct E2eGateReport {
    /// Runs compared across adversarial host profiles.
    pub runs: Vec<E2eRun>,
    /// Replayed run reconstructed directly from the artifact.
    pub reproduced: E2eRun,
    /// Artifact replays executed on different machine profiles.
    pub cross_machine_reproductions: Vec<E2eRun>,
}

/// A mock e2e gate failure.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum E2eGateError {
    /// No adversarial profiles were supplied.
    EmptyProfileMatrix,
    /// The scenario has fewer than two VM nodes.
    ScenarioTooSmall {
        /// Scenario name.
        scenario: String,
        /// Number of nodes present.
        node_count: usize,
    },
    /// The scenario has no configured fault.
    MissingFault {
        /// Scenario name.
        scenario: String,
    },
    /// The scenario does not include any I/O sub-node.
    MissingIoSubnode {
        /// Scenario name.
        scenario: String,
    },
    /// The schedule contains no I/O completion decision.
    MissingIoCompletion {
        /// Scenario name.
        scenario: String,
    },
    /// The scenario does not include a required fault class.
    MissingFaultKind {
        /// Scenario name.
        scenario: String,
        /// Missing fault class.
        kind: E2eFaultKind,
    },
    /// The schedule does not fire a required fault class.
    MissingFiredFaultKind {
        /// Scenario name.
        scenario: String,
        /// Missing fired fault class.
        kind: E2eFaultKind,
    },
    /// The scenario does not include a required property class.
    MissingPropertyKind {
        /// Scenario name.
        scenario: String,
        /// Missing property class.
        kind: E2ePropertyKind,
    },
    /// A property did not have a satisfied observation.
    MissingSatisfiedProperty {
        /// Property name.
        property: String,
    },
    /// An always property had a false observation.
    FailedAlwaysProperty {
        /// Property name.
        property: String,
    },
    /// The schedule contains no fired fault decision.
    MissingFiredFaultDecision {
        /// Scenario name.
        scenario: String,
    },
    /// A link references a node absent from the scenario.
    UnknownLinkEndpoint {
        /// Link name.
        link: String,
        /// Missing node name.
        node: String,
    },
    /// A fault references a node or link absent from the scenario.
    UnknownFaultTarget {
        /// Fault name.
        fault: String,
        /// Missing target name.
        target: String,
    },
    /// An I/O sub-node references a node absent from the scenario.
    UnknownIoAttachment {
        /// I/O sub-node name.
        subnode: String,
        /// Missing node name.
        node: String,
    },
    /// A schedule decision references a node absent from the scenario.
    UnknownDecisionNode {
        /// Missing node name.
        node: String,
    },
    /// A schedule decision references an I/O sub-node absent from the scenario.
    UnknownDecisionIoSubnode {
        /// Missing I/O sub-node name.
        subnode: String,
    },
    /// A schedule decision references a fault absent from the scenario.
    UnknownDecisionFault {
        /// Missing fault name.
        fault: String,
    },
    /// A schedule decision references a property absent from the scenario.
    UnknownDecisionProperty {
        /// Missing property name.
        property: String,
    },
    /// The reproduction artifact was produced by a different build identity.
    BuildIdentityMismatch {
        /// Expected build identity.
        expected: Box<E2eBuildIdentity>,
        /// Build identity in the artifact.
        actual: Box<E2eBuildIdentity>,
    },
    /// The adversarial host fixture failed.
    HostAdversary(HostAdversaryError),
    /// Runs diverged under adversarial host profiles.
    AdversarialComparison(AdversarialComparisonError),
    /// No supplied profile represented a different machine from the baseline.
    MissingDifferentMachineProfile,
    /// Replaying the artifact did not match the baseline run.
    ReproductionMismatch {
        /// Baseline final fingerprint bytes.
        baseline: Vec<u8>,
        /// Reproduced final fingerprint bytes.
        reproduced: Vec<u8>,
    },
}

impl fmt::Display for E2eGateError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::EmptyProfileMatrix => write!(formatter, "e2e gate requires host profiles"),
            Self::ScenarioTooSmall {
                scenario,
                node_count,
            } => write!(
                formatter,
                "e2e scenario `{scenario}` has {node_count} nodes; at least two are required"
            ),
            Self::MissingFault { scenario } => {
                write!(formatter, "e2e scenario `{scenario}` has no fault")
            }
            Self::MissingIoSubnode { scenario } => {
                write!(formatter, "e2e scenario `{scenario}` has no I/O sub-node")
            }
            Self::MissingIoCompletion { scenario } => write!(
                formatter,
                "e2e scenario `{scenario}` schedule has no I/O completion"
            ),
            Self::MissingFaultKind { scenario, kind } => write!(
                formatter,
                "e2e scenario `{scenario}` is missing `{}` fault coverage",
                kind.as_str()
            ),
            Self::MissingFiredFaultKind { scenario, kind } => write!(
                formatter,
                "e2e scenario `{scenario}` schedule does not fire `{}` fault coverage",
                kind.as_str()
            ),
            Self::MissingPropertyKind { scenario, kind } => write!(
                formatter,
                "e2e scenario `{scenario}` is missing `{}` property coverage",
                kind.as_str()
            ),
            Self::MissingSatisfiedProperty { property } => write!(
                formatter,
                "e2e property `{property}` has no satisfied observation"
            ),
            Self::FailedAlwaysProperty { property } => write!(
                formatter,
                "e2e always property `{property}` has an unsatisfied observation"
            ),
            Self::MissingFiredFaultDecision { scenario } => write!(
                formatter,
                "e2e scenario `{scenario}` schedule has no fired fault decision"
            ),
            Self::UnknownLinkEndpoint { link, node } => {
                write!(
                    formatter,
                    "e2e link `{link}` references unknown node `{node}`"
                )
            }
            Self::UnknownFaultTarget { fault, target } => {
                write!(
                    formatter,
                    "e2e fault `{fault}` references unknown target `{target}`"
                )
            }
            Self::UnknownIoAttachment { subnode, node } => {
                write!(
                    formatter,
                    "e2e I/O sub-node `{subnode}` references unknown node `{node}`"
                )
            }
            Self::UnknownDecisionNode { node } => {
                write!(formatter, "e2e schedule references unknown node `{node}`")
            }
            Self::UnknownDecisionIoSubnode { subnode } => write!(
                formatter,
                "e2e schedule references unknown I/O sub-node `{subnode}`"
            ),
            Self::UnknownDecisionFault { fault } => {
                write!(formatter, "e2e schedule references unknown fault `{fault}`")
            }
            Self::UnknownDecisionProperty { property } => write!(
                formatter,
                "e2e schedule references unknown property `{property}`"
            ),
            Self::BuildIdentityMismatch { expected, actual } => write!(
                formatter,
                "e2e artifact build identity mismatch: expected {:?}, got {:?}",
                expected, actual
            ),
            Self::HostAdversary(error) => write!(formatter, "{error}"),
            Self::AdversarialComparison(error) => write!(formatter, "{error}"),
            Self::MissingDifferentMachineProfile => write!(
                formatter,
                "e2e gate requires at least one different machine reproduction profile"
            ),
            Self::ReproductionMismatch {
                baseline,
                reproduced,
            } => write!(
                formatter,
                "e2e artifact reproduction mismatch: baseline {} reproduced {}",
                hex_bytes(baseline),
                hex_bytes(reproduced)
            ),
        }
    }
}

impl Error for E2eGateError {}

impl From<HostAdversaryError> for E2eGateError {
    fn from(error: HostAdversaryError) -> Self {
        Self::HostAdversary(error)
    }
}

impl From<AdversarialComparisonError> for E2eGateError {
    fn from(error: AdversarialComparisonError) -> Self {
        Self::AdversarialComparison(error)
    }
}

/// Shared-memory ABI version used by canonical harness identities.
///
/// The included expression is compile-time checked against the authoritative
/// [`crucible_shmem::ABI_VERSION`](https://docs.rs/crucible-shmem) declaration
/// inside the owning crate without adding a runtime dependency from this
/// test-only harness.
pub const CANONICAL_SHMEM_ABI_VERSION: u32 = include!("../../crucible-shmem/src/abi_version.in");

/// Returns the canonical mock backend build identity.
#[must_use]
pub fn canonical_mock_build_identity() -> E2eBuildIdentity {
    E2eBuildIdentity {
        crucible_version: env!("CARGO_PKG_VERSION").to_string(),
        harness_abi: String::from("crucible-harness-e2e-v2"),
        backend: String::from("simdouble-mock"),
        backend_build_id: String::from("mock-backend-source-v1"),
        qemu_patch_series_hash: String::from(
            "crucible-hash:68444481cdcf0b86f376d0dafe6cfd40c39ba1fcecbab2a371a96d864fd3378c",
        ),
        shmem_abi_version: CANONICAL_SHMEM_ABI_VERSION.to_string(),
        guest_host_protocol_version: String::from("1"),
        rpc_abi_version: String::from("5.0.0"),
        rpc_abi_build: String::from("crucible-rpc-abi-v5"),
        plugin_abi: String::from("simdouble-mock-plugin-abi"),
    }
}

/// Returns the representative multi-node, fault-injected mock e2e artifact.
#[must_use]
pub fn representative_mock_e2e_artifact() -> E2eReproductionArtifact {
    E2eReproductionArtifact {
        seed: 0xe2e0_0010,
        scenario: E2eScenario {
            name: String::from("mock-partition-recovery"),
            nodes: vec![
                E2eNode {
                    name: String::from("client"),
                    role: String::from("client"),
                },
                E2eNode {
                    name: String::from("server"),
                    role: String::from("server"),
                },
                E2eNode {
                    name: String::from("witness"),
                    role: String::from("quorum-witness"),
                },
            ],
            io_subnodes: vec![
                E2eIoSubnode {
                    name: String::from("server-block"),
                    attached_to: String::from("server"),
                    kind: String::from("blk"),
                },
                E2eIoSubnode {
                    name: String::from("server-9p"),
                    attached_to: String::from("server"),
                    kind: String::from("9p"),
                },
            ],
            links: vec![
                E2eLink {
                    name: String::from("client-server"),
                    from: String::from("client"),
                    to: String::from("server"),
                    latency_ticks: 7,
                },
                E2eLink {
                    name: String::from("server-witness"),
                    from: String::from("server"),
                    to: String::from("witness"),
                    latency_ticks: 11,
                },
            ],
            faults: vec![
                E2eFault {
                    name: String::from("partition-client-server"),
                    kind: E2eFaultKind::Partition,
                    target: String::from("client-server"),
                    at_tick: 20,
                    action: String::from("drop-link"),
                },
                E2eFault {
                    name: String::from("loss-server-witness"),
                    kind: E2eFaultKind::Loss,
                    target: String::from("server-witness"),
                    at_tick: 22,
                    action: String::from("drop-next-frame"),
                },
                E2eFault {
                    name: String::from("latency-client-server"),
                    kind: E2eFaultKind::Latency,
                    target: String::from("client-server"),
                    at_tick: 24,
                    action: String::from("delay-13-ticks"),
                },
                E2eFault {
                    name: String::from("crash-server"),
                    kind: E2eFaultKind::Crash,
                    target: String::from("server"),
                    at_tick: 26,
                    action: String::from("crash-and-restart"),
                },
            ],
            properties: vec![
                E2eProperty {
                    name: String::from("no-past-delivery"),
                    kind: E2ePropertyKind::Always,
                    subject: String::from("deliveries occur at assigned virtual ticks"),
                },
                E2eProperty {
                    name: String::from("partition-recovers"),
                    kind: E2ePropertyKind::Eventually,
                    subject: String::from("client-server traffic resumes after partition"),
                },
                E2eProperty {
                    name: String::from("loss-observed"),
                    kind: E2ePropertyKind::Sometimes,
                    subject: String::from("loss fault affects at least one delivery"),
                },
            ],
        },
        schedule: E2eSchedule {
            decisions: vec![
                E2eDecision::Deliver {
                    at_tick: 5,
                    from: String::from("client"),
                    to: String::from("server"),
                    sequence: 1,
                },
                E2eDecision::IoCompletion {
                    at_tick: 13,
                    subnode: String::from("server-block"),
                    request_id: 1,
                    bytes: 4096,
                },
                E2eDecision::Fault {
                    at_tick: 20,
                    fault: String::from("partition-client-server"),
                    fired: true,
                },
                E2eDecision::Fault {
                    at_tick: 22,
                    fault: String::from("loss-server-witness"),
                    fired: true,
                },
                E2eDecision::Fault {
                    at_tick: 24,
                    fault: String::from("latency-client-server"),
                    fired: true,
                },
                E2eDecision::Fault {
                    at_tick: 26,
                    fault: String::from("crash-server"),
                    fired: true,
                },
                E2eDecision::Deliver {
                    at_tick: 31,
                    from: String::from("server"),
                    to: String::from("witness"),
                    sequence: 2,
                },
                E2eDecision::AppRandom {
                    node: String::from("server"),
                    stream: String::from("request-id"),
                    request_id: 3,
                    value: 0x00c0_ffee,
                },
                E2eDecision::IoCompletion {
                    at_tick: 37,
                    subnode: String::from("server-9p"),
                    request_id: 2,
                    bytes: 128,
                },
                E2eDecision::PropertyObservation {
                    at_tick: 39,
                    property: String::from("no-past-delivery"),
                    satisfied: true,
                },
                E2eDecision::PropertyObservation {
                    at_tick: 43,
                    property: String::from("partition-recovers"),
                    satisfied: true,
                },
                E2eDecision::PropertyObservation {
                    at_tick: 47,
                    property: String::from("loss-observed"),
                    satisfied: true,
                },
            ],
        },
        build_identity: canonical_mock_build_identity(),
    }
}

/// Runs the mock backend e2e determinism gate.
///
/// # Errors
///
/// Returns [`E2eGateError`] if the artifact is malformed, the build identity
/// does not match, the host-adversary fixture fails, runs diverge across host
/// profiles, or artifact replay fails to match the baseline.
pub fn run_mock_e2e_determinism_gate(
    artifact: &E2eReproductionArtifact,
    profiles: &[HostAdversaryProfile],
    expected_build_identity: &E2eBuildIdentity,
) -> Result<E2eGateReport, E2eGateError> {
    if profiles.is_empty() {
        return Err(E2eGateError::EmptyProfileMatrix);
    }

    artifact.validate(expected_build_identity)?;
    let mut runs = Vec::with_capacity(profiles.len());
    for profile in profiles {
        runs.push(run_mock_e2e_once(
            artifact,
            *profile,
            expected_build_identity,
        )?);
    }

    let adversarial_runs = runs
        .iter()
        .map(|run| AdversarialRun {
            profile: HostileProfile {
                name: run.profile.clone(),
            },
            canonical_log: run.canonical_log.clone(),
            final_fingerprint: run.final_fingerprint.clone(),
        })
        .collect::<Vec<_>>();
    compare_adversarial_runs(&adversarial_runs)?;

    let reproduced = reproduce_mock_e2e_artifact(artifact, expected_build_identity)?;
    let Some(baseline) = runs.first() else {
        return Err(E2eGateError::EmptyProfileMatrix);
    };
    if reproduced.canonical_log != baseline.canonical_log
        || reproduced.final_fingerprint != baseline.final_fingerprint
    {
        return Err(E2eGateError::ReproductionMismatch {
            baseline: baseline.final_fingerprint.clone(),
            reproduced: reproduced.final_fingerprint.clone(),
        });
    }

    let baseline_profile = profiles[0];
    let mut cross_machine_reproductions = Vec::new();
    for profile in profiles
        .iter()
        .copied()
        .filter(|profile| is_different_machine_profile(baseline_profile, *profile))
    {
        let reproduced_on_profile =
            reproduce_mock_e2e_artifact_on_profile(artifact, profile, expected_build_identity)?;
        if reproduced_on_profile.canonical_log != baseline.canonical_log
            || reproduced_on_profile.final_fingerprint != baseline.final_fingerprint
        {
            return Err(E2eGateError::ReproductionMismatch {
                baseline: baseline.final_fingerprint.clone(),
                reproduced: reproduced_on_profile.final_fingerprint,
            });
        }
        cross_machine_reproductions.push(reproduced_on_profile);
    }
    if cross_machine_reproductions.is_empty() {
        return Err(E2eGateError::MissingDifferentMachineProfile);
    }

    Ok(E2eGateReport {
        runs,
        reproduced,
        cross_machine_reproductions,
    })
}

/// Replays a mock e2e reproduction artifact under the quiet baseline profile.
///
/// # Errors
///
/// Returns [`E2eGateError`] if the artifact is malformed or its build identity
/// does not match the expected identity.
pub fn reproduce_mock_e2e_artifact(
    artifact: &E2eReproductionArtifact,
    expected_build_identity: &E2eBuildIdentity,
) -> Result<E2eRun, E2eGateError> {
    run_mock_e2e_once(
        artifact,
        HostAdversaryProfile::quiet_single_core(),
        expected_build_identity,
    )
}

/// Replays a mock e2e reproduction artifact under the supplied host profile.
///
/// # Errors
///
/// Returns [`E2eGateError`] if the artifact is malformed, its build identity
/// does not match the expected identity, or the host-adversary fixture fails.
pub fn reproduce_mock_e2e_artifact_on_profile(
    artifact: &E2eReproductionArtifact,
    profile: HostAdversaryProfile,
    expected_build_identity: &E2eBuildIdentity,
) -> Result<E2eRun, E2eGateError> {
    run_mock_e2e_once(artifact, profile, expected_build_identity)
}

fn run_mock_e2e_once(
    artifact: &E2eReproductionArtifact,
    profile: HostAdversaryProfile,
    expected_build_identity: &E2eBuildIdentity,
) -> Result<E2eRun, E2eGateError> {
    artifact.validate(expected_build_identity)?;
    let task_pairs = run_profiled_producer_consumer_tasks(
        profile,
        artifact.schedule.len(),
        |task| format!("producer:{}", task.index),
        |task| format!("consumer:{}", task.index),
    )?;
    let canonical_log = canonical_log_material(artifact, &task_pairs).into_bytes();
    let artifact_material = artifact.canonical_material();
    let artifact_digest = stable_digest("crucible.e2e.artifact.v1", &artifact_material);
    let fingerprint_material = format!(
        "artifact={}\nlog={}\n",
        hex_bytes(&artifact_digest),
        String::from_utf8_lossy(&canonical_log)
    );
    let final_fingerprint = stable_digest("crucible.e2e.fingerprint.v1", &fingerprint_material);

    Ok(E2eRun {
        profile: profile.name.to_string(),
        canonical_log,
        final_fingerprint,
        artifact_digest,
    })
}

fn is_different_machine_profile(
    baseline: HostAdversaryProfile,
    candidate: HostAdversaryProfile,
) -> bool {
    candidate.worker_count != baseline.worker_count
        || candidate.task_order != baseline.task_order
        || candidate.affinity != baseline.affinity
        || candidate.load != baseline.load
        || candidate.producer_consumer_skew != baseline.producer_consumer_skew
}

impl E2eReproductionArtifact {
    fn validate(&self, expected_build_identity: &E2eBuildIdentity) -> Result<(), E2eGateError> {
        if &self.build_identity != expected_build_identity {
            return Err(E2eGateError::BuildIdentityMismatch {
                expected: Box::new(expected_build_identity.clone()),
                actual: Box::new(self.build_identity.clone()),
            });
        }
        if self.scenario.nodes.len() < 2 {
            return Err(E2eGateError::ScenarioTooSmall {
                scenario: self.scenario.name.clone(),
                node_count: self.scenario.nodes.len(),
            });
        }
        if self.scenario.faults.is_empty() {
            return Err(E2eGateError::MissingFault {
                scenario: self.scenario.name.clone(),
            });
        }
        if self.scenario.io_subnodes.is_empty() {
            return Err(E2eGateError::MissingIoSubnode {
                scenario: self.scenario.name.clone(),
            });
        }
        if !self
            .schedule
            .decisions
            .iter()
            .any(|decision| matches!(decision, E2eDecision::IoCompletion { .. }))
        {
            return Err(E2eGateError::MissingIoCompletion {
                scenario: self.scenario.name.clone(),
            });
        }
        if !self
            .schedule
            .decisions
            .iter()
            .any(|decision| matches!(decision, E2eDecision::Fault { fired: true, .. }))
        {
            return Err(E2eGateError::MissingFiredFaultDecision {
                scenario: self.scenario.name.clone(),
            });
        }
        for required_kind in [
            E2eFaultKind::Partition,
            E2eFaultKind::Loss,
            E2eFaultKind::Latency,
            E2eFaultKind::Crash,
        ] {
            if !self
                .scenario
                .faults
                .iter()
                .any(|fault| fault.kind == required_kind)
            {
                return Err(E2eGateError::MissingFaultKind {
                    scenario: self.scenario.name.clone(),
                    kind: required_kind,
                });
            }
            if !self.schedule.decisions.iter().any(|decision| {
                let E2eDecision::Fault { fault, fired, .. } = decision else {
                    return false;
                };
                *fired
                    && self.scenario.faults.iter().any(|candidate| {
                        candidate.name == *fault && candidate.kind == required_kind
                    })
            }) {
                return Err(E2eGateError::MissingFiredFaultKind {
                    scenario: self.scenario.name.clone(),
                    kind: required_kind,
                });
            }
        }
        for required_kind in [
            E2ePropertyKind::Always,
            E2ePropertyKind::Eventually,
            E2ePropertyKind::Sometimes,
        ] {
            if !self
                .scenario
                .properties
                .iter()
                .any(|property| property.kind == required_kind)
            {
                return Err(E2eGateError::MissingPropertyKind {
                    scenario: self.scenario.name.clone(),
                    kind: required_kind,
                });
            }
        }

        let node_names = self
            .scenario
            .nodes
            .iter()
            .map(|node| node.name.as_str())
            .collect::<Vec<_>>();
        let io_names = self
            .scenario
            .io_subnodes
            .iter()
            .map(|io_subnode| io_subnode.name.as_str())
            .collect::<Vec<_>>();
        let fault_names = self
            .scenario
            .faults
            .iter()
            .map(|fault| fault.name.as_str())
            .collect::<Vec<_>>();
        let property_names = self
            .scenario
            .properties
            .iter()
            .map(|property| property.name.as_str())
            .collect::<Vec<_>>();
        let link_names = self
            .scenario
            .links
            .iter()
            .map(|link| link.name.as_str())
            .collect::<Vec<_>>();

        for link in &self.scenario.links {
            if !node_names.contains(&link.from.as_str()) {
                return Err(E2eGateError::UnknownLinkEndpoint {
                    link: link.name.clone(),
                    node: link.from.clone(),
                });
            }
            if !node_names.contains(&link.to.as_str()) {
                return Err(E2eGateError::UnknownLinkEndpoint {
                    link: link.name.clone(),
                    node: link.to.clone(),
                });
            }
        }
        for io_subnode in &self.scenario.io_subnodes {
            if !node_names.contains(&io_subnode.attached_to.as_str()) {
                return Err(E2eGateError::UnknownIoAttachment {
                    subnode: io_subnode.name.clone(),
                    node: io_subnode.attached_to.clone(),
                });
            }
        }
        for fault in &self.scenario.faults {
            if !node_names.contains(&fault.target.as_str())
                && !link_names.contains(&fault.target.as_str())
                && !io_names.contains(&fault.target.as_str())
            {
                return Err(E2eGateError::UnknownFaultTarget {
                    fault: fault.name.clone(),
                    target: fault.target.clone(),
                });
            }
        }

        for decision in &self.schedule.decisions {
            match decision {
                E2eDecision::Deliver { from, to, .. } => {
                    if !node_names.contains(&from.as_str()) {
                        return Err(E2eGateError::UnknownDecisionNode { node: from.clone() });
                    }
                    if !node_names.contains(&to.as_str()) {
                        return Err(E2eGateError::UnknownDecisionNode { node: to.clone() });
                    }
                }
                E2eDecision::Fault { fault, .. } => {
                    if !fault_names.contains(&fault.as_str()) {
                        return Err(E2eGateError::UnknownDecisionFault {
                            fault: fault.clone(),
                        });
                    }
                }
                E2eDecision::AppRandom { node, .. } => {
                    if !node_names.contains(&node.as_str()) {
                        return Err(E2eGateError::UnknownDecisionNode { node: node.clone() });
                    }
                }
                E2eDecision::IoCompletion { subnode, .. } => {
                    if !io_names.contains(&subnode.as_str()) {
                        return Err(E2eGateError::UnknownDecisionIoSubnode {
                            subnode: subnode.clone(),
                        });
                    }
                }
                E2eDecision::PropertyObservation { property, .. } => {
                    if !property_names.contains(&property.as_str()) {
                        return Err(E2eGateError::UnknownDecisionProperty {
                            property: property.clone(),
                        });
                    }
                }
            }
        }
        for property in &self.scenario.properties {
            if property.kind == E2ePropertyKind::Always
                && self.schedule.decisions.iter().any(|decision| {
                    matches!(
                        decision,
                        E2eDecision::PropertyObservation {
                            property: observed,
                            satisfied: false,
                            ..
                        } if observed == &property.name
                    )
                })
            {
                return Err(E2eGateError::FailedAlwaysProperty {
                    property: property.name.clone(),
                });
            }
            if !self.schedule.decisions.iter().any(|decision| {
                matches!(
                    decision,
                    E2eDecision::PropertyObservation {
                        property: observed,
                        satisfied: true,
                        ..
                    } if observed == &property.name
                )
            }) {
                return Err(E2eGateError::MissingSatisfiedProperty {
                    property: property.name.clone(),
                });
            }
        }

        Ok(())
    }

    fn canonical_material(&self) -> String {
        let mut material = CanonicalMaterial::new();
        material.record("seed", &[CanonicalField::U64(self.seed)]);
        material.record(
            "build",
            &[
                CanonicalField::Str(&self.build_identity.crucible_version),
                CanonicalField::Str(&self.build_identity.harness_abi),
                CanonicalField::Str(&self.build_identity.backend),
                CanonicalField::Str(&self.build_identity.backend_build_id),
                CanonicalField::Str(&self.build_identity.qemu_patch_series_hash),
                CanonicalField::Str(&self.build_identity.shmem_abi_version),
                CanonicalField::Str(&self.build_identity.guest_host_protocol_version),
                CanonicalField::Str(&self.build_identity.rpc_abi_version),
                CanonicalField::Str(&self.build_identity.rpc_abi_build),
                CanonicalField::Str(&self.build_identity.plugin_abi),
            ],
        );
        material.record("scenario", &[CanonicalField::Str(&self.scenario.name)]);
        for node in &self.scenario.nodes {
            material.record(
                "node",
                &[
                    CanonicalField::Str(&node.name),
                    CanonicalField::Str(&node.role),
                ],
            );
        }
        for io_subnode in &self.scenario.io_subnodes {
            material.record(
                "io-subnode",
                &[
                    CanonicalField::Str(&io_subnode.name),
                    CanonicalField::Str(&io_subnode.attached_to),
                    CanonicalField::Str(&io_subnode.kind),
                ],
            );
        }
        for link in &self.scenario.links {
            material.record(
                "link",
                &[
                    CanonicalField::Str(&link.name),
                    CanonicalField::Str(&link.from),
                    CanonicalField::Str(&link.to),
                    CanonicalField::U64(link.latency_ticks),
                ],
            );
        }
        for fault in &self.scenario.faults {
            material.record(
                "fault",
                &[
                    CanonicalField::Str(&fault.name),
                    CanonicalField::Str(fault.kind.as_str()),
                    CanonicalField::Str(&fault.target),
                    CanonicalField::U64(fault.at_tick),
                    CanonicalField::Str(&fault.action),
                ],
            );
        }
        for property in &self.scenario.properties {
            material.record(
                "property",
                &[
                    CanonicalField::Str(&property.name),
                    CanonicalField::Str(property.kind.as_str()),
                    CanonicalField::Str(&property.subject),
                ],
            );
        }
        for decision in &self.schedule.decisions {
            push_decision_record(&mut material, decision);
        }
        material.finish()
    }
}

fn canonical_log_material(
    artifact: &E2eReproductionArtifact,
    task_pairs: &[ProducerConsumerPair<String, String>],
) -> String {
    let mut material = CanonicalMaterial::new();
    material.record("log", &[CanonicalField::Str("crucible.e2e.mock.v1")]);
    material.record("scenario", &[CanonicalField::Str(&artifact.scenario.name)]);
    material.record("seed", &[CanonicalField::U64(artifact.seed)]);
    for pair in task_pairs {
        let decision = &artifact.schedule.decisions[pair.task.index];
        material.record(
            "event",
            &[
                CanonicalField::U64(pair.task.index as u64),
                CanonicalField::Str(&pair.producer),
                CanonicalField::Str(&pair.consumer),
            ],
        );
        push_decision_record(&mut material, decision);
    }
    material.finish()
}

fn push_decision_record(material: &mut CanonicalMaterial, decision: &E2eDecision) {
    match decision {
        E2eDecision::Deliver {
            at_tick,
            from,
            to,
            sequence,
        } => material.record(
            "decision.deliver",
            &[
                CanonicalField::U64(*at_tick),
                CanonicalField::Str(from),
                CanonicalField::Str(to),
                CanonicalField::U64(*sequence),
            ],
        ),
        E2eDecision::Fault {
            at_tick,
            fault,
            fired,
        } => material.record(
            "decision.fault",
            &[
                CanonicalField::U64(*at_tick),
                CanonicalField::Str(fault),
                CanonicalField::Bool(*fired),
            ],
        ),
        E2eDecision::AppRandom {
            node,
            stream,
            request_id,
            value,
        } => material.record(
            "decision.app-random",
            &[
                CanonicalField::Str(node),
                CanonicalField::Str(stream),
                CanonicalField::U64(*request_id),
                CanonicalField::U64(*value),
            ],
        ),
        E2eDecision::IoCompletion {
            at_tick,
            subnode,
            request_id,
            bytes,
        } => material.record(
            "decision.io-completion",
            &[
                CanonicalField::U64(*at_tick),
                CanonicalField::Str(subnode),
                CanonicalField::U64(*request_id),
                CanonicalField::U64(*bytes),
            ],
        ),
        E2eDecision::PropertyObservation {
            at_tick,
            property,
            satisfied,
        } => material.record(
            "decision.property",
            &[
                CanonicalField::U64(*at_tick),
                CanonicalField::Str(property),
                CanonicalField::Bool(*satisfied),
            ],
        ),
    }
}

struct CanonicalMaterial {
    output: String,
}

impl CanonicalMaterial {
    fn new() -> Self {
        Self {
            output: String::new(),
        }
    }

    fn record(&mut self, tag: &str, fields: &[CanonicalField<'_>]) {
        self.length_prefixed(tag);
        self.output.push(' ');
        self.output.push_str(&fields.len().to_string());
        for field in fields {
            self.output.push(' ');
            match field {
                CanonicalField::Str(value) => self.length_prefixed(value),
                CanonicalField::U64(value) => self.length_prefixed(&value.to_string()),
                CanonicalField::Bool(value) => {
                    self.length_prefixed(if *value { "true" } else { "false" });
                }
            }
        }
        self.output.push('\n');
    }

    fn finish(self) -> String {
        self.output
    }

    fn length_prefixed(&mut self, value: &str) {
        self.output.push_str(&value.len().to_string());
        self.output.push(':');
        self.output.push_str(value);
    }
}

enum CanonicalField<'a> {
    Str(&'a str),
    U64(u64),
    Bool(bool),
}

fn stable_digest(domain: &str, material: &str) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(32);
    for lane in 0..4 {
        let mut state = 0xcbf2_9ce4_8422_2325u64 ^ lane;
        for byte in domain.bytes().chain([0xff]).chain(material.bytes()) {
            state ^= u64::from(byte);
            state = state.wrapping_mul(0x0000_0100_0000_01b3);
            state ^= state.rotate_left(17);
        }
        bytes.extend_from_slice(&state.to_be_bytes());
    }
    bytes
}

fn hex_bytes(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut encoded = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        encoded.push(HEX[(byte >> 4) as usize] as char);
        encoded.push(HEX[(byte & 0x0f) as usize] as char);
    }
    encoded
}
