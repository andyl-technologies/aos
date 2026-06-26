//! Mock-backend end-to-end determinism gate support.
//!
//! The final `gate:e2e-determinism` acceptance target needs real VM artifacts,
//! CLI plumbing, and machine-independent replay. This module owns the earlier
//! harness-level mock backend: a self-contained multi-node, fault-injected
//! reproduction artifact is replayed under adversarial host profiles and reduced
//! to a canonical log plus final fingerprint.

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

/// A deterministic fault available to a mock e2e scenario.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct E2eFault {
    /// Stable fault name.
    pub name: String,
    /// Link or node affected by the fault.
    pub target: String,
    /// Virtual tick at which the fault is eligible.
    pub at_tick: u64,
    /// Canonical action description.
    pub action: String,
}

/// A representative mock e2e scenario.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct E2eScenario {
    /// Stable scenario name.
    pub name: String,
    /// VM nodes participating in the run.
    pub nodes: Vec<E2eNode>,
    /// Directed links between nodes.
    pub links: Vec<E2eLink>,
    /// Faults that can be injected into the run.
    pub faults: Vec<E2eFault>,
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
    /// Harness ABI or schema version.
    pub harness_abi: String,
    /// Backend family used to produce the run.
    pub backend: String,
    /// Deterministic mock backend build id.
    pub backend_build_id: String,
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
    /// A schedule decision references a node absent from the scenario.
    UnknownDecisionNode {
        /// Missing node name.
        node: String,
    },
    /// A schedule decision references a fault absent from the scenario.
    UnknownDecisionFault {
        /// Missing fault name.
        fault: String,
    },
    /// The reproduction artifact was produced by a different build identity.
    BuildIdentityMismatch {
        /// Expected build identity.
        expected: E2eBuildIdentity,
        /// Build identity in the artifact.
        actual: E2eBuildIdentity,
    },
    /// The adversarial host fixture failed.
    HostAdversary(HostAdversaryError),
    /// Runs diverged under adversarial host profiles.
    AdversarialComparison(AdversarialComparisonError),
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
            Self::UnknownDecisionNode { node } => {
                write!(formatter, "e2e schedule references unknown node `{node}`")
            }
            Self::UnknownDecisionFault { fault } => {
                write!(formatter, "e2e schedule references unknown fault `{fault}`")
            }
            Self::BuildIdentityMismatch { expected, actual } => write!(
                formatter,
                "e2e artifact build identity mismatch: expected {:?}, got {:?}",
                expected, actual
            ),
            Self::HostAdversary(error) => write!(formatter, "{error}"),
            Self::AdversarialComparison(error) => write!(formatter, "{error}"),
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

/// Returns the canonical mock backend build identity.
#[must_use]
pub fn canonical_mock_build_identity() -> E2eBuildIdentity {
    E2eBuildIdentity {
        harness_abi: String::from("crucible-harness-e2e-v1"),
        backend: String::from("simdouble-mock"),
        backend_build_id: String::from("mock-backend-source-v1"),
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
            faults: vec![E2eFault {
                name: String::from("partition-client-server"),
                target: String::from("client-server"),
                at_tick: 20,
                action: String::from("drop-link"),
            }],
        },
        schedule: E2eSchedule {
            decisions: vec![
                E2eDecision::Deliver {
                    at_tick: 5,
                    from: String::from("client"),
                    to: String::from("server"),
                    sequence: 1,
                },
                E2eDecision::Fault {
                    at_tick: 20,
                    fault: String::from("partition-client-server"),
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

    Ok(E2eGateReport { runs, reproduced })
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

impl E2eReproductionArtifact {
    fn validate(&self, expected_build_identity: &E2eBuildIdentity) -> Result<(), E2eGateError> {
        if &self.build_identity != expected_build_identity {
            return Err(E2eGateError::BuildIdentityMismatch {
                expected: expected_build_identity.clone(),
                actual: self.build_identity.clone(),
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

        let node_names = self
            .scenario
            .nodes
            .iter()
            .map(|node| node.name.as_str())
            .collect::<Vec<_>>();
        let fault_names = self
            .scenario
            .faults
            .iter()
            .map(|fault| fault.name.as_str())
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
        for fault in &self.scenario.faults {
            if !node_names.contains(&fault.target.as_str())
                && !link_names.contains(&fault.target.as_str())
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
                CanonicalField::Str(&self.build_identity.harness_abi),
                CanonicalField::Str(&self.build_identity.backend),
                CanonicalField::Str(&self.build_identity.backend_build_id),
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
                    CanonicalField::Str(&fault.target),
                    CanonicalField::U64(fault.at_tick),
                    CanonicalField::Str(&fault.action),
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
