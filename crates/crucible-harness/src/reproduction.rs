//! Versioned reproduction artifact format.
//!
//! A reproduction artifact is the transport form of `(seed, ScenarioDef,
//! Schedule)` plus pinned producer identities and content-addressed component
//! references. The format is intentionally small: the schedule travels in the
//! artifact, while large scenario components are named by content hash and a
//! hermetic `cas:` URI. The encoding is a canonical tab-separated line format
//! with percent-escaped string fields.
//!
//! ```text
//! schema  crucible.reproduction-artifact.v3
//! seed    42
//! identity  0.1.0  engine-abi:v1  crucible.reproduction-artifact.v3  crucible-hash:...  crucible-hash:...  1  1  5.1.0  crucible-rpc-abi-v5  plugin-abi:v1
//! scenario  scenario_def  cluster.scn  crucible-hash:...  cas:crucible-hash:...  application/vnd.crucible.scenario+text  128
//! payload  crucible-hash:...  7363656e6172696f
//! schedule  crucible-hash:...  12
//! decision  0  1  node-a  deliver  crucible-hash:...
//! ```

use std::collections::BTreeMap;
use std::error::Error;
use std::fmt;

use crate::adversarial::{
    HostAdversaryProfile, ProducerConsumerPair, run_profiled_producer_consumer_tasks,
};
use crate::e2e::{
    E2eBuildIdentity, E2eDecision, E2eFaultKind, E2ePropertyKind, E2eReproductionArtifact,
    canonical_mock_build_identity, representative_mock_e2e_artifact, reproduce_mock_e2e_artifact,
};

/// Current reproduction artifact schema identifier.
pub const REPRODUCTION_ARTIFACT_SCHEMA: &str = "crucible.reproduction-artifact.v3";

/// Media type for the canonical artifact encoding.
pub const REPRODUCTION_ARTIFACT_MEDIA_TYPE: &str = "application/vnd.crucible.reproduction+text";

/// Component name for recorded producer canonical-log evidence.
pub const PRODUCER_CANONICAL_LOG_COMPONENT_NAME: &str = "producer-canonical-log";

/// Component name for recorded producer final-fingerprint evidence.
pub const PRODUCER_FINAL_FINGERPRINT_COMPONENT_NAME: &str = "producer-final-fingerprint";

/// Component name for the source producer artifact digest.
pub const PRODUCER_ARTIFACT_DIGEST_COMPONENT_NAME: &str = "producer-artifact-digest";

/// Component name for the source producer backend build id.
pub const PRODUCER_BACKEND_BUILD_ID_COMPONENT_NAME: &str = "producer-backend-build-id";

/// Media type for recorded producer canonical-log evidence.
pub const PRODUCER_CANONICAL_LOG_MEDIA_TYPE: &str =
    "application/vnd.crucible.producer-canonical-log+bytes";

/// Media type for recorded producer final-fingerprint evidence.
pub const PRODUCER_FINAL_FINGERPRINT_MEDIA_TYPE: &str =
    "application/vnd.crucible.producer-final-fingerprint+bytes";

/// Media type for the source producer artifact digest.
pub const PRODUCER_ARTIFACT_DIGEST_MEDIA_TYPE: &str =
    "application/vnd.crucible.producer-artifact-digest+bytes";

/// Media type for the source producer backend build id.
pub const PRODUCER_BACKEND_BUILD_ID_MEDIA_TYPE: &str =
    "application/vnd.crucible.producer-backend-build-id+text";

/// Media type for recorded decision payload evidence.
pub const RECORDED_DECISION_PAYLOAD_MEDIA_TYPE: &str =
    "application/vnd.crucible.recorded-decision-payload+text";

/// Schema for campaign provenance keys derived from pinned producer identities.
pub const CAMPAIGN_PROVENANCE_SCHEMA: &str = "crucible.campaign.provenance.v1";

/// Schema for a recorded fresh-lineage baseline event.
pub const CAMPAIGN_FRESH_LINEAGE_BASELINE_EVENT_SCHEMA: &str =
    "crucible.campaign.fresh-lineage-baseline.v1";

/// Reason recorded when a prior corpus is refused across provenance boundaries.
pub const CAMPAIGN_CROSS_PROVENANCE_REFUSAL_REASON: &str = "cross-provenance-corpus-reuse-refused";

/// A versioned reproduction artifact.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ReproductionArtifact {
    /// Schema identifier for this artifact.
    pub schema_version: String,
    /// Deterministic root seed used by the run.
    pub seed: u64,
    /// Pinned engine, QEMU, ABI, and plugin identities for the producer.
    pub build_identity: PinnedBuildIdentity,
    /// Content-addressed scenario definition reference.
    pub scenario: ContentAddressedComponent,
    /// Totally ordered schedule of replay decisions.
    pub schedule: ReproductionSchedule,
    /// Additional content-addressed components needed to resolve the scenario.
    pub components: Vec<ContentAddressedComponent>,
    /// Inline payloads for small components that travel with the artifact.
    pub component_payloads: Vec<ComponentPayload>,
    /// Tail of the fingerprint stream recorded for quick triage.
    pub fingerprint_tail: Vec<FingerprintTailSample>,
    /// Fingerprint sampling configuration used by the producer.
    pub sampling_config: FingerprintSamplingConfig,
}

/// Inputs used to construct a validated reproduction artifact.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ReproductionArtifactParts {
    /// Deterministic root seed used by the run.
    pub seed: u64,
    /// Pinned engine, QEMU, ABI, and plugin identities for the producer.
    pub build_identity: PinnedBuildIdentity,
    /// Content-addressed scenario definition reference.
    pub scenario: ContentAddressedComponent,
    /// Replay decisions to store as a totally ordered schedule.
    pub decisions: Vec<RecordedDecision>,
    /// Additional content-addressed components needed to resolve the scenario.
    pub components: Vec<ContentAddressedComponent>,
    /// Inline payloads for small components that travel with the artifact.
    pub component_payloads: Vec<ComponentPayload>,
    /// Tail of the fingerprint stream recorded for quick triage.
    pub fingerprint_tail: Vec<FingerprintTailSample>,
    /// Fingerprint sampling configuration used by the producer.
    pub sampling_config: FingerprintSamplingConfig,
}

/// A successful machine-independent reproduction verification report.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MachineReproductionReport {
    /// Content address of the validated artifact bytes.
    pub artifact_digest: String,
    /// Baseline reproduction run used for byte comparison.
    pub baseline: MachineReproductionRun,
    /// Reproduction runs from host profiles that differ from the baseline.
    pub reproduced_on_different_machine_profiles: Vec<MachineReproductionRun>,
}

/// One reproduction run derived from a versioned artifact.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MachineReproductionRun {
    /// Host profile used to execute the reproduction.
    pub profile: String,
    /// Canonical log bytes produced by the replay.
    pub canonical_log: Vec<u8>,
    /// Final execution fingerprint bytes produced by the replay.
    pub final_fingerprint: Vec<u8>,
    /// Content address of the artifact replayed by this run.
    pub artifact_digest: String,
}

/// The reproduction output field that diverged across host profiles.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MachineReproductionMismatchKind {
    /// The canonical log bytes differed.
    CanonicalLog,
    /// The final fingerprint bytes differed.
    FinalFingerprint,
}

impl ReproductionArtifact {
    /// Builds a validated reproduction artifact and computes its schedule digest.
    ///
    /// # Errors
    ///
    /// Returns [`ReproductionArtifactError`] when the artifact fields are
    /// malformed, the scenario is not a scenario definition reference, a digest
    /// is invalid, or the schedule is empty or not totally ordered.
    pub fn from_parts(parts: ReproductionArtifactParts) -> Result<Self, ReproductionArtifactError> {
        let ReproductionArtifactParts {
            seed,
            build_identity,
            scenario,
            decisions,
            components,
            component_payloads,
            fingerprint_tail,
            sampling_config,
        } = parts;
        let schedule = ReproductionSchedule::from_decisions(decisions)?;
        let artifact = Self {
            schema_version: REPRODUCTION_ARTIFACT_SCHEMA.to_string(),
            seed,
            build_identity,
            scenario,
            schedule,
            components,
            component_payloads,
            fingerprint_tail,
            sampling_config,
        };
        artifact.validate()?;
        Ok(artifact)
    }

    /// Encodes the artifact as canonical bytes.
    ///
    /// # Errors
    ///
    /// Returns [`ReproductionArtifactError`] when validation fails.
    pub fn encode(&self) -> Result<Vec<u8>, ReproductionArtifactError> {
        self.validate()?;
        Ok(self.encode_unchecked().into_bytes())
    }

    /// Decodes and validates canonical artifact bytes.
    ///
    /// # Errors
    ///
    /// Returns [`ReproductionArtifactError`] when the bytes are not valid UTF-8,
    /// the line format is malformed, or the decoded artifact violates the schema.
    pub fn decode(bytes: &[u8]) -> Result<Self, ReproductionArtifactError> {
        let text =
            std::str::from_utf8(bytes).map_err(|error| ReproductionArtifactError::Decode {
                reason: error.to_string(),
            })?;
        let artifact = decode_artifact(text)?;
        artifact.validate()?;
        if artifact.encode_unchecked() != text {
            return Err(ReproductionArtifactError::Decode {
                reason: String::from("non-canonical artifact encoding"),
            });
        }
        Ok(artifact)
    }

    /// Returns the content address of the encoded artifact.
    ///
    /// # Errors
    ///
    /// Returns [`ReproductionArtifactError`] when validation fails.
    pub fn digest(&self) -> Result<String, ReproductionArtifactError> {
        Ok(content_address_bytes(&self.encode()?))
    }

    /// Validates all artifact invariants.
    ///
    /// # Errors
    ///
    /// Returns [`ReproductionArtifactError`] when a required identity is empty, a
    /// digest is malformed, the scenario reference has the wrong kind, or the
    /// schedule digest does not match its decisions.
    pub fn validate(&self) -> Result<(), ReproductionArtifactError> {
        if self.schema_version != REPRODUCTION_ARTIFACT_SCHEMA {
            return Err(ReproductionArtifactError::UnsupportedSchema {
                schema_version: self.schema_version.clone(),
            });
        }
        self.build_identity.validate()?;
        if self.scenario.kind != ComponentKind::ScenarioDef {
            return Err(ReproductionArtifactError::ScenarioReferenceWrongKind {
                kind: self.scenario.kind,
            });
        }
        self.scenario.validate("scenario")?;
        self.schedule.validate()?;
        for component in &self.components {
            component.validate("component")?;
        }
        for payload in &self.component_payloads {
            payload.validate()?;
        }
        if !self.components.iter().any(|component| {
            component.kind == ComponentKind::ScenarioDef
                && component.digest == self.scenario.digest
                && component.store_uri == self.scenario.store_uri
        }) {
            return Err(ReproductionArtifactError::ScenarioComponentMissing {
                digest: self.scenario.digest.clone(),
            });
        }
        for payload in &self.component_payloads {
            if !self
                .components
                .iter()
                .any(|component| component.digest == payload.digest)
                && self.scenario.digest != payload.digest
            {
                return Err(ReproductionArtifactError::PayloadComponentMissing {
                    digest: payload.digest.clone(),
                });
            }
        }
        for sample in &self.fingerprint_tail {
            validate_digest("fingerprint_tail.digest", &sample.digest)?;
        }
        self.sampling_config.validate()?;
        Ok(())
    }

    fn encode_unchecked(&self) -> String {
        let mut text = String::new();
        line(&mut text, &["schema", &self.schema_version]);
        line(&mut text, &["seed", &self.seed.to_string()]);
        line(
            &mut text,
            &[
                "identity",
                &self.build_identity.engine_version,
                &self.build_identity.engine_abi,
                &self.build_identity.artifact_abi,
                &self.build_identity.qemu_build_id,
                &self.build_identity.qemu_patch_series_hash,
                &self.build_identity.shmem_abi_version,
                &self.build_identity.guest_host_protocol_version,
                &self.build_identity.rpc_abi_version,
                &self.build_identity.rpc_abi_build,
                &self.build_identity.plugin_abi,
            ],
        );
        component_line(&mut text, "scenario", &self.scenario);
        for component in &self.components {
            component_line(&mut text, "component", component);
        }
        for payload in &self.component_payloads {
            line(
                &mut text,
                &["payload", &payload.digest, &hex_bytes(&payload.bytes)],
            );
        }
        line(
            &mut text,
            &[
                "schedule",
                &self.schedule.digest,
                &self.schedule.decisions.len().to_string(),
            ],
        );
        for decision in &self.schedule.decisions {
            line(
                &mut text,
                &[
                    "decision",
                    &decision.sequence.to_string(),
                    &decision.virtual_time_ticks.to_string(),
                    &decision.node,
                    &decision.kind,
                    &decision.payload_digest,
                ],
            );
        }
        for sample in &self.fingerprint_tail {
            line(
                &mut text,
                &[
                    "fingerprint",
                    &sample.index.to_string(),
                    &sample.instruction.to_string(),
                    &sample.node,
                    &sample.digest,
                ],
            );
        }
        let mut sampling_fields = vec![
            "sampling".to_string(),
            self.sampling_config.fine.clone(),
            self.sampling_config.coarse.clone(),
            self.sampling_config.regions.len().to_string(),
        ];
        sampling_fields.extend(self.sampling_config.regions.iter().cloned());
        line(
            &mut text,
            &sampling_fields
                .iter()
                .map(String::as_str)
                .collect::<Vec<_>>(),
        );
        text
    }
}

/// Pinned producer identities embedded in a reproduction artifact.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PinnedBuildIdentity {
    /// Crucible engine version that produced the artifact.
    pub engine_version: String,
    /// Engine ABI version that produced the artifact.
    pub engine_abi: String,
    /// Reproduction artifact ABI version.
    pub artifact_abi: String,
    /// Content address of the QEMU build identity used by the producer.
    pub qemu_build_id: String,
    /// Hash of the ordered QEMU patch series applied to the producer QEMU.
    pub qemu_patch_series_hash: String,
    /// Shared-memory ABI version used by the producer.
    pub shmem_abi_version: String,
    /// Guest-host channel protocol version used by the producer.
    pub guest_host_protocol_version: String,
    /// Control-plane RPC ABI semantic version used by the producer.
    pub rpc_abi_version: String,
    /// Control-plane RPC ABI build tag used by the producer.
    pub rpc_abi_build: String,
    /// Plugin ABI version used by the producer.
    pub plugin_abi: String,
}

impl PinnedBuildIdentity {
    /// Validates the pinned identity fields.
    ///
    /// # Errors
    ///
    /// Returns [`ReproductionArtifactError`] when an identity field is empty or
    /// the QEMU build identity is not a content address.
    pub fn validate(&self) -> Result<(), ReproductionArtifactError> {
        require_non_empty("build_identity.engine_version", &self.engine_version)?;
        require_non_empty("build_identity.engine_abi", &self.engine_abi)?;
        require_non_empty("build_identity.artifact_abi", &self.artifact_abi)?;
        require_non_empty(
            "build_identity.qemu_patch_series_hash",
            &self.qemu_patch_series_hash,
        )?;
        require_non_empty("build_identity.shmem_abi_version", &self.shmem_abi_version)?;
        require_non_empty(
            "build_identity.guest_host_protocol_version",
            &self.guest_host_protocol_version,
        )?;
        require_non_empty("build_identity.rpc_abi_version", &self.rpc_abi_version)?;
        require_non_empty("build_identity.rpc_abi_build", &self.rpc_abi_build)?;
        require_non_empty("build_identity.plugin_abi", &self.plugin_abi)?;
        validate_digest("build_identity.qemu_build_id", &self.qemu_build_id)?;
        Ok(())
    }
}

/// Previously persisted campaign corpus and the provenance that produced it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CampaignCorpusSeed {
    /// Content-addressed corpus root proposed as a seed.
    pub corpus_root: String,
    /// Content-addressed lineage identifier that owns the corpus.
    pub lineage_id: String,
    /// Pinned build identity that produced the corpus.
    pub provenance: PinnedBuildIdentity,
}

impl CampaignCorpusSeed {
    /// Builds a validated prior campaign corpus seed.
    ///
    /// # Errors
    ///
    /// Returns [`ReproductionArtifactError`] when the corpus root, lineage id,
    /// or pinned provenance is invalid.
    pub fn new(
        corpus_root: impl Into<String>,
        lineage_id: impl Into<String>,
        provenance: PinnedBuildIdentity,
    ) -> Result<Self, ReproductionArtifactError> {
        let seed = Self {
            corpus_root: corpus_root.into(),
            lineage_id: lineage_id.into(),
            provenance,
        };
        seed.validate()?;
        Ok(seed)
    }

    fn validate(&self) -> Result<(), ReproductionArtifactError> {
        validate_digest("campaign.corpus_root", &self.corpus_root)?;
        validate_digest("campaign.lineage_id", &self.lineage_id)?;
        self.provenance.validate()
    }
}

/// Baseline event recorded when a new campaign lineage is forked.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CampaignFreshLineageBaselineEvent {
    /// Event schema identifier.
    pub schema_version: String,
    /// Loud refusal reason for operators and CI logs.
    pub reason: String,
    /// Prior corpus root that was refused as a seed.
    pub refused_corpus_root: String,
    /// Lineage id that owns the refused corpus.
    pub previous_lineage_id: String,
    /// Deterministic id for the newly forked lineage.
    pub fresh_lineage_id: String,
    /// Provenance key of the refused prior corpus.
    pub previous_provenance_key: String,
    /// Provenance key of the current run.
    pub run_provenance_key: String,
}

/// Result of deciding whether a prior campaign corpus may seed this run.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CampaignCorpusReuseDecision {
    /// The prior corpus has identical provenance and may be seeded.
    SeedPriorCorpus {
        /// Content-addressed corpus root to seed from.
        corpus_root: String,
        /// Existing lineage id reused by this campaign.
        lineage_id: String,
        /// Provenance key shared by the corpus and current run.
        provenance_key: String,
    },
    /// The prior corpus was loudly refused and a fresh lineage was recorded.
    RefuseCrossProvenanceReuse {
        /// Fresh-lineage baseline event that must be recorded by callers.
        baseline_event: CampaignFreshLineageBaselineEvent,
    },
}

/// Computes the deterministic campaign provenance key for a pinned identity.
///
/// The key is derived from the full pinned build identity used by reproduction
/// artifacts: Crucible version and ABI, QEMU build id and patch-series hash,
/// shmem ABI, guest-host protocol, RPC ABI/build tag, and plugin ABI.
///
/// # Errors
///
/// Returns [`ReproductionArtifactError`] when `identity` is not a valid pinned
/// build identity.
pub fn campaign_provenance_key(
    identity: &PinnedBuildIdentity,
) -> Result<String, ReproductionArtifactError> {
    identity.validate()?;
    Ok(content_address_bytes(
        campaign_provenance_material(identity).as_bytes(),
    ))
}

/// Decides whether `prior` can seed a campaign under `run_provenance`.
///
/// # Errors
///
/// Returns [`ReproductionArtifactError`] when either provenance identity or the
/// prior corpus seed is invalid.
pub fn evaluate_campaign_corpus_reuse(
    prior: &CampaignCorpusSeed,
    run_provenance: &PinnedBuildIdentity,
) -> Result<CampaignCorpusReuseDecision, ReproductionArtifactError> {
    prior.validate()?;
    run_provenance.validate()?;
    let previous_provenance_key = campaign_provenance_key(&prior.provenance)?;
    let run_provenance_key = campaign_provenance_key(run_provenance)?;
    if prior.provenance == *run_provenance {
        return Ok(CampaignCorpusReuseDecision::SeedPriorCorpus {
            corpus_root: prior.corpus_root.clone(),
            lineage_id: prior.lineage_id.clone(),
            provenance_key: run_provenance_key,
        });
    }

    let fresh_lineage_id =
        fresh_campaign_lineage_id(prior, &previous_provenance_key, &run_provenance_key);
    Ok(CampaignCorpusReuseDecision::RefuseCrossProvenanceReuse {
        baseline_event: CampaignFreshLineageBaselineEvent {
            schema_version: CAMPAIGN_FRESH_LINEAGE_BASELINE_EVENT_SCHEMA.to_string(),
            reason: CAMPAIGN_CROSS_PROVENANCE_REFUSAL_REASON.to_string(),
            refused_corpus_root: prior.corpus_root.clone(),
            previous_lineage_id: prior.lineage_id.clone(),
            fresh_lineage_id,
            previous_provenance_key,
            run_provenance_key,
        },
    })
}

/// A content-addressed artifact component reference.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ContentAddressedComponent {
    /// Component kind.
    pub kind: ComponentKind,
    /// Stable logical component name.
    pub name: String,
    /// Stable content address of the component.
    pub digest: String,
    /// Hermetic CAS URI used to resolve the component.
    pub store_uri: String,
    /// Media type of the component payload.
    pub media_type: String,
    /// Size of the component payload in bytes.
    pub size_bytes: u64,
}

impl ContentAddressedComponent {
    /// Builds a component reference from canonical component bytes.
    ///
    /// # Errors
    ///
    /// Returns [`ReproductionArtifactError`] when the component name or media
    /// type is empty.
    pub fn from_bytes(
        kind: ComponentKind,
        name: impl Into<String>,
        media_type: impl Into<String>,
        bytes: &[u8],
    ) -> Result<Self, ReproductionArtifactError> {
        let name = name.into();
        let media_type = media_type.into();
        require_non_empty("component.name", &name)?;
        require_non_empty("component.media_type", &media_type)?;
        let digest = content_address_bytes(bytes);
        Ok(Self {
            kind,
            name,
            store_uri: format!("cas:{digest}"),
            digest,
            media_type,
            size_bytes: bytes.len() as u64,
        })
    }

    fn validate(&self, field: &'static str) -> Result<(), ReproductionArtifactError> {
        require_non_empty("component.name", &self.name)?;
        require_non_empty("component.media_type", &self.media_type)?;
        validate_digest(field, &self.digest)?;
        if self.store_uri != format!("cas:{}", self.digest) {
            return Err(ReproductionArtifactError::InvalidStoreUri {
                field,
                store_uri: self.store_uri.clone(),
                digest: self.digest.clone(),
            });
        }
        Ok(())
    }
}

/// Inline payload bytes for a small content-addressed component.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ComponentPayload {
    /// Stable content address of the payload bytes.
    pub digest: String,
    /// Canonical component bytes carried by the artifact.
    pub bytes: Vec<u8>,
}

impl ComponentPayload {
    /// Builds an inline payload and computes its content address.
    #[must_use]
    pub fn from_bytes(bytes: &[u8]) -> Self {
        Self {
            digest: content_address_bytes(bytes),
            bytes: bytes.to_vec(),
        }
    }

    fn validate(&self) -> Result<(), ReproductionArtifactError> {
        validate_digest("component_payload.digest", &self.digest)?;
        let actual = content_address_bytes(&self.bytes);
        if self.digest != actual {
            return Err(ReproductionArtifactError::PayloadDigestMismatch {
                expected: actual,
                actual: self.digest.clone(),
            });
        }
        Ok(())
    }
}

/// A content-addressed component kind.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ComponentKind {
    /// A canonical `ScenarioDef`.
    ScenarioDef,
    /// A checkpoint component referenced by the scenario.
    Checkpoint,
    /// A disk-image component referenced by the scenario.
    DiskImage,
    /// A guest kernel component referenced by the scenario.
    Kernel,
    /// A workload component referenced by the scenario.
    Workload,
    /// Another content-addressed component.
    Other,
}

impl ComponentKind {
    fn as_str(self) -> &'static str {
        match self {
            Self::ScenarioDef => "scenario_def",
            Self::Checkpoint => "checkpoint",
            Self::DiskImage => "disk_image",
            Self::Kernel => "kernel",
            Self::Workload => "workload",
            Self::Other => "other",
        }
    }

    fn parse(value: &str) -> Result<Self, ReproductionArtifactError> {
        match value {
            "scenario_def" => Ok(Self::ScenarioDef),
            "checkpoint" => Ok(Self::Checkpoint),
            "disk_image" => Ok(Self::DiskImage),
            "kernel" => Ok(Self::Kernel),
            "workload" => Ok(Self::Workload),
            "other" => Ok(Self::Other),
            _ => Err(ReproductionArtifactError::Decode {
                reason: format!("unknown component kind `{value}`"),
            }),
        }
    }
}

/// A totally ordered replay schedule.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ReproductionSchedule {
    /// Content address of the encoded decisions.
    pub digest: String,
    /// Decisions in canonical replay order.
    pub decisions: Vec<RecordedDecision>,
}

impl ReproductionSchedule {
    /// Builds a schedule and computes the digest over its decisions.
    ///
    /// # Errors
    ///
    /// Returns [`ReproductionArtifactError`] when the schedule is empty or
    /// decisions are not ordered by sequence.
    pub fn from_decisions(
        decisions: Vec<RecordedDecision>,
    ) -> Result<Self, ReproductionArtifactError> {
        validate_decision_order(&decisions)?;
        let digest = schedule_digest(&decisions);
        Ok(Self { digest, decisions })
    }

    fn validate(&self) -> Result<(), ReproductionArtifactError> {
        validate_decision_order(&self.decisions)?;
        let expected = schedule_digest(&self.decisions);
        if self.digest != expected {
            return Err(ReproductionArtifactError::ScheduleDigestMismatch {
                expected,
                actual: self.digest.clone(),
            });
        }
        Ok(())
    }
}

/// One recorded replay decision.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RecordedDecision {
    /// Monotonic decision sequence number.
    pub sequence: u64,
    /// Virtual-time tick at which the decision is applied.
    pub virtual_time_ticks: u64,
    /// Logical node or sub-node named by the decision.
    pub node: String,
    /// Stable decision kind.
    pub kind: String,
    /// Content address of the decision payload.
    pub payload_digest: String,
}

/// One fingerprint sample retained at the tail of the run.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FingerprintTailSample {
    /// Fingerprint sample index.
    pub index: u64,
    /// Guest instruction coordinate associated with the sample.
    pub instruction: u64,
    /// Canonical World node name sampled at the coordinate.
    pub node: String,
    /// Content address of the sample payload.
    pub digest: String,
}

/// Fingerprint sampling configuration pinned into an artifact.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FingerprintSamplingConfig {
    /// Fine-grained sampling policy name.
    pub fine: String,
    /// Coarse-grained sampling policy name.
    pub coarse: String,
    /// Named regions sampled by the producer.
    pub regions: Vec<String>,
}

impl FingerprintSamplingConfig {
    /// Builds the default sampling configuration used by the mock e2e producer.
    #[must_use]
    pub fn mock_defaults() -> Self {
        Self {
            fine: String::from("every-decision"),
            coarse: String::from("final"),
            regions: vec![String::from("canonical-log-tail")],
        }
    }

    fn validate(&self) -> Result<(), ReproductionArtifactError> {
        require_non_empty("sampling_config.fine", &self.fine)?;
        require_non_empty("sampling_config.coarse", &self.coarse)?;
        if self.regions.is_empty() {
            return Err(ReproductionArtifactError::EmptySamplingRegions);
        }
        for region in &self.regions {
            require_non_empty("sampling_config.regions", region)?;
        }
        Ok(())
    }
}

/// A reproduction-artifact format error.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ReproductionArtifactError {
    /// No host profiles were supplied for reproduction verification.
    EmptyProfileMatrix,
    /// The artifact build identity did not match the local replay identity.
    BuildIdentityMismatch {
        /// Identity expected by the verifier.
        expected: Box<PinnedBuildIdentity>,
        /// Identity pinned in the artifact.
        actual: Box<PinnedBuildIdentity>,
    },
    /// No supplied profile represented a different machine from the baseline.
    MissingDifferentMachineProfile,
    /// The artifact did not carry required producer evidence.
    MissingProducerEvidence {
        /// Required producer evidence component name.
        component: String,
    },
    /// The recorded producer artifact digest did not match decoded contents.
    ProducerArtifactDigestMismatch {
        /// Digest recomputed from the decoded artifact contents.
        expected: Vec<u8>,
        /// Digest recorded in the artifact evidence.
        actual: Vec<u8>,
    },
    /// Reproduction output diverged across host profiles.
    MachineReproductionMismatch {
        /// Baseline host profile name.
        baseline_profile: String,
        /// Divergent host profile name.
        divergent_profile: String,
        /// Output field that differed.
        kind: MachineReproductionMismatchKind,
        /// Baseline bytes for the differing field.
        baseline: Vec<u8>,
        /// Divergent bytes for the differing field.
        reproduced: Vec<u8>,
    },
    /// The host-adversary fixture could not execute a profile.
    HostAdversary {
        /// Human-readable fixture failure.
        reason: String,
    },
    /// The artifact schema is not supported by this decoder.
    UnsupportedSchema {
        /// Schema identifier found in the artifact.
        schema_version: String,
    },
    /// A required string field was empty.
    EmptyField {
        /// Field path that was empty.
        field: &'static str,
    },
    /// A digest field was not a stable content address.
    InvalidDigest {
        /// Field path that held the digest.
        field: &'static str,
        /// Malformed digest value.
        digest: String,
    },
    /// A component store URI did not match the component digest.
    InvalidStoreUri {
        /// Field path that held the component.
        field: &'static str,
        /// Malformed store URI.
        store_uri: String,
        /// Expected component digest.
        digest: String,
    },
    /// The scenario reference was not a `scenario_def` component.
    ScenarioReferenceWrongKind {
        /// Component kind found on the scenario reference.
        kind: ComponentKind,
    },
    /// The scenario reference was absent from the component list.
    ScenarioComponentMissing {
        /// Scenario content address that was not present.
        digest: String,
    },
    /// An inline payload did not hash to the digest recorded beside it.
    PayloadDigestMismatch {
        /// Digest computed from the payload bytes.
        expected: String,
        /// Digest stored in the payload record.
        actual: String,
    },
    /// An inline payload did not match any component reference.
    PayloadComponentMissing {
        /// Payload content address that did not have a component reference.
        digest: String,
    },
    /// The schedule did not contain any decision.
    EmptySchedule,
    /// A decision sequence was not monotonically ordered from zero.
    DecisionOutOfOrder {
        /// Expected decision sequence.
        expected: u64,
        /// Actual decision sequence.
        actual: u64,
    },
    /// The stored schedule digest did not match the encoded decisions.
    ScheduleDigestMismatch {
        /// Expected digest computed from decisions.
        expected: String,
        /// Digest stored in the artifact.
        actual: String,
    },
    /// The sampling configuration did not name any region.
    EmptySamplingRegions,
    /// Decoding failed.
    Decode {
        /// Human-readable decoder failure.
        reason: String,
    },
    /// A mock e2e source artifact could not be reproduced.
    SourceReplay {
        /// Human-readable source replay failure.
        reason: String,
    },
}

impl fmt::Display for ReproductionArtifactError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::EmptyProfileMatrix => {
                write!(formatter, "machine reproduction profile matrix is empty")
            }
            Self::BuildIdentityMismatch { expected, actual } => write!(
                formatter,
                "reproduction build identity mismatch: expected engine `{}` ABI `{}` artifact ABI `{}` QEMU `{}` patch-series `{}` shmem `{}` guest-host `{}` RPC `{}+{}` plugin `{}`, got engine `{}` ABI `{}` artifact ABI `{}` QEMU `{}` patch-series `{}` shmem `{}` guest-host `{}` RPC `{}+{}` plugin `{}`",
                expected.engine_version,
                expected.engine_abi,
                expected.artifact_abi,
                expected.qemu_build_id,
                expected.qemu_patch_series_hash,
                expected.shmem_abi_version,
                expected.guest_host_protocol_version,
                expected.rpc_abi_version,
                expected.rpc_abi_build,
                expected.plugin_abi,
                actual.engine_version,
                actual.engine_abi,
                actual.artifact_abi,
                actual.qemu_build_id,
                actual.qemu_patch_series_hash,
                actual.shmem_abi_version,
                actual.guest_host_protocol_version,
                actual.rpc_abi_version,
                actual.rpc_abi_build,
                actual.plugin_abi
            ),
            Self::MissingDifferentMachineProfile => write!(
                formatter,
                "machine reproduction requires at least one profile that differs from the baseline"
            ),
            Self::MissingProducerEvidence { component } => write!(
                formatter,
                "reproduction artifact is missing producer evidence component `{component}`"
            ),
            Self::ProducerArtifactDigestMismatch { expected, actual } => write!(
                formatter,
                "producer artifact digest mismatch: expected {}, got {}",
                e2e_hex_bytes(expected),
                e2e_hex_bytes(actual)
            ),
            Self::MachineReproductionMismatch {
                baseline_profile,
                divergent_profile,
                kind,
                ..
            } => write!(
                formatter,
                "machine reproduction diverged for {kind:?}: baseline `{baseline_profile}`, reproduced `{divergent_profile}`"
            ),
            Self::HostAdversary { reason } => {
                write!(
                    formatter,
                    "host-adversary reproduction fixture failed: {reason}"
                )
            }
            Self::UnsupportedSchema { schema_version } => {
                write!(
                    formatter,
                    "unsupported reproduction artifact schema `{schema_version}`"
                )
            }
            Self::EmptyField { field } => write!(formatter, "required field `{field}` is empty"),
            Self::InvalidDigest { field, digest } => {
                write!(
                    formatter,
                    "field `{field}` is not a content address: `{digest}`"
                )
            }
            Self::InvalidStoreUri {
                field,
                store_uri,
                digest,
            } => write!(
                formatter,
                "component `{field}` store URI `{store_uri}` does not resolve digest `{digest}`"
            ),
            Self::ScenarioReferenceWrongKind { kind } => write!(
                formatter,
                "scenario reference must have kind scenario_def, got {kind:?}"
            ),
            Self::ScenarioComponentMissing { digest } => write!(
                formatter,
                "scenario component `{digest}` is missing from artifact component references"
            ),
            Self::PayloadDigestMismatch { expected, actual } => write!(
                formatter,
                "component payload digest mismatch: expected {expected}, got {actual}"
            ),
            Self::PayloadComponentMissing { digest } => write!(
                formatter,
                "component payload `{digest}` is missing from artifact component references"
            ),
            Self::EmptySchedule => write!(formatter, "reproduction schedule is empty"),
            Self::DecisionOutOfOrder { expected, actual } => write!(
                formatter,
                "schedule decision sequence out of order: expected {expected}, got {actual}"
            ),
            Self::ScheduleDigestMismatch { expected, actual } => write!(
                formatter,
                "schedule digest mismatch: expected {expected}, got {actual}"
            ),
            Self::EmptySamplingRegions => {
                write!(formatter, "fingerprint sampling regions must not be empty")
            }
            Self::Decode { reason } => write!(formatter, "artifact decoding failed: {reason}"),
            Self::SourceReplay { reason } => {
                write!(formatter, "source artifact replay failed: {reason}")
            }
        }
    }
}

impl Error for ReproductionArtifactError {}

/// Returns the stable content address for bytes.
#[must_use]
pub fn content_address_bytes(bytes: &[u8]) -> String {
    format!("crucible-hash:{}", hex_bytes(&stable_digest(bytes)))
}

/// Builds the representative mock e2e reproduction artifact in the versioned format.
///
/// # Errors
///
/// Returns [`ReproductionArtifactError`] if the source mock artifact cannot be
/// reproduced or cannot be represented by the versioned format.
pub fn mock_e2e_reproduction_artifact() -> Result<ReproductionArtifact, ReproductionArtifactError> {
    reproduction_artifact_from_mock_e2e(&representative_mock_e2e_artifact())
}

/// Returns the pinned identity expected by the mock reproduction verifier.
#[must_use]
pub fn mock_reproduction_build_identity() -> PinnedBuildIdentity {
    pinned_identity_from_e2e(&canonical_mock_build_identity())
}

/// Verifies that a versioned mock artifact reproduces identically across hosts.
///
/// # Errors
///
/// Returns [`ReproductionArtifactError`] when the artifact is malformed, the
/// pinned identity does not match `expected_build_identity`, the profile matrix
/// has no different-machine profile, the host fixture fails, or the reproduced
/// bytes diverge across profiles.
pub fn verify_mock_machine_independent_reproduction(
    artifact: &ReproductionArtifact,
    profiles: &[HostAdversaryProfile],
    expected_build_identity: &PinnedBuildIdentity,
) -> Result<MachineReproductionReport, ReproductionArtifactError> {
    if profiles.is_empty() {
        return Err(ReproductionArtifactError::EmptyProfileMatrix);
    }

    let producer_canonical_log = producer_evidence_payload(
        artifact,
        PRODUCER_CANONICAL_LOG_COMPONENT_NAME,
        PRODUCER_CANONICAL_LOG_MEDIA_TYPE,
    )?;
    let producer_final_fingerprint = producer_evidence_payload(
        artifact,
        PRODUCER_FINAL_FINGERPRINT_COMPONENT_NAME,
        PRODUCER_FINAL_FINGERPRINT_MEDIA_TYPE,
    )?;

    let baseline = reproduce_mock_reproduction_artifact_on_profile(
        artifact,
        profiles[0],
        expected_build_identity,
    )?;
    compare_run_to_producer_evidence(
        &baseline,
        &producer_canonical_log,
        &producer_final_fingerprint,
    )?;
    let mut reproduced_on_different_machine_profiles = Vec::new();
    for profile in profiles
        .iter()
        .copied()
        .filter(|profile| is_different_machine_profile(profiles[0], *profile))
    {
        let reproduced = reproduce_mock_reproduction_artifact_on_profile(
            artifact,
            profile,
            expected_build_identity,
        )?;
        compare_run_to_producer_evidence(
            &reproduced,
            &producer_canonical_log,
            &producer_final_fingerprint,
        )?;
        reproduced_on_different_machine_profiles.push(reproduced);
    }
    if reproduced_on_different_machine_profiles.is_empty() {
        return Err(ReproductionArtifactError::MissingDifferentMachineProfile);
    }

    Ok(MachineReproductionReport {
        artifact_digest: baseline.artifact_digest.clone(),
        baseline,
        reproduced_on_different_machine_profiles,
    })
}

/// Decodes and verifies a versioned mock artifact across host profiles.
///
/// # Errors
///
/// Returns [`ReproductionArtifactError`] when decoding fails or machine
/// reproduction verification fails.
pub fn verify_mock_machine_independent_reproduction_bytes(
    bytes: &[u8],
    profiles: &[HostAdversaryProfile],
    expected_build_identity: &PinnedBuildIdentity,
) -> Result<MachineReproductionReport, ReproductionArtifactError> {
    let artifact = ReproductionArtifact::decode(bytes)?;
    verify_mock_machine_independent_reproduction(&artifact, profiles, expected_build_identity)
}

/// Replays a versioned mock artifact under one host profile.
///
/// # Errors
///
/// Returns [`ReproductionArtifactError`] when the artifact is malformed, the
/// pinned identity does not match `expected_build_identity`, or the host fixture
/// cannot execute the profile.
pub fn reproduce_mock_reproduction_artifact_on_profile(
    artifact: &ReproductionArtifact,
    profile: HostAdversaryProfile,
    expected_build_identity: &PinnedBuildIdentity,
) -> Result<MachineReproductionRun, ReproductionArtifactError> {
    artifact.validate()?;
    verify_pinned_build_identity(&artifact.build_identity, expected_build_identity)?;
    let task_pairs = run_profiled_producer_consumer_tasks(
        profile,
        artifact.schedule.decisions.len(),
        |task| format!("producer:{}", task.index),
        |task| format!("consumer:{}", task.index),
    )
    .map_err(|error| ReproductionArtifactError::HostAdversary {
        reason: error.to_string(),
    })?;
    let canonical_log = machine_canonical_log_material(artifact, &task_pairs)?.into_bytes();
    let producer_artifact_digest = producer_evidence_payload(
        artifact,
        PRODUCER_ARTIFACT_DIGEST_COMPONENT_NAME,
        PRODUCER_ARTIFACT_DIGEST_MEDIA_TYPE,
    )?;
    let recomputed_artifact_digest = reconstructed_e2e_artifact_digest(artifact)?;
    if producer_artifact_digest != recomputed_artifact_digest {
        return Err(ReproductionArtifactError::ProducerArtifactDigestMismatch {
            expected: recomputed_artifact_digest,
            actual: producer_artifact_digest,
        });
    }
    let fingerprint_material = format!(
        "artifact={}\nlog={}\n",
        e2e_hex_bytes(&recomputed_artifact_digest),
        String::from_utf8_lossy(&canonical_log)
    );
    let final_fingerprint = e2e_stable_digest("crucible.e2e.fingerprint.v1", &fingerprint_material);

    Ok(MachineReproductionRun {
        profile: profile.name.to_string(),
        canonical_log,
        final_fingerprint,
        artifact_digest: artifact.digest()?,
    })
}

/// Converts a mock e2e source artifact into the versioned reproduction format.
///
/// # Errors
///
/// Returns [`ReproductionArtifactError`] if the source mock artifact cannot be
/// reproduced or if the converted artifact violates the format invariants.
pub fn reproduction_artifact_from_mock_e2e(
    source: &E2eReproductionArtifact,
) -> Result<ReproductionArtifact, ReproductionArtifactError> {
    let scenario_material = e2e_scenario_material(source).into_bytes();
    let scenario = ContentAddressedComponent::from_bytes(
        ComponentKind::ScenarioDef,
        source.scenario.name.clone(),
        "application/vnd.crucible.mock-scenario+text",
        &scenario_material,
    )?;
    let build_identity = pinned_identity_from_e2e(&source.build_identity);
    let decision_parts = source
        .schedule
        .decisions
        .iter()
        .enumerate()
        .map(|(sequence, decision)| recorded_decision_parts_from_e2e(sequence as u64, decision))
        .collect::<Vec<_>>();
    let decisions = decision_parts
        .iter()
        .map(|(decision, _payload)| decision.clone())
        .collect::<Vec<_>>();
    let source_run = reproduce_mock_e2e_artifact(source, &canonical_mock_build_identity())
        .map_err(|error| ReproductionArtifactError::SourceReplay {
            reason: error.to_string(),
        })?;
    let mut components = vec![scenario.clone()];
    let mut component_payloads = vec![ComponentPayload::from_bytes(&scenario_material)];
    for (decision, payload) in &decision_parts {
        let name = format!("decision-{}-payload", decision.sequence);
        let component = ContentAddressedComponent::from_bytes(
            ComponentKind::Other,
            name,
            RECORDED_DECISION_PAYLOAD_MEDIA_TYPE,
            payload.as_bytes(),
        )?;
        components.push(component);
        component_payloads.push(ComponentPayload::from_bytes(payload.as_bytes()));
    }
    let producer_artifact_digest_component = ContentAddressedComponent::from_bytes(
        ComponentKind::Other,
        PRODUCER_ARTIFACT_DIGEST_COMPONENT_NAME,
        PRODUCER_ARTIFACT_DIGEST_MEDIA_TYPE,
        &source_run.artifact_digest,
    )?;
    let producer_backend_build_id_component = ContentAddressedComponent::from_bytes(
        ComponentKind::Other,
        PRODUCER_BACKEND_BUILD_ID_COMPONENT_NAME,
        PRODUCER_BACKEND_BUILD_ID_MEDIA_TYPE,
        source.build_identity.backend_build_id.as_bytes(),
    )?;
    let producer_log_component = ContentAddressedComponent::from_bytes(
        ComponentKind::Other,
        PRODUCER_CANONICAL_LOG_COMPONENT_NAME,
        PRODUCER_CANONICAL_LOG_MEDIA_TYPE,
        &source_run.canonical_log,
    )?;
    let producer_fingerprint_component = ContentAddressedComponent::from_bytes(
        ComponentKind::Other,
        PRODUCER_FINAL_FINGERPRINT_COMPONENT_NAME,
        PRODUCER_FINAL_FINGERPRINT_MEDIA_TYPE,
        &source_run.final_fingerprint,
    )?;
    components.extend([
        producer_artifact_digest_component,
        producer_backend_build_id_component,
        producer_log_component,
        producer_fingerprint_component,
    ]);
    component_payloads.extend([
        ComponentPayload::from_bytes(&source_run.artifact_digest),
        ComponentPayload::from_bytes(source.build_identity.backend_build_id.as_bytes()),
        ComponentPayload::from_bytes(&source_run.canonical_log),
        ComponentPayload::from_bytes(&source_run.final_fingerprint),
    ]);
    let fingerprint_tail = vec![FingerprintTailSample {
        index: source.schedule.len() as u64,
        instruction: source.schedule.len() as u64,
        node: String::from("mock-node-a"),
        digest: content_address_bytes(&source_run.final_fingerprint),
    }];

    ReproductionArtifact::from_parts(ReproductionArtifactParts {
        seed: source.seed,
        build_identity,
        scenario: scenario.clone(),
        decisions,
        components,
        component_payloads,
        fingerprint_tail,
        sampling_config: FingerprintSamplingConfig::mock_defaults(),
    })
}

fn decode_artifact(text: &str) -> Result<ReproductionArtifact, ReproductionArtifactError> {
    let mut schema_version = None;
    let mut seed = None;
    let mut build_identity = None;
    let mut scenario = None;
    let mut components = Vec::new();
    let mut component_payloads = Vec::new();
    let mut schedule_digest = None;
    let mut schedule_len = None;
    let mut decisions = Vec::new();
    let mut fingerprint_tail = Vec::new();
    let mut sampling_config = None;

    for (line_index, line_text) in text.lines().enumerate() {
        let fields = parse_fields(line_text)?;
        let Some(tag) = fields.first().map(String::as_str) else {
            continue;
        };
        match tag {
            "schema" => {
                require_field_count(line_index, tag, &fields, 2)?;
                set_once(&mut schema_version, line_index, tag, fields[1].clone())?;
            }
            "seed" => {
                require_field_count(line_index, tag, &fields, 2)?;
                let parsed = parse_u64(line_index, tag, &fields[1])?;
                set_once(&mut seed, line_index, tag, parsed)?;
            }
            "identity" => {
                require_field_count(line_index, tag, &fields, 11)?;
                set_once(
                    &mut build_identity,
                    line_index,
                    tag,
                    PinnedBuildIdentity {
                        engine_version: fields[1].clone(),
                        engine_abi: fields[2].clone(),
                        artifact_abi: fields[3].clone(),
                        qemu_build_id: fields[4].clone(),
                        qemu_patch_series_hash: fields[5].clone(),
                        shmem_abi_version: fields[6].clone(),
                        guest_host_protocol_version: fields[7].clone(),
                        rpc_abi_version: fields[8].clone(),
                        rpc_abi_build: fields[9].clone(),
                        plugin_abi: fields[10].clone(),
                    },
                )?;
            }
            "scenario" => {
                let parsed = parse_component(line_index, tag, &fields)?;
                set_once(&mut scenario, line_index, tag, parsed)?;
            }
            "component" => {
                components.push(parse_component(line_index, tag, &fields)?);
            }
            "payload" => {
                require_field_count(line_index, tag, &fields, 3)?;
                component_payloads.push(ComponentPayload {
                    digest: fields[1].clone(),
                    bytes: parse_hex_bytes(line_index, tag, &fields[2])?,
                });
            }
            "schedule" => {
                require_field_count(line_index, tag, &fields, 3)?;
                let parsed_len = parse_usize(line_index, tag, &fields[2])?;
                set_once(&mut schedule_digest, line_index, tag, fields[1].clone())?;
                set_once(&mut schedule_len, line_index, tag, parsed_len)?;
            }
            "decision" => {
                require_field_count(line_index, tag, &fields, 6)?;
                decisions.push(RecordedDecision {
                    sequence: parse_u64(line_index, tag, &fields[1])?,
                    virtual_time_ticks: parse_u64(line_index, tag, &fields[2])?,
                    node: fields[3].clone(),
                    kind: fields[4].clone(),
                    payload_digest: fields[5].clone(),
                });
            }
            "fingerprint" => {
                require_field_count(line_index, tag, &fields, 5)?;
                fingerprint_tail.push(FingerprintTailSample {
                    index: parse_u64(line_index, tag, &fields[1])?,
                    instruction: parse_u64(line_index, tag, &fields[2])?,
                    node: fields[3].clone(),
                    digest: fields[4].clone(),
                });
            }
            "sampling" => {
                if fields.len() < 4 {
                    return Err(decode_line_error(
                        line_index,
                        tag,
                        "expected at least 4 fields",
                    ));
                }
                let region_count = parse_usize(line_index, tag, &fields[3])?;
                if fields.len() != region_count + 4 {
                    return Err(decode_line_error(
                        line_index,
                        tag,
                        "region count does not match fields",
                    ));
                }
                set_once(
                    &mut sampling_config,
                    line_index,
                    tag,
                    FingerprintSamplingConfig {
                        fine: fields[1].clone(),
                        coarse: fields[2].clone(),
                        regions: fields[4..].to_vec(),
                    },
                )?;
            }
            _ => {
                return Err(decode_line_error(line_index, tag, "unknown line tag"));
            }
        }
    }

    let schedule_len = schedule_len.ok_or_else(|| missing_line("schedule"))?;
    if schedule_len != decisions.len() {
        return Err(ReproductionArtifactError::Decode {
            reason: format!(
                "schedule declared {schedule_len} decisions but encoded {}",
                decisions.len()
            ),
        });
    }
    Ok(ReproductionArtifact {
        schema_version: schema_version.ok_or_else(|| missing_line("schema"))?,
        seed: seed.ok_or_else(|| missing_line("seed"))?,
        build_identity: build_identity.ok_or_else(|| missing_line("identity"))?,
        scenario: scenario.ok_or_else(|| missing_line("scenario"))?,
        schedule: ReproductionSchedule {
            digest: schedule_digest.ok_or_else(|| missing_line("schedule"))?,
            decisions,
        },
        components,
        component_payloads,
        fingerprint_tail,
        sampling_config: sampling_config.ok_or_else(|| missing_line("sampling"))?,
    })
}

fn parse_component(
    line_index: usize,
    tag: &str,
    fields: &[String],
) -> Result<ContentAddressedComponent, ReproductionArtifactError> {
    require_field_count(line_index, tag, fields, 7)?;
    Ok(ContentAddressedComponent {
        kind: ComponentKind::parse(&fields[1])?,
        name: fields[2].clone(),
        digest: fields[3].clone(),
        store_uri: fields[4].clone(),
        media_type: fields[5].clone(),
        size_bytes: parse_u64(line_index, tag, &fields[6])?,
    })
}

fn pinned_identity_from_e2e(source: &E2eBuildIdentity) -> PinnedBuildIdentity {
    PinnedBuildIdentity {
        engine_version: source.crucible_version.clone(),
        engine_abi: source.harness_abi.clone(),
        artifact_abi: REPRODUCTION_ARTIFACT_SCHEMA.to_string(),
        qemu_build_id: content_address_bytes(source.backend_build_id.as_bytes()),
        qemu_patch_series_hash: source.qemu_patch_series_hash.clone(),
        shmem_abi_version: source.shmem_abi_version.clone(),
        guest_host_protocol_version: source.guest_host_protocol_version.clone(),
        rpc_abi_version: source.rpc_abi_version.clone(),
        rpc_abi_build: source.rpc_abi_build.clone(),
        plugin_abi: source.plugin_abi.clone(),
    }
}

fn campaign_provenance_material(identity: &PinnedBuildIdentity) -> String {
    let mut material = String::new();
    record(&mut material, "schema", &[CAMPAIGN_PROVENANCE_SCHEMA]);
    record(
        &mut material,
        "identity",
        &[
            &identity.engine_version,
            &identity.engine_abi,
            &identity.artifact_abi,
            &identity.qemu_build_id,
            &identity.qemu_patch_series_hash,
            &identity.shmem_abi_version,
            &identity.guest_host_protocol_version,
            &identity.rpc_abi_version,
            &identity.rpc_abi_build,
            &identity.plugin_abi,
        ],
    );
    material
}

fn fresh_campaign_lineage_id(
    prior: &CampaignCorpusSeed,
    previous_provenance_key: &str,
    run_provenance_key: &str,
) -> String {
    let mut material = String::new();
    record(
        &mut material,
        "schema",
        &[CAMPAIGN_FRESH_LINEAGE_BASELINE_EVENT_SCHEMA],
    );
    record(
        &mut material,
        "fresh-lineage",
        &[
            CAMPAIGN_CROSS_PROVENANCE_REFUSAL_REASON,
            &prior.corpus_root,
            &prior.lineage_id,
            previous_provenance_key,
            run_provenance_key,
        ],
    );
    content_address_bytes(material.as_bytes())
}

fn verify_pinned_build_identity(
    actual: &PinnedBuildIdentity,
    expected: &PinnedBuildIdentity,
) -> Result<(), ReproductionArtifactError> {
    expected.validate()?;
    if actual != expected {
        return Err(ReproductionArtifactError::BuildIdentityMismatch {
            expected: Box::new(expected.clone()),
            actual: Box::new(actual.clone()),
        });
    }
    Ok(())
}

fn producer_evidence_payload(
    artifact: &ReproductionArtifact,
    component_name: &str,
    media_type: &str,
) -> Result<Vec<u8>, ReproductionArtifactError> {
    let component = artifact
        .components
        .iter()
        .find(|component| {
            component.kind == ComponentKind::Other
                && component.name == component_name
                && component.media_type == media_type
        })
        .ok_or_else(|| ReproductionArtifactError::MissingProducerEvidence {
            component: component_name.to_string(),
        })?;
    let payload = artifact
        .component_payloads
        .iter()
        .find(|payload| payload.digest == component.digest)
        .ok_or_else(|| ReproductionArtifactError::MissingProducerEvidence {
            component: component_name.to_string(),
        })?;
    Ok(payload.bytes.clone())
}

fn producer_evidence_text(
    artifact: &ReproductionArtifact,
    component_name: &str,
    media_type: &str,
) -> Result<String, ReproductionArtifactError> {
    let bytes = producer_evidence_payload(artifact, component_name, media_type)?;
    String::from_utf8(bytes).map_err(|error| ReproductionArtifactError::Decode {
        reason: format!("producer evidence `{component_name}` is not UTF-8: {error}"),
    })
}

fn compare_run_to_producer_evidence(
    run: &MachineReproductionRun,
    producer_canonical_log: &[u8],
    producer_final_fingerprint: &[u8],
) -> Result<(), ReproductionArtifactError> {
    if run.canonical_log != producer_canonical_log {
        return Err(ReproductionArtifactError::MachineReproductionMismatch {
            baseline_profile: String::from("producer-artifact"),
            divergent_profile: run.profile.clone(),
            kind: MachineReproductionMismatchKind::CanonicalLog,
            baseline: producer_canonical_log.to_vec(),
            reproduced: run.canonical_log.clone(),
        });
    }
    if run.final_fingerprint != producer_final_fingerprint {
        return Err(ReproductionArtifactError::MachineReproductionMismatch {
            baseline_profile: String::from("producer-artifact"),
            divergent_profile: run.profile.clone(),
            kind: MachineReproductionMismatchKind::FinalFingerprint,
            baseline: producer_final_fingerprint.to_vec(),
            reproduced: run.final_fingerprint.clone(),
        });
    }
    Ok(())
}

fn reconstructed_e2e_artifact_digest(
    artifact: &ReproductionArtifact,
) -> Result<Vec<u8>, ReproductionArtifactError> {
    let scenario_material = scenario_payload(artifact)?;
    let backend_build_id = producer_evidence_text(
        artifact,
        PRODUCER_BACKEND_BUILD_ID_COMPONENT_NAME,
        PRODUCER_BACKEND_BUILD_ID_MEDIA_TYPE,
    )?;
    let qemu_build_id = content_address_bytes(backend_build_id.as_bytes());
    if qemu_build_id != artifact.build_identity.qemu_build_id {
        let mut actual = artifact.build_identity.clone();
        actual.qemu_build_id = qemu_build_id;
        return Err(ReproductionArtifactError::BuildIdentityMismatch {
            expected: Box::new(artifact.build_identity.clone()),
            actual: Box::new(actual),
        });
    }
    let backend = artifact
        .build_identity
        .plugin_abi
        .strip_suffix("-plugin-abi")
        .unwrap_or(&artifact.build_identity.plugin_abi);
    let mut material = E2eCanonicalMaterial::new();
    material.record("seed", &[E2eCanonicalField::U64(artifact.seed)]);
    material.record(
        "build",
        &[
            E2eCanonicalField::Str(&artifact.build_identity.engine_version),
            E2eCanonicalField::Str(&artifact.build_identity.engine_abi),
            E2eCanonicalField::Str(backend),
            E2eCanonicalField::Str(&backend_build_id),
            E2eCanonicalField::Str(&artifact.build_identity.qemu_patch_series_hash),
            E2eCanonicalField::Str(&artifact.build_identity.shmem_abi_version),
            E2eCanonicalField::Str(&artifact.build_identity.guest_host_protocol_version),
            E2eCanonicalField::Str(&artifact.build_identity.rpc_abi_version),
            E2eCanonicalField::Str(&artifact.build_identity.rpc_abi_build),
            E2eCanonicalField::Str(&artifact.build_identity.plugin_abi),
        ],
    );
    push_scenario_material(&mut material, &scenario_material)?;
    for decision in &artifact.schedule.decisions {
        let payload = decision_payload_for_digest(artifact, &decision.payload_digest)?;
        push_recorded_decision_record(&mut material, decision, &payload)?;
    }
    Ok(e2e_stable_digest(
        "crucible.e2e.artifact.v1",
        &material.finish(),
    ))
}

fn scenario_payload(artifact: &ReproductionArtifact) -> Result<String, ReproductionArtifactError> {
    let payload = artifact
        .component_payloads
        .iter()
        .find(|payload| payload.digest == artifact.scenario.digest)
        .ok_or_else(|| ReproductionArtifactError::MissingProducerEvidence {
            component: String::from("scenario payload"),
        })?;
    String::from_utf8(payload.bytes.clone()).map_err(|error| ReproductionArtifactError::Decode {
        reason: format!(
            "scenario payload `{}` is not UTF-8: {error}",
            artifact.scenario.digest
        ),
    })
}

fn push_scenario_material(
    material: &mut E2eCanonicalMaterial,
    scenario_material: &str,
) -> Result<(), ReproductionArtifactError> {
    for (line_index, line_text) in scenario_material.lines().enumerate() {
        let fields = parse_fields(line_text)?;
        let Some(tag) = fields.first().map(String::as_str) else {
            continue;
        };
        match tag {
            "scenario" => {
                require_field_count(line_index, tag, &fields, 2)?;
                material.record("scenario", &[E2eCanonicalField::Str(&fields[1])]);
            }
            "node" => {
                require_field_count(line_index, tag, &fields, 3)?;
                material.record(
                    "node",
                    &[
                        E2eCanonicalField::Str(&fields[1]),
                        E2eCanonicalField::Str(&fields[2]),
                    ],
                );
            }
            "io-subnode" => {
                require_field_count(line_index, tag, &fields, 4)?;
                material.record(
                    "io-subnode",
                    &[
                        E2eCanonicalField::Str(&fields[1]),
                        E2eCanonicalField::Str(&fields[2]),
                        E2eCanonicalField::Str(&fields[3]),
                    ],
                );
            }
            "link" => {
                require_field_count(line_index, tag, &fields, 5)?;
                material.record(
                    "link",
                    &[
                        E2eCanonicalField::Str(&fields[1]),
                        E2eCanonicalField::Str(&fields[2]),
                        E2eCanonicalField::Str(&fields[3]),
                        E2eCanonicalField::U64(parse_u64(line_index, tag, &fields[4])?),
                    ],
                );
            }
            "fault" => {
                require_field_count(line_index, tag, &fields, 6)?;
                material.record(
                    "fault",
                    &[
                        E2eCanonicalField::Str(&fields[1]),
                        E2eCanonicalField::Str(&fields[2]),
                        E2eCanonicalField::Str(&fields[3]),
                        E2eCanonicalField::U64(parse_u64(line_index, tag, &fields[4])?),
                        E2eCanonicalField::Str(&fields[5]),
                    ],
                );
            }
            "property" => {
                require_field_count(line_index, tag, &fields, 4)?;
                material.record(
                    "property",
                    &[
                        E2eCanonicalField::Str(&fields[1]),
                        E2eCanonicalField::Str(&fields[2]),
                        E2eCanonicalField::Str(&fields[3]),
                    ],
                );
            }
            _ => {
                return Err(decode_line_error(
                    line_index,
                    tag,
                    "unknown scenario line tag",
                ));
            }
        }
    }
    Ok(())
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

fn machine_canonical_log_material(
    artifact: &ReproductionArtifact,
    task_pairs: &[ProducerConsumerPair<String, String>],
) -> Result<String, ReproductionArtifactError> {
    let mut material = E2eCanonicalMaterial::new();
    material.record("log", &[E2eCanonicalField::Str("crucible.e2e.mock.v1")]);
    material.record(
        "scenario",
        &[E2eCanonicalField::Str(&artifact.scenario.name)],
    );
    material.record("seed", &[E2eCanonicalField::U64(artifact.seed)]);
    for pair in task_pairs {
        let decision = &artifact.schedule.decisions[pair.task.index];
        let payload = decision_payload_for_digest(artifact, &decision.payload_digest)?;
        material.record(
            "event",
            &[
                E2eCanonicalField::U64(pair.task.index as u64),
                E2eCanonicalField::Str(&pair.producer),
                E2eCanonicalField::Str(&pair.consumer),
            ],
        );
        push_recorded_decision_record(&mut material, decision, &payload)?;
    }
    Ok(material.finish())
}

fn decision_payload_for_digest(
    artifact: &ReproductionArtifact,
    digest: &str,
) -> Result<String, ReproductionArtifactError> {
    if !artifact.components.iter().any(|component| {
        component.kind == ComponentKind::Other
            && component.media_type == RECORDED_DECISION_PAYLOAD_MEDIA_TYPE
            && component.digest == digest
    }) {
        return Err(ReproductionArtifactError::MissingProducerEvidence {
            component: format!("decision payload {digest}"),
        });
    }
    let payload = artifact
        .component_payloads
        .iter()
        .find(|payload| payload.digest == digest)
        .ok_or_else(|| ReproductionArtifactError::MissingProducerEvidence {
            component: format!("decision payload {digest}"),
        })?;
    String::from_utf8(payload.bytes.clone()).map_err(|error| ReproductionArtifactError::Decode {
        reason: format!("decision payload `{digest}` is not UTF-8: {error}"),
    })
}

fn push_recorded_decision_record(
    material: &mut E2eCanonicalMaterial,
    decision: &RecordedDecision,
    payload: &str,
) -> Result<(), ReproductionArtifactError> {
    let fields = parse_recorded_payload(decision.sequence, payload)?;
    match decision.kind.as_str() {
        "deliver" => material.record(
            "decision.deliver",
            &[
                E2eCanonicalField::U64(decision.virtual_time_ticks),
                E2eCanonicalField::Str(required_payload(decision.sequence, &fields, "from")?),
                E2eCanonicalField::Str(required_payload(decision.sequence, &fields, "to")?),
                E2eCanonicalField::U64(parse_payload_u64(
                    decision.sequence,
                    "sequence",
                    required_payload(decision.sequence, &fields, "sequence")?,
                )?),
            ],
        ),
        "fault" => material.record(
            "decision.fault",
            &[
                E2eCanonicalField::U64(decision.virtual_time_ticks),
                E2eCanonicalField::Str(required_payload(decision.sequence, &fields, "fault")?),
                E2eCanonicalField::Bool(parse_payload_bool(
                    decision.sequence,
                    "fired",
                    required_payload(decision.sequence, &fields, "fired")?,
                )?),
            ],
        ),
        "app_random" => material.record(
            "decision.app-random",
            &[
                E2eCanonicalField::Str(&decision.node),
                E2eCanonicalField::Str(required_payload(decision.sequence, &fields, "stream")?),
                E2eCanonicalField::U64(parse_payload_u64(
                    decision.sequence,
                    "request_id",
                    required_payload(decision.sequence, &fields, "request_id")?,
                )?),
                E2eCanonicalField::U64(parse_payload_u64(
                    decision.sequence,
                    "value",
                    required_payload(decision.sequence, &fields, "value")?,
                )?),
            ],
        ),
        "io_completion" => material.record(
            "decision.io-completion",
            &[
                E2eCanonicalField::U64(decision.virtual_time_ticks),
                E2eCanonicalField::Str(required_payload(decision.sequence, &fields, "subnode")?),
                E2eCanonicalField::U64(parse_payload_u64(
                    decision.sequence,
                    "request_id",
                    required_payload(decision.sequence, &fields, "request_id")?,
                )?),
                E2eCanonicalField::U64(parse_payload_u64(
                    decision.sequence,
                    "bytes",
                    required_payload(decision.sequence, &fields, "bytes")?,
                )?),
            ],
        ),
        "property_observation" => material.record(
            "decision.property",
            &[
                E2eCanonicalField::U64(decision.virtual_time_ticks),
                E2eCanonicalField::Str(required_payload(decision.sequence, &fields, "property")?),
                E2eCanonicalField::Bool(parse_payload_bool(
                    decision.sequence,
                    "satisfied",
                    required_payload(decision.sequence, &fields, "satisfied")?,
                )?),
            ],
        ),
        kind => {
            return Err(ReproductionArtifactError::Decode {
                reason: format!("decision {} has unknown kind `{kind}`", decision.sequence),
            });
        }
    }
    Ok(())
}

fn parse_recorded_payload(
    sequence: u64,
    payload: &str,
) -> Result<BTreeMap<String, String>, ReproductionArtifactError> {
    let mut fields = BTreeMap::new();
    for field in payload.split(';') {
        let Some((name, value)) = field.split_once('=') else {
            return Err(ReproductionArtifactError::Decode {
                reason: format!("decision {sequence} payload field `{field}` is malformed"),
            });
        };
        if fields.insert(name.to_string(), value.to_string()).is_some() {
            return Err(ReproductionArtifactError::Decode {
                reason: format!("decision {sequence} payload field `{name}` is duplicated"),
            });
        }
    }
    Ok(fields)
}

fn required_payload<'a>(
    sequence: u64,
    fields: &'a BTreeMap<String, String>,
    name: &str,
) -> Result<&'a str, ReproductionArtifactError> {
    fields
        .get(name)
        .map(String::as_str)
        .ok_or_else(|| ReproductionArtifactError::Decode {
            reason: format!("decision {sequence} payload is missing `{name}`"),
        })
}

fn parse_payload_u64(
    sequence: u64,
    field: &str,
    value: &str,
) -> Result<u64, ReproductionArtifactError> {
    value
        .parse::<u64>()
        .map_err(|error| ReproductionArtifactError::Decode {
            reason: format!("decision {sequence} payload `{field}` is not a u64: {error}"),
        })
}

fn parse_payload_bool(
    sequence: u64,
    field: &str,
    value: &str,
) -> Result<bool, ReproductionArtifactError> {
    value
        .parse::<bool>()
        .map_err(|error| ReproductionArtifactError::Decode {
            reason: format!("decision {sequence} payload `{field}` is not a bool: {error}"),
        })
}

struct E2eCanonicalMaterial {
    output: String,
}

impl E2eCanonicalMaterial {
    fn new() -> Self {
        Self {
            output: String::new(),
        }
    }

    fn record(&mut self, tag: &str, fields: &[E2eCanonicalField<'_>]) {
        self.length_prefixed(tag);
        self.output.push(' ');
        self.output.push_str(&fields.len().to_string());
        for field in fields {
            self.output.push(' ');
            match field {
                E2eCanonicalField::Str(value) => self.length_prefixed(value),
                E2eCanonicalField::U64(value) => self.length_prefixed(&value.to_string()),
                E2eCanonicalField::Bool(value) => {
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

enum E2eCanonicalField<'a> {
    Str(&'a str),
    U64(u64),
    Bool(bool),
}

fn e2e_stable_digest(domain: &str, material: &str) -> Vec<u8> {
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

fn e2e_hex_bytes(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut encoded = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        encoded.push(HEX[(byte >> 4) as usize] as char);
        encoded.push(HEX[(byte & 0x0f) as usize] as char);
    }
    encoded
}

fn recorded_decision_parts_from_e2e(
    sequence: u64,
    decision: &E2eDecision,
) -> (RecordedDecision, String) {
    let (virtual_time_ticks, node, kind, payload) = match decision {
        E2eDecision::Deliver {
            at_tick,
            from,
            to,
            sequence,
        } => (
            *at_tick,
            to.clone(),
            String::from("deliver"),
            format!("from={from};to={to};sequence={sequence}"),
        ),
        E2eDecision::Fault {
            at_tick,
            fault,
            fired,
        } => (
            *at_tick,
            fault.clone(),
            String::from("fault"),
            format!("fault={fault};fired={fired}"),
        ),
        E2eDecision::AppRandom {
            node,
            stream,
            request_id,
            value,
        } => (
            0,
            node.clone(),
            String::from("app_random"),
            format!("stream={stream};request_id={request_id};value={value}"),
        ),
        E2eDecision::IoCompletion {
            at_tick,
            subnode,
            request_id,
            bytes,
        } => (
            *at_tick,
            subnode.clone(),
            String::from("io_completion"),
            format!("subnode={subnode};request_id={request_id};bytes={bytes}"),
        ),
        E2eDecision::PropertyObservation {
            at_tick,
            property,
            satisfied,
        } => (
            *at_tick,
            property.clone(),
            String::from("property_observation"),
            format!("property={property};satisfied={satisfied}"),
        ),
    };

    (
        RecordedDecision {
            sequence,
            virtual_time_ticks,
            node,
            kind,
            payload_digest: content_address_bytes(payload.as_bytes()),
        },
        payload,
    )
}

fn e2e_scenario_material(source: &E2eReproductionArtifact) -> String {
    let mut material = String::new();
    record(&mut material, "scenario", &[&source.scenario.name]);
    for node in &source.scenario.nodes {
        record(&mut material, "node", &[&node.name, &node.role]);
    }
    for io_subnode in &source.scenario.io_subnodes {
        record(
            &mut material,
            "io-subnode",
            &[&io_subnode.name, &io_subnode.attached_to, &io_subnode.kind],
        );
    }
    for link in &source.scenario.links {
        let latency = link.latency_ticks.to_string();
        record(
            &mut material,
            "link",
            &[&link.name, &link.from, &link.to, &latency],
        );
    }
    for fault in &source.scenario.faults {
        let tick = fault.at_tick.to_string();
        record(
            &mut material,
            "fault",
            &[
                &fault.name,
                e2e_fault_kind(fault.kind),
                &fault.target,
                &tick,
                &fault.action,
            ],
        );
    }
    for property in &source.scenario.properties {
        record(
            &mut material,
            "property",
            &[
                &property.name,
                e2e_property_kind(property.kind),
                &property.subject,
            ],
        );
    }
    material
}

fn e2e_fault_kind(kind: E2eFaultKind) -> &'static str {
    match kind {
        E2eFaultKind::Partition => "partition",
        E2eFaultKind::Loss => "loss",
        E2eFaultKind::Latency => "latency",
        E2eFaultKind::Crash => "crash",
    }
}

fn e2e_property_kind(kind: E2ePropertyKind) -> &'static str {
    match kind {
        E2ePropertyKind::Always => "always",
        E2ePropertyKind::Eventually => "eventually",
        E2ePropertyKind::Sometimes => "sometimes",
    }
}

fn schedule_digest(decisions: &[RecordedDecision]) -> String {
    let mut material = String::new();
    for decision in decisions {
        line(
            &mut material,
            &[
                "decision",
                &decision.sequence.to_string(),
                &decision.virtual_time_ticks.to_string(),
                &decision.node,
                &decision.kind,
                &decision.payload_digest,
            ],
        );
    }
    content_address_bytes(material.as_bytes())
}

fn validate_decision_order(
    decisions: &[RecordedDecision],
) -> Result<(), ReproductionArtifactError> {
    if decisions.is_empty() {
        return Err(ReproductionArtifactError::EmptySchedule);
    }
    for (expected, decision) in decisions.iter().enumerate() {
        if decision.sequence != expected as u64 {
            return Err(ReproductionArtifactError::DecisionOutOfOrder {
                expected: expected as u64,
                actual: decision.sequence,
            });
        }
        require_non_empty("schedule.decisions.node", &decision.node)?;
        require_non_empty("schedule.decisions.kind", &decision.kind)?;
        validate_digest(
            "schedule.decisions.payload_digest",
            &decision.payload_digest,
        )?;
    }
    Ok(())
}

fn validate_digest(field: &'static str, digest: &str) -> Result<(), ReproductionArtifactError> {
    let Some(hex) = digest.strip_prefix("crucible-hash:") else {
        return Err(ReproductionArtifactError::InvalidDigest {
            field,
            digest: digest.to_string(),
        });
    };
    if hex.len() != 64 || !hex.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(ReproductionArtifactError::InvalidDigest {
            field,
            digest: digest.to_string(),
        });
    }
    Ok(())
}

fn require_non_empty(field: &'static str, value: &str) -> Result<(), ReproductionArtifactError> {
    if value.is_empty() {
        return Err(ReproductionArtifactError::EmptyField { field });
    }
    Ok(())
}

fn line(text: &mut String, fields: &[&str]) {
    for (index, field) in fields.iter().enumerate() {
        if index > 0 {
            text.push('\t');
        }
        text.push_str(&escape_field(field));
    }
    text.push('\n');
}

fn component_line(text: &mut String, tag: &str, component: &ContentAddressedComponent) {
    line(
        text,
        &[
            tag,
            component.kind.as_str(),
            &component.name,
            &component.digest,
            &component.store_uri,
            &component.media_type,
            &component.size_bytes.to_string(),
        ],
    );
}

fn record(material: &mut String, tag: &str, fields: &[&str]) {
    material.push_str(tag);
    for field in fields {
        material.push('\t');
        material.push_str(&escape_field(field));
    }
    material.push('\n');
}

fn escape_field(value: &str) -> String {
    let mut escaped = String::new();
    for byte in value.bytes() {
        match byte {
            b'%' => escaped.push_str("%25"),
            b'\t' => escaped.push_str("%09"),
            b'\n' => escaped.push_str("%0A"),
            b'\r' => escaped.push_str("%0D"),
            _ => escaped.push(char::from(byte)),
        }
    }
    escaped
}

fn parse_fields(line_text: &str) -> Result<Vec<String>, ReproductionArtifactError> {
    line_text.split('\t').map(unescape_field).collect()
}

fn unescape_field(value: &str) -> Result<String, ReproductionArtifactError> {
    let bytes = value.as_bytes();
    let mut output = String::new();
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index] != b'%' {
            output.push(char::from(bytes[index]));
            index += 1;
            continue;
        }
        if index + 2 >= bytes.len() {
            return Err(ReproductionArtifactError::Decode {
                reason: format!("truncated escape in `{value}`"),
            });
        }
        let escape = &value[index + 1..index + 3];
        match escape {
            "25" => output.push('%'),
            "09" => output.push('\t'),
            "0A" => output.push('\n'),
            "0D" => output.push('\r'),
            _ => {
                return Err(ReproductionArtifactError::Decode {
                    reason: format!("unknown escape %{escape} in `{value}`"),
                });
            }
        }
        index += 3;
    }
    Ok(output)
}

fn require_field_count(
    line_index: usize,
    tag: &str,
    fields: &[String],
    expected: usize,
) -> Result<(), ReproductionArtifactError> {
    if fields.len() == expected {
        return Ok(());
    }
    Err(decode_line_error(
        line_index,
        tag,
        &format!("expected {expected} fields, got {}", fields.len()),
    ))
}

fn set_once<T>(
    slot: &mut Option<T>,
    line_index: usize,
    tag: &str,
    value: T,
) -> Result<(), ReproductionArtifactError> {
    if slot.is_some() {
        return Err(decode_line_error(
            line_index,
            tag,
            "duplicate singleton line",
        ));
    }
    *slot = Some(value);
    Ok(())
}

fn parse_u64(line_index: usize, tag: &str, value: &str) -> Result<u64, ReproductionArtifactError> {
    value.parse::<u64>().map_err(|error| {
        decode_line_error(line_index, tag, &format!("invalid u64 `{value}`: {error}"))
    })
}

fn parse_usize(
    line_index: usize,
    tag: &str,
    value: &str,
) -> Result<usize, ReproductionArtifactError> {
    value.parse::<usize>().map_err(|error| {
        decode_line_error(
            line_index,
            tag,
            &format!("invalid usize `{value}`: {error}"),
        )
    })
}

fn parse_hex_bytes(
    line_index: usize,
    tag: &str,
    value: &str,
) -> Result<Vec<u8>, ReproductionArtifactError> {
    if !value.len().is_multiple_of(2) {
        return Err(decode_line_error(
            line_index,
            tag,
            "hex payload has odd length",
        ));
    }
    let mut bytes = Vec::with_capacity(value.len() / 2);
    for chunk in value.as_bytes().chunks(2) {
        let high = hex_nibble(chunk[0])
            .ok_or_else(|| decode_line_error(line_index, tag, "hex payload is malformed"))?;
        let low = hex_nibble(chunk[1])
            .ok_or_else(|| decode_line_error(line_index, tag, "hex payload is malformed"))?;
        bytes.push((high << 4) | low);
    }
    Ok(bytes)
}

fn hex_nibble(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        _ => None,
    }
}

fn decode_line_error(line_index: usize, tag: &str, reason: &str) -> ReproductionArtifactError {
    ReproductionArtifactError::Decode {
        reason: format!("line {} `{tag}`: {reason}", line_index + 1),
    }
}

fn missing_line(tag: &str) -> ReproductionArtifactError {
    ReproductionArtifactError::Decode {
        reason: format!("missing `{tag}` line"),
    }
}

fn stable_digest(material: &[u8]) -> [u8; 32] {
    let mut output = [0u8; 32];
    for lane in 0..4 {
        let mut state = 0xcbf2_9ce4_8422_2325u64 ^ lane;
        for byte in b"crucible.reproduction.hash.v1"
            .iter()
            .copied()
            .chain([0xff])
            .chain(material.iter().copied())
        {
            state ^= u64::from(byte);
            state = state.wrapping_mul(0x0000_0100_0000_01b3);
            state ^= state.rotate_left(17);
        }
        output[lane as usize * 8..lane as usize * 8 + 8].copy_from_slice(&state.to_be_bytes());
    }
    output
}

fn hex_bytes(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        output.push(char::from(HEX[(byte >> 4) as usize]));
        output.push(char::from(HEX[(byte & 0x0f) as usize]));
    }
    output
}
