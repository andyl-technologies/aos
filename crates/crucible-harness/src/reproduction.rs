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
//! schema  crucible.reproduction-artifact.v1
//! seed    42
//! identity  0.1.0  engine-abi:v1  crucible.reproduction-artifact.v1  crucible-hash:...  plugin-abi:v1
//! scenario  scenario_def  cluster.scn  crucible-hash:...  cas:crucible-hash:...  application/vnd.crucible.scenario+text  128
//! payload  crucible-hash:...  7363656e6172696f
//! schedule  crucible-hash:...  12
//! decision  0  1  node-a  deliver  crucible-hash:...
//! ```

use std::error::Error;
use std::fmt;

use crate::e2e::{
    E2eBuildIdentity, E2eDecision, E2eFaultKind, E2ePropertyKind, E2eReproductionArtifact,
    canonical_mock_build_identity, representative_mock_e2e_artifact, reproduce_mock_e2e_artifact,
};

/// Current reproduction artifact schema identifier.
pub const REPRODUCTION_ARTIFACT_SCHEMA: &str = "crucible.reproduction-artifact.v1";

/// Media type for the canonical artifact encoding.
pub const REPRODUCTION_ARTIFACT_MEDIA_TYPE: &str = "application/vnd.crucible.reproduction+text";

/// A versioned reproduction artifact.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ReproductionArtifact {
    /// Schema identifier for this artifact.
    pub schema_version: String,
    /// Deterministic root seed used by the run.
    pub seed: u64,
    /// Pinned engine, ABI, and QEMU/plugin identities for the producer.
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

impl ReproductionArtifact {
    /// Builds a validated reproduction artifact and computes its schedule digest.
    ///
    /// # Errors
    ///
    /// Returns [`ReproductionArtifactError`] when the artifact fields are
    /// malformed, the scenario is not a scenario definition reference, a digest
    /// is invalid, or the schedule is empty or not totally ordered.
    pub fn from_parts(
        seed: u64,
        build_identity: PinnedBuildIdentity,
        scenario: ContentAddressedComponent,
        decisions: Vec<RecordedDecision>,
        components: Vec<ContentAddressedComponent>,
        component_payloads: Vec<ComponentPayload>,
        fingerprint_tail: Vec<FingerprintTailSample>,
        sampling_config: FingerprintSamplingConfig,
    ) -> Result<Self, ReproductionArtifactError> {
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
                &["fingerprint", &sample.index.to_string(), &sample.digest],
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
        require_non_empty("build_identity.plugin_abi", &self.plugin_abi)?;
        validate_digest("build_identity.qemu_build_id", &self.qemu_build_id)?;
        Ok(())
    }
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
    let decisions = source
        .schedule
        .decisions
        .iter()
        .enumerate()
        .map(|(sequence, decision)| recorded_decision_from_e2e(sequence as u64, decision))
        .collect::<Vec<_>>();
    let run =
        reproduce_mock_e2e_artifact(source, &canonical_mock_build_identity()).map_err(|error| {
            ReproductionArtifactError::SourceReplay {
                reason: error.to_string(),
            }
        })?;
    let fingerprint_tail = vec![FingerprintTailSample {
        index: source.schedule.len() as u64,
        digest: content_address_bytes(&run.final_fingerprint),
    }];

    ReproductionArtifact::from_parts(
        source.seed,
        build_identity,
        scenario.clone(),
        decisions,
        vec![scenario],
        vec![ComponentPayload::from_bytes(&scenario_material)],
        fingerprint_tail,
        FingerprintSamplingConfig::mock_defaults(),
    )
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
                require_field_count(line_index, tag, &fields, 6)?;
                set_once(
                    &mut build_identity,
                    line_index,
                    tag,
                    PinnedBuildIdentity {
                        engine_version: fields[1].clone(),
                        engine_abi: fields[2].clone(),
                        artifact_abi: fields[3].clone(),
                        qemu_build_id: fields[4].clone(),
                        plugin_abi: fields[5].clone(),
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
                require_field_count(line_index, tag, &fields, 3)?;
                fingerprint_tail.push(FingerprintTailSample {
                    index: parse_u64(line_index, tag, &fields[1])?,
                    digest: fields[2].clone(),
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
        engine_version: env!("CARGO_PKG_VERSION").to_string(),
        engine_abi: source.harness_abi.clone(),
        artifact_abi: REPRODUCTION_ARTIFACT_SCHEMA.to_string(),
        qemu_build_id: content_address_bytes(source.backend_build_id.as_bytes()),
        plugin_abi: format!("{}-plugin-abi", source.backend),
    }
}

fn recorded_decision_from_e2e(sequence: u64, decision: &E2eDecision) -> RecordedDecision {
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

    RecordedDecision {
        sequence,
        virtual_time_ticks,
        node,
        kind,
        payload_digest: content_address_bytes(payload.as_bytes()),
    }
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
    if value.len() % 2 != 0 {
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
