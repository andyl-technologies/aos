//! Session request, response, and reproduction data contracts.

use super::*;

/// Stable API-level session identifier.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct SessionId {
    /// Monotone control-plane-local identifier.
    pub value: u64,
}

impl SessionId {
    /// Builds a session identifier from a monotone numeric value.
    #[must_use]
    pub const fn new(value: u64) -> Self {
        Self { value }
    }
}

/// Epoch-guarded reference to a live or recently-absent session.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct SessionRef {
    /// Stable session identifier.
    pub id: SessionId,
    /// Monotone epoch used to detect recycled identifiers.
    pub epoch: u64,
    /// Seed recorded for the session creation request.
    pub seed: Seed,
}

impl SessionRef {
    /// Builds an epoch-guarded session reference.
    #[must_use]
    pub const fn new(id: SessionId, epoch: u64, seed: Seed) -> Self {
        Self { id, epoch, seed }
    }
}

/// Scenario entry advertised by `ListScenarios`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ScenarioCatalogEntry {
    /// Human-readable registry name used by scenario-reference creation.
    pub name: String,
    /// Human-readable description returned by discovery.
    pub description: String,
    /// Stable source identifier for the scenario definition.
    pub source_id: String,
    /// Executable scenario source.
    pub source: ScenarioCatalogSource,
}

/// Scenario source stored in the server-side catalog.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ScenarioCatalogSource {
    /// A fixed scenario definition that accepts only its embedded seed.
    Fixed {
        /// Executable scenario definition.
        scenario: ScenarioDef,
    },
    /// Canonical material that can be re-materialized with the request seed.
    CanonicalMaterial {
        /// Canonical domain passed to [`ScenarioDef::from_canonical_material_with_seed`].
        domain: String,
        /// Seed-independent canonical scenario material.
        material: String,
    },
}

impl ScenarioCatalogEntry {
    /// Builds a scenario catalog entry.
    #[must_use]
    pub fn new(
        name: impl Into<String>,
        description: impl Into<String>,
        source_id: impl Into<String>,
        scenario: ScenarioDef,
    ) -> Self {
        Self {
            name: name.into(),
            description: description.into(),
            source_id: source_id.into(),
            source: ScenarioCatalogSource::Fixed { scenario },
        }
    }

    /// Builds a seed-parameterized scenario entry from canonical material.
    #[must_use]
    pub fn from_canonical_material(
        name: impl Into<String>,
        description: impl Into<String>,
        source_id: impl Into<String>,
        domain: impl Into<String>,
        material: impl Into<String>,
    ) -> Self {
        Self {
            name: name.into(),
            description: description.into(),
            source_id: source_id.into(),
            source: ScenarioCatalogSource::CanonicalMaterial {
                domain: domain.into(),
                material: material.into(),
            },
        }
    }

    /// Returns the public discovery view for this scenario.
    #[must_use]
    pub fn summary(&self) -> ScenarioSummary {
        ScenarioSummary {
            name: self.name.clone(),
            description: self.description.clone(),
            source_id: self.source_id.clone(),
        }
    }

    pub(super) fn scenario_for_seed(&self, seed: Seed) -> Result<ScenarioDef, LifecycleApiError> {
        match &self.source {
            ScenarioCatalogSource::Fixed { scenario } => {
                if scenario.seed() != seed {
                    return Err(LifecycleApiError::ScenarioSeedMismatch {
                        scenario_seed: scenario.seed(),
                        request_seed: seed,
                    });
                }
                Ok(scenario.clone())
            }
            ScenarioCatalogSource::CanonicalMaterial { domain, material } => Ok(
                ScenarioDef::from_canonical_material_with_seed(domain, material, seed),
            ),
        }
    }
}

/// Scenario metadata returned by `ListScenarios`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ScenarioSummary {
    /// Human-readable registry name.
    pub name: String,
    /// Human-readable description.
    pub description: String,
    /// Stable source identifier.
    pub source_id: String,
}

/// Response returned by `ListScenarios`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ListScenariosResponse {
    /// Scenario entries known by the server.
    pub scenarios: Vec<ScenarioSummary>,
}

/// Scenario input accepted by `CreateSession`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CreateSessionSource {
    /// Resolve a named scenario from the server registry.
    ScenarioRef {
        /// Registry name to resolve.
        name: String,
    },
    /// Use a self-contained scenario definition.
    Inline {
        /// Complete inline scenario source transferred with the request.
        scenario: Box<ScenarioDefForm>,
    },
}

/// Request accepted by `CreateSession`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CreateSessionRequest {
    /// Scenario source, either by reference or inline.
    pub source: CreateSessionSource,
    /// Seed recorded in the returned [`SessionRef`].
    pub seed: Seed,
    /// Whether the session should remain paused immediately after `Start`.
    pub start_paused: bool,
}

impl CreateSessionRequest {
    /// Builds a request from a scenario registry name.
    #[must_use]
    pub fn scenario_ref(name: impl Into<String>, seed: Seed) -> Self {
        Self {
            source: CreateSessionSource::ScenarioRef { name: name.into() },
            seed,
            start_paused: true,
        }
    }

    /// Builds a request from a complete inline scenario source form.
    #[must_use]
    pub fn inline(scenario: ScenarioDefForm, seed: Seed) -> Self {
        Self {
            source: CreateSessionSource::Inline {
                scenario: Box::new(scenario),
            },
            seed,
            start_paused: true,
        }
    }

    /// Sets whether the created session should stay paused after `Start`.
    #[must_use]
    pub fn with_start_paused(mut self, start_paused: bool) -> Self {
        self.start_paused = start_paused;
        self
    }
}

pub(super) fn inline_scenario_form(request: &CreateSessionRequest) -> Option<&ScenarioDefForm> {
    match &request.source {
        CreateSessionSource::ScenarioRef { .. } => None,
        CreateSessionSource::Inline { scenario } => Some(scenario),
    }
}

pub(super) fn scenario_form_white_box_policies(
    scenario_form: &ScenarioDefForm,
) -> BTreeMap<NodeId, WhiteBoxPolicy> {
    scenario_form
        .world()
        .vm_nodes()
        .iter()
        .map(|node| (node.id.clone(), node.white_box))
        .collect()
}

/// Response returned by `CreateSession`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CreateSessionResponse {
    /// Epoch-guarded session reference.
    pub session: SessionRef,
    /// State observed from the lock-free mirror after startup.
    pub state: LiveStateKind,
}

/// Request accepted by `ResumeSession`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ResumeSessionRequest {
    /// Serialized scenario form owning the checkpoint.
    pub scenario: ScenarioDefForm,
    /// Recorded schedule for the checkpoint configuration.
    pub schedule: Schedule,
    /// Fat checkpoint that materializes the recorded configuration.
    pub checkpoint: Checkpoint,
    /// Seed recorded in the returned [`SessionRef`].
    pub seed: Seed,
    /// Authenticated campaign choice records required by a typed selection schedule.
    pub replay_closure: Option<ResumeReplayClosure>,
    /// Portable observation claim that the daemon must authenticate before resume.
    pub observation_source: ResumeObservationSource,
}

impl ResumeSessionRequest {
    /// Builds a request from a checkpoint and content-bound observation source.
    #[must_use]
    pub fn new(
        scenario: ScenarioDefForm,
        schedule: Schedule,
        checkpoint: Checkpoint,
        seed: Seed,
        observation_source: ResumeObservationSource,
    ) -> Self {
        Self {
            scenario,
            schedule,
            checkpoint,
            seed,
            replay_closure: None,
            observation_source,
        }
    }

    /// Returns this request with a versioned campaign replay closure.
    #[must_use]
    pub fn with_replay_closure(mut self, replay_closure: ResumeReplayClosure) -> Self {
        self.replay_closure = Some(replay_closure);
        self
    }
}

/// Versioned portable observation claim supplied to `ResumeSession`.
///
/// This envelope provides transport integrity only. A configured campaign
/// owner must replay the source from genesis and compare newly produced proof
/// and evidence before the lifecycle control plane can allocate a session.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ResumeObservationSource {
    schema_version: u32,
    identity: ContentHash,
    proof: Vec<u8>,
    evidence: Vec<u8>,
}

impl ResumeObservationSource {
    /// Binds canonical proof and evidence bytes to one exact resume source.
    ///
    /// # Errors
    ///
    /// Returns [`LifecycleApiError::ResumeObservationSource`] when their
    /// combined length exceeds [`RESUME_OBSERVATION_SOURCE_MAX_BYTES`].
    pub fn new(
        scenario: &ScenarioDefForm,
        schedule: &Schedule,
        checkpoint: &Checkpoint,
        schema_version: u32,
        proof: Vec<u8>,
        evidence: Vec<u8>,
    ) -> Result<Self, LifecycleApiError> {
        let total = proof.len().checked_add(evidence.len()).ok_or_else(|| {
            LifecycleApiError::ResumeObservationSource {
                message: String::from("portable observation source size overflowed"),
            }
        })?;
        if total > RESUME_OBSERVATION_SOURCE_MAX_BYTES {
            return Err(LifecycleApiError::ResumeObservationSource {
                message: format!(
                    "portable observation source has {total} bytes, maximum is {RESUME_OBSERVATION_SOURCE_MAX_BYTES}"
                ),
            });
        }
        let identity = resume_observation_source_identity(
            scenario,
            schedule,
            checkpoint,
            schema_version,
            &proof,
            &evidence,
        );
        Ok(Self {
            schema_version,
            identity,
            proof,
            evidence,
        })
    }

    /// Returns the transport-envelope schema version.
    #[must_use]
    pub const fn schema_version(&self) -> u32 {
        self.schema_version
    }

    /// Returns the identity binding both payloads to the exact resume source.
    #[must_use]
    pub const fn identity(&self) -> ContentHash {
        self.identity
    }

    /// Returns the canonical campaign observation-stop proof.
    #[must_use]
    pub fn proof(&self) -> &[u8] {
        &self.proof
    }

    /// Returns the canonical raw measurement replay evidence.
    #[must_use]
    pub fn evidence(&self) -> &[u8] {
        &self.evidence
    }

    /// Returns the combined bounded payload length.
    #[must_use]
    pub fn payload_len(&self) -> usize {
        self.proof.len().saturating_add(self.evidence.len())
    }
}

pub(super) fn resume_observation_source_identity(
    scenario: &ScenarioDefForm,
    schedule: &Schedule,
    checkpoint: &Checkpoint,
    schema_version: u32,
    proof: &[u8],
    evidence: &[u8],
) -> ContentHash {
    const DOMAIN: &[u8] = b"crucible.resume-observation-source.v1\0";

    let configuration = Configuration {
        def: scenario.scenario_def(),
        schedule: schedule.clone(),
    };
    let checkpoint_material = ContentHash::from_bytes(&checkpoint.to_compact_binary());
    let proof_len = u64::try_from(proof.len()).unwrap_or(u64::MAX);
    let evidence_len = u64::try_from(evidence.len()).unwrap_or(u64::MAX);
    let mut material = Vec::with_capacity(
        DOMAIN
            .len()
            .saturating_add(32 * 3)
            .saturating_add(4 + 8 + proof.len() + 8 + evidence.len()),
    );
    material.extend_from_slice(DOMAIN);
    material.extend_from_slice(&scenario.id().bytes);
    material.extend_from_slice(&configuration.id().bytes);
    material.extend_from_slice(&checkpoint_material.bytes);
    material.extend_from_slice(&schema_version.to_be_bytes());
    material.extend_from_slice(&proof_len.to_be_bytes());
    material.extend_from_slice(proof);
    material.extend_from_slice(&evidence_len.to_be_bytes());
    material.extend_from_slice(evidence);
    ContentHash::from_bytes(&material)
}

/// Versioned, content-bound campaign choice evidence supplied to `ResumeSession`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ResumeReplayClosure {
    schema_version: u32,
    identity: ContentHash,
    payload: Vec<u8>,
}

impl ResumeReplayClosure {
    /// Binds a schema version and exact payload to one resume source.
    ///
    /// # Errors
    ///
    /// Returns [`LifecycleApiError::ResumeReplayClosure`] before hashing when
    /// `payload` exceeds [`RESUME_REPLAY_CLOSURE_MAX_BYTES`].
    pub fn new(
        scenario: &ScenarioDefForm,
        schedule: &Schedule,
        checkpoint: &Checkpoint,
        schema_version: u32,
        payload: Vec<u8>,
    ) -> Result<Self, LifecycleApiError> {
        if payload.len() > RESUME_REPLAY_CLOSURE_MAX_BYTES {
            return Err(LifecycleApiError::ResumeReplayClosure {
                message: format!(
                    "campaign replay closure has {} bytes, maximum is {RESUME_REPLAY_CLOSURE_MAX_BYTES}",
                    payload.len()
                ),
            });
        }
        let identity = resume_replay_closure_identity(
            scenario,
            schedule,
            checkpoint,
            schema_version,
            &payload,
        );
        Ok(Self {
            schema_version,
            identity,
            payload,
        })
    }

    /// Returns the replay-closure schema version.
    #[must_use]
    pub const fn schema_version(&self) -> u32 {
        self.schema_version
    }

    /// Returns the identity binding the resume source, schema, length, and payload.
    #[must_use]
    pub const fn identity(&self) -> ContentHash {
        self.identity
    }

    /// Returns the exact canonical replay-closure payload.
    #[must_use]
    pub fn payload(&self) -> &[u8] {
        &self.payload
    }

    /// Returns the bound payload length.
    #[must_use]
    pub const fn payload_len(&self) -> usize {
        self.payload.len()
    }
}

pub(super) fn resume_replay_closure_identity(
    scenario: &ScenarioDefForm,
    schedule: &Schedule,
    checkpoint: &Checkpoint,
    schema_version: u32,
    payload: &[u8],
) -> ContentHash {
    const DOMAIN: &[u8] = b"crucible.resume-replay-closure.v1\0";

    let configuration = Configuration {
        def: scenario.scenario_def(),
        schedule: schedule.clone(),
    };
    let checkpoint_material = ContentHash::from_bytes(&checkpoint.to_compact_binary());
    let payload_len = u64::try_from(payload.len()).unwrap_or(u64::MAX);
    let mut material = Vec::with_capacity(
        DOMAIN
            .len()
            .saturating_add(32 * 3)
            .saturating_add(4 + 8)
            .saturating_add(payload.len()),
    );
    material.extend_from_slice(DOMAIN);
    material.extend_from_slice(&scenario.id().bytes);
    material.extend_from_slice(&configuration.id().bytes);
    material.extend_from_slice(&checkpoint_material.bytes);
    material.extend_from_slice(&schema_version.to_be_bytes());
    material.extend_from_slice(&payload_len.to_be_bytes());
    material.extend_from_slice(payload);
    ContentHash::from_bytes(&material)
}

/// Response returned by `ResumeSession`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ResumeSessionResponse {
    /// Epoch-guarded session reference.
    pub session: SessionRef,
    /// State observed from the lock-free mirror after resume.
    pub state: LiveStateKind,
    /// Checkpoint accepted as the resume source.
    pub checkpoint: ContentHash,
    /// Configuration realized by the resumed session.
    pub configuration: ContentHash,
}

/// Summary returned by `ListSessions`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SessionSummary {
    /// Epoch-guarded session reference.
    pub session: SessionRef,
    /// State read from the lock-free live mirror.
    pub state: LiveStateKind,
    /// Terminal outcome read from the live mirror, when the session stopped.
    pub outcome: Option<OutcomeKind>,
    /// Terminal savepoint checkpoint id materialized for the outcome.
    pub terminal_savepoint: Option<ContentHash>,
    /// Latest scheduler virtual-time frontier read from the live mirror.
    pub frontier: VirtualTime,
    /// Event-log length read from the lock-free live mirror.
    pub event_log_len: u64,
    /// Number of scheduler quanta completed by the session actor.
    pub quanta_stepped: u64,
}

/// Response returned by `ListSessions`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ListSessionsResponse {
    /// Live session summaries.
    pub sessions: Vec<SessionSummary>,
}

/// Request accepted by `DestroySession`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct DestroySessionRequest {
    /// Session reference to stop and drop.
    pub session: SessionRef,
    /// Optional epoch guard supplied by the client.
    pub expected_epoch: Option<u64>,
}

impl DestroySessionRequest {
    /// Builds a destroy request for `session`.
    #[must_use]
    pub const fn new(session: SessionRef) -> Self {
        Self {
            session,
            expected_epoch: None,
        }
    }

    /// Sets the optional expected epoch guard.
    #[must_use]
    pub const fn with_expected_epoch(mut self, expected_epoch: u64) -> Self {
        self.expected_epoch = Some(expected_epoch);
        self
    }
}

/// Response returned by `DestroySession`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct DestroySessionResponse {
    /// Session reference supplied by the caller.
    pub session: SessionRef,
    /// Whether the session id was already absent.
    pub already_absent: bool,
    /// Whether a live actor was stopped by this request.
    pub stopped: bool,
}

/// Request accepted by `GetReproduction`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct GetReproductionRequest {
    /// Session whose reproduction context should be read.
    pub session: SessionRef,
    /// Optional epoch guard supplied by the client.
    pub expected_epoch: Option<u64>,
}

impl GetReproductionRequest {
    /// Builds a reproduction request for `session`.
    #[must_use]
    pub const fn new(session: SessionRef) -> Self {
        Self {
            session,
            expected_epoch: None,
        }
    }

    /// Sets the optional expected epoch guard.
    #[must_use]
    pub const fn with_expected_epoch(mut self, expected_epoch: u64) -> Self {
        self.expected_epoch = Some(expected_epoch);
        self
    }
}

/// Response returned by `GetReproduction`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GetReproductionResponse {
    /// Epoch-guarded session reference whose context was read.
    pub session: SessionRef,
    /// Recorded operator command stream in deterministic replay order.
    pub commands: Vec<ReproductionCommandRecord>,
}

/// Payload recorded for one command in the reproduction context.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct ReproductionCommandPayload {
    /// Payload-free command kind admitted at the boundary.
    pub command: SessionCommandKind,
    /// Stable reply-free command payload material admitted at the boundary.
    pub command_payload: String,
    /// Scheduler-control batch identifier, or zero when no scheduler payload was applied.
    pub scheduler_batch: u64,
    /// Stable scheduler-owned control payload material admitted by this command, when any.
    pub scheduler_control: Option<String>,
}

/// Result recorded for one command in the reproduction context.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum ReproductionCommandResult {
    /// The command was accepted and is part of the deterministic replay stream.
    Accepted,
}

impl From<SessionControlResult> for ReproductionCommandResult {
    fn from(value: SessionControlResult) -> Self {
        match value {
            SessionControlResult::Accepted => Self::Accepted,
        }
    }
}

/// One recorded command in the API reproduction context.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct ReproductionCommandRecord {
    /// Monotone session-local reproduction sequence.
    pub sequence: u64,
    /// Command payload admitted at the boundary.
    pub payload: ReproductionCommandPayload,
    /// Virtual-time boundary where the command took effect.
    pub virtual_time: VirtualTime,
    /// Number of scheduler quanta completed before the command took effect.
    pub quanta: u64,
    /// Event-log sequence immediately before the command took effect.
    pub at_sequence: u64,
    /// Terminal result returned for this recorded command.
    pub result: ReproductionCommandResult,
    /// Observational ordering aid for same-boundary commands; not a replay input.
    pub observational_order: u64,
}

/// Error returned when an API reproduction record cannot become a session log entry.
#[derive(Clone, Debug, Error, PartialEq, Eq)]
#[error("invalid reproduction command record {sequence}: {reason}")]
pub struct ReproductionCommandDecodeError {
    sequence: u64,
    reason: String,
}

impl ReproductionCommandDecodeError {
    fn new(sequence: u64, reason: impl Into<String>) -> Self {
        Self {
            sequence,
            reason: reason.into(),
        }
    }
}

impl From<SessionControlLogEntry> for ReproductionCommandRecord {
    fn from(value: SessionControlLogEntry) -> Self {
        Self {
            sequence: value.sequence,
            payload: ReproductionCommandPayload {
                command: value.command,
                command_payload: session_control_payload_material(&value.payload),
                scheduler_batch: value.scheduler_batch,
                scheduler_control: value
                    .scheduler_control
                    .as_ref()
                    .map(control_operation_material),
            },
            virtual_time: value.frontier,
            quanta: value.quanta,
            at_sequence: value.event_log_sequence_before,
            result: value.result.into(),
            observational_order: value.sequence,
        }
    }
}

impl TryFrom<ReproductionCommandRecord> for SessionControlLogEntry {
    type Error = ReproductionCommandDecodeError;

    fn try_from(value: ReproductionCommandRecord) -> Result<Self, Self::Error> {
        let sequence = value.sequence;
        if sequence == 0 {
            return Err(ReproductionCommandDecodeError::new(
                sequence,
                "sequence must start at one",
            ));
        }
        if value.observational_order != sequence {
            return Err(ReproductionCommandDecodeError::new(
                sequence,
                "observational order must equal the canonical sequence",
            ));
        }

        let command = value.payload.command;
        let payload =
            decode_session_control_payload(sequence, command, &value.payload.command_payload)?;
        let scheduler_control = value
            .payload
            .scheduler_control
            .as_deref()
            .map(|material| decode_scheduler_control(sequence, material))
            .transpose()?;
        match (&scheduler_control, value.payload.scheduler_batch) {
            (None, 0) | (Some(_), 1..) => {}
            (None, batch) => {
                return Err(ReproductionCommandDecodeError::new(
                    sequence,
                    format!("scheduler batch {batch} has no scheduler control"),
                ));
            }
            (Some(_), 0) => {
                return Err(ReproductionCommandDecodeError::new(
                    sequence,
                    "scheduler control has zero batch",
                ));
            }
        }

        let result = match value.result {
            ReproductionCommandResult::Accepted => SessionControlResult::Accepted,
        };
        Ok(Self {
            sequence,
            command,
            payload,
            frontier: value.virtual_time,
            quanta: value.quanta,
            event_log_sequence_before: value.at_sequence,
            result,
            scheduler_batch: value.payload.scheduler_batch,
            scheduler_control,
        })
    }
}

fn decode_session_control_payload(
    sequence: u64,
    command: SessionCommandKind,
    material: &str,
) -> Result<SessionControlPayload, ReproductionCommandDecodeError> {
    let command_kind = format!("payload=command-kind\ncommand={command:?}\n");
    if material == command_kind {
        return Ok(SessionControlPayload::CommandKind { command });
    }

    match command {
        SessionCommandKind::Fork => {
            let from = decode_single_payload_field(sequence, material, "fork", "from")?;
            let from = if from == "current" {
                CheckpointRef::Current
            } else if let Some(hash) = from.strip_prefix("checkpoint:") {
                CheckpointRef::Checkpoint(decode_content_hash(sequence, hash)?)
            } else {
                return Err(ReproductionCommandDecodeError::new(
                    sequence,
                    "fork payload has an invalid checkpoint reference",
                ));
            };
            Ok(SessionControlPayload::Fork { from })
        }
        SessionCommandKind::RemoveBreakpoint => {
            let id = decode_single_payload_field(sequence, material, "remove-breakpoint", "id")?
                .parse::<u64>()
                .map_err(|error| {
                    ReproductionCommandDecodeError::new(
                        sequence,
                        format!("remove-breakpoint id is invalid: {error}"),
                    )
                })?;
            Ok(SessionControlPayload::RemoveBreakpoint { id })
        }
        SessionCommandKind::CreateSavepoint => {
            let label =
                decode_single_payload_field(sequence, material, "create-savepoint", "label")?;
            Ok(SessionControlPayload::CreateSavepoint {
                label: decode_hex_text(sequence, label)?,
            })
        }
        SessionCommandKind::SetBreakpoint => Err(ReproductionCommandDecodeError::new(
            sequence,
            "set-breakpoint canonical summaries are not reversible",
        )),
        _ => Err(ReproductionCommandDecodeError::new(
            sequence,
            format!("payload does not match command {command:?}"),
        )),
    }
}

fn decode_single_payload_field<'a>(
    sequence: u64,
    material: &'a str,
    payload_kind: &str,
    field: &str,
) -> Result<&'a str, ReproductionCommandDecodeError> {
    let mut lines = material.lines();
    if lines.next() != Some(format!("payload={payload_kind}").as_str()) {
        return Err(ReproductionCommandDecodeError::new(
            sequence,
            format!("expected {payload_kind} payload"),
        ));
    }
    let line = lines.next().ok_or_else(|| {
        ReproductionCommandDecodeError::new(sequence, format!("missing {field} payload field"))
    })?;
    if lines.next().is_some() {
        return Err(ReproductionCommandDecodeError::new(
            sequence,
            "unexpected extra command payload fields",
        ));
    }
    line.strip_prefix(&format!("{field}=")).ok_or_else(|| {
        ReproductionCommandDecodeError::new(sequence, format!("missing {field} payload field"))
    })
}

fn decode_scheduler_control(
    sequence: u64,
    material: &str,
) -> Result<ControlOperationKind, ReproductionCommandDecodeError> {
    match material {
        "control=pause\n" => Ok(ControlOperationKind::Pause),
        "control=resume\n" => Ok(ControlOperationKind::Resume),
        "control=step\n" => Ok(ControlOperationKind::Step),
        "control=snapshot\n" => Ok(ControlOperationKind::Snapshot),
        "control=fork\n" => Ok(ControlOperationKind::Fork),
        "control=query\n" => Ok(ControlOperationKind::Query),
        _ => Err(ReproductionCommandDecodeError::new(
            sequence,
            "unknown scheduler control payload",
        )),
    }
}

fn decode_content_hash(
    sequence: u64,
    encoded: &str,
) -> Result<ContentHash, ReproductionCommandDecodeError> {
    let bytes = decode_hex_bytes(sequence, encoded)?;
    let bytes: [u8; 32] = bytes.try_into().map_err(|_| {
        ReproductionCommandDecodeError::new(sequence, "content hash must contain 32 bytes")
    })?;
    Ok(ContentHash { bytes })
}

fn decode_hex_text(sequence: u64, encoded: &str) -> Result<String, ReproductionCommandDecodeError> {
    String::from_utf8(decode_hex_bytes(sequence, encoded)?).map_err(|error| {
        ReproductionCommandDecodeError::new(sequence, format!("hex payload is not UTF-8: {error}"))
    })
}

fn decode_hex_bytes(
    sequence: u64,
    encoded: &str,
) -> Result<Vec<u8>, ReproductionCommandDecodeError> {
    if !encoded.len().is_multiple_of(2) {
        return Err(ReproductionCommandDecodeError::new(
            sequence,
            "hex payload has odd length",
        ));
    }
    encoded
        .as_bytes()
        .as_chunks::<2>()
        .0
        .iter()
        .map(|pair| {
            let high = decode_hex_nibble(pair[0]);
            let low = decode_hex_nibble(pair[1]);
            match (high, low) {
                (Some(high), Some(low)) => Ok((high << 4) | low),
                _ => Err(ReproductionCommandDecodeError::new(
                    sequence,
                    "hex payload contains a non-hex character",
                )),
            }
        })
        .collect()
}

fn decode_hex_nibble(value: u8) -> Option<u8> {
    match value {
        b'0'..=b'9' => Some(value - b'0'),
        b'a'..=b'f' => Some(value - b'a' + 10),
        b'A'..=b'F' => Some(value - b'A' + 10),
        _ => None,
    }
}

fn session_control_payload_material(payload: &SessionControlPayload) -> String {
    match payload {
        SessionControlPayload::CommandKind { command } => {
            format!("payload=command-kind\ncommand={command:?}\n")
        }
        SessionControlPayload::Fork { from } => {
            format!("payload=fork\nfrom={}\n", checkpoint_ref_material(*from))
        }
        SessionControlPayload::SetBreakpoint { spec } => format!(
            "payload=set-breakpoint\npredicate={}\ndisposition={}\npolicy={}\n",
            hex_string(&spec.predicate.canonical_summary()),
            breakpoint_disposition_material(&spec.disposition),
            breakpoint_policy_material(spec.policy),
        ),
        SessionControlPayload::RemoveBreakpoint { id } => {
            format!("payload=remove-breakpoint\nid={id}\n")
        }
        SessionControlPayload::CreateSavepoint { label } => {
            format!("payload=create-savepoint\nlabel={}\n", hex_string(label))
        }
    }
}

fn control_operation_material(control: &ControlOperationKind) -> String {
    match control {
        ControlOperationKind::Pause => String::from("control=pause\n"),
        ControlOperationKind::Resume => String::from("control=resume\n"),
        ControlOperationKind::Step => String::from("control=step\n"),
        ControlOperationKind::Snapshot => String::from("control=snapshot\n"),
        ControlOperationKind::Fork => String::from("control=fork\n"),
        ControlOperationKind::Query => String::from("control=query\n"),
    }
}

fn checkpoint_ref_material(from: CheckpointRef) -> String {
    match from {
        CheckpointRef::Current => String::from("current"),
        CheckpointRef::Checkpoint(hash) => format!("checkpoint:{}", hash.to_hex()),
    }
}

fn breakpoint_disposition_material(disposition: &BreakpointDisposition) -> String {
    match disposition {
        BreakpointDisposition::Suspend => String::from("suspend"),
        BreakpointDisposition::Trace => String::from("trace"),
        BreakpointDisposition::Action(action) => {
            format!("action:{}", hex_string(&action_material(action)))
        }
    }
}

fn action_material(action: &Action) -> String {
    match action {
        Action::ArmTimer { name, after } => format!(
            "action=arm-timer\nname={}\nafter-ticks={}\n",
            hex_string(&name.name),
            after.ticks,
        ),
        Action::CancelTimer { name } => {
            format!("action=cancel-timer\nname={}\n", hex_string(&name.name))
        }
        Action::StartNode { node } => {
            format!("action=start-node\nnode={}\n", hex_string(&node.name))
        }
        Action::StopNode { node } => {
            format!("action=stop-node\nnode={}\n", hex_string(&node.name))
        }
        Action::CreateSavepoint { label } => format!(
            "action=create-savepoint\nlabel={}\n",
            optional_hex_string(label.as_deref()),
        ),
        Action::Fork { label } => format!(
            "action=fork\nlabel={}\n",
            optional_hex_string(label.as_deref()),
        ),
        Action::Pass => String::from("action=pass\n"),
        Action::Fail { reason } => format!("action=fail\nreason={}\n", hex_string(reason)),
        Action::Log { level, message } => format!(
            "action=log\nlevel={}\nmessage={}\n",
            log_level_material(*level),
            hex_string(message),
        ),
        Action::Group(actions) => {
            let mut output = format!("action=group\ncount={}\n", actions.len());
            for (index, action) in actions.iter().enumerate() {
                output.push_str(&format!(
                    "member.{index}={}\n",
                    hex_string(&action_material(action)),
                ));
            }
            output
        }
    }
}

fn log_level_material(level: LogLevel) -> &'static str {
    match level {
        LogLevel::Debug => "debug",
        LogLevel::Info => "info",
        LogLevel::Warn => "warn",
        LogLevel::Error => "error",
    }
}

fn breakpoint_policy_material(policy: BreakpointPolicy) -> &'static str {
    match policy {
        BreakpointPolicy::OneShot => "one-shot",
        BreakpointPolicy::Repeatable => "repeatable",
    }
}

#[cfg(test)]
mod exact_tick_wire_tests {
    use super::*;

    #[test]
    fn arm_timer_reproduction_material_names_exact_ticks() {
        let action = Action::arm_timer(
            crucible::TimerId {
                name: String::from("pulse"),
            },
            crucible::SimDuration { ticks: 3 },
        );

        assert_eq!(
            action_material(&action),
            "action=arm-timer\nname=70756c7365\nafter-ticks=3\n"
        );
    }
}
