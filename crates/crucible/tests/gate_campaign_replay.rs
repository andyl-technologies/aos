//! Verifies portable rich-finding replay without campaign repository access.
//!
//! The ordinary gate process exports only canonical reproduction, candidate,
//! and replay-evidence records. A separately invoked ignored helper starts with
//! a cleared environment, reads that export, reconstructs all four native
//! signatures, and checks their active-policy key. Negative exports prove that
//! missing, corrupt, and cross-record mismatches fail closed.

#![forbid(unsafe_code)]

use std::collections::BTreeSet;
use std::error::Error;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::sync::atomic::{AtomicU64, Ordering};

use crucible::test_support::{
    condition_observation_entry_for_test, condition_payload_entry_for_test,
};
use crucible::{
    AssertionId, AssertionPhase, AssertionQuantifierKind, ChoiceTag, Configuration, ContentHash,
    Decision, FAILURE_TRIAGE_REPLAY_EVIDENCE_SCHEMA_VERSION, FailureClusterReportFailure,
    FailureKind as NativeFailureKind, FailurePropertyViolationRecord, FailureTriageReplayEvidence,
    FindingDiscoveryPath, FindingReproductionArtifact, HostAssertionViolation, Icount, MarkerId,
    NodeId, NodeTemplate, ObservableEvent, OverrideDecision, Plan, Properties, ReadyPoint,
    ScenarioDefForm, Schedule, SchedulerEventLogEntry, SchedulerEventLogPayload, SchedulingPoint,
    Seed, SignaturePolicy, VirtualTime, WhiteBoxPolicy, World, WorldNode,
};
use crucible_campaign::{
    CampaignHash, ConfigurationArtifactId, ConfigurationId, FindingCandidateBundle,
    FindingExactPins, FindingKind, FindingMinimizationAttempt, FindingMinimizationEvidence,
    FindingReplaySignature, FindingSignature, FindingSignatureMinimizationEvidence, FindingTarget,
    FindingTriageEvidenceSet, FindingTriageReplayEvidence, ObservationId,
    ReproductionArtifact as CampaignReproductionArtifact, ScenarioArtifactId, ScenarioDefId,
};
use crucible_cas::content_store::{ContentId, ObjectKind};

const EXPORT_DIRECTORY_ENV: &str = "CRUCIBLE_CAMPAIGN_REPLAY_EXPORT";
const BUNDLE_FILE: &str = "candidate.bundle";
const ORIGINAL_REPRODUCTION_FILE: &str = "original.reproduction";
const SELECTED_REPRODUCTION_FILE: &str = "selected.reproduction";
const NATIVE_KEY_FILE: &str = "native-signature.key";
const MINIMIZATION_ORIGINAL_FILE: &str = "minimization-original.evidence";
const MINIMIZATION_SELECTED_FILE: &str = "minimization-selected.evidence";
const VERIFICATION_ORIGINAL_FILE: &str = "verification-original.evidence";
const VERIFICATION_SELECTED_FILE: &str = "verification-selected.evidence";

static NEXT_EXPORT_DIRECTORY: AtomicU64 = AtomicU64::new(0);

#[derive(Clone, Copy)]
enum InvalidExport {
    MissingEvidence,
    CorruptEvidence,
    WrongPayloadSchema,
    WrongReproduction,
    WrongObservedSignature,
    WrongNativePayload,
    WrongSlotIdentity,
    WrongLedgerKey,
}

impl InvalidExport {
    const fn expected_diagnostic(self) -> &'static str {
        match self {
            Self::MissingEvidence => "cannot read required export verification-selected.evidence",
            Self::CorruptEvidence => "triage evidence canonical body is corrupt",
            Self::WrongPayloadSchema => "unsupported native replay-evidence payload schema",
            Self::WrongReproduction => "triage evidence names another reproduction",
            Self::WrongObservedSignature => "triage evidence names another observed signature",
            Self::WrongNativePayload => "native replay payload is corrupt or mismatched",
            Self::WrongSlotIdentity => "triage evidence differs from authenticated bundle slot",
            Self::WrongLedgerKey => "native replay signature differs from ledger member key",
        }
    }
}

struct ReplayExport {
    bundle: FindingCandidateBundle,
    original_reproduction: CampaignReproductionArtifact,
    selected_reproduction: CampaignReproductionArtifact,
    minimization_original: FindingTriageReplayEvidence,
    minimization_selected: FindingTriageReplayEvidence,
    verification_original: FindingTriageReplayEvidence,
    verification_selected: FindingTriageReplayEvidence,
    alternate_original: FindingTriageReplayEvidence,
    native_key: String,
}

struct ExportDirectory {
    path: PathBuf,
}

impl ExportDirectory {
    fn new(label: &str) -> io::Result<Self> {
        let sequence = NEXT_EXPORT_DIRECTORY.fetch_add(1, Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!(
            "crucible-campaign-replay-{}-{sequence}-{label}",
            std::process::id()
        ));
        fs::create_dir(&path)?;
        Ok(Self { path })
    }

    fn path(&self) -> &Path {
        &self.path
    }
}

impl Drop for ExportDirectory {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.path);
    }
}

#[test]
fn offline_rich_finding_replays_without_campaign_store() -> Result<(), Box<dyn Error>> {
    let export = replay_export()?;
    assert_consumer_is_listed()?;

    let valid = ExportDirectory::new("valid")?;
    write_export(valid.path(), &export)?;
    assert_consumer_succeeds(valid.path())?;

    for (label, mutation) in [
        ("missing", InvalidExport::MissingEvidence),
        ("corrupt", InvalidExport::CorruptEvidence),
        ("schema", InvalidExport::WrongPayloadSchema),
        ("reproduction", InvalidExport::WrongReproduction),
        ("signature", InvalidExport::WrongObservedSignature),
        ("native-payload", InvalidExport::WrongNativePayload),
        ("slot", InvalidExport::WrongSlotIdentity),
        ("ledger-key", InvalidExport::WrongLedgerKey),
    ] {
        let invalid = ExportDirectory::new(label)?;
        write_export(invalid.path(), &export)?;
        invalidate_export(invalid.path(), &export, mutation)?;
        assert_consumer_fails(invalid.path(), label, mutation.expected_diagnostic())?;
    }

    Ok(())
}

#[test]
#[ignore = "spawned offline campaign-replay consumer"]
fn offline_campaign_replay_consumer() {
    let directory = std::env::var_os(EXPORT_DIRECTORY_ENV)
        .map(PathBuf::from)
        .unwrap_or_else(|| panic!("{EXPORT_DIRECTORY_ENV} is required"));
    if let Err(error) = consume_export(&directory) {
        panic!("offline campaign replay rejected export: {error}");
    }
}

fn assert_consumer_succeeds(directory: &Path) -> Result<(), Box<dyn Error>> {
    let output = run_consumer(directory)?;
    if !output.status.success() {
        return Err(process_failure("valid export", &output).into());
    }
    require_consumer_outcome(
        &output,
        "ok",
        "test result: ok. 1 passed; 0 failed; 0 ignored;",
    )?;
    Ok(())
}

fn assert_consumer_fails(
    directory: &Path,
    label: &str,
    expected_diagnostic: &str,
) -> Result<(), Box<dyn Error>> {
    let output = run_consumer(directory)?;
    if output.status.success() {
        return Err(
            io::Error::other(format!("offline consumer accepted invalid {label} export")).into(),
        );
    }
    require_consumer_outcome(
        &output,
        "FAILED",
        "test result: FAILED. 0 passed; 1 failed; 0 ignored;",
    )?;
    let transcript = process_transcript(&output);
    if !transcript.contains("offline campaign replay rejected export:")
        || !transcript.contains(expected_diagnostic)
    {
        return Err(io::Error::other(format!(
            "offline consumer rejected invalid {label} export without the expected diagnostic `{expected_diagnostic}`: {transcript}"
        ))
        .into());
    }
    Ok(())
}

fn assert_consumer_is_listed() -> Result<(), Box<dyn Error>> {
    let output = Command::new(std::env::current_exe()?)
        .args([
            "--ignored",
            "--exact",
            "offline_campaign_replay_consumer",
            "--list",
        ])
        .env_clear()
        .output()?;
    if !output.status.success() {
        return Err(process_failure("consumer listing", &output).into());
    }

    let listed = String::from_utf8_lossy(&output.stdout)
        .lines()
        .filter(|line| *line == "offline_campaign_replay_consumer: test")
        .count();
    if listed != 1 {
        return Err(io::Error::other(format!(
            "expected exactly one listed offline consumer, found {listed}: {}",
            process_transcript(&output)
        ))
        .into());
    }
    Ok(())
}

fn require_consumer_outcome(
    output: &Output,
    outcome: &str,
    summary: &str,
) -> Result<(), io::Error> {
    let transcript = process_transcript(output);
    let test_line = format!("test offline_campaign_replay_consumer ... {outcome}");
    if !transcript.lines().any(|line| line == test_line) || !transcript.contains(summary) {
        return Err(io::Error::other(format!(
            "offline consumer did not produce the exact `{outcome}` result: {transcript}"
        )));
    }
    Ok(())
}

fn run_consumer(directory: &Path) -> io::Result<Output> {
    Command::new(std::env::current_exe()?)
        .args([
            "--ignored",
            "--exact",
            "offline_campaign_replay_consumer",
            "--nocapture",
        ])
        .current_dir(directory)
        .env_clear()
        .env(EXPORT_DIRECTORY_ENV, directory)
        .output()
}

fn process_failure(label: &str, output: &Output) -> io::Error {
    io::Error::other(format!(
        "offline consumer rejected {label}: status={} transcript={}",
        output.status,
        process_transcript(output)
    ))
}

fn process_transcript(output: &Output) -> String {
    format!(
        "stdout={} stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    )
}

fn consume_export(directory: &Path) -> Result<(), Box<dyn Error>> {
    let bundle = FindingCandidateBundle::from_canonical_bytes(&read(directory, BUNDLE_FILE)?)?;
    let original = CampaignReproductionArtifact::from_canonical_bytes(&read(
        directory,
        ORIGINAL_REPRODUCTION_FILE,
    )?)?;
    let selected = CampaignReproductionArtifact::from_canonical_bytes(&read(
        directory,
        SELECTED_REPRODUCTION_FILE,
    )?)?;

    if bundle.schema_version() != 2
        || original.id()? != bundle.reproduction()
        || selected.id()? != bundle.minimized()
    {
        return Err(invalid("candidate bundle reproduction closure mismatch").into());
    }
    let minimization = selected
        .minimization()
        .ok_or_else(|| invalid("selected reproduction has no minimization trace"))?;
    if minimization.original() != bundle.reproduction() {
        return Err(invalid("selected reproduction names another original").into());
    }
    let selected_index = minimization
        .attempts()
        .iter()
        .position(|attempt| attempt.accepted())
        .map(|index| index + 1)
        .unwrap_or(0);
    let signatures = bundle.signature_minimization();
    let minimization_original_signature = signature_at(signatures.minimization_pass(), 0)?;
    let minimization_selected_signature =
        signature_at(signatures.minimization_pass(), selected_index)?;
    let verification_original_signature = signature_at(signatures.verification_pass(), 0)?;
    let verification_selected_signature =
        signature_at(signatures.verification_pass(), selected_index)?;
    let triage = bundle
        .triage_evidence()
        .ok_or_else(|| invalid("candidate bundle has no rich triage evidence"))?;

    let slots = [
        EvidenceSlot {
            file: MINIMIZATION_ORIGINAL_FILE,
            expected_id: triage.minimization_original(),
            reproduction: &original,
            signature: minimization_original_signature,
        },
        EvidenceSlot {
            file: MINIMIZATION_SELECTED_FILE,
            expected_id: triage.minimization_selected(),
            reproduction: &selected,
            signature: minimization_selected_signature,
        },
        EvidenceSlot {
            file: VERIFICATION_ORIGINAL_FILE,
            expected_id: triage.verification_original(),
            reproduction: &original,
            signature: verification_original_signature,
        },
        EvidenceSlot {
            file: VERIFICATION_SELECTED_FILE,
            expected_id: triage.verification_selected(),
            reproduction: &selected,
            signature: verification_selected_signature,
        },
    ];
    let expected_native_key = read_native_key(directory)?;
    let active_policy = SignaturePolicy::default_policy();

    for slot in slots {
        let record =
            FindingTriageReplayEvidence::from_canonical_bytes(&read(directory, slot.file)?)
                .map_err(|_| invalid("triage evidence canonical body is corrupt"))?;
        if record.payload_schema() != FAILURE_TRIAGE_REPLAY_EVIDENCE_SCHEMA_VERSION {
            return Err(invalid("unsupported native replay-evidence payload schema").into());
        }
        if record.reproduction() != slot.reproduction.id()? {
            return Err(invalid("triage evidence names another reproduction").into());
        }
        if record.observed_signature() != slot.signature {
            return Err(invalid("triage evidence names another observed signature").into());
        }

        let finding = campaign_reproduction_to_native(slot.reproduction)?;
        let native = FailureTriageReplayEvidence::from_compact_binary(finding, record.payload())
            .map_err(|_| invalid("native replay payload is corrupt or mismatched"))?;
        validate_campaign_signature_binding(&native, slot.reproduction, slot.signature)?;
        let native_key = native
            .signature()
            .signature_key(active_policy)?
            .content_hash()
            .to_hex();
        if native_key != expected_native_key {
            return Err(invalid("native replay signature differs from ledger member key").into());
        }
        if record.id()? != slot.expected_id {
            return Err(invalid("triage evidence differs from authenticated bundle slot").into());
        }
    }

    let original_replay = FindingReplaySignature::from_observed(minimization_original_signature);
    let selected_replay = FindingReplaySignature::from_observed(minimization_selected_signature);
    if original_replay.cluster_key() != selected_replay.cluster_key()
        || original_replay.cluster_key() != signatures.target_signature()
    {
        return Err(invalid("campaign replay signatures do not preserve the target key").into());
    }

    Ok(())
}

struct EvidenceSlot<'a> {
    file: &'static str,
    expected_id: crucible_campaign::FindingTriageReplayEvidenceId,
    reproduction: &'a CampaignReproductionArtifact,
    signature: &'a FindingSignature,
}

fn signature_at(
    pass: &[Option<FindingSignature>],
    index: usize,
) -> Result<&FindingSignature, io::Error> {
    pass.get(index)
        .and_then(Option::as_ref)
        .ok_or_else(|| invalid("finding signature pass has no selected observation"))
}

fn campaign_reproduction_to_native(
    reproduction: &CampaignReproductionArtifact,
) -> Result<FindingReproductionArtifact, Box<dyn Error>> {
    let artifact = crucible::ReproductionArtifact::from_compact_binary(reproduction.payload())?;
    let replay = artifact.replay()?;
    let configuration = Configuration {
        def: artifact.scenario_def(),
        schedule: artifact.schedule().clone(),
    };
    let finding = FindingReproductionArtifact {
        discovery_path: FindingDiscoveryPath::StateSpaceSearch,
        finding_fingerprint: ContentHash {
            bytes: reproduction.finding_fingerprint().as_bytes(),
        },
        configuration: configuration.id(),
        artifact,
        replay,
    };
    if reproduction.scenario().as_hash().as_bytes() != finding.artifact.scenario_def().id().bytes
        || reproduction.configuration().as_hash().as_bytes() != finding.configuration.bytes
    {
        return Err(invalid("campaign reproduction semantic identity mismatch").into());
    }
    Ok(finding)
}

fn validate_campaign_signature_binding(
    native: &FailureTriageReplayEvidence,
    reproduction: &CampaignReproductionArtifact,
    observed: &FindingSignature,
) -> Result<(), io::Error> {
    let expected_kind = match native.signature().failure_kind {
        NativeFailureKind::PropertyViolation => FindingKind::PropertyViolation,
        NativeFailureKind::Divergence => FindingKind::Divergence,
        NativeFailureKind::Timeout => FindingKind::Timeout,
    };
    let expected_property = native
        .signature()
        .property
        .as_ref()
        .map(|property| property.id.name.as_str());
    if observed.kind() != expected_kind
        || observed.fingerprint() != reproduction.finding_fingerprint()
        || observed.property() != expected_property
        || observed.target()
            != Some(FindingTarget::Configuration(
                reproduction.configuration_artifact(),
            ))
    {
        return Err(invalid(
            "campaign signature is not bound to native replay inputs",
        ));
    }
    Ok(())
}

fn replay_export() -> Result<ReplayExport, Box<dyn Error>> {
    let scenario = scenario_form()?;
    let failure_decision = override_decision("triage-decision", "fail");
    let original_decisions = vec![
        override_decision("irrelevant-prefix", "left"),
        failure_decision.clone(),
    ];
    let selected_decisions = vec![failure_decision];
    let fingerprint = hash("portable-finding");
    let original_finding = finding_artifact(
        &scenario,
        Schedule::from_decisions(original_decisions.clone()),
        fingerprint,
    )?;
    let selected_finding = finding_artifact(
        &scenario,
        Schedule::from_decisions(selected_decisions.clone()),
        fingerprint,
    )?;

    let scenario_id = ScenarioDefId::from_hash(CampaignHash::from_bytes(
        original_finding.artifact.scenario_def().id().bytes,
    ));
    let scenario_artifact =
        content_id::<ScenarioArtifactId>(ObjectKind::Scenario, 1, b"portable scenario artifact")?;
    let original_configuration = ConfigurationId::from_hash(CampaignHash::from_bytes(
        original_finding.configuration.bytes,
    ));
    let selected_configuration = ConfigurationId::from_hash(CampaignHash::from_bytes(
        selected_finding.configuration.bytes,
    ));
    let original_configuration_artifact = content_id::<ConfigurationArtifactId>(
        ObjectKind::Configuration,
        1,
        b"portable original configuration",
    )?;
    let selected_configuration_artifact = content_id::<ConfigurationArtifactId>(
        ObjectKind::Configuration,
        1,
        b"portable selected configuration",
    )?;
    let campaign_fingerprint = CampaignHash::from_bytes(fingerprint.bytes);
    let original_reproduction = CampaignReproductionArtifact::new(
        scenario_id,
        scenario_artifact,
        original_configuration,
        original_configuration_artifact,
        campaign_fingerprint,
        1,
        original_finding.artifact.to_compact_binary(),
    )?;
    let original_reproduction_id = original_reproduction.id()?;
    let selected_state = CampaignHash::from_bytes(selected_finding.replay.state.bytes);
    let minimization = FindingMinimizationEvidence::new(
        original_reproduction_id,
        1,
        b"portable lexicographic minimization".to_vec(),
        vec![FindingMinimizationAttempt::new(
            0,
            CampaignHash::from_bytes(selected_finding.artifact.id().bytes),
            CampaignHash::from_bytes(selected_finding.artifact.schedule().content_hash().bytes),
            selected_state,
            Some(campaign_fingerprint),
            true,
        )],
        selected_state,
    )?;
    let selected_reproduction = CampaignReproductionArtifact::new_minimized(
        scenario_id,
        scenario_artifact,
        selected_configuration,
        selected_configuration_artifact,
        campaign_fingerprint,
        1,
        selected_finding.artifact.to_compact_binary(),
        minimization.clone(),
    )?;
    let selected_reproduction_id = selected_reproduction.id()?;

    let original_signature =
        campaign_signature(campaign_fingerprint, original_configuration_artifact)?;
    let selected_signature =
        campaign_signature(campaign_fingerprint, selected_configuration_artifact)?;
    let signature_minimization = FindingSignatureMinimizationEvidence::new(
        &original_signature,
        &minimization,
        vec![
            Some(original_signature.clone()),
            Some(selected_signature.clone()),
        ],
        vec![
            Some(original_signature.clone()),
            Some(selected_signature.clone()),
        ],
    )?;

    let minimization_original_payload = native_evidence(
        &original_finding,
        &original_decisions,
        b"minimization-original",
    )?;
    let minimization_selected_payload = native_evidence(
        &selected_finding,
        &selected_decisions,
        b"minimization-selected",
    )?;
    let verification_original_payload = native_evidence(
        &original_finding,
        &original_decisions,
        b"verification-original",
    )?;
    let verification_selected_payload = native_evidence(
        &selected_finding,
        &selected_decisions,
        b"verification-selected",
    )?;
    let alternate_original_payload = native_evidence(
        &original_finding,
        &original_decisions,
        b"alternate-original",
    )?;
    let native_key = minimization_original_payload
        .signature()
        .signature_key(SignaturePolicy::default_policy())?
        .content_hash()
        .to_hex();
    for evidence in [
        &minimization_selected_payload,
        &verification_original_payload,
        &verification_selected_payload,
        &alternate_original_payload,
    ] {
        if evidence
            .signature()
            .signature_key(SignaturePolicy::default_policy())?
            .content_hash()
            .to_hex()
            != native_key
        {
            return Err(invalid("fixture native signatures do not share a policy key").into());
        }
    }

    let minimization_original = campaign_evidence(
        original_reproduction_id,
        original_signature.clone(),
        &minimization_original_payload,
    )?;
    let minimization_selected = campaign_evidence(
        selected_reproduction_id,
        selected_signature.clone(),
        &minimization_selected_payload,
    )?;
    let verification_original = campaign_evidence(
        original_reproduction_id,
        original_signature.clone(),
        &verification_original_payload,
    )?;
    let verification_selected = campaign_evidence(
        selected_reproduction_id,
        selected_signature.clone(),
        &verification_selected_payload,
    )?;
    let alternate_original = campaign_evidence(
        original_reproduction_id,
        original_signature.clone(),
        &alternate_original_payload,
    )?;
    let triage = FindingTriageEvidenceSet::new(
        minimization_original.id()?,
        minimization_selected.id()?,
        verification_original.id()?,
        verification_selected.id()?,
    );
    let observation =
        content_id::<ObservationId>(ObjectKind::Observation, 1, b"portable finding observation")?;
    let bundle = FindingCandidateBundle::new_with_triage_evidence(
        observation,
        original_signature,
        original_reproduction_id,
        selected_reproduction_id,
        signature_minimization,
        FindingExactPins::default(),
        triage,
    )?;

    Ok(ReplayExport {
        bundle,
        original_reproduction,
        selected_reproduction,
        minimization_original,
        minimization_selected,
        verification_original,
        verification_selected,
        alternate_original,
        native_key,
    })
}

fn campaign_evidence(
    reproduction: crucible_campaign::ReproductionArtifactId,
    signature: FindingSignature,
    native: &FailureTriageReplayEvidence,
) -> Result<FindingTriageReplayEvidence, Box<dyn Error>> {
    Ok(FindingTriageReplayEvidence::new(
        reproduction,
        signature,
        FAILURE_TRIAGE_REPLAY_EVIDENCE_SCHEMA_VERSION,
        native.to_compact_binary()?,
    )?)
}

fn native_evidence(
    finding: &FindingReproductionArtifact,
    decisions: &[Decision],
    frame: &[u8],
) -> Result<FailureTriageReplayEvidence, Box<dyn Error>> {
    let failure = FailureClusterReportFailure::property(FailurePropertyViolationRecord::new(
        HostAssertionViolation {
            assertion: AssertionId::from_name("no-forbidden-marker"),
            message: String::from("forbidden marker must stay absent"),
            quantifier: AssertionQuantifierKind::Always,
            event_kind: String::from("assertion_state_changed"),
            at_icount: Some(Icount { retired: 8 }),
            at_virtual_time: VirtualTime { ticks: 8 },
            node: Some(node_id()),
            detail: String::from("observed forbidden marker"),
            reproduction_artifact: finding.artifact.id(),
        },
    ));
    FailureTriageReplayEvidence::new(
        finding.clone(),
        failure,
        recorded_entries(decisions),
        hash("portable-coverage"),
        vec![frame.to_vec()],
    )
    .map_err(Into::into)
}

fn recorded_entries(decisions: &[Decision]) -> Vec<SchedulerEventLogEntry> {
    let mut entries = decisions
        .iter()
        .enumerate()
        .map(|(index, decision)| {
            condition_payload_entry_for_test(
                index as u64,
                VirtualTime {
                    ticks: index as u64 + 1,
                },
                SchedulerEventLogPayload::Decision(decision.clone()),
            )
        })
        .collect::<Vec<_>>();
    entries.push(condition_observation_entry_for_test(
        decisions.len() as u64,
        &ObservableEvent::coverage_marker(
            Icount { retired: 7 },
            node_id(),
            MarkerId::from_name("portable-hot-path"),
        ),
    ));
    entries.push(condition_observation_entry_for_test(
        decisions.len() as u64 + 1,
        &ObservableEvent::assertion_state_changed(
            VirtualTime { ticks: 8 },
            AssertionId::from_name("no-forbidden-marker"),
            AssertionPhase::Violated,
        ),
    ));
    entries
}

fn finding_artifact(
    scenario: &ScenarioDefForm,
    schedule: Schedule,
    fingerprint: ContentHash,
) -> Result<FindingReproductionArtifact, crucible::EngineError> {
    let configuration = Configuration {
        def: scenario.scenario_def(),
        schedule,
    };
    FindingReproductionArtifact::capture(
        FindingDiscoveryPath::StateSpaceSearch,
        fingerprint,
        scenario,
        &configuration,
    )
}

fn scenario_form() -> Result<ScenarioDefForm, crucible::EngineError> {
    let world = World::from_nodes(vec![WorldNode {
        id: node_id(),
        arch: NodeTemplate::DEFAULT_ARCH,
        memory_mib: NodeTemplate::DEFAULT_MEMORY_MIB,
        cmdline: String::from("crucible-campaign-replay"),
        ready_point: ReadyPoint::FixedIcount {
            icount: Icount { retired: 1 },
        },
        white_box: WhiteBoxPolicy::Enabled,
        smp_vcpus: NodeTemplate::DEFAULT_SMP_VCPUS,
        icount_shift: NodeTemplate::DEFAULT_ICOUNT_SHIFT,
        kernel: None,
        root_image: None,
        initrd: None,
    }])?;
    ScenarioDefForm::from_components(
        &world,
        &Plan::empty(),
        &Properties::empty(),
        Seed::default(),
    )
}

fn override_decision(point: &str, choice: &str) -> Decision {
    Decision::Override(OverrideDecision {
        point: SchedulingPoint {
            key: point.to_owned(),
        },
        choice: ChoiceTag {
            name: choice.to_owned(),
        },
    })
}

fn campaign_signature(
    fingerprint: CampaignHash,
    configuration: ConfigurationArtifactId,
) -> Result<FindingSignature, crucible_campaign::CampaignCodecError> {
    FindingSignature::new(
        FindingKind::PropertyViolation,
        fingerprint,
        Some(String::from("no-forbidden-marker")),
        String::from("assertion-violation"),
        Some(FindingTarget::Configuration(configuration)),
        BTreeSet::new(),
    )
}

fn node_id() -> NodeId {
    NodeId {
        name: String::from("replay-node"),
    }
}

trait FromContentId: Sized {
    fn parse_typed(id: ContentId) -> Result<Self, crucible_campaign::CampaignCodecError>;
}

macro_rules! from_content_id {
    ($($type:ty => $tag:literal),+ $(,)?) => {
        $(
            impl FromContentId for $type {
                fn parse_typed(id: ContentId) -> Result<Self, crucible_campaign::CampaignCodecError> {
                    Self::parse(&format!("{}@{}", $tag, id.encode()))
                }
            }
        )+
    };
}

from_content_id!(
    ScenarioArtifactId => "crucible.campaign.scenario-artifact",
    ConfigurationArtifactId => "crucible.campaign.configuration-artifact",
    ObservationId => "crucible.campaign.observation",
);

fn content_id<T: FromContentId>(
    kind: ObjectKind,
    schema_version: u32,
    bytes: &[u8],
) -> Result<T, crucible_campaign::CampaignCodecError> {
    T::parse_typed(ContentId::for_bytes(kind, schema_version, bytes))
}

fn write_export(directory: &Path, export: &ReplayExport) -> io::Result<()> {
    write(directory, BUNDLE_FILE, &export.bundle.canonical_bytes())?;
    write(
        directory,
        ORIGINAL_REPRODUCTION_FILE,
        &export.original_reproduction.canonical_bytes(),
    )?;
    write(
        directory,
        SELECTED_REPRODUCTION_FILE,
        &export.selected_reproduction.canonical_bytes(),
    )?;
    write(
        directory,
        MINIMIZATION_ORIGINAL_FILE,
        &export.minimization_original.canonical_bytes(),
    )?;
    write(
        directory,
        MINIMIZATION_SELECTED_FILE,
        &export.minimization_selected.canonical_bytes(),
    )?;
    write(
        directory,
        VERIFICATION_ORIGINAL_FILE,
        &export.verification_original.canonical_bytes(),
    )?;
    write(
        directory,
        VERIFICATION_SELECTED_FILE,
        &export.verification_selected.canonical_bytes(),
    )?;
    write_native_key(directory, &export.native_key)
}

fn invalidate_export(
    directory: &Path,
    export: &ReplayExport,
    mutation: InvalidExport,
) -> Result<(), Box<dyn Error>> {
    match mutation {
        InvalidExport::MissingEvidence => {
            fs::remove_file(directory.join(VERIFICATION_SELECTED_FILE))?;
        }
        InvalidExport::CorruptEvidence => {
            let mut bytes = read(directory, MINIMIZATION_ORIGINAL_FILE)?;
            let schema_byte = bytes
                .first_mut()
                .ok_or_else(|| invalid("triage evidence cannot be empty"))?;
            *schema_byte ^= 1;
            write(directory, MINIMIZATION_ORIGINAL_FILE, &bytes)?;
        }
        InvalidExport::WrongPayloadSchema => {
            let record = FindingTriageReplayEvidence::new(
                export.minimization_original.reproduction(),
                export.minimization_original.observed_signature().clone(),
                FAILURE_TRIAGE_REPLAY_EVIDENCE_SCHEMA_VERSION + 1,
                export.minimization_original.payload().to_vec(),
            )?;
            write(
                directory,
                MINIMIZATION_ORIGINAL_FILE,
                &record.canonical_bytes(),
            )?;
        }
        InvalidExport::WrongReproduction => {
            let record = FindingTriageReplayEvidence::new(
                export.selected_reproduction.id()?,
                export.minimization_original.observed_signature().clone(),
                FAILURE_TRIAGE_REPLAY_EVIDENCE_SCHEMA_VERSION,
                export.minimization_original.payload().to_vec(),
            )?;
            write(
                directory,
                MINIMIZATION_ORIGINAL_FILE,
                &record.canonical_bytes(),
            )?;
        }
        InvalidExport::WrongObservedSignature => {
            let record = FindingTriageReplayEvidence::new(
                export.original_reproduction.id()?,
                export.minimization_selected.observed_signature().clone(),
                FAILURE_TRIAGE_REPLAY_EVIDENCE_SCHEMA_VERSION,
                export.minimization_original.payload().to_vec(),
            )?;
            write(
                directory,
                MINIMIZATION_ORIGINAL_FILE,
                &record.canonical_bytes(),
            )?;
        }
        InvalidExport::WrongNativePayload => {
            let record = FindingTriageReplayEvidence::new(
                export.original_reproduction.id()?,
                export.minimization_original.observed_signature().clone(),
                FAILURE_TRIAGE_REPLAY_EVIDENCE_SCHEMA_VERSION,
                export.minimization_selected.payload().to_vec(),
            )?;
            write(
                directory,
                MINIMIZATION_ORIGINAL_FILE,
                &record.canonical_bytes(),
            )?;
        }
        InvalidExport::WrongSlotIdentity => {
            write(
                directory,
                MINIMIZATION_ORIGINAL_FILE,
                &export.alternate_original.canonical_bytes(),
            )?;
        }
        InvalidExport::WrongLedgerKey => {
            write_native_key(directory, &"0".repeat(64))?;
        }
    }
    Ok(())
}

fn read_native_key(directory: &Path) -> Result<String, io::Error> {
    let text = fs::read_to_string(directory.join(NATIVE_KEY_FILE))?;
    let Some(key) = text.strip_suffix('\n') else {
        return Err(invalid("native signature key record is not canonical"));
    };
    if key.len() != 64
        || !key
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(invalid("native signature key record is malformed"));
    }
    Ok(key.to_owned())
}

fn write_native_key(directory: &Path, key: &str) -> io::Result<()> {
    write(directory, NATIVE_KEY_FILE, format!("{key}\n").as_bytes())
}

fn read(directory: &Path, name: &str) -> io::Result<Vec<u8>> {
    fs::read(directory.join(name)).map_err(|source| {
        io::Error::new(
            source.kind(),
            format!("cannot read required export {name}: {source}"),
        )
    })
}

fn write(directory: &Path, name: &str, bytes: &[u8]) -> io::Result<()> {
    fs::write(directory.join(name), bytes)
}

fn hash(label: &str) -> ContentHash {
    ContentHash::from_canonical_material("gate.campaign-replay", label)
}

fn invalid(reason: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, reason)
}
