//! Bundle-only packaged-QEMU flight for a canonical alternate finding choice.

use std::io::Write;

use crucible_campaign::{
    AttemptId, CampaignArchiveManifestId, CampaignFact, CampaignPrincipalAuthorizer,
    CampaignRecordKind, CampaignRepository, CampaignServiceOperation, ChoiceDomain, ChoiceValue,
    FindingId, ObjectEnvelope, ObservationId, StopCondition, StopOutcome,
};
use crucible_cas::content_store::{DirectoryRefBackend, ImmutableBlobBackend};
use crucible_session::engine::Decision;

use super::*;

const SOURCE_NAME: &str = "imported-finding-source";
const BRANCH_NAME: &str = "imported-finding-branch";

pub(super) fn run_imported_canonical_branch(
    fixture: &FlightFixture,
    snapshot: &str,
    finding: &str,
) -> Result<(), Box<dyn Error>> {
    grant_export_reads(&fixture.peer_policy)?;
    let source_bundle = fixture._temporary.path().join("branch-source-bundle");
    let exported = run_json(
        command(&[
            "--format",
            "jsonl",
            "campaign",
            "finding-bundle",
            "export",
            CAMPAIGN,
        ])
        .args(["--snapshot", snapshot, "--finding", finding])
        .arg("--source-state")
        .arg(&fixture.state)
        .arg("--source-policy")
        .arg(&fixture.peer_policy)
        .arg("--source-store")
        .arg(&fixture.store)
        .arg("--output")
        .arg(&source_bundle),
        "export canonical branch source finding",
    )?;
    assert_eq!(exported["native_signature_verified"], true);

    let investigator = TempDir::new()?;
    fs::set_permissions(investigator.path(), fs::Permissions::from_mode(0o700))?;
    let bundle = investigator.path().join("finding-bundle");
    copy_bundle(&source_bundle, &bundle)?;
    let pristine = bundle_fingerprints(&bundle)?;
    let archive = archive_id(&bundle)?;
    let finding_id = FindingId::parse(finding)?;
    let repository = CampaignRepository::new(
        Arc::new(DirectoryBlobBackend::new(
            "branch-bundle-source",
            bundle.join("archive/objects"),
        )),
        Arc::new(DirectoryRefBackend::new(bundle.join("archive/refs"))),
    );
    let retained = repository.inspect_archived_exact_finding(archive, finding_id)?;
    let reproduction = repository.load_reproduction_artifact(retained.reproduction())?;
    let model = crucible_core::ReproductionArtifact::from_compact_binary(reproduction.payload())?;
    let original = model
        .schedule()
        .decisions()
        .iter()
        .find_map(|decision| match decision {
            Decision::Selection(selection) => Some(selection.selection()),
            _ => None,
        })
        .ok_or("finding reproduction contains no declared choice")??;
    let domain = repository.load_choice_domain(original.domain())?;
    let ChoiceDomain::Discrete(discrete) = domain else {
        return Err("finding first choice is not the recovery-policy domain".into());
    };
    let safe_id = discrete
        .alternatives()
        .iter()
        .find_map(|(id, alternative)| (alternative.label() == "safe").then_some(*id))
        .ok_or("recovery-policy domain has no safe alternative")?;
    assert_ne!(original.value(), &ChoiceValue::Discrete(safe_id));
    drop(repository);

    // The executor receives only this copy, its own host deployment, and the
    // immutable packaged runtime. The source service and campaign vanish here.
    fs::remove_dir_all(fixture._temporary.path())?;
    let output = investigator.path().join("executed-branch");
    let binary = std::env::var_os("CRUCIBLE_EXACT_BUNDLE_BINARY")
        .ok_or("packaged finding branch binary is not configured")?;
    let deployment = std::env::var_os("CRUCIBLE_FLIGHT_DEPLOYMENT")
        .ok_or("packaged finding branch deployment is not configured")?;
    let alternate = format!("discrete:{safe_id}");
    let branch = run_json(
        Command::new(binary)
            .current_dir(investigator.path())
            .env_remove("CRUCIBLE_QEMU")
            .env_remove("CRUCIBLE_PLUGIN")
            .env_remove("CRUCIBLE_KERNEL")
            .env_remove("CRUCIBLE_ROOT_IMAGE")
            .env_remove("CRUCIBLE_INITRD")
            .env_remove("CRUCIBLE_RUN_STATE_ROOT")
            .args(["--format", "jsonl", "--campaign-deployment"])
            .arg(deployment)
            .args(["campaign", "finding-bundle", "branch"])
            .arg(&bundle)
            .args(["--value", "safe", "--output"])
            .arg(&output),
        "execute canonical finding branch from copied bundle",
    )?;
    assert_eq!(
        branch["schema"],
        "crucible.cli.campaign-finding-bundle-branch.v1"
    );
    assert_eq!(branch["branch_classification"], "canonical");
    assert_eq!(branch["selected_value"], alternate);
    assert_eq!(branch["original_archive_unchanged"], true);
    assert_eq!(branch["source_snapshot"], snapshot);
    assert_eq!(branch["output"], output.display().to_string());
    assert_eq!(bundle_fingerprints(&bundle)?, pristine);

    let executed = CampaignRepository::new(
        Arc::new(DirectoryBlobBackend::new(
            "branch-executed",
            output.join("state/objects"),
        )),
        Arc::new(DirectoryRefBackend::new(output.join("state/refs"))),
    );
    assert_eq!(
        executed.head(SOURCE_NAME)?.snapshot_id().to_string(),
        snapshot
    );
    assert_eq!(
        executed.head(BRANCH_NAME)?.snapshot_id().to_string(),
        branch["branch_snapshot"]
    );
    assert_eq!(
        executed.inspect_archived_exact_finding(archive, finding_id)?,
        retained
    );
    let attempt = AttemptId::parse(&json_string(&branch, "attempt")?)?;
    let observation = ObservationId::parse(&json_string(&branch, "observation")?)?;
    let observed = executed.load_observation(observation)?;
    assert_eq!(observed.attempt(), attempt);
    assert_eq!(
        observed.stop(),
        &StopOutcome::Reached(StopCondition::NextChoice)
    );
    let inherited_claimable = executed.project_claimable_attempts(SOURCE_NAME, None, 10_000)?;
    let final_claimable = executed.project_claimable_attempts(BRANCH_NAME, None, 10_000)?;
    assert!(inherited_claimable.next().is_none());
    assert!(final_claimable.next().is_none());
    assert!(
        inherited_claimable
            .attempts()
            .iter()
            .all(|inherited| final_claimable.attempts().contains(inherited))
    );
    assert!(!final_claimable.attempts().contains(&attempt));
    assert_private_branch_transitions(&executed, &output, observation)?;
    assert!(output.join("branch-report.json").is_file());
    println!("finding_bundle_canonical_branch_executed=true");
    println!("finding_bundle_source_owner_absent=true");
    println!("finding_bundle_original_archive_unchanged=true");
    Ok(())
}

fn assert_private_branch_transitions(
    repository: &CampaignRepository,
    output: &Path,
    expected_observation: ObservationId,
) -> Result<(), Box<dyn Error>> {
    let objects =
        DirectoryBlobBackend::new("branch-transition-audit", output.join("state/objects"));
    let mut snapshot = repository.head(BRANCH_NAME)?.snapshot_id();
    let mut reached_derivation = false;
    let mut credited_observations = 0;
    for _ in 0..256 {
        let current = repository.snapshot_in_campaign(BRANCH_NAME, snapshot)?;
        let transition = current
            .transition()
            .ok_or("private branch has no transition")?;
        let blob = objects.read(transition.content_id(), None)?;
        let bytes = blob.read_all(1024 * 1024)?;
        let envelope = ObjectEnvelope::from_canonical_bytes(&bytes)?;
        assert_eq!(envelope.record_kind(), CampaignRecordKind::Fact);
        match CampaignFact::from_canonical_bytes(envelope.body())? {
            CampaignFact::CampaignDerived(_) => {
                reached_derivation = true;
                break;
            }
            CampaignFact::ObservationCredited(observation) => {
                assert_eq!(observation, expected_observation);
                credited_observations += 1;
            }
            CampaignFact::ObjectiveEvaluationPublished(_) => {
                return Err("private branch published inherited objective work".into());
            }
            _ => {}
        }
        snapshot = current
            .parent()
            .ok_or("private branch transition has no parent")?;
    }
    assert!(
        reached_derivation,
        "private branch derivation was not reached"
    );
    assert_eq!(credited_observations, 1);
    Ok(())
}

fn grant_export_reads(path: &Path) -> Result<(), Box<dyn Error>> {
    {
        let mut file = fs::OpenOptions::new().append(true).open(path)?;
        for operation in [
            "query-campaign-finding-occurrences",
            "get-campaign-finding-occurrence-object",
            "get-campaign-finding-triage-replay-segment",
        ] {
            writeln!(
                file,
                "\n[[grants]]\nprincipal = {PRINCIPAL:?}\noperation = {operation:?}\ncampaign = \"*\""
            )?;
        }
    }
    let policy = UnixPeerCampaignPolicy::from_toml_bytes(&fs::read(path)?)?;
    let principal = CampaignPrincipal::new(PRINCIPAL)?;
    let campaign = CampaignName::new(CAMPAIGN)?;
    let request = CampaignHash::derive("finding-branch-export-grants", b"ledger");
    for operation in [
        CampaignServiceOperation::QueryCampaignFindings,
        CampaignServiceOperation::QueryCampaignFindingOccurrences,
        CampaignServiceOperation::GetCampaignFindingObject,
        CampaignServiceOperation::GetCampaignFindingOccurrenceObject,
        CampaignServiceOperation::GetCampaignFindingTriageReplaySegment,
    ] {
        policy.authorize(&principal, operation, &campaign, request)?;
    }
    Ok(())
}

fn archive_id(bundle: &Path) -> Result<CampaignArchiveManifestId, Box<dyn Error>> {
    let manifest = fs::read_to_string(bundle.join("manifest"))?;
    let id = manifest
        .lines()
        .find_map(|line| line.strip_prefix("archive_manifest="))
        .ok_or("finding bundle has no archive manifest ID")?;
    Ok(CampaignArchiveManifestId::parse(id)?)
}

fn copy_bundle(source: &Path, destination: &Path) -> Result<(), Box<dyn Error>> {
    fs::create_dir(destination)?;
    fs::set_permissions(destination, fs::Permissions::from_mode(0o700))?;
    for entry in fs::read_dir(source)? {
        let entry = entry?;
        let target = destination.join(entry.file_name());
        let kind = entry.file_type()?;
        if kind.is_dir() {
            copy_bundle(&entry.path(), &target)?;
        } else if kind.is_file() {
            fs::copy(entry.path(), target)?;
        } else {
            return Err("finding bundle contains a nonregular entry".into());
        }
    }
    Ok(())
}

fn bundle_fingerprints(bundle: &Path) -> Result<BTreeMap<PathBuf, CampaignHash>, Box<dyn Error>> {
    let mut pending = vec![bundle.to_path_buf()];
    let mut hashes = BTreeMap::new();
    while let Some(directory) = pending.pop() {
        for entry in fs::read_dir(directory)? {
            let entry = entry?;
            if entry.file_type()?.is_dir() {
                pending.push(entry.path());
            } else {
                let bytes = fs::read(entry.path())?;
                hashes.insert(
                    entry.path().strip_prefix(bundle)?.to_path_buf(),
                    CampaignHash::derive(
                        "crucible.test.finding-bundle-byte-fingerprint.v1",
                        &bytes,
                    ),
                );
            }
        }
    }
    Ok(hashes)
}
