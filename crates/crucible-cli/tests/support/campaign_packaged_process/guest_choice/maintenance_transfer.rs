//! Packaged exact-pause restart and offline executable maintenance transfer.

use super::*;
use crucible_daemon::{
    DirectoryExactPinMaterializationStore, EXACT_PIN_MATERIALIZATION_DIRECTORY,
    ExactPinRetentionAdmin,
};
use crucible_qemu::QemuLaunchArtifactIdentity;

pub(super) const ARCHIVE_NAME: &str = "packaged-maintenance";
const INCOMPATIBLE_BUILD_ID: &str =
    "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

#[test]
#[ignore = "requires dedicated cgroup-v2 and ext4 project-quota roots inside the VM check"]
fn public_active_pause_restart_and_executable_transfer_rejects_incompatible_provenance()
-> Result<(), Box<dyn Error>> {
    run_transfer_flight(ArchiveTransferMode::Uninterrupted)
}

/// Selects the retained archive-maintenance window in the shared guest flight.
#[derive(Clone, Copy, PartialEq, Eq)]
pub(super) enum ArchiveTransferMode {
    /// Retains the original uninterrupted transfer and incompatible recipient.
    Uninterrupted,
    /// Exercises incomplete journals and public GC before the same exact import.
    Interrupted,
}

/// Runs the original source and recipient with one selected archive operation.
///
/// # Errors
///
/// Returns the original guest, public storage, provenance or cleanup failure.
pub(super) fn run_transfer_flight(mode: ArchiveTransferMode) -> Result<(), Box<dyn Error>> {
    let source = FlightFixture::new()?;
    let destination = FlightFixture::new()?;
    let (compiled, _scenario) = compile_guest_choice_campaign(&source)?;
    let packaged = QemuLaunchArtifactIdentity::authenticate(
        required_path("CRUCIBLE_FLIGHT_QEMU")?,
        required_path("CRUCIBLE_FLIGHT_PLUGIN")?,
    )?;
    let source_build = packaged.qemu_build_id().to_owned();
    create_guest_choice_campaign(&source, &compiled, &source_build)?;
    let authority = write_component_authority(&source)?;
    let mut service = start_packaged_service(&source, &authority)?;
    grant_and_start_guest_choice_campaign(&source)?;

    let genesis = json_string(&compiled, "genesis_artifact")?;
    let (discovery, explanation) = wait_for_initial_discovery(&source, &mut service, &genesis)?;
    diagnostics::report_maintenance_stage("transfer-initial-discovery-completed");
    let recovery_parent = json_string(&explanation["observation"], "child_artifact")?;
    let recovery_configuration = json_string(&explanation["observation"], "child")?;
    let recovery = wait_for_choice(
        &source,
        "network.recovery-policy",
        &recovery_parent,
        &recovery_configuration,
    )?;
    let mut known_attempts = attempt_states(&source)?
        .into_keys()
        .collect::<BTreeSet<_>>();
    known_attempts.insert(discovery);

    let fast = submit_choice(
        &source,
        &recovery,
        &format!("discrete:{FAST_ALTERNATIVE}"),
        "next-choice",
        0x81,
    )?;
    let fast_request = accepted_branch_request(&fast)?;
    // Reaching this branch requires the same cold Linux replay as the
    // ordinary guest-choice flight, rather than an already-running guest.
    let fast_attempt = wait_for_new_completed_attempt_with_timeout(
        &source,
        &mut service,
        &known_attempts,
        &fast_request,
        GUEST_CHOICE_ATTEMPT_WAIT,
    )?;
    known_attempts.insert(fast_attempt);
    diagnostics::report_maintenance_stage("transfer-fast-recovery-completed");
    let fast_explanation = wait_for_attempt_observation(&source, fast_attempt)?;
    let fast_parent = json_string(&fast_explanation["observation"], "child_artifact")?;
    let fast_configuration = json_string(&fast_explanation["observation"], "child")?;
    let retry = wait_for_choice(
        &source,
        "network.retry-quanta",
        &fast_parent,
        &fast_configuration,
    )?;
    let terminal = submit_choice(&source, &retry, "u64:7", "terminal", 0x82)?;
    let terminal_request = accepted_branch_request(&terminal)?;
    let active =
        wait_for_new_running_attempt(&source, &mut service, &known_attempts, &terminal_request)?;
    diagnostics::report_maintenance_stage("transfer-selected-attempt-running");
    let checkpoint =
        capture_checkpoint_after_progress(&source, &service, active, &mut 0x83_u64, None)?;
    let paused_snapshot = json_string(&campaign_status(&source)?, "snapshot")?;
    diagnostics::report_maintenance_stage("transfer-source-exact-checkpoint-captured");
    service.stop()?;

    assert_no_nested_qemu_processes("source-after-exact-pause")?;
    require_empty_guest_choice_run_root("source-after-exact-pause")?;
    diagnostics::report_maintenance_stage("transfer-source-owner-stopped");
    let mut restarted = start_packaged_service(&source, &authority)?;
    assert_eq!(campaign_status(&source)?["snapshot"], paused_snapshot);
    resume_campaign(&source, &"84".repeat(32))?;
    let (resumed, execution) = wait_for_resumed_attempt(&source, active, checkpoint)?;
    assert_eq!(resumed, checkpoint);
    wait_for_resumed_guest_progress(&restarted, active, execution)?;
    diagnostics::report_maintenance_stage("transfer-source-execution-guest-marker-observed");
    let advanced = capture_checkpoint_after_progress(
        &source,
        &restarted,
        active,
        &mut 0x85_u64,
        Some(checkpoint),
    )?;
    assert_ne!(advanced, checkpoint);
    diagnostics::report_maintenance_stage("transfer-source-distinct-checkpoint-authenticated");

    let before_pin = campaign_status(&source)?;
    run_json(
        connected_campaign(&source).args([
            "pin",
            CAMPAIGN,
            &fast_configuration,
            "--expected",
            &json_string(&before_pin, "snapshot")?,
            "--command",
            &"86".repeat(32),
            "--tier",
            "exact",
            "--reason",
            "offline maintenance transfer",
        ]),
        "pin executable configuration",
    )?;
    let archive_snapshot = json_string(&campaign_status(&source)?, "snapshot")?;
    if mode == ArchiveTransferMode::Interrupted {
        interrupted_transfer::derive_source_refs(&source, &archive_snapshot)?;
    }
    restarted.stop()?;
    assert_no_nested_qemu_processes("source-before-transfer")?;
    require_empty_guest_choice_run_root("source-before-transfer")?;

    let configuration = ConfigurationId::parse(&fast_configuration)?;
    let source_pin = selected_pin_checkpoint(&source, configuration)?;
    let (preflight, transfer) = match mode {
        ArchiveTransferMode::Uninterrupted => {
            transfer_executable_archive(&source, &destination, &archive_snapshot)?
        }
        ArchiveTransferMode::Interrupted => interrupted_transfer::transfer_after_interruption(
            &source,
            &destination,
            &archive_snapshot,
        )?,
    };
    assert_eq!(preflight["schema"], "crucible.cli.campaign-archive-plan.v1");
    assert_eq!(preflight["phase"], "pre-transfer");
    assert_eq!(preflight["policy"], "executable");
    assert!(
        preflight["sensitive_classes"]
            .as_array()
            .is_some_and(|classes| !classes.is_empty())
    );
    assert_eq!(transfer["authenticated"], true);
    diagnostics::report_maintenance_stage("transfer-public-copy-authenticated");
    assert_eq!(transfer["campaign"], CAMPAIGN);
    if mode == ArchiveTransferMode::Uninterrupted {
        assert!(
            transfer["copied_objects"]
                .as_u64()
                .is_some_and(|count| count > 0)
        );
    }
    let inspected = inspect_archive(&destination)?;
    assert_eq!(inspected["manifest"], transfer["manifest"]);
    assert_eq!(inspected["authenticated"], true);
    assert_eq!(
        inspected["sensitive_classes"],
        preflight["sensitive_classes"]
    );
    assert_eq!(
        selected_pin_checkpoint(&destination, configuration)?,
        source_pin
    );

    let recipient_authority = write_component_authority(&destination)?;
    let mut recipient = start_packaged_service(&destination, &recipient_authority)?;
    let imported = campaign_status(&destination)?;
    assert_eq!(imported["snapshot"], archive_snapshot);
    assert_eq!(imported["state"], "paused");
    resume_campaign(&destination, &"87".repeat(32))?;
    assert_eq!(campaign_status(&destination)?["state"], "running");
    let (recipient_origin, recipient_execution) =
        wait_for_resumed_attempt(&destination, active, advanced)?;
    assert_eq!(recipient_origin, advanced);
    diagnostics::report_maintenance_stage("transfer-recipient-origin-bound");
    attest_fingerprint_enabled_qemu_descendants(&recipient, "recipient-exact-resume")?;
    wait_for_resumed_guest_progress(&recipient, active, recipient_execution)?;
    diagnostics::report_maintenance_stage("transfer-recipient-execution-guest-marker-observed");
    let recipient_checkpoint = capture_checkpoint_after_progress(
        &destination,
        &recipient,
        active,
        &mut 0x88_u64,
        Some(advanced),
    )?;
    assert_ne!(recipient_checkpoint, advanced);
    diagnostics::report_maintenance_stage("transfer-recipient-distinct-checkpoint-authenticated");
    if mode == ArchiveTransferMode::Interrupted {
        let explanation = wait_for_attempt_explanation(&destination, active)?;
        assert_eq!(explanation["selection"]["value"], "u64:7");
        assert_eq!(explanation["proposal"]["request"], terminal_request);
    }
    recipient.stop()?;
    assert_no_nested_qemu_processes("recipient-after-resume")?;
    require_empty_guest_choice_run_root("recipient-after-resume")?;

    let (alternate_qemu, alternate_plugin) = incompatible_runtime_pair(&destination, &packaged)?;
    let alternate = QemuLaunchArtifactIdentity::authenticate(&alternate_qemu, &alternate_plugin)?;
    assert_ne!(alternate.qemu_build_id(), source_build);
    let incompatible_deployment = hot_fork_deployment(&destination)?;
    let rejected = start_packaged_service_with_artifacts(
        &destination,
        &recipient_authority,
        &incompatible_deployment,
        &alternate_qemu,
        &alternate_plugin,
        FlightDiagnostics::Disabled,
    )
    .err()
    .ok_or("incompatible packaged recipient unexpectedly started")?;
    let diagnostic = rejected.to_string();
    let expected_diagnostic = format!(
        "selected QEMU build `{}` differs from campaign lineage build `{source_build}`",
        alternate.qemu_build_id()
    );
    if !diagnostic.contains(&expected_diagnostic) {
        return Err(
            format!("incompatible recipient lacked provenance diagnostic: {diagnostic}").into(),
        );
    }
    assert_no_nested_qemu_processes("incompatible-recipient-rejection")?;
    require_empty_guest_choice_run_root("incompatible-recipient-rejection")?;
    diagnostics::report_maintenance_stage("transfer-final-owner-cleanup");
    assert_eq!(selected_pin_checkpoint(&source, configuration)?, source_pin);
    assert_eq!(
        selected_pin_checkpoint(&destination, configuration)?,
        source_pin
    );

    println!("source_active_world_exact_pause_restart=true");
    println!("source_exact_resume_progress=true");
    println!("source_nested_qemu_stopped=true");
    println!("recipient_executable_archive_authenticated=true");
    println!("recipient_exact_pin_import_authenticated=true");
    println!("recipient_campaign_resume=true");
    println!("recipient_imported_attempt_running=true");
    println!("recipient_imported_exact_origin_preserved=true");
    println!("recipient_scheduler_observed_guest_progress=true");
    println!("recipient_new_authenticated_checkpoint=true");
    println!("recipient_nested_qemu_stopped=true");
    println!("incompatible_provenance_rejected_before_guest=true");
    println!("source_checkpoint_preserved=true");
    Ok(())
}

pub(super) fn assert_no_nested_qemu_processes(stage: &str) -> Result<(), Box<dyn Error>> {
    let mut observed = Vec::new();
    let exited = wait_for_process_observation(Instant::now() + Duration::from_secs(5), || {
        observed.clear();
        for entry in fs::read_dir("/proc")?.filter_map(Result::ok) {
            let Some(pid) = entry
                .file_name()
                .to_str()
                .and_then(|name| name.parse::<u32>().ok())
            else {
                continue;
            };
            let Ok(arguments) = fs::read(entry.path().join("cmdline")) else {
                continue;
            };
            if arguments
                .split(|byte| *byte == 0)
                .next()
                .is_some_and(|executable| executable.ends_with(b"/qemu-system-x86_64"))
            {
                observed.push(pid);
            }
        }
        Ok(observed.is_empty().then_some(()))
    })?;
    if exited.is_none() {
        return Err(format!("{stage} retained nested QEMU processes {observed:?}").into());
    }
    Ok(())
}

fn selected_pin_checkpoint(
    fixture: &FlightFixture,
    configuration: ConfigurationId,
) -> Result<ExactCheckpointId, Box<dyn Error>> {
    let mut selections = DirectoryExactPinMaterializationStore::open(
        fixture.state.join(EXACT_PIN_MATERIALIZATION_DIRECTORY),
    )?;
    let campaign = CampaignName::new(CAMPAIGN)?;
    let mut fence = selections.acquire_exact_pin_retention_fence()?;
    let checkpoint = fence
        .selection(&campaign, configuration)?
        .ok_or("exact pin has no authenticated materialization")?
        .checkpoint();
    Ok(checkpoint)
}

/// Executes the original public executable archive command and decodes its records.
///
/// # Errors
///
/// Returns the original process or authenticated report decoding failure.
pub(super) fn transfer_executable_archive(
    source: &FlightFixture,
    destination: &FlightFixture,
    snapshot: &str,
) -> Result<(Value, Value), Box<dyn Error>> {
    let output = executable_archive_command(source, destination, snapshot).output()?;
    require_success(&output, "transfer executable campaign archive")?;
    Ok((
        serde_json::from_slice(&output.stderr)?,
        serde_json::from_slice(&output.stdout)?,
    ))
}

/// Builds the unchanged public archive arguments for an identical retry.
pub(super) fn executable_archive_command(
    source: &FlightFixture,
    destination: &FlightFixture,
    snapshot: &str,
) -> Command {
    let mut transfer = command(&[
        "--format",
        "jsonl",
        "campaign",
        "archive",
        "transfer",
        "--source-state",
    ]);
    transfer
        .arg(&source.state)
        .arg("--source-policy")
        .arg(&source.peer_policy)
        .arg("--source-store")
        .arg(&source.store)
        .args(["--source-campaign", CAMPAIGN, "--snapshot", snapshot])
        .args(["--mode", "executable"])
        .arg("--destination-state")
        .arg(&destination.state)
        .arg("--destination-policy")
        .arg(&destination.peer_policy)
        .arg("--destination-store")
        .arg(&destination.store)
        .args(["--archive", ARCHIVE_NAME, "--campaign", CAMPAIGN]);
    transfer
}

/// Authenticates the published archive through the original public CLI.
///
/// # Errors
///
/// Returns the original process or inspection report decoding failure.
pub(super) fn inspect_archive(fixture: &FlightFixture) -> Result<Value, Box<dyn Error>> {
    run_json(
        command(&[
            "--format", "jsonl", "campaign", "archive", "inspect", "--state",
        ])
        .arg(&fixture.state)
        .arg("--policy")
        .arg(&fixture.peer_policy)
        .arg("--store")
        .arg(&fixture.store)
        .args(["--archive", ARCHIVE_NAME]),
        "inspect imported executable archive",
    )
}

fn incompatible_runtime_pair(
    destination: &FlightFixture,
    packaged: &QemuLaunchArtifactIdentity,
) -> Result<(PathBuf, PathBuf), Box<dyn Error>> {
    let root = destination._temporary.path().join("incompatible-runtime");
    let qemu = root.join("bin/qemu-system-x86_64");
    let plugin = root.join("lib/libcrucible_qemu_plugin.so");
    let qemu_marker = root.join("share/aos/crucible/qemu-build-identity.env");
    let plugin_marker = root.join("nix-support/crucible-qemu-plugin-build-info");
    let packaged_qemu_root = packaged
        .qemu()
        .parent()
        .and_then(Path::parent)
        .ok_or("packaged QEMU path has no package root")?;
    let packaged_plugin_root = packaged
        .plugin()
        .parent()
        .and_then(Path::parent)
        .ok_or("packaged plugin path has no package root")?;

    for parent in [&qemu, &plugin, &qemu_marker, &plugin_marker] {
        fs::create_dir_all(parent.parent().ok_or("runtime artifact has no parent")?)?;
    }
    // Both alternate markers agree so startup reaches the imported-lineage
    // comparison before the negative fixture can start a guest.
    symlink(packaged.qemu(), &qemu)?;
    symlink(packaged.plugin(), &plugin)?;
    write_incompatible_marker(
        &packaged_qemu_root.join("share/aos/crucible/qemu-build-identity.env"),
        &qemu_marker,
    )?;
    write_incompatible_marker(
        &packaged_plugin_root.join("nix-support/crucible-qemu-plugin-build-info"),
        &plugin_marker,
    )?;
    Ok((qemu, plugin))
}

fn write_incompatible_marker(source: &Path, destination: &Path) -> Result<(), Box<dyn Error>> {
    let original = fs::read_to_string(source)?;
    let mut replaced = 0;
    let fields = original
        .lines()
        .map(|line| {
            if line.starts_with("qemu_build_id=") {
                replaced += 1;
                format!("qemu_build_id={INCOMPATIBLE_BUILD_ID}")
            } else {
                line.to_owned()
            }
        })
        .collect::<Vec<_>>();
    if replaced != 1 {
        return Err(format!(
            "runtime marker {} has {replaced} build IDs",
            source.display()
        )
        .into());
    }
    fs::write(destination, format!("{}\n", fields.join("\n")))?;
    Ok(())
}

fn hot_fork_deployment(destination: &FlightFixture) -> Result<PathBuf, Box<dyn Error>> {
    // Source admission binds installed QEMU provenance to the imported lineage
    // before QEMU starts, which is the restore rejection under test.
    let deployment = destination
        ._temporary
        .path()
        .join("incompatible-executor.toml");
    let authored = fs::read_to_string(required_path("CRUCIBLE_FLIGHT_DEPLOYMENT")?)?;
    fs::write(
        &deployment,
        format!(
            "{authored}\n[hot_fork]\nmaximum_templates = 2\nmaximum_template_bytes = 1073741824\nmaximum_expected_private_dirty_bytes = 536870912\nmaximum_processes = 8\nmaximum_virtual_cpus = 8\nmaximum_descriptors = 4096\nmaximum_overlays = 16\nmaximum_forks_per_window = 8\nfork_rate_window_ms = 1000\nshutdown_step_timeout_ms = 1000\nhost_io_timeout_ms = 30000\n"
        ),
    )?;
    fs::set_permissions(&deployment, fs::Permissions::from_mode(0o600))?;
    Ok(deployment)
}
