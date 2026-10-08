//! Real exact-restored guest progress after S3 outage and credential recovery.

use super::super::super::live_s3_product::{GaragePauseGuard, write_credentials, write_store};
use super::*;
use crucible_cas::content_store::{S3BlobBackend, S3BlobBackendConfig, StoreS3EndpointId};
use crucible_daemon::campaign_store_composition::{AwsSdkS3Client, AwsSdkS3ClientConfig};
use crucible_qemu::QemuLaunchArtifactIdentity;

#[test]
#[ignore = "requires packaged QEMU, exclusive Garage, cgroup-v2 and project quota inside the VM check"]
fn public_exact_paused_guest_recovers_from_s3_outage_and_expired_credentials()
-> Result<(), Box<dyn Error>> {
    let fixture = FlightFixture::new()?;
    let credentials = fixture._temporary.path().join("s3-credentials.toml");
    let access_key = std::env::var("AWS_ACCESS_KEY_ID")?;
    let secret_key = std::env::var("AWS_SECRET_ACCESS_KEY")?;
    write_credentials(&credentials, &access_key, &secret_key, None)?;
    write_store(
        &fixture,
        &std::env::var("CRUCIBLE_S3_TEST_ENDPOINT")?,
        &std::env::var("CRUCIBLE_S3_TEST_BUCKET")?,
        &std::env::var("CRUCIBLE_S3_TEST_PREFIX")?,
        &credentials,
    )?;

    // Compile actual immutable guest artifacts, then bind the lineage to the
    // selected packaged QEMU/plugin before production genesis capture.
    let (compiled, _) = compile_guest_choice_campaign(&fixture)?;
    let packaged = QemuLaunchArtifactIdentity::authenticate(
        required_path("CRUCIBLE_FLIGHT_QEMU")?,
        required_path("CRUCIBLE_FLIGHT_PLUGIN")?,
    )?;
    create_guest_choice_campaign(&fixture, &compiled, packaged.qemu_build_id())?;
    let authority = write_component_authority(&fixture)?;
    let immutable_inputs = guest_choice_immutable_inputs(&authority)?;
    let mut service = start_packaged_service(&fixture, &authority)?;
    let checkpoints = checkpoint_inspection_store()?;
    grant_and_start_guest_choice_campaign(&fixture)?;

    let genesis = json_string(&compiled, "genesis_artifact")?;
    let (discovery, explanation) = wait_for_initial_discovery(&fixture, &mut service, &genesis)?;
    let parent = json_string(&explanation["observation"], "child_artifact")?;
    let configuration = json_string(&explanation["observation"], "child")?;
    let recovery = wait_for_choice(&fixture, "network.recovery-policy", &parent, &configuration)?;
    let mut known = attempt_states(&fixture)?
        .into_keys()
        .collect::<BTreeSet<_>>();
    known.insert(discovery);

    let fast = submit_choice(
        &fixture,
        &recovery,
        &format!("discrete:{FAST_ALTERNATIVE}"),
        "next-choice",
        0x91,
    )?;
    let fast_request = accepted_branch_request(&fast)?;
    let fast_attempt =
        wait_for_new_completed_attempt(&fixture, &mut service, &known, &fast_request)?;
    known.insert(fast_attempt);
    let fast_explanation = wait_for_attempt_observation(&fixture, fast_attempt)?;
    let fast_parent = json_string(&fast_explanation["observation"], "child_artifact")?;
    let fast_configuration = json_string(&fast_explanation["observation"], "child")?;
    let retry = wait_for_choice(
        &fixture,
        "network.retry-quanta",
        &fast_parent,
        &fast_configuration,
    )?;
    let terminal = submit_choice(&fixture, &retry, "u64:7", "terminal", 0x92)?;
    let terminal_request = accepted_branch_request(&terminal)?;
    let active = wait_for_new_running_attempt(&fixture, &mut service, &known, &terminal_request)?;
    attest_fingerprint_enabled_qemu_descendants(&service, "storage-recovery-source")?;

    let mut command_sequence = 0x93_u64;
    let checkpoint = capture_checkpoint_after_progress_with_store(
        &fixture,
        &service,
        active,
        &mut command_sequence,
        None,
        &checkpoints,
    )?;
    let paused = campaign_status(&fixture)?;
    assert_eq!(paused["state"], "paused");
    let paused_snapshot = json_string(&paused, "snapshot")?;
    let mut retained_refs = Vec::new();
    for name in DERIVED_CAMPAIGNS {
        run_json(
            connected_campaign(&fixture).args([
                "derive",
                CAMPAIGN,
                "--snapshot",
                &paused_snapshot,
                name,
            ]),
            "derive exact-paused storage recovery campaign",
        )?;
        retained_refs.push((
            name,
            json_string(&campaign_status_named(&fixture, name)?, "snapshot")?,
        ));
    }
    service.stop()?;
    require_no_guest("storage-recovery-paused")?;
    let placements = json_u64(&fixture.verify_store()?, "placements")?;
    assert!(placements > 0);

    // Faults occur after durable pause and process retirement. A failed restart
    // must not replace the checkpoint, publish a new ref or start any guest.
    let mut outage = GaragePauseGuard::pause()?;
    require_failed_packaged_restart(&fixture, &authority, "backend-unavailable", "unavailable")?;
    outage.resume()?;
    assert_eq!(
        json_u64(&fixture.verify_store()?, "placements")?,
        placements
    );

    write_credentials(&credentials, &access_key, &secret_key, Some(1))?;
    require_failed_packaged_restart(&fixture, &authority, "credential-expired", "expired")?;
    write_credentials(&credentials, &access_key, &secret_key, None)?;
    run_json(
        command(&["--format", "jsonl", "store", "credentials", "refresh"]).arg(&fixture.store),
        "refresh exact-paused S3 credentials",
    )?;
    assert_eq!(
        json_u64(&fixture.verify_store()?, "placements")?,
        placements
    );
    attest_guest_choice_immutable_inputs(
        "storage-recovery-restored",
        &immutable_inputs,
        &authority,
    )?;

    let mut restored = start_packaged_service(&fixture, &authority)?;
    assert_eq!(campaign_status(&fixture)?["snapshot"], paused_snapshot);
    assert_eq!(campaign_status(&fixture)?["state"], "paused");
    for (name, snapshot) in &retained_refs {
        assert_eq!(
            campaign_status_named(&fixture, name)?["snapshot"],
            snapshot.as_str()
        );
    }
    assert_eq!(
        wait_for_promoted_checkpoint_with_store(&fixture, active, &checkpoints)?,
        checkpoint
    );
    resume_campaign(&fixture, &next_command_identity(&mut command_sequence)?)?;
    let (origin, execution) = wait_for_resumed_attempt(&fixture, active, checkpoint)?;
    assert_eq!(origin, checkpoint);
    attest_fingerprint_enabled_qemu_descendants(&restored, "storage-recovery-exact-resume")?;
    wait_for_resumed_guest_progress(&restored, active, execution)?;
    let advanced = capture_checkpoint_after_progress_with_store(
        &fixture,
        &restored,
        active,
        &mut command_sequence,
        Some(checkpoint),
        &checkpoints,
    )?;
    assert_ne!(advanced, checkpoint);
    let resumed = wait_for_attempt_explanation(&fixture, active)?;
    assert_eq!(resumed["selection"]["value"], "u64:7");
    assert_eq!(resumed["proposal"]["request"], terminal_request);
    for (name, snapshot) in &retained_refs {
        assert_eq!(
            campaign_status_named(&fixture, name)?["snapshot"],
            snapshot.as_str()
        );
    }
    restored.stop()?;
    require_no_guest("storage-recovery-finished")?;

    println!("storage_recovery_original_checkpoint={checkpoint}");
    println!("storage_recovery_advanced_checkpoint={advanced}");
    println!("storage_recovery_real_exact_pause=true");
    println!("storage_recovery_outage_refused_before_guest=true");
    println!("storage_recovery_expired_credentials_refused_before_guest=true");
    println!("storage_recovery_exact_origin_preserved=true");
    println!("storage_recovery_scheduler_observed_guest_progress=true");
    println!("storage_recovery_selected_outcome_preserved=true");
    println!("storage_recovery_derived_refs_preserved=2");
    println!("storage_recovery_final_guest_cleanup=true");
    Ok(())
}

fn require_failed_packaged_restart(
    fixture: &FlightFixture,
    authority: &Path,
    stage: &str,
    expected_diagnostic: &str,
) -> Result<(), Box<dyn Error>> {
    match start_packaged_service(fixture, authority) {
        Ok(mut unexpected) => {
            unexpected.stop()?;
            Err(format!("{stage} unexpectedly admitted a packaged executor").into())
        }
        Err(error) => {
            if !error
                .to_string()
                .to_ascii_lowercase()
                .contains(expected_diagnostic)
            {
                return Err(format!("{stage} failed without the expected {expected_diagnostic} storage diagnostic: {error}").into());
            }
            println!("storage_recovery_rejected stage={stage} diagnostic={error}");
            require_no_guest(stage)
        }
    }
}

fn require_no_guest(stage: &str) -> Result<(), Box<dyn Error>> {
    maintenance_transfer::assert_no_nested_qemu_processes(stage)?;
    require_empty_guest_choice_run_root(stage)
}

fn checkpoint_inspection_store() -> Result<ExactCheckpointStore, Box<dyn Error>> {
    // This adapter only reads canonical closure bytes for the oracle. Actual
    // startup/restore uses the CLI's strict credential-file and graph loader;
    // the inspector is never used during either fault or to start a guest.
    let endpoint = StoreS3EndpointId::new("live-product")?;
    let sdk = aws_sdk_s3::config::Builder::new()
        .behavior_version_latest()
        .region(aws_sdk_s3::config::Region::new("garage"))
        .credentials_provider(aws_credential_types::Credentials::new(
            std::env::var("AWS_ACCESS_KEY_ID")?,
            std::env::var("AWS_SECRET_ACCESS_KEY")?,
            None,
            None,
            "packaged-storage-inspection",
        ))
        .endpoint_url(std::env::var("CRUCIBLE_S3_TEST_ENDPOINT")?)
        .force_path_style(true)
        .build();
    let client = Arc::new(AwsSdkS3Client::start(
        endpoint.clone(),
        aws_sdk_s3::Client::from_conf(sdk),
        AwsSdkS3ClientConfig::new(8, 2, 128 * 1024 * 1024, Duration::from_secs(1))?,
    )?);
    let backend = S3BlobBackend::new(
        S3BlobBackendConfig::new(
            "storage-recovery-inspection",
            endpoint,
            std::env::var("CRUCIBLE_S3_TEST_BUCKET")?,
            format!(
                "{}/product-{}",
                std::env::var("CRUCIBLE_S3_TEST_PREFIX")?,
                std::process::id()
            ),
            MAXIMUM_LOGICAL_OBJECT_BYTES,
            5 * 1024 * 1024,
        ),
        client,
    )?;
    Ok(ExactCheckpointStore::new(
        Arc::new(backend),
        1024 * 1024 * 1024,
    )?)
}
