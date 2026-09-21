//! Offline campaign archive transfer process flight.

use super::*;

#[test]
fn public_offline_archive_transfer_reports_and_authenticates_sensitive_closure()
-> Result<(), Box<dyn Error>> {
    let source = FlightFixture::new()?;
    let destination = FlightFixture::new()?;
    let trace_backend = DirectoryBlobBackend::new("archive-source-trace", &source.objects);

    run_public_offline_archive_transfer(&source, &destination, &trace_backend)
}

#[test]
fn public_archive_transfer_is_backend_neutral_across_compressed_stores()
-> Result<(), Box<dyn Error>> {
    let source = compressed_archive_fixture()?;
    let destination = compressed_archive_fixture()?;
    let trace_backend = CompressedDirectoryBlobBackend::new(
        "compressed-archive-source",
        &source.objects,
        MAXIMUM_LOGICAL_OBJECT_BYTES,
    )?;

    run_public_offline_archive_transfer(&source, &destination, &trace_backend)
}

fn compressed_archive_fixture() -> Result<FlightFixture, Box<dyn Error>> {
    let fixture = FlightFixture::new()?;
    let refs = fixture._temporary.path().join("refs");
    fs::write(
        &fixture.store,
        format!(
            r#"schema = "crucible.campaign-repository-store"
version = 2
root = "compressed"
admitted_kinds = ["campaign-fact", "campaign-snapshot", "merkle-node", "scenario", "configuration", "policy", "exact-manifest", "ram-extent", "disk-extent", "device-state", "observation", "finding", "projection", "trace"]
ref_directory = {refs:?}

[[nodes]]
id = "compressed"
[nodes.spec]
kind = "compressed-directory"
root = {objects:?}
maximum_logical_object_bytes = {MAXIMUM_LOGICAL_OBJECT_BYTES}
"#,
            objects = fixture.objects,
        ),
    )?;
    fs::set_permissions(&fixture.store, fs::Permissions::from_mode(0o600))?;

    Ok(fixture)
}

fn run_public_offline_archive_transfer(
    source: &FlightFixture,
    destination: &FlightFixture,
    trace_backend: &dyn ImmutableBlobBackend,
) -> Result<(), Box<dyn Error>> {
    let generated = run_json(
        command(&[
            "--format",
            "jsonl",
            "campaign",
            "fixture",
            "worked-network",
            "--output",
        ])
        .arg(&source.fixture),
        "generate archive source fixture",
    )?;
    let manifest = json_path(&generated, "manifest")?;
    let lineage = json_path(&generated, "lineage")?;
    let policy = json_path(&generated, "policy")?;
    let mut service = source.start_service(Some(&manifest))?;
    run_json(
        connected_campaign(source)
            .args(["create", CAMPAIGN, "--lineage"])
            .arg(&lineage)
            .arg("--policy")
            .arg(&policy),
        "create archive source campaign",
    )?;
    let snapshot = json_string(&campaign_status(source)?, "snapshot")?;
    service.stop()?;

    let trace_bytes = b"sensitive offline archive trace";
    let trace = ContentId::for_bytes(ObjectKind::Trace, 1, trace_bytes);
    trace_backend.put_if_absent(trace, &BlobHandle::from_bytes(trace_bytes.to_vec()))?;
    let trace = trace.encode();

    // A symlink alias bypasses lexical source/destination comparison. The
    // second owner acquisition must still fail immediately on the same lock.
    let state_alias = source._temporary.path().join("state-alias");
    symlink(&source.state, &state_alias)?;
    let mut aliased = command(&[
        "--format",
        "jsonl",
        "campaign",
        "archive",
        "transfer",
        "--source-state",
    ]);
    aliased
        .arg(&source.state)
        .arg("--source-policy")
        .arg(&source.peer_policy)
        .arg("--source-store")
        .arg(&source.store)
        .args(["--source-campaign", CAMPAIGN, "--snapshot", &snapshot])
        .args(["--mode", "metadata"])
        .arg("--destination-state")
        .arg(&state_alias)
        .arg("--destination-policy")
        .arg(&source.peer_policy)
        .arg("--destination-store")
        .arg(&source.store)
        .args(["--archive", "aliased-owner"]);
    let aliased = output_with_timeout(aliased, Duration::from_secs(5))?;
    assert!(!aliased.status.success());
    let aliased_error = String::from_utf8_lossy(&aliased.stderr);
    assert!(
        aliased_error.contains("repository is already in use")
            || aliased_error.contains("state directory is invalid"),
        "unexpected aliased-owner failure: {aliased_error}",
    );

    let mut transfer = command(&[
        "--format",
        "jsonl",
        "campaign",
        "archive",
        "transfer",
        "--source-state",
    ]);
    let output = transfer
        .arg(&source.state)
        .arg("--source-policy")
        .arg(&source.peer_policy)
        .arg("--source-store")
        .arg(&source.store)
        .args(["--source-campaign", CAMPAIGN, "--snapshot", &snapshot])
        .args(["--mode", "mirror", "--retain", &trace])
        .arg("--destination-state")
        .arg(&destination.state)
        .arg("--destination-policy")
        .arg(&destination.peer_policy)
        .arg("--destination-store")
        .arg(&destination.store)
        .args(["--archive", "offline-copy"])
        .output()?;
    require_success(&output, "transfer offline archive")?;
    let preflight: Value = serde_json::from_slice(&output.stderr)?;
    let completion: Value = serde_json::from_slice(&output.stdout)?;
    assert_eq!(preflight["schema"], "crucible.cli.campaign-archive-plan.v1");
    assert_eq!(preflight["phase"], "pre-transfer");
    assert!(
        preflight["sensitive_classes"]
            .as_array()
            .is_some_and(|classes| classes.iter().any(|class| class == "trace"))
    );
    let trace_class = preflight["classes"]
        .as_array()
        .and_then(|classes| classes.iter().find(|class| class["class"] == "trace"))
        .ok_or("pre-transfer report omitted trace class")?;
    assert_eq!(trace_class["logical_bytes"], trace_bytes.len());
    assert!(trace_class["physical_bytes"].is_null());
    assert_eq!(
        completion["schema"],
        "crucible.cli.campaign-archive-transfer.v1"
    );
    assert_eq!(completion["phase"], "complete");
    assert_eq!(completion["authenticated"], true);

    let inspected = run_json(
        command(&[
            "--format", "jsonl", "campaign", "archive", "inspect", "--state",
        ])
        .arg(&destination.state)
        .arg("--policy")
        .arg(&destination.peer_policy)
        .arg("--store")
        .arg(&destination.store)
        .args(["--archive", "offline-copy"]),
        "inspect offline archive",
    )?;
    assert_eq!(
        inspected["schema"],
        "crucible.cli.campaign-archive-inspection.v1"
    );
    assert_eq!(inspected["manifest"], completion["manifest"]);
    assert_eq!(inspected["authenticated"], true);
    assert!(
        inspected["sensitive_classes"]
            .as_array()
            .is_some_and(|classes| classes.iter().any(|class| class == "trace"))
    );

    Ok(())
}
