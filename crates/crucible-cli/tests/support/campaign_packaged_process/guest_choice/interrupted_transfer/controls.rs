//! Actual public-process controls for interrupted archive retention and retry.

use super::*;

#[test]
fn public_interrupted_transfer_gc_retains_copy_then_retries_idempotently()
-> Result<(), Box<dyn Error>> {
    let source = FlightFixture::new()?;
    let destination = FlightFixture::new()?;
    let snapshot = create_host_source(&source)?;
    let plan = source_plan(&source, &snapshot)?;
    let window = InterruptedCopy::refuse(&source, &destination, &snapshot, &plan)?;

    let (_, complete) = window.repair_gc_and_retry(&source, &destination, &snapshot)?;
    assert!(json_u64(&complete, "existing_objects")? > 0);
    assert_eq!(complete["authenticated"], true);
    Ok(())
}

#[test]
fn public_unrepaired_manifest_refuses_again_without_changing_journals_or_refs()
-> Result<(), Box<dyn Error>> {
    let source = FlightFixture::new()?;
    let destination = FlightFixture::new()?;
    let snapshot = create_host_source(&source)?;
    let plan = source_plan(&source, &snapshot)?;
    let window = InterruptedCopy::refuse(&source, &destination, &snapshot, &plan)?;
    let damaged_bytes = fs::read(&window.manifest_path)?;

    require_transfer_corruption(&source, &destination, &snapshot, window.manifest)?;

    assert_eq!(fs::read(&window.manifest_path)?, damaged_bytes);
    assert_eq!(journal_inventory(&source)?, window.source_journal);
    assert_eq!(journal_inventory(&destination)?, window.destination_journal);
    assert_eq!(retained_source_refs(&source)?, window.source_refs);
    require_destination_refs_absent(&destination)?;
    let preceding = window
        .objects
        .iter()
        .filter(|(id, _)| **id != window.manifest)
        .map(|(id, length)| (*id, *length))
        .collect();
    authenticate_ids(&directory_backend(&destination), &preceding)?;
    Ok(())
}

#[test]
fn public_transfer_and_gc_refuse_owned_source_before_creating_transfer_records()
-> Result<(), Box<dyn Error>> {
    let source = FlightFixture::new()?;
    let destination = FlightFixture::new()?;
    let snapshot = create_host_source(&source)?;
    let mut owner = source.start_service(None)?;
    storage_recovery::require_live_owner_gc_refusal(&source)?;

    let refused = output_with_timeout(
        maintenance_transfer::executable_archive_command(&source, &destination, &snapshot),
        Duration::from_secs(20),
    )?;
    assert!(!refused.status.success());
    assert!(refused.stdout.is_empty());
    let diagnostic = String::from_utf8_lossy(&refused.stderr);
    assert!(
        diagnostic.contains("campaign owner acquisition failed"),
        "owned source failed without original owner refusal: {diagnostic}"
    );
    owner.stop()?;

    require_empty_journal(&source)?;
    require_destination_refs_absent(&destination)?;
    assert!(!destination.state.join("campaign-transfers").exists());
    Ok(())
}

/// Creates only host metadata; none of these controls claims guest execution.
fn create_host_source(source: &FlightFixture) -> Result<String, Box<dyn Error>> {
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
        "generate interrupted-transfer host source",
    )?;
    let manifest = json_path(&generated, "manifest")?;
    let mut service = source.start_service(Some(&manifest))?;
    run_json(
        connected_campaign(source)
            .args(["create", CAMPAIGN, "--lineage"])
            .arg(json_path(&generated, "lineage")?)
            .arg("--policy")
            .arg(json_path(&generated, "policy")?),
        "create interrupted-transfer host campaign",
    )?;
    let snapshot = json_string(&campaign_status(source)?, "snapshot")?;
    derive_source_refs(source, &snapshot)?;
    service.stop()?;
    Ok(snapshot)
}
