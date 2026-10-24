//! Checks source-fixed Clock oracles and the actual owning runtime entry.

use super::*;

type TestResult = Result<(), Box<dyn std::error::Error>>;

fn fixed_case() -> Result<ExpectedClockCase, NodeObservedError> {
    ExpectedClockCase::new(
        &Id::new("clock")?,
        &[],
        &Id::new("clock/fractional-ns")?,
        Position::new(1.into(), 0.into(), Phase::BoundaryControl),
        Position::new(1001.into(), 0.into(), Phase::BoundaryControl),
        false,
    )
}

#[test]
fn clock_oracle_retains_subnanosecond_cursor_and_complete_empty_inventory() -> TestResult {
    let expected = fixed_case()?;
    let native = &expected.objects[1];
    let mut bytes = b"crucible.host-clock.v1\0".to_vec();
    bytes.extend_from_slice(&1001_u64.to_le_bytes());
    assert_eq!(native.bytes, bytes);
    assert!(expected.outcome.retained_outputs.is_empty());
    let observation = expected
        .outcome
        .scheduling
        .as_ref()
        .ok_or("expected frontier")?;
    assert!(observation.publications.is_empty());
    assert!(observation.external_inputs.is_empty());
    assert!(observation.input_progress.is_none());
    assert_eq!(observation.reached.time_ps.get(), 1001);
    expected.authenticate_objects(&expected.objects)?;
    Ok(())
}

#[test]
fn clock_oracle_refuses_changed_missing_and_duplicated_original_bodies() -> TestResult {
    let expected = fixed_case()?;
    let copy = || {
        expected
            .objects
            .iter()
            .map(|row| InputPayload {
                reference: row.reference.clone(),
                bytes: row.bytes.clone(),
            })
            .collect::<Vec<_>>()
    };
    let mut changed = copy();
    changed[1].bytes[0] ^= 1;
    assert!(expected.authenticate_objects(&changed).is_err());

    let missing = &expected.objects[..2];
    assert!(expected.authenticate_objects(missing).is_err());

    let mut duplicate = copy();
    duplicate[2] = InputPayload {
        reference: expected.objects[1].reference.clone(),
        bytes: expected.objects[1].bytes.clone(),
    };
    assert!(expected.authenticate_objects(&duplicate).is_err());
    Ok(())
}

#[test]
fn same_instant_settlement_keeps_native_time_and_advances_only_superdense_cut() -> TestResult {
    let start = Position::new(1001.into(), 0.into(), Phase::BoundaryControl);
    let limit = Position::new(1001.into(), 1.into(), Phase::BoundaryControl);
    let expected = ExpectedClockCase::new(
        &Id::new("clock")?,
        &[],
        &Id::new("clock/settle")?,
        start,
        limit,
        true,
    )?;
    assert_eq!(
        expected.request,
        OperationRequest::BoundarySettle { start, limit }
    );
    assert_eq!(
        expected.outcome.progress,
        ProgressEvidence::Exact {
            reached: limit,
            stop: StopReason::HorizonPark
        }
    );
    assert_eq!(expected.objects[1].bytes, fixed_case()?.objects[1].bytes);
    Ok(())
}

#[test]
fn clock_origin_refuses_a_real_foreign_thread_before_executable_read() -> TestResult {
    let origin = ClockOrigin {
        source: canonical::content_ref(b"original", "application/octet-stream")?,
        source_path: PathBuf::from("/unopened-on-foreign-origin"),
        process: std::process::id(),
        thread: std::thread::current().id(),
    };
    let result = std::thread::spawn(move || origin.current())
        .join()
        .map_err(|_| "origin control thread unwound")?;
    let Err(NodeObservedError::Native(reason)) = result else {
        return Err("foreign creator did not refuse".into());
    };
    assert_eq!(
        reason,
        "Clock qualification original process/thread changed"
    );
    Ok(())
}

#[test]
fn clock_origin_remeasures_actual_changed_bytes_without_replacing_its_identity() -> TestResult {
    let directory = tempfile::tempdir()?;
    let path = directory.path().join("executable-data");
    std::fs::write(&path, b"original")?;
    let identity = measure_executable(&path)?;
    let origin = ClockOrigin {
        source: identity.clone(),
        source_path: path.clone(),
        process: std::process::id(),
        thread: std::thread::current().id(),
    };
    origin.current()?;
    std::fs::write(&path, b"changed!")?;
    assert!(origin.current().is_err());
    assert_eq!(origin.source, identity);
    Ok(())
}

#[test]
#[ignore = "executes the actual installed Clock/common runtime with genuine source-built companion identity and durable local CAS"]
fn actual_installed_clock_executes_source_programme_with_original_native_bodies_and_acks()
-> TestResult {
    use crate::node_observed_executor::StoredWorldActivationPublisher;
    use crucible_store::content_store::{
        DirectoryBlobBackend, DirectoryRefBackend, ImmutableBlobBackend, MutableRefBackend, RefName,
    };
    use std::{sync::Arc, time::Duration};

    let root = tempfile::tempdir()?;
    let executable = PathBuf::from(std::env::var("CRUCIBLE_REFERENCE_DEVICE")?);
    let identity = measure_executable(&executable)?;
    let mut catalog = InstalledNodeCatalog::new(
        executable,
        identity,
        root.path().to_owned(),
        Duration::from_secs(5),
        2,
    )?;
    let profile = catalog.installed_normal_clock()?;
    let mut original = catalog
        .prepare_original_clock_qualification(&profile, ExecutionId::from_bytes([78; 16])?)?;
    let before = original
        .case_oracles_data()
        .map(|(_, row)| row.reference.clone())
        .collect::<Vec<_>>();
    let blobs: Arc<dyn ImmutableBlobBackend> = Arc::new(DirectoryBlobBackend::new(
        "normal-clock",
        root.path().join("blobs"),
    ));
    let refs: Arc<dyn MutableRefBackend> =
        Arc::new(DirectoryRefBackend::new(root.path().join("refs")));
    let mut publisher = StoredWorldActivationPublisher::new(
        blobs,
        refs,
        RefName::new("node-world-activations/normal-clock-original")?,
    )?;
    original.activate(&mut publisher)?;
    assert!(original.activate(&mut publisher).is_err());
    for (name, _, _) in CASES {
        assert_eq!(original.execute_next()?, name);
    }
    assert_eq!(original.next, CASES.len());
    assert!(
        original
            .cases
            .iter()
            .all(|case| case.attempted && case.acknowledged && case.objects.is_some())
    );
    assert_eq!(
        before,
        original
            .case_oracles_data()
            .map(|(_, row)| row.reference.clone())
            .collect::<Vec<_>>()
    );
    assert!(original.execute_next().is_err());
    Ok(())
}

#[test]
fn public_clock_profile_preserves_generic_bytes_and_selects_real_preparation_codec() -> TestResult {
    let host = canonical::content_ref(b"profile-data-only-host", "application/octet-stream")?;
    let selection = InstalledNodeSelection {
        node: Id::new("clock")?,
        owner: Id::new("owner/clock")?,
        kind: InstalledNodeKind::HostClock,
    };
    let baseline = super::super::profile::build_world(
        &[selection],
        &host,
        &host,
        &std::collections::BTreeMap::new(),
    )?
    .scenario;
    let old_bytes = baseline.canonical_bytes()?;
    let selected = profile::build(&baseline)?;
    assert_eq!(baseline.canonical_bytes()?, old_bytes);
    assert_ne!(selected.canonical_bytes()?, old_bytes);
    let old = &baseline.compatibility[0];
    let new = &selected.compatibility[0];
    assert_eq!(old.execution_owner, new.execution_owner);
    assert_eq!(old.capture_owner, new.capture_owner);
    assert_eq!(old.guarantees_ref, new.guarantees_ref);
    assert_eq!(old.implementation.artifacts, new.implementation.artifacts);
    assert_eq!(old.operating_contract.mode, new.operating_contract.mode);
    assert_eq!(
        selected.descriptors[0].initialization_ref,
        baseline.descriptors[0].initialization_ref
    );
    assert!(
        new.implementation.formats.contains(
            &crucible_engine::node_adapters::host_public_clock_preparation_schema()
                .map_err(|error| error.reason)?
        )
    );
    assert!(
        new.implementation.formats.contains(
            &crucible_engine::node_adapters::host_public_clock_continuation_schema()
                .map_err(|error| error.reason)?
        )
    );
    assert_eq!(
        selected.world.node_bindings[0].binding_hash,
        new.identity()?
    );
    assert_eq!(
        selected.owners[0].node_bindings,
        selected.world.node_bindings
    );
    Ok(())
}
