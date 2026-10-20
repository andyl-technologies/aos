//! Checks original pause proof scope and the genuine production admission route.

use super::*;

type TestResult = Result<(), Box<dyn std::error::Error>>;

#[test]
fn pause_oracle_binds_actual_owner_generation_and_full_closed_position() -> TestResult {
    let node = Id::new("clock")?;
    let owner = OwnerIdentity {
        owner: Id::new("owner/clock")?,
        incarnation: Id::new("original")?,
        generation: 1.into(),
    };
    let before = OriginalClockPause::new(&node, std::slice::from_ref(&owner))?;
    let mut changed = owner.clone();
    changed.generation = 2.into();
    let after = OriginalClockPause::new(&node, &[changed])?;
    assert_ne!(before.proof.reference, after.proof.reference);
    assert_ne!(before.proof.bytes, after.proof.bytes);
    assert!(
        matches!(before.expected.progress,ProgressEvidence::Paused { reached: Some(Position { time_ps,.. }),.. } if time_ps.get()==1_000_001)
    );
    assert!(before.expected.scheduling.is_none());
    assert!(!before.complete());
    Ok(())
}

#[test]
#[ignore = "requires the genuine source-built CRUCIBLE_REFERENCE_DEVICE catalog artifact"]
fn actual_closed_clock_pause_refuses_prepublication_foreign_and_unknown_scope() -> TestResult {
    use crate::node_observed_executor::StoredWorldActivationPublisher;
    use crucible_engine::node_contract::RuntimeError;
    use crucible_store::content_store::{
        DirectoryBlobBackend, DirectoryRefBackend, ImmutableBlobBackend, MutableRefBackend, RefName,
    };
    use std::{sync::Arc, time::Duration};

    let directory = tempfile::tempdir()?;
    let device = PathBuf::from(std::env::var("CRUCIBLE_REFERENCE_DEVICE")?);
    let mut catalog = InstalledNodeCatalog::new(
        device.clone(),
        super::super::super::measure_executable(&device)?,
        directory.path().to_path_buf(),
        Duration::from_secs(5),
        4,
    )?;
    let profile = catalog.installed_normal_clock()?;
    let mut original = catalog
        .prepare_original_clock_qualification(&profile, ExecutionId::from_bytes([101; 16])?)?;
    let mut foreign = catalog
        .prepare_original_clock_qualification(&profile, ExecutionId::from_bytes([102; 16])?)?;
    let blobs: Arc<dyn ImmutableBlobBackend> = Arc::new(DirectoryBlobBackend::new(
        "clock-pause",
        directory.path().join("blobs"),
    ));
    let refs: Arc<dyn MutableRefBackend> =
        Arc::new(DirectoryRefBackend::new(directory.path().join("refs")));
    let publisher =
        |name: &str| -> Result<StoredWorldActivationPublisher, Box<dyn std::error::Error>> {
            Ok(StoredWorldActivationPublisher::new(
                blobs.clone(),
                refs.clone(),
                RefName::new(format!("node-world-activations/{name}"))?,
            )?)
        };
    foreign.activate(&mut publisher("foreign")?)?;
    let foreign_activation = foreign
        .activation
        .as_ref()
        .ok_or("foreign activation absent")?;
    assert!(matches!(
        original
            .runtime
            .as_mut()
            .ok_or("original runtime absent")?
            .begin_exact_boundary_pause(
                &original.graph,
                foreign_activation,
                &original.node,
                Id::new("before-publication")?
            ),
        Err(RuntimeError::NotActivated)
    ));
    original.activate(&mut publisher("original")?)?;
    let activation = original
        .activation
        .as_ref()
        .ok_or("original activation absent")?;
    let runtime = original.runtime.as_mut().ok_or("original runtime absent")?;
    assert!(matches!(
        runtime.begin_exact_boundary_pause(
            &original.graph,
            foreign_activation,
            &original.node,
            Id::new("foreign-pause")?
        ),
        Err(RuntimeError::ForeignAuthority)
    ));
    assert!(matches!(
        runtime.begin_exact_boundary_pause(
            &original.graph,
            activation,
            &Id::new("unknown-node")?,
            Id::new("unknown-pause")?
        ),
        Err(RuntimeError::UnknownNode)
    ));
    assert!(runtime.recover(&Id::new("foreign-pause")?).is_err());
    assert!(runtime.recover(&Id::new("unknown-pause")?).is_err());
    for (name, _, _) in CASES {
        assert_eq!(original.execute_next()?, name);
    }
    original.execute_original_pause()?;
    assert!(original.pause.complete());
    assert!(original.execute_original_pause().is_err());
    Ok(())
}
