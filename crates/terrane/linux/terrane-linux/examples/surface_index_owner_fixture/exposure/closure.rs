//! Checks actual index-only exposure retirement through authenticated closure.

use super::{Result, config, limits, now, snapshot};
use crate::repository_fixture::{MAIN, RepositoryFixture};
use std::{fs::File, io, os::fd::AsFd, time::Duration};
use terrane_format::surface::ViewTarget;
use terrane_linux::{
    host_cache::{NativeExposureReconciliation, NativeMetadataOwner},
    structural_index::MappedIndex,
};

pub(super) async fn verify(
    owner: &NativeMetadataOwner,
    inputs: &config::Inputs,
    fixture: &RepositoryFixture,
    mut maintenance: Option<&mut crate::maintenance::Launched>,
) -> Result<()> {
    eprintln!("EXPOSURE_CLOSURE_STAGE snapshot");
    let preserved = snapshot(inputs).await?;
    eprintln!("EXPOSURE_CLOSURE_STAGE signed-commit");
    fixture
        .commit(b"independent index-only closure source")
        .await?;
    let target = ViewTarget::Ref(MAIN.parse()?);
    eprintln!("EXPOSURE_CLOSURE_STAGE prepare-root");
    let selection = fixture
        .repository
        .prepare_root_read(&target, fixture.authority.token(), "sdk", limits())
        .await?;
    eprintln!("EXPOSURE_CLOSURE_STAGE admit-mapping");
    let admitted = owner.prepare_surface_mapping(selection).await?;
    let key = admitted.key();
    eprintln!("EXPOSURE_CLOSURE_STAGE retain-exposure");
    let lease = owner
        .retain_surface_exposure(&admitted, now()? + 90)
        .await?;
    let id = lease.id().to_owned();
    let generation = lease.generation();
    let selection = fixture
        .repository
        .prepare_root_read(
            &ViewTarget::Commit(admitted.commit()),
            fixture.authority.token(),
            "sdk",
            limits(),
        )
        .await?;
    eprintln!("EXPOSURE_CLOSURE_STAGE grant-original");
    let grant = owner
        .prepare_exposure_root_backing(&lease, &admitted, selection)
        .await?;
    let file = File::from(grant.as_fd().try_clone_to_owned()?);
    let seal = terrane_linux::verity::measure(&file)?;
    let maximum = usize::try_from(file.metadata()?.len())?;
    let mapping = MappedIndex::open(file.into(), key.root(), &seal, maximum)?;
    let policy = inputs.root.join("state/cache/records.toml");
    eprintln!("EXPOSURE_CLOSURE_STAGE active-refusal");
    let before = std::fs::read(&policy)?;
    if !matches!(owner.reconcile_surface_exposure(&id, generation).await,
        Err(error) if error.kind() == io::ErrorKind::PermissionDenied)
        || std::fs::read(&policy)? != before
    {
        return Err("active exposure reconciliation changed original obligations".into());
    }
    if reconcile(owner, &mut maintenance).await?
        != (NativeExposureReconciliation {
            checked: 1,
            completed: 0,
            blocked: 1,
        })
        || std::fs::read(&policy)? != before
    {
        return Err(
            "batch reconciliation selected active or released named exposure custody".into(),
        );
    }

    eprintln!("EXPOSURE_CLOSURE_STAGE drain");
    owner.drain_surface_exposure(&lease).await?;
    let before = std::fs::read(&policy)?;
    if !matches!(owner.retire_draining_surface_index(key).await,
        Err(error) if error.kind() == io::ErrorKind::WouldBlock)
        || !matches!(owner.reconcile_surface_exposure(&id, generation + 1).await,
            Err(error) if error.kind() == io::ErrorKind::PermissionDenied)
        || std::fs::read(&policy)? != before
    {
        return Err("retained receipt or foreign generation changed exposure custody".into());
    }
    drop(grant);
    drop(admitted);
    drop(lease);
    eprintln!("EXPOSURE_CLOSURE_STAGE retire-original");
    if !owner.retire_draining_surface_index(key).await?
        || crate::canonical_path(inputs, key.root()).exists()
        || mapping.index().lookup(b"file").is_none()
    {
        return Err(
            "draining index retirement lost actual retained mapping or name custody".into(),
        );
    }
    let before = std::fs::read(&policy)?;
    eprintln!("EXPOSURE_CLOSURE_STAGE retained-mapping-refusal");
    if owner.reconcile_surface_exposure(&id, generation).await? || std::fs::read(&policy)? != before
    {
        return Err("live kernel mapping released durable exposure obligations".into());
    }
    if reconcile(owner, &mut maintenance).await?
        != (NativeExposureReconciliation {
            checked: 2,
            completed: 0,
            blocked: 2,
        })
        || std::fs::read(&policy)? != before
    {
        return Err("batch reconciliation released an original retained mapping".into());
    }

    drop(mapping);
    eprintln!("EXPOSURE_CLOSURE_STAGE final-closure");
    tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            let report = reconcile(owner, &mut maintenance).await?;
            if report
                == (NativeExposureReconciliation {
                    checked: 2,
                    completed: 1,
                    blocked: 1,
                })
            {
                return Ok::<(), Box<dyn std::error::Error>>(());
            }
            if report
                != (NativeExposureReconciliation {
                    checked: 2,
                    completed: 0,
                    blocked: 2,
                })
            {
                return Err("batch reconciliation lost original draining inventory".into());
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await??;
    eprintln!("EXPOSURE_CLOSURE_STAGE verify-policy");
    let after = snapshot(inputs).await?;
    let pin_owner = format!("exposure:{id}");
    if after.exposures.iter().any(|row| row.id == id)
        || after.pins.iter().any(|row| row.owner == pin_owner)
        || after.leases.iter().any(|row| row.owner == pin_owner)
        || preserved
            .exposures
            .iter()
            .any(|row| !after.exposures.contains(row))
        || preserved.pins.iter().any(|row| {
            !after.pins.iter().any(|actual| {
                actual.owner == row.owner
                    && actual.hash == row.hash
                    && actual.expires == row.expires
            })
        })
        || owner.reconcile_surface_exposure(&id, generation).await?
    {
        return Err(
            "proven closure released unrelated exposure custody or lost idempotence".into(),
        );
    }
    let before = std::fs::read(&policy)?;
    if reconcile(owner, &mut maintenance).await?
        != (NativeExposureReconciliation {
            checked: 1,
            completed: 0,
            blocked: 1,
        })
        || std::fs::read(&policy)? != before
    {
        return Err("repeated batch reconciliation changed unrelated exposure obligations".into());
    }
    println!(
        "PASS draining index retirement closes owner descriptors; actual retained mapping prevents exposure release until final unmap and authenticated closure"
    );
    println!(
        "PASS original-owner batch reconciliation skips active exposure, preserves blocked custody and closes a later draining mapping only after final unmap"
    );
    Ok(())
}

async fn reconcile(
    owner: &NativeMetadataOwner,
    maintenance: &mut Option<&mut crate::maintenance::Launched>,
) -> Result<NativeExposureReconciliation> {
    match maintenance {
        Some(launched) => launched.reconcile(owner).await,
        None => Ok(owner.reconcile_draining_surface_exposures().await?),
    }
}
