//! Retains actual old mappings through the production configured cache opener.

use super::{NativeCachePlan, Result, quota_confinement};
use crate::{
    exposure::{limits, now},
    repository_fixture::{MAIN, RepositoryFixture},
};
use std::{fs, os::fd::AsFd, os::unix::fs::MetadataExt, path::Path, sync::Arc, time::Duration};
use terrane_format::surface::ViewTarget;
use terrane_linux::structural_index::MappedIndex;
use terrane_sdk::{
    config::host::HostTier,
    host::cache::{CacheState, ExposurePhase, StateLimits},
    store::TokioLocalFs,
};

pub(super) async fn verify(
    plan: NativeCachePlan,
    host: &HostTier,
    confinement: Arc<quota_confinement::Installed>,
    source_parent: &Path,
) -> Result<()> {
    let started = tokio::time::Instant::now();
    let stage = |phase| {
        eprintln!(
            "CONFIGURED_RECOVERY_STAGE phase={phase} elapsed_ms={}",
            started.elapsed().as_millis()
        );
    };
    stage("cache-open");
    let domain = &host.domains["public"];
    let root = Path::new(&domain.path);
    let resources = domain.cache.as_ref().ok_or("missing cache resources")?;
    let state_limits = StateLimits {
        bytes: resources.state_bytes,
        records: resources.state_records,
    };
    let records = root.join("state/cache/records.toml");
    let caches = plan.open(Arc::clone(&confinement)).await?;
    stage("cache-ready");
    let cache = caches.get("public").ok_or("missing configured cache")?;
    let owner = cache.content().ready().owner();
    // The supervisor's TMPDIR is private to root. Keep signed source beside
    // the actor-owned configuration, outside every native cache project.
    let fixture = Box::pin(RepositoryFixture::new_in("public", source_parent)).await?;
    Box::pin(fixture.commit(b"configured recovery retains the original mapping")).await?;
    let selection = fixture
        .repository
        .prepare_root_read(
            &ViewTarget::Ref(MAIN.parse()?),
            fixture.authority.token(),
            "sdk",
            limits(),
        )
        .await?;
    stage("index-admission");
    let admitted = owner.prepare_surface_mapping(selection).await?;
    let key = admitted.key();
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
    stage("root-grant");
    let grant = owner
        .prepare_exposure_root_backing(&lease, &admitted, selection)
        .await?;
    let file = fs::File::from(grant.as_fd().try_clone_to_owned()?);
    let seal = terrane_linux::verity::measure(&file)?;
    let original_inode = file.metadata()?;
    let mapping = MappedIndex::open(
        file.into(),
        key.root(),
        &seal,
        usize::try_from(original_inode.len())?,
    )?;
    let original = snapshot(root, state_limits).await?;
    let mut expected = original
        .exposures
        .iter()
        .find(|row| row.id == id)
        .cloned()
        .ok_or("configured owner omitted original exposure")?;
    if expected.phase != ExposurePhase::Active
        || expected.backings.len() != 1
        || expected.backings[0].device != original_inode.dev()
        || expected.backings[0].inode != original_inode.ino()
    {
        return Err("configured exposure differs from original mapped inode".into());
    }
    expected.phase = ExposurePhase::Draining;
    drop(grant);
    drop(admitted);
    drop(lease);
    drop(caches);
    stage("original-owner-dropped");

    let mut unfunded = host.clone();
    unfunded
        .domains
        .get_mut("public")
        .and_then(|domain| domain.cache.as_mut())
        .ok_or("missing original public cache configuration")?
        .surface_index = None;
    let durable = fs::read(&records)?;
    stage("unfunded-open");
    let error = NativeCachePlan::from_host(&unfunded, Default::default())?
        .open(Arc::clone(&confinement))
        .await
        .err()
        .ok_or("unfunded configured reopen accepted unresolved custody")?;
    if error.kind() != std::io::ErrorKind::WouldBlock || fs::read(&records)? != durable {
        return Err("unfunded configured refusal changed original exposure policy".into());
    }

    // Re-enter the public configured factory, without calling lower-level
    // recovery or manufacturing a completed recovery/Resume receipt.
    stage("funded-reopen");
    let reopened = NativeCachePlan::from_host(host, Default::default())?
        .open(confinement)
        .await?;
    let ready = reopened
        .get("public")
        .ok_or("configured reopen omitted original cache")?
        .content()
        .ready();
    stage("reopened-ready");
    ready.validate_portable().await?;
    let owner = ready.owner();
    let recovered = snapshot(root, state_limits).await?;
    let pins = |state: &CacheState| {
        state
            .pins
            .iter()
            .map(|row| (row.owner.clone(), row.hash.clone(), row.expires))
            .collect::<Vec<_>>()
    };
    let leases = |state: &CacheState| {
        state
            .leases
            .iter()
            .map(|row| (row.owner.clone(), row.expires))
            .collect::<Vec<_>>()
    };
    let status = owner.status().await?;
    let digest: String = key
        .root()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect();
    if recovered.exposures.iter().find(|row| row.id == id) != Some(&expected)
        || pins(&recovered) != pins(&original)
        || leases(&recovered) != leases(&original)
        || root
            .join(format!("objects/.terrane-surface:2:{digest}"))
            .exists()
        || status.active_exposures != 0
        || status.draining_exposures != 1
        || mapping.index().lookup(b"file").is_none()
    {
        return Err("configured new Running owner lost original draining custody".into());
    }
    let durable = fs::read(&records)?;
    if owner.reconcile_surface_exposure(&id, generation).await? || fs::read(&records)? != durable {
        return Err("configured recovery released the actual surviving mapping".into());
    }

    let before = owner.status().await?;
    drop(mapping);
    tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            let after = owner.status().await?;
            if before
                .charged_reserved_bytes
                .checked_sub(after.charged_reserved_bytes)
                == Some(original_inode.blocks() * 512)
                && before.charged_inodes.checked_sub(after.charged_inodes) == Some(1)
            {
                return Ok::<_, std::io::Error>(());
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await??;
    if fs::read(&records)? != durable {
        return Err("configured final unmap changed policy before closure proof".into());
    }
    tokio::time::timeout(Duration::from_secs(5), async {
        while !owner.reconcile_surface_exposure(&id, generation).await? {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        Ok::<_, std::io::Error>(())
    })
    .await??;
    let after = snapshot(root, state_limits).await?;
    let pin_owner = format!("exposure:{id}");
    if after.exposures.iter().any(|row| row.id == id)
        || after.pins.iter().any(|row| row.owner == pin_owner)
        || after.leases.iter().any(|row| row.owner == pin_owner)
        || owner.status().await?.draining_exposures != 0
    {
        return Err("configured final closure retained discharged obligations".into());
    }
    println!(
        "PASS configured funded cache reopen completes actual recovery and new Resume while retaining the original draining mapping; exact final-unmap charge release precedes authenticated policy discharge"
    );
    Ok(())
}

async fn snapshot(root: &Path, limits: StateLimits) -> Result<CacheState> {
    CacheState::load(&TokioLocalFs, &root.join("state/cache"), limits)
        .await?
        .ok_or_else(|| "configured original cache state is absent".into())
}
