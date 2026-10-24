//! Observes actual publisher retirement while exposure descriptors remain held.

use super::{Result, config, hex, limits, now, snapshot};
use crate::repository_fixture::{MAIN, RepositoryFixture};
use std::{
    fs::File,
    os::{
        fd::AsFd,
        unix::fs::{FileExt, MetadataExt},
    },
    time::Duration,
};
use terrane_format::{
    identity::{Descriptor, IdentityKind, TERRANE_V1},
    surface::{View, ViewTarget},
};
use terrane_linux::{host_cache::NativeMetadataOwner, structural_index::MappedIndex};

const BODY: &[u8] = b"actual draining sealed file closure";

pub(crate) async fn verify(owner: &NativeMetadataOwner, inputs: &config::Inputs) -> Result<()> {
    let fixture = RepositoryFixture::new(&inputs.domain).await?;
    fixture.commit(BODY).await?;
    let selection = fixture
        .repository
        .prepare_root_read(
            &ViewTarget::Ref(MAIN.parse()?),
            fixture.authority.token(),
            "sdk",
            limits(),
        )
        .await?;
    let admitted = owner.prepare_surface_mapping(selection).await?;
    let key = admitted.key();
    let lease = owner
        .retain_surface_exposure(&admitted, now()? + 150)
        .await?;
    let id = lease.id().to_owned();
    let generation = lease.generation();
    let identity = TERRANE_V1.calculate(IdentityKind::Chunk, BODY)?;
    let descriptor = Descriptor::from_identity(&TERRANE_V1, &identity, BODY)?;
    let publication = owner
        .publish_inline(descriptor, [vec![0], BODY.to_vec()].concat())
        .await?;
    let selection = fixture
        .repository
        .prepare_file_read(
            &View::parse(MAIN)?,
            b"file",
            fixture.authority.token(),
            "sdk",
        )
        .await?;
    let backing = owner
        .prepare_exposure_file_backing(&lease, &admitted, selection, now()? + 120)
        .await?;
    let file = File::from(backing.as_fd().try_clone_to_owned()?);
    let original = file.metadata()?;
    owner.release_sealed_object_lease(backing.lease()).await?;
    drop(backing);
    publication.complete_cache_handoff(owner).await?;
    let selection = fixture
        .repository
        .prepare_root_read(
            &ViewTarget::Commit(admitted.commit()),
            fixture.authority.token(),
            "sdk",
            limits(),
        )
        .await?;
    let grant = owner
        .prepare_exposure_root_backing(&lease, &admitted, selection)
        .await?;
    let index_file = File::from(grant.as_fd().try_clone_to_owned()?);
    let seal = terrane_linux::verity::measure(&index_file)?;
    let maximum = usize::try_from(index_file.metadata()?.len())?;
    let mapping = MappedIndex::open(index_file.into(), key.root(), &seal, maximum)?;
    let hash = hex(identity.digest());
    let pin_owner = format!("exposure:{id}");

    // Actual producer and consumer release grace must finish before the active
    // exposure is the sole promise protecting this original sealed body.
    tokio::time::timeout(Duration::from_secs(40), async {
        loop {
            owner.sweep_consumer_leases().await?;
            if !snapshot(inputs)
                .await?
                .pins
                .iter()
                .any(|pin| pin.hash == hash && pin.owner != pin_owner)
            {
                return Ok::<(), Box<dyn std::error::Error>>(());
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    })
    .await??;
    if pressure(owner, inputs).await? != 0 || file.metadata()?.nlink() != 1 {
        return Err(
            "active exposure failed to protect the original body after actual grace".into(),
        );
    }
    owner.drain_surface_exposure(&lease).await?;
    let retained = snapshot(inputs).await?.exposures;
    drop(grant);
    drop(admitted);
    drop(lease);
    if !owner.retire_draining_surface_index(key).await? || pressure(owner, inputs).await? != 1 {
        return Err("draining exposure did not retire its exact index and publisher body".into());
    }
    tokio::time::timeout(Duration::from_secs(40), async {
        while file.metadata()?.nlink() != 0 {
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
        Ok::<(), Box<dyn std::error::Error>>(())
    })
    .await??;
    let after = file.metadata()?;
    let mut bytes = [0; BODY.len()];
    file.read_exact_at(&mut bytes, 0)?;
    if (after.dev(), after.ino()) != (original.dev(), original.ino())
        || bytes != BODY
        || mapping.index().lookup(b"file").is_none()
        || owner.reconcile_surface_exposure(&id, generation).await?
        || snapshot(inputs).await?.exposures != retained
    {
        return Err(
            "publisher retirement lost original readable custody or exposure obligations".into(),
        );
    }
    drop(mapping);
    if owner.reconcile_surface_exposure(&id, generation).await? {
        return Err("final index unmap released the still-open sealed file obligation".into());
    }
    drop(file);
    tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            if owner.reconcile_surface_exposure(&id, generation).await? {
                return Ok::<(), Box<dyn std::error::Error>>(());
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await??;
    let after = snapshot(inputs).await?;
    if after.exposures.iter().any(|row| row.id == id)
        || after.pins.iter().any(|pin| pin.owner == pin_owner)
        || after.leases.iter().any(|row| row.owner == pin_owner)
    {
        return Err("proven whole-exposure closure retained its discharged policy".into());
    }
    println!(
        "PASS active exposure blocks sealed body retirement after ordinary grace; draining retires the exact publisher inode while preserving exposure pins through final mapping and descriptor closure"
    );
    Ok(())
}

/// Requests one byte beyond actual available capacity without inventing quota.
///
/// # Errors
/// Preserves native eviction, policy, arithmetic and quota observation failures.
pub(super) async fn pressure(
    owner: &NativeMetadataOwner,
    inputs: &config::Inputs,
) -> Result<usize> {
    let current = owner.evict_cached(0).await?;
    let incoming = inputs
        .owner_config()?
        .policy
        .capacity
        .checked_sub(current.charged_reserved_bytes)
        .and_then(|free| free.checked_sub(current.future_hold_bytes))
        .and_then(|free| free.checked_add(1))
        .ok_or("sealed exposure pressure overflows")?;
    Ok(owner.evict_cached(incoming).await?.retired_allocations)
}
