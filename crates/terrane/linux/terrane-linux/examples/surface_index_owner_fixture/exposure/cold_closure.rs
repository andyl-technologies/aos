//! Restarts after checked unlink while a genuine old index mapping survives.

use super::{Result, config, limits, now, snapshot};
use crate::{
    repository_fixture::{MAIN, RepositoryFixture},
    restart,
};
use std::{fs::File, io, os::fd::AsFd, sync::Arc, time::Duration};
use terrane_format::surface::ViewTarget;
use terrane_linux::{
    host_cache::{NativeMetadataOwner, SurfaceIndexPolicy},
    quota_confinement::Installed,
    structural_index::MappedIndex,
};

pub(crate) fn verify(
    owner: NativeMetadataOwner,
    runtime: &tokio::runtime::Runtime,
    inputs: &config::Inputs,
    policy: SurfaceIndexPolicy,
    confinement: Arc<Installed>,
) -> Result<()> {
    let fixture = runtime.block_on(RepositoryFixture::new(&inputs.domain))?;
    runtime.block_on(fixture.commit(b"cold retired original exposure source"))?;
    let target = ViewTarget::Ref(MAIN.parse()?);
    let selection = runtime.block_on(fixture.repository.prepare_root_read(
        &target,
        fixture.authority.token(),
        "sdk",
        limits(),
    ))?;
    let admitted = runtime.block_on(owner.prepare_surface_mapping(selection))?;
    let key = admitted.key();
    let lease = runtime.block_on(owner.retain_surface_exposure(&admitted, now()? + 90))?;
    let id = lease.id().to_owned();
    let selection = runtime.block_on(fixture.repository.prepare_root_read(
        &ViewTarget::Commit(admitted.commit()),
        fixture.authority.token(),
        "sdk",
        limits(),
    ))?;
    let grant =
        runtime.block_on(owner.prepare_exposure_root_backing(&lease, &admitted, selection))?;
    let file = File::from(grant.as_fd().try_clone_to_owned()?);
    let seal = terrane_linux::verity::measure(&file)?;
    let maximum = usize::try_from(file.metadata()?.len())?;
    let mapping = MappedIndex::open(file.into(), key.root(), &seal, maximum)?;
    runtime.block_on(owner.drain_surface_exposure(&lease))?;
    drop(grant);
    drop(admitted);
    drop(lease);
    if !runtime.block_on(owner.retire_draining_surface_index(key))? {
        return Err("cold closure fixture lost original index retirement".into());
    }
    drop(owner);

    let policy_path = inputs.root.join("state/cache/records.toml");
    let before = std::fs::read(&policy_path)?;
    let restarted = restart(inputs, policy, confinement)?;
    if !matches!(runtime.block_on(restarted.recover()), Err(error) if error.kind() == io::ErrorKind::WouldBlock)
        || std::fs::read(&policy_path)? != before
        || mapping.index().lookup(b"file").is_none()
    {
        return Err("cold recovery discarded a genuine surviving retired mapping".into());
    }
    drop(mapping);
    let completed = runtime.block_on(async {
        tokio::time::timeout(Duration::from_secs(5), async {
            loop {
                match restarted.recover().await {
                    Ok(completed) => return Ok::<_, Box<dyn std::error::Error>>(completed),
                    Err(error)
                        if error.kind() == io::ErrorKind::WouldBlock
                            && std::fs::read(&policy_path)? == before =>
                    {
                        tokio::time::sleep(Duration::from_millis(10)).await;
                    }
                    Err(error) => return Err(error.into()),
                }
            }
        })
        .await
    })??;
    runtime.block_on(restarted.resume_recovered(completed))?;
    let after = runtime.block_on(snapshot(inputs))?;
    let pin_owner = format!("exposure:{id}");
    if after.exposures.iter().any(|row| row.id == id)
        || after.pins.iter().any(|pin| pin.owner == pin_owner)
        || after.leases.iter().any(|row| row.owner == pin_owner)
        || crate::canonical_path(inputs, key.root()).exists()
    {
        return Err(
            "funded cold closure did not discharge only its actual retired exposure".into(),
        );
    }
    println!(
        "PASS cold draining exposure preserves policy while the actual retired mapping survives; final unmap permits authenticated closure in funded recovery before Resume"
    );
    Ok(())
}
