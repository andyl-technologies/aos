//! Recovers new Running custody while an old exposure's real mapping survives.

use super::{Result, config, limits, now, retained_file, snapshot};
use crate::{
    repository_fixture::{MAIN, RepositoryFixture},
    restart,
};
use std::{fs::File, io, os::fd::AsFd, os::unix::fs::MetadataExt, sync::Arc, time::Duration};
use terrane_format::surface::ViewTarget;
use terrane_linux::{
    host_cache::{NativeMetadataOwner, SurfaceIndexPolicy},
    host_quota::HostQuotaClient,
    quota_confinement::Installed,
    structural_index::MappedIndex,
};
use terrane_sdk::host::cache::ExposurePhase;

/// Selects the actual original kernel backing retained across recovery.
#[derive(Clone, Copy, Eq, PartialEq)]
pub(crate) enum Scenario {
    /// Retains only the actual index mapping.
    Index,
    /// Retains a sealed file whose original name survives until new Resume.
    NamedFile,
    /// Retains a file unlinked through genuine publisher retirement before restart.
    RetiredFile,
}

pub(crate) fn verify(
    owner: NativeMetadataOwner,
    runtime: &tokio::runtime::Runtime,
    inputs: &config::Inputs,
    policy: SurfaceIndexPolicy,
    confinement: Arc<Installed>,
    scenario: Scenario,
) -> Result<()> {
    let retain_file = scenario != Scenario::Index;
    let fixture = runtime.block_on(RepositoryFixture::new(&inputs.domain))?;
    let body = if retain_file {
        retained_file::BODY
    } else {
        b"original exposure retained across native recovery"
    };
    runtime.block_on(fixture.commit(body))?;
    let selection = runtime.block_on(fixture.repository.prepare_root_read(
        &ViewTarget::Ref(MAIN.parse()?),
        fixture.authority.token(),
        "sdk",
        limits(),
    ))?;
    let admitted = runtime.block_on(owner.prepare_surface_mapping(selection))?;
    let key = admitted.key();
    let expires = now()? + 90;
    let lease = runtime.block_on(owner.retain_surface_exposure(&admitted, expires))?;
    let id = lease.id().to_owned();
    let generation = lease.generation();
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
    let original_inode = file.metadata()?;
    let maximum = usize::try_from(original_inode.len())?;
    let mapping = MappedIndex::open(file.into(), key.root(), &seal, maximum)?;
    let retained = if retain_file {
        Some(runtime.block_on(retained_file::RetainedFile::prepare(
            &owner, &fixture, &admitted, &lease, expires,
        ))?)
    } else {
        None
    };
    if scenario == Scenario::RetiredFile {
        runtime.block_on(owner.drain_surface_exposure(&lease))?;
        let file = retained
            .as_ref()
            .ok_or("retired scenario has no original file")?;
        runtime.block_on(file.retire_backing(&owner, inputs, &id, generation))?;
    }
    let original = runtime.block_on(snapshot(inputs))?;
    let mut expected = original
        .exposures
        .iter()
        .find(|row| row.id == id)
        .cloned()
        .ok_or("original retained exposure is absent")?;
    let original_phase = if scenario == Scenario::RetiredFile {
        ExposurePhase::Draining
    } else {
        ExposurePhase::Active
    };
    if expected.phase != original_phase
        || expected.backings.len() != if retain_file { 2 } else { 1 }
        || !expected
            .backings
            .iter()
            .any(|row| row.device == original_inode.dev() && row.inode == original_inode.ino())
    {
        return Err("retained recovery lost the expected original exposure and index".into());
    }
    expected.phase = ExposurePhase::Draining;
    drop(grant);
    drop(admitted);
    drop(lease);
    drop(owner);

    let policy_path = inputs.root.join("state/cache/records.toml");
    let before = std::fs::read(&policy_path)?;
    let restarted = restart(inputs, policy, confinement)?;
    if !matches!(runtime.block_on(restarted.recover()), Err(error) if error.kind() == io::ErrorKind::WouldBlock)
        || std::fs::read(&policy_path)? != before
    {
        return Err("strict recovery changed unresolved original exposure policy".into());
    }
    let completed = runtime.block_on(restarted.recover_retaining_surface_exposures())?;
    completed.check_current()?;
    let recovered = runtime.block_on(snapshot(inputs))?;
    let original_pins: Vec<_> = original
        .pins
        .iter()
        .map(|row| (&row.owner, &row.hash, row.expires))
        .collect();
    let recovered_pins: Vec<_> = recovered
        .pins
        .iter()
        .map(|row| (&row.owner, &row.hash, row.expires))
        .collect();
    let original_leases: Vec<_> = original
        .leases
        .iter()
        .map(|row| (&row.owner, row.expires))
        .collect();
    let recovered_leases: Vec<_> = recovered
        .leases
        .iter()
        .map(|row| (&row.owner, row.expires))
        .collect();
    if recovered.exposures.iter().find(|row| row.id == id) != Some(&expected)
        || recovered_pins != original_pins
        || recovered_leases != original_leases
        || crate::canonical_path(inputs, key.root()).exists()
        || mapping.index().lookup(b"file").is_none()
        || runtime.block_on(restarted.status()).is_ok()
    {
        return Err("funded recovery lost original draining custody or bypassed Resume".into());
    }
    runtime.block_on(restarted.resume_recovered(completed))?;
    if let Some(file) = &retained {
        file.check_readable()?;
        if scenario == Scenario::RetiredFile {
            runtime.block_on(file.check_unadopted(&restarted, inputs))?;
        }
    }
    let running = runtime.block_on(restarted.status())?;
    if running.active_exposures != 0 || running.draining_exposures != 1 {
        return Err("new Running status omitted the retained draining exposure".into());
    }
    let before = std::fs::read(&policy_path)?;
    if runtime.block_on(restarted.reconcile_surface_exposure(&id, generation))?
        || std::fs::read(&policy_path)? != before
        || mapping.index().lookup(b"file").is_none()
    {
        return Err("new Running owner released the actual surviving old mapping".into());
    }

    // Observe final-unmap accounting before the closure snapshot can change
    // metadata allocation. The surviving original inode remains kernel charged.
    let mut quota = HostQuotaClient::connect(&inputs.quota, 0, config::EPOCH)?;
    let before_charge = crate::quota_sample(&mut quota, inputs)?;
    drop(mapping);
    let deadline = crate::observation_now() + Duration::from_secs(5);
    loop {
        let after_charge = crate::quota_sample(&mut quota, inputs)?;
        if before_charge.0.checked_sub(after_charge.0) == Some(original_inode.blocks() * 512)
            && before_charge.1.checked_sub(after_charge.1) == Some(1)
        {
            break;
        }
        if crate::observation_now() >= deadline {
            return Err("recovered final unmap did not release exact original index charge".into());
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    if std::fs::read(&policy_path)? != before {
        return Err("physical unmap discharged policy without authenticated reconciliation".into());
    }
    if let Some(file) = retained {
        if scenario != Scenario::RetiredFile {
            runtime.block_on(file.retire_backing(&restarted, inputs, &id, generation))?;
        }
        runtime.block_on(file.close(&restarted, inputs, &id, generation))?;
    }
    runtime.block_on(async {
        tokio::time::timeout(Duration::from_secs(5), async {
            loop {
                if restarted
                    .reconcile_surface_exposure(&id, generation)
                    .await?
                {
                    return Ok::<_, io::Error>(());
                }
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
    })??;
    let after = runtime.block_on(snapshot(inputs))?;
    let pin_owner = format!("exposure:{id}");
    if after.exposures.iter().any(|row| row.id == id)
        || after.pins.iter().any(|row| row.owner == pin_owner)
        || after.leases.iter().any(|row| row.owner == pin_owner)
        || runtime.block_on(restarted.status())?.draining_exposures != 0
    {
        return Err("final native closure retained an already discharged exposure".into());
    }
    if scenario == Scenario::RetiredFile {
        println!(
            "PASS funded recovery retains already-unlinked original file as draining custody without adoption; new Resume preserves readable descriptor and exact charges until authenticated final closure"
        );
    } else if retain_file {
        println!(
            "PASS funded cold recovery re-verifies original sealed file and retains descriptor through new Resume and publisher retirement; exact inode charges release only on final closure before exposure reconciliation"
        );
    } else {
        println!(
            "PASS funded cold recovery retains actual old mapping and draining exposure through new Resume; unchanged native obligations discharge only after final unmap and authenticated closure"
        );
    }
    Ok(())
}
