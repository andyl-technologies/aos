//! Qualifies actual index-pressure retirement and retained-mapping accounting.
//!
//! A separate genuine project measures the empty snapshot and sealed allocation.
//! Those public measurements size the pressure project's cap before its owner
//! starts. They never replace that owner's actual admission or quota checks.

use super::{
    Result, canonical_path, config, exposure, quota_sample,
    repository_fixture::{MAIN, RepositoryFixture},
    tree_with_content,
};
use std::{
    fs::{self, File},
    io,
    time::Duration,
};
use terrane_format::surface::ViewTarget;
use terrane_linux::{
    host_cache::{NativeCacheOwnerConfig, NativeMetadataOwner, SurfaceIndexPolicy},
    host_quota::HostQuotaClient,
    structural_index::MappedIndex,
};

fn measured(name: &str) -> Result<u64> {
    let value = std::env::var(name)?.parse::<u64>()?;
    if value > config::HARD_LIMIT {
        return Err("pressure calibration exceeds genuine project budget".into());
    }
    Ok(value)
}

/// Selects a finite cap before native inspection from genuine calibration data.
///
/// # Errors
/// Refuses missing, overflowing or out-of-budget measurements.
pub(super) fn policy(mut policy: SurfaceIndexPolicy, baseline: u64) -> Result<SurfaceIndexPolicy> {
    let allocation = measured("TERRANE_PRESSURE_ALLOCATION")?;
    if allocation == 0 {
        return Err("pressure calibration has no sealed allocation".into());
    }
    policy.capacity_bytes = baseline
        .checked_add(measured("TERRANE_PRESSURE_SNAPSHOT")?)
        .and_then(|bytes| {
            allocation
                .checked_mul(2)
                .and_then(|indexes| bytes.checked_add(indexes))
        })
        .ok_or("pressure cap overflows")?;
    policy.max_index_bytes = 4096;
    Ok(policy)
}

/// Selects a genuine host-pressure boundary while leaving one index-cap slot.
///
/// # Errors
/// Refuses overflowing actual calibration or an out-of-budget host policy.
pub(super) fn admission_policy(
    settings: &mut NativeCacheOwnerConfig,
    mut policy: SurfaceIndexPolicy,
) -> Result<SurfaceIndexPolicy> {
    let allocation = measured("TERRANE_PRESSURE_ALLOCATION")?;
    let full = policy.capacity_bytes;
    policy.capacity_bytes = full
        .checked_add(allocation)
        .ok_or("admission index cap overflows")?;
    // The initial recovery and each actual index have distinct configured
    // holds. The third index's real hold crosses this host boundary by one
    // allocation even though its separate index cap still has space.
    settings.policy.capacity = policy
        .future_hold_bytes
        .checked_mul(3)
        .and_then(|holds| holds.checked_add(config::HOLD))
        .and_then(|holds| holds.checked_add(full))
        .and_then(|bytes| bytes.checked_sub(allocation))
        .filter(|bytes| *bytes <= config::HARD_LIMIT)
        .ok_or("admission host capacity exceeds genuine project budget")?;
    settings.policy.low_watermark = settings
        .policy
        .capacity
        .checked_sub(policy.future_hold_bytes)
        .ok_or("admission low watermark underflows")?;
    settings.policy.probation_bytes = settings
        .policy
        .probation_bytes
        .min(settings.policy.capacity);
    Ok(policy)
}

/// Runs calibration or the actual bounded pressure control outside main's frame.
///
/// # Errors
/// Preserves native failures and refuses lost exposure custody, premature grace
/// release, another victim, false free-space credit or unavailable final closure.
pub(super) fn run(
    mode: &str,
    runtime: &tokio::runtime::Runtime,
    owner: &NativeMetadataOwner,
    inputs: &config::Inputs,
    policy: SurfaceIndexPolicy,
    baseline: u64,
) -> Result<()> {
    runtime.block_on(Box::pin(async {
        if mode == "pressure-calibrate" {
            return calibrate(owner, inputs, baseline).await;
        }
        verify(owner, inputs, policy, mode).await
    }))
}

async fn calibrate(
    owner: &NativeMetadataOwner,
    inputs: &config::Inputs,
    baseline: u64,
) -> Result<()> {
    let mut quota = HostQuotaClient::connect(&inputs.quota, 0, config::EPOCH)?;
    let resumed = quota_sample(&mut quota, inputs)?.0;
    let (root, nodes) = tree_with_content([7; 32])?;
    let admitted = owner.cache_surface_index(root, nodes).await?;
    let allocated = admitted.synchronized_inode_bytes();
    let charged = quota_sample(&mut quota, inputs)?.0;
    if allocated == 0 || charged.checked_sub(resumed) != Some(allocated) {
        return Err("actual calibration allocation differs from measured project charge".into());
    }
    println!(
        "CALIBRATION {} {allocated}",
        resumed
            .checked_sub(baseline)
            .ok_or("calibration snapshot charge went backwards")?
    );
    Ok(())
}

async fn refused(
    owner: &NativeMetadataOwner,
    root: [u8; 32],
    nodes: std::collections::BTreeMap<[u8; 32], Vec<u8>>,
) -> Result<()> {
    match owner.cache_surface_index(root, nodes).await {
        Err(error) if error.kind() == io::ErrorKind::StorageFull => Ok(()),
        Err(error) => Err(error.into()),
        Ok(_) => Err("pressured index admission unexpectedly succeeded".into()),
    }
}

async fn verify(
    owner: &NativeMetadataOwner,
    inputs: &config::Inputs,
    policy: SurfaceIndexPolicy,
    mode: &str,
) -> Result<()> {
    let global = mode == "global-pressure";
    let admission = mode == "host-admission";
    let fixture = RepositoryFixture::new(&inputs.domain).await?;
    fixture
        .commit(b"durable active root protected against automatic index eviction")
        .await?;
    let selection = fixture
        .repository
        .prepare_root_read(
            &ViewTarget::Ref(MAIN.parse()?),
            fixture.authority.token(),
            "sdk",
            exposure::limits(),
        )
        .await?;
    let active = owner.prepare_surface_mapping(selection).await?;
    let active_key = active.key();
    let lease = owner
        .retain_surface_exposure(&active, exposure::now()? + 90)
        .await?;
    let exposure_id = lease.id().to_owned();
    drop(active);
    drop(lease);

    let active_state = exposure::snapshot(inputs).await?;
    let (cold_root, cold_nodes) = tree_with_content([8; 32])?;
    let cold = owner.cache_surface_index(cold_root, cold_nodes).await?;
    let cold_path = canonical_path(inputs, cold_root);
    let (incoming_root, incoming_nodes) = tree_with_content([9; 32])?;
    let mut quota = HostQuotaClient::connect(&inputs.quota, 0, config::EPOCH)?;
    let full = quota_sample(&mut quota, inputs)?.0;
    let allocation = measured("TERRANE_PRESSURE_ALLOCATION")?;
    let expected_full = policy
        .capacity_bytes
        .checked_sub(if admission { allocation } else { 0 })
        .ok_or("pressure fill bound underflows")?;
    if full != expected_full || cold.synchronized_inode_bytes() != allocation {
        return Err(format!(
            "actual pressure fill differs from calibrated bound: {full} != {expected_full}"
        )
        .into());
    }
    let path = inputs.root.join("state/cache/records.toml");
    let before = fs::read(&path)?;
    let snapshot = exposure::snapshot(inputs).await?;
    let future = snapshot
        .reservations
        .iter()
        .try_fold(0u64, |sum, hold| sum.checked_add(hold.bytes))
        .ok_or("pressure future holds overflow")?;
    let incoming = inputs
        .owner_config()?
        .policy
        .capacity
        .checked_sub(
            full.checked_add(future)
                .ok_or("pressure accounting overflows")?,
        )
        .and_then(|headroom| headroom.checked_add(allocation))
        .ok_or("pressure incoming bound overflows")?;
    let obligations = snapshot.exposures;
    if global {
        if owner.evict_cached(incoming).await?.retired_allocations != 0 {
            return Err("global pressure ignored a genuine retained receipt".into());
        }
    } else {
        refused(owner, incoming_root, incoming_nodes.clone()).await?;
    }
    if fs::read(&path)? != before || !cold_path.exists() {
        return Err("automatic pressure ignored a genuine retained admission receipt".into());
    }
    let file = File::open(&cold_path)?;
    let seal = terrane_linux::verity::measure(&file)?;
    let mapping = MappedIndex::open(file.into(), cold_root, &seal, 4096)?;
    drop(cold);
    if global {
        if owner.evict_cached(incoming).await?.retired_allocations != 0 {
            return Err("global pressure skipped genuine index release grace".into());
        }
    } else {
        refused(owner, incoming_root, incoming_nodes.clone()).await?;
    }
    if fs::read(&path)? != before || !cold_path.exists() {
        return Err("automatic pressure skipped genuine release grace".into());
    }
    tokio::time::sleep(inputs.owner_config()?.policy.release_grace).await;
    let admitted = if admission {
        Some(
            owner
                .cache_surface_index(incoming_root, incoming_nodes.clone())
                .await?,
        )
    } else {
        None
    };
    if global {
        let retired = owner.evict_cached(incoming).await?;
        if retired.retired_allocations != 1
            || retired.charged_reserved_bytes != full
            || retired.future_hold_bytes
                != future
                    .checked_sub(policy.future_hold_bytes)
                    .ok_or("pressure future hold underflows")?
        {
            return Err("global pressure changed actual charge or an unrelated future hold".into());
        }
    }
    if !admission {
        refused(owner, incoming_root, incoming_nodes.clone()).await?;
    }
    if cold_path.exists()
        || !canonical_path(inputs, active_key.root()).exists()
        || mapping.index().lookup(b"file").is_none()
        || exposure::snapshot(inputs).await?.exposures != obligations
    {
        return Err("automatic pressure lost active exposure or original retired mapping".into());
    }
    if admission {
        if quota_sample(&mut quota, inputs)?.0
            != full
                .checked_add(allocation)
                .ok_or("admission charge overflows")?
        {
            return Err("automatic admission credited a still mapped original inode".into());
        }
        println!(
            "PASS verified index admission requests bounded host eviction before funding; retained receipts and real grace refuse without mutation while the original mapped victim remains fully charged"
        );
    } else if global {
        println!(
            "PASS shared host FIFO selects the original derived index after real release grace while preserving active exposure and exact mapped charge"
        );
    } else {
        println!(
            "PASS automatic index pressure preserves retained receipts and release grace; active exposure survives while original unlinked mapping prevents capacity credit"
        );
    }
    let held = quota_sample(&mut quota, inputs)?.0;
    drop(mapping);
    tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            let actual = quota_sample(&mut quota, inputs)?.0;
            if held.checked_sub(actual) == Some(measured("TERRANE_PRESSURE_ALLOCATION")?) {
                return Ok::<_, Box<dyn std::error::Error>>(());
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await??;
    let admitted = match admitted {
        Some(admitted) => admitted,
        None => {
            owner
                .cache_surface_index(incoming_root, incoming_nodes)
                .await?
        }
    };
    admitted.check_native_backing()?;
    let after = exposure::snapshot(inputs).await?;
    if after.exposures != obligations
        || after.exposures[0].id != exposure_id
        || !canonical_path(inputs, active_key.root()).exists()
        || cold_path.exists()
        || quota_sample(&mut quota, inputs)?.0 > policy.capacity_bytes
    {
        return Err("automatic pressure failed exact retry after actual final unmap".into());
    }
    if admission {
        if after.reservations.len() != active_state.reservations.len() + 1
            || active_state.reservations.iter().any(|original| {
                !after.reservations.iter().any(|row| {
                    row.id == original.id
                        && row.owner == original.owner
                        && row.bytes == original.bytes
                })
            })
            || after
                .reservations
                .iter()
                .try_fold(0u64, |sum, hold| sum.checked_add(hold.bytes))
                != Some(future)
        {
            return Err("automatic admission changed an unrelated funded obligation".into());
        }
        println!(
            "PASS automatic host-pressure index admission preserves unrelated exposure and funding; actual final unmap releases exactly the original victim allocation"
        );
    } else if global {
        println!(
            "PASS shared host retirement releases only the original index future hold; actual final unmap precedes bounded index-cap retry with durable custody unchanged"
        );
    } else {
        println!(
            "PASS actual final unmap releases exact original index charge before bounded pressure retry admits a new canonical index with unrelated durable custody unchanged"
        );
    }
    Ok(())
}
