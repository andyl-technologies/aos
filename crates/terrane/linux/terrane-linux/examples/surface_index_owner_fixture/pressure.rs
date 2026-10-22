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
    host_cache::{NativeMetadataOwner, SurfaceIndexPolicy},
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
        verify(owner, inputs, policy, mode == "global-pressure").await
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
    global: bool,
) -> Result<()> {
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

    let (cold_root, cold_nodes) = tree_with_content([8; 32])?;
    let cold = owner.cache_surface_index(cold_root, cold_nodes).await?;
    let cold_path = canonical_path(inputs, cold_root);
    let (incoming_root, incoming_nodes) = tree_with_content([9; 32])?;
    let mut quota = HostQuotaClient::connect(&inputs.quota, 0, config::EPOCH)?;
    let full = quota_sample(&mut quota, inputs)?.0;
    if full != policy.capacity_bytes
        || cold.synchronized_inode_bytes() != measured("TERRANE_PRESSURE_ALLOCATION")?
    {
        return Err(format!(
            "actual pressure fill differs from calibrated cap: {full} != {}",
            policy.capacity_bytes
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
    let allocation = measured("TERRANE_PRESSURE_ALLOCATION")?;
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
    refused(owner, incoming_root, incoming_nodes.clone()).await?;
    if cold_path.exists()
        || !canonical_path(inputs, active_key.root()).exists()
        || mapping.index().lookup(b"file").is_none()
        || exposure::snapshot(inputs).await?.exposures != obligations
    {
        return Err("automatic pressure lost active exposure or original retired mapping".into());
    }
    if global {
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
    let admitted = owner
        .cache_surface_index(incoming_root, incoming_nodes)
        .await?;
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
    if global {
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
