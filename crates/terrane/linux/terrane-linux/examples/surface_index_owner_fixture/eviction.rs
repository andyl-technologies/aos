//! Observes live-receipt refusal and actual warm retirement with a retained map.

use super::{
    Result, canonical_path, config, no_surface_hold, observation_now, quota_sample, snapshot, tree,
};
use std::{fs::File, io, os::unix::fs::MetadataExt};
use terrane_linux::{
    host_cache::{NativeMetadataOwner, NativeSurfaceIndex},
    host_quota::HostQuotaClient,
    structural_index::MappedIndex,
};

pub(super) fn verify(
    runtime: &tokio::runtime::Runtime,
    owner: &NativeMetadataOwner,
    inputs: &config::Inputs,
    admitted: NativeSurfaceIndex,
) -> Result<()> {
    let key = admitted.key();
    let canonical = canonical_path(inputs, key.root());
    let metadata = File::open(&canonical)?.metadata()?;
    let stable = snapshot(inputs)?;
    let alias = admitted.clone();
    for retained in [admitted, alias] {
        let error = runtime
            .block_on(owner.evict_surface_index(key))
            .err()
            .ok_or("surface retirement ignored a retained receipt")?;
        if error.kind() != io::ErrorKind::WouldBlock
            || snapshot(inputs)? != stable
            || File::open(&canonical)?.metadata()?.ino() != metadata.ino()
        {
            return Err("retained surface receipt refusal changed durable state or inode".into());
        }
        drop(retained);
    }
    let file = File::open(&canonical)?;
    let binding = terrane_linux::verity::measure(&file)?;
    let mapping = MappedIndex::open(file.into(), key.root(), &binding, 65536)?;
    if !runtime.block_on(owner.evict_surface_index(key))?
        || canonical.exists()
        || runtime.block_on(owner.evict_surface_index(key))?
        || mapping.index().lookup(b"file").is_none()
    {
        return Err(
            "warm surface retirement lost original mapping or exact namespace completion".into(),
        );
    }
    no_surface_hold(runtime, inputs)?;
    let mut quota = HostQuotaClient::connect(&inputs.quota, 0, config::EPOCH)?;
    let before = quota_sample(&mut quota, inputs)?;
    drop(mapping);
    let deadline = observation_now() + std::time::Duration::from_secs(5);
    loop {
        let after = quota_sample(&mut quota, inputs)?;
        if before.0.checked_sub(after.0) == Some(metadata.blocks() * 512)
            && before.1.checked_sub(after.1) == Some(1)
        {
            break;
        }
        if observation_now() >= deadline {
            return Err("warm-retired final unmap did not release exact index charge".into());
        }
        std::thread::sleep(std::time::Duration::from_millis(10));
    }
    let (_, nodes) = tree()?;
    let replacement = runtime.block_on(owner.cache_surface_index(key.root(), nodes))?;
    replacement.check_native_backing()?;
    println!(
        "PASS warm surface eviction refuses retained receipts without effects and releases exact mapped charge only after final unmap"
    );
    Ok(())
}
