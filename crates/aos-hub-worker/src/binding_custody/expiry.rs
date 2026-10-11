//! Bounded alarm pages remove expired secrets while retaining original journals.

use super::{
    frozen::RecoveryMaterial,
    runtime::{read, write},
    state::HeldCredential,
};
use anyhow::{ensure, Result};
use std::time::Duration;
use worker::{ListOptions, Storage};

/// Schedules bounded retention cleanup independently of control acknowledgement.
///
/// # Errors
/// Returns an error when the durable alarm cannot be retained.
pub(crate) async fn schedule_expiry(storage: &Storage) -> Result<()> {
    // A control turn schedules a bounded sweep without extending authority.
    storage.set_alarm(Duration::from_secs(1)).await?;
    Ok(())
}

/// Removes expired secret material in one bounded persistent page.
///
/// Original metadata and unknown journals survive every sweep. The returned
/// alarm delay lets the binding combine snapshot and material deadlines.
///
/// # Errors
/// Returns an error for corrupt records, unavailable storage or alarm writes.
pub(crate) async fn expire_material(storage: &Storage) -> Result<Option<u64>> {
    let now = aos_hub_core::clock::now_unix_secs();
    let cursor = read::<String>(storage, "credential-custody/expiry-cursor/v1")
        .await?
        .unwrap_or_default();
    let earliest = read::<i64>(storage, "credential-custody/expiry-earliest/v1")
        .await?
        .unwrap_or(i64::MAX);
    let mut earliest = earliest;
    let page = storage
        .list_with_options(
            ListOptions::new()
                .prefix("credential-custody/")
                .start(&cursor)
                .limit(1000),
        )
        .await?;
    let entries = js_sys::try_iter(&page.entries())
        .map_err(|_| anyhow::anyhow!("custody expiry page unavailable"))?
        .ok_or_else(|| anyhow::anyhow!("custody expiry page unavailable"))?;
    let mut count = 0;
    let mut last = None;
    for entry in entries {
        let entry = js_sys::Array::from(
            &entry.map_err(|_| anyhow::anyhow!("custody expiry entry unavailable"))?,
        );
        let key = entry
            .get(0)
            .as_string()
            .ok_or_else(|| anyhow::anyhow!("custody expiry key unavailable"))?;
        count += 1;
        last = Some(key.clone());
        if key.starts_with("credential-custody/material/v1/") {
            let mut held: HeldCredential = read(storage, &key)
                .await?
                .ok_or_else(|| anyhow::anyhow!("custody expiry original lost"))?;
            if held.expire(now) {
                write(storage, &key, &held).await?;
            }
            if held.material.is_some() {
                earliest = earliest.min(held.material_not_after);
            }
        } else if key.starts_with("credential-custody/frozen-material/v1/") {
            let mut held: RecoveryMaterial = read(storage, &key)
                .await?
                .ok_or_else(|| anyhow::anyhow!("custody expiry original lost"))?;
            if held.material.is_some() && now >= held.material_not_after {
                held.material = None;
                write(storage, &key, &held).await?;
            }
            if held.material.is_some() {
                earliest = earliest.min(held.material_not_after);
            }
        }
    }
    if count == 1000 {
        let last = last.ok_or_else(|| anyhow::anyhow!("custody expiry cursor absent"))?;
        ensure!(last >= cursor, "custody expiry cursor regressed");
        write(
            storage,
            "credential-custody/expiry-cursor/v1",
            &format!("{last}\0"),
        )
        .await?;
        write(storage, "credential-custody/expiry-earliest/v1", &earliest).await?;
        storage.set_alarm(Duration::from_secs(1)).await?;
        return Ok(Some(1));
    } else {
        storage
            .delete("credential-custody/expiry-cursor/v1")
            .await?;
        storage
            .delete("credential-custody/expiry-earliest/v1")
            .await?;
        if earliest != i64::MAX {
            let delay = earliest.saturating_sub(now).max(1) as u64;
            storage.set_alarm(Duration::from_secs(delay)).await?;
            return Ok(Some(delay));
        }
    }
    Ok(None)
}
