//! Owns hardware watchdog configuration and manager re-execution receipts.
//!
//! The private receipt precedes every file mutation and retains both sides of
//! an update. A foreign configuration or edited receipt never grants authority.

use std::fs::{self, File};
use std::os::unix::fs::MetadataExt;
use std::path::Path;
use std::time::{Duration, Instant};

use anyhow::{Context, Result, ensure};
use aos_ability_runtime::activation::{Action, Invocation};
use aos_systemd::PinnedSystemdManager;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

use super::{STATE_ROOT, atomic_write, read_regular, reject_symlink_ancestors};

const CONFIGURATION: &str = "/etc/systemd/system.conf.d/50-aos-watchdog.conf";

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct Settings {
    enabled: bool,
    runtime_timeout_millis: u64,
    reboot_timeout_millis: u64,
    kexec_timeout_millis: u64,
}

impl Settings {
    fn render(&self) -> Result<Vec<u8>> {
        let timeouts = [
            self.runtime_timeout_millis,
            self.reboot_timeout_millis,
            self.kexec_timeout_millis,
        ];
        ensure!(
            timeouts.iter().all(|value| *value <= 172_800_000),
            "watchdog timeout exceeds two days"
        );
        ensure!(
            !self.enabled || timeouts.iter().all(|value| *value > 0),
            "enabled watchdog requires positive timeouts"
        );
        let timeout = |millis| {
            if self.enabled {
                format!("{millis}ms")
            } else {
                "0".to_owned()
            }
        };
        Ok(format!(
            "[Manager]\nRuntimeWatchdogSec={}\nRebootWatchdogSec={}\nKExecWatchdogSec={}\n",
            timeout(timeouts[0]),
            timeout(timeouts[1]),
            timeout(timeouts[2])
        )
        .into_bytes())
    }
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Receipt {
    owner: String,
    revision: String,
    settings: Settings,
    retiring: Option<Settings>,
    complete: bool,
    removing: bool,
}

fn check_configuration(receipt: Option<&Receipt>, configuration: Option<&[u8]>) -> Result<()> {
    let Some(bytes) = configuration else {
        return Ok(());
    };
    let receipt = receipt.context("watchdog configuration has no ownership receipt")?;
    let desired = receipt.settings.render()?;
    let retiring = receipt
        .retiring
        .as_ref()
        .map(Settings::render)
        .transpose()?;
    ensure!(
        bytes == desired || retiring.as_deref() == Some(bytes),
        "watchdog configuration differs from its ownership receipt"
    );
    Ok(())
}

async fn reexecute() -> Result<()> {
    let manager = PinnedSystemdManager::connect().await?;
    let bus = manager.incarnation().bus_id().to_owned();
    let owner = manager.incarnation().owner().to_owned();
    manager.reexecute().await?;
    drop(manager);

    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        if let Ok(current) = PinnedSystemdManager::connect().await {
            if current.incarnation().bus_id() != bus || current.incarnation().owner() != owner {
                return Ok(());
            }
        }
        ensure!(
            Instant::now() < deadline,
            "watchdog manager re-execution timed out"
        );
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
}

/// Converges or observes one owned manager watchdog configuration.
///
/// # Errors
/// Returns an error for invalid settings, foreign or edited state, stale revision
/// authority, or failure to reconnect to a new manager after re-execution.
pub(super) async fn execute(invocation: &Invocation, action: &str) -> Result<Value> {
    let settings: Settings = serde_json::from_value(invocation.input.clone())?;
    let desired = settings.render()?;
    // The manager has one watchdog configuration. A singleton ownership
    // receipt prevents equal bytes from authorizing two independent effects.
    let path = Path::new(STATE_ROOT).join("manager-watchdog.json");
    let previous: Option<Receipt> = read_regular(&path, 65_536)?
        .map(|bytes| serde_json::from_slice(&bytes))
        .transpose()?;
    if let Some(receipt) = &previous {
        ensure!(
            receipt.owner == invocation.id,
            "watchdog receipt owner differs"
        );
    }
    let configuration = read_regular(Path::new(CONFIGURATION), 65_536)?;
    check_configuration(previous.as_ref(), configuration.as_deref())?;

    if action == "observe" {
        let Some(receipt) = previous else {
            return Ok(
                json!({"status": if invocation.action == Action::Remove {"absent"} else {"retry-safe"}}),
            );
        };
        if receipt.revision != invocation.revision && invocation.action == Action::Apply {
            let prior = invocation
                .previous
                .as_ref()
                .context("watchdog observation has no prior authority")?;
            ensure!(
                prior.revision == receipt.revision
                    && serde_json::from_value::<Settings>(prior.input.clone())? == receipt.settings
                    && !receipt.removing
                    && receipt.retiring.is_none(),
                "watchdog observation cannot authorize update replay"
            );
            return Ok(json!({"status":"retry-safe"}));
        }
        ensure!(
            receipt.revision == invocation.revision && receipt.settings == settings,
            "watchdog receipt differs from requested revision"
        );
        if invocation.action == Action::Remove || !receipt.complete {
            ensure!(
                invocation.action == Action::Remove || !receipt.removing,
                "watchdog removal remains unfinished"
            );
            return Ok(json!({"status":"retry-safe"}));
        }
        if configuration.as_deref() != Some(desired.as_slice()) {
            return Ok(json!({"status":"retry-safe"}));
        }
        PinnedSystemdManager::connect().await?;
        return Ok(json!({"status":"current","outputs":{"resource":CONFIGURATION}}));
    }

    if action == "remove" {
        let Some(mut receipt) = previous else {
            return Ok(json!({}));
        };
        ensure!(
            receipt.revision == invocation.revision && receipt.settings == settings,
            "watchdog removal revision differs"
        );
        receipt.removing = true;
        receipt.complete = false;
        atomic_write(&path, &serde_json::to_vec(&receipt)?, 0o600)?;
        if configuration.is_some() {
            fs::remove_file(CONFIGURATION)?;
            File::open(
                Path::new(CONFIGURATION)
                    .parent()
                    .context("watchdog path has no parent")?,
            )?
            .sync_all()?;
        }
        reexecute().await?;
        fs::remove_file(&path)?;
        File::open(STATE_ROOT)?.sync_all()?;
        return Ok(json!({}));
    }

    let mut receipt = match previous {
        Some(mut receipt) => {
            ensure!(!receipt.removing, "watchdog removal remains unfinished");
            if receipt.revision != invocation.revision {
                let prior = invocation
                    .previous
                    .as_ref()
                    .context("watchdog update has no prior authority")?;
                ensure!(
                    prior.revision == receipt.revision
                        && serde_json::from_value::<Settings>(prior.input.clone())?
                            == receipt.settings,
                    "watchdog update prior revision differs"
                );
                ensure!(
                    receipt.retiring.is_none(),
                    "watchdog prior update remains unfinished"
                );
                receipt.retiring = Some(receipt.settings.clone());
                receipt.settings = settings;
                receipt.revision = invocation.revision.clone();
                receipt.complete = false;
            } else {
                ensure!(
                    receipt.settings == settings,
                    "watchdog revision settings differ"
                );
                if receipt.complete && configuration.as_deref() == Some(desired.as_slice()) {
                    return Ok(json!({"resource":CONFIGURATION}));
                }
                receipt.complete = false;
            }
            receipt
        }
        None => Receipt {
            owner: invocation.id.clone(),
            revision: invocation.revision.clone(),
            settings,
            retiring: None,
            complete: false,
            removing: false,
        },
    };
    atomic_write(&path, &serde_json::to_vec(&receipt)?, 0o600)?;
    let parent = Path::new(CONFIGURATION)
        .parent()
        .context("watchdog path has no parent")?;
    reject_symlink_ancestors(Path::new(CONFIGURATION))?;
    fs::create_dir_all(parent)?;
    let metadata = fs::symlink_metadata(parent)?;
    ensure!(
        metadata.is_dir() && !metadata.file_type().is_symlink() && metadata.uid() == 0,
        "watchdog configuration directory is not owned by root"
    );
    atomic_write(Path::new(CONFIGURATION), &desired, 0o644)?;
    reexecute().await?;
    receipt.complete = true;
    receipt.retiring = None;
    atomic_write(&path, &serde_json::to_vec(&receipt)?, 0o600)?;
    Ok(json!({"resource":CONFIGURATION}))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn settings(enabled: bool) -> Settings {
        Settings {
            enabled,
            runtime_timeout_millis: 30_000,
            reboot_timeout_millis: 60_000,
            kexec_timeout_millis: 60_000,
        }
    }

    #[test]
    fn disabled_watchdog_explicitly_clears_all_timeouts() {
        let rendered = String::from_utf8(settings(false).render().unwrap()).unwrap();
        assert_eq!(
            rendered,
            "[Manager]\nRuntimeWatchdogSec=0\nRebootWatchdogSec=0\nKExecWatchdogSec=0\n"
        );
        let mut invalid = settings(true);
        invalid.runtime_timeout_millis = 0;
        assert!(invalid.render().is_err());
    }

    #[test]
    fn foreign_and_edited_configuration_fail_closed() {
        let receipt = Receipt {
            owner: "owner".into(),
            revision: "revision".into(),
            settings: settings(true),
            retiring: Some(settings(false)),
            complete: false,
            removing: false,
        };
        assert!(check_configuration(None, Some(b"foreign")).is_err());
        assert!(check_configuration(Some(&receipt), Some(b"foreign")).is_err());
        assert!(
            check_configuration(Some(&receipt), Some(&settings(true).render().unwrap())).is_ok()
        );
        assert!(
            check_configuration(Some(&receipt), Some(&settings(false).render().unwrap())).is_ok()
        );
    }
}
