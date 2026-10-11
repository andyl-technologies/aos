//! Native OpenZFS pool import, property convergence, and export.

use crate::{native_state as state, process::run_native};
use anyhow::{Context as _, Result, bail, ensure};
use aos_ability_runtime::activation::{Action, Invocation};
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

const ROOT: &str = "/run/aos/native-zfs-pools";

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Desired {
    pool: String,
    properties: BTreeMap<String, String>,
    zpool: PathBuf,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
struct Claim {
    id: String,
    revision: String,
    input: Desired,
}

/// Applies, observes, or exports a native pool effect.
///
/// # Errors
/// Returns an error for malformed input, ownership conflicts, failed OpenZFS
/// commands, or a process action inconsistent with the retained invocation.
pub fn handle(action: &str, bytes: &[u8]) -> Result<Vec<u8>> {
    let invocation: Invocation = serde_json::from_slice(bytes)?;
    ensure!(
        matches!(action, "apply" | "remove" | "observe"),
        "unsupported pool action"
    );
    ensure!(
        action == "observe"
            || matches!(
                (action, invocation.action),
                ("apply", Action::Apply) | ("remove", Action::Remove)
            ),
        "pool action differs from invocation"
    );
    let input: Desired = serde_json::from_value(invocation.input.clone())?;
    validate_pool_name(&input.pool)?;
    validate_properties(&input.properties)?;
    let root = Path::new(ROOT);
    let _lock = state::Lock::acquire(root)?;
    let claim: Option<Claim> = state::read(root, &invocation.id)?;
    if let Some(claim) = &claim {
        ensure!(
            claim.id == invocation.id,
            "pool claim belongs to another effect"
        );
        validate_pool_name(&claim.input.pool)?;
    }
    let output = match action {
        "apply" => {
            if let Some(old) = &claim {
                if old.input.pool != input.pool && is_imported(&old.input.zpool, &old.input.pool)? {
                    run_success(
                        &old.input.zpool,
                        &["export", "--", &old.input.pool],
                        invocation.effect.timeout_ms,
                    )?;
                }
            }
            // A named pre-existing pool is deliberately configurable: import
            // is a lease on existing data, never permission to recreate it.
            let receipt = Claim {
                id: invocation.id.clone(),
                revision: invocation.revision.clone(),
                input: input.clone(),
            };
            state::write(root, &invocation.id, &receipt)?;
            if !is_imported(&input.zpool, &input.pool)? {
                run_success(
                    &input.zpool,
                    &["import", "-N", "-f", "--", &input.pool],
                    invocation.effect.timeout_ms,
                )?;
            }
            let observed = inspect_properties(
                &input.zpool,
                &input.pool,
                input.properties.keys().map(String::as_str),
            )?;
            for (name, value) in &input.properties {
                if observed.get(name) != Some(value) {
                    run_success(
                        &input.zpool,
                        &["set", &format!("{name}={value}"), "--", &input.pool],
                        invocation.effect.timeout_ms,
                    )?;
                }
            }
            json!({"pool":input.pool,"resource":invocation.id})
        }
        "remove" => {
            if let Some(claim) = &claim {
                if is_imported(&claim.input.zpool, &claim.input.pool)? {
                    run_success(
                        &claim.input.zpool,
                        &["export", "--", &claim.input.pool],
                        invocation.effect.timeout_ms,
                    )?;
                }
            }
            state::remove(root, &invocation.id)?;
            json!({})
        }
        "observe" => {
            if invocation.action == Action::Remove {
                json!({"status":if claim.is_some(){"retry-safe"}else{"absent"}})
            } else if !is_imported(&input.zpool, &input.pool)? {
                json!({"status":"retry-safe"})
            } else if exact(
                &invocation.revision,
                &input,
                claim.as_ref(),
                is_imported(&input.zpool, &input.pool)?,
                &inspect_properties(
                    &input.zpool,
                    &input.pool,
                    input.properties.keys().map(String::as_str),
                )?,
            ) {
                json!({"status":"current","outputs":{"pool":input.pool,"resource":invocation.id}})
            } else {
                json!({"status":"retry-safe"})
            }
        }
        _ => bail!("unsupported pool action"),
    };
    Ok(serde_json::to_vec(&output)?)
}

fn exact(
    revision: &str,
    desired: &Desired,
    claim: Option<&Claim>,
    imported: bool,
    observed: &BTreeMap<String, String>,
) -> bool {
    imported
        && observed == &desired.properties
        && claim.is_some_and(|claim| claim.revision == revision && claim.input.pool == desired.pool)
}

fn inspect_properties<'a>(
    zpool: &Path,
    pool: &str,
    names: impl Iterator<Item = &'a str>,
) -> Result<BTreeMap<String, String>> {
    let names = names.collect::<Vec<_>>();
    if names.is_empty() {
        return Ok(BTreeMap::new());
    }

    let fields = names.join(",");
    let output = run_native(
        zpool,
        &[
            "get",
            "-H",
            "-p",
            "-o",
            "property,value",
            &fields,
            "--",
            pool,
        ],
        5_000,
    )?;
    ensure!(
        output.status.success(),
        "zpool property inspection failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let stdout = String::from_utf8(output.stdout).context("decoding zpool property output")?;
    let mut properties = BTreeMap::new();
    for line in stdout.lines() {
        let (name, value) = line
            .split_once('\t')
            .context("zpool property output is malformed")?;
        ensure!(
            names.contains(&name),
            "zpool returned an unrequested property"
        );
        ensure!(
            properties
                .insert(name.to_string(), value.to_string())
                .is_none(),
            "zpool repeated a requested property"
        );
    }
    ensure!(
        properties.len() == names.len(),
        "zpool omitted requested properties"
    );
    Ok(properties)
}

fn is_imported(zpool: &Path, pool: &str) -> Result<bool> {
    let output = run_native(zpool, &["list", "-H", "-o", "name", "--", pool], 5_000)?;
    if !output.status.success() {
        ensure!(
            output.status.code() == Some(1),
            "zpool inspection failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        return Ok(false);
    }
    let observed = String::from_utf8(output.stdout).context("decoding zpool output")?;
    Ok(observed.trim() == pool)
}

fn validate_properties(properties: &BTreeMap<String, String>) -> Result<()> {
    ensure!(properties.len() <= 256, "too many storage-pool properties");
    for (name, value) in properties {
        ensure!(
            !name.is_empty()
                && name.len() <= 255
                && !name.bytes().any(|byte| byte.is_ascii_control()),
            "storage-pool property name is invalid"
        );
        ensure!(
            !value.is_empty()
                && value.len() <= 4096
                && !value.bytes().any(|byte| byte.is_ascii_control()),
            "storage-pool property value is invalid"
        );
    }
    Ok(())
}

fn validate_pool_name(pool: &str) -> Result<()> {
    ensure!(
        !pool.is_empty() && pool.len() <= 255,
        "storage-pool name is invalid"
    );
    ensure!(
        pool.bytes().enumerate().all(|(index, byte)| {
            if index == 0 {
                byte.is_ascii_alphabetic()
            } else {
                byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'.' | b':' | b'-')
            }
        }),
        "storage-pool name is invalid"
    );
    Ok(())
}

fn run_success(executable: &Path, arguments: &[&str], remaining_millis: u64) -> Result<()> {
    let output = run_native(executable, arguments, remaining_millis)?;
    ensure!(
        output.status.success(),
        "zpool command failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn desired() -> Desired {
        Desired {
            pool: "aos-pool".into(),
            properties: BTreeMap::new(),
            zpool: PathBuf::new(),
        }
    }

    #[test]
    fn ambient_import_never_proves_owned_completion() {
        assert!(!exact("desired", &desired(), None, true, &BTreeMap::new()));
    }

    #[test]
    fn exact_import_receipt_proves_recovery_but_absent_pool_does_not() {
        let desired = desired();
        let claim = Claim {
            id: "pool".into(),
            revision: "desired".into(),
            input: desired.clone(),
        };
        assert!(exact(
            "desired",
            &desired,
            Some(&claim),
            true,
            &BTreeMap::new()
        ));
        assert!(!exact(
            "desired",
            &desired,
            Some(&claim),
            false,
            &BTreeMap::new()
        ));
        assert!(!exact(
            "changed",
            &desired,
            Some(&claim),
            true,
            &BTreeMap::new()
        ));
    }

    #[test]
    fn changed_pool_property_requires_reconciliation() {
        let mut desired = desired();
        desired
            .properties
            .insert("dedup_table_quota".into(), "2G".into());
        let claim = Claim {
            id: "pool".into(),
            revision: "desired".into(),
            input: desired.clone(),
        };
        let observed = BTreeMap::from([("dedup_table_quota".into(), "1G".into())]);
        assert!(!exact("desired", &desired, Some(&claim), true, &observed));
    }
}
