//! Native OpenZFS dataset properties and mount leases.
//!
//! Teardown unmounts the exact claimed dataset and retains its data. Retargeting
//! an owned dataset is rejected; changing its mount or properties reconciles it.

use crate::{native_state as state, process::run_native};
use anyhow::{Context as _, Result, bail, ensure};
use aos_ability_runtime::activation::{Action, Invocation};
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::collections::BTreeMap;
use std::path::{Component, Path, PathBuf};

const ROOT: &str = "/run/aos/native-zfs-datasets";

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Desired {
    pool: String,
    dataset: String,
    mountpoint: Option<String>,
    mount_options: Vec<String>,
    properties: BTreeMap<String, String>,
    zfs: PathBuf,
}
#[derive(Clone, Debug, Deserialize, Serialize)]
struct Claim {
    id: String,
    revision: String,
    input: Desired,
}
#[derive(Default)]
struct NativeState {
    exists: bool,
    mounted: bool,
    mountpoint: Option<String>,
    properties: BTreeMap<String, String>,
}

/// Reconciles or removes one native dataset mount lease.
///
/// # Errors
/// Returns an error for invalid properties, retargeting an owned dataset,
/// inconsistent actions, or failed native inspection or mutation.
pub fn handle(action: &str, bytes: &[u8]) -> Result<Vec<u8>> {
    let invocation: Invocation = serde_json::from_slice(bytes)?;
    ensure!(
        matches!(action, "apply" | "remove" | "observe"),
        "unsupported dataset action"
    );
    ensure!(
        action == "observe"
            || matches!(
                (action, invocation.action),
                ("apply", Action::Apply) | ("remove", Action::Remove)
            ),
        "dataset action differs from invocation"
    );
    let input: Desired = serde_json::from_value(invocation.input.clone())?;
    validate_desired(&input)?;
    let full = full_dataset_name(&input)?;
    let root = Path::new(ROOT);
    let _lock = state::Lock::acquire(root)?;
    let claim: Option<Claim> = state::read(root, &invocation.id)?;
    if let Some(claim) = &claim {
        ensure!(
            claim.id == invocation.id,
            "dataset claim belongs to another effect"
        );
        validate_desired(&claim.input)?;
    }
    let output = match action {
        "apply" => {
            if let Some(claim) = &claim {
                ensure!(
                    full_dataset_name(&claim.input)? == full,
                    "refusing to retarget an owned dataset"
                );
            }
            let native = inspect(&input.zfs, &full, &input.properties)?;
            state::write(
                root,
                &invocation.id,
                &Claim {
                    id: invocation.id.clone(),
                    revision: invocation.revision.clone(),
                    input: input.clone(),
                },
            )?;
            if !native.exists {
                let mut arguments = vec!["create".into(), "-p".into()];
                push_property(
                    &mut arguments,
                    "mountpoint",
                    input.mountpoint.as_deref().unwrap_or("none"),
                )?;
                for (key, value) in &input.properties {
                    push_property(&mut arguments, key, value)?;
                }
                arguments.push("--".into());
                arguments.push(full.clone());
                run_owned(&input.zfs, &arguments, invocation.effect.timeout_ms)?;
            } else {
                if native.mounted
                    && (input.mountpoint.is_none()
                        || claim
                            .as_ref()
                            .is_some_and(|claim| claim.input.mount_options != input.mount_options))
                {
                    run_success(
                        &input.zfs,
                        &["unmount", "--", &full],
                        invocation.effect.timeout_ms,
                    )?;
                }
                set_property(
                    &input.zfs,
                    "mountpoint",
                    input.mountpoint.as_deref().unwrap_or("none"),
                    &full,
                    invocation.effect.timeout_ms,
                )?;
                for (key, value) in &input.properties {
                    if native.properties.get(key) != Some(value) {
                        set_property(&input.zfs, key, value, &full, invocation.effect.timeout_ms)?;
                    }
                }
            }
            let current = inspect(&input.zfs, &full, &input.properties)?;
            if input.mountpoint.is_some() && !current.mounted {
                let mut arguments = vec!["mount".into()];
                if !input.mount_options.is_empty() {
                    arguments.push("-o".into());
                    arguments.push(input.mount_options.join(","));
                }
                arguments.push("--".into());
                arguments.push(full.clone());
                run_owned(&input.zfs, &arguments, invocation.effect.timeout_ms)?;
            }
            json!({"path":input.mountpoint,"dataset":full,"resource":invocation.id})
        }
        "remove" => {
            if let Some(claim) = &claim {
                let name = full_dataset_name(&claim.input)?;
                if inspect(&claim.input.zfs, &name, &claim.input.properties)?.mounted {
                    run_success(
                        &claim.input.zfs,
                        &["unmount", "--", &name],
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
            } else {
                let native = inspect(&input.zfs, &full, &input.properties)?;
                let current = exact(&invocation.revision, &input, claim.as_ref(), &native);
                if current {
                    json!({"status":"current","outputs":{"path":input.mountpoint,"dataset":full,"resource":invocation.id}})
                } else {
                    json!({"status":"retry-safe"})
                }
            }
        }
        _ => bail!("unsupported dataset action"),
    };
    Ok(serde_json::to_vec(&output)?)
}

fn exact(revision: &str, desired: &Desired, claim: Option<&Claim>, native: &NativeState) -> bool {
    claim.is_some_and(|claim| {
        claim.revision == revision
            && full_dataset_name(&claim.input).ok() == full_dataset_name(desired).ok()
    }) && native.exists
        && native.properties == desired.properties
        && match desired.mountpoint.as_deref() {
            Some(path) => native.mounted && native.mountpoint.as_deref() == Some(path),
            None => !native.mounted && native.mountpoint.as_deref() == Some("none"),
        }
}

fn inspect(zfs: &Path, dataset: &str, expected: &BTreeMap<String, String>) -> Result<NativeState> {
    let mut property_names = vec!["mounted", "mountpoint"];
    property_names.extend(expected.keys().map(String::as_str));
    let fields = property_names.join(",");
    let output = run_native(
        zfs,
        &[
            "get",
            "-H",
            "-p",
            "-o",
            "property,value",
            &fields,
            "--",
            dataset,
        ],
        5_000,
    )?;
    if !output.status.success() {
        ensure!(
            output.status.code() == Some(1),
            "zfs inspection failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        return Ok(NativeState::default());
    }
    let stdout = String::from_utf8(output.stdout).context("decoding zfs output")?;
    let mut state = NativeState {
        exists: true,
        ..NativeState::default()
    };
    for line in stdout.lines() {
        let (property, value) = line
            .split_once('\t')
            .context("zfs property output is malformed")?;
        match property {
            "mounted" => state.mounted = value == "yes",
            "mountpoint" => state.mountpoint = Some(value.to_string()),
            property if expected.contains_key(property) => {
                state
                    .properties
                    .insert(property.to_string(), value.to_string());
            }
            _ => bail!("zfs returned an unrequested property"),
        }
    }
    ensure!(
        state.mountpoint.is_some(),
        "zfs omitted mountpoint observation"
    );
    ensure!(
        state.properties.len() == expected.len(),
        "zfs omitted requested property observations"
    );
    Ok(state)
}

fn set_property(
    zfs: &Path,
    key: &str,
    value: &str,
    dataset: &str,
    remaining_millis: u64,
) -> Result<()> {
    validate_property(key, value)?;
    let assignment = format!("{key}={value}");
    run_success(zfs, &["set", &assignment, "--", dataset], remaining_millis)
}

fn push_property(arguments: &mut Vec<String>, key: &str, value: &str) -> Result<()> {
    validate_property(key, value)?;
    arguments.push("-o".into());
    arguments.push(format!("{key}={value}"));
    Ok(())
}

fn run_owned(executable: &Path, arguments: &[String], remaining_millis: u64) -> Result<()> {
    let borrowed = arguments.iter().map(String::as_str).collect::<Vec<_>>();
    run_success(executable, &borrowed, remaining_millis)
}

fn run_success(executable: &Path, arguments: &[&str], remaining_millis: u64) -> Result<()> {
    let output = run_native(executable, arguments, remaining_millis)?;
    ensure!(
        output.status.success(),
        "zfs command failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    Ok(())
}

fn full_dataset_name(desired: &Desired) -> Result<String> {
    validate_pool_name(&desired.pool)?;
    validate_dataset_name(&desired.dataset)?;
    Ok(format!("{}/{}", desired.pool, desired.dataset))
}

fn validate_desired(desired: &Desired) -> Result<()> {
    full_dataset_name(desired)?;
    if let Some(mountpoint) = &desired.mountpoint {
        validate_path(mountpoint)?;
    }
    ensure!(
        !desired.properties.contains_key("mountpoint")
            && !desired.properties.contains_key("mounted"),
        "dataset properties duplicate controller-owned fields"
    );
    for (key, value) in &desired.properties {
        validate_property(key, value)?;
    }
    ensure!(
        desired.mount_options.len() <= 64
            && desired
                .mount_options
                .windows(2)
                .all(|pair| pair[0] < pair[1]),
        "storage-dataset mount options must be unique and canonically ordered"
    );
    for option in &desired.mount_options {
        ensure!(
            !option.is_empty()
                && option.len() <= 1024
                && !option
                    .bytes()
                    .any(|byte| byte.is_ascii_control() || byte == b','),
            "storage-dataset mount option is invalid"
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
        pool.bytes().enumerate().all(|(index, byte)| if index == 0 {
            byte.is_ascii_alphabetic()
        } else {
            byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'.' | b':' | b'-')
        }),
        "storage-pool name is invalid"
    );
    Ok(())
}

fn validate_dataset_name(dataset: &str) -> Result<()> {
    ensure!(
        !dataset.is_empty() && dataset.len() <= 1024,
        "storage-dataset name is invalid"
    );
    ensure!(
        dataset.split('/').all(|part| !part.is_empty()
            && part
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric()
                    || matches!(byte, b'_' | b'.' | b':' | b'-'))),
        "storage-dataset name is invalid"
    );
    Ok(())
}

fn validate_property(key: &str, value: &str) -> Result<()> {
    ensure!(
        !key.is_empty() && key.len() <= 255 && value.len() <= 4096,
        "storage-dataset property is invalid"
    );
    ensure!(
        key.bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'.' | b':' | b'-')),
        "storage-dataset property name is invalid"
    );
    ensure!(
        !value.contains('\0') && !value.contains('\n'),
        "storage-dataset property value is invalid"
    );
    Ok(())
}

fn validate_path(value: &str) -> Result<()> {
    let path = Path::new(value);
    ensure!(
        path.is_absolute(),
        "storage-dataset mountpoint is not absolute"
    );
    ensure!(
        path.components()
            .all(|part| matches!(part, Component::RootDir | Component::Normal(_))),
        "storage-dataset mountpoint is not normalized"
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn desired() -> Desired {
        Desired {
            pool: "aos-pool".into(),
            dataset: "var/log".into(),
            mountpoint: Some("/var/log".into()),
            mount_options: vec!["nodev".into()],
            properties: BTreeMap::new(),
            zfs: PathBuf::new(),
        }
    }

    #[test]
    fn ambient_dataset_never_proves_completion() {
        let native = NativeState {
            exists: true,
            mounted: true,
            mountpoint: Some("/var/log".into()),
            properties: BTreeMap::new(),
        };
        assert!(!exact("desired", &desired(), None, &native));
    }

    #[test]
    fn exact_receipt_and_mount_prove_recovery() {
        let desired = desired();
        let claim = Claim {
            id: "dataset".into(),
            revision: "desired".into(),
            input: desired.clone(),
        };
        let native = NativeState {
            exists: true,
            mounted: true,
            mountpoint: desired.mountpoint.clone(),
            properties: BTreeMap::new(),
        };
        assert!(exact("desired", &desired, Some(&claim), &native));
        assert!(!exact("changed", &desired, Some(&claim), &native));
    }

    #[test]
    fn unmounted_dataset_is_current_only_when_mounting_is_disabled() {
        let mut desired = desired();
        desired.mountpoint = None;
        desired.mount_options.clear();
        let claim = Claim {
            id: "dataset".into(),
            revision: "desired".into(),
            input: desired.clone(),
        };
        let native = NativeState {
            exists: true,
            mounted: false,
            mountpoint: Some("none".into()),
            properties: BTreeMap::new(),
        };
        assert!(exact("desired", &desired, Some(&claim), &native));
        desired.mountpoint = Some("/var/log".into());
        assert!(!exact("desired", &desired, Some(&claim), &native));
    }
}
