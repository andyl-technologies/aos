//! OpenZFS-backed dataset configuration and mount resources.

use std::collections::BTreeMap;
use std::path::{Component, Path};

use anyhow::{Context as _, Result, bail, ensure};
use aos_ability_model::{AbilityValue, ResourceReference, RevisionId};
use aos_provider_protocol::ResourceContext;
use serde::{Deserialize, Serialize};
use serde_json::json;

use crate::engine::{Backend, BackendObservation, ability_value};
use crate::process::{Executable, ExecutableReference};
use crate::state;

const REALIZATION_SCHEMA: &str = "aos.storage.dataset-realization/v1";
const OBSERVATION_SCHEMA: &str = "aos.ability.storage-dataset-observation/v1";
const CONTEXT_SCHEMA: &str = "aos.zfs.storage-dataset-context/v1";
const MARKER_SCHEMA: &str = "aos.zfs.storage-dataset-state/v1";
const STATE_ROOT: &str = "/run/aos/storage-datasets";
const MARKER_DOMAIN: &str = "aos.storage.dataset-resource/v1";

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct Desired {
    name: String,
    enabled: bool,
    pool: String,
    dataset: String,
    mountpoint: Option<String>,
    mount_options: Vec<String>,
    properties: BTreeMap<String, String>,
    prerequisites: Vec<ResourceReference>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Realization {
    schema: String,
    zfs: ExecutableReference,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct Context {
    schema: String,
    zfs: Executable,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct Marker {
    schema: String,
    revision: RevisionId,
    dataset: String,
    mountpoint: Option<String>,
    mount_options: Vec<String>,
    properties: BTreeMap<String, String>,
    pending: bool,
}

#[derive(Default)]
struct NativeState {
    exists: bool,
    mounted: bool,
    mountpoint: Option<String>,
    properties: BTreeMap<String, String>,
}

/// Implements dataset convergence through one exact zfs executable.
pub struct ZfsDatasetBackend;

impl Backend for ZfsDatasetBackend {
    fn action_method(&self) -> &'static str {
        "mount"
    }

    fn path_output(&self) -> &'static str {
        "mountpoint"
    }

    fn admit_context(
        &self,
        desired: &AbilityValue,
        realization: &AbilityValue,
        _target: &ResourceReference,
        _revision: RevisionId,
        _resources: &[ResourceContext],
    ) -> Result<AbilityValue> {
        validate_desired(&decode(desired)?)?;
        let realization: Realization = decode(realization)?;
        ensure!(
            realization.schema == REALIZATION_SCHEMA,
            "unsupported storage-dataset realization"
        );
        ability_value(serde_json::to_value(Context {
            schema: CONTEXT_SCHEMA.into(),
            zfs: realization.zfs.resolve()?,
        })?)
    }

    fn observe(
        &self,
        desired: &AbilityValue,
        _realization: &AbilityValue,
        target: &ResourceReference,
        revision: RevisionId,
        context: &AbilityValue,
    ) -> Result<BackendObservation> {
        let desired_value: Desired = decode(desired)?;
        let context: Context = decode(context)?;
        validate_context(&context)?;
        let full_name = full_dataset_name(&desired_value)?;
        let marker = read_marker(target)?;
        let native = inspect(&context.zfs, &full_name, &desired_value.properties)?;
        let (state_name, ready, released) = classify(
            &desired_value,
            &full_name,
            revision,
            marker.as_ref(),
            &native,
        );
        let evidence = ability_value(json!({
            "schema": OBSERVATION_SCHEMA,
            "expected": desired.as_json(),
            "realized": ready.then(|| desired_value.mountpoint.clone()),
            "state": state_name,
        }))?;
        Ok(BackendObservation {
            evidence,
            ready,
            released,
            path: ready.then_some(desired_value.mountpoint).flatten(),
            unknown: false,
        })
    }

    fn apply(
        &self,
        desired: &AbilityValue,
        _realization: &AbilityValue,
        target: &ResourceReference,
        revision: RevisionId,
        context: &AbilityValue,
        remaining_millis: u64,
    ) -> Result<()> {
        let desired: Desired = decode(desired)?;
        validate_desired(&desired)?;
        let context: Context = decode(context)?;
        validate_context(&context)?;
        let full_name = full_dataset_name(&desired)?;
        if let Some(marker) = read_marker(target)? {
            ensure!(
                marker.dataset == full_name,
                "refusing to retarget an owned mounted dataset"
            );
        }
        let native = inspect(&context.zfs, &full_name, &desired.properties)?;
        let pending = Marker {
            schema: MARKER_SCHEMA.into(),
            revision,
            dataset: full_name.clone(),
            mountpoint: desired.mountpoint.clone(),
            mount_options: desired.mount_options.clone(),
            properties: desired.properties.clone(),
            pending: true,
        };
        write_marker(target, &pending)?;

        if !native.exists {
            let mut arguments = vec!["create".to_string(), "-p".to_string()];
            push_property(
                &mut arguments,
                "mountpoint",
                desired.mountpoint.as_deref().unwrap_or("none"),
            )?;
            for (key, value) in &desired.properties {
                push_property(&mut arguments, key, value)?;
            }
            arguments.push("--".into());
            arguments.push(full_name.clone());
            run_owned(&context.zfs, &arguments, remaining_millis)?;
        } else {
            if desired.mountpoint.is_none() && native.mounted {
                run_success(
                    &context.zfs,
                    &["unmount", "--", &full_name],
                    remaining_millis,
                )?;
            }
            set_property(
                &context.zfs,
                "mountpoint",
                desired.mountpoint.as_deref().unwrap_or("none"),
                &full_name,
                remaining_millis,
            )?;
            for (key, value) in &desired.properties {
                if native.properties.get(key) != Some(value) {
                    set_property(&context.zfs, key, value, &full_name, remaining_millis)?;
                }
            }
        }
        let current = inspect(&context.zfs, &full_name, &desired.properties)?;
        if desired.mountpoint.is_some() && !current.mounted {
            let mut arguments = vec!["mount".to_string()];
            if !desired.mount_options.is_empty() {
                arguments.push("-o".into());
                arguments.push(desired.mount_options.join(","));
            }
            arguments.push("--".into());
            arguments.push(full_name.clone());
            run_owned(&context.zfs, &arguments, remaining_millis)?;
        }
        write_marker(
            target,
            &Marker {
                pending: false,
                ..pending
            },
        )
    }

    fn release(
        &self,
        _desired: &AbilityValue,
        _realization: &AbilityValue,
        target: &ResourceReference,
        context: &AbilityValue,
        remaining_millis: u64,
    ) -> Result<()> {
        let context: Context = decode(context)?;
        validate_context(&context)?;
        if let Some(marker) = read_marker(target)? {
            let native = inspect(&context.zfs, &marker.dataset, &marker.properties)?;
            if native.mounted {
                run_success(
                    &context.zfs,
                    &["unmount", "--", &marker.dataset],
                    remaining_millis,
                )?;
            }
        }
        remove_marker(target)
    }
}

fn classify(
    desired: &Desired,
    full_name: &str,
    revision: RevisionId,
    marker: Option<&Marker>,
    native: &NativeState,
) -> (&'static str, bool, bool) {
    let exact_marker = marker.is_some_and(|marker| {
        marker.revision == revision
            && marker.dataset == full_name
            && marker.mountpoint == desired.mountpoint
            && marker.mount_options == desired.mount_options
            && marker.properties == desired.properties
    });
    let exact_native = native.exists
        && match desired.mountpoint.as_deref() {
            Some(mountpoint) => native.mounted && native.mountpoint.as_deref() == Some(mountpoint),
            None => !native.mounted && native.mountpoint.as_deref() == Some("none"),
        }
        && native.properties == desired.properties;
    let ready = desired.enabled && exact_marker && exact_native;
    let released = marker.is_none();
    let state = if ready {
        "ready"
    } else if marker.is_none() && !native.exists {
        "absent"
    } else if marker.is_none() {
        "unmanaged"
    } else {
        "drifted"
    };
    (state, ready, released)
}

fn inspect(
    zfs: &Executable,
    dataset: &str,
    expected: &BTreeMap<String, String>,
) -> Result<NativeState> {
    let mut property_names = vec!["mounted", "mountpoint"];
    property_names.extend(expected.keys().map(String::as_str));
    let fields = property_names.join(",");
    let output = zfs.run(
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
    zfs: &Executable,
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

fn run_owned(executable: &Executable, arguments: &[String], remaining_millis: u64) -> Result<()> {
    let borrowed = arguments.iter().map(String::as_str).collect::<Vec<_>>();
    run_success(executable, &borrowed, remaining_millis)
}

fn run_success(executable: &Executable, arguments: &[&str], remaining_millis: u64) -> Result<()> {
    let output = executable.run(arguments, remaining_millis)?;
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
        !desired.name.is_empty() && desired.name.len() <= 128,
        "storage-dataset request name is invalid"
    );
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

fn validate_context(context: &Context) -> Result<()> {
    ensure!(
        context.schema == CONTEXT_SCHEMA,
        "unsupported storage-dataset context"
    );
    Ok(())
}

fn read_marker(target: &ResourceReference) -> Result<Option<Marker>> {
    let marker: Marker = match state::read(Path::new(STATE_ROOT), MARKER_DOMAIN, target)? {
        Some(marker) => marker,
        None => return Ok(None),
    };
    ensure!(
        marker.schema == MARKER_SCHEMA,
        "unsupported storage-dataset marker"
    );
    let (pool, dataset) = marker
        .dataset
        .split_once('/')
        .context("storage-dataset marker name is invalid")?;
    validate_pool_name(pool)?;
    validate_dataset_name(dataset)?;
    if let Some(mountpoint) = &marker.mountpoint {
        validate_path(mountpoint)?;
    }
    ensure!(
        marker.mount_options.len() <= 64
            && marker
                .mount_options
                .windows(2)
                .all(|pair| pair[0] < pair[1]),
        "storage-dataset marker mount options are invalid"
    );
    for (key, value) in &marker.properties {
        validate_property(key, value)?;
    }
    Ok(Some(marker))
}

fn write_marker(target: &ResourceReference, marker: &Marker) -> Result<()> {
    state::write(Path::new(STATE_ROOT), MARKER_DOMAIN, target, marker)
}

fn remove_marker(target: &ResourceReference) -> Result<()> {
    state::remove(Path::new(STATE_ROOT), MARKER_DOMAIN, target)
}

fn decode<T: for<'de> Deserialize<'de>>(value: &AbilityValue) -> Result<T> {
    serde_json::from_value(value.as_json().clone()).context("decoding storage-dataset value")
}

#[cfg(test)]
mod tests {
    use aos_contract::Sha256Digest;

    use super::*;

    fn revision(label: &[u8]) -> RevisionId {
        RevisionId(Sha256Digest::of_bytes(label))
    }

    fn desired() -> Desired {
        Desired {
            name: "dataset".into(),
            enabled: true,
            pool: "aos-pool".into(),
            dataset: "var/log".into(),
            mountpoint: Some("/var/log".into()),
            mount_options: vec!["nodev".into(), "nosuid".into()],
            properties: BTreeMap::from([("compression".into(), "zstd-3".into())]),
            prerequisites: vec![],
        }
    }

    fn native() -> NativeState {
        NativeState {
            exists: true,
            mounted: true,
            mountpoint: Some("/var/log".into()),
            properties: BTreeMap::from([("compression".into(), "zstd-3".into())]),
        }
    }

    #[test]
    fn ambient_dataset_is_unmanaged() {
        assert_eq!(
            classify(
                &desired(),
                "aos-pool/var/log",
                revision(b"desired"),
                None,
                &native()
            ),
            ("unmanaged", false, true)
        );
    }

    #[test]
    fn exact_pending_dataset_is_recoverably_ready() {
        let desired = desired();
        let marker = Marker {
            schema: MARKER_SCHEMA.into(),
            revision: revision(b"desired"),
            dataset: "aos-pool/var/log".into(),
            mountpoint: desired.mountpoint.clone(),
            mount_options: desired.mount_options.clone(),
            properties: desired.properties.clone(),
            pending: true,
        };
        assert_eq!(
            classify(
                &desired,
                "aos-pool/var/log",
                revision(b"desired"),
                Some(&marker),
                &native()
            ),
            ("ready", true, false)
        );
    }

    #[test]
    fn unmounted_dataset_is_ready_only_when_mounting_is_disabled() {
        let mut desired = desired();
        desired.mountpoint = None;
        desired.mount_options.clear();
        let marker = Marker {
            schema: MARKER_SCHEMA.into(),
            revision: revision(b"desired"),
            dataset: "aos-pool/var/log".into(),
            mountpoint: None,
            mount_options: vec![],
            properties: desired.properties.clone(),
            pending: false,
        };
        let native = NativeState {
            exists: true,
            mounted: false,
            mountpoint: Some("none".into()),
            properties: desired.properties.clone(),
        };

        assert_eq!(
            classify(
                &desired,
                "aos-pool/var/log",
                revision(b"desired"),
                Some(&marker),
                &native
            ),
            ("ready", true, false)
        );
    }
}
