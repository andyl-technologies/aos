//! Native Linux kernel-tunable operations with durable baseline restoration.
//!
//! Each effect saves displaced procfs values before writing. Reconfiguration
//! restores keys removed from the desired map; teardown restores every baseline.
//! Pending restoration remains in the marker until its writes have completed.

#![forbid(unsafe_code)]

use std::collections::{BTreeMap, BTreeSet};
use std::fs::{self, OpenOptions};
use std::io::{self, Read as _, Write as _};
use std::os::unix::fs::{OpenOptionsExt as _, PermissionsExt as _};
use std::path::{Path, PathBuf};

use anyhow::{Context as _, Result, bail, ensure};
use aos_contract::Sha256Digest;
use serde::{Deserialize, Serialize};
use serde_json::json;

const MARKER_SCHEMA: &str = "aos.kernel.tunables-native-state/v1";
const PROC_ROOT: &str = "/proc/sys";
const STATE_ROOT: &str = "/run/aos/kernel-tunables";
const MAX_MARKER_BYTES: u64 = 256 * 1024;

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct TunableRequest {
    values: BTreeMap<String, String>,
}

#[derive(Deserialize)]
struct Invocation {
    id: String,
    revision: String,
    action: String,
    input: TunableRequest,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct StateMarker {
    schema: String,
    revision: String,
    baseline: BTreeMap<String, String>,
    managed: BTreeSet<String>,
    pending_restore: BTreeSet<String>,
}

/// Converges Linux procfs tunables and retains the values it displaced.
pub struct KernelTunableProvider {
    proc_root: PathBuf,
    state_root: PathBuf,
}

impl KernelTunableProvider {
    /// Constructs a provider for the production procfs and runtime state paths.
    #[must_use]
    pub fn production() -> Self {
        Self {
            proc_root: PROC_ROOT.into(),
            state_root: STATE_ROOT.into(),
        }
    }

    /// Executes one native apply, remove, or observe invocation.
    ///
    /// # Errors
    /// Returns an error for malformed input, invalid tunables, unreadable state,
    /// or unsuccessful procfs writes and baseline restoration.
    pub fn handle(&self, purpose: &str, input: &[u8]) -> Result<Vec<u8>> {
        ensure!(
            input.len() <= 256 * 1024,
            "invocation exceeds its byte bound"
        );
        let invocation: Invocation = serde_json::from_slice(input)?;
        validate_request(&invocation.input)?;
        ensure!(
            !invocation.id.is_empty() && invocation.id.len() <= 128,
            "invalid effect identity"
        );
        ensure!(
            matches!(invocation.action.as_str(), "apply" | "remove"),
            "invalid action"
        );
        ensure!(
            !invocation.revision.is_empty() && invocation.revision.len() <= 128,
            "invalid revision"
        );
        ensure!(
            purpose == "observe" || purpose == invocation.action,
            "action differs from argv"
        );

        let response = match purpose {
            "apply" => {
                self.apply(&invocation.input, &invocation.id, invocation.revision)?;
                let values = self.observed_values(&invocation.input)?;
                ensure!(
                    values == invocation.input.values,
                    "kernel did not retain requested tunables"
                );
                json!({"values": values})
            }
            "remove" => {
                self.remove(&invocation.id)?;
                json!({})
            }
            "observe" => {
                let marker = self.read_marker(&invocation.id)?;
                if invocation.action == "remove" {
                    json!({"status": if marker.is_none() { "absent" } else { "retry-safe" }})
                } else {
                    let values = self.observed_values(&invocation.input)?;
                    let complete = marker.is_some_and(|marker| {
                        marker.revision == invocation.revision
                            && marker.pending_restore.is_empty()
                            && marker.managed == invocation.input.values.keys().cloned().collect()
                    }) && values == invocation.input.values;
                    if complete {
                        json!({"status": "current", "outputs": {"values": values}})
                    } else {
                        json!({"status": "retry-safe"})
                    }
                }
            }
            _ => bail!("unsupported operation {purpose:?}"),
        };

        serde_json::to_vec(&response).context("encoding native handler response")
    }

    fn observed_values(&self, desired: &TunableRequest) -> Result<BTreeMap<String, String>> {
        desired
            .values
            .keys()
            .map(|key| {
                let value = fs::read_to_string(self.tunable_path(key))
                    .with_context(|| format!("reading tunable {key}"))?
                    .trim_end_matches(['\n', '\r'])
                    .to_string();
                Ok((key.clone(), value))
            })
            .collect()
    }

    fn apply(&self, desired: &TunableRequest, target: &str, revision: String) -> Result<()> {
        let mut marker = match self.read_marker(target)? {
            Some(mut marker) => {
                marker.revision = revision;
                marker
            }
            None => StateMarker {
                schema: MARKER_SCHEMA.into(),
                revision,
                baseline: BTreeMap::new(),
                managed: BTreeSet::new(),
                pending_restore: BTreeSet::new(),
            },
        };

        for key in desired.values.keys() {
            if !marker.baseline.contains_key(key) {
                let baseline = fs::read_to_string(self.tunable_path(key))
                    .with_context(|| format!("reading baseline for {key}"))?
                    .trim_end_matches(['\n', '\r'])
                    .to_string();
                marker.baseline.insert(key.clone(), baseline);
            }
        }
        let desired_keys = desired.values.keys().cloned().collect::<BTreeSet<_>>();
        // A retry may reintroduce a key whose earlier restoration was pending.
        // Keep its original baseline, but let the new desired value own it.
        marker
            .pending_restore
            .retain(|key| !desired_keys.contains(key));
        marker
            .pending_restore
            .extend(marker.managed.difference(&desired_keys).cloned());
        marker.managed = desired_keys;
        self.write_marker(target, &marker)?;

        for key in &marker.pending_restore {
            let baseline = marker
                .baseline
                .get(key)
                .with_context(|| format!("missing baseline for {key}"))?;
            write_tunable(&self.tunable_path(key), baseline)
                .with_context(|| format!("restoring removed tunable {key}"))?;
        }
        for key in &marker.pending_restore {
            marker.baseline.remove(key);
        }
        marker.pending_restore.clear();
        self.write_marker(target, &marker)?;

        for (key, value) in &desired.values {
            write_tunable(&self.tunable_path(key), value)
                .with_context(|| format!("writing tunable {key}"))?;
        }
        Ok(())
    }

    fn remove(&self, target: &str) -> Result<()> {
        let Some(marker) = self.read_marker(target)? else {
            return Ok(());
        };
        for (key, value) in &marker.baseline {
            write_tunable(&self.tunable_path(key), value)
                .with_context(|| format!("restoring tunable {key}"))?;
        }
        match fs::remove_file(self.marker_path(target)?) {
            Ok(()) => {
                fs::File::open(&self.state_root)?.sync_all()?;
                Ok(())
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
            Err(error) => Err(error).context("removing kernel-tunable state marker"),
        }
    }

    fn tunable_path(&self, key: &str) -> PathBuf {
        self.proc_root.join(key.replace('.', "/"))
    }

    fn marker_path(&self, target: &str) -> Result<PathBuf> {
        let digest = Sha256Digest::of_canonical("aos.kernel.tunables-resource/v1", &target)?;
        Ok(self
            .state_root
            .join(digest.to_string().trim_start_matches("sha256:")))
    }

    fn read_marker(&self, target: &str) -> Result<Option<StateMarker>> {
        let path = self.marker_path(target)?;
        let file = match fs::File::open(path) {
            Ok(file) => file,
            Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
            Err(error) => return Err(error).context("reading kernel-tunable state marker"),
        };
        let mut bytes = Vec::new();
        file.take(MAX_MARKER_BYTES + 1)
            .read_to_end(&mut bytes)
            .context("reading bounded kernel-tunable state marker")?;
        ensure!(
            u64::try_from(bytes.len()).unwrap_or(u64::MAX) <= MAX_MARKER_BYTES,
            "kernel-tunable state marker exceeds its document bound"
        );
        let marker: StateMarker =
            aos_contract::canonical::from_slice(&bytes, "kernel-tunable marker")?;
        validate_marker(&marker)?;
        Ok(Some(marker))
    }

    fn write_marker(&self, target: &str, marker: &StateMarker) -> Result<()> {
        validate_marker(marker)?;
        fs::create_dir_all(&self.state_root)?;
        fs::set_permissions(&self.state_root, fs::Permissions::from_mode(0o700))?;
        let path = self.marker_path(target)?;
        let temporary = path.with_extension("tmp");
        let bytes = aos_contract::canonical::canonical_json(&serde_json::to_value(marker)?)?;
        let mut file = OpenOptions::new()
            .create(true)
            .truncate(true)
            .write(true)
            .mode(0o600)
            .open(&temporary)?;
        file.write_all(&bytes)?;
        file.sync_all()?;
        fs::rename(temporary, path)?;
        fs::File::open(&self.state_root)?.sync_all()?;
        Ok(())
    }
}

fn write_tunable(path: &Path, value: &str) -> Result<()> {
    ensure!(
        !value.contains(['\n', '\r', '\0']),
        "tunable value contains a forbidden byte"
    );
    fs::write(path, format!("{value}\n")).context("writing procfs tunable")
}

fn validate_request(request: &TunableRequest) -> Result<()> {
    ensure!(
        !request.values.is_empty() && request.values.len() <= 256,
        "invalid tunable count"
    );
    for (key, value) in &request.values {
        ensure!(valid_tunable_key(key), "invalid tunable key {key:?}");
        ensure!(
            value.len() <= 4096 && !value.contains(['\n', '\r', '\0']),
            "invalid tunable value"
        );
    }
    Ok(())
}
fn validate_marker(marker: &StateMarker) -> Result<()> {
    ensure!(marker.schema == MARKER_SCHEMA, "unsupported marker schema");
    ensure!(
        !marker.managed.is_empty(),
        "state marker must own at least one tunable"
    );
    ensure!(
        marker.managed.len() <= 256
            && marker.pending_restore.len() <= 256
            && marker.baseline.len() <= 512,
        "state marker exceeds tunable bounds"
    );
    ensure!(
        marker.managed.is_disjoint(&marker.pending_restore),
        "managed and pending-restore tunables overlap"
    );

    let tracked = marker
        .managed
        .union(&marker.pending_restore)
        .cloned()
        .collect::<BTreeSet<_>>();
    ensure!(
        marker.baseline.keys().cloned().collect::<BTreeSet<_>>() == tracked,
        "state marker baselines differ from tracked tunables"
    );
    for (key, value) in &marker.baseline {
        ensure!(
            valid_tunable_key(key),
            "invalid persisted tunable key {key:?}"
        );
        ensure!(
            value.len() <= 4096 && !value.contains(['\n', '\r', '\0']),
            "invalid persisted tunable value"
        );
    }
    Ok(())
}

fn valid_tunable_key(key: &str) -> bool {
    !key.is_empty()
        && key.len() <= 128
        && !key.starts_with('.')
        && !key.ends_with('.')
        && !key.contains("..")
        && key
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::Value;
    use tempfile::{TempDir, tempdir};

    fn fixture() -> (TempDir, KernelTunableProvider) {
        let root = tempdir().unwrap();
        let provider = KernelTunableProvider {
            proc_root: root.path().join("proc"),
            state_root: root.path().join("state"),
        };
        fs::create_dir_all(provider.proc_root.join("vm")).unwrap();
        fs::write(provider.proc_root.join("vm/swappiness"), "60\n").unwrap();
        fs::write(provider.proc_root.join("vm/max_map_count"), "65530\n").unwrap();
        (root, provider)
    }

    fn invoke(
        provider: &KernelTunableProvider,
        purpose: &str,
        action: &str,
        revision: &str,
        values: Value,
    ) -> Value {
        let input = serde_json::to_vec(&json!({
            "id": "stable-effect", "revision": revision, "action": action,
            "effect": {}, "previous": null, "input": {"values": values}
        }))
        .unwrap();
        serde_json::from_slice(&provider.handle(purpose, &input).unwrap()).unwrap()
    }

    #[test]
    fn reconfiguration_restores_removed_keys_and_teardown_restores_baselines() {
        let (_root, provider) = fixture();
        invoke(
            &provider,
            "apply",
            "apply",
            "one",
            json!({
                "vm.swappiness": "10", "vm.max_map_count": "1048576"
            }),
        );

        invoke(
            &provider,
            "apply",
            "apply",
            "two",
            json!({"vm.swappiness": "20"}),
        );
        assert_eq!(
            fs::read_to_string(provider.proc_root.join("vm/max_map_count")).unwrap(),
            "65530\n"
        );
        assert_eq!(
            invoke(
                &provider,
                "observe",
                "apply",
                "two",
                json!({"vm.swappiness": "20"})
            )["status"],
            "current"
        );

        invoke(
            &provider,
            "remove",
            "remove",
            "two",
            json!({"vm.swappiness": "20"}),
        );
        assert_eq!(
            fs::read_to_string(provider.proc_root.join("vm/swappiness")).unwrap(),
            "60\n"
        );
        assert_eq!(
            invoke(
                &provider,
                "observe",
                "remove",
                "two",
                json!({"vm.swappiness": "20"})
            )["status"],
            "absent"
        );
    }

    #[test]
    fn interrupted_write_is_observed_before_retry_without_losing_baseline() {
        let (_root, provider) = fixture();
        let desired = TunableRequest {
            values: BTreeMap::from([("vm.swappiness".into(), "10".into())]),
        };
        provider
            .write_marker(
                "stable-effect",
                &StateMarker {
                    schema: MARKER_SCHEMA.into(),
                    revision: "one".into(),
                    baseline: BTreeMap::from([("vm.swappiness".into(), "60".into())]),
                    managed: BTreeSet::from(["vm.swappiness".into()]),
                    pending_restore: BTreeSet::new(),
                },
            )
            .unwrap();

        assert_eq!(
            invoke(
                &provider,
                "observe",
                "apply",
                "one",
                json!({"vm.swappiness": "10"})
            )["status"],
            "retry-safe"
        );
        provider
            .apply(&desired, "stable-effect", "one".into())
            .unwrap();
        provider.remove("stable-effect").unwrap();
        assert_eq!(
            fs::read_to_string(provider.proc_root.join("vm/swappiness")).unwrap(),
            "60\n"
        );
    }

    #[test]
    fn malformed_keys_fail_before_any_mutation() {
        let (_root, provider) = fixture();
        let input = serde_json::to_vec(&json!({
            "id": "stable-effect", "revision": "one", "action": "apply",
            "input": {"values": {"vm.swappiness": "10", "../escape": "x"}}
        }))
        .unwrap();

        assert!(provider.handle("apply", &input).is_err());
        assert_eq!(
            fs::read_to_string(provider.proc_root.join("vm/swappiness")).unwrap(),
            "60\n"
        );
        assert!(!provider.state_root.exists());
    }
}
