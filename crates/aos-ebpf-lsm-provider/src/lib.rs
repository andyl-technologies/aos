//! Checked Linux realization of package-selected BPF-LSM policy resources.
//!
//! Native activation resolves immutable policy and BPF object paths and the
//! package-owned loader. Ownership markers bind pins to logical effect identity
//! and revision; teardown removes only the pins established by that effect.

#![forbid(unsafe_code)]

use std::collections::BTreeSet;
use std::fs::{self, OpenOptions};
use std::io::{Read as _, Write as _};
use std::os::unix::fs::{OpenOptionsExt as _, PermissionsExt as _};
use std::path::{Path, PathBuf};
use std::time::Instant;

use anyhow::{Context as _, Result, bail, ensure};
use aos_ability_runtime::activation::{Action, Invocation};
use aos_contract::Sha256Digest;
use serde::{Deserialize, Serialize};

mod native;

use native::{Executable, path_text, resolve_artifact_path};

const CONTEXT_SCHEMA: &str = "aos.linux.ebpf-lsm-policy-context/v1";
const MARKER_SCHEMA: &str = "aos.linux.ebpf-lsm-policy-state/v1";
const STORE_ROOT: &str = "/nix/store";
const PIN_ROOT: &str = "/sys/fs/bpf/aos/lsm";
const STATE_ROOT: &str = "/run/aos/ebpf-lsm-policy";
const MAX_MARKER_BYTES: u64 = 256 * 1024;
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct PolicySelection {
    name: String,
    policy: String,
    object: String,
    programs: Vec<String>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct PolicySetRequest {
    policies: Vec<PolicySelection>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct ResolvedPolicy {
    name: String,
    policy: PathBuf,
    object: PathBuf,
    programs: Vec<String>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct ProviderContext {
    schema: String,
    loader: Executable,
    pin_directory: PathBuf,
    policies: Vec<ResolvedPolicy>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct StateMarker {
    schema: String,
    revision: String,
    pins: Vec<String>,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
enum PolicyState {
    Absent,
    Applied,
    Drifted,
    Unknown,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct PolicyObservation {
    schema: String,
    expected: PolicySetRequest,
    state: PolicyState,
    loaded: Vec<String>,
}

/// Handles one package-owned BPF-LSM policy resource.
pub struct EbpfLsmProvider {
    immutable_root: PathBuf,
    pin_root: PathBuf,
    state_root: PathBuf,
}

impl EbpfLsmProvider {
    /// Constructs the production provider over the immutable store and bpffs.
    #[must_use]
    pub fn production() -> Self {
        Self {
            immutable_root: STORE_ROOT.into(),
            pin_root: PIN_ROOT.into(),
            state_root: STATE_ROOT.into(),
        }
    }

    #[cfg(test)]
    fn for_test(immutable_root: PathBuf, pin_root: PathBuf, state_root: PathBuf) -> Self {
        Self {
            immutable_root,
            pin_root,
            state_root,
        }
    }

    /// Executes or observes one native activation invocation.
    ///
    /// # Errors
    /// Returns an error for invalid inputs, immutable artifacts, ownership
    /// conflicts, or failed loader execution.
    pub fn handle(&self, purpose: &str, input: &[u8]) -> Result<Vec<u8>> {
        let invocation: Invocation =
            aos_contract::canonical::from_slice(input, "BPF-LSM invocation")?;
        ensure!(
            matches!(purpose, "apply" | "remove" | "observe"),
            "unsupported native purpose"
        );
        ensure!(
            purpose == "observe" || (purpose == "apply") == (invocation.action == Action::Apply),
            "action differs from argv"
        );
        let desired: PolicySetRequest = serde_json::from_value(invocation.input.clone())?;
        validate_request(&desired)?;
        let context = self.resolve_context(&desired)?;
        let output = match purpose {
            "apply" => {
                self.apply(
                    &context,
                    &invocation.id,
                    invocation.revision.clone(),
                    invocation.effect.timeout_ms,
                )?;
                let observation = self.observe(
                    "aos.security.ebpf-lsm-observation/v1",
                    &desired,
                    &context,
                    &invocation.id,
                    &invocation.revision,
                )?;
                ensure!(
                    observation.state == PolicyState::Applied,
                    "policy pins did not converge"
                );
                serde_json::json!({"loaded": observation.loaded})
            }
            "remove" => {
                self.remove(&invocation.id)?;
                serde_json::json!({})
            }
            _ => {
                let observation = self.observe(
                    "aos.security.ebpf-lsm-observation/v1",
                    &desired,
                    &context,
                    &invocation.id,
                    &invocation.revision,
                )?;
                match (invocation.action, observation.state) {
                    (_, PolicyState::Absent) => serde_json::json!({"status":"absent"}),
                    (Action::Apply, PolicyState::Applied) => {
                        serde_json::json!({"status":"current","outputs":{"loaded":observation.loaded}})
                    }
                    (_, PolicyState::Drifted) | (Action::Remove, PolicyState::Applied) => {
                        serde_json::json!({"status":"retry-safe"})
                    }
                    (_, PolicyState::Unknown) => serde_json::json!({"status":"indeterminate"}),
                }
            }
        };
        aos_contract::canonical::canonical_json(&output)
    }

    fn resolve_context(&self, desired: &PolicySetRequest) -> Result<ProviderContext> {
        let loader = Executable::from_process(&self.immutable_root)?;
        let policies = desired
            .policies
            .iter()
            .map(|policy| self.resolve_policy(policy))
            .collect::<Result<Vec<_>>>()?;
        Ok(ProviderContext {
            schema: CONTEXT_SCHEMA.into(),
            loader,
            pin_directory: self.pin_root.clone(),
            policies,
        })
    }

    fn resolve_policy(&self, policy: &PolicySelection) -> Result<ResolvedPolicy> {
        Ok(ResolvedPolicy {
            name: policy.name.clone(),
            policy: resolve_artifact_path(&policy.policy, &self.immutable_root)?,
            object: resolve_artifact_path(&policy.object, &self.immutable_root)?,
            programs: policy.programs.clone(),
        })
    }

    fn observe(
        &self,
        observation_schema: &str,
        desired: &PolicySetRequest,
        context: &ProviderContext,
        target: &str,
        desired_revision: &str,
    ) -> Result<PolicyObservation> {
        let marker = self.read_marker(target)?;
        let expected_pins = pin_names(&context.policies);
        let present = expected_pins
            .iter()
            .filter(|pin| context.pin_directory.join(pin).exists())
            .cloned()
            .collect::<BTreeSet<_>>();
        let expected = expected_pins.iter().cloned().collect::<BTreeSet<_>>();
        let owned = marker.as_ref().is_some_and(|marker| {
            marker.revision == desired_revision
                && marker.pins.iter().cloned().collect::<BTreeSet<_>>() == expected
        });
        let state = if marker.is_none() && present.is_empty() {
            PolicyState::Absent
        } else if marker.is_none() {
            PolicyState::Unknown
        } else if owned && present == expected {
            PolicyState::Applied
        } else {
            PolicyState::Drifted
        };
        let loaded = context
            .policies
            .iter()
            .filter(|policy| {
                policy
                    .programs
                    .iter()
                    .all(|program| present.contains(&pin_name(&policy.name, program)))
            })
            .map(|policy| policy.name.clone())
            .collect();
        Ok(PolicyObservation {
            schema: observation_schema.into(),
            expected: desired.clone(),
            state,
            loaded,
        })
    }

    fn apply(
        &self,
        context: &ProviderContext,
        target: &str,
        revision: String,
        remaining_millis: u64,
    ) -> Result<()> {
        let marker = self.read_marker(target)?;
        let pins = pin_names(&context.policies);
        if marker.is_none()
            && pins
                .iter()
                .any(|pin| context.pin_directory.join(pin).exists())
        {
            bail!("refusing to replace unmanaged BPF-LSM pins");
        }
        if let Some(marker) = marker {
            remove_pins(&context.pin_directory, &marker.pins)?;
        }
        self.write_marker(
            target,
            &StateMarker {
                schema: MARKER_SCHEMA.into(),
                revision,
                pins,
            },
        )?;

        let started = Instant::now();
        for policy in &context.policies {
            let remaining = remaining_millis
                .saturating_sub(u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX));
            let output = context.loader.run(
                &[
                    "load",
                    "--policy",
                    path_text(&policy.policy)?,
                    "--object",
                    path_text(&policy.object)?,
                    "--pin-dir",
                    path_text(&context.pin_directory)?,
                ],
                remaining,
            )?;
            ensure!(
                output.status.success(),
                "BPF-LSM loader rejected policy {}: {}",
                policy.name,
                String::from_utf8_lossy(&output.stderr)
            );
        }
        Ok(())
    }

    fn remove(&self, target: &str) -> Result<()> {
        let Some(marker) = self.read_marker(target)? else {
            return Ok(());
        };
        remove_pins(&self.pin_root, &marker.pins)?;
        match fs::remove_file(self.marker_path(target)?) {
            Ok(()) => Ok(()),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(error) => Err(error).context("removing BPF-LSM ownership marker"),
        }
    }

    fn marker_path(&self, target: &str) -> Result<PathBuf> {
        let digest = Sha256Digest::of_canonical("aos.linux.ebpf-lsm-policy-resource/v1", &target)?;
        Ok(self
            .state_root
            .join(digest.to_string().trim_start_matches("sha256:")))
    }

    fn read_marker(&self, target: &str) -> Result<Option<StateMarker>> {
        let file = match fs::File::open(self.marker_path(target)?) {
            Ok(file) => file,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(error) => return Err(error).context("opening BPF-LSM ownership marker"),
        };
        let mut bytes = Vec::new();
        file.take(MAX_MARKER_BYTES + 1)
            .read_to_end(&mut bytes)
            .context("reading bounded BPF-LSM ownership marker")?;
        ensure!(
            u64::try_from(bytes.len()).unwrap_or(u64::MAX) <= MAX_MARKER_BYTES,
            "BPF-LSM ownership marker exceeds its document bound"
        );
        let marker: StateMarker =
            aos_contract::canonical::from_slice(&bytes, "BPF-LSM ownership marker")?;
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
        Ok(())
    }
}

fn validate_request(request: &PolicySetRequest) -> Result<()> {
    ensure!(
        !request.policies.is_empty() && request.policies.len() <= 64,
        "BPF-LSM policy set must contain 1..=64 policies"
    );
    let mut names = BTreeSet::new();
    let mut pins = BTreeSet::new();
    for policy in &request.policies {
        ensure!(safe_name(&policy.name), "invalid BPF-LSM policy name");
        ensure!(names.insert(&policy.name), "duplicate BPF-LSM policy name");
        ensure!(
            !policy.programs.is_empty() && policy.programs.len() <= 64,
            "BPF-LSM policy must select 1..=64 programs"
        );
        ensure!(
            policy.programs.windows(2).all(|pair| pair[0] < pair[1]),
            "BPF-LSM program names are not canonical and unique"
        );
        for program in &policy.programs {
            ensure!(safe_name(program), "invalid BPF-LSM program name");
            ensure!(
                pins.insert(pin_name(&policy.name, program)),
                "BPF-LSM policies produce a duplicate pin"
            );
        }
    }
    ensure!(
        request
            .policies
            .windows(2)
            .all(|pair| pair[0].name < pair[1].name),
        "BPF-LSM policies are not in canonical name order"
    );
    Ok(())
}

fn validate_marker(marker: &StateMarker) -> Result<()> {
    ensure!(marker.schema == MARKER_SCHEMA, "unsupported marker schema");
    ensure!(
        !marker.pins.is_empty() && marker.pins.len() <= 4096,
        "BPF-LSM marker has an invalid pin set"
    );
    ensure!(
        marker.pins.windows(2).all(|pair| pair[0] < pair[1]),
        "BPF-LSM marker pins are not canonical and unique"
    );
    ensure!(
        marker.pins.iter().all(|pin| safe_pin_name(pin)),
        "BPF-LSM marker contains an invalid pin name"
    );
    Ok(())
}

fn safe_name(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-' | b'.'))
}

fn safe_pin_name(value: &str) -> bool {
    value.len() <= 257 && safe_name(value)
}

fn pin_name(policy: &str, program: &str) -> String {
    format!("{policy}-{program}")
}

fn pin_names(policies: &[ResolvedPolicy]) -> Vec<String> {
    let mut pins = policies
        .iter()
        .flat_map(|policy| {
            policy
                .programs
                .iter()
                .map(|program| pin_name(&policy.name, program))
        })
        .collect::<Vec<_>>();
    pins.sort();
    pins
}

fn remove_pins(pin_root: &Path, pins: &[String]) -> Result<()> {
    for pin in pins {
        ensure!(
            safe_pin_name(pin),
            "refusing to remove an invalid BPF pin name"
        );
        match fs::remove_file(pin_root.join(pin)) {
            Ok(()) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(error).with_context(|| format!("removing BPF pin {pin}")),
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    fn target() -> String {
        "test-host-policy".into()
    }

    fn policy(root: &Path) -> PolicySelection {
        PolicySelection {
            name: "audit".into(),
            policy: root
                .join("share/policy.json")
                .to_string_lossy()
                .into_owned(),
            object: root.join("lib/policy.bpf.o").to_string_lossy().into_owned(),
            programs: vec!["file_mprotect".into()],
        }
    }

    #[test]
    fn selected_artifacts_and_owned_pins_are_exact() {
        let temporary = tempdir().expect("temporary directory");
        let immutable = temporary.path().join("store");
        let package = immutable.join("package");
        let pins = temporary.path().join("pins");
        let state = temporary.path().join("state");
        fs::create_dir_all(package.join("share")).expect("policy directory");
        fs::create_dir_all(package.join("lib")).expect("object directory");
        fs::create_dir_all(&pins).expect("pin directory");
        fs::write(package.join("share/policy.json"), b"{}").expect("policy");
        fs::write(package.join("lib/policy.bpf.o"), b"bpf").expect("object");
        let provider = EbpfLsmProvider::for_test(immutable, pins.clone(), state);
        let resolved = provider
            .resolve_policy(&policy(&package))
            .expect("resolve policy");
        assert_eq!(resolved.policy, package.join("share/policy.json"));
        assert_eq!(resolved.object, package.join("lib/policy.bpf.o"));

        let owned = pin_name("audit", "file_mprotect");
        fs::write(pins.join(&owned), b"pin").expect("owned pin");
        fs::write(pins.join("another-owner"), b"pin").expect("foreign pin");
        provider
            .write_marker(
                &target(),
                &StateMarker {
                    schema: MARKER_SCHEMA.into(),
                    revision: "revision".into(),
                    pins: vec![owned.clone()],
                },
            )
            .expect("write marker");
        provider.remove(&target()).expect("remove resource");
        assert!(!pins.join(owned).exists());
        assert!(pins.join("another-owner").exists());
    }

    #[test]
    fn artifact_paths_cannot_escape_the_selected_package() {
        let temporary = tempdir().expect("temporary directory");
        let immutable = temporary.path().join("store");
        let package = immutable.join("package");
        fs::create_dir_all(&package).expect("package directory");
        fs::write(temporary.path().join("outside"), b"outside").expect("outside file");
        let reference = package.join("../outside").to_string_lossy().into_owned();
        assert!(resolve_artifact_path(&reference, &immutable).is_err());
    }

    #[test]
    fn duplicate_pin_identity_is_rejected() {
        let request = PolicySetRequest {
            policies: vec![
                PolicySelection {
                    name: "a-b".into(),
                    programs: vec!["c".into()],
                    ..policy(Path::new("/nix/store/test"))
                },
                PolicySelection {
                    name: "a".into(),
                    programs: vec!["b-c".into()],
                    ..policy(Path::new("/nix/store/test"))
                },
            ],
        };
        assert!(validate_request(&request).is_err());
    }
}
