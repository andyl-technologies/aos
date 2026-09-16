//! Checked Linux realization of package-selected BPF network policy resources.
//!
//! The provider accepts immutable policy and BPF object artifact references
//! from the selected package contract. Admission resolves those references and
//! the package-owned loader once, then effect execution loads or removes only
//! the exact pins owned by the admitted resource.

#![forbid(unsafe_code)]

use std::collections::{BTreeMap, BTreeSet};
use std::fs::{self, OpenOptions};
use std::io::{Read as _, Write as _};
use std::os::unix::fs::{OpenOptionsExt as _, PermissionsExt as _};
use std::path::{Path, PathBuf};
use std::time::Instant;

use anyhow::{Context as _, Result, bail, ensure};
use aos_ability_model::{
    AbilityValue, AccessMode, LocalKey, MethodSemantics, ResourceReference, RevisionId,
};
use aos_contract::Sha256Digest;
use aos_provider_protocol::{
    ADMISSION_REQUEST_SCHEMA, ADMISSION_SCHEMA, AdmissionDisposition, AdmissionRequest,
    AdmissionResult, AdmissionRevision, BoundNativeContext, INVOCATION_SCHEMA, Invocation,
    InvocationDisposition, InvocationPurpose, InvocationResult, RESULT_SCHEMA, ResourceContext,
    SupportedPurposes, resource_set_digest, validate_admission_resource, validate_resource_context,
    validate_resource_contexts,
};
use serde::{Deserialize, Serialize};

mod native;

use native::{
    ArtifactPathReference, Executable, ExecutableReference, path_text, resolve_artifact_path,
};

const CONTEXT_SCHEMA: &str = "aos.linux.ebpf-net-policy-context/v1";
const MARKER_SCHEMA: &str = "aos.linux.ebpf-net-policy-state/v1";
const STORE_ROOT: &str = "/nix/store";
const PIN_ROOT: &str = "/sys/fs/bpf/aos/network";
const STATE_ROOT: &str = "/run/aos/ebpf-net-policy";
const MAX_MARKER_BYTES: u64 = 256 * 1024;
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct PolicySelection {
    name: String,
    cgroup: String,
    policy: ArtifactPathReference,
    object: ArtifactPathReference,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct PolicySetRequest {
    policies: Vec<PolicySelection>,
    prerequisites: Vec<ResourceReference>,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Realization {
    schema: String,
    loader: ExecutableReference,
    pin_directory: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct ResolvedPolicy {
    name: String,
    cgroup: PathBuf,
    policy: PathBuf,
    object: PathBuf,
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
    revision: RevisionId,
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

/// Handles one package-owned BPF network policy resource.
pub struct EbpfNetPolicyProvider {
    immutable_root: PathBuf,
    pin_root: PathBuf,
    state_root: PathBuf,
}

impl EbpfNetPolicyProvider {
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

    /// Handles one bounded command invocation and emits canonical JSON.
    ///
    /// # Errors
    ///
    /// Returns an error when the invocation, resource authority, immutable
    /// artifact paths, selected loader, pin ownership, or native effect fails
    /// validation.
    pub fn handle(&self, purpose: &str, input: &[u8]) -> Result<Vec<u8>> {
        let result = match purpose {
            "admit" => {
                let request: AdmissionRequest =
                    aos_contract::canonical::from_slice(input, "BPF network admission request")?;
                ensure!(
                    request.schema == ADMISSION_REQUEST_SCHEMA,
                    "unsupported admission schema"
                );
                serde_json::to_value(self.admit(request)?)?
            }
            "effect" | "reconcile" | "cancel" | "compensate" | "reconcile-compensation" => {
                let invocation: Invocation =
                    aos_contract::canonical::from_slice(input, "BPF network invocation")?;
                ensure!(
                    invocation.schema == INVOCATION_SCHEMA,
                    "unsupported invocation schema"
                );
                ensure!(
                    purpose == purpose_name(invocation.purpose),
                    "purpose differs from argv"
                );
                serde_json::to_value(self.invoke(invocation)?)?
            }
            _ => bail!("unsupported command-handler purpose {purpose:?}"),
        };

        aos_contract::canonical::canonical_json(&result)
            .context("encoding canonical BPF network response")
    }

    fn admit(&self, request: AdmissionRequest) -> Result<AdmissionResult> {
        validate_method(request.method.method.as_str(), &request.semantics)?;
        validate_admission_resource(&request)?;
        validate_resource_contexts(&request.resources)?;
        let observation_schema = request
            .contract
            .observation_discriminator()
            .context("selected BPF network method has no observation discriminator")?;
        let desired: PolicySetRequest = decode_value(&request.resource_spec.value)?;
        validate_request(&desired)?;
        require_prerequisites(&desired.prerequisites, &request.resources)?;
        let context = self.resolve_context(&desired, &request.resource_spec.realization)?;
        let observation = self.observe(
            observation_schema,
            &desired,
            &context,
            &request.target,
            request.resource_spec.revision,
        )?;
        let revision = observation_revision(&observation, request.resource_spec.revision)?;
        let supported_purposes = if request.method.method.as_str() == "observe" {
            SupportedPurposes::from_ordered(vec![InvocationPurpose::Effect])
        } else {
            SupportedPurposes::from_ordered(vec![
                InvocationPurpose::Effect,
                InvocationPurpose::Reconcile,
                InvocationPurpose::Cancel,
            ])
        }
        .context("constructing canonical purpose support")?;

        Ok(AdmissionResult {
            schema: ADMISSION_SCHEMA.into(),
            disposition: AdmissionDisposition::Admitted,
            revision,
            incarnation: Some(request.assignment.incarnation),
            observation: ability_value(serde_json::to_value(observation)?)?,
            native_context: ability_value(serde_json::to_value(context)?)?,
            supported_purposes,
        })
    }

    fn invoke(&self, invocation: Invocation) -> Result<InvocationResult> {
        ensure!(
            invocation.method_is_bound(),
            "invocation method is not durably bound"
        );
        validate_method(invocation.method.method.as_str(), &invocation.semantics)?;
        let observation_schema = invocation
            .contract
            .observation_discriminator()
            .context("selected BPF network method has no observation discriminator")?;
        validate_resource_contexts(&invocation.request.resources)?;
        ensure!(
            resource_set_digest(&invocation.request.resources)?
                == invocation.request.native_context_digest,
            "resource contexts differ from their authenticated set digest"
        );
        let target = require_resource(&invocation.request.resources, &invocation.request.target)?;
        let bound: BoundNativeContext = validate_resource_context(target)?;
        ensure!(
            invocation.method.interface == invocation.request.method.interface
                && invocation
                    .request
                    .target
                    .operations
                    .binary_search(&invocation.method.method)
                    .is_ok(),
            "invocation method is outside the target resource authority"
        );
        ensure!(
            bound.resource_spec.value == invocation.request.inputs,
            "bound inputs differ"
        );
        let desired: PolicySetRequest = decode_value(&bound.resource_spec.value)?;
        validate_request(&desired)?;
        require_prerequisites(&desired.prerequisites, &invocation.request.resources)?;
        let context: ProviderContext = decode_value(&bound.provider_context)?;
        self.validate_context(&desired, &bound.resource_spec.realization, &context)?;
        let before = self.observe(
            observation_schema,
            &desired,
            &context,
            &invocation.request.target,
            bound.resource_spec.revision,
        )?;
        let removing = invocation.method.method.as_str() == "remove";
        let (disposition, evidence) = match invocation.purpose {
            InvocationPurpose::Effect if invocation.method.method.as_str() == "observe" => {
                (InvocationDisposition::Completed, before)
            }
            InvocationPurpose::Effect if invocation.control.cancelled => {
                (InvocationDisposition::RejectedBeforeEffect, before)
            }
            InvocationPurpose::Effect if invocation.method.method.as_str() == "apply" => {
                self.apply(
                    &context,
                    &invocation.request.target,
                    bound.resource_spec.revision,
                    invocation.control.attempt_remaining_millis,
                )?;
                let after = self.observe(
                    observation_schema,
                    &desired,
                    &context,
                    &invocation.request.target,
                    bound.resource_spec.revision,
                )?;
                let disposition = if after.state == PolicyState::Applied {
                    InvocationDisposition::Completed
                } else {
                    InvocationDisposition::Indeterminate
                };
                (disposition, after)
            }
            InvocationPurpose::Effect => {
                self.remove(&invocation.request.target)?;
                let after = self.observe(
                    observation_schema,
                    &desired,
                    &context,
                    &invocation.request.target,
                    bound.resource_spec.revision,
                )?;
                let disposition = if after.state == PolicyState::Absent {
                    InvocationDisposition::Completed
                } else {
                    InvocationDisposition::Indeterminate
                };
                (disposition, after)
            }
            InvocationPurpose::Reconcile => {
                let complete = if removing {
                    before.state == PolicyState::Absent
                } else {
                    before.state == PolicyState::Applied
                };
                let disposition = if complete {
                    InvocationDisposition::Completed
                } else if before.state == PolicyState::Unknown {
                    InvocationDisposition::InterventionRequired
                } else {
                    InvocationDisposition::SafeToRetry
                };
                (disposition, before)
            }
            InvocationPurpose::Cancel => {
                let complete = if removing {
                    before.state == PolicyState::Absent
                } else {
                    before.state == PolicyState::Applied
                };
                let disposition = if complete {
                    InvocationDisposition::Completed
                } else if before.state == PolicyState::Absent {
                    InvocationDisposition::RejectedBeforeEffect
                } else {
                    InvocationDisposition::Indeterminate
                };
                (disposition, before)
            }
            InvocationPurpose::Compensate | InvocationPurpose::ReconcileCompensation => {
                (InvocationDisposition::InterventionRequired, before)
            }
        };

        let evidence = ability_value(serde_json::to_value(evidence)?)?;
        let mut outputs = BTreeMap::new();
        if disposition == InvocationDisposition::Completed {
            outputs.insert(LocalKey::new("observation")?, evidence.clone());
            if invocation.method.method.as_str() == "apply" {
                outputs.insert(
                    LocalKey::new("retained-resource")?,
                    ability_value(serde_json::to_value(&invocation.request.target)?)?,
                );
            }
        }
        Ok(InvocationResult {
            schema: RESULT_SCHEMA.into(),
            disposition,
            evidence,
            outputs,
            native_context_digest: invocation.request.native_context_digest,
        })
    }

    fn resolve_context(
        &self,
        desired: &PolicySetRequest,
        realization: &AbilityValue,
    ) -> Result<ProviderContext> {
        let realization: Realization = decode_value(realization)?;
        ensure!(
            realization.schema == "aos.linux.ebpf-net-policy-realization/v1",
            "unsupported BPF network realization"
        );
        ensure!(
            Path::new(&realization.pin_directory) == self.pin_root,
            "BPF network realization selects an unauthorized pin directory"
        );
        let loader = realization.loader.resolve(&self.immutable_root)?;
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

    fn validate_context(
        &self,
        desired: &PolicySetRequest,
        realization: &AbilityValue,
        context: &ProviderContext,
    ) -> Result<()> {
        ensure!(
            context.schema == CONTEXT_SCHEMA,
            "unsupported provider context"
        );
        ensure!(
            self.resolve_context(desired, realization)? == *context,
            "provider context differs from the exact selected artifacts"
        );
        Ok(())
    }

    fn resolve_policy(&self, policy: &PolicySelection) -> Result<ResolvedPolicy> {
        Ok(ResolvedPolicy {
            name: policy.name.clone(),
            cgroup: checked_cgroup_path(&policy.cgroup)?,
            policy: resolve_artifact_path(&policy.policy, &self.immutable_root)?,
            object: resolve_artifact_path(&policy.object, &self.immutable_root)?,
        })
    }

    fn observe(
        &self,
        observation_schema: &str,
        desired: &PolicySetRequest,
        context: &ProviderContext,
        target: &ResourceReference,
        desired_revision: RevisionId,
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
                LINK_NAMES
                    .iter()
                    .all(|link| present.contains(&pin_name(&policy.name, link)))
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
        target: &ResourceReference,
        revision: RevisionId,
        remaining_millis: u64,
    ) -> Result<()> {
        let marker = self.read_marker(target)?;
        let pins = pin_names(&context.policies);
        if marker.is_none()
            && pins
                .iter()
                .any(|pin| context.pin_directory.join(pin).exists())
        {
            bail!("refusing to replace unmanaged BPF network pins");
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
            let policy_pin_directory = context.pin_directory.join(&policy.name);
            fs::create_dir_all(&policy_pin_directory)?;
            let remaining = remaining_millis
                .saturating_sub(u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX));
            let output = context.loader.run(
                &[
                    "apply",
                    "--policy",
                    path_text(&policy.policy)?,
                    "--cgroup",
                    path_text(&policy.cgroup)?,
                    "--object",
                    path_text(&policy.object)?,
                    "--pin-dir",
                    path_text(&policy_pin_directory)?,
                ],
                remaining,
            )?;
            ensure!(
                output.status.success(),
                "BPF network loader rejected policy {}: {}",
                policy.name,
                String::from_utf8_lossy(&output.stderr)
            );
        }
        Ok(())
    }

    fn remove(&self, target: &ResourceReference) -> Result<()> {
        let Some(marker) = self.read_marker(target)? else {
            return Ok(());
        };
        remove_pins(&self.pin_root, &marker.pins)?;
        match fs::remove_file(self.marker_path(target)?) {
            Ok(()) => Ok(()),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(error) => Err(error).context("removing BPF network ownership marker"),
        }
    }

    fn marker_path(&self, target: &ResourceReference) -> Result<PathBuf> {
        let digest =
            Sha256Digest::of_canonical("aos.linux.ebpf-net-policy-resource/v1", &target.resource)?;
        Ok(self
            .state_root
            .join(digest.to_string().trim_start_matches("sha256:")))
    }

    fn read_marker(&self, target: &ResourceReference) -> Result<Option<StateMarker>> {
        let file = match fs::File::open(self.marker_path(target)?) {
            Ok(file) => file,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(error) => return Err(error).context("opening BPF network ownership marker"),
        };
        let mut bytes = Vec::new();
        file.take(MAX_MARKER_BYTES + 1)
            .read_to_end(&mut bytes)
            .context("reading bounded BPF network ownership marker")?;
        ensure!(
            u64::try_from(bytes.len()).unwrap_or(u64::MAX) <= MAX_MARKER_BYTES,
            "BPF network ownership marker exceeds its document bound"
        );
        let marker: StateMarker =
            aos_contract::canonical::from_slice(&bytes, "BPF network ownership marker")?;
        validate_marker(&marker)?;
        Ok(Some(marker))
    }

    fn write_marker(&self, target: &ResourceReference, marker: &StateMarker) -> Result<()> {
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
        "BPF network policy set must contain 1..=64 policies"
    );
    let mut names = BTreeSet::new();
    let mut pins = BTreeSet::new();
    for policy in &request.policies {
        ensure!(safe_name(&policy.name), "invalid BPF network policy name");
        ensure!(
            names.insert(&policy.name),
            "duplicate BPF network policy name"
        );
        checked_cgroup_path(&policy.cgroup)?;
        for link in LINK_NAMES {
            ensure!(
                pins.insert(pin_name(&policy.name, link)),
                "BPF network policies produce a duplicate pin"
            );
        }
    }
    ensure!(
        request
            .policies
            .windows(2)
            .all(|pair| pair[0].name < pair[1].name),
        "BPF network policies are not in canonical name order"
    );
    let prerequisites = request
        .prerequisites
        .iter()
        .map(serde_json::to_vec)
        .collect::<std::result::Result<Vec<_>, _>>()?;
    ensure!(
        prerequisites.windows(2).all(|pair| pair[0] < pair[1]),
        "BPF network prerequisites are not canonical and unique"
    );
    Ok(())
}

fn validate_marker(marker: &StateMarker) -> Result<()> {
    ensure!(marker.schema == MARKER_SCHEMA, "unsupported marker schema");
    ensure!(
        !marker.pins.is_empty() && marker.pins.len() <= 4096,
        "BPF network marker has an invalid pin set"
    );
    ensure!(
        marker.pins.windows(2).all(|pair| pair[0] < pair[1]),
        "BPF network marker pins are not canonical and unique"
    );
    ensure!(
        marker.pins.iter().all(|pin| safe_pin_name(pin)),
        "BPF network marker contains an invalid pin name"
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
    value.len() <= 257
        && value.split_once('/').is_some_and(|(policy, link)| {
            safe_name(policy) && LINK_NAMES.binary_search(&link).is_ok()
        })
}

fn pin_name(policy: &str, program: &str) -> String {
    format!("{policy}/{program}")
}

const LINK_NAMES: &[&str] = &["bind4", "bind6", "connect4", "connect6"];

fn pin_names(policies: &[ResolvedPolicy]) -> Vec<String> {
    let mut pins = policies
        .iter()
        .flat_map(|policy| LINK_NAMES.iter().map(|link| pin_name(&policy.name, link)))
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
    for directory in pins
        .iter()
        .filter_map(|pin| pin.split_once('/').map(|pair| pair.0))
    {
        match fs::remove_dir(pin_root.join(directory)) {
            Ok(()) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) if error.kind() == std::io::ErrorKind::DirectoryNotEmpty => {}
            Err(error) => {
                return Err(error)
                    .with_context(|| format!("removing BPF pin directory {directory}"));
            }
        }
    }
    Ok(())
}

fn checked_cgroup_path(value: &str) -> Result<PathBuf> {
    let path = Path::new(value);
    ensure!(
        path.is_absolute()
            && path.starts_with("/sys/fs/cgroup")
            && path.components().all(|component| {
                matches!(
                    component,
                    std::path::Component::RootDir | std::path::Component::Normal(_)
                )
            }),
        "BPF network cgroup path is outside the unified cgroup hierarchy"
    );
    Ok(path.to_path_buf())
}

fn validate_method(method: &str, semantics: &MethodSemantics) -> Result<()> {
    let expected = match method {
        "observe" => MethodSemantics::ordinary(AccessMode::Read),
        "apply" => MethodSemantics::ordinary(AccessMode::ExclusiveWrite),
        "remove" => MethodSemantics::provider_stop(),
        _ => bail!("unsupported BPF network policy method"),
    };
    ensure!(*semantics == expected, "method semantics differ");
    Ok(())
}

fn require_prerequisites(
    prerequisites: &[ResourceReference],
    resources: &[ResourceContext],
) -> Result<()> {
    for prerequisite in prerequisites {
        require_resource(resources, prerequisite)?;
    }
    Ok(())
}

fn require_resource<'a>(
    resources: &'a [ResourceContext],
    reference: &ResourceReference,
) -> Result<&'a ResourceContext> {
    let index = resources
        .binary_search_by(|context| context.reference.resource.cmp(&reference.resource))
        .map_err(|_| anyhow::anyhow!("request omits a referenced resource context"))?;
    let context = &resources[index];
    ensure!(
        &context.reference == reference,
        "resource context authority differs from the exact reference"
    );
    Ok(context)
}

fn observation_revision(
    observation: &PolicyObservation,
    desired: RevisionId,
) -> Result<AdmissionRevision> {
    match observation.state {
        PolicyState::Applied => Ok(AdmissionRevision::Present { revision: desired }),
        PolicyState::Absent => Ok(AdmissionRevision::Absent),
        PolicyState::Drifted => Ok(AdmissionRevision::Present {
            revision: RevisionId(Sha256Digest::of_canonical(
                "aos.linux.ebpf-net-policy-observed/v1",
                observation,
            )?),
        }),
        PolicyState::Unknown => Ok(AdmissionRevision::Unknown),
    }
}

fn ability_value(value: serde_json::Value) -> Result<AbilityValue> {
    AbilityValue::new(value).context("constructing canonical ability value")
}

fn decode_value<T: for<'de> Deserialize<'de>>(value: &AbilityValue) -> Result<T> {
    serde_json::from_value(value.as_json().clone()).context("decoding checked ability value")
}

const fn purpose_name(purpose: InvocationPurpose) -> &'static str {
    match purpose {
        InvocationPurpose::Effect => "effect",
        InvocationPurpose::Reconcile => "reconcile",
        InvocationPurpose::Cancel => "cancel",
        InvocationPurpose::Compensate => "compensate",
        InvocationPurpose::ReconcileCompensation => "reconcile-compensation",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use aos_ability_model::{
        ArtifactReference, EnvironmentId, ExecutionStage, InstanceId, InterfaceKey, InterfaceName,
        ResourceId, ResourceLifetime,
    };
    use std::num::NonZeroU32;
    use tempfile::tempdir;

    fn artifact(root: &Path) -> ArtifactReference {
        ArtifactReference {
            content: Sha256Digest::of_bytes(b"content"),
            store_path: root.to_string_lossy().into_owned(),
            nar_hash: Sha256Digest::of_bytes(b"nar"),
            closure: Sha256Digest::of_bytes(b"closure"),
        }
    }

    fn target() -> ResourceReference {
        ResourceReference {
            interface: InterfaceKey {
                name: InterfaceName::new("aos.security.ebpf-net-policy-set").expect("interface"),
                abi: NonZeroU32::new(1).expect("ABI"),
                descriptor: Sha256Digest::of_bytes(b"descriptor"),
            },
            resource: ResourceId {
                provider: InstanceId {
                    environment: EnvironmentId {
                        authority: LocalKey::new("test").expect("authority"),
                        key: LocalKey::new("host").expect("environment"),
                        stage: ExecutionStage::Host,
                    },
                    key: LocalKey::new("ebpf-net").expect("provider"),
                },
                key: LocalKey::new("fleet-policy").expect("resource"),
            },
            operations: vec![LocalKey::new("observe").expect("operation")],
            lifetime: ResourceLifetime::Instance,
        }
    }

    fn policy(root: &Path) -> PolicySelection {
        PolicySelection {
            name: "audit".into(),
            cgroup: "/sys/fs/cgroup/aos/audit".into(),
            policy: ArtifactPathReference {
                artifact: artifact(root),
                path: "share/policy.json".into(),
            },
            object: ArtifactPathReference {
                artifact: artifact(root),
                path: "lib/policy.bpf.o".into(),
            },
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
        let provider = EbpfNetPolicyProvider::for_test(immutable, pins.clone(), state);
        let resolved = provider
            .resolve_policy(&policy(&package))
            .expect("resolve policy");
        assert_eq!(resolved.policy, package.join("share/policy.json"));
        assert_eq!(resolved.object, package.join("lib/policy.bpf.o"));

        fs::create_dir_all(pins.join("audit")).expect("owned pin directory");
        let owned = pin_name("audit", "bind4");
        fs::write(pins.join(&owned), b"pin").expect("owned pin");
        fs::write(pins.join("another-owner"), b"pin").expect("foreign pin");
        provider
            .write_marker(
                &target(),
                &StateMarker {
                    schema: MARKER_SCHEMA.into(),
                    revision: RevisionId(Sha256Digest::of_bytes(b"revision")),
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
        let reference = ArtifactPathReference {
            artifact: artifact(&package),
            path: "../outside".into(),
        };
        assert!(resolve_artifact_path(&reference, &immutable).is_err());
    }

    #[test]
    fn cgroup_must_stay_beneath_the_unified_hierarchy() {
        let request = PolicySetRequest {
            policies: vec![PolicySelection {
                cgroup: "/run/not-a-cgroup".into(),
                ..policy(Path::new("/nix/store/test"))
            }],
            prerequisites: Vec::new(),
        };
        assert!(validate_request(&request).is_err());
    }
}
