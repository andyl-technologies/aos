//! Checked convergence of bounded kernel-tunable maps through procfs.
//!
//! The provider owns the Linux-specific realization of the portable
//! `aos.kernel.tunables` interface. It records the exact values it displaced
//! before the first write so removal can restore them, and it derives every
//! procfs path from a checked tunable key.

#![forbid(unsafe_code)]

use std::collections::{BTreeMap, BTreeSet};
use std::fs::{self, OpenOptions};
use std::io::{self, Read as _, Write as _};
use std::os::unix::fs::{OpenOptionsExt as _, PermissionsExt as _};
use std::path::{Path, PathBuf};

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
use serde_json::json;

const INTERFACE_NAME: &str = "aos.kernel.tunable-effects";
const REALIZATION_SCHEMA: &str = "aos.kernel.tunables-realization/v1";
const OBSERVATION_SCHEMA: &str = "aos.ability.kernel-tunables-observation/v1";
const CONTEXT_SCHEMA: &str = "aos.kernel.tunables-context/v1";
const MARKER_SCHEMA: &str = "aos.kernel.tunables-state/v1";
const PROC_ROOT: &str = "/proc/sys";
const STATE_ROOT: &str = "/run/aos/kernel-tunables";
const MAX_MARKER_BYTES: u64 = 3 * 1024 * 1024;

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct TunableRequest {
    values: BTreeMap<String, String>,
    dependencies: Vec<ResourceReference>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct TunableRealization {
    schema: String,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
enum TunableState {
    Applied,
    Drifted,
    Unmanaged,
    Unknown,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct TunableObservation {
    schema: String,
    expected: TunableRequest,
    observed: BTreeMap<String, String>,
    state: TunableState,
    discrepancies: Vec<String>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct ProviderContext {
    schema: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct StateMarker {
    schema: String,
    revision: RevisionId,
    baseline: BTreeMap<String, String>,
    managed: BTreeSet<String>,
    pending_restore: BTreeSet<String>,
}

/// Handles the package-owned kernel-tunable ability.
pub struct KernelTunableProvider {
    proc_root: PathBuf,
    state_root: PathBuf,
}

impl KernelTunableProvider {
    /// Constructs the production provider over the Linux procfs ABI.
    #[must_use]
    pub fn production() -> Self {
        Self {
            proc_root: PROC_ROOT.into(),
            state_root: STATE_ROOT.into(),
        }
    }

    #[cfg(test)]
    fn for_test(proc_root: PathBuf, state_root: PathBuf) -> Self {
        Self {
            proc_root,
            state_root,
        }
    }

    /// Handles one bounded command invocation and emits canonical JSON.
    ///
    /// # Errors
    ///
    /// Returns an error when the wire contract, selected method, dependency
    /// contexts, tunable keys, state marker, or procfs operation is invalid.
    pub fn handle(&self, purpose: &str, input: &[u8]) -> Result<Vec<u8>> {
        let result = match purpose {
            "admit" => {
                let request: AdmissionRequest =
                    aos_contract::canonical::from_slice(input, "kernel-tunable admission request")?;
                ensure!(
                    request.schema == ADMISSION_REQUEST_SCHEMA,
                    "unsupported admission schema"
                );
                serde_json::to_value(self.admit(request)?)?
            }
            "effect" | "reconcile" | "cancel" | "compensate" | "reconcile-compensation" => {
                let invocation: Invocation =
                    aos_contract::canonical::from_slice(input, "kernel-tunable invocation")?;
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
            .context("encoding canonical kernel-tunable response")
    }

    fn admit(&self, request: AdmissionRequest) -> Result<AdmissionResult> {
        validate_method(
            request.method.interface.name.as_str(),
            request.method.method.as_str(),
            &request.semantics,
        )?;
        validate_admission_resource(&request)?;
        validate_resource_contexts(&request.resources)?;
        let desired: TunableRequest = decode_value(&request.resource_spec.value)?;
        validate_request(&desired)?;
        let realization: TunableRealization = decode_value(&request.resource_spec.realization)?;
        ensure!(
            realization.schema == REALIZATION_SCHEMA,
            "unsupported realization schema"
        );
        require_dependencies(&desired.dependencies, &request.resources)?;

        let observation = self.observe(&desired, &request.target)?;
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
            native_context: ability_value(json!({"schema": CONTEXT_SCHEMA}))?,
            supported_purposes,
        })
    }

    fn invoke(&self, invocation: Invocation) -> Result<InvocationResult> {
        ensure!(
            invocation.method_is_bound(),
            "invocation method is not durably bound"
        );
        validate_method(
            invocation.method.interface.name.as_str(),
            invocation.method.method.as_str(),
            &invocation.semantics,
        )?;
        validate_resource_contexts(&invocation.request.resources)?;
        ensure!(
            resource_set_digest(&invocation.request.resources)?
                == invocation.request.native_context_digest,
            "resource contexts differ from their authenticated set digest"
        );
        let target = require_resource(&invocation.request.resources, &invocation.request.target)?;
        let bound: BoundNativeContext = validate_resource_context(target)?;
        ensure!(
            invocation.method.interface == invocation.request.target.interface
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
        let realization: TunableRealization = decode_value(&bound.resource_spec.realization)?;
        ensure!(
            realization.schema == REALIZATION_SCHEMA,
            "unsupported realization schema"
        );
        let context: ProviderContext = decode_value(&bound.provider_context)?;
        ensure!(
            context.schema == CONTEXT_SCHEMA,
            "unsupported provider context"
        );

        let desired: TunableRequest = decode_value(&bound.resource_spec.value)?;
        validate_request(&desired)?;
        require_dependencies(&desired.dependencies, &invocation.request.resources)?;
        let removing = invocation.method.method.as_str() == "remove";
        let before = self.observe(&desired, &invocation.request.target)?;
        let (disposition, evidence) = match invocation.purpose {
            InvocationPurpose::Effect if invocation.method.method.as_str() == "observe" => {
                (InvocationDisposition::Completed, before)
            }
            InvocationPurpose::Effect if invocation.control.cancelled => {
                (InvocationDisposition::RejectedBeforeEffect, before)
            }
            InvocationPurpose::Effect if invocation.method.method.as_str() == "apply" => {
                self.apply(&desired, &invocation.request.target, target.revision)?;
                let after = self.observe(&desired, &invocation.request.target)?;
                let disposition = if after.state == TunableState::Applied {
                    InvocationDisposition::Completed
                } else {
                    InvocationDisposition::Indeterminate
                };
                (disposition, after)
            }
            InvocationPurpose::Effect => {
                self.remove(&invocation.request.target)?;
                let after = self.observe(&desired, &invocation.request.target)?;
                let disposition = if after.state == TunableState::Unmanaged {
                    InvocationDisposition::Completed
                } else {
                    InvocationDisposition::Indeterminate
                };
                (disposition, after)
            }
            InvocationPurpose::Reconcile => {
                let complete = if removing {
                    before.state == TunableState::Unmanaged
                } else {
                    before.state == TunableState::Applied
                };
                (
                    if complete {
                        InvocationDisposition::Completed
                    } else if before.state == TunableState::Unknown {
                        InvocationDisposition::StillIndeterminate
                    } else {
                        InvocationDisposition::SafeToRetry
                    },
                    before,
                )
            }
            InvocationPurpose::Cancel => {
                let complete = if removing {
                    before.state == TunableState::Unmanaged
                } else {
                    before.state == TunableState::Applied
                };
                (
                    if complete {
                        InvocationDisposition::Completed
                    } else if before.state == TunableState::Unmanaged {
                        InvocationDisposition::RejectedBeforeEffect
                    } else {
                        InvocationDisposition::Indeterminate
                    },
                    before,
                )
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

    fn observe(
        &self,
        desired: &TunableRequest,
        target: &ResourceReference,
    ) -> Result<TunableObservation> {
        let managed = self.read_marker(target)?.is_some();
        let mut observed = BTreeMap::new();
        let mut discrepancies = Vec::new();
        for (key, expected) in &desired.values {
            match fs::read_to_string(self.tunable_path(key)) {
                Ok(value) => {
                    let value = value.trim_end_matches(['\n', '\r']).to_string();
                    if &value != expected {
                        discrepancies.push(key.clone());
                    }
                    observed.insert(key.clone(), value);
                }
                Err(error) if error.kind() == io::ErrorKind::NotFound => {
                    discrepancies.push(key.clone());
                }
                Err(error) => return Err(error).with_context(|| format!("reading tunable {key}")),
            }
        }
        let state = if !managed {
            TunableState::Unmanaged
        } else if discrepancies.is_empty() {
            TunableState::Applied
        } else if managed {
            TunableState::Drifted
        } else {
            TunableState::Unmanaged
        };
        Ok(TunableObservation {
            schema: OBSERVATION_SCHEMA.into(),
            expected: desired.clone(),
            observed,
            state,
            discrepancies,
        })
    }

    fn apply(
        &self,
        desired: &TunableRequest,
        target: &ResourceReference,
        revision: RevisionId,
    ) -> Result<()> {
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

    fn remove(&self, target: &ResourceReference) -> Result<()> {
        let Some(marker) = self.read_marker(target)? else {
            return Ok(());
        };
        for (key, value) in &marker.baseline {
            write_tunable(&self.tunable_path(key), value)
                .with_context(|| format!("restoring tunable {key}"))?;
        }
        match fs::remove_file(self.marker_path(target)?) {
            Ok(()) => Ok(()),
            Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
            Err(error) => Err(error).context("removing kernel-tunable state marker"),
        }
    }

    fn tunable_path(&self, key: &str) -> PathBuf {
        self.proc_root.join(key.replace('.', "/"))
    }

    fn marker_path(&self, target: &ResourceReference) -> Result<PathBuf> {
        let digest =
            Sha256Digest::of_canonical("aos.kernel.tunables-resource/v1", &target.resource)?;
        Ok(self
            .state_root
            .join(digest.to_string().trim_start_matches("sha256:")))
    }

    fn read_marker(&self, target: &ResourceReference) -> Result<Option<StateMarker>> {
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

fn write_tunable(path: &Path, value: &str) -> Result<()> {
    ensure!(
        !value.contains(['\n', '\r', '\0']),
        "tunable value contains a forbidden byte"
    );
    fs::write(path, format!("{value}\n")).context("writing procfs tunable")
}

fn validate_request(request: &TunableRequest) -> Result<()> {
    ensure!(!request.values.is_empty(), "tunable map must not be empty");
    ensure!(
        request.values.len() <= 256,
        "tunable map exceeds 256 entries"
    );
    for (key, value) in &request.values {
        ensure!(valid_tunable_key(key), "invalid tunable key {key:?}");
        ensure!(
            value.len() <= 4096 && !value.contains(['\n', '\r', '\0']),
            "invalid tunable value"
        );
    }
    let dependencies = request
        .dependencies
        .iter()
        .map(serde_json::to_vec)
        .collect::<std::result::Result<Vec<_>, _>>()?;
    ensure!(
        dependencies.windows(2).all(|pair| pair[0] < pair[1]),
        "dependencies are not canonical and unique"
    );
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

fn validate_method(interface: &str, method: &str, semantics: &MethodSemantics) -> Result<()> {
    ensure!(
        interface == INTERFACE_NAME,
        "selected interface is not kernel tunables"
    );
    let access = match method {
        "observe" => AccessMode::Read,
        "apply" | "remove" => AccessMode::ExclusiveWrite,
        _ => bail!("unsupported kernel-tunable method"),
    };
    ensure!(
        *semantics == MethodSemantics::ordinary(access),
        "method semantics differ"
    );
    Ok(())
}

fn require_dependencies(
    dependencies: &[ResourceReference],
    resources: &[ResourceContext],
) -> Result<()> {
    for dependency in dependencies {
        require_resource(resources, dependency)?;
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
    observation: &TunableObservation,
    desired: RevisionId,
) -> Result<AdmissionRevision> {
    match observation.state {
        TunableState::Applied => Ok(AdmissionRevision::Present { revision: desired }),
        TunableState::Unmanaged => Ok(AdmissionRevision::Absent),
        TunableState::Drifted => Ok(AdmissionRevision::Present {
            revision: RevisionId(Sha256Digest::of_canonical(
                "aos.kernel.tunables-observed/v1",
                observation,
            )?),
        }),
        TunableState::Unknown => Ok(AdmissionRevision::Unknown),
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
        EnvironmentId, ExecutionStage, InstanceId, InterfaceKey, InterfaceName, ResourceId,
    };
    use tempfile::tempdir;

    fn reference() -> ResourceReference {
        ResourceReference {
            interface: InterfaceKey {
                name: InterfaceName::new(INTERFACE_NAME).expect("interface"),
                abi: std::num::NonZeroU32::new(1).expect("nonzero ABI"),
                descriptor: Sha256Digest::of_bytes(b"kernel tunables test"),
            },
            resource: ResourceId {
                provider: InstanceId {
                    environment: EnvironmentId {
                        authority: LocalKey::new("test").expect("authority"),
                        key: LocalKey::new("host").expect("environment"),
                        stage: ExecutionStage::Host,
                    },
                    key: LocalKey::new("procps").expect("provider"),
                },
                key: LocalKey::new("network").expect("resource"),
            },
            operations: vec![LocalKey::new("observe").expect("operation")],
            lifetime: aos_ability_model::ResourceLifetime::Instance,
        }
    }

    #[test]
    fn apply_and_remove_restore_the_original_values() {
        let temporary = tempdir().expect("temporary directory");
        let proc_root = temporary.path().join("proc");
        let state_root = temporary.path().join("state");
        let tunable = proc_root.join("net/ipv4/ip_forward");
        fs::create_dir_all(tunable.parent().expect("parent")).expect("create proc tree");
        fs::write(&tunable, "0\n").expect("seed tunable");
        let provider = KernelTunableProvider::for_test(proc_root, state_root);
        let request = TunableRequest {
            values: BTreeMap::from([("net.ipv4.ip_forward".into(), "1".into())]),
            dependencies: Vec::new(),
        };
        let target = reference();

        provider
            .apply(
                &request,
                &target,
                RevisionId(Sha256Digest::of_bytes(b"desired")),
            )
            .expect("apply tunable");
        assert_eq!(fs::read_to_string(&tunable).expect("read applied"), "1\n");
        assert_eq!(
            provider.observe(&request, &target).expect("observe").state,
            TunableState::Applied
        );

        provider.remove(&target).expect("remove tunable resource");
        assert_eq!(fs::read_to_string(&tunable).expect("read restored"), "0\n");
        assert_eq!(
            provider
                .observe(&request, &target)
                .expect("observe removal")
                .state,
            TunableState::Unmanaged
        );
    }

    #[test]
    fn matching_unowned_values_do_not_claim_the_desired_revision() {
        let temporary = tempdir().expect("temporary directory");
        let proc_root = temporary.path().join("proc");
        let state_root = temporary.path().join("state");
        let tunable = proc_root.join("net/ipv4/ip_forward");
        fs::create_dir_all(tunable.parent().expect("parent")).expect("create proc tree");
        fs::write(&tunable, "1\n").expect("seed matching tunable");
        let provider = KernelTunableProvider::for_test(proc_root, state_root);
        let request = TunableRequest {
            values: BTreeMap::from([("net.ipv4.ip_forward".into(), "1".into())]),
            dependencies: Vec::new(),
        };
        let target = reference();
        let desired_revision = RevisionId(Sha256Digest::of_bytes(b"matching desired"));

        let unowned = provider
            .observe(&request, &target)
            .expect("observe matching unowned value");
        assert_eq!(unowned.state, TunableState::Unmanaged);
        assert_eq!(
            observation_revision(&unowned, desired_revision).expect("derive admission revision"),
            AdmissionRevision::Absent
        );

        provider
            .apply(&request, &target, desired_revision)
            .expect("establish ownership");
        assert!(
            provider
                .read_marker(&target)
                .expect("read marker")
                .is_some()
        );
        assert_eq!(
            provider
                .observe(&request, &target)
                .expect("observe owned value")
                .state,
            TunableState::Applied
        );

        provider.remove(&target).expect("remove owned resource");
        assert!(
            provider
                .read_marker(&target)
                .expect("read marker")
                .is_none()
        );
        assert_eq!(
            fs::read_to_string(tunable).expect("read restored value"),
            "1\n"
        );
    }

    #[test]
    fn replacing_an_exact_map_restores_removed_keys_and_tracks_added_baselines() {
        let temporary = tempdir().expect("temporary directory");
        let proc_root = temporary.path().join("proc");
        let state_root = temporary.path().join("state");
        let forwarding = proc_root.join("net/ipv4/ip_forward");
        let panic = proc_root.join("kernel/panic");
        fs::create_dir_all(forwarding.parent().expect("forwarding parent"))
            .expect("create networking proc tree");
        fs::create_dir_all(panic.parent().expect("panic parent")).expect("create kernel proc tree");
        fs::write(&forwarding, "0\n").expect("seed forwarding");
        fs::write(&panic, "5\n").expect("seed panic");
        let provider = KernelTunableProvider::for_test(proc_root, state_root);
        let target = reference();
        let first = TunableRequest {
            values: BTreeMap::from([("net.ipv4.ip_forward".into(), "1".into())]),
            dependencies: Vec::new(),
        };
        let replacement = TunableRequest {
            values: BTreeMap::from([("kernel.panic".into(), "30".into())]),
            dependencies: Vec::new(),
        };

        provider
            .apply(
                &first,
                &target,
                RevisionId(Sha256Digest::of_bytes(b"first")),
            )
            .expect("apply first map");
        provider
            .apply(
                &replacement,
                &target,
                RevisionId(Sha256Digest::of_bytes(b"replacement")),
            )
            .expect("apply replacement map");

        assert_eq!(
            fs::read_to_string(&forwarding).expect("read restored forwarding"),
            "0\n"
        );
        assert_eq!(
            fs::read_to_string(&panic).expect("read applied panic"),
            "30\n"
        );

        provider.remove(&target).expect("remove replacement map");
        assert_eq!(
            fs::read_to_string(&forwarding).expect("read unowned forwarding"),
            "0\n"
        );
        assert_eq!(
            fs::read_to_string(&panic).expect("read restored panic"),
            "5\n"
        );
    }

    #[test]
    fn request_rejects_path_traversal_and_noncanonical_dependencies() {
        assert!(!valid_tunable_key("net..ipv4.ip_forward"));
        assert!(!valid_tunable_key("../proc/sys/kernel"));

        let dependency = reference();
        let request = TunableRequest {
            values: BTreeMap::from([("net.ipv4.ip_forward".into(), "1".into())]),
            dependencies: vec![dependency.clone(), dependency],
        };
        assert!(validate_request(&request).is_err());
    }

    #[test]
    fn corrupt_marker_is_rejected_before_a_procfs_write() {
        let temporary = tempdir().expect("temporary directory");
        let proc_root = temporary.path().join("proc");
        let state_root = temporary.path().join("state");
        let provider = KernelTunableProvider::for_test(proc_root, state_root.clone());
        let target = reference();
        let marker = StateMarker {
            schema: MARKER_SCHEMA.into(),
            revision: RevisionId(Sha256Digest::of_bytes(b"corrupt marker")),
            baseline: BTreeMap::from([("../outside".into(), "1".into())]),
            managed: BTreeSet::from(["../outside".into()]),
            pending_restore: BTreeSet::new(),
        };
        fs::create_dir_all(&state_root).expect("create state root");
        fs::write(
            provider.marker_path(&target).expect("marker path"),
            aos_contract::canonical::canonical_json(
                &serde_json::to_value(marker).expect("serialize marker"),
            )
            .expect("encode marker"),
        )
        .expect("write corrupt marker");

        assert!(provider.remove(&target).is_err());
        assert!(!temporary.path().join("outside").exists());
    }
}
