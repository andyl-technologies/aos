//! Checked convergence of one aggregate host network ruleset through nftables.
//!
//! The provider renders the provider-neutral ruleset resource into one private
//! nftables table. After every mutation it captures the canonical nftables JSON
//! observation and records its digest beside the selected resource revision.
//! Reconciliation compares the live kernel object with that captured digest,
//! so drift is detected independently from the desired declaration.

#![forbid(unsafe_code)]

use std::collections::{BTreeMap, BTreeSet};
use std::fs::{self, OpenOptions};
use std::io::{Read as _, Write as _};
use std::os::unix::fs::{OpenOptionsExt as _, PermissionsExt as _};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

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

const CONTEXT_SCHEMA: &str = "aos.network.ruleset-context/v1";
const MARKER_SCHEMA: &str = "aos.network.ruleset-state/v1";
const STATE_ROOT: &str = "/run/aos/network-ruleset";
const TABLE_FAMILY: &str = "inet";
const TABLE_NAME: &str = "aos_filter";
const MAX_MARKER_BYTES: u64 = 1024 * 1024;
const MAX_OBSERVATION_BYTES: usize = 8 * 1024 * 1024;
const NFT_EXECUTABLE: &str = match option_env!("AOS_NFT_EXECUTABLE") {
    Some(path) => path,
    None => "/nonexistent/aos-nft",
};

#[derive(Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(deny_unknown_fields)]
struct Endpoint {
    transport: Transport,
    port: u16,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "lowercase")]
enum Transport {
    Tcp,
    Udp,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "lowercase")]
enum Policy {
    Accept,
    Drop,
}

impl Policy {
    const fn as_str(self) -> &'static str {
        match self {
            Self::Accept => "accept",
            Self::Drop => "drop",
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct BasePolicy {
    input_policy: Policy,
    forward_policy: Policy,
    trusted_interfaces: Vec<String>,
    prerequisites: Vec<ResourceReference>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct IngressPolicy {
    endpoints: Vec<Endpoint>,
    prerequisites: Vec<ResourceReference>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct ForwardingPolicy {
    policy: Policy,
    prerequisites: Vec<ResourceReference>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct RulesetRequest {
    base: BasePolicy,
    ingress: BTreeMap<String, IngressPolicy>,
    forwarding: BTreeMap<String, ForwardingPolicy>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct RulesetRealization {
    #[serde(rename = "schema")]
    _schema: String,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
enum RulesetState {
    Applied,
    Drifted,
    Unmanaged,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct RulesetObservation {
    schema: String,
    expected: RulesetRequest,
    observed_digest: Option<Sha256Digest>,
    state: RulesetState,
    discrepancies: Vec<LocalKey>,
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
    observed_digest: Sha256Digest,
}

/// Handles the package-owned aggregate network-ruleset ability.
pub struct NetworkRulesetProvider {
    nft: PathBuf,
    state_root: PathBuf,
}

impl NetworkRulesetProvider {
    /// Constructs the production provider with the build-authenticated nft executable.
    #[must_use]
    pub fn production() -> Self {
        Self {
            nft: NFT_EXECUTABLE.into(),
            state_root: STATE_ROOT.into(),
        }
    }

    #[cfg(test)]
    fn for_test(nft: PathBuf, state_root: PathBuf) -> Self {
        Self { nft, state_root }
    }

    /// Handles one bounded command invocation and emits canonical JSON.
    ///
    /// # Errors
    ///
    /// Returns an error when the wire contract, selected method, resource
    /// contexts, desired ruleset, retained state, or nftables operation is invalid.
    pub fn handle(&self, purpose: &str, input: &[u8]) -> Result<Vec<u8>> {
        let result = match purpose {
            "admit" => {
                let request: AdmissionRequest =
                    aos_contract::canonical::from_slice(input, "network-ruleset admission")?;
                ensure!(
                    request.schema == ADMISSION_REQUEST_SCHEMA,
                    "unsupported admission schema"
                );
                serde_json::to_value(self.admit(request)?)?
            }
            "effect" | "reconcile" | "cancel" | "compensate" | "reconcile-compensation" => {
                let invocation: Invocation =
                    aos_contract::canonical::from_slice(input, "network-ruleset invocation")?;
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
            .context("encoding canonical network-ruleset response")
    }

    fn admit(&self, request: AdmissionRequest) -> Result<AdmissionResult> {
        validate_method(request.method.method.as_str(), &request.semantics)?;
        validate_admission_resource(&request)?;
        validate_resource_contexts(&request.resources)?;
        let observation_schema = request
            .contract
            .observation_discriminator()
            .context("selected network-ruleset method has no observation discriminator")?;
        let desired: RulesetRequest = decode_value(&request.resource_spec.value)?;
        validate_request(&desired)?;
        let _realization: RulesetRealization = decode_value(&request.resource_spec.realization)?;
        require_dependencies(&desired, &request.resources)?;

        let observation = self.observe(
            observation_schema,
            &desired,
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
            native_context: ability_value(json!({"schema": CONTEXT_SCHEMA}))?,
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
            .context("selected network-ruleset method has no observation discriminator")?;
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
                && invocation.method.interface == invocation.request.target.interface
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
        let _realization: RulesetRealization = decode_value(&bound.resource_spec.realization)?;
        let context: ProviderContext = decode_value(&bound.provider_context)?;
        ensure!(
            context.schema == CONTEXT_SCHEMA,
            "unsupported provider context"
        );

        let desired: RulesetRequest = decode_value(&bound.resource_spec.value)?;
        validate_request(&desired)?;
        require_dependencies(&desired, &invocation.request.resources)?;
        let before = self.observe(
            observation_schema,
            &desired,
            &invocation.request.target,
            target.revision,
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
                self.apply(&desired, &invocation.request.target, target.revision)?;
                let after = self.observe(
                    observation_schema,
                    &desired,
                    &invocation.request.target,
                    target.revision,
                )?;
                let disposition = if after.state == RulesetState::Applied {
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
                    &invocation.request.target,
                    target.revision,
                )?;
                let disposition = if after.state == RulesetState::Unmanaged {
                    InvocationDisposition::Completed
                } else {
                    InvocationDisposition::Indeterminate
                };
                (disposition, after)
            }
            InvocationPurpose::Reconcile => {
                let complete = if removing {
                    before.state == RulesetState::Unmanaged
                } else {
                    before.state == RulesetState::Applied
                };
                (
                    if complete {
                        InvocationDisposition::Completed
                    } else {
                        InvocationDisposition::SafeToRetry
                    },
                    before,
                )
            }
            InvocationPurpose::Cancel => (
                if before.state == RulesetState::Unmanaged {
                    InvocationDisposition::RejectedBeforeEffect
                } else {
                    InvocationDisposition::Indeterminate
                },
                before,
            ),
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
        observation_schema: &str,
        desired: &RulesetRequest,
        target: &ResourceReference,
        desired_revision: RevisionId,
    ) -> Result<RulesetObservation> {
        let marker = self.read_marker(target)?;
        let observed_digest = self.observed_digest()?;
        let mut discrepancies = Vec::new();
        let state = match (marker, observed_digest) {
            (None, None) => RulesetState::Unmanaged,
            (None, Some(_)) => {
                discrepancies.push(LocalKey::new("ownership-absent")?);
                RulesetState::Unmanaged
            }
            (Some(_), None) => {
                discrepancies.push(LocalKey::new("ruleset-absent")?);
                RulesetState::Drifted
            }
            (Some(marker), Some(observed))
                if marker.revision == desired_revision && marker.observed_digest == observed =>
            {
                RulesetState::Applied
            }
            (Some(marker), Some(observed)) => {
                if marker.revision != desired_revision {
                    discrepancies.push(LocalKey::new("revision-mismatch")?);
                }
                if marker.observed_digest != observed {
                    discrepancies.push(LocalKey::new("ruleset-drift")?);
                }
                RulesetState::Drifted
            }
        };
        Ok(RulesetObservation {
            schema: observation_schema.into(),
            expected: desired.clone(),
            observed_digest,
            state,
            discrepancies,
        })
    }

    fn apply(
        &self,
        desired: &RulesetRequest,
        target: &ResourceReference,
        revision: RevisionId,
    ) -> Result<()> {
        let replacement = render_replacement(desired, self.table_exists()?);
        let mut child = Command::new(&self.nft)
            .args(["--file", "-"])
            .stdin(Stdio::piped())
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .spawn()
            .context("starting nftables ruleset transaction")?;
        child
            .stdin
            .take()
            .context("nftables transaction omitted stdin")?
            .write_all(replacement.as_bytes())
            .context("writing nftables ruleset transaction")?;
        let output = child
            .wait_with_output()
            .context("waiting for nftables ruleset transaction")?;
        ensure!(
            output.status.success(),
            "nftables rejected the rendered ruleset: {}",
            String::from_utf8_lossy(&output.stderr)
        );

        let observed_digest = self
            .observed_digest()?
            .context("applied nftables table is absent")?;
        self.write_marker(
            target,
            &StateMarker {
                schema: MARKER_SCHEMA.into(),
                revision,
                observed_digest,
            },
        )
    }

    fn remove(&self, target: &ResourceReference) -> Result<()> {
        self.remove_table_if_present()?;
        match fs::remove_file(self.marker_path(target)?) {
            Ok(()) => fs::File::open(&self.state_root)?
                .sync_all()
                .context("synchronizing removed network-ruleset state marker"),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(error) => Err(error).context("removing network-ruleset state marker"),
        }
    }

    fn observed_digest(&self) -> Result<Option<Sha256Digest>> {
        if !self.table_exists()? {
            return Ok(None);
        }
        let output = Command::new(&self.nft)
            .args(["-j", "list", "table", TABLE_FAMILY, TABLE_NAME])
            .output()
            .context("observing nftables ruleset")?;
        ensure!(
            output.status.success(),
            "nftables could not observe its owned table: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        ensure!(
            output.stdout.len() <= MAX_OBSERVATION_BYTES,
            "nftables observation exceeds its bound"
        );
        let value: serde_json::Value =
            serde_json::from_slice(&output.stdout).context("decoding nftables JSON observation")?;
        Ok(Some(Sha256Digest::of_canonical(
            "aos.network.ruleset-observation/v1",
            &value,
        )?))
    }

    fn table_exists(&self) -> Result<bool> {
        let output = Command::new(&self.nft)
            .args(["-j", "list", "tables"])
            .output()
            .context("listing nftables tables")?;
        ensure!(
            output.status.success(),
            "nftables could not list tables: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        ensure!(
            output.stdout.len() <= MAX_OBSERVATION_BYTES,
            "nftables table inventory exceeds its bound"
        );
        let value: serde_json::Value =
            serde_json::from_slice(&output.stdout).context("decoding nftables table inventory")?;
        let entries = value
            .get("nftables")
            .and_then(serde_json::Value::as_array)
            .context("nftables table inventory omits its entry array")?;
        Ok(entries.iter().any(|entry| {
            entry.get("table").is_some_and(|table| {
                table.get("family").and_then(serde_json::Value::as_str) == Some(TABLE_FAMILY)
                    && table.get("name").and_then(serde_json::Value::as_str) == Some(TABLE_NAME)
            })
        }))
    }

    fn remove_table_if_present(&self) -> Result<()> {
        if !self.table_exists()? {
            return Ok(());
        }
        let output = Command::new(&self.nft)
            .args(["delete", "table", TABLE_FAMILY, TABLE_NAME])
            .output()
            .context("removing nftables ruleset")?;
        ensure!(
            output.status.success(),
            "nftables could not remove its owned table: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        Ok(())
    }

    fn marker_path(&self, target: &ResourceReference) -> Result<PathBuf> {
        let digest =
            Sha256Digest::of_canonical("aos.network.ruleset-resource/v1", &target.resource)?;
        Ok(self
            .state_root
            .join(digest.to_string().trim_start_matches("sha256:")))
    }

    fn read_marker(&self, target: &ResourceReference) -> Result<Option<StateMarker>> {
        let path = self.marker_path(target)?;
        let file = match fs::File::open(path) {
            Ok(file) => file,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(error) => return Err(error).context("reading network-ruleset state marker"),
        };
        let mut bytes = Vec::new();
        file.take(MAX_MARKER_BYTES + 1)
            .read_to_end(&mut bytes)
            .context("reading bounded network-ruleset state marker")?;
        ensure!(
            u64::try_from(bytes.len()).unwrap_or(u64::MAX) <= MAX_MARKER_BYTES,
            "network-ruleset state marker exceeds its bound"
        );
        let marker: StateMarker =
            aos_contract::canonical::from_slice(&bytes, "network-ruleset marker")?;
        ensure!(
            marker.schema == MARKER_SCHEMA,
            "unsupported network-ruleset marker schema"
        );
        Ok(Some(marker))
    }

    fn write_marker(&self, target: &ResourceReference, marker: &StateMarker) -> Result<()> {
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
        fs::File::open(&self.state_root)?
            .sync_all()
            .context("synchronizing network-ruleset state directory")?;
        Ok(())
    }
}

fn render_ruleset(request: &RulesetRequest) -> String {
    let mut tcp = BTreeSet::new();
    let mut udp = BTreeSet::new();
    for policy in request.ingress.values() {
        for endpoint in &policy.endpoints {
            match endpoint.transport {
                Transport::Tcp => tcp.insert(endpoint.port),
                Transport::Udp => udp.insert(endpoint.port),
            };
        }
    }
    let forwarding = if request.base.forward_policy == Policy::Drop
        || request
            .forwarding
            .values()
            .any(|policy| policy.policy == Policy::Drop)
    {
        Policy::Drop
    } else {
        Policy::Accept
    };
    let mut rules = format!(
        "table {TABLE_FAMILY} {TABLE_NAME} {{\n  chain input {{\n    type filter hook input priority 0; policy {};\n    ct state established,related accept\n    ct state invalid drop\n",
        request.base.input_policy.as_str()
    );
    for interface in &request.base.trusted_interfaces {
        rules.push_str(&format!(
            "    iifname \"{}\" accept\n",
            escape_nft_string(interface)
        ));
    }
    rules.push_str("    ip protocol icmp accept\n    ip6 nexthdr ipv6-icmp accept\n");
    if !tcp.is_empty() {
        rules.push_str(&format!(
            "    tcp dport {{ {} }} accept\n",
            join_ports(&tcp)
        ));
    }
    if !udp.is_empty() {
        rules.push_str(&format!(
            "    udp dport {{ {} }} accept\n",
            join_ports(&udp)
        ));
    }
    rules.push_str(&format!(
        "  }}\n  chain forward {{\n    type filter hook forward priority 0; policy {};\n    ct state established,related accept\n    ct state invalid drop\n  }}\n  chain output {{\n    type filter hook output priority 0; policy accept;\n  }}\n}}\n",
        forwarding.as_str()
    ));
    rules
}

fn render_replacement(request: &RulesetRequest, table_exists: bool) -> String {
    let ruleset = render_ruleset(request);
    if table_exists {
        format!("delete table {TABLE_FAMILY} {TABLE_NAME}\n{ruleset}")
    } else {
        ruleset
    }
}

fn join_ports(ports: &BTreeSet<u16>) -> String {
    ports
        .iter()
        .map(u16::to_string)
        .collect::<Vec<_>>()
        .join(", ")
}

fn escape_nft_string(value: &str) -> String {
    value.replace('\\', "\\\\").replace('"', "\\\"")
}

fn validate_request(request: &RulesetRequest) -> Result<()> {
    ensure!(
        request.ingress.len() <= 4096,
        "ingress contribution bound exceeded"
    );
    ensure!(
        request.forwarding.len() <= 4096,
        "forwarding contribution bound exceeded"
    );
    ensure!(
        request.base.trusted_interfaces.len() <= 256,
        "trusted-interface bound exceeded"
    );
    for interface in &request.base.trusted_interfaces {
        ensure!(
            interface.len() <= 128 && !interface.contains(['\0', '\n', '\r']),
            "invalid trusted interface name"
        );
    }
    ensure!(
        request
            .base
            .trusted_interfaces
            .windows(2)
            .all(|pair| pair[0] < pair[1]),
        "trusted interfaces are not canonical and unique"
    );
    validate_prerequisites("base", &request.base.prerequisites)?;
    for (key, policy) in &request.ingress {
        LocalKey::new(key.clone()).context("invalid ingress contribution key")?;
        ensure!(policy.endpoints.len() <= 65_536, "endpoint bound exceeded");
        ensure!(
            policy.endpoints.windows(2).all(|pair| pair[0] < pair[1]),
            "ingress endpoints are not canonical and unique"
        );
        validate_prerequisites("ingress", &policy.prerequisites)?;
    }
    for (key, policy) in &request.forwarding {
        LocalKey::new(key.clone()).context("invalid forwarding contribution key")?;
        validate_prerequisites("forwarding", &policy.prerequisites)?;
    }
    Ok(())
}

fn validate_prerequisites(context: &str, prerequisites: &[ResourceReference]) -> Result<()> {
    ensure!(
        prerequisites.len() <= 64,
        "{context} prerequisite bound exceeded"
    );
    let encoded = prerequisites
        .iter()
        .map(serde_json::to_vec)
        .collect::<std::result::Result<Vec<_>, _>>()?;
    ensure!(
        encoded.windows(2).all(|pair| pair[0] < pair[1]),
        "{context} prerequisites are not canonical and unique"
    );
    Ok(())
}

fn validate_method(method: &str, semantics: &MethodSemantics) -> Result<()> {
    let access = match method {
        "observe" => AccessMode::Read,
        "apply" | "remove" => AccessMode::ExclusiveWrite,
        _ => bail!("unsupported network-ruleset method"),
    };
    ensure!(
        *semantics == MethodSemantics::ordinary(access),
        "method semantics differ"
    );
    Ok(())
}

fn require_dependencies(request: &RulesetRequest, resources: &[ResourceContext]) -> Result<()> {
    for dependency in request
        .base
        .prerequisites
        .iter()
        .chain(
            request
                .ingress
                .values()
                .flat_map(|policy| &policy.prerequisites),
        )
        .chain(
            request
                .forwarding
                .values()
                .flat_map(|policy| &policy.prerequisites),
        )
    {
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
        "resource context authority differs"
    );
    Ok(context)
}

fn observation_revision(
    observation: &RulesetObservation,
    desired: RevisionId,
) -> Result<AdmissionRevision> {
    match observation.state {
        RulesetState::Applied => Ok(AdmissionRevision::Present { revision: desired }),
        RulesetState::Unmanaged => Ok(AdmissionRevision::Absent),
        RulesetState::Drifted => Ok(AdmissionRevision::Present {
            revision: RevisionId(Sha256Digest::of_canonical(
                "aos.network.ruleset-observed/v1",
                observation,
            )?),
        }),
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

    #[test]
    fn rendering_is_canonical_across_contribution_order() {
        let request = RulesetRequest {
            base: BasePolicy {
                input_policy: Policy::Drop,
                forward_policy: Policy::Accept,
                trusted_interfaces: vec!["lo".into()],
                prerequisites: Vec::new(),
            },
            ingress: BTreeMap::from([
                (
                    "web".into(),
                    IngressPolicy {
                        endpoints: vec![Endpoint {
                            transport: Transport::Tcp,
                            port: 443,
                        }],
                        prerequisites: Vec::new(),
                    },
                ),
                (
                    "dns".into(),
                    IngressPolicy {
                        endpoints: vec![Endpoint {
                            transport: Transport::Udp,
                            port: 53,
                        }],
                        prerequisites: Vec::new(),
                    },
                ),
            ]),
            forwarding: BTreeMap::new(),
        };

        let rendered = render_ruleset(&request);
        assert!(rendered.contains("tcp dport { 443 } accept"));
        assert!(rendered.contains("udp dport { 53 } accept"));
        assert!(rendered.contains("chain forward"));
        let replacement = render_replacement(&request, true);
        assert!(replacement.starts_with("delete table inet aos_filter\n"));
        assert_eq!(replacement.matches("table inet aos_filter").count(), 2);
    }

    #[test]
    fn production_constructor_uses_authenticated_nft_path() {
        let provider = NetworkRulesetProvider::production();
        assert!(provider.nft.is_absolute());
        assert_eq!(provider.state_root, Path::new(STATE_ROOT));
    }

    #[test]
    fn test_constructor_keeps_explicit_paths() {
        let provider = NetworkRulesetProvider::for_test("/nft".into(), "/state".into());
        assert_eq!(provider.nft, Path::new("/nft"));
        assert_eq!(provider.state_root, Path::new("/state"));
    }
}
