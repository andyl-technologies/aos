//! Strict semantic validation and canonicalization for the evaluated
//! `aos.provisioning.storage` projection.
//!
//! Nix supplies defaults and merges operator definitions. Rust treats the
//! resulting JSON as an untrusted data contract: unknown fields, malformed
//! paths and identifiers, invalid sizes, and ambiguous growth all fail before
//! the selected storage provider may mutate a disk.

#![forbid(unsafe_code)]

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Component, Path};

use anyhow::{Context, Result, bail};
use aos_ability_model::ResourceReference;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// Carries the fixed-point storage policy into one runtime provisioning transaction.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProvisioningIntent {
    /// Names the logical provisioning resource.
    pub name: String,
    /// Enables the one-time provisioning transaction.
    pub enabled: bool,
    /// Identifies the root filesystem device observed by the boot substrate.
    pub root_device: String,
    /// Requires the measured-boot storage policy when true.
    pub measured_boot: bool,
    /// Selects the only supported initialization and divergence behavior.
    pub policy: ProvisioningPolicy,
    /// Lists exact resources that must be ready before provisioning begins.
    pub prerequisites: Vec<ResourceReference>,
}

/// Defines the closed storage initialization and divergence policy.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProvisioningPolicy {
    /// Selects when an absent storage layout may be initialized.
    pub initialize: ProvisioningInitialization,
    /// Selects the required response to drift after a committed transaction.
    pub committed_divergence: CommittedDivergence,
}

/// Selects the supported storage initialization condition.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ProvisioningInitialization {
    /// Initializes storage only when no durable provisioning marker exists.
    IfUnprovisioned,
}

/// Selects the supported response to committed storage divergence.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum CommittedDivergence {
    /// Requires an explicit factory reset before applying changed storage intent.
    RequireFactoryReset,
}

/// Carries the exact authenticated metadata input between provisioning operations.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuthorizedProvisioningInput {
    /// Must equal `aos.metadata.authorized-provisioning-input/v1`.
    pub schema: String,
    /// Identifies whether operator input or image defaults supply the plan.
    pub source: CanonicalProvisioningSource,
    /// Carries exact authenticated `host.nix` bytes for operator input.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub host_module: Option<String>,
    /// Authenticates [`Self::host_module`] when operator input is present.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub host_module_sha256: Option<String>,
    /// Records the authorization decision and source platform.
    pub authorization: ProvisioningAuthorization,
    /// Carries normalized platform facts as explicitly unauthenticated observations.
    pub facts: ObservedInstanceFacts,
    /// Pins the exact module library used for restricted evaluation.
    pub base_library: BaseLibraryIdentity,
}

/// Carries normalized platform facts without granting them authorization authority.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ObservedInstanceFacts {
    /// Must equal `aos.metadata.observed-instance-facts/v1`.
    pub schema: String,
    /// Explicitly classifies every contained value as observational input.
    pub trust: InstanceFactsTrust,
    /// Carries the normalized metadata facts value.
    pub value: serde_json::Value,
    /// Authenticates the canonical facts value without making it trusted.
    pub sha256: String,
}

/// Classifies the authority of metadata-derived instance facts.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum InstanceFactsTrust {
    /// Allows facts to inform configuration while denying authorization use.
    UnauthenticatedObservational,
}

/// Records how one metadata input was authorized.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProvisioningAuthorization {
    /// Identifies the configured trust policy.
    pub trust_mode: ProvisioningTrustMode,
    /// Identifies the platform that supplied metadata.
    pub platform_id: String,
    /// Identifies the matching configuration signer in signed mode.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signer: Option<String>,
}

/// Selects how metadata input is authorized.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ProvisioningTrustMode {
    /// Trusts exact delivery by the selected deployment platform.
    Platform,
    /// Requires a matching signature from an explicit configuration key.
    Signed,
}

/// Pins one immutable base module library and its ABI schema digest.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BaseLibraryIdentity {
    /// Identifies the exact immutable module-library store path.
    pub store_path: String,
    /// Authenticates the option schema accepted by the module library.
    pub abi_hash: String,
}

/// Validates the closed fixed-point provisioning intent.
///
/// # Errors
///
/// Returns an error when the local name, root device, policy, or prerequisite
/// set falls outside the public interface contract.
pub fn validate_provisioning_intent(intent: &ProvisioningIntent) -> Result<()> {
    validate_local_key(&intent.name, "provisioning name")?;
    if !intent.root_device.starts_with('/') {
        bail!("root device must be an absolute execution path");
    }
    if intent.prerequisites.len() > 64 {
        bail!("provisioning prerequisites exceed the interface bound");
    }

    let mut prerequisites = BTreeSet::new();
    for prerequisite in &intent.prerequisites {
        let encoded = serde_json::to_string(prerequisite)
            .context("encoding one provisioning prerequisite")?;
        if !prerequisites.insert(encoded) {
            bail!("provisioning prerequisites must be unique");
        }
    }
    Ok(())
}

/// Validates the exact authenticated metadata value passed to plan evaluation.
///
/// # Errors
///
/// Returns an error when its schema, source arm, digest, platform identity, or
/// base-library identity is inconsistent.
pub fn validate_authorized_provisioning_input(input: &AuthorizedProvisioningInput) -> Result<()> {
    if input.schema != "aos.metadata.authorized-provisioning-input/v1" {
        bail!("unsupported authorized provisioning input schema");
    }
    validate_local_key(&input.authorization.platform_id, "metadata platform id")?;
    if input
        .authorization
        .signer
        .as_ref()
        .is_some_and(|signer| signer.len() > 512)
    {
        bail!("metadata signer identity exceeds the interface bound");
    }
    validate_digest(&input.base_library.abi_hash, "base-library ABI hash")?;
    if !input.base_library.store_path.starts_with("/nix/store/") {
        bail!("base library must use an immutable store path");
    }
    validate_observed_instance_facts(&input.facts)?;

    match (
        input.source,
        input.host_module.as_deref(),
        input.host_module_sha256.as_deref(),
    ) {
        (CanonicalProvisioningSource::Operator, Some(module), Some(digest)) => {
            if module.len() > 131_072 {
                bail!("authorized host module exceeds the runtime result bound");
            }
            validate_digest(digest, "host module digest")?;
            let actual = format!("sha256:{}", hex_digest(module.as_bytes()));
            if actual != digest {
                bail!("authorized host module differs from its digest");
            }
        }
        (CanonicalProvisioningSource::Fallback, None, None) => {}
        (CanonicalProvisioningSource::Operator, _, _) => {
            bail!("operator provisioning requires an exact host module and digest");
        }
        (CanonicalProvisioningSource::Fallback, _, _) => {
            bail!("fallback provisioning must not carry an operator host module");
        }
    }

    match input.authorization.trust_mode {
        ProvisioningTrustMode::Platform if input.authorization.signer.is_some() => {
            bail!("platform-authorized input must not claim a configuration signer");
        }
        ProvisioningTrustMode::Signed
            if input.source == CanonicalProvisioningSource::Operator
                && input.authorization.signer.is_none() =>
        {
            bail!("signed operator input must identify its matching signer");
        }
        _ => {}
    }
    Ok(())
}

/// Constructs normalized instance facts with a domain-separated canonical digest.
///
/// # Errors
///
/// Returns an error when the facts value cannot be encoded in canonical AOS JSON.
pub fn observed_instance_facts(value: serde_json::Value) -> Result<ObservedInstanceFacts> {
    let sha256 = aos_contract::Sha256Digest::of_canonical(
        "aos.metadata.observed-instance-facts/v1",
        &value,
    )?
    .to_string();
    Ok(ObservedInstanceFacts {
        schema: "aos.metadata.observed-instance-facts/v1".into(),
        trust: InstanceFactsTrust::UnauthenticatedObservational,
        value,
        sha256,
    })
}

/// Validates normalized facts without promoting them into authorization state.
///
/// # Errors
///
/// Returns an error when the schema or canonical digest differs from the value.
pub fn validate_observed_instance_facts(facts: &ObservedInstanceFacts) -> Result<()> {
    if facts.schema != "aos.metadata.observed-instance-facts/v1" {
        bail!("unsupported observed instance facts schema");
    }
    validate_digest(&facts.sha256, "observed instance facts digest")?;
    let actual = aos_contract::Sha256Digest::of_canonical(
        "aos.metadata.observed-instance-facts/v1",
        &facts.value,
    )?
    .to_string();
    if actual != facts.sha256 {
        bail!("observed instance facts differ from their canonical digest");
    }
    Ok(())
}

fn validate_digest(value: &str, description: &str) -> Result<()> {
    let Some(hex) = value.strip_prefix("sha256:") else {
        bail!("{description} must use the sha256 digest prefix");
    };
    if hex.len() != 64
        || !hex
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
    {
        bail!("{description} must contain 64 lower-case hexadecimal digits");
    }
    Ok(())
}

fn hex_digest(bytes: &[u8]) -> String {
    use std::fmt::Write as _;

    Sha256::digest(bytes)
        .iter()
        .fold(String::with_capacity(64), |mut encoded, byte| {
            let _ = write!(encoded, "{byte:02x}");
            encoded
        })
}

/// Closed JSON product of restricted initrd evaluation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProvisioningPlan {
    /// Must equal `aos.provisioning-plan/v1`.
    pub schema: String,
    /// One-time storage declaration.
    pub storage: StoragePlan,
}

/// Evaluated storage configuration.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StoragePlan {
    /// Logical partition name to definition.
    pub partitions: BTreeMap<String, PartitionSpec>,
}

/// One additive partition definition.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct PartitionSpec {
    /// Provider-selected absolute device target, or `null` for the root disk.
    pub device: Option<String>,
    /// GPT partition label.
    pub label: String,
    /// Semantic type or canonical raw GUID.
    #[serde(rename = "type")]
    pub partition_type: String,
    /// Minimum size in systemd size syntax.
    pub size_min: String,
    /// Optional maximum size.
    pub size_max: Option<String>,
    /// Relative free-space allocation weight.
    pub weight: i64,
    /// Optional initial filesystem format.
    pub format: Option<String>,
    /// Optional deterministic partition UUID.
    pub uuid: Option<String>,
    /// Whether this partition consumes remaining free space.
    pub grow: bool,
    /// Whether an existing filesystem may grow.
    pub grow_fs: bool,
    /// Stable placement priority.
    pub priority: i64,
}

/// Canonical storage-provisioning plan passed between checked ability operations.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CanonicalProvisioningPlan {
    /// Must equal `aos.storage.provisioning-plan/v1`.
    pub schema: String,
    /// Records whether authenticated operator input or image defaults supplied the intent.
    pub source: CanonicalProvisioningSource,
    /// Names the durable GPT provenance marker and UUID namespace.
    pub marker_uuid: String,
    /// Records whether the plan must leave `/var` raw for measured boot.
    pub measured_boot: bool,
    /// Maps logical partition keys to their normalized definitions.
    pub partitions: BTreeMap<String, CanonicalPartitionSpec>,
}

/// Identifies the authenticated source of one provisioning plan.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum CanonicalProvisioningSource {
    /// The plan came from an authenticated operator host module.
    Operator,
    /// The plan came from the image's closed provisioning defaults.
    Fallback,
}

/// Reports the storage provider's exact observation of the durable GPT marker.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProvisioningMarkerObservation {
    /// Must equal `aos.storage.provisioning-marker-observation/v1`.
    pub schema: String,
    /// Classifies the complete marker set observed on the root disk.
    pub state: ProvisioningMarkerState,
    /// Identifies the committed provenance arm when exactly one marker exists.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source: Option<CanonicalProvisioningSource>,
    /// Carries the canonical PARTUUID when exactly one committed marker exists.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub marker_uuid: Option<String>,
}

/// Classifies the durable provisioning marker set on the selected root disk.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ProvisioningMarkerState {
    /// No provisioning marker is present.
    Absent,
    /// A transaction began but did not atomically publish its committed label.
    Pending,
    /// Exactly one committed marker with a canonical PARTUUID is present.
    Completed,
    /// The marker set cannot identify one authoritative committed state.
    Indeterminate,
}

/// Validates one typed GPT marker observation.
///
/// # Errors
///
/// Returns an error when the schema, state-dependent fields, or committed
/// marker UUID is inconsistent.
pub fn validate_provisioning_marker_observation(
    observation: &ProvisioningMarkerObservation,
) -> Result<()> {
    if observation.schema != "aos.storage.provisioning-marker-observation/v1" {
        bail!("unsupported provisioning marker observation schema");
    }

    match (
        observation.state,
        observation.source,
        observation.marker_uuid.as_deref(),
    ) {
        (ProvisioningMarkerState::Completed, Some(_), Some(marker_uuid)) => {
            if normalize_marker_uuid(marker_uuid)? != marker_uuid {
                bail!("provisioning marker UUID is not canonical lower-case");
            }
        }
        (ProvisioningMarkerState::Completed, _, _) => {
            bail!("completed provisioning marker observation is incomplete");
        }
        (_, None, None) => {}
        _ => bail!("non-completed provisioning marker carries committed fields"),
    }
    Ok(())
}

/// Canonical target and settings for one partition.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CanonicalPartitionSpec {
    /// Selects the root disk or one stable explicit device path.
    pub target: CanonicalPartitionTarget,
    /// GPT partition label.
    pub label: String,
    /// Semantic partition type or canonical raw GUID.
    pub partition_type: String,
    /// Minimum partition size in systemd size syntax.
    pub size_min: String,
    /// Optional maximum partition size.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub size_max: Option<String>,
    /// Relative free-space allocation weight.
    pub weight: i64,
    /// Optional initial filesystem format.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub format: Option<String>,
    /// Deterministic GPT partition UUID.
    pub uuid: String,
    /// Whether this partition consumes remaining free space.
    pub grow: bool,
    /// Whether an existing filesystem may grow.
    pub grow_fs: bool,
    /// Stable placement priority.
    pub priority: i64,
}

/// Selects the block device that receives one partition.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "kebab-case", deny_unknown_fields)]
pub enum CanonicalPartitionTarget {
    /// Uses the disk containing the active root partition.
    RootDisk,
    /// Uses one provider-selected explicit device path.
    Device {
        /// Absolute normalized path interpreted by the selected provider.
        path: String,
    },
}

/// Validates and converts evaluated provisioning intent into its ability wire plan.
///
/// Missing partition UUIDs are derived once from the durable marker UUID. Optional
/// null fields remain absent in the serialized canonical value.
///
/// # Errors
///
/// Returns an error when the evaluated intent, measured-boot policy, or marker
/// UUID is invalid.
pub fn canonicalize_provisioning_plan(
    mut plan: ProvisioningPlan,
    source: CanonicalProvisioningSource,
    measured_boot: bool,
    marker_uuid: &str,
) -> Result<CanonicalProvisioningPlan> {
    validate_provisioning_plan(&plan, measured_boot)?;
    let marker_uuid = normalize_marker_uuid(marker_uuid)?;
    assign_missing_partition_uuids(&mut plan, &marker_uuid);

    let partitions = plan
        .storage
        .partitions
        .into_iter()
        .map(|(name, partition)| -> Result<_> {
            let target = match partition.device {
                Some(path) => CanonicalPartitionTarget::Device { path },
                None => CanonicalPartitionTarget::RootDisk,
            };
            let uuid = partition
                .uuid
                .context("partition UUID assignment omitted a partition")?;

            Ok((
                name,
                CanonicalPartitionSpec {
                    target,
                    label: partition.label,
                    partition_type: partition.partition_type,
                    size_min: partition.size_min,
                    size_max: partition.size_max,
                    weight: partition.weight,
                    format: partition.format,
                    uuid,
                    grow: partition.grow,
                    grow_fs: partition.grow_fs,
                    priority: partition.priority,
                },
            ))
        })
        .collect::<Result<_>>()?;

    Ok(CanonicalProvisioningPlan {
        schema: "aos.storage.provisioning-plan/v1".into(),
        source,
        marker_uuid,
        measured_boot,
        partitions,
    })
}

/// Validates the complete evaluated provisioning plan.
///
/// # Errors
///
/// Returns an error for an unsupported schema, invalid or duplicated labels,
/// malformed paths, identifiers, sizes or UUIDs, multiple grow partitions per
/// device, or a missing root-disk `var` partition.
pub fn validate_provisioning_plan(plan: &ProvisioningPlan, measured_boot: bool) -> Result<()> {
    if plan.schema != "aos.provisioning-plan/v1" {
        bail!("unsupported provisioning plan schema '{}'", plan.schema);
    }
    if plan.storage.partitions.is_empty() {
        bail!("aos.provisioning.storage.partitions must not be empty");
    }

    let mut labels = BTreeSet::new();
    let mut grow_devices = BTreeSet::new();
    let mut root_var = false;
    for (name, partition) in &plan.storage.partitions {
        validate_label(name, "logical partition name")?;
        validate_label(&partition.label, "GPT partition label")?;
        if !labels.insert(partition.label.as_str()) {
            bail!("duplicate GPT partition label '{}'", partition.label);
        }
        let device = partition.device.as_deref().unwrap_or("root");
        if device != "root" {
            validate_execution_path(device)
                .with_context(|| format!("partition '{name}' device"))?;
        }
        validate_provider_identifier(&partition.partition_type, "partition type")?;
        validate_size(&partition.size_min, "sizeMin", name)?;
        if let Some(max) = partition.size_max.as_deref() {
            validate_size(max, "sizeMax", name)?;
        }
        if partition.weight <= 0 {
            bail!("partition '{name}' weight must be positive");
        }
        if partition.priority < 0 {
            bail!("partition '{name}' priority must be non-negative");
        }
        if let Some(uuid) = partition.uuid.as_deref() {
            validate_uuid(uuid).with_context(|| format!("partition '{name}' uuid"))?;
        }
        if partition.grow && !grow_devices.insert(device) {
            bail!("device '{device}' has more than one grow partition");
        }
        if let Some(format) = partition.format.as_deref() {
            validate_provider_identifier(format, "storage format")
                .with_context(|| format!("partition '{name}' format"))?;
        }
        if partition.label == "var" && partition.device.is_none() {
            root_var = true;
            if measured_boot && partition.format.is_some() {
                bail!("measured boot requires root-disk var to remain raw");
            }
        }
    }
    if !root_var {
        bail!("storage plan must declare label 'var' on the root disk");
    }
    Ok(())
}

/// Validates and normalizes an existing GPT marker UUID.
///
/// # Errors
///
/// Returns an error unless `value` is a canonical hyphenated UUID.
pub fn normalize_marker_uuid(value: &str) -> Result<String> {
    validate_uuid(value)?;
    Ok(value.to_ascii_lowercase())
}

/// Assigns deterministic UUIDs to partitions that do not already carry one.
///
/// The derivation binds each UUID to the durable plan marker, target device,
/// logical name, and label without choosing a storage backend representation.
pub fn assign_missing_partition_uuids(plan: &mut ProvisioningPlan, marker_uuid: &str) {
    for (name, partition) in &mut plan.storage.partitions {
        if partition.uuid.is_some() {
            continue;
        }
        let device = partition.device.as_deref().unwrap_or("root");
        let mut digest = Sha256::new();
        digest.update(b"aos.provisioning.partition-uuid/v1\0");
        digest.update(marker_uuid.as_bytes());
        digest.update(b"\0");
        digest.update(device.as_bytes());
        digest.update(b"\0");
        digest.update(name.as_bytes());
        digest.update(b"\0");
        digest.update(partition.label.as_bytes());
        let output = digest.finalize();
        let mut bytes = [0_u8; 16];
        bytes.copy_from_slice(&output[..16]);
        // RFC 9562 UUID version 8 reserves the payload for application-defined
        // deterministic schemes. Keep the RFC variant bits canonical.
        bytes[6] = (bytes[6] & 0x0f) | 0x80;
        bytes[8] = (bytes[8] & 0x3f) | 0x80;
        partition.uuid = Some(format_uuid(bytes));
    }
}

fn format_uuid(bytes: [u8; 16]) -> String {
    format!(
        "{:02x}{:02x}{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
        bytes[0],
        bytes[1],
        bytes[2],
        bytes[3],
        bytes[4],
        bytes[5],
        bytes[6],
        bytes[7],
        bytes[8],
        bytes[9],
        bytes[10],
        bytes[11],
        bytes[12],
        bytes[13],
        bytes[14],
        bytes[15],
    )
}

fn validate_label(value: &str, kind: &str) -> Result<()> {
    if value.is_empty()
        || value.len() > 36
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
    {
        bail!("{kind} '{value}' must be 1-36 ASCII letters, digits, '.', '_' or '-'");
    }
    Ok(())
}

fn validate_local_key(value: &str, kind: &str) -> Result<()> {
    if value.is_empty()
        || value.len() > 128
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
    {
        bail!("{kind} '{value}' must be 1-128 ASCII letters, digits, '.', '_' or '-'");
    }
    Ok(())
}

fn validate_execution_path(value: &str) -> Result<()> {
    let path = Path::new(value);
    if !path.is_absolute()
        || !path
            .components()
            .all(|part| matches!(part, Component::RootDir | Component::Normal(_)))
    {
        bail!("'{value}' must be an absolute normalized path");
    }
    Ok(())
}

fn validate_provider_identifier(value: &str, kind: &str) -> Result<()> {
    if value.is_empty()
        || value.len() > 64
        || !value.bytes().all(|byte| {
            byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b':' | b'+' | b'-')
        })
    {
        bail!("{kind} '{value}' must be 1-64 portable identifier characters");
    }
    Ok(())
}

fn validate_size(value: &str, field: &str, name: &str) -> Result<()> {
    let digit_count = value.bytes().take_while(u8::is_ascii_digit).count();
    let suffix = &value[digit_count..];
    if digit_count == 0
        || value[..digit_count].bytes().all(|byte| byte == b'0')
        || !matches!(suffix, "" | "K" | "M" | "G" | "T" | "P")
    {
        bail!("partition '{name}' {field} must be a positive integer with K/M/G/T/P suffix");
    }
    Ok(())
}

fn validate_uuid(value: &str) -> Result<()> {
    let bytes = value.as_bytes();
    if bytes.len() != 36
        || !bytes.iter().enumerate().all(|(index, byte)| {
            matches!(index, 8 | 13 | 18 | 23) && *byte == b'-'
                || !matches!(index, 8 | 13 | 18 | 23) && byte.is_ascii_hexdigit()
        })
    {
        bail!("'{value}' is not a canonical UUID");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn empty_observed_facts() -> ObservedInstanceFacts {
        observed_instance_facts(serde_json::json!({
            "hostname": null,
            "ssh_authorized_keys": [],
            "instance_id": null,
            "region": null,
            "availability_zone": null,
            "mac_to_iface": [],
            "disk_ids": [],
            "network": null,
        }))
        .expect("canonical empty facts")
    }

    fn evaluated_plan() -> ProvisioningPlan {
        ProvisioningPlan {
            schema: "aos.provisioning-plan/v1".into(),
            storage: StoragePlan {
                partitions: BTreeMap::from([
                    (
                        "swap".into(),
                        PartitionSpec {
                            device: Some("/dev/disk/by-id/qualification-disk".into()),
                            label: "swap".into(),
                            partition_type: "swap".into(),
                            size_min: "2G".into(),
                            size_max: Some("2G".into()),
                            weight: 1000,
                            format: Some("swap".into()),
                            uuid: None,
                            grow: false,
                            grow_fs: true,
                            priority: 500,
                        },
                    ),
                    (
                        "var".into(),
                        PartitionSpec {
                            device: None,
                            label: "var".into(),
                            partition_type: "linux-generic".into(),
                            size_min: "4G".into(),
                            size_max: None,
                            weight: 1000,
                            format: None,
                            uuid: None,
                            grow: true,
                            grow_fs: true,
                            priority: 9000,
                        },
                    ),
                ]),
            },
        }
    }

    #[test]
    fn canonical_plan_assigns_uuid_and_omits_null_fields() {
        let plan = canonicalize_provisioning_plan(
            evaluated_plan(),
            CanonicalProvisioningSource::Operator,
            false,
            "AAAAAAAA-BBBB-4CCC-8DDD-EEEEEEEEEEEE",
        )
        .expect("valid evaluated provisioning plan");

        assert_eq!(plan.schema, "aos.storage.provisioning-plan/v1");
        assert_eq!(plan.marker_uuid, "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee");
        assert_eq!(
            plan.partitions["var"].target,
            CanonicalPartitionTarget::RootDisk
        );
        assert_eq!(plan.partitions["var"].uuid.len(), 36);

        let value = serde_json::to_value(plan).expect("serializable canonical plan");
        let var = &value["partitions"]["var"];
        assert!(var.get("size_max").is_none());
        assert!(var.get("format").is_none());
    }

    #[test]
    fn canonical_plan_preserves_explicit_partition_uuid() {
        let mut plan = evaluated_plan();
        let expected = "01234567-89ab-cdef-8123-456789abcdef";
        plan.storage
            .partitions
            .get_mut("var")
            .expect("var fixture")
            .uuid = Some(expected.into());

        let canonical = canonicalize_provisioning_plan(
            plan,
            CanonicalProvisioningSource::Fallback,
            false,
            "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee",
        )
        .expect("valid evaluated provisioning plan");

        assert_eq!(canonical.partitions["var"].uuid, expected);
    }

    #[test]
    fn authorized_input_binds_exact_operator_bytes() {
        let host_module = "{ aos.provisioning.storage.partitions.var.sizeMin = \"4G\"; }\n";
        let input = AuthorizedProvisioningInput {
            schema: "aos.metadata.authorized-provisioning-input/v1".into(),
            source: CanonicalProvisioningSource::Operator,
            host_module: Some(host_module.into()),
            host_module_sha256: Some(format!("sha256:{}", hex_digest(host_module.as_bytes()))),
            authorization: ProvisioningAuthorization {
                trust_mode: ProvisioningTrustMode::Signed,
                platform_id: "aos-metadata".into(),
                signer: Some("ops:01234567".into()),
            },
            facts: empty_observed_facts(),
            base_library: BaseLibraryIdentity {
                store_path: "/nix/store/00000000000000000000000000000000-base-lib".into(),
                abi_hash: format!("sha256:{}", "a".repeat(64)),
            },
        };

        validate_authorized_provisioning_input(&input).expect("operator input is self-consistent");
    }

    #[test]
    fn fallback_input_cannot_smuggle_an_operator_module() {
        let input = AuthorizedProvisioningInput {
            schema: "aos.metadata.authorized-provisioning-input/v1".into(),
            source: CanonicalProvisioningSource::Fallback,
            host_module: Some("{}".into()),
            host_module_sha256: Some(format!("sha256:{}", hex_digest(b"{}"))),
            authorization: ProvisioningAuthorization {
                trust_mode: ProvisioningTrustMode::Platform,
                platform_id: "metal".into(),
                signer: None,
            },
            facts: empty_observed_facts(),
            base_library: BaseLibraryIdentity {
                store_path: "/nix/store/00000000000000000000000000000000-base-lib".into(),
                abi_hash: format!("sha256:{}", "b".repeat(64)),
            },
        };

        assert!(validate_authorized_provisioning_input(&input).is_err());
    }

    #[test]
    fn observed_facts_digest_does_not_grant_authorization() {
        let mut facts = empty_observed_facts();
        facts.value["instance_id"] = serde_json::Value::String("changed".into());

        let error = validate_observed_instance_facts(&facts)
            .expect_err("changed observational facts require a new digest");

        assert!(error.to_string().contains("canonical digest"));
    }

    #[test]
    fn observed_facts_cannot_fill_authorization_fields() {
        let host_module = "{}";
        let input = AuthorizedProvisioningInput {
            schema: "aos.metadata.authorized-provisioning-input/v1".into(),
            source: CanonicalProvisioningSource::Operator,
            host_module: Some(host_module.into()),
            host_module_sha256: Some(format!("sha256:{}", hex_digest(host_module.as_bytes()))),
            authorization: ProvisioningAuthorization {
                trust_mode: ProvisioningTrustMode::Signed,
                platform_id: "aos-metadata".into(),
                signer: None,
            },
            facts: observed_instance_facts(serde_json::json!({
                "signer": "untrusted:01234567",
            }))
            .expect("canonical observational facts"),
            base_library: BaseLibraryIdentity {
                store_path: "/nix/store/00000000000000000000000000000000-base-lib".into(),
                abi_hash: format!("sha256:{}", "c".repeat(64)),
            },
        };

        let error = validate_authorized_provisioning_input(&input)
            .expect_err("observational fields cannot satisfy a missing signer");

        assert!(
            error
                .to_string()
                .contains("must identify its matching signer")
        );
    }

    #[test]
    fn completed_marker_requires_exact_source_and_uuid() {
        let observation = ProvisioningMarkerObservation {
            schema: "aos.storage.provisioning-marker-observation/v1".into(),
            state: ProvisioningMarkerState::Completed,
            source: Some(CanonicalProvisioningSource::Operator),
            marker_uuid: Some("aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee".into()),
        };

        validate_provisioning_marker_observation(&observation)
            .expect("complete marker observation");

        let mut incomplete = observation;
        incomplete.marker_uuid = None;
        assert!(validate_provisioning_marker_observation(&incomplete).is_err());
    }

    #[test]
    fn non_completed_marker_cannot_claim_committed_fields() {
        let observation = ProvisioningMarkerObservation {
            schema: "aos.storage.provisioning-marker-observation/v1".into(),
            state: ProvisioningMarkerState::Pending,
            source: Some(CanonicalProvisioningSource::Fallback),
            marker_uuid: None,
        };

        assert!(validate_provisioning_marker_observation(&observation).is_err());
    }
}
