//! Fixture-only derivation from the exact initially selected Worker bindings.
//!
//! Only public profile, policy and issuer coordinates are returned. Credentials
//! and candidate keys are read for equality/fingerprint checks and never emitted.
//!
//! A public projection is a closed object; secret bindings are never serialized:
//!
//! ```json
//! {"version":1,"bindings":{"HUB_DEPLOYMENT_ID":"fixture", "...":"remaining public coordinates"},"r2BucketNamespace":"fixture-bucket"}
//! ```
//! The abbreviated example illustrates the envelope. The implementation requires
//! exactly all sixteen named public coordinates and actual private file custody.

use super::*;
use aos_hub_core::direct_upload::{
    direct_private_stage_policy_commitment, DirectChecksumAlgorithm,
    DirectClockPolicy, DirectClockPolicyMode,
};
use aos_hub_core::direct_upload::WireInteger;

#[derive(Clone, Debug, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
/// Pins actual private config custody without committing secret content.
pub(super) struct ConfigCustody {
    /// Actual observing guest UID.
    pub(super) owner_uid: u32,
    /// Exact private file mode, required to be 0600.
    pub(super) mode: String,
    /// Actual hardlink count, required to be one.
    pub(super) nlink: String,
    /// Actual filesystem device identifier.
    pub(super) device: String,
    /// Actual selected inode, preserved through each SDK read.
    pub(super) inode: String,
    /// Actual bounded file size, containing no content digest.
    pub(super) bytes: String,
    /// Actual modification timestamp seconds.
    pub(super) modified_seconds: String,
    /// Actual modification timestamp nanoseconds.
    pub(super) modified_nanos: String,
    /// Actual inode-change timestamp seconds.
    pub(super) changed_seconds: String,
    /// Actual inode-change timestamp nanoseconds.
    pub(super) changed_nanos: String,
}

fn custody(metadata: &fs::Metadata) -> ConfigCustody {
    ConfigCustody {
        owner_uid: metadata.uid(), mode: format!("{:04o}", metadata.mode() & 0o777),
        nlink: metadata.nlink().to_string(), device: metadata.dev().to_string(),
        inode: metadata.ino().to_string(), bytes: metadata.len().to_string(),
        modified_seconds: metadata.mtime().to_string(), modified_nanos: metadata.mtime_nsec().to_string(),
        changed_seconds: metadata.ctime().to_string(), changed_nanos: metadata.ctime_nsec().to_string(),
    }
}

/// Reads actual private config for opaque SDK use without hashing secret values.
///
/// # Errors
/// Returns an error for changed selected custody, links, permissions or size.
pub(super) fn read_configuration(path: &Path, expected: &ConfigCustody) -> Result<serde_json::Value> {
    let before = fs::symlink_metadata(path)?;
    ensure!(before.is_file() && before.uid() == fs::metadata("/proc/self")?.uid()
        && before.nlink() == 1 && before.mode() & 0o777 == 0o600 && before.len() <= 256 * 1024
        && custody(&before) == *expected, "actual private config custody differs");
    // The existing SDK reader validates every ancestor, opens without following
    // links and retains its bounded actual descriptor through the complete read.
    let raw = private_bytes(path, 256 * 1024)?;
    ensure!(raw.len() as u64 == before.len()
        && custody(&fs::symlink_metadata(path)?) == *expected,
        "actual private config changed during SDK read");
    Ok(serde_json::from_slice(&raw)?)
}

const PUBLIC_BINDINGS: &[&str] = &[
    "HUB_DEPLOYMENT_ID", "HUB_DIRECT_UPLOAD_MANAGED_R2",
    "HUB_MIRROR_CANDIDATE_SOURCE_SHA256", "HUB_MIRROR_CANDIDATE_SCRIPT_VERSION",
    "HUB_DIRECT_UPLOAD_CLOCK_MODE", "HUB_DIRECT_UPLOAD_CLOCK_UNCERTAINTY_SECONDS",
    "HUB_DIRECT_UPLOAD_CLOCK_QUALIFICATION", "HUB_DIRECT_UPLOAD_R2_ACCOUNT_ID",
    "HUB_DIRECT_UPLOAD_R2_BUCKET_NAME", "HUB_DIRECT_UPLOAD_R2_BUCKET_NAMESPACE",
    "HUB_DIRECT_UPLOAD_R2_CREDENTIAL_ID", "HUB_DIRECT_UPLOAD_R2_CREDENTIAL_GENERATION",
    "HUB_DIRECT_UPLOAD_R2_SECRET_VERSION_REF", "HUB_DIRECT_UPLOAD_R2_CHECKSUM",
    "HUB_DIRECT_UPLOAD_R2_PRIVATE_POLICY_ID", "HUB_DIRECT_UPLOAD_R2_PRIVATE_POLICY_DIGEST",
];

/// Selects only closed public coordinates, excluding all credential/key values.
///
/// # Errors
/// Returns an error if an actual public binding or bucket namespace is missing.
pub(super) fn public_projection(configuration: &serde_json::Value) -> Result<serde_json::Value> {
    let mut bindings = serde_json::Map::new();
    for name in PUBLIC_BINDINGS {
        bindings.insert((*name).into(), json!(binding(configuration, name)?));
    }
    let namespace = configuration.get("r2Buckets").and_then(|value| value.get("REGISTRY_BUCKET"))
        .and_then(serde_json::Value::as_str).context("actual selected bucket namespace absent")?;
    Ok(json!({"version":1,"bindings":bindings,"r2BucketNamespace":namespace}))
}

pub(super) struct Material {
    /// Raw current protected coordinates, not accepted runtime evidence.
    pub(super) profile: DirectManagedR2Profile,
    /// Core-derived private namespace policy commitment.
    pub(super) policy: DirectPrivateStagePolicyRef,
    /// Actual source-built emulator identity selected before startup.
    pub(super) issuer: MirrorGuardIssuer,
}

fn binding<'a>(configuration: &'a serde_json::Value, name: &str) -> Result<&'a str> {
    configuration.get("bindings").and_then(|value| value.get(name))
        .and_then(serde_json::Value::as_str).context("selected candidate binding absent")
}

fn integer(configuration: &serde_json::Value, name: &str) -> Result<u64> {
    let raw = binding(configuration, name)?;
    let number: u64 = raw.parse().context("candidate binding integer malformed")?;
    ensure!(raw == number.to_string(), "candidate binding integer noncanonical");
    Ok(number)
}

/// Computes missing pre-start commitments while refusing conflicting values.
///
/// The returned projection is installed before startup. Subsequent consumers
/// require a separately pinned complete installed configuration and strict derive.
/// This commitment does not observe actual provider privacy or grant acceptance.
///
/// # Errors
/// Returns an error for malformed coordinates, conflicting commitments or material.
pub(super) fn derive_seed(configuration: &serde_json::Value) -> Result<(Material, serde_json::Value, serde_json::Value)> {
    let uncertainty = integer(configuration, "HUB_DIRECT_UPLOAD_CLOCK_UNCERTAINTY_SECONDS")?;
    let clock = DirectClockPolicy { version: 1, mode: DirectClockPolicyMode::BoundedUtc,
        uncertainty_seconds: WireInteger::new(uncertainty) };
    let policy = direct_private_stage_policy_commitment(
        binding(configuration, "HUB_DIRECT_UPLOAD_R2_PRIVATE_POLICY_ID")?,
        binding(configuration, "HUB_DIRECT_UPLOAD_R2_BUCKET_NAMESPACE")?)?;
    let projection = json!({
        "HUB_DIRECT_UPLOAD_CLOCK_QUALIFICATION":clock.commitment()?,
        "HUB_DIRECT_UPLOAD_R2_PRIVATE_POLICY_DIGEST":policy,
    });
    let mut completed = configuration.clone();
    let bindings = completed.get_mut("bindings").and_then(serde_json::Value::as_object_mut)
        .context("candidate seed bindings absent")?;
    for (name, expected) in projection.as_object().context("candidate projection malformed")? {
        if let Some(supplied) = bindings.get(name) {
            ensure!(supplied == expected, "candidate seed commitment differs");
        } else {
            bindings.insert(name.clone(), expected.clone());
        }
    }
    Ok((derive(&completed)?, projection, public_projection(&completed)?))
}

/// Derives a secret-free projection from actual initially selected bindings.
///
/// # Errors
/// Returns an error for missing or inconsistent material, clock, keys or policy.
pub(super) fn derive(configuration: &serde_json::Value) -> Result<Material> {
    ensure!(binding(configuration, "HUB_DIRECT_UPLOAD_MANAGED_R2")? == "true",
        "actual candidate Managed descriptor is disabled");
    let uncertainty = integer(configuration, "HUB_DIRECT_UPLOAD_CLOCK_UNCERTAINTY_SECONDS")?;
    let clock = DirectClockPolicy {
        version: 1, mode: DirectClockPolicyMode::BoundedUtc,
        uncertainty_seconds: WireInteger::new(uncertainty),
    };
    let clock_digest = clock.commitment()?;
    ensure!((1..30).contains(&uncertainty)
        && binding(configuration, "HUB_DIRECT_UPLOAD_CLOCK_MODE")? == "bounded_utc"
        && binding(configuration, "HUB_DIRECT_UPLOAD_CLOCK_QUALIFICATION")? == clock_digest,
        "actual candidate clock projection differs");
    let mut profile = DirectManagedR2Profile {
        deployment_id: binding(configuration, "HUB_DEPLOYMENT_ID")?.to_owned(),
        bucket_namespace: binding(configuration, "HUB_DIRECT_UPLOAD_R2_BUCKET_NAMESPACE")?.to_owned(),
        account_id: binding(configuration, "HUB_DIRECT_UPLOAD_R2_ACCOUNT_ID")?.to_owned(),
        bucket_name: binding(configuration, "HUB_DIRECT_UPLOAD_R2_BUCKET_NAME")?.to_owned(),
        credential_id: binding(configuration, "HUB_DIRECT_UPLOAD_R2_CREDENTIAL_ID")?.to_owned(),
        credential_generation: WireInteger::new(integer(configuration,
            "HUB_DIRECT_UPLOAD_R2_CREDENTIAL_GENERATION")?),
        secret_version_ref: binding(configuration, "HUB_DIRECT_UPLOAD_R2_SECRET_VERSION_REF")?.to_owned(),
        credential_fingerprint: String::new(),
        checksum_algorithm: match binding(configuration, "HUB_DIRECT_UPLOAD_R2_CHECKSUM")? {
            "md5" => DirectChecksumAlgorithm::Md5,
            "sha256" => DirectChecksumAlgorithm::Sha256,
            _ => anyhow::bail!("candidate checksum is unsupported"),
        },
        clock_qualification: clock_digest,
        clock_uncertainty_seconds: WireInteger::new(uncertainty),
    };
    ensure!(profile.account_id.len() == 32 && profile.account_id.bytes()
        .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase()),
        "candidate account coordinate malformed");
    let namespace = configuration.get("r2Buckets").and_then(|value| value.get("REGISTRY_BUCKET"))
        .and_then(serde_json::Value::as_str).context("actual selected bucket namespace absent")?;
    ensure!(profile.bucket_namespace == namespace, "candidate bucket namespace differs");
    profile.credential_fingerprint = profile.fingerprint_with_credentials(
        binding(configuration, "HUB_DIRECT_UPLOAD_R2_ACCESS_KEY_ID")?,
        binding(configuration, "HUB_DIRECT_UPLOAD_R2_SECRET_ACCESS_KEY")?)?;
    profile.validate()?;
    let policy = DirectPrivateStagePolicyRef {
        policy_id: binding(configuration, "HUB_DIRECT_UPLOAD_R2_PRIVATE_POLICY_ID")?.to_owned(),
        policy_digest: binding(configuration, "HUB_DIRECT_UPLOAD_R2_PRIVATE_POLICY_DIGEST")?.to_owned(),
        namespace: namespace.to_owned(),
    };
    ensure!(policy.policy_digest == direct_private_stage_policy_commitment(
        &policy.policy_id, &policy.namespace)?, "candidate private policy projection differs");
    let issuer = MirrorGuardIssuer {
        source_digest: binding(configuration, "HUB_MIRROR_CANDIDATE_SOURCE_SHA256")?.to_owned(),
        script_version: binding(configuration, "HUB_MIRROR_CANDIDATE_SCRIPT_VERSION")?.to_owned(),
    };
    ensure!(aos_hub_core::direct_upload::valid_direct_digest(&issuer.source_digest)
        && issuer.script_version == format!("emulated-{}", issuer.source_digest),
        "candidate source/script projection differs");
    let candidate = binding(configuration, "HUB_MIRROR_CANDIDATE_KEY")?;
    ensure!((32..=8192).contains(&candidate.len())
        && candidate != binding(configuration, "HUB_STORAGE_WORK_KEY")?,
        "candidate key reuses ordinary work authority");
    StorageWorkKey::new(candidate)?;
    aos_hub_core::mirror_acceptance::mirror_candidate_profile_digest(&profile, &policy)?;
    Ok(Material { profile, policy, issuer })
}

/// Reopens the initial config and compares every selected candidate coordinate.
///
/// # Errors
/// Returns an error for changed custody/public projection or crossed source, clock, material or key.
pub(super) fn checked_work(
    work: RemoteStorageWorkClient,
    input: &Input,
    configuration_file: &Path,
    configuration_custody: &ConfigCustody,
    public_configuration_file: &Path,
    public_configuration_digest: &str,
    managed_profile_file: &Path,
    policy_file: &Path,
    candidate_key_file: &Path,
    issuer: MirrorGuardIssuer,
) -> Result<RemoteStorageWorkClient> {
    let configuration = read_configuration(configuration_file, configuration_custody)?;
    let public_raw = private_bytes(public_configuration_file, MAX_INPUT_BYTES)?;
    let expected_public: serde_json::Value = serde_json::from_slice(&public_raw)?;
    let actual_public = public_projection(&configuration)?;
    ensure!(expected_public == actual_public
        && aos_hub_core::mirror_work::digest(&actual_public)? == public_configuration_digest,
        "selected public configuration differs from actual private config");
    let actual = derive(&configuration)?;
    let profile: DirectManagedR2Profile = serde_json::from_slice(
        &private_bytes(managed_profile_file, MAX_INPUT_BYTES)?)?;
    let policy: DirectPrivateStagePolicyRef = serde_json::from_slice(
        &private_bytes(policy_file, MAX_INPUT_BYTES)?)?;
    ensure!(profile == actual.profile && policy == actual.policy && issuer == actual.issuer
        && profile.deployment_id == input.deployment_id
        && issuer.source_digest == input.worker_source_digest
        && issuer.script_version == input.worker_script_version
        && i64::try_from(profile.clock_uncertainty_seconds.get())? == input.clock_uncertainty_seconds,
        "candidate material differs from actual selected configuration/source/clock");
    let key = private_bytes(candidate_key_file, 8192)?;
    ensure!(key.as_slice() == binding(&configuration, "HUB_MIRROR_CANDIDATE_KEY")?.as_bytes(),
        "selected candidate key differs from actual configuration");
    work.with_controlled_mirror(&profile, &policy, issuer, &key)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn configuration() -> serde_json::Value {
        let namespace = "fixture-bucket-namespace";
        let clock = DirectClockPolicy { version: 1, mode: DirectClockPolicyMode::BoundedUtc,
            uncertainty_seconds: WireInteger::new(1) };
        json!({"r2Buckets":{"REGISTRY_BUCKET":namespace},"bindings":{
            "HUB_DEPLOYMENT_ID":"fixture-deployment", "HUB_DIRECT_UPLOAD_MANAGED_R2":"true",
            "HUB_STORAGE_WORK_KEY":"ordinary-fixture-key".repeat(2),
            "HUB_MIRROR_CANDIDATE_KEY":"separate-fixture-key".repeat(2),
            "HUB_MIRROR_CANDIDATE_SOURCE_SHA256":"ab".repeat(32),
            "HUB_MIRROR_CANDIDATE_SCRIPT_VERSION":format!("emulated-{}", "ab".repeat(32)),
            "HUB_DIRECT_UPLOAD_CLOCK_MODE":"bounded_utc",
            "HUB_DIRECT_UPLOAD_CLOCK_QUALIFICATION":clock.commitment().unwrap(),
            "HUB_DIRECT_UPLOAD_CLOCK_UNCERTAINTY_SECONDS":"1",
            "HUB_DIRECT_UPLOAD_R2_ACCESS_KEY_ID":"fixture-access",
            "HUB_DIRECT_UPLOAD_R2_SECRET_ACCESS_KEY":"fixture-secret",
            "HUB_DIRECT_UPLOAD_R2_ACCOUNT_ID":"01".repeat(16),
            "HUB_DIRECT_UPLOAD_R2_BUCKET_NAME":"fixture-bucket",
            "HUB_DIRECT_UPLOAD_R2_BUCKET_NAMESPACE":namespace,
            "HUB_DIRECT_UPLOAD_R2_CREDENTIAL_ID":"fixture-credential",
            "HUB_DIRECT_UPLOAD_R2_CREDENTIAL_GENERATION":"1",
            "HUB_DIRECT_UPLOAD_R2_SECRET_VERSION_REF":"fixture-secret-version",
            "HUB_DIRECT_UPLOAD_R2_CHECKSUM":"md5",
            "HUB_DIRECT_UPLOAD_R2_PRIVATE_POLICY_ID":"fixture-private-policy",
            "HUB_DIRECT_UPLOAD_R2_PRIVATE_POLICY_DIGEST":direct_private_stage_policy_commitment(
                "fixture-private-policy", namespace).unwrap()}})
    }

    #[test]
    fn candidate_material_uses_actual_credential_fingerprint_and_core_policy() {
        let config = configuration();
        let material = derive(&config).unwrap();
        assert_eq!(material.profile.credential_fingerprint,
            material.profile.fingerprint_with_credentials("fixture-access", "fixture-secret").unwrap());
        let mut changed = config;
        changed["bindings"]["HUB_DIRECT_UPLOAD_R2_SECRET_ACCESS_KEY"] = json!("changed-fixture-secret");
        assert_ne!(derive(&changed).unwrap().profile.credential_fingerprint,
            material.profile.credential_fingerprint);
        let public = serde_json::to_string(&json!({"profile":material.profile,"policy":material.policy,
            "issuer":material.issuer})).unwrap();
        assert!(!public.contains("fixture-access") && !public.contains("fixture-secret\""));
        assert!(!public.contains("separate-fixture-key"));
        let mut seed = configuration();
        seed["bindings"].as_object_mut().unwrap().remove("HUB_DIRECT_UPLOAD_CLOCK_QUALIFICATION");
        seed["bindings"].as_object_mut().unwrap().remove("HUB_DIRECT_UPLOAD_R2_PRIVATE_POLICY_DIGEST");
        assert!(derive(&seed).is_err());
        let (derived, projection, public_projection) = derive_seed(&seed).unwrap();
        assert_eq!(derived.profile.credential_fingerprint, material.profile.credential_fingerprint);
        assert_eq!(projection.as_object().unwrap().len(), 2);
        let public_json = serde_json::to_string(&public_projection).unwrap();
        assert!(!public_json.contains("fixture-secret\"")
            && !public_json.contains("fixture-access") && !public_json.contains("fixture-key"));
        seed["bindings"]["HUB_DIRECT_UPLOAD_R2_PRIVATE_POLICY_DIGEST"] = json!("wrong");
        assert!(derive_seed(&seed).is_err());
    }

    #[test]
    fn candidate_material_refuses_namespace_clock_source_key_and_flag_drift() {
        for (key, value) in [
            ("HUB_DIRECT_UPLOAD_R2_BUCKET_NAMESPACE", "wrong-namespace"),
            ("HUB_DIRECT_UPLOAD_CLOCK_QUALIFICATION", "wrong-clock"),
            ("HUB_MIRROR_CANDIDATE_SCRIPT_VERSION", "wrong-source"),
            ("HUB_MIRROR_CANDIDATE_KEY", "ordinary-fixture-keyordinary-fixture-key"),
            ("HUB_DIRECT_UPLOAD_MANAGED_R2", "false"),
            ("HUB_DIRECT_UPLOAD_R2_CREDENTIAL_GENERATION", "01"),
        ] {
            let mut changed = configuration();
            changed["bindings"][key] = json!(value);
            assert!(derive(&changed).is_err(), "{key}");
        }
    }
}
