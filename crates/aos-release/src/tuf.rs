//! Role-separated TUF metadata contracts and offline verification.
//!
//! The registry metadata surface carries root, top-level targets/delegations,
//! release-class delegated targets, and snapshot metadata. These files are
//! repository metadata rather than targets and therefore remain outside the
//! manifest payload closure they authorize. Timestamp metadata is verified as
//! an independently renewable pointer to the already-authorized snapshot.

use std::collections::{BTreeMap, BTreeSet};

use anyhow::{Context as _, Result, bail};
use base64::Engine as _;
use serde::{Deserialize, Serialize};

use crate::canonical;
use crate::digest::Sha256Digest;
use crate::plan::ReleaseClass;
use crate::registry::registry_policy;
use crate::signing::{
    SignatureResponseV1, SignerRole, SigningContext, SigningOperation, SigningRequestV1,
    TrustedEd25519Key, verify_ed25519_response,
};

/// TUF specification profile implemented by canonical AOS releases.
pub const TUF_SPEC_VERSION: &str = "1.0.31";
/// Schema for root metadata.
pub const TUF_ROOT_V1: &str = "aos.release.tuf-root/v1";
/// Schema for top-level targets and delegation metadata.
pub const TUF_TARGETS_V1: &str = "aos.release.tuf-targets/v1";
/// Schema for delegated release-class targets metadata.
pub const TUF_DELEGATED_TARGETS_V1: &str = "aos.release.tuf-delegated-targets/v1";
/// Schema for snapshot metadata.
pub const TUF_SNAPSHOT_V1: &str = "aos.release.tuf-snapshot/v1";
/// Schema for independently renewable timestamp metadata.
pub const TUF_TIMESTAMP_V1: &str = "aos.release.tuf-timestamp/v1";

/// Closed metadata roles with independent key policies.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum TufRole {
    /// Root-of-trust and role roster.
    Root,
    /// Top-level targets and delegations.
    Targets,
    /// Stable and emergency release authorization.
    Stable,
    /// Release-candidate authorization.
    Candidate,
    /// Integration-edge authorization.
    Edge,
    /// Immutable metadata-set snapshot.
    Snapshot,
    /// Short-lived snapshot freshness pointer.
    Timestamp,
}

impl TufRole {
    /// Returns the signer authority required for this TUF role.
    #[must_use]
    pub const fn signer_role(self) -> SignerRole {
        match self {
            Self::Root => SignerRole::TufRoot,
            Self::Targets => SignerRole::TufTargets,
            Self::Stable => SignerRole::TufStable,
            Self::Candidate => SignerRole::TufCandidate,
            Self::Edge => SignerRole::TufEdge,
            Self::Snapshot => SignerRole::TufSnapshot,
            Self::Timestamp => SignerRole::TufTimestamp,
        }
    }

    /// Returns the canonical metadata role name.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Root => "root",
            Self::Targets => "targets",
            Self::Stable => "stable",
            Self::Candidate => "candidate",
            Self::Edge => "edge",
            Self::Snapshot => "snapshot",
            Self::Timestamp => "timestamp",
        }
    }

    /// Returns the delegated metadata role that authorizes a release class.
    #[must_use]
    pub const fn for_release(class: ReleaseClass) -> Self {
        match class {
            ReleaseClass::Edge => Self::Edge,
            ReleaseClass::Candidate => Self::Candidate,
            ReleaseClass::Stable | ReleaseClass::Emergency => Self::Stable,
        }
    }
}

/// Constructs canonical top-level targets metadata.
///
/// # Errors
///
/// Returns an error for a zero version or malformed/non-UTC expiry.
pub fn canonical_targets_metadata(
    registry: &str,
    version: u64,
    expires: String,
) -> Result<TargetsMetadataV1> {
    let metadata = TargetsMetadataV1 {
        schema_version: TUF_TARGETS_V1.to_owned(),
        spec_version: TUF_SPEC_VERSION.to_owned(),
        registry: registry.to_owned(),
        version,
        expires,
        delegations: [
            (TufRole::Stable, "releases/stable/"),
            (TufRole::Candidate, "releases/candidate/"),
            (TufRole::Edge, "releases/edge/"),
        ]
        .into_iter()
        .map(|(role, path_prefix)| TufDelegationV1 {
            role,
            path_prefix: path_prefix.to_owned(),
            terminating: true,
        })
        .collect(),
    };
    validate_targets(&metadata)?;
    require_valid_expiry(&metadata.expires)?;
    Ok(metadata)
}

/// Constructs one canonical delegated release authorization.
///
/// # Errors
///
/// Returns an error for malformed identity, class/path mismatch, a zero
/// version or length, or malformed/non-UTC expiry.
pub fn delegated_release_metadata(
    registry: &str,
    version: u64,
    expires: String,
    target: TufReleaseTargetV1,
) -> Result<DelegatedTargetsMetadataV1> {
    let role = TufRole::for_release(target.release_class);
    let metadata = DelegatedTargetsMetadataV1 {
        schema_version: TUF_DELEGATED_TARGETS_V1.to_owned(),
        spec_version: TUF_SPEC_VERSION.to_owned(),
        registry: registry.to_owned(),
        role,
        version,
        expires,
        targets: vec![target],
    };
    let target = &metadata.targets[0];
    validate_delegated(
        &metadata,
        &target.release_id,
        target.release_class,
        target.manifest_digest,
    )?;
    require_valid_expiry(&metadata.expires)?;
    Ok(metadata)
}

/// Constructs a snapshot over exact already-signed immutable envelopes.
///
/// # Errors
///
/// Returns an error for a zero version, malformed/non-UTC expiry, or an
/// envelope that cannot be canonically encoded.
pub fn immutable_snapshot_metadata(
    registry: &str,
    version: u64,
    expires: String,
    root: &TufEnvelopeV1<RootMetadataV1>,
    targets: &TufEnvelopeV1<TargetsMetadataV1>,
    delegated: &TufEnvelopeV1<DelegatedTargetsMetadataV1>,
) -> Result<SnapshotMetadataV1> {
    let metadata = SnapshotMetadataV1 {
        schema_version: TUF_SNAPSHOT_V1.to_owned(),
        spec_version: TUF_SPEC_VERSION.to_owned(),
        registry: registry.to_owned(),
        version,
        expires,
        metadata: vec![
            metadata_description(
                format!("{}.root.json", root.signed.version),
                root.signed.version,
                root,
            )?,
            metadata_description(
                format!("{}.targets.json", targets.signed.version),
                targets.signed.version,
                targets,
            )?,
            metadata_description(
                format!(
                    "{}.{}.json",
                    delegated.signed.version,
                    delegated.signed.role.as_str()
                ),
                delegated.signed.version,
                delegated,
            )?,
        ],
    };
    validate_common(&metadata, TUF_SNAPSHOT_V1)?;
    require_valid_expiry(&metadata.expires)?;
    Ok(metadata)
}

/// Constructs a short-lived timestamp over one exact signed snapshot.
///
/// # Errors
///
/// Returns an error when its version is zero, times are malformed, expiry is
/// not after issuance, its validity exceeds 48 hours, or canonical encoding
/// of the snapshot fails.
pub fn timestamp_metadata(
    registry: &str,
    version: u64,
    issued_at: String,
    expires: String,
    snapshot: &TufEnvelopeV1<SnapshotMetadataV1>,
) -> Result<TimestampMetadataV1> {
    let metadata = TimestampMetadataV1 {
        schema_version: TUF_TIMESTAMP_V1.to_owned(),
        spec_version: TUF_SPEC_VERSION.to_owned(),
        registry: registry.to_owned(),
        version,
        issued_at,
        expires,
        snapshot: metadata_description(
            format!("{}.snapshot.json", snapshot.signed.version),
            snapshot.signed.version,
            snapshot,
        )?,
    };
    validate_common(&metadata, TUF_TIMESTAMP_V1)?;
    let issued = parse_utc(&metadata.issued_at, "TUF timestamp issuance")?;
    validate_timestamp_freshness(&metadata, issued)?;
    Ok(metadata)
}

/// Validates a production-strength unsigned root policy before signing.
///
/// # Errors
///
/// Returns an error for malformed metadata, collapsed authorities, missing
/// roles, weak thresholds, invalid keys, or malformed/non-UTC expiry.
pub fn validate_root_metadata(root: &RootMetadataV1) -> Result<()> {
    validate_root(root)?;
    require_valid_expiry(&root.expires)
}

/// Computes the role-domain digest an external signer must authorize.
///
/// # Errors
///
/// Returns an error when `metadata` cannot be represented as canonical JSON.
pub fn metadata_signing_digest(role: TufRole, metadata: &impl Serialize) -> Result<Sha256Digest> {
    Sha256Digest::of_canonical(&format!("aos.release.tuf-{}/v1", role.as_str()), metadata)
}

/// Describes the exact canonical bytes of one signed metadata envelope.
///
/// # Errors
///
/// Returns an error for canonical encoding or length conversion failure.
pub fn metadata_description<T: Serialize>(
    path: String,
    version: u64,
    envelope: &TufEnvelopeV1<T>,
) -> Result<TufMetadataDescriptionV1> {
    let bytes = canonical::to_vec(envelope)?;
    Ok(TufMetadataDescriptionV1 {
        path,
        version,
        length: u64::try_from(bytes.len())?,
        sha256: Sha256Digest::of_bytes(bytes),
    })
}

/// One Ed25519 public key authorized by root metadata.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct TufKeyV1 {
    /// Stable key id used by role policies.
    pub key_id: String,
    /// Exact raw 32-byte Ed25519 key in standard base64.
    pub public_key_base64: String,
    /// Independently auditable provider, device, or certificate identity.
    pub verification_identity: String,
}

/// Threshold policy for one independent TUF role.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct TufRolePolicyV1 {
    /// Closed role governed by the policy.
    pub role: TufRole,
    /// Sorted unique eligible key ids.
    pub key_ids: Vec<String>,
    /// Required number of distinct valid signatures.
    pub threshold: u16,
}

/// Root metadata signed by both sides of every root rotation.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RootMetadataV1 {
    /// Exact AOS schema.
    pub schema_version: String,
    /// TUF specification profile.
    pub spec_version: String,
    /// Canonical registry identity.
    pub registry: String,
    /// Strictly increasing root version.
    pub version: u64,
    /// RFC 3339 UTC expiry.
    pub expires: String,
    /// Whether version-prefixed immutable metadata is required.
    pub consistent_snapshot: bool,
    /// Sorted unique public keys.
    pub keys: Vec<TufKeyV1>,
    /// Exactly one independent policy for every role.
    pub roles: Vec<TufRolePolicyV1>,
}

/// One terminating release-class delegation from top-level targets.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct TufDelegationV1 {
    /// Delegated release role.
    pub role: TufRole,
    /// Exact path prefix controlled by this delegation.
    pub path_prefix: String,
    /// Whether lookup stops after matching this delegation.
    pub terminating: bool,
}

/// Top-level targets metadata containing only delegation structure.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct TargetsMetadataV1 {
    /// Exact AOS schema.
    pub schema_version: String,
    /// TUF specification profile.
    pub spec_version: String,
    /// Canonical registry identity.
    pub registry: String,
    /// Strictly increasing metadata version.
    pub version: u64,
    /// RFC 3339 UTC expiry.
    pub expires: String,
    /// Disjoint stable, candidate, and edge delegations.
    pub delegations: Vec<TufDelegationV1>,
}

/// One immutable release manifest authorized by a delegated role.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct TufReleaseTargetV1 {
    /// Delegated path under `releases/<class>/`.
    pub path: String,
    /// Immutable release id.
    pub release_id: String,
    /// Release class constrained by the delegated role.
    pub release_class: ReleaseClass,
    /// Exact signed manifest-envelope digest; that manifest closes payloads.
    pub manifest_digest: Sha256Digest,
    /// Exact manifest-envelope byte length.
    pub length: u64,
}

/// Release-class delegated targets metadata.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct DelegatedTargetsMetadataV1 {
    /// Exact AOS schema.
    pub schema_version: String,
    /// TUF specification profile.
    pub spec_version: String,
    /// Canonical registry identity.
    pub registry: String,
    /// Stable, candidate, or edge delegated role.
    pub role: TufRole,
    /// Strictly increasing metadata version.
    pub version: u64,
    /// RFC 3339 UTC expiry.
    pub expires: String,
    /// Sorted unique release targets.
    pub targets: Vec<TufReleaseTargetV1>,
}

/// Hash, length, and version of one exact metadata envelope.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct TufMetadataDescriptionV1 {
    /// Canonical version-prefixed metadata filename.
    pub path: String,
    /// Exact metadata version.
    pub version: u64,
    /// Exact envelope byte length.
    pub length: u64,
    /// SHA-256 of exact canonical envelope bytes.
    pub sha256: Sha256Digest,
}

/// Immutable snapshot over already authorized metadata.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SnapshotMetadataV1 {
    /// Exact AOS schema.
    pub schema_version: String,
    /// TUF specification profile.
    pub spec_version: String,
    /// Canonical registry identity.
    pub registry: String,
    /// Strictly increasing snapshot version.
    pub version: u64,
    /// RFC 3339 UTC expiry.
    pub expires: String,
    /// Sorted exact root, targets, and delegated-role envelopes.
    pub metadata: Vec<TufMetadataDescriptionV1>,
}

/// Independently renewable freshness pointer to one authorized snapshot.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct TimestampMetadataV1 {
    /// Exact AOS schema.
    pub schema_version: String,
    /// TUF specification profile.
    pub spec_version: String,
    /// Canonical registry identity.
    pub registry: String,
    /// Strictly increasing timestamp version.
    pub version: u64,
    /// RFC 3339 UTC issuance time used to enforce the freshness window.
    pub issued_at: String,
    /// RFC 3339 UTC expiry no more than 48 hours after issuance policy permits.
    pub expires: String,
    /// Exact already-authorized snapshot envelope.
    pub snapshot: TufMetadataDescriptionV1,
}

/// One role-bound release signature embedded in TUF metadata.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct TufSignatureV1 {
    /// Complete external-signer request.
    pub request: SigningRequestV1,
    /// Public external-signer response.
    pub response: SignatureResponseV1,
}

/// Signed TUF envelope with a canonical payload.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct TufEnvelopeV1<T> {
    /// Role-specific signed metadata.
    pub signed: T,
    /// Threshold signature requests and responses.
    pub signatures: Vec<TufSignatureV1>,
}

/// Complete immutable metadata set stored in a release bundle.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ImmutableTufSetV1 {
    /// Root metadata.
    pub root: TufEnvelopeV1<RootMetadataV1>,
    /// Top-level targets and delegations.
    pub targets: TufEnvelopeV1<TargetsMetadataV1>,
    /// Release-class authorization.
    pub delegated: TufEnvelopeV1<DelegatedTargetsMetadataV1>,
    /// Snapshot binding the preceding envelopes.
    pub snapshot: TufEnvelopeV1<SnapshotMetadataV1>,
}

/// Trusted bootstrap policy supplied independently of root metadata.
pub struct TufRootTrust<'a> {
    /// Independently authenticated root public keys.
    pub keys: &'a [TrustedEd25519Key],
    /// Required distinct bootstrap signatures.
    pub threshold: u16,
}

/// Exact release identity that delegated targets must authorize.
pub struct TufReleaseExpectation<'a> {
    /// Registry trust domain authenticated by the release plan.
    pub registry: &'a str,
    /// Immutable release id.
    pub release_id: &'a str,
    /// Release class selecting the delegated role.
    pub release_class: ReleaseClass,
    /// Final signed manifest-envelope digest; that manifest closes payloads.
    pub manifest_digest: Sha256Digest,
}

/// Verifies an independently bootstrapped root envelope and optional rotation.
///
/// # Errors
///
/// Returns an error for malformed or expired root metadata, weak or collapsed
/// role policy, failed bootstrap/new-root thresholds, or an invalid rotation.
pub fn verify_root_envelope(
    root: &TufEnvelopeV1<RootMetadataV1>,
    trust: &TufRootTrust<'_>,
    previous_root: Option<&TufEnvelopeV1<RootMetadataV1>>,
    now: std::time::SystemTime,
) -> Result<()> {
    validate_root(&root.signed)?;
    verify_root(root, trust, previous_root, now)
}

/// Verifies a snapshot envelope against the role policy in a trusted root.
///
/// This establishes snapshot authority and expiry. A caller verifying a full
/// immutable set must additionally compare every described predecessor via
/// [`verify_immutable_set`].
///
/// # Errors
///
/// Returns an error for malformed root/snapshot metadata, expiry, an invalid
/// role signature threshold, or a public verification-identity mismatch.
pub fn verify_snapshot_envelope(
    snapshot: &TufEnvelopeV1<SnapshotMetadataV1>,
    root: &RootMetadataV1,
    now: std::time::SystemTime,
) -> Result<()> {
    validate_root(root)?;
    if snapshot.signed.registry != root.registry {
        bail!("TUF snapshot registry differs from its trusted root");
    }
    let keys = root_keys(root)?;
    let policies = root_policies(root)?;
    verify_envelope(snapshot, policy(&policies, TufRole::Snapshot)?, &keys, now)?;
    verify_declared_identities(snapshot, root)
}

trait SignedMetadata {
    fn role(&self) -> TufRole;
    fn version(&self) -> u64;
    fn expires(&self) -> &str;
    fn registry(&self) -> &str;
    fn schema(&self) -> &str;
    fn expected_schema(&self) -> &'static str;
    fn spec_version(&self) -> &str;
}

macro_rules! impl_signed_metadata {
    ($type:ty, $role:expr, $schema:expr) => {
        impl SignedMetadata for $type {
            fn role(&self) -> TufRole {
                $role
            }
            fn version(&self) -> u64 {
                self.version
            }
            fn expires(&self) -> &str {
                &self.expires
            }
            fn registry(&self) -> &str {
                &self.registry
            }
            fn schema(&self) -> &str {
                &self.schema_version
            }
            fn expected_schema(&self) -> &'static str {
                $schema
            }
            fn spec_version(&self) -> &str {
                &self.spec_version
            }
        }
    };
}

impl_signed_metadata!(RootMetadataV1, TufRole::Root, TUF_ROOT_V1);
impl_signed_metadata!(TargetsMetadataV1, TufRole::Targets, TUF_TARGETS_V1);
impl SignedMetadata for DelegatedTargetsMetadataV1 {
    fn role(&self) -> TufRole {
        self.role
    }
    fn version(&self) -> u64 {
        self.version
    }
    fn expires(&self) -> &str {
        &self.expires
    }
    fn registry(&self) -> &str {
        &self.registry
    }
    fn schema(&self) -> &str {
        &self.schema_version
    }
    fn expected_schema(&self) -> &'static str {
        TUF_DELEGATED_TARGETS_V1
    }
    fn spec_version(&self) -> &str {
        &self.spec_version
    }
}
impl_signed_metadata!(SnapshotMetadataV1, TufRole::Snapshot, TUF_SNAPSHOT_V1);
impl_signed_metadata!(TimestampMetadataV1, TufRole::Timestamp, TUF_TIMESTAMP_V1);

/// Verifies an immutable role-separated metadata set and its release target.
///
/// # Errors
///
/// Returns an error for root bootstrap or rotation failure, collapsed role
/// keys, wrong thresholds, expiry, rollback, invalid delegation, signature
/// failure, snapshot mismatch, or release-manifest identity drift.
pub fn verify_immutable_set(
    set: &ImmutableTufSetV1,
    trust: &TufRootTrust<'_>,
    previous_root: Option<&TufEnvelopeV1<RootMetadataV1>>,
    now: std::time::SystemTime,
    expected: &TufReleaseExpectation<'_>,
) -> Result<()> {
    validate_root(&set.root.signed)?;
    if set.root.signed.registry != expected.registry {
        bail!("immutable TUF registry does not match the release plan");
    }
    if set.targets.signed.registry != set.root.signed.registry
        || set.delegated.signed.registry != set.root.signed.registry
        || set.snapshot.signed.registry != set.root.signed.registry
    {
        bail!("immutable TUF metadata crosses registry trust domains");
    }
    verify_root(&set.root, trust, previous_root, now)?;
    let keys = root_keys(&set.root.signed)?;
    let policies = root_policies(&set.root.signed)?;

    validate_targets(&set.targets.signed)?;
    verify_envelope(
        &set.targets,
        policy(&policies, TufRole::Targets)?,
        &keys,
        now,
    )?;
    verify_declared_identities(&set.targets, &set.root.signed)?;
    validate_delegated(
        &set.delegated.signed,
        expected.release_id,
        expected.release_class,
        expected.manifest_digest,
    )?;
    verify_envelope(
        &set.delegated,
        policy(&policies, TufRole::for_release(expected.release_class))?,
        &keys,
        now,
    )?;
    verify_declared_identities(&set.delegated, &set.root.signed)?;
    verify_envelope(
        &set.snapshot,
        policy(&policies, TufRole::Snapshot)?,
        &keys,
        now,
    )?;
    verify_declared_identities(&set.snapshot, &set.root.signed)?;
    validate_snapshot(set)?;
    Ok(())
}

/// Verifies a fresh timestamp over an exact already-authorized snapshot.
///
/// # Errors
///
/// Returns an error for wrong role policy, expiry, rollback, signature failure,
/// or a snapshot version, length, path, or digest mismatch.
pub fn verify_timestamp(
    timestamp: &TufEnvelopeV1<TimestampMetadataV1>,
    root: &RootMetadataV1,
    snapshot: &TufEnvelopeV1<SnapshotMetadataV1>,
    previous_version: Option<u64>,
    now: std::time::SystemTime,
) -> Result<()> {
    validate_root(root)?;
    if timestamp.signed.registry != root.registry || snapshot.signed.registry != root.registry {
        bail!("TUF timestamp chain crosses registry trust domains");
    }
    validate_timestamp_freshness(&timestamp.signed, now)?;
    let keys = root_keys(root)?;
    let policies = root_policies(root)?;
    verify_envelope(
        timestamp,
        policy(&policies, TufRole::Timestamp)?,
        &keys,
        now,
    )?;
    verify_declared_identities(timestamp, root)?;
    if previous_version.is_some_and(|version| timestamp.signed.version <= version) {
        bail!("TUF timestamp version did not increase");
    }
    let expected = metadata_description(
        format!("{}.snapshot.json", snapshot.signed.version),
        snapshot.signed.version,
        snapshot,
    )?;
    if timestamp.signed.snapshot != expected {
        bail!("TUF timestamp does not name the exact authorized snapshot");
    }
    Ok(())
}

/// Verifies a prior timestamp for monotonic refresh even after its expiry.
///
/// The prior envelope is checked at its own issuance instant, including its
/// signature threshold, ≤48-hour validity window, and exact snapshot binding.
/// This permits recovery from an expired freshness pointer without permitting
/// rollback or authorizing a different snapshot.
///
/// # Errors
///
/// Returns an error for malformed time, signature or role-policy failure, or
/// when the prior timestamp does not name `snapshot` exactly.
pub fn verify_prior_timestamp_for_refresh(
    timestamp: &TufEnvelopeV1<TimestampMetadataV1>,
    root: &RootMetadataV1,
    snapshot: &TufEnvelopeV1<SnapshotMetadataV1>,
) -> Result<()> {
    let issued = parse_utc(&timestamp.signed.issued_at, "TUF timestamp issuance")?;
    validate_root(root)?;
    if timestamp.signed.registry != root.registry || snapshot.signed.registry != root.registry {
        bail!("prior TUF timestamp chain crosses registry trust domains");
    }
    validate_timestamp_freshness(&timestamp.signed, issued)?;
    let keys = root_keys(root)?;
    let policies = root_policies(root)?;
    verify_envelope(
        timestamp,
        policy(&policies, TufRole::Timestamp)?,
        &keys,
        issued,
    )?;
    verify_declared_identities(timestamp, root)?;
    let expected = metadata_description(
        format!("{}.snapshot.json", snapshot.signed.version),
        snapshot.signed.version,
        snapshot,
    )?;
    if timestamp.signed.snapshot != expected {
        bail!("prior TUF timestamp does not name the exact snapshot");
    }
    Ok(())
}

fn validate_root(root: &RootMetadataV1) -> Result<()> {
    validate_common(root, TUF_ROOT_V1)?;
    if !root.consistent_snapshot {
        bail!("TUF root must require consistent snapshots");
    }
    let keys = root_keys(root)?;
    let policies = root_policies(root)?;
    if policies.len() != 7 {
        bail!("TUF root must define every independent role exactly once");
    }
    let mut assigned = BTreeSet::new();
    for role in [
        TufRole::Root,
        TufRole::Targets,
        TufRole::Stable,
        TufRole::Candidate,
        TufRole::Edge,
        TufRole::Snapshot,
        TufRole::Timestamp,
    ] {
        let role_policy = policy(&policies, role)?;
        if role_policy.threshold == 0
            || usize::from(role_policy.threshold) > role_policy.key_ids.len()
            || role_policy.key_ids.is_empty()
        {
            bail!("TUF role has an unattainable threshold");
        }
        let (minimum_keys, minimum_threshold) = match role {
            TufRole::Root | TufRole::Targets | TufRole::Stable => (3, 2),
            TufRole::Candidate => (2, 1),
            TufRole::Edge | TufRole::Snapshot | TufRole::Timestamp => (1, 1),
        };
        if role_policy.key_ids.len() < minimum_keys || role_policy.threshold < minimum_threshold {
            bail!("TUF role is weaker than the canonical production policy");
        }
        for key_id in &role_policy.key_ids {
            if !keys.contains_key(key_id.as_str()) {
                bail!("TUF role references an unknown key");
            }
            if !assigned.insert(key_id) {
                bail!("TUF signing key is collapsed across independent roles");
            }
        }
    }
    Ok(())
}

fn validate_targets(targets: &TargetsMetadataV1) -> Result<()> {
    validate_common(targets, TUF_TARGETS_V1)?;
    let expected = [
        (TufRole::Stable, "releases/stable/"),
        (TufRole::Candidate, "releases/candidate/"),
        (TufRole::Edge, "releases/edge/"),
    ];
    if targets.delegations.len() != expected.len()
        || targets
            .delegations
            .iter()
            .zip(expected)
            .any(|(found, (role, prefix))| {
                found.role != role || found.path_prefix != prefix || !found.terminating
            })
    {
        bail!("TUF targets delegations are not canonical and disjoint");
    }
    Ok(())
}

fn validate_delegated(
    delegated: &DelegatedTargetsMetadataV1,
    release_id: &str,
    release_class: ReleaseClass,
    manifest_digest: Sha256Digest,
) -> Result<()> {
    validate_common(delegated, TUF_DELEGATED_TARGETS_V1)?;
    let role = TufRole::for_release(release_class);
    if delegated.role != role || delegated.targets.is_empty() {
        bail!("delegated TUF role does not authorize this release class");
    }
    let prefix = format!("releases/{}/", role.as_str());
    if delegated
        .targets
        .windows(2)
        .any(|pair| pair[0].path >= pair[1].path)
    {
        bail!("delegated TUF targets must be unique and sorted");
    }
    let matches = delegated
        .targets
        .iter()
        .filter(|target| {
            target.release_id == release_id
                && target.release_class == release_class
                && target.manifest_digest == manifest_digest
        })
        .count();
    if matches != 1
        || delegated.targets.iter().any(|target| {
            !target.path.starts_with(&prefix)
                || target.path.contains("/../")
                || target.path.ends_with('/')
                || target.length == 0
        })
    {
        bail!("delegated TUF targets do not contain one exact authorized release");
    }
    Ok(())
}

fn validate_snapshot(set: &ImmutableTufSetV1) -> Result<()> {
    validate_common(&set.snapshot.signed, TUF_SNAPSHOT_V1)?;
    let expected = vec![
        metadata_description(
            format!("{}.root.json", set.root.signed.version),
            set.root.signed.version,
            &set.root,
        )?,
        metadata_description(
            format!("{}.targets.json", set.targets.signed.version),
            set.targets.signed.version,
            &set.targets,
        )?,
        metadata_description(
            format!(
                "{}.{}.json",
                set.delegated.signed.version,
                set.delegated.signed.role.as_str()
            ),
            set.delegated.signed.version,
            &set.delegated,
        )?,
    ];
    if set.snapshot.signed.metadata != expected {
        bail!("TUF snapshot does not bind the exact immutable metadata set");
    }
    Ok(())
}

fn validate_timestamp_freshness(
    timestamp: &TimestampMetadataV1,
    now: std::time::SystemTime,
) -> Result<()> {
    if !timestamp.issued_at.ends_with('Z') || !timestamp.expires.ends_with('Z') {
        bail!("TUF timestamp times must be RFC 3339 UTC");
    }
    let issued = humantime::parse_rfc3339(&timestamp.issued_at)
        .context("parsing TUF timestamp issuance time")?;
    let expiry =
        humantime::parse_rfc3339(&timestamp.expires).context("parsing TUF timestamp expiry")?;
    if issued > now
        || expiry <= issued
        || expiry.duration_since(issued)? > std::time::Duration::from_secs(48 * 60 * 60)
    {
        bail!("TUF timestamp exceeds its 48-hour freshness policy");
    }
    Ok(())
}

fn verify_root(
    root: &TufEnvelopeV1<RootMetadataV1>,
    trust: &TufRootTrust<'_>,
    previous: Option<&TufEnvelopeV1<RootMetadataV1>>,
    now: std::time::SystemTime,
) -> Result<()> {
    if trust.threshold == 0 || usize::from(trust.threshold) > trust.keys.len() {
        bail!("TUF root bootstrap threshold is unattainable");
    }
    verify_with_keys(root, trust.keys, trust.threshold, now)?;
    if let Some(previous) = previous {
        validate_root(&previous.signed)?;
        if root.signed.registry != previous.signed.registry {
            bail!("TUF root rotation cannot change registry identity");
        }
        if root.signed.version != previous.signed.version.saturating_add(1) {
            bail!("TUF root rotation must increase the version by exactly one");
        }
        let old_keys = root_keys(&previous.signed)?;
        let old_policies = root_policies(&previous.signed)?;
        verify_envelope(root, policy(&old_policies, TufRole::Root)?, &old_keys, now)?;
    }
    let new_keys = root_keys(&root.signed)?;
    let new_policies = root_policies(&root.signed)?;
    verify_envelope(root, policy(&new_policies, TufRole::Root)?, &new_keys, now)?;
    verify_declared_identities(root, &root.signed)
}

fn verify_envelope<T: SignedMetadata + Serialize>(
    envelope: &TufEnvelopeV1<T>,
    role_policy: &TufRolePolicyV1,
    keys: &BTreeMap<&str, TrustedEd25519Key>,
    now: std::time::SystemTime,
) -> Result<()> {
    validate_common(&envelope.signed, envelope.signed.expected_schema())?;
    if role_policy.role != envelope.signed.role() {
        bail!("TUF envelope was checked against the wrong role policy");
    }
    let selected = role_policy
        .key_ids
        .iter()
        .filter_map(|key_id| keys.get(key_id.as_str()).cloned())
        .collect::<Vec<_>>();
    verify_with_keys(envelope, &selected, role_policy.threshold, now)
}

fn verify_with_keys<T: SignedMetadata + Serialize>(
    envelope: &TufEnvelopeV1<T>,
    trusted_keys: &[TrustedEd25519Key],
    threshold: u16,
    now: std::time::SystemTime,
) -> Result<()> {
    validate_common(&envelope.signed, envelope.signed.expected_schema())?;
    require_not_expired(envelope.signed.expires(), now)?;
    let payload_digest = Sha256Digest::of_canonical(
        &format!("aos.release.tuf-{}/v1", envelope.signed.role().as_str()),
        &envelope.signed,
    )?;
    let trusted = trusted_keys
        .iter()
        .map(|key| (key.key_id.as_str(), key))
        .collect::<BTreeMap<_, _>>();
    if trusted.len() != trusted_keys.len() {
        bail!("TUF verifier trust input repeats a key id");
    }
    let mut accepted = BTreeSet::new();
    for signature in &envelope.signatures {
        let request = &signature.request;
        if request.role != envelope.signed.role().signer_role()
            || request.operation != SigningOperation::SignPayload
            || request.payload_digest != payload_digest
            || !matches!(
                &request.context,
                SigningContext::Tuf { metadata_role, metadata_version }
                    if metadata_role == envelope.signed.role().as_str()
                        && *metadata_version == envelope.signed.version()
            )
        {
            bail!("TUF signature request is outside its metadata role");
        }
        let Some(key) = trusted.get(request.key_id.as_str()) else {
            continue;
        };
        if !accepted.insert(request.key_id.as_str()) {
            bail!("TUF envelope repeats an authorized signing key");
        }
        verify_ed25519_response(request, &signature.response, key)?;
        if signature.response.verification_material_digest != Sha256Digest::of_bytes(key.public_key)
        {
            bail!("TUF signature returned the wrong public verification material");
        }
    }
    if accepted.len() < usize::from(threshold) {
        bail!("TUF role signature threshold is not satisfied");
    }
    Ok(())
}

fn verify_declared_identities<T>(envelope: &TufEnvelopeV1<T>, root: &RootMetadataV1) -> Result<()> {
    let identities = root
        .keys
        .iter()
        .map(|key| (key.key_id.as_str(), key.verification_identity.as_str()))
        .collect::<BTreeMap<_, _>>();
    for signature in &envelope.signatures {
        if let Some(expected) = identities.get(signature.request.key_id.as_str())
            && signature.response.verification_identity != *expected
        {
            bail!("TUF signature verification identity differs from root metadata");
        }
    }
    Ok(())
}

fn validate_common(metadata: &impl SignedMetadata, schema: &str) -> Result<()> {
    if metadata.schema() != schema
        || metadata.spec_version() != TUF_SPEC_VERSION
        || metadata.version() == 0
    {
        bail!("invalid TUF metadata identity");
    }
    registry_policy(metadata.registry())?;
    Ok(())
}

fn root_keys(root: &RootMetadataV1) -> Result<BTreeMap<&str, TrustedEd25519Key>> {
    if root
        .keys
        .windows(2)
        .any(|pair| pair[0].key_id >= pair[1].key_id)
    {
        bail!("TUF root keys must be unique and sorted");
    }
    root.keys
        .iter()
        .map(|key| {
            let bytes = base64::engine::general_purpose::STANDARD
                .decode(&key.public_key_base64)
                .context("decoding TUF Ed25519 key")?;
            let trusted = TrustedEd25519Key::from_encoded(key.key_id.clone(), &bytes)?;
            Ok((key.key_id.as_str(), trusted))
        })
        .collect()
}

fn root_policies(root: &RootMetadataV1) -> Result<BTreeMap<TufRole, &TufRolePolicyV1>> {
    if root
        .roles
        .windows(2)
        .any(|pair| pair[0].role >= pair[1].role)
    {
        bail!("TUF root role policies must be unique and sorted");
    }
    Ok(root.roles.iter().map(|value| (value.role, value)).collect())
}

fn policy<'a>(
    policies: &'a BTreeMap<TufRole, &'a TufRolePolicyV1>,
    role: TufRole,
) -> Result<&'a TufRolePolicyV1> {
    policies
        .get(&role)
        .copied()
        .with_context(|| format!("TUF root lacks the {} role", role.as_str()))
}

fn parse_utc(value: &str, label: &str) -> Result<std::time::SystemTime> {
    if !value.ends_with('Z') {
        bail!("{label} must be RFC 3339 UTC");
    }
    humantime::parse_rfc3339(value).with_context(|| format!("parsing {label}"))
}

fn require_valid_expiry(value: &str) -> Result<()> {
    let _ = parse_utc(value, "TUF expiry")?;
    Ok(())
}

fn require_not_expired(value: &str, now: std::time::SystemTime) -> Result<()> {
    if !value.ends_with('Z') {
        bail!("TUF expiry must be RFC 3339 UTC");
    }
    let expiry = humantime::parse_rfc3339(value).context("parsing TUF expiry")?;
    if expiry <= now {
        bail!("TUF metadata is expired");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::registry::MAIN_REGISTRY;

    fn key(id: &str, byte: u8) -> TufKeyV1 {
        TufKeyV1 {
            key_id: id.to_owned(),
            public_key_base64: base64::engine::general_purpose::STANDARD.encode([byte; 32]),
            verification_identity: format!("device-{id}"),
        }
    }

    fn production_root() -> RootMetadataV1 {
        let assignments = [
            (TufRole::Root, vec!["key-01", "key-02", "key-03"], 2),
            (TufRole::Targets, vec!["key-04", "key-05", "key-06"], 2),
            (TufRole::Stable, vec!["key-07", "key-08", "key-09"], 2),
            (TufRole::Candidate, vec!["key-10", "key-11"], 1),
            (TufRole::Edge, vec!["key-12"], 1),
            (TufRole::Snapshot, vec!["key-13"], 1),
            (TufRole::Timestamp, vec!["key-14"], 1),
        ];
        RootMetadataV1 {
            schema_version: TUF_ROOT_V1.to_owned(),
            spec_version: TUF_SPEC_VERSION.to_owned(),
            registry: MAIN_REGISTRY.to_owned(),
            version: 1,
            expires: "2030-01-01T00:00:00Z".to_owned(),
            consistent_snapshot: true,
            keys: (1..=14)
                .map(|number| key(&format!("key-{number:02}"), number))
                .collect(),
            roles: assignments
                .into_iter()
                .map(|(role, key_ids, threshold)| TufRolePolicyV1 {
                    role,
                    key_ids: key_ids.into_iter().map(str::to_owned).collect(),
                    threshold,
                })
                .collect(),
        }
    }

    #[test]
    fn production_root_requires_role_separation_and_strong_offline_thresholds() {
        let root = production_root();
        assert!(validate_root(&root).is_ok());

        let mut collapsed = root.clone();
        collapsed.roles[1].key_ids[0] = "key-01".to_owned();
        assert!(validate_root(&collapsed).is_err());

        let mut weak = root;
        weak.roles[0].threshold = 1;
        assert!(validate_root(&weak).is_err());
    }

    #[test]
    fn canonical_delegations_are_disjoint_and_terminating() {
        let mut targets = TargetsMetadataV1 {
            schema_version: TUF_TARGETS_V1.to_owned(),
            spec_version: TUF_SPEC_VERSION.to_owned(),
            registry: MAIN_REGISTRY.to_owned(),
            version: 1,
            expires: "2030-01-01T00:00:00Z".to_owned(),
            delegations: [
                (TufRole::Stable, "releases/stable/"),
                (TufRole::Candidate, "releases/candidate/"),
                (TufRole::Edge, "releases/edge/"),
            ]
            .into_iter()
            .map(|(role, path_prefix)| TufDelegationV1 {
                role,
                path_prefix: path_prefix.to_owned(),
                terminating: true,
            })
            .collect(),
        };
        assert!(validate_targets(&targets).is_ok());
        targets.delegations[2].path_prefix = "releases/stable/".to_owned();
        assert!(validate_targets(&targets).is_err());
    }

    #[test]
    fn authoring_constructors_bind_exact_predecessor_envelopes() -> Result<()> {
        let targets = TufEnvelopeV1 {
            signed: canonical_targets_metadata(
                MAIN_REGISTRY,
                4,
                "2030-01-01T00:00:00Z".to_owned(),
            )?,
            signatures: vec![],
        };
        let root = TufEnvelopeV1 {
            signed: production_root(),
            signatures: vec![],
        };
        let delegated = TufEnvelopeV1 {
            signed: delegated_release_metadata(
                MAIN_REGISTRY,
                8,
                "2030-01-01T00:00:00Z".to_owned(),
                TufReleaseTargetV1 {
                    path: "releases/stable/release-2030.1.0.json".to_owned(),
                    release_id: "release-2030.1.0".to_owned(),
                    release_class: ReleaseClass::Stable,
                    manifest_digest: Sha256Digest::of_bytes("manifest"),
                    length: 123,
                },
            )?,
            signatures: vec![],
        };
        let snapshot = TufEnvelopeV1 {
            signed: immutable_snapshot_metadata(
                MAIN_REGISTRY,
                9,
                "2030-01-01T00:00:00Z".to_owned(),
                &root,
                &targets,
                &delegated,
            )?,
            signatures: vec![],
        };
        assert_eq!(snapshot.signed.metadata[0].path, "1.root.json");
        assert_eq!(snapshot.signed.metadata[1].path, "4.targets.json");
        assert_eq!(snapshot.signed.metadata[2].path, "8.stable.json");

        let timestamp = timestamp_metadata(
            MAIN_REGISTRY,
            10,
            "2029-12-30T00:00:00Z".to_owned(),
            "2030-01-01T00:00:00Z".to_owned(),
            &snapshot,
        )?;
        assert_eq!(timestamp.snapshot.path, "9.snapshot.json");
        let set = ImmutableTufSetV1 {
            root,
            targets,
            delegated,
            snapshot,
        };
        for registry in ["andyl/testing", "andyl/testing-v2"] {
            let error = verify_immutable_set(
                &set,
                &TufRootTrust {
                    keys: &[],
                    threshold: 1,
                },
                None,
                humantime::parse_rfc3339("2029-12-30T00:00:00Z")?,
                &TufReleaseExpectation {
                    registry,
                    release_id: "release-2030.1.0",
                    release_class: ReleaseClass::Stable,
                    manifest_digest: Sha256Digest::of_bytes("manifest"),
                },
            )
            .unwrap_err();
            assert!(
                error
                    .to_string()
                    .contains("registry does not match the release plan")
            );
        }
        Ok(())
    }

    #[test]
    fn timestamp_window_cannot_exceed_forty_eight_hours() -> Result<()> {
        let now = humantime::parse_rfc3339("2026-09-03T01:00:00Z")?;
        let mut timestamp = TimestampMetadataV1 {
            schema_version: TUF_TIMESTAMP_V1.to_owned(),
            spec_version: TUF_SPEC_VERSION.to_owned(),
            registry: MAIN_REGISTRY.to_owned(),
            version: 1,
            issued_at: "2026-09-03T00:00:00Z".to_owned(),
            expires: "2026-09-05T00:00:00Z".to_owned(),
            snapshot: TufMetadataDescriptionV1 {
                path: "1.snapshot.json".to_owned(),
                version: 1,
                length: 1,
                sha256: Sha256Digest::of_bytes("snapshot"),
            },
        };
        assert!(validate_timestamp_freshness(&timestamp, now).is_ok());
        timestamp.expires = "2026-09-05T00:00:01Z".to_owned();
        assert!(validate_timestamp_freshness(&timestamp, now).is_err());
        Ok(())
    }
}
