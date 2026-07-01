//! AOS-TUF metadata for registry releases.
//!
//! The registry transport is still git-native: signed commits, signed
//! release tags, channel partitions, and fast-forward state remain the outer
//! integrity mechanism. This module adds an in-tree TUF-style metadata layer
//! over the selected registry catalog:
//!
//! ```text
//! tuf/root.json       role keys and thresholds
//! tuf/targets.json    hashes of every non-tuf registry catalog file
//! tuf/snapshot.json   hashes and versions of root/targets metadata
//! tuf/timestamp.json  short-lived hash/version pointer to snapshot
//! ```
//!
//! Metadata files are JSON envelopes. The `signed` object is serialized in a
//! deterministic field order and signed with detached OpenSSH signatures
//! using the same Ed25519 maintainer keys as registry commits and tags.

use std::collections::{BTreeMap, HashSet};
use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::security::{sign_payload_signature, verify_payload_signature};
use crate::types::RegistryState;

/// Directory holding committed registry TUF metadata.
pub const TUF_DIR: &str = "tuf";

const ROOT_JSON: &str = "tuf/root.json";
const TARGETS_JSON: &str = "tuf/targets.json";
const SNAPSHOT_JSON: &str = "tuf/snapshot.json";
const TIMESTAMP_JSON: &str = "tuf/timestamp.json";

const ROLE_ROOT: &str = "root";
const ROLE_TARGETS: &str = "targets";
const ROLE_SNAPSHOT: &str = "snapshot";
const ROLE_TIMESTAMP: &str = "timestamp";

const SCHEMA_ROOT: &str = "https://andyl.com/aos/registry/tuf/root/v1";
const SCHEMA_TARGETS: &str = "https://andyl.com/aos/registry/tuf/targets/v1";
const SCHEMA_SNAPSHOT: &str = "https://andyl.com/aos/registry/tuf/snapshot/v1";
const SCHEMA_TIMESTAMP: &str = "https://andyl.com/aos/registry/tuf/timestamp/v1";
const SPEC_VERSION: &str = "aos-tuf-1";
const SIGNATURE_NAMESPACE: &str = "aos-registry-tuf-v1";

const ROOT_EXPIRES_SECONDS: u64 = 365 * 24 * 60 * 60;
const TARGETS_EXPIRES_SECONDS: u64 = 90 * 24 * 60 * 60;
const SNAPSHOT_EXPIRES_SECONDS: u64 = 30 * 24 * 60 * 60;
const TIMESTAMP_EXPIRES_SECONDS: u64 = 14 * 24 * 60 * 60;

/// Successful TUF verification result for a selected registry commit.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedMetadata {
    /// Accepted root metadata version.
    pub root_version: u64,
    /// Accepted targets metadata version.
    pub targets_version: u64,
    /// Accepted snapshot metadata version.
    pub snapshot_version: u64,
    /// Accepted timestamp metadata version.
    pub timestamp_version: u64,
}

/// Local private key material available for signing TUF metadata.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MetadataSigningKey {
    /// Key id as named in `tuf/root.json` role specifications.
    pub key_id: String,
    /// Path to the OpenSSH private key used for detached signatures.
    pub key_path: PathBuf,
    /// Public trust line in `registry:Ed25519:<base64>` form.
    pub key: String,
    /// Whether this key belongs to the new root role policy.
    pub role_key: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct Envelope<T> {
    signed: T,
    #[serde(default)]
    signatures: Vec<TufSignature>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct TufSignature {
    key_id: String,
    sig: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct TufKey {
    key: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct TufRoleSpec {
    key_ids: Vec<String>,
    threshold: u32,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct RootSigned {
    schema: String,
    spec_version: String,
    registry: String,
    version: u64,
    expires: String,
    keys: BTreeMap<String, TufKey>,
    roles: BTreeMap<String, TufRoleSpec>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct TargetsSigned {
    schema: String,
    spec_version: String,
    registry: String,
    version: u64,
    expires: String,
    release: String,
    catalog_hash: String,
    targets: BTreeMap<String, TufFileMeta>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct SnapshotSigned {
    schema: String,
    spec_version: String,
    registry: String,
    version: u64,
    expires: String,
    meta: BTreeMap<String, TufVersionedMeta>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct TimestampSigned {
    schema: String,
    spec_version: String,
    registry: String,
    version: u64,
    expires: String,
    snapshot: TufVersionedMeta,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct TufFileMeta {
    length: u64,
    sha256: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct TufVersionedMeta {
    version: u64,
    length: u64,
    sha256: String,
}

/// Generate and write release TUF metadata in a registry authoring clone.
///
/// The catalog covers every file in the current `HEAD` tree except `tuf/`.
/// The caller commits the returned changes before creating the release tag,
/// so the signed tag covers both the catalog and the generated metadata.
///
/// # Errors
///
/// Returns an error if existing metadata is malformed, the signing key is
/// not authorized for every role it must sign, threshold verification fails,
/// catalog files cannot be read, or metadata files cannot be written.
pub fn write_release_metadata_worktree(
    repo_dir: &Path,
    registry: &str,
    release: &semver::Version,
    signing_keys: &[MetadataSigningKey],
) -> Result<bool> {
    if signing_keys.is_empty() {
        bail!("at least one TUF metadata signing key is required");
    }
    if !signing_keys.iter().any(|signer| signer.role_key) {
        bail!("at least one TUF metadata role key is required");
    }
    let tuf_dir = repo_dir.join(TUF_DIR);
    let existing_root = read_worktree_envelope::<RootSigned>(&tuf_dir.join("root.json"))?;
    let existing_targets = read_worktree_envelope::<TargetsSigned>(&tuf_dir.join("targets.json"))?;
    let existing_snapshot =
        read_worktree_envelope::<SnapshotSigned>(&tuf_dir.join("snapshot.json"))?;
    let existing_timestamp =
        read_worktree_envelope::<TimestampSigned>(&tuf_dir.join("timestamp.json"))?;

    let (keys, roles) = root_policy_for_signers(existing_root.as_ref(), signing_keys);
    validate_root_policy(&keys, &roles)?;

    let now = unix_now_secs();
    let root_signed = RootSigned {
        schema: SCHEMA_ROOT.to_string(),
        spec_version: SPEC_VERSION.to_string(),
        registry: registry.to_string(),
        version: next_version(existing_root.as_ref().map(|root| root.signed.version)),
        expires: format_iso8601_utc(now.saturating_add(ROOT_EXPIRES_SECONDS)),
        keys: keys.clone(),
        roles: roles.clone(),
    };
    let root = sign_root_envelope(
        root_signed,
        signing_keys,
        &keys,
        &roles,
        existing_root.as_ref(),
    )?;
    if let Some(previous_root) = &existing_root {
        verify_envelope(
            &root,
            ROLE_ROOT,
            &previous_root.signed.keys,
            &previous_root.signed.roles,
            None,
        )
        .context("verifying rotated root metadata against previous root role")?;
    }
    verify_envelope(
        &root,
        ROLE_ROOT,
        &root.signed.keys,
        &root.signed.roles,
        None,
    )?;

    let targets_map = collect_commit_catalog(repo_dir, "HEAD")?;
    let targets_signed = TargetsSigned {
        schema: SCHEMA_TARGETS.to_string(),
        spec_version: SPEC_VERSION.to_string(),
        registry: registry.to_string(),
        version: next_version(
            existing_targets
                .as_ref()
                .map(|targets| targets.signed.version),
        ),
        expires: format_iso8601_utc(now.saturating_add(TARGETS_EXPIRES_SECONDS)),
        release: release.to_string(),
        catalog_hash: catalog_hash(&targets_map)?,
        targets: targets_map,
    };
    let targets = sign_envelope(
        targets_signed,
        ROLE_TARGETS,
        signing_keys,
        &root.signed.keys,
        &root.signed.roles,
    )?;
    verify_envelope(
        &targets,
        ROLE_TARGETS,
        &root.signed.keys,
        &root.signed.roles,
        None,
    )?;

    let root_bytes = envelope_bytes(&root)?;
    let targets_bytes = envelope_bytes(&targets)?;
    let mut snapshot_meta = BTreeMap::new();
    snapshot_meta.insert(
        ROOT_JSON.to_string(),
        versioned_meta(root.signed.version, &root_bytes),
    );
    snapshot_meta.insert(
        TARGETS_JSON.to_string(),
        versioned_meta(targets.signed.version, &targets_bytes),
    );
    let snapshot_signed = SnapshotSigned {
        schema: SCHEMA_SNAPSHOT.to_string(),
        spec_version: SPEC_VERSION.to_string(),
        registry: registry.to_string(),
        version: next_version(
            existing_snapshot
                .as_ref()
                .map(|snapshot| snapshot.signed.version),
        ),
        expires: format_iso8601_utc(now.saturating_add(SNAPSHOT_EXPIRES_SECONDS)),
        meta: snapshot_meta,
    };
    let snapshot = sign_envelope(
        snapshot_signed,
        ROLE_SNAPSHOT,
        signing_keys,
        &root.signed.keys,
        &root.signed.roles,
    )?;
    verify_envelope(
        &snapshot,
        ROLE_SNAPSHOT,
        &root.signed.keys,
        &root.signed.roles,
        None,
    )?;

    let snapshot_bytes = envelope_bytes(&snapshot)?;
    let timestamp_signed = TimestampSigned {
        schema: SCHEMA_TIMESTAMP.to_string(),
        spec_version: SPEC_VERSION.to_string(),
        registry: registry.to_string(),
        version: next_version(
            existing_timestamp
                .as_ref()
                .map(|timestamp| timestamp.signed.version),
        ),
        expires: format_iso8601_utc(now.saturating_add(TIMESTAMP_EXPIRES_SECONDS)),
        snapshot: versioned_meta(snapshot.signed.version, &snapshot_bytes),
    };
    let timestamp = sign_envelope(
        timestamp_signed,
        ROLE_TIMESTAMP,
        signing_keys,
        &root.signed.keys,
        &root.signed.roles,
    )?;
    verify_envelope(
        &timestamp,
        ROLE_TIMESTAMP,
        &root.signed.keys,
        &root.signed.roles,
        None,
    )?;

    let timestamp_bytes = envelope_bytes(&timestamp)?;
    fs::create_dir_all(&tuf_dir).with_context(|| format!("creating {}", tuf_dir.display()))?;
    let mut changed = false;
    changed |= write_if_changed(&tuf_dir.join("root.json"), &root_bytes)?;
    changed |= write_if_changed(&tuf_dir.join("targets.json"), &targets_bytes)?;
    changed |= write_if_changed(&tuf_dir.join("snapshot.json"), &snapshot_bytes)?;
    changed |= write_if_changed(&tuf_dir.join("timestamp.json"), &timestamp_bytes)?;
    Ok(changed)
}

/// Verify committed TUF metadata for a selected registry commit.
///
/// Missing metadata is accepted only for immutable sync modes that do not
/// enforce expiry and only before a registry has ever accepted TUF metadata.
/// Once version floors exist in [`RegistryState`], stripping the `tuf/` tree is
/// treated as a rollback.
///
/// # Errors
///
/// Returns an error when metadata is partial, signatures fail their role
/// threshold, metadata is expired, versions go backwards, snapshot or
/// timestamp hashes do not match, or the targets catalog does not match
/// the selected commit's non-`tuf/` files.
pub fn verify_commit_metadata(
    repo_dir: &Path,
    registry: &str,
    commit: &str,
    previous_commit: Option<&str>,
    trusted_keys: &[String],
    state: &RegistryState,
    now_secs: u64,
    enforce_expiry: bool,
) -> Result<Option<VerifiedMetadata>> {
    let has_tuf_floors = state_has_tuf_floors(state);
    let Some(files) = load_commit_metadata(repo_dir, commit)? else {
        if has_tuf_floors {
            bail!("registry commit {commit} removes previously accepted TUF metadata");
        }
        if enforce_expiry {
            bail!("registry commit {commit} is missing required TUF metadata");
        }
        return Ok(None);
    };

    let root: Envelope<RootSigned> = parse_envelope(&files.root, ROOT_JSON)?;
    let targets: Envelope<TargetsSigned> = parse_envelope(&files.targets, TARGETS_JSON)?;
    let snapshot: Envelope<SnapshotSigned> = parse_envelope(&files.snapshot, SNAPSHOT_JSON)?;
    let timestamp: Envelope<TimestampSigned> = parse_envelope(&files.timestamp, TIMESTAMP_JSON)?;

    validate_root_policy(&root.signed.keys, &root.signed.roles)?;
    ensure_registry(&root.signed.registry, registry, ROOT_JSON)?;
    ensure_registry(&targets.signed.registry, registry, TARGETS_JSON)?;
    ensure_registry(&snapshot.signed.registry, registry, SNAPSHOT_JSON)?;
    ensure_registry(&timestamp.signed.registry, registry, TIMESTAMP_JSON)?;
    ensure_schema(&root.signed.schema, SCHEMA_ROOT, ROOT_JSON)?;
    ensure_schema(&targets.signed.schema, SCHEMA_TARGETS, TARGETS_JSON)?;
    ensure_schema(&snapshot.signed.schema, SCHEMA_SNAPSHOT, SNAPSHOT_JSON)?;
    ensure_schema(&timestamp.signed.schema, SCHEMA_TIMESTAMP, TIMESTAMP_JSON)?;
    for (path, spec) in [
        (ROOT_JSON, root.signed.spec_version.as_str()),
        (TARGETS_JSON, targets.signed.spec_version.as_str()),
        (SNAPSHOT_JSON, snapshot.signed.spec_version.as_str()),
        (TIMESTAMP_JSON, timestamp.signed.spec_version.as_str()),
    ] {
        if spec != SPEC_VERSION {
            bail!("{path} uses unsupported TUF spec version '{spec}'");
        }
    }

    if enforce_expiry {
        ensure_not_expired(ROOT_JSON, &root.signed.expires, now_secs)?;
        ensure_not_expired(TARGETS_JSON, &targets.signed.expires, now_secs)?;
        ensure_not_expired(SNAPSHOT_JSON, &snapshot.signed.expires, now_secs)?;
        ensure_not_expired(TIMESTAMP_JSON, &timestamp.signed.expires, now_secs)?;
    }

    let previous_files = previous_commit
        .map(|previous| load_commit_metadata(repo_dir, previous))
        .transpose()?
        .flatten();
    let previous_root = previous_files
        .as_ref()
        .map(|previous| parse_envelope::<RootSigned>(&previous.root, ROOT_JSON))
        .transpose()?;
    if let Some(previous_root) = &previous_root {
        verify_envelope(
            &root,
            ROLE_ROOT,
            &previous_root.signed.keys,
            &previous_root.signed.roles,
            None,
        )
        .context("verifying root metadata against previous root role")?;
        ensure_replaced_metadata_version_advances(
            ROOT_JSON,
            previous_root.signed.version,
            &signed_payload_bytes(&previous_root.signed)?,
            root.signed.version,
            &signed_payload_bytes(&root.signed)?,
        )?;
    } else if has_tuf_floors {
        bail!("previous accepted TUF metadata is unavailable for registry commit {commit}");
    } else {
        verify_envelope(
            &root,
            ROLE_ROOT,
            &root.signed.keys,
            &root.signed.roles,
            Some(trusted_keys),
        )
        .context("verifying bootstrap root metadata against trusted keys")?;
    }
    if let Some(previous_files) = &previous_files {
        let previous_targets: Envelope<TargetsSigned> =
            parse_envelope(&previous_files.targets, TARGETS_JSON)?;
        let previous_snapshot: Envelope<SnapshotSigned> =
            parse_envelope(&previous_files.snapshot, SNAPSHOT_JSON)?;
        let previous_timestamp: Envelope<TimestampSigned> =
            parse_envelope(&previous_files.timestamp, TIMESTAMP_JSON)?;
        ensure_replaced_metadata_version_advances(
            TARGETS_JSON,
            previous_targets.signed.version,
            &signed_payload_bytes(&previous_targets.signed)?,
            targets.signed.version,
            &signed_payload_bytes(&targets.signed)?,
        )?;
        ensure_replaced_metadata_version_advances(
            SNAPSHOT_JSON,
            previous_snapshot.signed.version,
            &signed_payload_bytes(&previous_snapshot.signed)?,
            snapshot.signed.version,
            &signed_payload_bytes(&snapshot.signed)?,
        )?;
        ensure_replaced_metadata_version_advances(
            TIMESTAMP_JSON,
            previous_timestamp.signed.version,
            &signed_payload_bytes(&previous_timestamp.signed)?,
            timestamp.signed.version,
            &signed_payload_bytes(&timestamp.signed)?,
        )?;
    }
    verify_envelope(
        &root,
        ROLE_ROOT,
        &root.signed.keys,
        &root.signed.roles,
        None,
    )?;
    verify_envelope(
        &targets,
        ROLE_TARGETS,
        &root.signed.keys,
        &root.signed.roles,
        None,
    )?;
    verify_envelope(
        &snapshot,
        ROLE_SNAPSHOT,
        &root.signed.keys,
        &root.signed.roles,
        None,
    )?;
    verify_envelope(
        &timestamp,
        ROLE_TIMESTAMP,
        &root.signed.keys,
        &root.signed.roles,
        None,
    )?;

    ensure_version_not_lower(ROOT_JSON, state.tuf_root_version, root.signed.version)?;
    ensure_version_not_lower(
        TARGETS_JSON,
        state.tuf_targets_version,
        targets.signed.version,
    )?;
    ensure_version_not_lower(
        SNAPSHOT_JSON,
        state.tuf_snapshot_version,
        snapshot.signed.version,
    )?;
    ensure_version_not_lower(
        TIMESTAMP_JSON,
        state.tuf_timestamp_version,
        timestamp.signed.version,
    )?;

    let root_meta = snapshot
        .signed
        .meta
        .get(ROOT_JSON)
        .ok_or_else(|| anyhow::anyhow!("{SNAPSHOT_JSON} does not reference {ROOT_JSON}"))?;
    verify_versioned_meta(ROOT_JSON, root.signed.version, &files.root, root_meta)?;
    let targets_meta = snapshot
        .signed
        .meta
        .get(TARGETS_JSON)
        .ok_or_else(|| anyhow::anyhow!("{SNAPSHOT_JSON} does not reference {TARGETS_JSON}"))?;
    verify_versioned_meta(
        TARGETS_JSON,
        targets.signed.version,
        &files.targets,
        targets_meta,
    )?;
    verify_versioned_meta(
        SNAPSHOT_JSON,
        snapshot.signed.version,
        &files.snapshot,
        &timestamp.signed.snapshot,
    )?;

    let actual_catalog = collect_commit_catalog(repo_dir, commit)?;
    if actual_catalog != targets.signed.targets {
        bail!("{TARGETS_JSON} catalog does not match selected commit {commit}");
    }
    let actual_catalog_hash = catalog_hash(&actual_catalog)?;
    if actual_catalog_hash != targets.signed.catalog_hash {
        bail!(
            "{TARGETS_JSON} catalog hash mismatch: expected '{}', got '{}'",
            targets.signed.catalog_hash,
            actual_catalog_hash,
        );
    }

    Ok(Some(VerifiedMetadata {
        root_version: root.signed.version,
        targets_version: targets.signed.version,
        snapshot_version: snapshot.signed.version,
        timestamp_version: timestamp.signed.version,
    }))
}

/// Return root-role key ids from the worktree's current TUF root metadata.
///
/// This lets producers include old root-role private keys as transition-only
/// signatures when a new root removes them from the role policy.
///
/// # Errors
///
/// Returns an error when `tuf/root.json` exists but cannot be read or parsed.
pub fn worktree_root_role_key_ids(repo_dir: &Path) -> Result<Vec<String>> {
    let Some(root) = read_worktree_envelope::<RootSigned>(&repo_dir.join(ROOT_JSON))? else {
        return Ok(Vec::new());
    };
    Ok(root
        .signed
        .roles
        .get(ROLE_ROOT)
        .map_or_else(Vec::new, |role| role.key_ids.clone()))
}

/// Return the `(key_id, public_key)` pairs that make up the worktree root's
/// root-role policy.
///
/// A producer rotating the root signing key uses this to match the operator's
/// `--rotate-from` private key (by its derived public key) back to the root
/// role key id it must co-sign under, so [`sign_root_envelope`]'s
/// previous-root authorization check accepts the transition signature.
///
/// # Errors
///
/// Returns an error when `tuf/root.json` exists but cannot be read or parsed.
pub fn worktree_root_role_keys(repo_dir: &Path) -> Result<Vec<(String, String)>> {
    let Some(root) = read_worktree_envelope::<RootSigned>(&repo_dir.join(ROOT_JSON))? else {
        return Ok(Vec::new());
    };
    let Some(role) = root.signed.roles.get(ROLE_ROOT) else {
        return Ok(Vec::new());
    };
    Ok(role
        .key_ids
        .iter()
        .filter_map(|key_id| {
            root.signed
                .keys
                .get(key_id)
                .map(|key| (key_id.clone(), key.key.clone()))
        })
        .collect())
}

fn next_version(previous: Option<u64>) -> u64 {
    previous.unwrap_or(0).saturating_add(1)
}

fn root_policy_for_signers(
    existing_root: Option<&Envelope<RootSigned>>,
    signing_keys: &[MetadataSigningKey],
) -> (BTreeMap<String, TufKey>, BTreeMap<String, TufRoleSpec>) {
    let policy_keys = signing_keys
        .iter()
        .filter(|signer| signer.role_key)
        .collect::<Vec<_>>();
    let mut keys = BTreeMap::new();
    for signer in &policy_keys {
        keys.insert(
            signer.key_id.clone(),
            TufKey {
                key: signer.key.clone(),
            },
        );
    }
    let key_ids = policy_keys
        .iter()
        .map(|signer| signer.key_id.clone())
        .collect::<Vec<_>>();
    let default_threshold = std::cmp::min(2, key_ids.len()) as u32;
    let mut roles = BTreeMap::new();
    for role in [ROLE_ROOT, ROLE_TARGETS, ROLE_SNAPSHOT, ROLE_TIMESTAMP] {
        let previous_threshold = existing_root
            .and_then(|root| root.signed.roles.get(role))
            .map_or(default_threshold, |spec| spec.threshold);
        let threshold = previous_threshold
            .max(default_threshold)
            .min(key_ids.len() as u32);
        roles.insert(
            role.to_string(),
            TufRoleSpec {
                key_ids: key_ids.clone(),
                threshold,
            },
        );
    }
    (keys, roles)
}

fn state_has_tuf_floors(state: &RegistryState) -> bool {
    state.tuf_root_version.is_some()
        || state.tuf_targets_version.is_some()
        || state.tuf_snapshot_version.is_some()
        || state.tuf_timestamp_version.is_some()
}

fn sign_root_envelope<T: Serialize>(
    signed: T,
    signing_keys: &[MetadataSigningKey],
    keys: &BTreeMap<String, TufKey>,
    roles: &BTreeMap<String, TufRoleSpec>,
    previous_root: Option<&Envelope<RootSigned>>,
) -> Result<Envelope<T>> {
    let role_spec = roles
        .get(ROLE_ROOT)
        .ok_or_else(|| anyhow::anyhow!("TUF root metadata has no '{ROLE_ROOT}' role"))?;
    let previous_role = previous_root.and_then(|root| root.signed.roles.get(ROLE_ROOT));
    let payload = signed_payload_bytes(&signed)?;
    let mut signatures = Vec::new();
    let mut signed_key_ids = HashSet::new();
    for signer in signing_keys {
        let authorized_by_new = role_spec.key_ids.contains(&signer.key_id)
            && keys
                .get(&signer.key_id)
                .is_some_and(|key| key.key == signer.key);
        let authorized_by_previous =
            previous_root
                .zip(previous_role)
                .is_some_and(|(root, role)| {
                    role.key_ids.contains(&signer.key_id)
                        && root
                            .signed
                            .keys
                            .get(&signer.key_id)
                            .is_some_and(|key| key.key == signer.key)
                });
        if !(authorized_by_new || authorized_by_previous)
            || !signed_key_ids.insert(signer.key_id.clone())
        {
            continue;
        }
        let sig = sign_payload_signature(&signer.key_path, SIGNATURE_NAMESPACE, &payload)
            .with_context(|| format!("signing root TUF metadata with '{}'", signer.key_id))?;
        signatures.push(TufSignature {
            key_id: signer.key_id.clone(),
            sig,
        });
    }
    Ok(Envelope { signed, signatures })
}

fn sign_envelope<T: Serialize>(
    signed: T,
    role: &str,
    signing_keys: &[MetadataSigningKey],
    keys: &BTreeMap<String, TufKey>,
    roles: &BTreeMap<String, TufRoleSpec>,
) -> Result<Envelope<T>> {
    let role_spec = roles
        .get(role)
        .ok_or_else(|| anyhow::anyhow!("TUF root metadata has no '{role}' role"))?;
    let payload = signed_payload_bytes(&signed)?;
    let mut signatures = Vec::new();
    for signer in signing_keys {
        if !role_spec.key_ids.contains(&signer.key_id) {
            continue;
        }
        let Some(expected_key) = keys.get(&signer.key_id) else {
            continue;
        };
        if expected_key.key != signer.key {
            bail!(
                "configured TUF signing key '{}' does not match root metadata",
                signer.key_id,
            );
        }
        let sig = sign_payload_signature(&signer.key_path, SIGNATURE_NAMESPACE, &payload)
            .with_context(|| format!("signing {role} TUF metadata with '{}'", signer.key_id))?;
        signatures.push(TufSignature {
            key_id: signer.key_id.clone(),
            sig,
        });
    }
    Ok(Envelope { signed, signatures })
}

fn verify_envelope<T: Serialize>(
    envelope: &Envelope<T>,
    role: &str,
    keys: &BTreeMap<String, TufKey>,
    roles: &BTreeMap<String, TufRoleSpec>,
    trusted_filter: Option<&[String]>,
) -> Result<()> {
    let role_spec = roles
        .get(role)
        .ok_or_else(|| anyhow::anyhow!("TUF root metadata has no '{role}' role"))?;
    validate_role(role, role_spec, keys)?;
    let payload = signed_payload_bytes(&envelope.signed)?;
    let mut accepted = HashSet::new();
    for signature in &envelope.signatures {
        if !role_spec.key_ids.contains(&signature.key_id) || accepted.contains(&signature.key_id) {
            continue;
        }
        let Some(key) = keys.get(&signature.key_id) else {
            continue;
        };
        if let Some(trusted_keys) = trusted_filter
            && !trusted_keys.iter().any(|trusted| trusted == &key.key)
        {
            continue;
        }
        if verify_payload_signature(&payload, &signature.sig, &key.key, SIGNATURE_NAMESPACE)
            .with_context(|| format!("verifying {role} signature from '{}'", signature.key_id))?
        {
            accepted.insert(signature.key_id.clone());
        }
    }
    if accepted.len() < role_spec.threshold as usize {
        bail!(
            "TUF {role} role has {}/{} required valid signature(s)",
            accepted.len(),
            role_spec.threshold,
        );
    }
    Ok(())
}

fn validate_root_policy(
    keys: &BTreeMap<String, TufKey>,
    roles: &BTreeMap<String, TufRoleSpec>,
) -> Result<()> {
    if keys.is_empty() {
        bail!("TUF root metadata has no keys");
    }
    for (key_id, key) in keys {
        crate::security::parse_signing_key(&key.key)
            .with_context(|| format!("invalid TUF key '{key_id}'"))?;
    }
    let mut seen_key_material = HashSet::new();
    for (key_id, key) in keys {
        if !seen_key_material.insert(key.key.as_str()) {
            bail!("TUF root metadata contains duplicate public key material at '{key_id}'");
        }
    }
    for role in [ROLE_ROOT, ROLE_TARGETS, ROLE_SNAPSHOT, ROLE_TIMESTAMP] {
        let spec = roles
            .get(role)
            .ok_or_else(|| anyhow::anyhow!("TUF root metadata has no '{role}' role"))?;
        validate_role(role, spec, keys)?;
    }
    Ok(())
}

fn validate_role(role: &str, spec: &TufRoleSpec, keys: &BTreeMap<String, TufKey>) -> Result<()> {
    if spec.threshold == 0 {
        bail!("TUF {role} role threshold must be at least 1");
    }
    let unique: HashSet<_> = spec.key_ids.iter().collect();
    if unique.len() != spec.key_ids.len() {
        bail!("TUF {role} role contains duplicate key ids");
    }
    if spec.threshold as usize > spec.key_ids.len() {
        bail!(
            "TUF {role} role threshold {} exceeds {} configured key(s)",
            spec.threshold,
            spec.key_ids.len(),
        );
    }
    for key_id in &spec.key_ids {
        if !keys.contains_key(key_id) {
            bail!("TUF {role} role references missing key '{key_id}'");
        }
    }
    Ok(())
}

fn collect_commit_catalog(repo_dir: &Path, commit: &str) -> Result<BTreeMap<String, TufFileMeta>> {
    let paths = crate::registry::repo::list_tree_paths_blocking(repo_dir, commit)
        .with_context(|| format!("listing tree for {commit}"))?;

    let mut catalog = BTreeMap::new();
    for path in paths {
        if path.starts_with("tuf/") {
            continue;
        }
        let bytes = read_commit_blob(repo_dir, commit, &path)?;
        catalog.insert(path, file_meta(&bytes));
    }
    Ok(catalog)
}

fn catalog_hash(catalog: &BTreeMap<String, TufFileMeta>) -> Result<String> {
    let bytes = serde_json::to_vec(catalog).context("serializing TUF catalog for hashing")?;
    Ok(sha256_digest(&bytes))
}

fn file_meta(bytes: &[u8]) -> TufFileMeta {
    TufFileMeta {
        length: bytes.len() as u64,
        sha256: sha256_digest(bytes),
    }
}

fn versioned_meta(version: u64, bytes: &[u8]) -> TufVersionedMeta {
    TufVersionedMeta {
        version,
        length: bytes.len() as u64,
        sha256: sha256_digest(bytes),
    }
}

fn verify_versioned_meta(
    path: &str,
    version: u64,
    bytes: &[u8],
    meta: &TufVersionedMeta,
) -> Result<()> {
    if meta.version != version {
        bail!(
            "{path} version mismatch in TUF metadata: expected {}, got {}",
            meta.version,
            version,
        );
    }
    verify_file_meta(path, bytes, meta.length, &meta.sha256)
}

fn verify_file_meta(path: &str, bytes: &[u8], length: u64, sha256: &str) -> Result<()> {
    if bytes.len() as u64 != length {
        bail!(
            "{path} length mismatch in TUF metadata: expected {}, got {}",
            length,
            bytes.len(),
        );
    }
    let actual = sha256_digest(bytes);
    if actual != sha256 {
        bail!("{path} hash mismatch in TUF metadata: expected '{sha256}', got '{actual}'");
    }
    Ok(())
}

fn sha256_digest(bytes: &[u8]) -> String {
    format!("sha256:{}", hex::encode(Sha256::digest(bytes)))
}

struct CommitMetadataFiles {
    root: Vec<u8>,
    targets: Vec<u8>,
    snapshot: Vec<u8>,
    timestamp: Vec<u8>,
}

fn load_commit_metadata(repo_dir: &Path, commit: &str) -> Result<Option<CommitMetadataFiles>> {
    let paths = [ROOT_JSON, TARGETS_JSON, SNAPSHOT_JSON, TIMESTAMP_JSON];
    let mut present = Vec::new();
    for path in paths {
        present.push(commit_path_exists(repo_dir, commit, path)?);
    }
    if present.iter().all(|value| !*value) {
        return Ok(None);
    }
    if present.iter().any(|value| !*value) {
        bail!("registry commit {commit} has partial TUF metadata under {TUF_DIR}/");
    }
    Ok(Some(CommitMetadataFiles {
        root: read_commit_blob(repo_dir, commit, ROOT_JSON)?,
        targets: read_commit_blob(repo_dir, commit, TARGETS_JSON)?,
        snapshot: read_commit_blob(repo_dir, commit, SNAPSHOT_JSON)?,
        timestamp: read_commit_blob(repo_dir, commit, TIMESTAMP_JSON)?,
    }))
}

fn commit_path_exists(repo_dir: &Path, commit: &str, path: &str) -> Result<bool> {
    crate::registry::repo::tree_path_exists_blocking(repo_dir, commit, path)
        .with_context(|| format!("checking {commit}:{path}"))
}

fn read_worktree_envelope<T: DeserializeOwned>(path: &Path) -> Result<Option<Envelope<T>>> {
    if !path.exists() {
        return Ok(None);
    }
    let bytes = fs::read(path).with_context(|| format!("reading {}", path.display()))?;
    parse_envelope(&bytes, &path.display().to_string()).map(Some)
}

fn parse_envelope<T: DeserializeOwned>(bytes: &[u8], path: &str) -> Result<Envelope<T>> {
    serde_json::from_slice(bytes).with_context(|| format!("parsing {path}"))
}

fn signed_payload_bytes<T: Serialize>(signed: &T) -> Result<Vec<u8>> {
    serde_json::to_vec(signed).context("serializing TUF signed payload")
}

fn envelope_bytes<T: Serialize>(envelope: &Envelope<T>) -> Result<Vec<u8>> {
    let mut bytes = serde_json::to_vec_pretty(envelope).context("serializing TUF envelope")?;
    bytes.push(b'\n');
    Ok(bytes)
}

fn write_if_changed(path: &Path, bytes: &[u8]) -> Result<bool> {
    if path.exists() {
        let existing = fs::read(path).with_context(|| format!("reading {}", path.display()))?;
        if existing == bytes {
            return Ok(false);
        }
    }
    fs::write(path, bytes).with_context(|| format!("writing {}", path.display()))?;
    Ok(true)
}

/// Read the blob at `commit:path` from the registry repository via libgit2.
///
/// # Errors
///
/// Returns an error if the commit cannot be resolved or the path is absent or
/// not a blob.
fn read_commit_blob(repo_dir: &Path, commit: &str, path: &str) -> Result<Vec<u8>> {
    crate::registry::repo::read_blob_at_blocking(repo_dir, commit, path)
        .with_context(|| format!("reading {commit}:{path}"))?
        .ok_or_else(|| anyhow::anyhow!("{commit}:{path} is missing"))
}

fn ensure_schema(actual: &str, expected: &str, path: &str) -> Result<()> {
    if actual != expected {
        bail!("{path} schema mismatch: expected '{expected}', got '{actual}'");
    }
    Ok(())
}

fn ensure_registry(actual: &str, expected: &str, path: &str) -> Result<()> {
    if actual != expected {
        bail!("{path} registry mismatch: expected '{expected}', got '{actual}'");
    }
    Ok(())
}

fn ensure_not_expired(path: &str, expires: &str, now_secs: u64) -> Result<()> {
    let expiry = parse_iso8601_utc_secs(expires)
        .with_context(|| format!("parsing TUF expiry for {path}"))?;
    if expiry <= now_secs {
        bail!("{path} expired at {expires}");
    }
    Ok(())
}

fn ensure_version_not_lower(path: &str, floor: Option<u64>, version: u64) -> Result<()> {
    if let Some(floor) = floor
        && version < floor
    {
        bail!("{path} version rollback: {version} is below accepted floor {floor}");
    }
    Ok(())
}

fn ensure_replaced_metadata_version_advances(
    path: &str,
    old_version: u64,
    old_payload: &[u8],
    new_version: u64,
    new_payload: &[u8],
) -> Result<()> {
    if old_payload != new_payload && new_version <= old_version {
        bail!("{path} changed without a version increase: old {old_version}, new {new_version}",);
    }
    Ok(())
}

fn unix_now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

fn format_iso8601_utc(secs: u64) -> String {
    let days = secs / 86400;
    let time_of_day = secs % 86400;
    let hours = time_of_day / 3600;
    let minutes = (time_of_day % 3600) / 60;
    let seconds = time_of_day % 60;
    let (year, month, day) = days_to_ymd(days);
    format!("{year:04}-{month:02}-{day:02}T{hours:02}:{minutes:02}:{seconds:02}Z")
}

fn parse_iso8601_utc_secs(input: &str) -> Result<u64> {
    if input.len() != 20
        || !input.ends_with('Z')
        || &input[4..5] != "-"
        || &input[7..8] != "-"
        || &input[10..11] != "T"
        || &input[13..14] != ":"
        || &input[16..17] != ":"
    {
        bail!("timestamp must be YYYY-MM-DDTHH:MM:SSZ");
    }
    let year = parse_decimal(&input[0..4], "year")?;
    let month = parse_decimal(&input[5..7], "month")?;
    let day = parse_decimal(&input[8..10], "day")?;
    let hour = parse_decimal(&input[11..13], "hour")?;
    let minute = parse_decimal(&input[14..16], "minute")?;
    let second = parse_decimal(&input[17..19], "second")?;
    if hour > 23 || minute > 59 || second > 59 {
        bail!("timestamp time is out of range");
    }
    Ok(ymd_to_days(year, month, day)? * 86_400 + hour * 3_600 + minute * 60 + second)
}

fn parse_decimal(input: &str, field: &str) -> Result<u64> {
    if input.is_empty() || !input.bytes().all(|byte| byte.is_ascii_digit()) {
        bail!("timestamp {field} is not numeric");
    }
    input
        .parse()
        .with_context(|| format!("parsing timestamp {field}"))
}

fn days_to_ymd(days: u64) -> (u64, u64, u64) {
    let z = days + 719468;
    let era = z / 146097;
    let doe = z - era * 146097;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if m <= 2 { y + 1 } else { y };
    (y, m, d)
}

fn ymd_to_days(year: u64, month: u64, day: u64) -> Result<u64> {
    if !(1..=12).contains(&month) {
        bail!("timestamp month is out of range");
    }
    let max_day = days_in_month(year, month);
    if day == 0 || day > max_day {
        bail!("timestamp day is out of range");
    }
    let year = year as i64;
    let month = month as i64;
    let day = day as i64;
    let adjusted_year = year - i64::from(month <= 2);
    let era = if adjusted_year >= 0 {
        adjusted_year
    } else {
        adjusted_year - 399
    } / 400;
    let yoe = adjusted_year - era * 400;
    let month_prime = month + if month > 2 { -3 } else { 9 };
    let doy = (153 * month_prime + 2) / 5 + day - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    let days = era * 146_097 + doe - 719_468;
    if days < 0 {
        bail!("timestamp predates Unix epoch");
    }
    Ok(days as u64)
}

fn days_in_month(year: u64, month: u64) -> u64 {
    match month {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        2 if is_leap_year(year) => 29,
        2 => 28,
        _ => 0,
    }
}

fn is_leap_year(year: u64) -> bool {
    year % 4 == 0 && (year % 100 != 0 || year % 400 == 0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sshkey::Ed25519Keypair;
    use crate::testutil;
    use std::path::PathBuf;
    use tempfile::TempDir;

    struct TestKey {
        id: String,
        trust: String,
        private: PathBuf,
    }

    #[test]
    fn threshold_verification_requires_enough_distinct_signatures() {
        let tmp = TempDir::new().unwrap();
        let a = write_test_key(tmp.path(), "core", "a", [1; 32]);
        let b = write_test_key(tmp.path(), "core", "b", [2; 32]);
        let (keys, roles) = two_key_policy(&a, &b, 2);
        let signed = RootSigned {
            schema: SCHEMA_ROOT.to_string(),
            spec_version: SPEC_VERSION.to_string(),
            registry: "core".to_string(),
            version: 1,
            expires: "2030-01-01T00:00:00Z".to_string(),
            keys,
            roles,
        };
        let payload = signed_payload_bytes(&signed).unwrap();
        let sig_a = sign_payload_signature(&a.private, SIGNATURE_NAMESPACE, &payload).unwrap();
        let mut envelope = Envelope {
            signed,
            signatures: vec![TufSignature {
                key_id: a.id.clone(),
                sig: sig_a,
            }],
        };

        let err = verify_envelope(
            &envelope,
            ROLE_ROOT,
            &envelope.signed.keys,
            &envelope.signed.roles,
            None,
        )
        .unwrap_err();
        assert!(format!("{err:#}").contains("1/2 required"));

        let sig_b = sign_payload_signature(&b.private, SIGNATURE_NAMESPACE, &payload).unwrap();
        envelope.signatures.push(TufSignature {
            key_id: b.id.clone(),
            sig: sig_b,
        });
        verify_envelope(
            &envelope,
            ROLE_ROOT,
            &envelope.signed.keys,
            &envelope.signed.roles,
            None,
        )
        .unwrap();
    }

    #[test]
    fn commit_metadata_verification_rejects_catalog_mix_and_match() {
        let tmp = TempDir::new().unwrap();
        let repo = init_repo(tmp.path());
        let key = write_test_key(tmp.path(), "core", "a", [3; 32]);
        fs::write(repo.join("registry.toml"), "[registry]\nname = \"core\"\n").unwrap();
        fs::create_dir_all(repo.join("packages/w")).unwrap();
        fs::write(repo.join("packages/w/web.toml"), "name = \"web\"\n").unwrap();
        testutil::git(&repo, &["add", "."]);
        testutil::git(&repo, &["commit", "-m", "package"]);
        write_release_metadata_worktree(
            &repo,
            "core",
            &semver::Version::new(1, 0, 0),
            &[metadata_signer(&key)],
        )
        .unwrap();
        testutil::git(&repo, &["add", "."]);
        testutil::git(&repo, &["commit", "-m", "release"]);
        let commit = testutil::git(&repo, &["rev-parse", "HEAD"]);
        let state = RegistryState::default();
        verify_commit_metadata(
            &repo,
            "core",
            &commit,
            None,
            std::slice::from_ref(&key.trust),
            &state,
            parse_iso8601_utc_secs("2026-01-01T00:00:00Z").unwrap(),
            true,
        )
        .unwrap();
        verify_commit_metadata(
            &repo,
            "core",
            &commit,
            None,
            std::slice::from_ref(&key.trust),
            &state,
            parse_iso8601_utc_secs("2100-01-01T00:00:00Z").unwrap(),
            false,
        )
        .unwrap();
        let expired = verify_commit_metadata(
            &repo,
            "core",
            &commit,
            None,
            std::slice::from_ref(&key.trust),
            &state,
            parse_iso8601_utc_secs("2100-01-01T00:00:00Z").unwrap(),
            true,
        )
        .unwrap_err();
        assert!(format!("{expired:#}").contains("expired"));

        fs::write(repo.join("packages/w/web.toml"), "name = \"tampered\"\n").unwrap();
        testutil::git(&repo, &["add", "packages/w/web.toml"]);
        testutil::git(&repo, &["commit", "-m", "tamper"]);
        let tampered = testutil::git(&repo, &["rev-parse", "HEAD"]);
        let err = verify_commit_metadata(
            &repo,
            "core",
            &tampered,
            Some(&commit),
            std::slice::from_ref(&key.trust),
            &state,
            parse_iso8601_utc_secs("2026-01-01T00:00:00Z").unwrap(),
            true,
        )
        .unwrap_err();
        assert!(format!("{err:#}").contains("catalog does not match"));
    }

    #[test]
    fn moving_ref_requires_tuf_metadata_on_first_sync() {
        let tmp = TempDir::new().unwrap();
        let repo = init_repo(tmp.path());
        let key = write_test_key(tmp.path(), "core", "a", [10; 32]);
        fs::write(repo.join("registry.toml"), "[registry]\nname = \"core\"\n").unwrap();
        testutil::git(&repo, &["add", "."]);
        testutil::git(&repo, &["commit", "-m", "legacy release"]);
        let commit = testutil::git(&repo, &["rev-parse", "HEAD"]);
        let state = RegistryState::default();

        let err = verify_commit_metadata(
            &repo,
            "core",
            &commit,
            None,
            std::slice::from_ref(&key.trust),
            &state,
            parse_iso8601_utc_secs("2026-01-01T00:00:00Z").unwrap(),
            true,
        )
        .unwrap_err();
        assert!(format!("{err:#}").contains("missing required TUF metadata"));

        assert!(
            verify_commit_metadata(
                &repo,
                "core",
                &commit,
                None,
                std::slice::from_ref(&key.trust),
                &state,
                parse_iso8601_utc_secs("2026-01-01T00:00:00Z").unwrap(),
                false,
            )
            .unwrap()
            .is_none()
        );
    }

    #[test]
    fn accepted_tuf_state_requires_previous_metadata() {
        let tmp = TempDir::new().unwrap();
        let repo = init_repo(tmp.path());
        let key = write_test_key(tmp.path(), "core", "a", [11; 32]);
        fs::write(repo.join("registry.toml"), "[registry]\nname = \"core\"\n").unwrap();
        testutil::git(&repo, &["add", "."]);
        testutil::git(&repo, &["commit", "-m", "catalog"]);
        write_release_metadata_worktree(
            &repo,
            "core",
            &semver::Version::new(1, 0, 0),
            &[metadata_signer(&key)],
        )
        .unwrap();
        testutil::git(&repo, &["add", "."]);
        testutil::git(&repo, &["commit", "-m", "release"]);
        let commit = testutil::git(&repo, &["rev-parse", "HEAD"]);
        let state = RegistryState {
            tuf_root_version: Some(1),
            tuf_targets_version: Some(1),
            tuf_snapshot_version: Some(1),
            tuf_timestamp_version: Some(1),
            ..RegistryState::default()
        };

        let err = verify_commit_metadata(
            &repo,
            "core",
            &commit,
            None,
            std::slice::from_ref(&key.trust),
            &state,
            parse_iso8601_utc_secs("2026-01-01T00:00:00Z").unwrap(),
            true,
        )
        .unwrap_err();
        assert!(format!("{err:#}").contains("previous accepted TUF metadata is unavailable"));
    }

    #[test]
    fn producer_writes_threshold_signatures_for_available_keys() {
        let tmp = TempDir::new().unwrap();
        let repo = init_repo(tmp.path());
        let a = write_test_key(tmp.path(), "core", "a", [8; 32]);
        let b = write_test_key(tmp.path(), "core", "b", [9; 32]);
        fs::write(repo.join("registry.toml"), "[registry]\nname = \"core\"\n").unwrap();
        testutil::git(&repo, &["add", "."]);
        testutil::git(&repo, &["commit", "-m", "catalog"]);

        write_release_metadata_worktree(
            &repo,
            "core",
            &semver::Version::new(1, 0, 0),
            &[metadata_signer(&a), metadata_signer(&b)],
        )
        .unwrap();

        let root_bytes = fs::read(repo.join(ROOT_JSON)).unwrap();
        let root: Envelope<RootSigned> = parse_envelope(&root_bytes, ROOT_JSON).unwrap();
        assert_eq!(root.signed.roles[ROLE_ROOT].threshold, 2);
        assert_eq!(root.signatures.len(), 2);
        let targets_bytes = fs::read(repo.join(TARGETS_JSON)).unwrap();
        let targets: Envelope<TargetsSigned> =
            parse_envelope(&targets_bytes, TARGETS_JSON).unwrap();
        assert_eq!(targets.signatures.len(), 2);
    }

    #[test]
    fn producer_updates_roles_for_available_signers() {
        let tmp = TempDir::new().unwrap();
        let repo = init_repo(tmp.path());
        let a = write_test_key(tmp.path(), "core", "a", [12; 32]);
        let b = write_test_key(tmp.path(), "core", "b", [13; 32]);
        fs::write(repo.join("registry.toml"), "[registry]\nname = \"core\"\n").unwrap();
        testutil::git(&repo, &["add", "."]);
        testutil::git(&repo, &["commit", "-m", "catalog"]);

        write_release_metadata_worktree(
            &repo,
            "core",
            &semver::Version::new(1, 0, 0),
            &[metadata_signer(&a)],
        )
        .unwrap();
        write_release_metadata_worktree(
            &repo,
            "core",
            &semver::Version::new(1, 1, 0),
            &[metadata_signer(&a), metadata_signer(&b)],
        )
        .unwrap();

        let root_bytes = fs::read(repo.join(ROOT_JSON)).unwrap();
        let root: Envelope<RootSigned> = parse_envelope(&root_bytes, ROOT_JSON).unwrap();
        assert_eq!(root.signed.roles[ROLE_ROOT].threshold, 2);
        assert_eq!(
            root.signed.roles[ROLE_ROOT].key_ids,
            vec!["a".to_string(), "b".to_string()]
        );
        assert_eq!(root.signatures.len(), 2);

        let err = write_release_metadata_worktree(
            &repo,
            "core",
            &semver::Version::new(1, 2, 0),
            &[metadata_signer(&b)],
        )
        .unwrap_err();
        assert!(format!("{err:#}").contains("verifying rotated root metadata"));

        let mut transition_a = metadata_signer(&a);
        transition_a.role_key = false;
        write_release_metadata_worktree(
            &repo,
            "core",
            &semver::Version::new(1, 2, 0),
            &[transition_a, metadata_signer(&b)],
        )
        .unwrap();
        let root_bytes = fs::read(repo.join(ROOT_JSON)).unwrap();
        let root: Envelope<RootSigned> = parse_envelope(&root_bytes, ROOT_JSON).unwrap();
        assert_eq!(root.signed.roles[ROLE_ROOT].threshold, 1);
        assert_eq!(root.signed.roles[ROLE_ROOT].key_ids, vec!["b".to_string()]);
        assert_eq!(root.signatures.len(), 2);
    }

    #[test]
    fn root_policy_rejects_duplicate_key_material() {
        let tmp = TempDir::new().unwrap();
        let a = write_test_key(tmp.path(), "core", "a", [4; 32]);
        let mut keys = BTreeMap::new();
        keys.insert(
            "a".to_string(),
            TufKey {
                key: a.trust.clone(),
            },
        );
        keys.insert(
            "alias".to_string(),
            TufKey {
                key: a.trust.clone(),
            },
        );
        let mut roles = BTreeMap::new();
        roles.insert(
            ROLE_ROOT.to_string(),
            TufRoleSpec {
                key_ids: vec!["a".to_string(), "alias".to_string()],
                threshold: 2,
            },
        );
        for role in [ROLE_TARGETS, ROLE_SNAPSHOT, ROLE_TIMESTAMP] {
            roles.insert(
                role.to_string(),
                TufRoleSpec {
                    key_ids: vec!["a".to_string()],
                    threshold: 1,
                },
            );
        }
        let err = validate_root_policy(&keys, &roles).unwrap_err();
        assert!(format!("{err:#}").contains("duplicate public key material"));
    }

    #[test]
    fn changed_metadata_requires_version_increase() {
        let err = ensure_replaced_metadata_version_advances(
            TARGETS_JSON,
            2,
            br#"{"version":2,"targets":{"a":1}}"#,
            2,
            br#"{"version":2,"targets":{"a":2}}"#,
        )
        .unwrap_err();
        assert!(format!("{err:#}").contains("changed without a version increase"));
    }

    #[test]
    fn expired_timestamp_is_rejected() {
        let err = ensure_not_expired(
            TIMESTAMP_JSON,
            "2026-01-01T00:00:00Z",
            parse_iso8601_utc_secs("2026-01-01T00:00:01Z").unwrap(),
        )
        .unwrap_err();
        assert!(format!("{err:#}").contains("expired"));
    }

    fn two_key_policy(
        a: &TestKey,
        b: &TestKey,
        threshold: u32,
    ) -> (BTreeMap<String, TufKey>, BTreeMap<String, TufRoleSpec>) {
        let mut keys = BTreeMap::new();
        keys.insert(
            a.id.clone(),
            TufKey {
                key: a.trust.clone(),
            },
        );
        keys.insert(
            b.id.clone(),
            TufKey {
                key: b.trust.clone(),
            },
        );
        let mut roles = BTreeMap::new();
        for role in [ROLE_ROOT, ROLE_TARGETS, ROLE_SNAPSHOT, ROLE_TIMESTAMP] {
            roles.insert(
                role.to_string(),
                TufRoleSpec {
                    key_ids: vec![a.id.clone(), b.id.clone()],
                    threshold,
                },
            );
        }
        (keys, roles)
    }

    fn init_repo(root: &Path) -> PathBuf {
        let repo = root.join("repo");
        testutil::git(
            root,
            &["init", "--initial-branch=main", repo.to_str().unwrap()],
        );
        testutil::git(&repo, &["config", "user.name", "AOS Test"]);
        testutil::git(&repo, &["config", "user.email", "test@example.com"]);
        repo
    }

    fn write_test_key(root: &Path, registry: &str, id: &str, seed: [u8; 32]) -> TestKey {
        let dir = root.join("keys");
        fs::create_dir_all(&dir).unwrap();
        let keypair = Ed25519Keypair::from_seed(seed);
        let private = dir.join(id);
        fs::write(&private, keypair.to_openssh_private_key(id)).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            fs::set_permissions(&private, fs::Permissions::from_mode(0o600)).unwrap();
        }
        TestKey {
            id: id.to_string(),
            trust: keypair.trust_key_line(registry),
            private,
        }
    }

    fn metadata_signer(key: &TestKey) -> MetadataSigningKey {
        MetadataSigningKey {
            key_id: key.id.clone(),
            key_path: key.private.clone(),
            key: key.trust.clone(),
            role_key: true,
        }
    }

    #[test]
    fn worktree_root_role_keys_returns_role_pairs() {
        let tmp = TempDir::new().unwrap();
        let repo = init_repo(tmp.path());
        let a = write_test_key(tmp.path(), "core", "a", [20; 32]);
        fs::write(repo.join("registry.toml"), "[registry]\nname = \"core\"\n").unwrap();
        testutil::git(&repo, &["add", "."]);
        testutil::git(&repo, &["commit", "-m", "catalog"]);
        write_release_metadata_worktree(
            &repo,
            "core",
            &semver::Version::new(1, 0, 0),
            &[metadata_signer(&a)],
        )
        .unwrap();

        let role_keys = worktree_root_role_keys(&repo).unwrap();
        assert_eq!(role_keys, vec![("a".to_string(), a.trust.clone())]);
    }

    #[test]
    fn root_rotation_requires_matching_previous_root_key_id() {
        let tmp = TempDir::new().unwrap();
        let repo = init_repo(tmp.path());
        let a = write_test_key(tmp.path(), "core", "a", [21; 32]);
        let b = write_test_key(tmp.path(), "core", "b", [22; 32]);
        fs::write(repo.join("registry.toml"), "[registry]\nname = \"core\"\n").unwrap();
        testutil::git(&repo, &["add", "."]);
        testutil::git(&repo, &["commit", "-m", "catalog"]);
        write_release_metadata_worktree(
            &repo,
            "core",
            &semver::Version::new(1, 0, 0),
            &[metadata_signer(&a)],
        )
        .unwrap();

        // A transition co-signer carrying the previous root key material but an
        // id that is NOT the previous root-role key id cannot authorize the
        // rotation: `authorized_by_previous` matches on the role's key id.
        let mut wrong_id_transition = metadata_signer(&a);
        wrong_id_transition.key_id = "not-the-root-id".to_string();
        wrong_id_transition.role_key = false;
        let err = write_release_metadata_worktree(
            &repo,
            "core",
            &semver::Version::new(2, 0, 0),
            &[wrong_id_transition, metadata_signer(&b)],
        )
        .unwrap_err();
        assert!(
            format!("{err:#}").contains("verifying rotated root metadata"),
            "expected rotation rejection, got: {err:#}"
        );

        // With the correct previous root-role id ("a") the rotation succeeds and
        // the new policy is the rotated-to key only.
        let mut correct_transition = metadata_signer(&a);
        correct_transition.role_key = false;
        write_release_metadata_worktree(
            &repo,
            "core",
            &semver::Version::new(2, 0, 0),
            &[correct_transition, metadata_signer(&b)],
        )
        .unwrap();
        let root_bytes = fs::read(repo.join(ROOT_JSON)).unwrap();
        let root: Envelope<RootSigned> = parse_envelope(&root_bytes, ROOT_JSON).unwrap();
        assert_eq!(root.signed.roles[ROLE_ROOT].key_ids, vec!["b".to_string()]);
    }
}
