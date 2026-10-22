//! Native verification and historical version floors for registry catalog metadata.

use crate::security::verify_payload_signature;
use crate::types::RegistryState;
use anyhow::{Context, Result, bail};
use aos_registry_format::tuf::*;
use serde::Serialize;
use serde::de::DeserializeOwned;
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, HashSet};
use std::fs;
use std::path::Path;
/// Contains the four signed catalog envelopes read from one registry commit.
pub struct CommitMetadataFiles {
    /// Root-authority envelope bytes.
    pub root: Vec<u8>,
    /// Catalog-target envelope bytes.
    pub targets: Vec<u8>,
    /// Metadata-snapshot envelope bytes.
    pub snapshot: Vec<u8>,
    /// Freshness-envelope bytes.
    pub timestamp: Vec<u8>,
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

fn state_has_tuf_floors(state: &RegistryState) -> bool {
    state.tuf_root_version.is_some()
        || state.tuf_targets_version.is_some()
        || state.tuf_snapshot_version.is_some()
        || state.tuf_timestamp_version.is_some()
}

/// Verifies the distinct-key signature threshold for a metadata role.
///
/// # Errors
///
/// Returns an error when the role policy is invalid, serialization or key
/// verification fails, or too few authorized signatures verify.
pub fn verify_envelope<T: Serialize>(
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

/// Validates the signing keys and all required catalog role policies.
///
/// # Errors
///
/// Returns an error for missing roles, malformed or duplicate key material,
/// unknown role keys, or an unsatisfiable signature threshold.
pub fn validate_root_policy(
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

/// Verifies current candidate files through the unchanged APM metadata verifier.
///
/// The candidate is captured in an unreferenced Git commit; no branch or tag
/// moves. The latest published metadata supplies root-rotation authorization
/// and rollback floors; `HEAD` supplies the initial base when no release exists.
/// Existing metadata cannot be stripped; present metadata must be current and valid.
/// A pre-TUF base without metadata remains available to legacy library callers.
///
/// # Errors
///
/// Returns an error for missing, stale, expired, stripped, incorrectly signed,
/// or unauthorized catalog metadata, or an unreadable worktree snapshot.
pub fn verify_worktree_metadata(
    repo_dir: &Path,
    registry: &str,
    trusted_keys: &[String],
) -> Result<Option<VerifiedMetadata>> {
    let commit = snapshot_worktree(repo_dir)?;
    let repo = git2::Repository::open(repo_dir)?;
    let published = published_metadata_history(repo_dir, None)?;
    let previous = published
        .as_ref()
        .map(|(commit, _)| commit.clone())
        .unwrap_or(repo.head()?.peel_to_commit()?.id().to_string());
    let commit = commit.to_string();
    let has_previous = load_commit_metadata(repo_dir, &previous)?.is_some();
    let has_current = load_commit_metadata(repo_dir, &commit)?.is_some();
    if let (Some((_, history)), Some(current)) =
        (&published, load_commit_metadata(repo_dir, &commit)?)
    {
        require_history_floor::<RootSigned>(&history.root, &current.root, ROOT_JSON, |value| {
            value.version
        })?;
        require_history_floor::<TargetsSigned>(
            &history.targets,
            &current.targets,
            TARGETS_JSON,
            |value| value.version,
        )?;
        require_history_floor::<SnapshotSigned>(
            &history.snapshot,
            &current.snapshot,
            SNAPSHOT_JSON,
            |value| value.version,
        )?;
        require_history_floor::<TimestampSigned>(
            &history.timestamp,
            &current.timestamp,
            TIMESTAMP_JSON,
            |value| value.version,
        )?;
    }
    verify_commit_metadata(
        repo_dir,
        registry,
        &commit,
        Some(&previous),
        trusted_keys,
        &RegistryState::default(),
        unix_now_secs(),
        has_previous || has_current,
    )
}

/// Creates an unreferenced candidate commit for worktree verification.
///
/// Updates the index and writes a candidate tree and commit without moving
/// any repository ref.
///
/// # Errors
///
/// Returns an error when the repository, index, base commit, or candidate
/// tree cannot be read or written.
pub fn snapshot_worktree(repo_dir: &Path) -> Result<git2::Oid> {
    let repo = git2::Repository::open(repo_dir)?;
    let base = repo.head()?.peel_to_commit()?;
    let mut index = repo.index()?;
    index.add_all(["*"], git2::IndexAddOption::DEFAULT, None)?;
    index.update_all(["*"], None)?;
    let tree_id = index.write_tree()?;
    let tree = repo.find_tree(tree_id)?;
    let identity = base.author();
    repo.commit(
        None,
        &identity,
        &identity,
        "catalog metadata verification snapshot",
        &tree,
        &[&base],
    )
    .context("snapshotting candidate catalog without moving a ref")
}

/// Collects byte commitments for all committed files outside the TUF directory.
///
/// # Errors
///
/// Returns an error when the selected commit or its tree blobs cannot be read.
pub fn collect_commit_catalog(
    repo_dir: &Path,
    commit: &str,
) -> Result<BTreeMap<String, TufFileMeta>> {
    let mut catalog = BTreeMap::new();
    crate::registry::repo::visit_tree_blobs_blocking(repo_dir, commit, |path, bytes| {
        if !path.starts_with("tuf/") {
            catalog.insert(path.to_string(), file_meta(bytes));
        }
        Ok(())
    })?;
    Ok(catalog)
}

/// Hashes the ordered catalog commitment map using its JSON encoding.
///
/// # Errors
///
/// Returns an error if the catalog cannot be serialized.
pub fn catalog_hash(catalog: &BTreeMap<String, TufFileMeta>) -> Result<String> {
    let bytes = serde_json::to_vec(catalog).context("serializing TUF catalog for hashing")?;
    Ok(sha256_digest(&bytes))
}

fn file_meta(bytes: &[u8]) -> TufFileMeta {
    TufFileMeta {
        length: bytes.len() as u64,
        sha256: sha256_digest(bytes),
    }
}

/// Records the version, byte length, and SHA-256 identity of an envelope.
pub fn versioned_meta(version: u64, bytes: &[u8]) -> TufVersionedMeta {
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

/// Returns the lowercase hexadecimal SHA-256 digest of the supplied bytes.
pub fn sha256_digest(bytes: &[u8]) -> String {
    format!("sha256:{}", hex::encode(Sha256::digest(bytes)))
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

/// Loads published metadata envelopes and merges their highest version floors.
///
/// # Errors
///
/// Returns an error when release tags or their committed catalog envelopes
/// cannot be resolved, read, or parsed.
pub fn published_metadata_history(
    repo_dir: &Path,
    candidate: Option<&semver::Version>,
) -> Result<Option<(String, CommitMetadataFiles)>> {
    let repo = git2::Repository::open(repo_dir)?;
    let mut history: Option<(String, CommitMetadataFiles)> = None;
    for version in semver_tag_versions(repo_dir)?.into_iter().rev() {
        if candidate == Some(&version) {
            continue;
        }
        let reference = format!("refs/tags/{version}");
        let tag = repo
            .find_reference(&reference)?
            .peel_to_tag()
            .with_context(|| {
                format!("published catalog predecessor {version} is not an annotated tag")
            })?;
        let commit = tag.target()?.peel_to_commit()?.id().to_string();
        if let Some(files) = load_commit_metadata(repo_dir, &commit)? {
            if let Some((root_commit, retained)) = &mut history {
                // SemVer ordering is independent of publication chronology:
                // a hotfix on an older release line may carry a newer root.
                if merge_metadata_floor::<RootSigned>(
                    &mut retained.root,
                    &files.root,
                    ROOT_JSON,
                    |value| value.version,
                )? {
                    *root_commit = commit;
                }
                merge_metadata_floor::<TargetsSigned>(
                    &mut retained.targets,
                    &files.targets,
                    TARGETS_JSON,
                    |value| value.version,
                )?;
                merge_metadata_floor::<SnapshotSigned>(
                    &mut retained.snapshot,
                    &files.snapshot,
                    SNAPSHOT_JSON,
                    |value| value.version,
                )?;
                merge_metadata_floor::<TimestampSigned>(
                    &mut retained.timestamp,
                    &files.timestamp,
                    TIMESTAMP_JSON,
                    |value| value.version,
                )?;
            } else {
                history = Some((commit, files));
            }
        }
    }
    Ok(history)
}

fn merge_metadata_floor<T: DeserializeOwned + Serialize>(
    retained: &mut Vec<u8>,
    candidate: &[u8],
    path: &str,
    version: fn(&T) -> u64,
) -> Result<bool> {
    let existing: Envelope<T> = parse_envelope(retained, path)?;
    let incoming: Envelope<T> = parse_envelope(candidate, path)?;
    if version(&incoming.signed) > version(&existing.signed) {
        *retained = candidate.to_vec();
        return Ok(true);
    }
    if version(&incoming.signed) == version(&existing.signed)
        && signed_payload_bytes(&incoming.signed)? != signed_payload_bytes(&existing.signed)?
    {
        bail!(
            "published {path} identities conflict at metadata version {}",
            version(&incoming.signed)
        );
    }
    Ok(false)
}

fn require_history_floor<T: DeserializeOwned + Serialize>(
    historical: &[u8],
    candidate: &[u8],
    path: &str,
    version: fn(&T) -> u64,
) -> Result<()> {
    let previous: Envelope<T> = parse_envelope(historical, path)?;
    let current: Envelope<T> = parse_envelope(candidate, path)?;
    ensure_replaced_metadata_version_advances(
        path,
        version(&previous.signed),
        &signed_payload_bytes(&previous.signed)?,
        version(&current.signed),
        &signed_payload_bytes(&current.signed)?,
    )
}

fn commit_path_exists(repo_dir: &Path, commit: &str, path: &str) -> Result<bool> {
    crate::registry::repo::tree_path_exists_blocking(repo_dir, commit, path)
        .with_context(|| format!("checking {commit}:{path}"))
}

/// Reads a typed metadata envelope when its worktree path exists.
///
/// # Errors
///
/// Returns an error when an existing envelope cannot be read or parsed.
pub fn read_worktree_envelope<T: DeserializeOwned>(path: &Path) -> Result<Option<Envelope<T>>> {
    if !path.exists() {
        return Ok(None);
    }
    let bytes = fs::read(path).with_context(|| format!("reading {}", path.display()))?;
    parse_envelope(&bytes, &path.display().to_string()).map(Some)
}

/// Parses a typed JSON metadata envelope with its path in diagnostics.
///
/// # Errors
///
/// Returns an error when the bytes do not deserialize into the selected
/// envelope schema.
pub fn parse_envelope<T: DeserializeOwned>(bytes: &[u8], path: &str) -> Result<Envelope<T>> {
    serde_json::from_slice(bytes).with_context(|| format!("parsing {path}"))
}

/// Serializes the compact JSON bytes authenticated by catalog signatures.
///
/// # Errors
///
/// Returns an error when the payload cannot be serialized.
pub fn signed_payload_bytes<T: Serialize>(signed: &T) -> Result<Vec<u8>> {
    serde_json::to_vec(signed).context("serializing TUF signed payload")
}

/// Serializes a metadata envelope as pretty JSON with a trailing newline.
///
/// # Errors
///
/// Returns an error when the envelope cannot be serialized.
pub fn envelope_bytes<T: Serialize>(envelope: &Envelope<T>) -> Result<Vec<u8>> {
    let mut bytes = serde_json::to_vec_pretty(envelope).context("serializing TUF envelope")?;
    bytes.push(b'\n');
    Ok(bytes)
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

/// Rejects a metadata envelope whose UTC expiration is no longer fresh.
///
/// # Errors
///
/// Returns an error for an invalid timestamp or an expiration at or before
/// the supplied current time.
pub fn ensure_not_expired(path: &str, expires: &str, now_secs: u64) -> Result<()> {
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

/// Requires a version increase whenever authenticated metadata bytes change.
///
/// # Errors
///
/// Returns an error when changed payload bytes retain or lower their
/// previous metadata version.
pub fn ensure_replaced_metadata_version_advances(
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

/// Returns the current Unix time in seconds, or zero before the Unix epoch.
pub fn unix_now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

/// Formats Unix seconds as the catalog's UTC timestamp representation.
pub fn format_iso8601_utc(secs: u64) -> String {
    let days = secs / 86400;
    let time_of_day = secs % 86400;
    let hours = time_of_day / 3600;
    let minutes = (time_of_day % 3600) / 60;
    let seconds = time_of_day % 60;
    let (year, month, day) = days_to_ymd(days);
    format!("{year:04}-{month:02}-{day:02}T{hours:02}:{minutes:02}:{seconds:02}Z")
}

/// Parses the catalog's UTC timestamp representation into Unix seconds.
///
/// # Errors
///
/// Returns an error for an invalid timestamp shape or out-of-range date
/// and time fields.
///
/// # Panics
///
/// Panics if malformed non-ASCII input places a UTF-8 code point across
/// one of the fixed timestamp field boundaries.
pub fn parse_iso8601_utc_secs(input: &str) -> Result<u64> {
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

/// Lists parseable semver tags in ascending version order.
///
/// # Errors
///
/// Returns an error when the Git repository or its tag names cannot be read.
pub fn semver_tag_versions(directory: &Path) -> Result<Vec<semver::Version>> {
    let repo = git2::Repository::open(directory)?;
    let mut versions = repo
        .tag_names(None)?
        .iter()
        .flatten()
        .filter_map(|tag| tag.and_then(|name| semver::Version::parse(name).ok()))
        .collect::<Vec<_>>();
    versions.sort();
    versions.dedup();
    Ok(versions)
}
