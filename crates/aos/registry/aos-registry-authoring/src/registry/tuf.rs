//! Signed catalog generation for registry publication candidates.

use std::collections::{BTreeMap, HashSet};
use std::path::{Path, PathBuf};
use std::fs;
use anyhow::{Context, Result, bail};
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
pub use aos_registry_format::tuf::*;
use aos_registry_client::security::verify_payload_signature;
use futures_util::FutureExt as _;
use aos_registry_client::registry::tuf::*;
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

pub mod signer;

pub use signer::{MetadataSigningIdentity, MetadataSigningRequest, RegistryMetadataSigner};

use signer::FileMetadataSigner;

struct MetadataContext<'a> {
    registry: &'a str,
    release: &'a semver::Version,
}



/// Generate and write release TUF metadata in a registry authoring clone.
///
/// The catalog covers every file in the current worktree except `tuf/`.
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
    let mut signer = FileMetadataSigner { keys: signing_keys };
    // The file adapter performs synchronous signing and cannot yield. Keeping
    // this wrapper synchronous preserves APR's existing producer API without
    // starting or nesting an async runtime.
    write_metadata_with_signer(repo_dir, registry, release, &mut signer, true)
        .now_or_never()
        .context("synchronous catalog metadata signer unexpectedly yielded")?
}



/// Regenerates catalog metadata over an isolated candidate's current files.
///
/// The candidate's `HEAD` may still name its frozen base. The producer hashes
/// the current worktree, signs all four catalog roles, verifies current and
/// previous root thresholds, and writes metadata before review digests freeze.
///
/// # Errors
///
/// Returns an error for invalid or incomplete root authorization, signing or
/// threshold failures, malformed prior metadata, or unreadable candidate files.
pub async fn write_release_metadata_worktree_with_signer(
    repo_dir: &Path,
    registry: &str,
    release: &semver::Version,
    signer: &mut dyn RegistryMetadataSigner,
) -> Result<bool> {
    write_metadata_with_signer(repo_dir, registry, release, signer, true).await
}



async fn write_metadata_with_signer(
    repo_dir: &Path,
    registry: &str,
    release: &semver::Version,
    signer: &mut dyn RegistryMetadataSigner,
    current_worktree: bool,
) -> Result<bool> {
    let signing_keys = signer.signing_identities();
    let context = MetadataContext { registry, release };
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
    // A maintainer workspace may still descend from an older release. Local
    // publication history supplies the root authority and version floors, so
    // a later candidate cannot restart metadata counters from that workspace.
    let published = published_metadata_history(repo_dir, Some(release))?;
    let published_root = published
        .as_ref()
        .map(|(_, files)| parse_envelope::<RootSigned>(&files.root, ROOT_JSON))
        .transpose()?;
    let published_targets = published
        .as_ref()
        .map(|(_, files)| parse_envelope::<TargetsSigned>(&files.targets, TARGETS_JSON))
        .transpose()?;
    let published_snapshot = published
        .as_ref()
        .map(|(_, files)| parse_envelope::<SnapshotSigned>(&files.snapshot, SNAPSHOT_JSON))
        .transpose()?;
    let published_timestamp = published
        .as_ref()
        .map(|(_, files)| parse_envelope::<TimestampSigned>(&files.timestamp, TIMESTAMP_JSON))
        .transpose()?;
    let previous_root = published_root.as_ref().or(existing_root.as_ref());

    let (keys, roles) = root_policy_for_signers(previous_root, &signing_keys);
    validate_root_policy(&keys, &roles)?;

    let now = unix_now_secs();
    let root_signed = RootSigned {
        schema: SCHEMA_ROOT.to_string(),
        spec_version: SPEC_VERSION.to_string(),
        registry: registry.to_string(),
        version: next_version(version_floor(
            existing_root.as_ref().map(|root| root.signed.version),
            published_root.as_ref().map(|root| root.signed.version),
        )),
        expires: format_iso8601_utc(now.saturating_add(ROOT_EXPIRES_SECONDS)),
        keys: keys.clone(),
        roles: roles.clone(),
    };
    let root = sign_root_envelope(
        root_signed,
        &signing_keys,
        &keys,
        &roles,
        previous_root,
        &context,
        signer,
    )
    .await?;
    if let Some(previous_root) = previous_root {
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

    let catalog_commit = if current_worktree {
        snapshot_worktree(repo_dir)?.to_string()
    } else {
        "HEAD".to_string()
    };
    let targets_map = collect_commit_catalog(repo_dir, &catalog_commit)?;
    let targets_signed = TargetsSigned {
        schema: SCHEMA_TARGETS.to_string(),
        spec_version: SPEC_VERSION.to_string(),
        registry: registry.to_string(),
        version: next_version(version_floor(
            existing_targets
                .as_ref()
                .map(|targets| targets.signed.version),
            published_targets
                .as_ref()
                .map(|targets| targets.signed.version),
        )),
        expires: format_iso8601_utc(now.saturating_add(TARGETS_EXPIRES_SECONDS)),
        release: release.to_string(),
        catalog_hash: catalog_hash(&targets_map)?,
        targets: targets_map,
    };
    let targets = sign_envelope(
        targets_signed,
        ROLE_TARGETS,
        &signing_keys,
        &root.signed.keys,
        &root.signed.roles,
        &context,
        signer,
    )
    .await?;
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
        version: next_version(version_floor(
            existing_snapshot
                .as_ref()
                .map(|snapshot| snapshot.signed.version),
            published_snapshot
                .as_ref()
                .map(|snapshot| snapshot.signed.version),
        )),
        expires: format_iso8601_utc(now.saturating_add(SNAPSHOT_EXPIRES_SECONDS)),
        meta: snapshot_meta,
    };
    let snapshot = sign_envelope(
        snapshot_signed,
        ROLE_SNAPSHOT,
        &signing_keys,
        &root.signed.keys,
        &root.signed.roles,
        &context,
        signer,
    )
    .await?;
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
        version: next_version(version_floor(
            existing_timestamp
                .as_ref()
                .map(|timestamp| timestamp.signed.version),
            published_timestamp
                .as_ref()
                .map(|timestamp| timestamp.signed.version),
        )),
        expires: format_iso8601_utc(now.saturating_add(TIMESTAMP_EXPIRES_SECONDS)),
        snapshot: versioned_meta(snapshot.signed.version, &snapshot_bytes),
    };
    let timestamp = sign_envelope(
        timestamp_signed,
        ROLE_TIMESTAMP,
        &signing_keys,
        &root.signed.keys,
        &root.signed.roles,
        &context,
        signer,
    )
    .await?;
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



fn next_version(previous: Option<u64>) -> u64 {
    previous.unwrap_or(0).saturating_add(1)
}



fn version_floor(workspace: Option<u64>, published: Option<u64>) -> Option<u64> {
    workspace.into_iter().chain(published).max()
}



fn root_policy_for_signers(
    existing_root: Option<&Envelope<RootSigned>>,
    signing_keys: &[MetadataSigningIdentity],
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



async fn sign_root_envelope<T: Serialize>(
    signed: T,
    signing_keys: &[MetadataSigningIdentity],
    keys: &BTreeMap<String, TufKey>,
    roles: &BTreeMap<String, TufRoleSpec>,
    previous_root: Option<&Envelope<RootSigned>>,
    context: &MetadataContext<'_>,
    provider: &mut dyn RegistryMetadataSigner,
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
        let request =
            metadata_signing_request(&signed, context, ROLE_ROOT, &signer.key_id, &payload)?;
        let sig = provider
            .sign_metadata(request)
            .await
            .with_context(|| format!("signing root TUF metadata with '{}'", signer.key_id))?;
        signatures.push(TufSignature {
            key_id: signer.key_id.clone(),
            sig,
        });
    }
    Ok(Envelope { signed, signatures })
}



async fn sign_envelope<T: Serialize>(
    signed: T,
    role: &str,
    signing_keys: &[MetadataSigningIdentity],
    keys: &BTreeMap<String, TufKey>,
    roles: &BTreeMap<String, TufRoleSpec>,
    context: &MetadataContext<'_>,
    provider: &mut dyn RegistryMetadataSigner,
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
        let request = metadata_signing_request(&signed, context, role, &signer.key_id, &payload)?;
        let sig = provider
            .sign_metadata(request)
            .await
            .with_context(|| format!("signing {role} TUF metadata with '{}'", signer.key_id))?;
        signatures.push(TufSignature {
            key_id: signer.key_id.clone(),
            sig,
        });
    }
    Ok(Envelope { signed, signatures })
}


fn metadata_signing_request<T: Serialize>(
    signed: &T,
    context: &MetadataContext<'_>,
    role: &str,
    key_id: &str,
    payload: &[u8],
) -> Result<MetadataSigningRequest> {
    let value = serde_json::to_value(signed)?;
    let version = value
        .get("version")
        .and_then(serde_json::Value::as_u64)
        .context("catalog metadata lacks a nonzero integer version")?;
    Ok(MetadataSigningRequest {
        registry: context.registry.to_string(),
        release: context.release.to_string(),
        role: role.to_string(),
        version,
        key_id: key_id.to_string(),
        payload: payload.to_vec(),
    })
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
#[cfg(test)]
mod tests {
    use super::*;
    use aos_registry_client::sshkey::Ed25519Keypair;
    use crate::testutil;
    use aos_registry_client::security::sign_payload_signature;
    use aos_registry_client::types::RegistryState;
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
    fn synchronous_metadata_binds_an_uncommitted_container_sidecar() -> Result<()> {
        let temporary = TempDir::new()?;
        let repo = init_repo(temporary.path());
        fs::write(repo.join("registry.toml"), "[registry]\nname = \"core\"\n")?;
        testutil::git(&repo, &["add", "registry.toml"]);
        testutil::git(&repo, &["commit", "-m", "initial catalog"]);
        let base = git2::Repository::open(&repo)?
            .head()?
            .peel_to_commit()?
            .id();

        let sidecar_path = aos_oci_types::CONTAINER_RELEASE_SIDECAR_PATH;
        let sidecar_bytes = b"exact uncommitted container sidecar\n";
        fs::create_dir_all(repo.join(sidecar_path).parent().context("sidecar parent")?)?;
        fs::write(repo.join(sidecar_path), sidecar_bytes)?;
        let key = write_test_key(temporary.path(), "core", "maintainer", [34; 32]);
        write_release_metadata_worktree(
            &repo,
            "core",
            &semver::Version::new(1, 0, 0),
            &[metadata_signer(&key)],
        )?;

        let targets: Envelope<TargetsSigned> =
            parse_envelope(&fs::read(repo.join(TARGETS_JSON))?, TARGETS_JSON)?;
        assert_eq!(
            targets.signed.targets[sidecar_path].length,
            sidecar_bytes.len() as u64
        );
        assert_eq!(
            targets.signed.targets[sidecar_path].sha256,
            sha256_digest(sidecar_bytes)
        );
        assert!(verify_worktree_metadata(&repo, "core", &[key.trust])?.is_some());
        assert_eq!(
            git2::Repository::open(&repo)?
                .head()?
                .peel_to_commit()?
                .id(),
            base
        );
        assert!(
            git2::Repository::open(&repo)?
                .find_reference("refs/tags/1.0.0")
                .is_err()
        );
        Ok(())
    }

    #[tokio::test]
    async fn prepared_catalog_regenerates_apr_metadata_without_moving_refs() -> Result<()> {
        let tmp = TempDir::new()?;
        let repo = init_repo(tmp.path());
        let key = write_test_key(tmp.path(), "core", "maintainer", [31; 32]);
        fs::write(repo.join("registry.toml"), "[registry]\nname = \"core\"\n")?;
        testutil::git(&repo, &["add", "."]);
        testutil::git(&repo, &["commit", "-m", "base catalog"]);
        let signing_keys = vec![metadata_signer(&key)];
        write_release_metadata_worktree(
            &repo,
            "core",
            &semver::Version::new(1, 0, 0),
            &signing_keys,
        )?;
        testutil::git(&repo, &["add", "tuf"]);
        testutil::git(&repo, &["commit", "-m", "APR catalog metadata"]);
        let base = git2::Repository::open(&repo)?
            .head()?
            .peel_to_commit()?
            .id();

        fs::create_dir_all(repo.join("packages/z"))?;
        fs::write(
            repo.join("packages/z/zlib.toml"),
            "new exact catalog bytes\n",
        )?;
        let stale = verify_worktree_metadata(&repo, "core", &[key.trust.clone()]).unwrap_err();
        assert!(format!("{stale:#}").contains("catalog does not match"));
        assert_eq!(
            git2::Repository::open(&repo)?
                .head()?
                .peel_to_commit()?
                .id(),
            base
        );
        assert!(
            git2::Repository::open(&repo)?
                .find_reference("refs/tags/1.1.0")
                .is_err()
        );

        let mut signer = FileMetadataSigner {
            keys: &signing_keys,
        };
        write_release_metadata_worktree_with_signer(
            &repo,
            "core",
            &semver::Version::new(1, 1, 0),
            &mut signer,
        )
        .await?;
        let verified = verify_worktree_metadata(&repo, "core", &[key.trust])?
            .context("prepared candidate metadata was not verified")?;

        assert_eq!(verified.root_version, 2);
        assert_eq!(verified.targets_version, 2);
        assert_eq!(verified.snapshot_version, 2);
        assert_eq!(verified.timestamp_version, 2);
        assert_eq!(
            git2::Repository::open(&repo)?
                .head()?
                .peel_to_commit()?
                .id(),
            base
        );
        assert!(
            git2::Repository::open(&repo)?
                .find_reference("refs/tags/1.1.0")
                .is_err()
        );
        Ok(())
    }

    #[tokio::test]
    async fn stale_workspace_uses_latest_published_catalog_floor() -> Result<()> {
        let temporary = TempDir::new()?;
        let repo = init_repo(temporary.path());
        fs::write(repo.join("registry.toml"), "[registry]\nname = \"core\"\n")?;
        testutil::git(&repo, &["add", "registry.toml"]);
        testutil::git(&repo, &["commit", "-m", "initial catalog"]);

        let key = write_test_key(temporary.path(), "core", "maintainer", [32; 32]);
        let signing_keys = vec![metadata_signer(&key)];
        write_release_metadata_worktree(
            &repo,
            "core",
            &semver::Version::new(1, 4, 0),
            &signing_keys,
        )?;
        testutil::git(&repo, &["add", "tuf"]);
        testutil::git(&repo, &["commit", "-m", "first published metadata"]);
        testutil::git(&repo, &["tag", "-a", "1.4.0", "-m", "first release"]);
        let old_base = git2::Repository::open(&repo)?
            .head()?
            .peel_to_commit()?
            .id()
            .to_string();

        write_release_metadata_worktree(
            &repo,
            "core",
            &semver::Version::new(1, 6, 5),
            &signing_keys,
        )?;
        testutil::git(&repo, &["add", "tuf"]);
        testutil::git(&repo, &["commit", "-m", "second published metadata"]);
        testutil::git(&repo, &["tag", "-a", "1.6.5", "-m", "second release"]);
        let rotated_key = write_test_key(temporary.path(), "core", "rotated", [33; 32]);
        let mut transition_key = metadata_signer(&key);
        transition_key.role_key = false;
        write_release_metadata_worktree(
            &repo,
            "core",
            &semver::Version::new(1, 5, 8),
            &[transition_key, metadata_signer(&rotated_key)],
        )?;
        testutil::git(&repo, &["add", "tuf"]);
        testutil::git(
            &repo,
            &[
                "commit",
                "-m",
                "older-line hotfix rotates metadata authority",
            ],
        );
        testutil::git(&repo, &["tag", "-a", "1.5.8", "-m", "hotfix release"]);
        testutil::git(
            &repo,
            &["checkout", "-b", "dplecki/stale-workspace", &old_base],
        );
        let rotated_signers = vec![metadata_signer(&rotated_key)];

        let mut signer = FileMetadataSigner {
            keys: &rotated_signers,
        };
        write_release_metadata_worktree_with_signer(
            &repo,
            "core",
            &semver::Version::new(1, 5, 9),
            &mut signer,
        )
        .await?;
        let verified = verify_worktree_metadata(&repo, "core", &[rotated_key.trust])?
            .context("stale workspace candidate metadata was not verified")?;

        assert_eq!(verified.root_version, 4);
        assert_eq!(verified.targets_version, 4);
        assert_eq!(verified.snapshot_version, 4);
        assert_eq!(verified.timestamp_version, 4);
        assert_eq!(
            git2::Repository::open(&repo)?
                .head()?
                .peel_to_commit()?
                .id()
                .to_string(),
            old_base
        );
        Ok(())
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

fn semver_tag_versions(directory: &Path) -> Result<Vec<semver::Version>> {
 let repo = git2::Repository::open(directory)?;
 let mut versions = repo.tag_names(None)?.iter().flatten().filter_map(|tag| semver::Version::parse(tag).ok()).collect::<Vec<_>>();
 versions.sort(); versions.dedup(); Ok(versions)
}
