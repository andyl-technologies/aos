//! Exact signed finalization recovery without repeated signing operations.
//!
//! A durable receipt is written before either candidate ref is installed. It
//! retains the original provider operation identities and the frozen review:
//!
//! ```text
//! .git/apr/finalizations/<release>.json
//!   prepared, identity, commit, tag_object, signer_key_ids, provider_operation_ids
//! ```

use std::fs;
use std::io::Write as _;
use std::path::{Path, PathBuf};

use anyhow::{Context as _, Result, bail};
use git2::Repository;
use serde::{Deserialize, Serialize};

use super::{
    FinalizedRegistryRelease, PreparedRegistryRelease, RegistryCommitIdentity,
    RegistryReleaseLifecycle, RegistryReleaseTransaction, build_tag_payload,
    collect_static_surface, registry_surface_digests, validate_container_graph,
    validate_materialized_entries, verify_catalog_metadata,
};

const MAX_RECEIPT_BYTES: u64 = 33 * 1024 * 1024;

/// Original signed objects and their provider evidence before ref installation.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct SignedFinalizationReceipt {
    pub prepared: PreparedRegistryRelease,
    pub identity: RegistryCommitIdentity,
    pub commit: String,
    pub tag_object: String,
    pub signer_key_ids: Vec<String>,
    pub provider_operation_ids: Vec<String>,
}

fn receipt_path(directory: &Path, release: &str) -> Result<PathBuf> {
    semver::Version::parse(release)?;
    Ok(crate::registry::objectstore::repo_git_dir(directory)?
        .join("apr/finalizations")
        .join(format!("{release}.json")))
}

pub(super) fn read(directory: &Path, release: &str) -> Result<Option<SignedFinalizationReceipt>> {
    let path = receipt_path(directory, release)?;
    let metadata = match fs::metadata(&path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error.into()),
    };
    if metadata.len() > MAX_RECEIPT_BYTES {
        bail!("signed registry finalization receipt exceeds its size limit");
    }
    Ok(Some(serde_json::from_slice(&fs::read(path)?)?))
}

pub(super) fn write(receipt: &SignedFinalizationReceipt) -> Result<()> {
    let path = receipt_path(&receipt.prepared.directory, &receipt.prepared.release)?;
    let bytes = serde_json::to_vec(receipt)?;
    if bytes.len() as u64 > MAX_RECEIPT_BYTES {
        bail!("signed registry finalization receipt exceeds its size limit");
    }
    let parent = path
        .parent()
        .context("finalization receipt lacks a parent")?;
    fs::create_dir_all(parent)?;
    if let Some(existing) = read(&receipt.prepared.directory, &receipt.prepared.release)? {
        if existing != *receipt {
            bail!("signed registry finalization receipt already binds different objects");
        }
        return Ok(());
    }
    let mut temporary = tempfile::NamedTempFile::new_in(parent)?;
    temporary.write_all(&bytes)?;
    temporary.as_file().sync_all()?;
    temporary
        .persist_noclobber(&path)
        .map_err(|error| error.error)?;
    fs::File::open(parent)?.sync_all()?;
    Ok(())
}

/// Checks all immutable evidence before changing either candidate ref.
fn validate(receipt: &SignedFinalizationReceipt) -> Result<()> {
    let prepared = &receipt.prepared;
    if prepared.schema != super::PREPARED_SCHEMA
        || receipt.signer_key_ids.len() != 2
        || receipt.provider_operation_ids.len() != 2
        || receipt.provider_operation_ids.iter().any(String::is_empty)
    {
        bail!("signed registry finalization receipt is malformed");
    }
    super::require_git_oid(&prepared.base_commit)?;
    super::require_sha256(&prepared.plan_digest, "recovery plan digest")?;
    receipt.identity.validate()?;
    if registry_surface_digests(&prepared.directory)? != prepared.surfaces {
        bail!("candidate surfaces changed after signed finalization");
    }
    if let Some(graph) = &prepared.container {
        validate_container_graph(&prepared.directory, &prepared.release, graph)?;
    }

    let repository = Repository::open(&prepared.directory)?;
    let format = repository.object_format();
    let commit = repository.find_commit(git2::Oid::from_str_ext(&receipt.commit, format)?)?;
    let tag = repository.find_tag(git2::Oid::from_str_ext(&receipt.tag_object, format)?)?;
    let base = git2::Oid::from_str_ext(&prepared.base_commit, format)?;
    let mut expected_parents = vec![base];
    if let Some(previous) = &prepared.predecessor_commit {
        let previous = git2::Oid::from_str_ext(previous, format)?;
        if previous != base && !repository.graph_descendant_of(base, previous)? {
            expected_parents.push(previous);
        }
    }
    if commit.parent_ids().collect::<Vec<_>>() != expected_parents
        || commit.message()?
            != format!(
                "release {}\n\nAOS-Release-Plan: {}",
                prepared.release, prepared.plan_digest
            )
            .as_str()
        || tag.target_id() != commit.id()
        || tag.name()? != prepared.release
    {
        bail!("signed registry objects differ from the reviewed plan and ancestry");
    }
    for signature in [commit.author(), commit.committer()] {
        if signature.name()? != receipt.identity.name
            || signature.email()? != receipt.identity.email
            || signature.when().seconds() != receipt.identity.unix_seconds
            || signature.when().offset_minutes() != receipt.identity.offset_minutes
        {
            bail!("signed commit author identity differs from the persisted receipt");
        }
    }

    // Capture the full worktree into an in-memory index and compare it with
    // the signed tree. This detects unrelated tracked changes as well as
    // catalog changes without resetting or writing the caller's index.
    let mut index = repository.index()?;
    index.update_all(["*"], None)?;
    index.add_all(["*"], git2::IndexAddOption::DEFAULT, None)?;
    if index.write_tree()? != commit.tree_id() {
        bail!("candidate worktree differs from its exact signed tree");
    }
    let expected_tag = build_tag_payload(
        commit.id(),
        &prepared.release,
        &prepared.plan_digest,
        &receipt.identity.signature()?,
    );
    let (_, tag_payload) =
        crate::registry::repo::tag_signature(&prepared.directory, &receipt.tag_object)?
            .context("candidate release tag is unsigned")?;
    if tag_payload != expected_tag {
        bail!("candidate tag identity differs from the persisted signing receipt");
    }

    let roster = crate::registry::keys::load_keys_toml(&prepared.directory)?
        .context("signed finalization recovery requires a committed trust roster")?;
    for (position, key_id) in receipt.signer_key_ids.iter().enumerate() {
        let key = roster
            .active
            .iter()
            .find(|entry| &entry.id == key_id)
            .context("candidate signer is no longer an active registry authority")?;
        let valid = if position == 0 {
            crate::security::verify_commit_signature(
                &prepared.directory,
                &receipt.commit,
                std::slice::from_ref(&key.key),
            )?
        } else {
            crate::security::verify_tag_signature(
                &prepared.directory,
                &receipt.tag_object,
                std::slice::from_ref(&key.key),
            )?
        };
        if !valid {
            bail!("candidate signature does not match its original active authority");
        }
    }
    verify_catalog_metadata(&prepared.directory)?;
    Ok(())
}

pub(super) fn restore_refs(receipt: &SignedFinalizationReceipt) -> Result<()> {
    validate(receipt)?;
    let prepared = &receipt.prepared;
    let repository = Repository::open(&prepared.directory)?;
    let head = repository.head()?;
    let expected_branch = format!("refs/heads/{}", prepared.source_branch);
    if head.name()? != expected_branch
        || ![prepared.base_commit.as_str(), receipt.commit.as_str()].contains(
            &head
                .target()
                .map(|oid| oid.to_string())
                .as_deref()
                .unwrap_or_default(),
        )
    {
        bail!("candidate branch moved after its reviewed finalization");
    }
    let tag_name = format!("refs/tags/{}", prepared.release);
    let tag_oid = git2::Oid::from_str_ext(&receipt.tag_object, repository.object_format())?;
    match repository.find_reference(&tag_name) {
        Ok(reference) if reference.target() == Some(tag_oid) => {}
        Ok(_) => bail!("release tag differs from the original signed candidate"),
        Err(error) if error.code() == git2::ErrorCode::NotFound => {
            repository.reference(&tag_name, tag_oid, false, "resume exact signed release tag")?;
        }
        Err(error) => return Err(error.into()),
    }
    let mut branch = repository.find_reference(&expected_branch)?;
    branch.set_target(
        git2::Oid::from_str_ext(&receipt.commit, repository.object_format())?,
        "resume exact signed release commit",
    )?;
    Ok(())
}

pub(super) async fn complete(
    receipt: SignedFinalizationReceipt,
) -> Result<FinalizedRegistryRelease> {
    restore_refs(&receipt)?;
    let prepared = &receipt.prepared;
    let artifacts = RegistryReleaseLifecycle::complete_signed_release(
        &prepared.directory,
        &semver::Version::parse(&prepared.release)?,
        true,
        &aos_core::output::Printer::new(0, true, false),
    )
    .await?;
    Ok(FinalizedRegistryRelease {
        registry: prepared.registry.clone(),
        release: prepared.release.clone(),
        plan_digest: prepared.plan_digest.clone(),
        commit: receipt.commit,
        tag_object: receipt.tag_object,
        signer_key_ids: receipt.signer_key_ids,
        provider_operation_ids: receipt.provider_operation_ids,
        surfaces: prepared.surfaces.clone(),
        static_surface: collect_static_surface(&prepared.directory)?,
        source_branch: prepared.source_branch.clone(),
        container: prepared.container.clone(),
        full_pack: artifacts.full_pack,
        deltas: artifacts.deltas,
    })
}

pub(super) async fn resume_transaction(
    transaction: &RegistryReleaseTransaction,
    directory: &Path,
) -> Result<Option<FinalizedRegistryRelease>> {
    transaction.validate()?;
    let Some(receipt) = read(directory, &transaction.release)? else {
        return Ok(None);
    };
    let prepared = &receipt.prepared;
    if prepared.directory != directory
        || prepared.registry != transaction.registry
        || prepared.release != transaction.release
        || prepared.base_commit != transaction.base_commit
        || prepared.plan_digest != transaction.plan_digest
        || prepared.surfaces != transaction.expected
        || prepared.entry_count != transaction.entries.len()
        || prepared.container != transaction.container
        || prepared.predecessor_commit != transaction.predecessor_commit
    {
        bail!("signed registry finalization differs from the reviewed transaction");
    }
    validate_materialized_entries(directory, &transaction.entries)?;
    complete(receipt).await.map(Some)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::registry::release::KeyPathRegistryObjectSigner;

    #[tokio::test]
    async fn recovery_preserves_signed_identity_and_recreates_missing_pack() -> Result<()> {
        let temporary = tempfile::tempdir()?;
        let directory = temporary.path().join("registry");
        let key_path = temporary.path().join("authority");
        let key = crate::sshkey::Ed25519Keypair::from_seed([71; 32]);
        fs::write(&key_path, key.to_openssh_private_key("local"))?;
        fs::create_dir(&directory)?;
        let mut options = git2::RepositoryInitOptions::new();
        options
            .object_format(git2::ObjectFormat::Sha256)
            .initial_head("maintainer/candidate");
        let repository = Repository::init_opts(&directory, &options)?;
        fs::write(
            directory.join("registry.toml"),
            "[registry]\nname = \"local\"\n",
        )?;
        fs::write(
            directory.join("keys.toml"),
            format!(
                "schema = 1\n[[keys]]\nid = \"authority\"\nkey = \"{}\"\n",
                key.trust_key_line("local")
            ),
        )?;
        let mut index = repository.index()?;
        index.add_all(["*"], git2::IndexAddOption::DEFAULT, None)?;
        index.write()?;
        let tree = repository.find_tree(index.write_tree()?)?;
        let author = git2::Signature::now("Registry author", "registry@example.invalid")?;
        let base =
            repository.commit(Some("HEAD"), &author, &author, "registry base", &tree, &[])?;
        fs::write(directory.join("README.md"), "reviewed candidate\n")?;
        let prepared = PreparedRegistryRelease::from_authored_tree(
            &directory,
            "local",
            "1.0.0",
            &format!("sha256:{}", "1".repeat(64)),
            &base.to_string(),
            None,
        )?;
        let identity = RegistryCommitIdentity {
            name: "Registry author".to_string(),
            email: "registry@example.invalid".to_string(),
            unix_seconds: 1_770_000_000,
            offset_minutes: 0,
        };
        let mut signer =
            KeyPathRegistryObjectSigner::new(&directory, "local", &key_path, "authority")?;
        let finalized = prepared.finalize(&identity, &mut signer).await?;
        let receipt = read(&directory, "1.0.0")?.context("original signing receipt")?;
        repository
            .find_reference("refs/heads/maintainer/candidate")?
            .set_target(base, "simulate interruption before branch update")?;

        fs::write(directory.join("README.md"), "unreviewed change\n")?;
        assert!(restore_refs(&receipt).is_err());
        assert_eq!(repository.head()?.target(), Some(base));
        fs::write(directory.join("README.md"), "reviewed candidate\n")?;
        let pack = finalized
            .static_surface
            .iter()
            .find(|file| file.path.ends_with(".pack"))
            .context("optimized full pack")?;
        fs::remove_file(crate::registry::objectstore::repo_git_dir(&directory)?.join(&pack.path))?;

        let recovered = complete(receipt).await?;

        assert_eq!(recovered.commit, finalized.commit);
        assert_eq!(recovered.tag_object, finalized.tag_object);
        assert_eq!(
            recovered.provider_operation_ids,
            finalized.provider_operation_ids
        );
        assert_eq!(recovered.signer_key_ids, finalized.signer_key_ids);
        assert_eq!(recovered.full_pack, finalized.full_pack);
        assert!(
            crate::registry::objectstore::repo_git_dir(&directory)?
                .join(&pack.path)
                .is_file()
        );
        assert_eq!(
            repository.head()?.target().map(|oid| oid.to_string()),
            Some(finalized.commit)
        );
        Ok(())
    }
}
