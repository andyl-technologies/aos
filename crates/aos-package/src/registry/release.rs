//! Atomic, isolated registry authoring for canonical releases.
//!
//! A release transaction clones an exact clean registry base into a private
//! temporary directory, materializes every requested entry there, validates
//! the resulting catalog and store graph, and only then renames the prepared
//! tree to its caller-selected output. It never edits or advances a ref in the
//! maintainer's authoring clone.

use std::collections::{BTreeMap, BTreeSet};
use std::fs::{self, File, OpenOptions};
use std::io::{Read as _, Write as _};
use std::path::{Path, PathBuf};

use anyhow::{Context as _, Result, bail};
use aos_oci_types::CONTAINER_RELEASE_SIDECAR_PATH;
use async_trait::async_trait;
use git2::{Repository, StatusOptions};
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};

use super::parse::parse_registry_matching;
use super::store::StoreMap;
use crate::config::ApmConfig;
use crate::provenance::ProvenanceSigner;
use crate::types::{validate_package_name, validate_registry_name};

/// Schema identifier for an atomic registry authoring request.
pub const TRANSACTION_SCHEMA: &str = "aos.registry-release-transaction/v1";
/// Schema identifier for a successfully prepared registry result.
pub const PREPARED_SCHEMA: &str = "aos.prepared-registry-release/v1";
const DIGEST_DOMAIN: &[u8] = b"aos.registry-release-surface/v1\0";

/// One package-platform entry that must appear in the prepared registry.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RegistryReleaseEntry {
    /// Stable entry id from the enclosing release plan.
    pub id: String,
    /// Registry package name.
    pub name: String,
    /// Package version written into the catalog.
    pub version: String,
    /// Exact Nix target platform.
    pub platform: String,
    /// Exact realized store output expected in the catalog.
    pub store_path: String,
}

/// Public catalog metadata used to author every platform entry for a package.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RegistryPackagePublication {
    /// Human-readable package purpose.
    pub description: String,
    /// Optional canonical project home page.
    pub homepage: Option<String>,
    /// SPDX-compatible license expression.
    pub license_expression: String,
    /// Nonempty public maintainer identities.
    pub maintainers: Vec<String>,
}

/// Authors planned package entries through externally backed provenance.
pub struct CanonicalRegistryEntryAuthor<'a> {
    config: &'a ApmConfig,
    registry: &'a str,
    publications: &'a BTreeMap<String, RegistryPackagePublication>,
    signer: &'a mut dyn ProvenanceSigner,
    printer: &'a aos_core::output::Printer,
}

impl<'a> CanonicalRegistryEntryAuthor<'a> {
    /// Creates an author bound to one registry and closed metadata map.
    #[must_use]
    pub fn new(
        config: &'a ApmConfig,
        registry: &'a str,
        publications: &'a BTreeMap<String, RegistryPackagePublication>,
        signer: &'a mut dyn ProvenanceSigner,
        printer: &'a aos_core::output::Printer,
    ) -> Self {
        Self {
            config,
            registry,
            publications,
            signer,
            printer,
        }
    }
}

#[async_trait]
impl RegistryEntryAuthor for CanonicalRegistryEntryAuthor<'_> {
    async fn author_entry(
        &mut self,
        isolated_registry: &Path,
        entry: &RegistryReleaseEntry,
    ) -> Result<()> {
        let publication = self
            .publications
            .get(&entry.name)
            .with_context(|| format!("missing publication metadata for {}", entry.name))?;
        validate_publication(publication, &entry.name)?;
        let maintainer = publication.maintainers.join(", ");
        crate::registry_ops::publish_canonical_release_entry(
            self.config,
            isolated_registry,
            self.registry,
            &entry.store_path,
            &entry.name,
            &entry.version,
            &entry.platform,
            &publication.description,
            publication.homepage.as_deref(),
            &publication.license_expression,
            &maintainer,
            self.signer,
            self.printer,
        )
        .await
    }
}

fn validate_publication(publication: &RegistryPackagePublication, package: &str) -> Result<()> {
    if publication.description.trim().is_empty()
        || publication.license_expression.trim().is_empty()
        || publication.maintainers.is_empty()
        || publication.maintainers.iter().any(|maintainer| {
            maintainer.trim().is_empty() || maintainer.chars().any(char::is_control)
        })
        || publication.description.chars().any(char::is_control)
        || publication.license_expression.chars().any(char::is_control)
        || publication.homepage.as_ref().is_some_and(|homepage| {
            homepage.trim().is_empty() || homepage.chars().any(char::is_control)
        })
    {
        bail!("invalid publication metadata for package {package}");
    }
    Ok(())
}

/// Digests expected after all entries have been materialized.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RegistrySurfaceDigests {
    /// Digest of package, container, documentation, provenance, and transparency data.
    pub catalog: String,
    /// Digest of the complete registry store graph.
    pub store_graph: String,
    /// Digest of registry, trust-roster, Secure Boot, and TUF policy files.
    pub policy: String,
}

/// Complete all-or-nothing authoring request.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RegistryReleaseTransaction {
    /// Exact transaction schema.
    pub schema: String,
    /// Canonical registry identity.
    pub registry: String,
    /// Exact commit from which the isolated clone must start.
    pub base_commit: String,
    /// Release version reserved for the later signed tag.
    pub release: String,
    /// Canonical SHA-256 identity of the enclosing release plan.
    pub plan_digest: String,
    /// Every catalog entry to materialize in deterministic order.
    pub entries: Vec<RegistryReleaseEntry>,
    /// Expected identities of all authored registry surfaces.
    pub expected: RegistrySurfaceDigests,
    /// The release's own `[support]` tables, applied to `registry.toml` before
    /// the policy surface is digested; absent when the contract states none.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub support: Option<super::support::SupportSectionWrite>,
}

/// Auditable result of a successfully prepared registry tree.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PreparedRegistryRelease {
    /// Exact result schema.
    pub schema: String,
    /// Canonical registry identity.
    pub registry: String,
    /// Base commit still checked out in the prepared, uncommitted tree.
    pub base_commit: String,
    /// Release reserved by the transaction.
    pub release: String,
    /// Enclosing release-plan digest.
    pub plan_digest: String,
    /// Number of package-platform entries validated.
    pub entry_count: usize,
    /// Verified identities of the prepared registry surfaces.
    pub surfaces: RegistrySurfaceDigests,
    /// Durable isolated authoring directory.
    pub directory: PathBuf,
}

/// Deterministic author and tagger identity frozen for registry finalization.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RegistryCommitIdentity {
    /// Human-readable public maintainer identity.
    pub name: String,
    /// Public maintainer email address.
    pub email: String,
    /// Signed commit and tag time as Unix seconds.
    pub unix_seconds: i64,
    /// Signed timezone offset in minutes east of UTC.
    pub offset_minutes: i32,
}

/// Kind of Git object submitted to the registry signing authority.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RegistryGitObjectKind {
    /// Unsigned canonical commit buffer.
    Commit,
    /// Unsigned annotated release-tag payload.
    Tag,
}

/// Exact payload and release binding passed to a Git signing adapter.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RegistryGitSigningRequest {
    /// Canonical registry identity.
    pub registry: String,
    /// Release version being finalized.
    pub release: String,
    /// Enclosing release-plan identity.
    pub plan_digest: String,
    /// Narrow Git object operation.
    pub kind: RegistryGitObjectKind,
    /// SHA-256 of `payload`.
    pub payload_digest: String,
    /// Exact bytes Git will store before the SSHSIG armor is attached.
    pub payload: Vec<u8>,
}

/// Bound, audited result returned by a Git signing adapter.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RegistryGitSignature {
    /// Kind repeated from the request.
    pub kind: RegistryGitObjectKind,
    /// Payload digest repeated from the request.
    pub payload_digest: String,
    /// Preauthenticated registry-role public key id.
    pub key_id: String,
    /// Stable provider audit operation id.
    pub provider_operation_id: String,
    /// ASCII-armored OpenSSH SSHSIG over the request payload.
    pub armored_signature: String,
}

/// Signs only registry-bound Git commit and release-tag payloads.
#[async_trait]
pub trait RegistryObjectSigner {
    /// Returns a verified SSHSIG response for one exact request.
    ///
    /// Implementations must enforce the registry role, release, plan digest,
    /// provider revision, key id, and anti-replay policy before returning.
    ///
    /// # Errors
    ///
    /// Returns an error when provider policy or cryptographic verification
    /// rejects the request or the provider is unavailable.
    async fn sign_git_object(
        &mut self,
        request: RegistryGitSigningRequest,
    ) -> Result<RegistryGitSignature>;
}

/// Identities emitted by single-commit registry finalization.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct FinalizedRegistryRelease {
    /// Canonical registry identity.
    pub registry: String,
    /// Final release version.
    pub release: String,
    /// Enclosing release-plan identity.
    pub plan_digest: String,
    /// Exact signed registry commit id.
    pub commit: String,
    /// Exact signed annotated tag-object id.
    pub tag_object: String,
    /// Registry-role key ids used for commit and tag in order.
    pub signer_key_ids: Vec<String>,
    /// Provider operation ids used for commit and tag in order.
    pub provider_operation_ids: Vec<String>,
    /// Closed authored surface digests inherited from preparation.
    pub surfaces: RegistrySurfaceDigests,
    /// Exact static-origin files generated without uploading them.
    pub static_surface: Vec<RegistryStaticSurfaceFile>,
}

/// One exact file in the generated registry static surface.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RegistryStaticSurfaceFile {
    /// Slash-separated origin-relative path.
    pub path: String,
    /// Publication ordering class.
    pub class: String,
    /// Exact byte length.
    pub byte_size: u64,
    /// SHA-256 of the exact upload bytes.
    pub sha256: String,
}

/// Materializes one planned entry without committing or moving a ref.
#[async_trait]
pub trait RegistryEntryAuthor {
    /// Writes exactly one entry into `isolated_registry`.
    ///
    /// Implementations may update package, store, documentation, provenance,
    /// and transparency files, but must not commit, tag, or upload anything.
    ///
    /// # Errors
    ///
    /// Returns an error when the planned entry cannot be fully materialized.
    async fn author_entry(
        &mut self,
        isolated_registry: &Path,
        entry: &RegistryReleaseEntry,
    ) -> Result<()>;
}

/// Verifies an independently supplied trust line against the committed roster.
///
/// # Errors
///
/// Returns an error when the key id is malformed, missing, revoked, or bound
/// to different public key material in `keys.toml`.
pub fn require_active_signing_key(registry: &Path, key_id: &str, trusted_key: &str) -> Result<()> {
    crate::registry_ops::require_active_registry_key(registry, key_id, trusted_key)
}

impl RegistryReleaseTransaction {
    /// Prepares the complete transaction in a new isolated registry clone.
    ///
    /// The output becomes visible only after every entry, deep catalog check,
    /// store-graph check, and expected digest comparison succeeds. Its `HEAD`
    /// remains at `base_commit`; a later role-bound signing phase creates the
    /// sole release commit and tag.
    ///
    /// # Errors
    ///
    /// Returns an error for an invalid or duplicate request, dirty or
    /// mismatched source clone, existing release tag, pre-existing output,
    /// entry-author failure, ref movement, invalid catalog or store data, an
    /// incomplete entry, or a surface digest mismatch.
    pub async fn prepare(
        &self,
        source_registry: &Path,
        output: &Path,
        author: &mut dyn RegistryEntryAuthor,
    ) -> Result<PreparedRegistryRelease> {
        self.prepare_with_container_release(source_registry, output, author, None)
            .await
    }

    /// Prepares the transaction and commits an exact container sidecar surface.
    ///
    /// This is the canonical container-aware form of [`Self::prepare`]. The
    /// sidecar bytes have already been validated against their external
    /// signature input by the caller and are included in the transaction's
    /// expected catalog digest before the isolated tree becomes visible.
    ///
    /// # Errors
    ///
    /// Returns the errors from [`Self::prepare`], or an error when the
    /// container surface cannot be installed as a regular file.
    pub async fn prepare_with_container_release(
        &self,
        source_registry: &Path,
        output: &Path,
        author: &mut dyn RegistryEntryAuthor,
        container_release: Option<&[u8]>,
    ) -> Result<PreparedRegistryRelease> {
        self.validate()?;
        if output.exists() {
            bail!(
                "isolated registry output already exists: {}",
                output.display()
            );
        }
        let output_parent = output
            .parent()
            .context("isolated registry output has no parent")?;
        fs::create_dir_all(output_parent)
            .with_context(|| format!("creating {}", output_parent.display()))?;

        let _lock = AuthoringLock::acquire(source_registry)?;
        validate_source(source_registry, &self.base_commit, &self.release)?;

        let temporary = tempfile::Builder::new()
            .prefix(".aos-registry-release-")
            .tempdir_in(output_parent)
            .with_context(|| format!("creating isolated clone beside {}", output.display()))?;
        let isolated = temporary.path().join("registry");
        let source = source_registry
            .to_str()
            .context("source registry path is not valid UTF-8")?;
        Repository::clone(source, &isolated).with_context(|| {
            format!(
                "cloning exact registry base from {}",
                source_registry.display()
            )
        })?;
        require_head(&isolated, &self.base_commit)?;

        for entry in &self.entries {
            author
                .author_entry(&isolated, entry)
                .await
                .with_context(|| format!("authoring release entry '{}'", entry.id))?;
            require_head(&isolated, &self.base_commit)
                .context("entry author moved the isolated registry ref")?;
        }

        set_container_release(&isolated, container_release)?;
        require_head(&isolated, &self.base_commit)
            .context("container sidecar selection moved the isolated registry ref")?;
        // Support is section-owned: the release writes its own train's table
        // (and the default only from the newest train) and nothing else, so
        // several source lines can publish into one registry without one
        // rewriting another's promise.
        if let Some(support) = &self.support {
            super::support::apply_support_section(&isolated, support)
                .context("applying the release's support policy tables")?;
            require_head(&isolated, &self.base_commit)
                .context("support policy write moved the isolated registry ref")?;
        }

        validate_materialized_entries(&isolated, &self.entries)?;
        StoreMap::load(&isolated).context("validating prepared registry store graph")?;
        require_head(&isolated, &self.base_commit)?;
        require_worktree_changes(&isolated)?;

        let surfaces = registry_surface_digests(&isolated)?;
        if surfaces != self.expected {
            bail!(
                "prepared registry surface digests do not match the release transaction: expected {:?}, found {:?}",
                self.expected,
                surfaces
            );
        }

        rustix::fs::renameat_with(
            rustix::fs::CWD,
            &isolated,
            rustix::fs::CWD,
            output,
            rustix::fs::RenameFlags::NOREPLACE,
        )
        .with_context(|| {
            format!(
                "publishing prepared isolated registry {} to {} without replacement",
                isolated.display(),
                output.display()
            )
        })?;
        File::open(output_parent)?.sync_all().with_context(|| {
            format!(
                "syncing prepared registry parent {}",
                output_parent.display()
            )
        })?;

        Ok(PreparedRegistryRelease {
            schema: PREPARED_SCHEMA.to_string(),
            registry: self.registry.clone(),
            base_commit: self.base_commit.clone(),
            release: self.release.clone(),
            plan_digest: self.plan_digest.clone(),
            entry_count: self.entries.len(),
            surfaces,
            directory: output.to_path_buf(),
        })
    }

    fn validate(&self) -> Result<()> {
        if self.schema != TRANSACTION_SCHEMA {
            bail!("unsupported registry release transaction schema");
        }
        validate_registry_identity(&self.registry)?;
        require_git_oid(&self.base_commit)?;
        semver::Version::parse(&self.release).context("invalid registry release version")?;
        require_sha256(&self.plan_digest, "plan digest")?;
        require_sha256(&self.expected.catalog, "catalog digest")?;
        require_sha256(&self.expected.store_graph, "store-graph digest")?;
        require_sha256(&self.expected.policy, "policy digest")?;
        if self.entries.is_empty() {
            bail!("registry release transaction has no entries");
        }

        let mut ids = BTreeSet::new();
        let mut coordinates = BTreeSet::new();
        let mut previous_id: Option<&str> = None;
        for entry in &self.entries {
            if entry.id.is_empty() || !entry.id.bytes().all(is_identifier_byte) {
                bail!("invalid registry release entry id '{}'", entry.id);
            }
            validate_package_name(&entry.name)?;
            semver::Version::parse(&entry.version)
                .with_context(|| format!("invalid version for entry '{}'", entry.id))?;
            if !matches!(
                entry.platform.as_str(),
                "x86_64-linux" | "aarch64-linux" | "x86_64-darwin" | "aarch64-darwin"
            ) {
                bail!("entry '{}' has unsupported platform", entry.id);
            }
            if !entry.store_path.starts_with("/nix/store/") {
                bail!("entry '{}' has invalid store path", entry.id);
            }
            if !ids.insert(&entry.id) {
                bail!("duplicate registry release entry id '{}'", entry.id);
            }
            if previous_id.is_some_and(|previous| previous >= entry.id.as_str()) {
                bail!("registry release entries must be strictly ordered by id");
            }
            previous_id = Some(&entry.id);
            if !coordinates.insert((&entry.name, &entry.version, &entry.platform)) {
                bail!(
                    "duplicate registry release coordinate {}/{}/{}",
                    entry.name,
                    entry.version,
                    entry.platform
                );
            }
        }
        Ok(())
    }
}

impl PreparedRegistryRelease {
    /// Creates the transaction's sole signed commit and annotated release tag.
    ///
    /// The method stages the complete prepared tree, obtains two independently
    /// bound registry-role signatures, writes the commit and tag objects, and
    /// moves only the isolated clone's branch and release-tag refs. It does not
    /// generate cache bytes, upload objects, or advance a channel.
    ///
    /// # Errors
    ///
    /// Returns an error if the prepared tree changed, the base ref moved, the
    /// release tag appeared, identity data is invalid, staging yields no tree
    /// change, either signer response is unbound or malformed, or Git cannot
    /// write the objects and isolated refs.
    pub async fn finalize(
        &self,
        identity: &RegistryCommitIdentity,
        signer: &mut dyn RegistryObjectSigner,
    ) -> Result<FinalizedRegistryRelease> {
        self.validate_for_finalization(identity)?;
        let repository = Repository::open(&self.directory)
            .with_context(|| format!("opening prepared registry {}", self.directory.display()))?;
        let head = repository.head()?;
        let head_ref = head
            .name()
            .context("prepared registry HEAD is not a named branch")?
            .to_string();
        drop(head);
        if repository
            .find_reference(&format!("refs/tags/{}", self.release))
            .is_ok()
        {
            bail!("prepared registry release tag already exists");
        }

        let mut index = repository
            .index()
            .context("opening prepared registry index")?;
        index.update_all(["*"], None)?;
        index.add_all(["*"], git2::IndexAddOption::DEFAULT, None)?;
        index.write()?;
        crate::registry_ops::validate_canonical_release_registry_index(&self.directory)
            .context("validating complete staged registry release")?;
        let tree_oid = index.write_tree()?;
        let tree = repository.find_tree(tree_oid)?;
        let parent = repository
            .revparse_single(&self.base_commit)
            .context("resolving prepared registry base commit")?
            .peel_to_commit()
            .context("reading prepared registry base commit")?;
        if parent.tree_id() == tree_oid {
            bail!("prepared registry finalization has no tree change");
        }
        let signature = identity.signature()?;
        let message = format!(
            "release {}\n\nAOS-Release-Plan: {}",
            self.release, self.plan_digest
        );
        let commit_buffer = repository
            .commit_create_buffer(&signature, &signature, &message, &tree, &[&parent])
            .context("building unsigned registry release commit")?;
        let commit_payload = commit_buffer.to_vec();
        let commit_response = request_signature(
            signer,
            self,
            RegistryGitObjectKind::Commit,
            commit_payload.clone(),
        )
        .await?;
        let commit_payload = std::str::from_utf8(&commit_payload)
            .context("registry commit payload is not valid UTF-8")?;
        let commit_oid = repository
            .commit_signed(
                commit_payload,
                &commit_response.armored_signature,
                Some("gpgsig-sha256"),
            )
            .context("writing signed registry release commit")?;

        let tag_payload =
            build_tag_payload(commit_oid, &self.release, &self.plan_digest, &signature);
        let tag_response = request_signature(
            signer,
            self,
            RegistryGitObjectKind::Tag,
            tag_payload.clone(),
        )
        .await?;
        let mut signed_tag = tag_payload;
        signed_tag.extend_from_slice(tag_response.armored_signature.as_bytes());
        let tag_oid = repository
            .odb()?
            .write(git2::ObjectType::Tag, &signed_tag)
            .context("writing signed registry release tag")?;

        require_head(&self.directory, &self.base_commit)?;
        let tag_ref = format!("refs/tags/{}", self.release);
        if repository.find_reference(&tag_ref).is_ok() {
            bail!("prepared registry release tag appeared during signing");
        }
        repository.reference(
            &tag_ref,
            tag_oid,
            false,
            "aos canonical registry release tag",
        )?;
        let mut branch = repository.find_reference(&head_ref)?;
        if branch.target().map(|target| target.to_string()).as_deref()
            != Some(self.base_commit.as_str())
        {
            bail!("prepared registry branch moved during signing");
        }
        branch.set_target(commit_oid, "aos canonical registry release commit")?;

        crate::registry_ops::refresh_registry_object_store(&self.directory)
            .context("generating finalized registry static surface")?;
        let static_surface = collect_static_surface(&self.directory)?;

        Ok(FinalizedRegistryRelease {
            registry: self.registry.clone(),
            release: self.release.clone(),
            plan_digest: self.plan_digest.clone(),
            commit: commit_oid.to_string(),
            tag_object: tag_oid.to_string(),
            signer_key_ids: vec![commit_response.key_id, tag_response.key_id],
            provider_operation_ids: vec![
                commit_response.provider_operation_id,
                tag_response.provider_operation_id,
            ],
            surfaces: self.surfaces.clone(),
            static_surface,
        })
    }

    fn validate_for_finalization(&self, identity: &RegistryCommitIdentity) -> Result<()> {
        if self.schema != PREPARED_SCHEMA {
            bail!("unsupported prepared registry release schema");
        }
        validate_registry_identity(&self.registry)?;
        require_git_oid(&self.base_commit)?;
        require_sha256(&self.plan_digest, "plan digest")?;
        semver::Version::parse(&self.release).context("invalid prepared release version")?;
        identity.validate()?;
        require_head(&self.directory, &self.base_commit)?;
        if registry_surface_digests(&self.directory)? != self.surfaces {
            bail!("prepared registry surfaces changed before finalization");
        }
        require_worktree_changes(&self.directory)
    }
}

impl RegistryCommitIdentity {
    fn validate(&self) -> Result<()> {
        if self.name.trim().is_empty()
            || self.name.contains(['\n', '\r', '<', '>'])
            || self.email.trim().is_empty()
            || self.email.contains(['\n', '\r', '<', '>'])
            || !self.email.contains('@')
        {
            bail!("invalid registry commit identity");
        }
        if !(-1439..=1439).contains(&self.offset_minutes) {
            bail!("registry commit timezone offset is out of range");
        }
        Ok(())
    }

    fn signature(&self) -> Result<git2::Signature<'static>> {
        self.validate()?;
        git2::Signature::new(
            &self.name,
            &self.email,
            &git2::Time::new(self.unix_seconds, self.offset_minutes),
        )
        .context("building frozen registry commit identity")
    }
}

async fn request_signature(
    signer: &mut dyn RegistryObjectSigner,
    prepared: &PreparedRegistryRelease,
    kind: RegistryGitObjectKind,
    payload: Vec<u8>,
) -> Result<RegistryGitSignature> {
    let payload_digest = sha256_bytes(&payload);
    let request = RegistryGitSigningRequest {
        registry: prepared.registry.clone(),
        release: prepared.release.clone(),
        plan_digest: prepared.plan_digest.clone(),
        kind,
        payload_digest: payload_digest.clone(),
        payload,
    };
    let response = signer.sign_git_object(request).await?;
    if response.kind != kind
        || response.payload_digest != payload_digest
        || response.key_id.is_empty()
        || response.provider_operation_id.is_empty()
        || !response
            .armored_signature
            .starts_with("-----BEGIN SSH SIGNATURE-----\n")
        || !response
            .armored_signature
            .ends_with("-----END SSH SIGNATURE-----\n")
    {
        bail!("registry signer returned an unbound or malformed response");
    }
    Ok(response)
}

fn build_tag_payload(
    commit: git2::Oid,
    release: &str,
    plan_digest: &str,
    signature: &git2::Signature<'_>,
) -> Vec<u8> {
    let offset = signature.when().offset_minutes();
    let sign = if offset < 0 { '-' } else { '+' };
    let offset = offset.abs();
    format!(
        "object {commit}\ntype commit\ntag {release}\ntagger {} <{}> {} {sign}{:02}{:02}\n\nAOS registry release {release}\nAOS-Release-Plan: {plan_digest}\n",
        signature.name().unwrap_or(""),
        signature.email().unwrap_or(""),
        signature.when().seconds(),
        offset / 60,
        offset % 60,
    )
    .into_bytes()
}

fn sha256_bytes(bytes: &[u8]) -> String {
    format!("sha256:{}", hex::encode(Sha256::digest(bytes)))
}

fn collect_static_surface(directory: &Path) -> Result<Vec<RegistryStaticSurfaceFile>> {
    crate::registry::static_upload::collect_static_origin_files(directory)?
        .into_iter()
        .map(|file| {
            let (byte_size, sha256) = sha256_file(&file.source)?;
            Ok(RegistryStaticSurfaceFile {
                path: file.relative_path,
                class: format!("{:?}", file.class).to_ascii_lowercase(),
                byte_size,
                sha256,
            })
        })
        .collect()
}

fn sha256_file(path: &Path) -> Result<(u64, String)> {
    let mut file =
        File::open(path).with_context(|| format!("opening static surface {}", path.display()))?;
    let expected_size = file.metadata()?.len();
    let mut size = 0_u64;
    let mut digest = Sha256::new();
    let mut buffer = [0_u8; 64 * 1024];
    loop {
        let count = file.read(&mut buffer)?;
        if count == 0 {
            break;
        }
        size = size
            .checked_add(count as u64)
            .context("static surface file size overflow")?;
        digest.update(&buffer[..count]);
    }
    if size != expected_size || file.metadata()?.len() != expected_size {
        bail!(
            "static surface file changed while hashing: {}",
            path.display()
        );
    }
    Ok((size, format!("sha256:{}", hex::encode(digest.finalize()))))
}

fn validate_source(source: &Path, base_commit: &str, release: &str) -> Result<()> {
    let repository = Repository::open(source)
        .with_context(|| format!("opening source registry {}", source.display()))?;
    require_clean(&repository)?;
    require_head(source, base_commit)?;
    if repository
        .find_reference(&format!("refs/tags/{release}"))
        .is_ok()
    {
        bail!("registry release tag '{release}' already exists");
    }
    Ok(())
}

fn require_clean(repository: &Repository) -> Result<()> {
    let mut options = StatusOptions::new();
    options
        .include_untracked(true)
        .recurse_untracked_dirs(true)
        .include_ignored(false);
    if !repository.statuses(Some(&mut options))?.is_empty() {
        bail!("source registry worktree is not clean");
    }
    Ok(())
}

fn require_head(directory: &Path, expected: &str) -> Result<()> {
    let repository = Repository::open(directory)
        .with_context(|| format!("opening registry {}", directory.display()))?;
    let actual = repository.head()?.peel_to_commit()?.id().to_string();
    if actual != expected {
        bail!("registry HEAD mismatch: expected {expected}, found {actual}");
    }
    Ok(())
}

fn require_worktree_changes(directory: &Path) -> Result<()> {
    let repository = Repository::open(directory)?;
    let mut options = StatusOptions::new();
    options
        .include_untracked(true)
        .recurse_untracked_dirs(true)
        .include_ignored(false);
    if repository.statuses(Some(&mut options))?.is_empty() {
        bail!("registry release transaction produced no changes");
    }
    Ok(())
}

fn validate_materialized_entries(directory: &Path, entries: &[RegistryReleaseEntry]) -> Result<()> {
    let platforms = entries
        .iter()
        .map(|entry| entry.platform.as_str())
        .collect::<BTreeSet<_>>();
    for platform in platforms {
        let (_, _, versions) = parse_registry_matching(directory, platform, None)
            .with_context(|| format!("validating prepared {platform} catalog"))?;
        for entry in entries.iter().filter(|entry| entry.platform == platform) {
            let found = versions.iter().any(|meta| {
                meta.name == entry.name
                    && meta.version == entry.version
                    && meta.platform == entry.platform
                    && meta.store_path == entry.store_path
            });
            if !found {
                bail!("prepared registry is missing exact entry '{}'", entry.id);
            }
        }
    }
    Ok(())
}

/// Verifies exact package coordinates and store paths in a registry tree.
///
/// # Errors
///
/// Returns an error when a platform catalog is invalid or an expected entry
/// is absent or bound to different bytes.
pub fn verify_release_entries(directory: &Path, entries: &[RegistryReleaseEntry]) -> Result<()> {
    validate_materialized_entries(directory, entries)
}

fn registry_surface_digests(directory: &Path) -> Result<RegistrySurfaceDigests> {
    Ok(RegistrySurfaceDigests {
        catalog: digest_roots(
            directory,
            "catalog",
            &[
                "packages",
                "docs",
                "provenance",
                "transparency",
                "containers",
            ],
        )?,
        store_graph: digest_roots(directory, "store-graph", &["store"])?,
        policy: digest_roots(
            directory,
            "policy",
            &["registry.toml", "keys.toml", "sb-certs.toml", "tuf"],
        )?,
    })
}

fn set_container_release(directory: &Path, bytes: Option<&[u8]>) -> Result<()> {
    let path = directory.join(CONTAINER_RELEASE_SIDECAR_PATH);
    let Some(parent) = container_release_parent(directory, bytes.is_some())? else {
        return Ok(());
    };
    if bytes.is_none() {
        match fs::symlink_metadata(&path) {
            Ok(metadata) if metadata.file_type().is_file() => {
                fs::remove_file(&path).with_context(|| {
                    format!("removing stale container sidecar {}", path.display())
                })?;
                File::open(parent)?.sync_all()?;
            }
            Ok(_) => bail!(
                "container sidecar destination is not a regular file: {}",
                path.display()
            ),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
            Err(error) => return Err(error.into()),
        }
        return Ok(());
    }
    let bytes = bytes.context("container sidecar bytes disappeared")?;
    if let Ok(metadata) = fs::symlink_metadata(&path) {
        if !metadata.file_type().is_file() {
            bail!(
                "container sidecar destination is not a regular file: {}",
                path.display()
            );
        }
    }
    let mut file = OpenOptions::new()
        .create(true)
        .truncate(true)
        .write(true)
        .open(&path)
        .with_context(|| format!("opening container sidecar {}", path.display()))?;
    file.write_all(bytes)?;
    file.sync_all()?;
    File::open(parent)?.sync_all()?;
    Ok(())
}

fn container_release_parent(directory: &Path, create: bool) -> Result<Option<PathBuf>> {
    let mut current = directory.to_path_buf();
    for component in ["containers", "v1"] {
        let parent = current.clone();
        current.push(component);
        match fs::symlink_metadata(&current) {
            Ok(metadata) if metadata.is_dir() => {}
            Ok(_) => bail!(
                "container sidecar parent is not a directory: {}",
                current.display()
            ),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound && !create => {
                return Ok(None);
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                fs::create_dir(&current).with_context(|| {
                    format!("creating container sidecar parent {}", current.display())
                })?;
                File::open(&parent)?.sync_all()?;
            }
            Err(error) => return Err(error.into()),
        }
    }
    Ok(Some(current))
}

fn digest_roots(directory: &Path, surface: &str, roots: &[&str]) -> Result<String> {
    let mut files = Vec::new();
    for root in roots {
        collect_files(directory, &directory.join(root), &mut files)?;
    }
    files.sort();

    let mut digest = Sha256::new();
    digest.update(DIGEST_DOMAIN);
    digest.update((surface.len() as u64).to_be_bytes());
    digest.update(surface.as_bytes());
    for path in files {
        let relative = path
            .strip_prefix(directory)
            .context("registry surface path escaped its root")?;
        let relative = relative
            .to_str()
            .context("registry surface path is not valid UTF-8")?;
        digest.update((relative.len() as u64).to_be_bytes());
        digest.update(relative.as_bytes());

        let mut file = File::open(&path)
            .with_context(|| format!("opening registry surface {}", path.display()))?;
        let size = file.metadata()?.len();
        digest.update(size.to_be_bytes());
        let mut buffer = [0_u8; 64 * 1024];
        loop {
            let count = file.read(&mut buffer)?;
            if count == 0 {
                break;
            }
            digest.update(&buffer[..count]);
        }
    }
    Ok(format!("sha256:{}", hex::encode(digest.finalize())))
}

fn collect_files(root: &Path, path: &Path, files: &mut Vec<PathBuf>) -> Result<()> {
    let metadata = match fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(error) => return Err(error.into()),
    };
    if metadata.file_type().is_symlink() {
        bail!("registry surface contains symlink: {}", path.display());
    }
    if metadata.is_file() {
        require_single_link(&metadata, path)?;
        files.push(path.to_path_buf());
        return Ok(());
    }
    if !metadata.is_dir() {
        bail!("registry surface contains special file: {}", path.display());
    }

    let mut children = fs::read_dir(path)?
        .map(|entry| entry.map(|entry| entry.path()))
        .collect::<std::io::Result<Vec<_>>>()?;
    children.sort();
    for child in children {
        if !child.starts_with(root) {
            bail!("registry surface path escaped its root");
        }
        collect_files(root, &child, files)?;
    }
    Ok(())
}

#[cfg(unix)]
fn require_single_link(metadata: &fs::Metadata, path: &Path) -> Result<()> {
    use std::os::unix::fs::MetadataExt as _;

    if metadata.nlink() != 1 {
        bail!(
            "registry surface file has multiple hard links: {}",
            path.display()
        );
    }
    Ok(())
}

#[cfg(not(unix))]
fn require_single_link(_metadata: &fs::Metadata, _path: &Path) -> Result<()> {
    Ok(())
}

fn require_sha256(value: &str, label: &str) -> Result<()> {
    let Some(hex) = value.strip_prefix("sha256:") else {
        bail!("{label} must use sha256:<lowercase-hex>");
    };
    if hex.len() != 64 || !hex.bytes().all(is_lower_hex) {
        bail!("{label} must use sha256:<lowercase-hex>");
    }
    Ok(())
}

fn validate_registry_identity(value: &str) -> Result<()> {
    let Some((scope, name)) = value.split_once('/') else {
        bail!("registry identity must be SCOPE/NAME");
    };
    if name.contains('/') {
        bail!("registry identity must contain exactly one slash");
    }
    validate_registry_name(scope).context("validating registry scope")?;
    validate_registry_name(name).context("validating registry name")?;
    Ok(())
}

fn require_git_oid(value: &str) -> Result<()> {
    if value.len() != 64 || !value.bytes().all(is_lower_hex) {
        bail!("canonical registry base commit must be a lowercase SHA-256 Git oid");
    }
    Ok(())
}

const fn is_lower_hex(byte: u8) -> bool {
    byte.is_ascii_digit() || (byte >= b'a' && byte <= b'f')
}

const fn is_identifier_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b':' | b'/' | b'@' | b'-')
}

struct AuthoringLock {
    path: PathBuf,
}

impl AuthoringLock {
    fn acquire(source_registry: &Path) -> Result<Self> {
        let repository = Repository::open(source_registry)?;
        let path = repository.path().join("aos-release-authoring.lock");
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&path)
            .with_context(|| {
                format!(
                    "acquiring {}; another canonical release author may be active",
                    path.display()
                )
            })?;
        writeln!(file, "pid={}", std::process::id())?;
        Ok(Self { path })
    }
}

impl Drop for AuthoringLock {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.path);
    }
}

#[cfg(test)]
mod tests {
    use anyhow::anyhow;
    use git2::{IndexAddOption, Signature};

    use super::*;

    struct FailsAfterFirstEntry {
        calls: usize,
    }

    struct WritesPackageEntry;

    #[derive(Default)]
    struct MockRegistrySigner {
        requests: Vec<RegistryGitSigningRequest>,
    }

    #[async_trait]
    impl RegistryEntryAuthor for FailsAfterFirstEntry {
        async fn author_entry(
            &mut self,
            isolated_registry: &Path,
            _entry: &RegistryReleaseEntry,
        ) -> Result<()> {
            self.calls += 1;
            fs::write(isolated_registry.join("partial"), b"not publishable")?;
            if self.calls == 2 {
                return Err(anyhow!("injected author failure"));
            }
            Ok(())
        }
    }

    #[async_trait]
    impl RegistryEntryAuthor for WritesPackageEntry {
        async fn author_entry(
            &mut self,
            isolated_registry: &Path,
            entry: &RegistryReleaseEntry,
        ) -> Result<()> {
            let directory = isolated_registry.join("packages").join(&entry.name[..1]);
            fs::create_dir_all(&directory)?;
            let content = format!(
                "[package]\nname = \"{}\"\ndescription = \"test package\"\nlicense = \"MIT\"\nmaintainer = \"AOS test\"\n\n[[versions]]\nversion = \"{}\"\n\n[versions.platforms.{}]\nstore_path = \"{}\"\nclosure_size = 1\nsource_drv = \"\"\nsource_nar_hash = \"\"\n",
                entry.name, entry.version, entry.platform, entry.store_path
            );
            fs::write(directory.join(format!("{}.toml", entry.name)), content)?;
            Ok(())
        }
    }

    #[async_trait]
    impl RegistryObjectSigner for MockRegistrySigner {
        async fn sign_git_object(
            &mut self,
            request: RegistryGitSigningRequest,
        ) -> Result<RegistryGitSignature> {
            let response = RegistryGitSignature {
                kind: request.kind,
                payload_digest: request.payload_digest.clone(),
                key_id: "registry-test-key".to_string(),
                provider_operation_id: format!("mock-operation-{}", self.requests.len() + 1),
                armored_signature:
                    "-----BEGIN SSH SIGNATURE-----\ndGVzdA==\n-----END SSH SIGNATURE-----\n"
                        .to_string(),
            };
            self.requests.push(request);
            Ok(response)
        }
    }

    fn transaction(base_commit: String) -> RegistryReleaseTransaction {
        let entry = |id: &str, name: &str| RegistryReleaseEntry {
            id: id.to_string(),
            name: name.to_string(),
            version: "1.0.0".to_string(),
            platform: "x86_64-linux".to_string(),
            store_path: format!("/nix/store/00000000000000000000000000000000-{name}-1.0.0"),
        };
        let empty_digest = format!("sha256:{}", "0".repeat(64));
        RegistryReleaseTransaction {
            schema: TRANSACTION_SCHEMA.to_string(),
            registry: "andyl/main".to_string(),
            base_commit,
            release: "2026.1.0".to_string(),
            plan_digest: empty_digest.clone(),
            entries: vec![
                entry("alpha@x86_64-linux", "alpha"),
                entry("beta@x86_64-linux", "beta"),
            ],
            expected: RegistrySurfaceDigests {
                catalog: empty_digest.clone(),
                store_graph: empty_digest.clone(),
                policy: empty_digest,
            },
            support: None,
        }
    }

    fn initialize_registry(path: &Path) -> Result<String> {
        let mut options = git2::RepositoryInitOptions::new();
        options
            .object_format(git2::ObjectFormat::Sha256)
            .initial_head("master");
        let repository = Repository::init_opts(path, &options)?;
        fs::write(
            path.join("registry.toml"),
            b"[registry]\nname = \"andyl/main\"\n",
        )?;
        let mut index = repository.index()?;
        index.add_all(["registry.toml"], IndexAddOption::DEFAULT, None)?;
        index.write()?;
        let tree_id = index.write_tree()?;
        let tree = repository.find_tree(tree_id)?;
        let signature = Signature::now("AOS test", "test@example.invalid")?;
        let commit = repository.commit(
            Some("HEAD"),
            &signature,
            &signature,
            "initial registry",
            &tree,
            &[],
        )?;
        Ok(commit.to_string())
    }

    #[tokio::test]
    async fn partial_failure_never_touches_source_or_exposes_output() -> Result<()> {
        let temporary = tempfile::tempdir()?;
        let source = temporary.path().join("source");
        fs::create_dir(&source)?;
        let base = initialize_registry(&source)?;
        let output = temporary.path().join("prepared");
        let mut author = FailsAfterFirstEntry { calls: 0 };

        let error = transaction(base.clone())
            .prepare(&source, &output, &mut author)
            .await
            .expect_err("second entry must fail");

        assert!(format!("{error:#}").contains("injected author failure"));
        assert_eq!(author.calls, 2);
        assert!(!source.join("partial").exists());
        assert!(!output.exists());
        require_head(&source, &base)?;
        require_clean(&Repository::open(&source)?)?;
        Ok(())
    }

    #[tokio::test]
    async fn support_tables_are_applied_before_the_policy_surface_is_digested() -> Result<()> {
        let temporary = tempfile::tempdir()?;
        let source = temporary.path().join("source");
        fs::create_dir(&source)?;
        let base = initialize_registry(&source)?;
        let mut transaction = transaction(base.clone());
        let support = super::super::support::SupportSectionWrite {
            train: "2026.1".to_string(),
            entry: aos_registry_surface::support::SupportTrain {
                kind: aos_registry_surface::support::SupportKind::Lts,
                supported_until: Some("2028-01-31".to_string()),
            },
            default: Some(aos_registry_surface::support::SupportDefault::default()),
        };
        transaction.support = Some(support.clone());

        // An operator computes the expected digests over the intended result,
        // which includes the support tables the release owns.
        let expected_clone = temporary.path().join("expected");
        Repository::clone(
            source.to_str().context("test path encoding")?,
            &expected_clone,
        )?;
        let mut expected_author = WritesPackageEntry;
        for entry in &transaction.entries {
            expected_author.author_entry(&expected_clone, entry).await?;
        }
        super::super::support::apply_support_section(&expected_clone, &support)?;
        transaction.expected = registry_surface_digests(&expected_clone)?;
        fs::remove_dir_all(&expected_clone)?;

        let output = temporary.path().join("prepared");
        transaction
            .prepare(&source, &output, &mut WritesPackageEntry)
            .await?;
        let config: aos_registry_surface::manifest::RegistryRootConfig =
            toml::from_str(&fs::read_to_string(output.join("registry.toml"))?)?;
        let policy = config
            .support
            .context("prepared tree carries the support policy")?;
        assert_eq!(
            policy.kind((2026, 1)),
            aos_registry_surface::support::SupportKind::Lts
        );

        // A transaction whose digests omit the tables fails closed.
        let stale = temporary.path().join("stale");
        let mut without = transaction.clone();
        without.support = None;
        let error = without
            .prepare(&source, &stale, &mut WritesPackageEntry)
            .await
            .expect_err("policy digest must include the support tables");
        assert!(format!("{error:#}").contains("surface digests do not match"));
        Ok(())
    }

    #[tokio::test]
    async fn complete_transaction_exposes_one_valid_isolated_tree() -> Result<()> {
        let temporary = tempfile::tempdir()?;
        let source = temporary.path().join("source");
        fs::create_dir(&source)?;
        let base = initialize_registry(&source)?;
        let mut transaction = transaction(base.clone());

        let expected_clone = temporary.path().join("expected");
        Repository::clone(
            source.to_str().context("test path encoding")?,
            &expected_clone,
        )?;
        let mut expected_author = WritesPackageEntry;
        for entry in &transaction.entries {
            expected_author.author_entry(&expected_clone, entry).await?;
        }
        transaction.expected = registry_surface_digests(&expected_clone)?;
        fs::remove_dir_all(&expected_clone)?;

        let output = temporary.path().join("prepared");
        let report = transaction
            .prepare(&source, &output, &mut WritesPackageEntry)
            .await?;

        assert_eq!(report.entry_count, 2);
        assert_eq!(report.directory, output);
        assert_eq!(report.surfaces, transaction.expected);
        require_head(&report.directory, &base)?;
        require_worktree_changes(&report.directory)?;
        validate_materialized_entries(&report.directory, &transaction.entries)?;
        require_clean(&Repository::open(&source)?)?;
        Ok(())
    }

    #[tokio::test]
    async fn container_sidecar_is_bound_into_the_reviewed_catalog_surface() -> Result<()> {
        let temporary = tempfile::tempdir()?;
        let source = temporary.path().join("source");
        fs::create_dir(&source)?;
        let base = initialize_registry(&source)?;
        let mut transaction = transaction(base);
        let sidecar = br#"{"schemaVersion":1}"#;

        let expected_clone = temporary.path().join("expected");
        Repository::clone(
            source.to_str().context("test path encoding")?,
            &expected_clone,
        )?;
        let mut expected_author = WritesPackageEntry;
        for entry in &transaction.entries {
            expected_author.author_entry(&expected_clone, entry).await?;
        }
        let without_sidecar = registry_surface_digests(&expected_clone)?.catalog;
        set_container_release(&expected_clone, Some(sidecar))?;
        transaction.expected = registry_surface_digests(&expected_clone)?;
        assert_ne!(transaction.expected.catalog, without_sidecar);
        fs::remove_dir_all(&expected_clone)?;

        let output = temporary.path().join("prepared");
        transaction
            .prepare_with_container_release(
                &source,
                &output,
                &mut WritesPackageEntry,
                Some(sidecar),
            )
            .await?;

        assert_eq!(
            fs::read(output.join(CONTAINER_RELEASE_SIDECAR_PATH))?,
            sidecar
        );
        Ok(())
    }

    #[test]
    fn release_without_container_removes_the_fixed_prior_sidecar() -> Result<()> {
        let temporary = tempfile::tempdir()?;
        let path = temporary.path().join(CONTAINER_RELEASE_SIDECAR_PATH);
        fs::create_dir_all(path.parent().context("sidecar parent")?)?;
        fs::write(&path, b"prior release")?;

        set_container_release(temporary.path(), None)?;

        assert!(!path.exists());
        Ok(())
    }

    #[cfg(unix)]
    #[test]
    fn release_without_container_refuses_a_symlinked_parent() -> Result<()> {
        let temporary = tempfile::tempdir()?;
        let outside = tempfile::tempdir()?;
        let outside_sidecar = outside.path().join("v1/index.json");
        fs::create_dir_all(outside_sidecar.parent().context("outside parent")?)?;
        fs::write(&outside_sidecar, b"outside release")?;
        std::os::unix::fs::symlink(outside.path(), temporary.path().join("containers"))?;

        assert!(set_container_release(temporary.path(), None).is_err());
        assert_eq!(fs::read(outside_sidecar)?, b"outside release");
        Ok(())
    }

    #[tokio::test]
    async fn finalization_creates_one_commit_and_one_tag_without_upload_or_channel() -> Result<()> {
        let temporary = tempfile::tempdir()?;
        let source = temporary.path().join("source");
        fs::create_dir(&source)?;
        let base = initialize_registry(&source)?;
        let mut transaction = transaction(base.clone());

        let expected_clone = temporary.path().join("expected");
        Repository::clone(
            source.to_str().context("test path encoding")?,
            &expected_clone,
        )?;
        let mut expected_author = WritesPackageEntry;
        for entry in &transaction.entries {
            expected_author.author_entry(&expected_clone, entry).await?;
        }
        transaction.expected = registry_surface_digests(&expected_clone)?;
        fs::remove_dir_all(&expected_clone)?;

        let output = temporary.path().join("prepared");
        let prepared = transaction
            .prepare(&source, &output, &mut WritesPackageEntry)
            .await?;
        let identity = RegistryCommitIdentity {
            name: "AOS release test".to_string(),
            email: "release@example.invalid".to_string(),
            unix_seconds: 1_700_000_000,
            offset_minutes: 0,
        };
        let mut signer = MockRegistrySigner::default();

        let finalized = prepared.finalize(&identity, &mut signer).await?;

        assert_eq!(signer.requests.len(), 2);
        assert_eq!(signer.requests[0].kind, RegistryGitObjectKind::Commit);
        assert_eq!(signer.requests[1].kind, RegistryGitObjectKind::Tag);
        let repository = Repository::open(&output)?;
        let head = repository.head()?.peel_to_commit()?;
        assert_eq!(head.id().to_string(), finalized.commit);
        assert_eq!(head.parent_count(), 1);
        assert_eq!(head.parent_id(0)?.to_string(), base);
        let tag = repository
            .find_reference("refs/tags/2026.1.0")?
            .peel(git2::ObjectType::Tag)?;
        assert_eq!(tag.id().to_string(), finalized.tag_object);
        assert!(repository.find_reference("refs/heads/stable").is_err());
        Ok(())
    }

    #[test]
    fn duplicate_coordinates_fail_before_authoring() {
        let mut transaction = transaction("0".repeat(64));
        transaction.entries[1].name = transaction.entries[0].name.clone();
        transaction.entries[1].id = "different-id".to_string();

        let error = transaction.validate().expect_err("duplicate coordinate");
        assert!(format!("{error:#}").contains("duplicate registry release coordinate"));
    }
}
