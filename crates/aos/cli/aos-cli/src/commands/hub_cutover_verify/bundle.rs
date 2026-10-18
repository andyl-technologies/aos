//! Closed bundle I/O, trust-chain authentication, and generation stages.

use std::cell::RefCell;
use std::collections::{BTreeMap, BTreeSet};
use std::ffi::OsString;
use std::fs::File;
use std::io::{Read as _, Seek as _, SeekFrom, Write as _};
use std::os::fd::{AsRawFd as _, OwnedFd};
use std::path::{Component, Path};

use anyhow::{Context as _, Result, anyhow, bail};
use base64::Engine as _;
use ed25519_dalek::{Signer as _, SigningKey, VerifyingKey};
use rustix::fs::{AtFlags, Dir, Mode, OFlags, linkat, open, openat, unlinkat};
use serde_json::Value;

use crate::cli::{
    HubTopologyCutoverGenerateArgs, HubTopologyCutoverMaterializeVerifierArgs,
    HubTopologyCutoverVerifyArgs,
};

use super::canonical::{
    canonical_json, hex, parse_json, parse_public_key, parse_sha256, parse_signing_key,
    reject_placeholder_hashes, separated_digest, sha256, verify_detached,
};
use super::fixtures::validate_fixtures;
use super::schema::validate_schema;
use super::semantics::{compare_instants, scan_sensitive_contract, validate_canonical_arrays};
use super::{
    BUNDLE_DOMAIN, BundleDocuments, BundleEntry, BundleManifest, BundleManifestEnvelope,
    CutoverErrorCode, DIALECT_NAME, DOCUMENT_DOMAIN, GenerationLayout, GenerationRecipe,
    KEY_MAP_DOMAIN, MachineResult, RunningExecutable, SignatureEnvelope, SignerKeyMap,
    VerifiedInputs, classify_error, typed_error,
};

const MAX_CAPTURE_DEPTH: usize = 32;
const MAX_CAPTURE_ENTRIES: usize = 16_384;
const MAX_CAPTURE_FILE_BYTES: u64 = 256 * 1024 * 1024;
const MAX_CAPTURE_TOTAL_BYTES: u64 = 512 * 1024 * 1024;
const MAX_EXTERNAL_INPUT_BYTES: u64 = 16 * 1024 * 1024;

#[cfg(unix)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
struct InodeIdentity {
    device: u64,
    inode: u64,
}

struct PinnedRoot {
    handle: OwnedFd,
    namespace_parent: OwnedFd,
    namespace_name: OsString,
    namespace: Vec<PinnedNamespaceStep>,
    identity: InodeIdentity,
    ancestors: Vec<InodeIdentity>,
    label: String,
}

#[cfg(unix)]
type StableFileIdentity = (u64, u64, u64, i64, i64);

struct PinnedDirectory {
    handle: OwnedFd,
    identity: InodeIdentity,
    parent: Option<String>,
    name: Option<OsString>,
}

struct PinnedLeaf {
    handle: File,
    identity: StableFileIdentity,
    bytes: Vec<u8>,
    parent: String,
    name: OsString,
}

#[derive(Clone, Copy, Default)]
struct CaptureBudget {
    entries: usize,
    bytes: u64,
}

impl CaptureBudget {
    fn charge_entry(&mut self) -> Result<()> {
        self.entries = self
            .entries
            .checked_add(1)
            .ok_or_else(|| anyhow!("captured tree entry count overflow"))?;
        if self.entries > MAX_CAPTURE_ENTRIES {
            bail!("captured tree exceeds maximum entry count of {MAX_CAPTURE_ENTRIES}");
        }
        Ok(())
    }

    fn charge_file(&mut self, size: u64) -> Result<()> {
        if size > MAX_CAPTURE_FILE_BYTES {
            bail!("captured file exceeds maximum size of {MAX_CAPTURE_FILE_BYTES} bytes");
        }
        self.charge_entry()?;
        self.bytes = self
            .bytes
            .checked_add(size)
            .ok_or_else(|| anyhow!("captured tree byte count overflow"))?;
        if self.bytes > MAX_CAPTURE_TOTAL_BYTES {
            bail!("captured tree exceeds maximum total size of {MAX_CAPTURE_TOTAL_BYTES} bytes");
        }
        Ok(())
    }

    fn with_file(mut self, size: u64) -> Result<Self> {
        self.charge_file(size)?;
        Ok(self)
    }
}

struct PinnedNamespaceStep {
    parent: OwnedFd,
    name: OsString,
    identity: InodeIdentity,
}

struct PinnedExternalOutput {
    parent: OwnedFd,
    name: OsString,
    namespace: Vec<PinnedNamespaceStep>,
    published: RefCell<Option<FreshPublication>>,
}

struct FreshPublication {
    handle: File,
    identity: InodeIdentity,
}

/// A directory tree captured through one no-follow descriptor traversal.
///
/// Every directory and regular-file descriptor stays open for the command
/// lifetime. Reads use the captured file descriptor, and publications use the
/// captured parent descriptor. [`PreopenedTree::assert_unchanged`] proves that
/// the namespace still names the same captured objects before trust decisions
/// or externally visible publication.
struct PreopenedTree {
    root: PinnedRoot,
    directories: BTreeMap<String, PinnedDirectory>,
    files: BTreeMap<String, PinnedLeaf>,
    budget: CaptureBudget,
    owned_outputs: BTreeSet<String>,
}

impl PreopenedTree {
    fn open(path: &Path, label: &str, identities: &mut IdentitySet) -> Result<Self> {
        let root = PinnedRoot::open(path, label)?;
        let mut directories = BTreeMap::new();
        let mut files = BTreeMap::new();
        let mut budget = CaptureBudget::default();
        Self::capture_directory(
            root.handle.try_clone()?,
            "".to_owned(),
            None,
            None,
            label,
            identities,
            &mut directories,
            &mut files,
            &mut budget,
            0,
        )?;
        Ok(Self {
            root,
            directories,
            files,
            budget,
            owned_outputs: BTreeSet::new(),
        })
    }

    #[allow(clippy::too_many_arguments)]
    fn capture_directory(
        handle: OwnedFd,
        relative: String,
        parent: Option<String>,
        name: Option<OsString>,
        root_label: &str,
        identities: &mut IdentitySet,
        directories: &mut BTreeMap<String, PinnedDirectory>,
        files: &mut BTreeMap<String, PinnedLeaf>,
        budget: &mut CaptureBudget,
        depth: usize,
    ) -> Result<()> {
        if depth > MAX_CAPTURE_DEPTH {
            bail!("captured tree exceeds maximum depth of {MAX_CAPTURE_DEPTH}: {relative}");
        }
        budget.charge_entry()?;
        let metadata = File::from(handle.try_clone()?).metadata()?;
        if !metadata.is_dir() {
            bail!("captured tree member is not a directory: {relative}");
        }
        let identity = inode_identity(&metadata);
        let mut children = Vec::new();
        for entry in Dir::read_from(&handle)? {
            let entry = entry?;
            let name = entry
                .file_name()
                .to_str()
                .map_err(|_| anyhow!("tree path is not UTF-8"))?
                .to_owned();
            if name == "." || name == ".." {
                continue;
            }
            if children.len() >= MAX_CAPTURE_ENTRIES {
                bail!("captured directory exceeds maximum entry count of {MAX_CAPTURE_ENTRIES}");
            }
            children.push(name);
        }
        children.sort();
        for child in children {
            let child_handle = openat(
                &handle,
                child.as_str(),
                OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
                Mode::empty(),
            )
            .with_context(|| format!("opening captured tree member {child}"))?;
            let child_file = File::from(child_handle.try_clone()?);
            let child_metadata = child_file.metadata()?;
            let child_relative = if relative.is_empty() {
                child.clone()
            } else {
                format!("{relative}/{child}")
            };
            if child_metadata.is_dir() {
                Self::capture_directory(
                    child_handle,
                    child_relative,
                    Some(relative.clone()),
                    Some(OsString::from(child)),
                    root_label,
                    identities,
                    directories,
                    files,
                    budget,
                    depth + 1,
                )?;
            } else if child_metadata.is_file() {
                let file_size = child_metadata.len();
                if file_size > MAX_CAPTURE_FILE_BYTES {
                    bail!(
                        "captured file exceeds maximum size of {MAX_CAPTURE_FILE_BYTES} bytes: {child_relative}"
                    );
                }
                budget.charge_file(file_size)?;
                identities.insert_file(&child_file, &format!("{root_label}:{child_relative}"))?;
                let mut file = File::from(child_handle);
                let before = file_identity(&file)?;
                let bytes = read_bounded(
                    &mut file,
                    file_size,
                    MAX_CAPTURE_FILE_BYTES,
                    &child_relative,
                )?;
                if file_identity(&file)? != before {
                    bail!("captured file changed while reading: {child_relative}");
                }
                files.insert(
                    child_relative,
                    PinnedLeaf {
                        handle: file,
                        identity: before,
                        bytes,
                        parent: relative.clone(),
                        name: OsString::from(child),
                    },
                );
            } else {
                bail!("tree contains a symlink or special file: {child_relative}");
            }
        }
        directories.insert(
            relative,
            PinnedDirectory {
                handle,
                identity,
                parent,
                name,
            },
        );
        Ok(())
    }

    fn read(&self, relative: &str) -> Result<Vec<u8>> {
        validate_relative_path(relative)?;
        let leaf = self
            .files
            .get(relative)
            .ok_or_else(|| anyhow!("captured tree file absent: {relative}"))?;
        require_single_link(&leaf.handle, relative)?;
        if file_identity(&leaf.handle)? != leaf.identity {
            bail!("captured file identity changed: {relative}");
        }
        Ok(leaf.bytes.clone())
    }

    fn paths(&self) -> BTreeSet<String> {
        self.files.keys().cloned().collect()
    }

    fn publish(
        &mut self,
        relative: &str,
        bytes: &[u8],
        mode: Mode,
        identities: &mut IdentitySet,
    ) -> Result<()> {
        validate_relative_path(relative)?;
        if self.files.contains_key(relative) {
            return Err(typed_error(
                CutoverErrorCode::OutputAlreadyExists,
                anyhow!("bundle output already exists: {relative}"),
            ));
        }
        let next_budget = self.budget.with_file(bytes.len() as u64)?;
        let path = Path::new(relative);
        let parent = path.parent().and_then(Path::to_str).unwrap_or("");
        let name = path
            .file_name()
            .ok_or_else(|| anyhow!("bundle output has no filename: {relative}"))?
            .to_owned();
        let directory = self
            .directories
            .get(parent)
            .ok_or_else(|| anyhow!("captured output parent is absent: {parent}"))?;
        let mut publication = atomic_publish_fresh(&directory.handle, &name, bytes, relative, mode)
            .map_err(|error| classify_error(error, CutoverErrorCode::FilesystemBoundaryInvalid))?;
        let verified = (|| -> Result<(StableFileIdentity, Vec<u8>)> {
            assert_owned_name(
                &directory.handle,
                &name,
                &publication.handle,
                publication.identity,
                1,
                relative,
            )?;
            let file = &mut publication.handle;
            identities.insert_file(file, &format!("{}:{relative}", self.root.label))?;
            let identity = file_identity(file)?;
            file.seek(SeekFrom::Start(0))?;
            let observed =
                read_bounded(file, bytes.len() as u64, MAX_CAPTURE_FILE_BYTES, relative)?;
            if observed != bytes || file_identity(file)? != identity {
                bail!("published bundle output identity mismatch: {relative}");
            }
            Ok((identity, observed))
        })();
        let (identity, observed) = match verified {
            Ok(verified) => verified,
            Err(error) => {
                let error = classify_error(error, CutoverErrorCode::FilesystemBoundaryInvalid);
                return match remove_owned_name(
                    &directory.handle,
                    &name,
                    &publication.handle,
                    publication.identity,
                    1,
                    relative,
                ) {
                    Ok(()) => Err(error),
                    Err(cleanup) => Err(error.context(format!(
                        "failed to remove rejected fresh output: {cleanup:#}"
                    ))),
                };
            }
        };
        let file = publication.handle;
        self.files.insert(
            relative.to_owned(),
            PinnedLeaf {
                handle: file,
                identity,
                bytes: observed,
                parent: parent.to_owned(),
                name,
            },
        );
        self.budget = next_budget;
        self.owned_outputs.insert(relative.to_owned());
        Ok(())
    }

    fn rollback_outputs(&mut self) -> Result<()> {
        let outputs: Vec<_> = self.owned_outputs.iter().cloned().collect();
        let mut failures = Vec::new();
        for relative in outputs.iter().rev() {
            let Some(leaf) = self.files.get(relative) else {
                failures.push(format!("owned output disappeared from capture: {relative}"));
                continue;
            };
            let Some(parent) = self.directories.get(&leaf.parent) else {
                failures.push(format!("owned output parent disappeared: {relative}"));
                continue;
            };
            let identity = inode_identity(&leaf.handle.metadata()?);
            match remove_owned_name(
                &parent.handle,
                &leaf.name,
                &leaf.handle,
                identity,
                1,
                relative,
            ) {
                Ok(()) => {
                    self.files.remove(relative);
                    self.owned_outputs.remove(relative);
                }
                Err(error) => failures.push(format!("{relative}: {error:#}")),
            }
        }
        if failures.is_empty() {
            Ok(())
        } else {
            bail!("generated-output rollback failed: {}", failures.join("; "))
        }
    }

    fn commit_outputs(&mut self) {
        self.owned_outputs.clear();
    }

    fn assert_unchanged(&self) -> Result<()> {
        assert_namespace_steps(&self.root.namespace, &self.root.label)?;
        let reopened_root = openat(
            &self.root.namespace_parent,
            &self.root.namespace_name,
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
        )?;
        if inode_identity(&File::from(reopened_root).metadata()?) != self.root.identity {
            bail!("captured root namespace identity changed");
        }
        for (relative, directory) in &self.directories {
            let mut observed = BTreeSet::new();
            for entry in Dir::read_from(&directory.handle)? {
                let entry = entry?;
                let name = entry
                    .file_name()
                    .to_str()
                    .map_err(|_| anyhow!("tree path is not UTF-8"))?;
                if name == "." || name == ".." {
                    continue;
                }
                if observed.len() >= MAX_CAPTURE_ENTRIES {
                    bail!(
                        "captured directory exceeds maximum entry count of {MAX_CAPTURE_ENTRIES}"
                    );
                }
                observed.insert(name.to_owned());
            }
            let expected: BTreeSet<_> = self
                .directories
                .values()
                .filter(|child| child.parent.as_deref() == Some(relative.as_str()))
                .filter_map(|child| child.name.as_ref())
                .chain(
                    self.files
                        .values()
                        .filter(|child| child.parent == *relative)
                        .map(|child| &child.name),
                )
                .map(|name| name.to_string_lossy().into_owned())
                .collect();
            if observed != expected {
                bail!("captured directory membership changed: {relative}");
            }
        }
        for (relative, directory) in &self.directories {
            let (Some(parent), Some(name)) = (&directory.parent, &directory.name) else {
                continue;
            };
            let parent = self
                .directories
                .get(parent)
                .ok_or_else(|| anyhow!("captured directory parent is absent: {relative}"))?;
            let reopened = openat(
                &parent.handle,
                name,
                OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
                Mode::empty(),
            )?;
            let metadata = File::from(reopened).metadata()?;
            if inode_identity(&metadata) != directory.identity {
                bail!("captured directory identity changed: {relative}");
            }
        }
        for (relative, leaf) in &self.files {
            require_single_link(&leaf.handle, relative)?;
            if file_identity(&leaf.handle)? != leaf.identity {
                bail!("captured file identity changed: {relative}");
            }
            let parent = self
                .directories
                .get(&leaf.parent)
                .ok_or_else(|| anyhow!("captured file parent is absent: {relative}"))?;
            let reopened = openat(
                &parent.handle,
                &leaf.name,
                OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
                Mode::empty(),
            )?;
            let mut reopened = File::from(reopened);
            require_single_link(&reopened, relative)?;
            if file_identity(&reopened)? != leaf.identity {
                bail!("captured namespace leaf identity changed: {relative}");
            }
            let observed = read_bounded(
                &mut reopened,
                leaf.bytes.len() as u64,
                MAX_CAPTURE_FILE_BYTES,
                relative,
            )?;
            if observed != leaf.bytes || file_identity(&reopened)? != leaf.identity {
                bail!("captured file bytes changed: {relative}");
            }
        }
        Ok(())
    }
}

impl PinnedRoot {
    fn open(path: &Path, label: &str) -> Result<Self> {
        let (handle, namespace_parent, namespace_name, ancestors, namespace) =
            open_absolute_directory_pinned(path, label).map_err(|error| {
                if error.downcast_ref::<super::CutoverError>().is_some() {
                    error
                } else {
                    typed_error(CutoverErrorCode::FilesystemBoundaryInvalid, error)
                }
            })?;
        let metadata = File::from(handle.try_clone()?).metadata()?;
        if !metadata.is_dir() {
            return Err(typed_error(
                CutoverErrorCode::FilesystemBoundaryInvalid,
                anyhow!("{label} is not a directory"),
            ));
        }
        Ok(Self {
            identity: inode_identity(&metadata),
            handle,
            namespace_parent,
            namespace_name,
            namespace,
            ancestors,
            label: label.to_owned(),
        })
    }
}

#[derive(Default)]
struct IdentitySet {
    files: BTreeMap<InodeIdentity, String>,
}

impl IdentitySet {
    fn insert_file(&mut self, file: &File, label: &str) -> Result<()> {
        let metadata = file.metadata()?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt as _;
            if metadata.nlink() != 1 {
                return Err(typed_error(
                    CutoverErrorCode::InputIdentityAliased,
                    anyhow!(
                        "{label} has link count {}; exactly one is required",
                        metadata.nlink()
                    ),
                ));
            }
        }
        let identity = inode_identity(&metadata);
        if let Some(first) = self.files.get(&identity) {
            if first == label {
                return Ok(());
            }
            return Err(typed_error(
                CutoverErrorCode::InputIdentityAliased,
                anyhow!("{label} aliases {first}"),
            ));
        }
        self.files.insert(identity, label.to_owned());
        Ok(())
    }
}

/// Verifies one closed bundle through all authentication and validation stages.
pub(super) fn verify(
    args: &HubTopologyCutoverVerifyArgs,
    executable: &RunningExecutable,
) -> Result<MachineResult> {
    verify_inner(args, executable)
        .map_err(|error| classify_error(error, CutoverErrorCode::InputInvalid))
}

fn verify_inner(
    args: &HubTopologyCutoverVerifyArgs,
    executable: &RunningExecutable,
) -> Result<MachineResult> {
    let mut identities = IdentitySet::default();
    let bundle = PreopenedTree::open(&args.bundle, "bundle root", &mut identities)?;
    let manifest_bytes = read_external_pinned(
        &args.bundle_manifest,
        "bundle manifest",
        &[bundle.root.identity],
        &mut identities,
    )?;
    let root_key_bytes = read_external_pinned(
        &args.trusted_root_public_key,
        "trusted root public key",
        &[bundle.root.identity],
        &mut identities,
    )?;
    let manifest_value = parse_json(&manifest_bytes, "bundle manifest envelope")
        .map_err(|error| classify_error(error, CutoverErrorCode::InputInvalid))?;
    let manifest_envelope: BundleManifestEnvelope = serde_json::from_value(manifest_value.clone())
        .context("invalid closed bundle manifest envelope")
        .map_err(|error| classify_error(error, CutoverErrorCode::InputInvalid))?;
    validate_manifest_envelope_classifiers(&manifest_envelope)
        .map_err(|error| classify_error(error, CutoverErrorCode::InputInvalid))?;
    let bundle_files = load_closed_bundle(&bundle, &manifest_envelope.payload)
        .map_err(|error| classify_error(error, CutoverErrorCode::BundleClosureInvalid))?;
    bundle
        .assert_unchanged()
        .map_err(|error| classify_error(error, CutoverErrorCode::FilesystemBoundaryInvalid))?;
    let inputs = VerifiedInputs {
        manifest_envelope,
        manifest_value,
        bundle_files,
        root_key_bytes,
        running_executable_bytes: executable.bytes.clone(),
    };

    let supplied_fingerprint = parse_sha256(&args.trusted_root_sha256, "trusted root")
        .map_err(|error| classify_error(error, CutoverErrorCode::TrustRootInvalid))?;
    if sha256(&inputs.root_key_bytes) != supplied_fingerprint {
        return Err(typed_error(
            CutoverErrorCode::TrustRootInvalid,
            anyhow!("trusted root fingerprint mismatch"),
        ));
    }
    let root_key = parse_public_key(&inputs.root_key_bytes)
        .map_err(|error| classify_error(error, CutoverErrorCode::TrustRootInvalid))?;
    let mut signatures_verified = 0;
    authenticate_bundle_manifest(&inputs, &root_key)
        .map_err(|error| classify_error(error, CutoverErrorCode::SignatureInvalid))?;
    signatures_verified += 1;
    let verifier_sha256 = authenticate_running_verifier(&inputs)?;
    let key_map = authenticate_key_map(&inputs, &root_key)
        .map_err(|error| classify_error(error, CutoverErrorCode::SignatureInvalid))?;
    signatures_verified += 1;

    let manifest = &inputs.manifest_envelope.payload;
    let plan = parse_node(&inputs, &manifest.documents.plan_payload_node_id, "plan")?;
    let report = parse_node(
        &inputs,
        &manifest.documents.report_payload_node_id,
        "report",
    )?;
    let verification = parse_node(
        &inputs,
        &manifest.documents.verification_payload_node_id,
        "verification",
    )?;
    let plan_auth = verify_document(&inputs, &key_map, "plan", &plan)
        .map_err(|error| classify_error(error, CutoverErrorCode::SignatureInvalid))?;
    signatures_verified += 1;
    let report_auth = verify_document(&inputs, &key_map, "report", &report)
        .map_err(|error| classify_error(error, CutoverErrorCode::SignatureInvalid))?;
    signatures_verified += 1;
    let verification_auth = verify_document(&inputs, &key_map, "verification", &verification)
        .map_err(|error| classify_error(error, CutoverErrorCode::SignatureInvalid))?;
    signatures_verified += 1;
    validate_verification_provenance(
        &verification,
        &report,
        &plan_auth,
        &report_auth,
        &verification_auth,
    )
    .map_err(|error| classify_error(error, CutoverErrorCode::SignatureInvalid))?;

    let plan_schema = parse_node(&inputs, &manifest.schemas.plan_node_id, "plan schema")?;
    let report_schema = parse_node(&inputs, &manifest.schemas.report_node_id, "report schema")?;
    let verification_schema = parse_node(
        &inputs,
        &manifest.schemas.verification_node_id,
        "verification schema",
    )?;
    validate_schema(&plan_schema, &plan, "plan")
        .map_err(|error| classify_error(error, CutoverErrorCode::SchemaInvalid))?;
    validate_schema(&report_schema, &report, "report")
        .map_err(|error| classify_error(error, CutoverErrorCode::SchemaInvalid))?;
    validate_schema(&verification_schema, &verification, "verification")
        .map_err(|error| classify_error(error, CutoverErrorCode::SchemaInvalid))?;
    validate_contract_schemas(&inputs)
        .map_err(|error| classify_error(error, CutoverErrorCode::SchemaInvalid))?;
    let fixtures = parse_unique_role(&inputs, "fixture_manifest")?;
    let fixture_count = validate_fixtures(
        &fixtures,
        &plan,
        &report,
        &verification,
        &plan_schema,
        &report_schema,
        &verification_schema,
        &inputs,
        &key_map,
        &root_key,
    )
    .map_err(|error| classify_error(error, CutoverErrorCode::FixtureInvalid))?;

    Ok(MachineResult {
        schema_version: "aos.hub.topology-cutover-verifier-result/v1",
        result: "verified",
        code: "ok",
        validated_document_count: 3,
        validated_contract_schema_count: 9,
        bundle_entry_count: manifest.entries.len(),
        materialized_fixture_count: fixture_count,
        signatures_verified,
        verifier_sha256,
    })
}

/// Generates and signs the complete bundle in one descriptor-frozen transaction.
pub(super) fn generate(
    args: &HubTopologyCutoverGenerateArgs,
    executable: &RunningExecutable,
) -> Result<Value> {
    generate_inner(args, executable)
        .map_err(|error| classify_error(error, CutoverErrorCode::InputInvalid))
}

fn generate_inner(
    args: &HubTopologyCutoverGenerateArgs,
    executable: &RunningExecutable,
) -> Result<Value> {
    let mut identities = IdentitySet::default();
    let mut bundle = PreopenedTree::open(&args.bundle, "bundle root", &mut identities)?;
    let source = PreopenedTree::open(&args.bundle_source, "bundle source", &mut identities)?;
    if bundle.root.identity == source.root.identity {
        return Err(typed_error(
            CutoverErrorCode::InputIdentityAliased,
            anyhow!("bundle source aliases bundle root"),
        ));
    }
    require_roots_disjoint(&bundle.root, &source.root)?;
    let forbidden_roots = [bundle.root.identity, source.root.identity];
    let recipe_bytes = read_external_pinned(
        &args.bundle_recipe,
        "bundle generation recipe",
        &forbidden_roots,
        &mut identities,
    )
    .map_err(|error| classify_error(error, CutoverErrorCode::BundleClosureInvalid))?;
    let root_signing_key_bytes = read_external_pinned(
        &args.root_signing_key,
        "root signing key",
        &forbidden_roots,
        &mut identities,
    )?;
    let document_signing_key_bytes = read_external_pinned(
        &args.document_signing_key,
        "document signing key",
        &forbidden_roots,
        &mut identities,
    )?;
    let verification_signing_key_bytes = read_external_pinned(
        &args.verification_signing_key,
        "verification signing key",
        &forbidden_roots,
        &mut identities,
    )?;
    let trusted_root_bytes = read_external_pinned(
        &args.trusted_root_public_key,
        "trusted root public key",
        &forbidden_roots,
        &mut identities,
    )?;
    let manifest_parent = pin_fresh_external_output(
        &args.bundle_manifest_output,
        "bundle manifest output",
        &forbidden_roots,
    )?;
    let recipe_value = parse_json(&recipe_bytes, "bundle generation recipe")
        .map_err(|error| classify_error(error, CutoverErrorCode::InputInvalid))?;
    let recipe: GenerationRecipe = serde_json::from_value(recipe_value.clone())
        .context("invalid closed generation recipe")
        .map_err(|error| classify_error(error, CutoverErrorCode::InputInvalid))?;
    scan_sensitive_contract(&recipe_value)
        .map_err(|error| classify_error(error, CutoverErrorCode::InputInvalid))?;
    validate_recipe(&recipe)
        .map_err(|error| classify_error(error, CutoverErrorCode::InputInvalid))?;
    let generated_paths = generated_output_paths(&recipe)
        .map_err(|error| classify_error(error, CutoverErrorCode::InputInvalid))?;
    require_absent_paths(&bundle, &generated_paths)?;
    validate_captured_tree_membership(&bundle, &recipe, "bundle")
        .map_err(|error| classify_error(error, CutoverErrorCode::BundleClosureInvalid))?;
    validate_captured_tree_membership(&source, &recipe, "source")
        .map_err(|error| classify_error(error, CutoverErrorCode::InputInvalid))?;
    let recipe_schema_layout =
        generation_layout(&recipe, &recipe.schemas.bundle_generation_node_id)?;
    let recipe_schema = parse_json(
        &source.read(&recipe_schema_layout.path)?,
        "bundle generation schema",
    )?;
    validate_schema(&recipe_schema, &recipe_value, "bundle generation recipe")
        .map_err(|error| classify_error(error, CutoverErrorCode::SchemaInvalid))?;
    let root_signing_key = parse_signing_key(&root_signing_key_bytes)
        .map_err(|error| classify_error(error, CutoverErrorCode::SignatureInvalid))?;
    let document_signing_key = parse_signing_key(&document_signing_key_bytes)
        .map_err(|error| classify_error(error, CutoverErrorCode::SignatureInvalid))?;
    let verification_signing_key = parse_signing_key(&verification_signing_key_bytes)
        .map_err(|error| classify_error(error, CutoverErrorCode::SignatureInvalid))?;
    validate_generation_authorities(
        args,
        &root_signing_key,
        &document_signing_key,
        &verification_signing_key,
        &trusted_root_bytes,
    )
    .map_err(|error| classify_error(error, CutoverErrorCode::SignerSeparationInvalid))?;

    let generation = (|| -> Result<Value> {
        for (role, signer_id, signing_key) in [
            (
                "key_map_root",
                args.root_signer_key_id.as_str(),
                &root_signing_key,
            ),
            (
                "plan",
                args.document_signer_key_id.as_str(),
                &document_signing_key,
            ),
            (
                "report",
                args.document_signer_key_id.as_str(),
                &document_signing_key,
            ),
            (
                "verification",
                args.verification_signer_key_id.as_str(),
                &verification_signing_key,
            ),
        ] {
            generate_document_stage(
                role,
                signer_id,
                signing_key,
                &recipe,
                executable,
                &mut bundle,
                &source,
                &mut identities,
            )?;
            if role == "key_map_root" {
                validate_generated_authority_identity(
                    args,
                    &recipe,
                    &bundle,
                    &document_signing_key.verifying_key(),
                    &verification_signing_key.verifying_key(),
                )?;
            }
        }
        source
            .assert_unchanged()
            .map_err(|error| classify_error(error, CutoverErrorCode::FilesystemBoundaryInvalid))?;
        bundle
            .assert_unchanged()
            .map_err(|error| classify_error(error, CutoverErrorCode::FilesystemBoundaryInvalid))?;
        let result = generate_bundle_root(
            &args.root_signer_key_id,
            &recipe,
            &root_signing_key,
            &bundle,
            &manifest_parent,
        )?;
        source
            .assert_unchanged()
            .map_err(|error| classify_error(error, CutoverErrorCode::FilesystemBoundaryInvalid))?;
        bundle
            .assert_unchanged()
            .map_err(|error| classify_error(error, CutoverErrorCode::FilesystemBoundaryInvalid))?;
        Ok(result)
    })();
    match generation {
        Ok(result) => {
            bundle.commit_outputs();
            manifest_parent.commit();
            Ok(result)
        }
        Err(error) => Err(rollback_generation(&mut bundle, &manifest_parent, error)),
    }
}

/// Copies the exact current executable bytes to a fresh declared bundle path.
pub(super) fn materialize_verifier(
    args: &HubTopologyCutoverMaterializeVerifierArgs,
    executable: &RunningExecutable,
) -> Result<Value> {
    materialize_verifier_inner(args, executable)
        .map_err(|error| classify_error(error, CutoverErrorCode::InputInvalid))
}

fn materialize_verifier_inner(
    args: &HubTopologyCutoverMaterializeVerifierArgs,
    executable: &RunningExecutable,
) -> Result<Value> {
    let mut identities = IdentitySet::default();
    let mut bundle = PreopenedTree::open(&args.bundle, "bundle root", &mut identities)?;
    let recipe_bytes = read_external_pinned(
        &args.bundle_recipe,
        "bundle generation recipe",
        &[bundle.root.identity],
        &mut identities,
    )?;
    let recipe_value = parse_json(&recipe_bytes, "bundle generation recipe")
        .map_err(|error| classify_error(error, CutoverErrorCode::InputInvalid))?;
    let recipe: GenerationRecipe = serde_json::from_value(recipe_value)
        .context("invalid closed generation recipe")
        .map_err(|error| classify_error(error, CutoverErrorCode::InputInvalid))?;
    validate_recipe(&recipe)
        .map_err(|error| classify_error(error, CutoverErrorCode::InputInvalid))?;
    validate_captured_tree_membership(&bundle, &recipe, "bundle")
        .map_err(|error| classify_error(error, CutoverErrorCode::BundleClosureInvalid))?;
    let verifier = generation_layout(&recipe, &recipe.verifier_node_id)
        .map_err(|error| classify_error(error, CutoverErrorCode::InputInvalid))?;
    require_generation_classifier(verifier, "tool", "verifier", "application/octet-stream")?;
    let materialization = (|| -> Result<Value> {
        bundle.publish(
            &verifier.path,
            &executable.bytes,
            Mode::from_bits_truncate(0o700),
            &mut identities,
        )?;
        bundle
            .assert_unchanged()
            .map_err(|error| classify_error(error, CutoverErrorCode::FilesystemBoundaryInvalid))?;
        Ok(serde_json::json!({
            "schema_version":"aos.hub.topology-cutover-materializer-result/v1",
            "result":"materialized",
            "code":"ok",
            "path":verifier.path,
            "sha256":hex(&sha256(&executable.bytes))
        }))
    })();
    match materialization {
        Ok(result) => {
            bundle.commit_outputs();
            Ok(result)
        }
        Err(error) => {
            if let Err(cleanup) = bundle.rollback_outputs() {
                Err(typed_error(
                    CutoverErrorCode::FilesystemBoundaryInvalid,
                    error.context(format!("materialization rollback failed: {cleanup:#}")),
                ))
            } else {
                Err(error)
            }
        }
    }
}

fn rollback_generation(
    bundle: &mut PreopenedTree,
    manifest: &PinnedExternalOutput,
    error: anyhow::Error,
) -> anyhow::Error {
    let mut failures = Vec::new();
    if let Err(cleanup) = manifest.rollback("bundle manifest output") {
        failures.push(format!("manifest: {cleanup:#}"));
    }
    if let Err(cleanup) = bundle.rollback_outputs() {
        failures.push(format!("bundle: {cleanup:#}"));
    }
    if failures.is_empty() {
        error
    } else {
        typed_error(
            CutoverErrorCode::FilesystemBoundaryInvalid,
            error.context(format!(
                "generation rollback failed: {}",
                failures.join("; ")
            )),
        )
    }
}

fn generate_document_stage(
    role: &str,
    signer_key_id: &str,
    signing_key: &SigningKey,
    recipe: &GenerationRecipe,
    executable: &RunningExecutable,
    bundle: &mut PreopenedTree,
    source: &PreopenedTree,
    identities: &mut IdentitySet,
) -> Result<()> {
    let (document_node_id, envelope_node_id, document_kind, schema_node_id, domain) = match role {
        "plan" => (
            &recipe.documents.plan_payload_node_id,
            &recipe.documents.plan_signature_envelope_node_id,
            "plan",
            &recipe.schemas.plan_node_id,
            DOCUMENT_DOMAIN,
        ),
        "report" => (
            &recipe.documents.report_payload_node_id,
            &recipe.documents.report_signature_envelope_node_id,
            "report",
            &recipe.schemas.report_node_id,
            DOCUMENT_DOMAIN,
        ),
        "verification" => (
            &recipe.documents.verification_payload_node_id,
            &recipe.documents.verification_signature_envelope_node_id,
            "verification",
            &recipe.schemas.verification_node_id,
            DOCUMENT_DOMAIN,
        ),
        "key_map_root" => (
            &recipe.trust.key_map_payload_node_id,
            &recipe.trust.key_map_signature_envelope_node_id,
            "signer_key_map",
            &recipe.schemas.signer_key_map_node_id,
            KEY_MAP_DOMAIN,
        ),
        unknown => bail!("unsupported generation signer role: {unknown}"),
    };
    let document_layout = generation_layout(recipe, document_node_id)?;
    let envelope_layout = generation_layout(recipe, envelope_node_id)?;
    let signature_role = if role == "key_map_root" {
        "key_map_signature".to_owned()
    } else {
        format!("{role}_signature")
    };
    let signature_layout = unique_generation_role(recipe, &signature_role)?;
    let schema_layout = generation_layout(recipe, schema_node_id)?;
    let schema = parse_json(&source.read(&schema_layout.path)?, "payload schema")?;
    let mut payload = parse_json(&source.read(&document_layout.path)?, document_kind)?;
    materialize_hash_markers(&mut payload, recipe, bundle, &executable.bytes)?;
    reject_derive_markers(&payload, "")?;
    reject_placeholder_hashes(&payload, "")?;
    scan_sensitive_contract(&payload)?;
    validate_schema(&schema, &payload, document_kind)?;
    if document_kind == "signer_key_map" {
        validate_generation_key_map(recipe, bundle, &payload, Some(&signing_key.verifying_key()))?;
    } else {
        validate_generation_array_order(recipe, source, document_kind, &payload)?;
    }
    let canonical_payload = canonical_json(&payload)?;
    bundle.publish(
        &document_layout.path,
        &canonical_payload,
        Mode::from_bits_truncate(0o600),
        identities,
    )?;

    let digest = separated_digest(domain.as_bytes(), &canonical_payload);
    let signature = signing_key.sign(&digest).to_bytes();
    bundle.publish(
        &signature_layout.path,
        &signature,
        Mode::from_bits_truncate(0o600),
        identities,
    )?;
    if bundle.read(&signature_layout.path)? != signature {
        bail!("generated raw signature byte identity mismatch");
    }
    let envelope = SignatureEnvelope {
        schema_version: "aos-cutover-signature-envelope/v1".to_owned(),
        document_node_id: document_node_id.clone(),
        document_kind: document_kind.to_owned(),
        canonical_payload_sha256: hex(&digest),
        omitted_json_pointers: Vec::new(),
        signer_key_id: signer_key_id.to_owned(),
        signer_role: role.to_owned(),
        signature_node_id: signature_layout.node_id.clone(),
        signature_sha256: hex(&sha256(&signature)),
        algorithm: "ed25519".to_owned(),
        domain: domain.to_owned(),
    };
    let envelope_value = serde_json::to_value(&envelope)?;
    let envelope_schema_layout =
        generation_layout(recipe, &recipe.schemas.signature_envelope_node_id)?;
    let envelope_schema = parse_json(
        &bundle.read(&envelope_schema_layout.path)?,
        "signature envelope schema",
    )?;
    validate_schema(&envelope_schema, &envelope_value, "signature envelope")?;
    bundle.publish(
        &envelope_layout.path,
        &canonical_json(&envelope_value)?,
        Mode::from_bits_truncate(0o600),
        identities,
    )?;
    if parse_json(
        &bundle.read(&envelope_layout.path)?,
        "generated signature envelope",
    )? != envelope_value
    {
        bail!("generated signature envelope identity mismatch");
    }
    Ok(())
}

fn validate_generation_key_map(
    recipe: &GenerationRecipe,
    bundle: &PreopenedTree,
    value: &Value,
    trusted_root: Option<&VerifyingKey>,
) -> Result<()> {
    let key_map: SignerKeyMap =
        serde_json::from_value(value.clone()).context("invalid generated signer key map")?;
    if key_map.schema_version != "aos-cutover-signer-key-map/v1" || key_map.keys.len() != 2 {
        bail!("invalid generated signer key map classifiers");
    }
    let mut fingerprints = BTreeSet::new();
    if key_map
        .keys
        .windows(2)
        .any(|pair| pair[0].key_id >= pair[1].key_id)
    {
        bail!("generated signer key map is not in canonical key order");
    }
    for key in &key_map.keys {
        if key.roles.is_empty()
            || key.roles.windows(2).any(|pair| pair[0] >= pair[1])
            || key
                .roles
                .iter()
                .any(|role| !matches!(role.as_str(), "plan" | "report" | "verification"))
        {
            bail!("generated signer key map has a noncanonical role set");
        }
        let layout = generation_layout(recipe, &key.public_key_node_id)?;
        require_generation_classifier(
            layout,
            "public_key",
            "signer_public_key",
            "application/octet-stream",
        )?;
        let bytes = bundle.read(&layout.path)?;
        if key.public_key_sha256 != hex(&sha256(&bytes))
            || !fingerprints.insert(key.public_key_sha256.as_str())
        {
            bail!("generated signer public-key identity is invalid or aliased");
        }
        let public_key = parse_public_key(&bytes)?;
        if trusted_root.is_some_and(|root| public_key == *root) {
            return Err(typed_error(
                CutoverErrorCode::SignerSeparationInvalid,
                anyhow!(
                    "authenticated signer {} aliases the trusted root key",
                    key.key_id
                ),
            ));
        }
    }
    let role_sets: BTreeSet<Vec<String>> =
        key_map.keys.iter().map(|key| key.roles.clone()).collect();
    if role_sets
        != BTreeSet::from([
            vec!["plan".to_owned(), "report".to_owned()],
            vec!["verification".to_owned()],
        ])
    {
        bail!("generated key map must contain distinct document and verification authorities");
    }
    Ok(())
}

fn validate_generated_authority_identity(
    args: &HubTopologyCutoverGenerateArgs,
    recipe: &GenerationRecipe,
    bundle: &PreopenedTree,
    document_key: &VerifyingKey,
    verification_key: &VerifyingKey,
) -> Result<()> {
    let layout = generation_layout(recipe, &recipe.trust.key_map_payload_node_id)?;
    let value = parse_json(&bundle.read(&layout.path)?, "generated signer key map")?;
    let key_map: SignerKeyMap = serde_json::from_value(value)?;
    for (key_id, roles, expected) in [
        (
            args.document_signer_key_id.as_str(),
            &["plan", "report"][..],
            document_key,
        ),
        (
            args.verification_signer_key_id.as_str(),
            &["verification"][..],
            verification_key,
        ),
    ] {
        let authority = key_map
            .keys
            .iter()
            .find(|key| key.key_id == key_id)
            .ok_or_else(|| anyhow!("generated authority is absent: {key_id}"))?;
        let observed_roles = authority
            .roles
            .iter()
            .map(String::as_str)
            .collect::<Vec<_>>();
        if observed_roles.as_slice() != roles {
            bail!("generated authority has the wrong closed role set: {key_id}");
        }
        let public_layout = generation_layout(recipe, &authority.public_key_node_id)?;
        let bytes = bundle.read(&public_layout.path)?;
        if authority.public_key_sha256 != hex(&sha256(&bytes))
            || parse_public_key(&bytes)? != *expected
        {
            bail!("generated authority key identity mismatch: {key_id}");
        }
    }
    Ok(())
}

fn validate_generation_array_order(
    recipe: &GenerationRecipe,
    source: &PreopenedTree,
    kind: &str,
    current: &Value,
) -> Result<()> {
    let load = |node_id: &str, label: &str| -> Result<Value> {
        let layout = generation_layout(recipe, node_id)?;
        parse_json(&source.read(&layout.path)?, label)
    };
    let plan = if kind == "plan" {
        current.clone()
    } else {
        load(&recipe.documents.plan_payload_node_id, "generation plan")?
    };
    let report = if kind == "report" {
        current.clone()
    } else {
        load(
            &recipe.documents.report_payload_node_id,
            "generation report",
        )?
    };
    let verification = if kind == "verification" {
        current.clone()
    } else {
        load(
            &recipe.documents.verification_payload_node_id,
            "generation verification",
        )?
    };
    validate_canonical_arrays(&plan, &report, &verification)
        .context("generation document array order is noncanonical")
}

fn validate_generation_authorities(
    args: &HubTopologyCutoverGenerateArgs,
    root_signing_key: &SigningKey,
    document_signing_key: &SigningKey,
    verification_signing_key: &SigningKey,
    trusted_root_bytes: &[u8],
) -> Result<()> {
    if args.root_signer_key_id.is_empty()
        || args.document_signer_key_id.is_empty()
        || args.verification_signer_key_id.is_empty()
    {
        bail!("generation signer key IDs must not be empty");
    }
    let trusted_root = parse_public_key(trusted_root_bytes)?;
    if root_signing_key.verifying_key() != trusted_root {
        bail!("root generation signing key does not match the trusted root public key");
    }
    let root = root_signing_key.verifying_key();
    let document = document_signing_key.verifying_key();
    let verification = verification_signing_key.verifying_key();
    if root == document || root == verification || document == verification {
        return Err(typed_error(
            CutoverErrorCode::SignerSeparationInvalid,
            anyhow!("root, document, and verification signing keys must be distinct"),
        ));
    }
    if args.root_signer_key_id == args.document_signer_key_id
        || args.root_signer_key_id == args.verification_signer_key_id
        || args.document_signer_key_id == args.verification_signer_key_id
    {
        bail!("root, document, and verification signer IDs must be distinct");
    }
    Ok(())
}

fn require_generation_classifier(
    layout: &GenerationLayout,
    kind: &str,
    role: &str,
    media_type: &str,
) -> Result<()> {
    if layout.kind != kind || layout.role != role || layout.media_type != media_type {
        bail!("generation node classifier mismatch for {}", layout.node_id);
    }
    Ok(())
}

fn generate_bundle_root(
    root_signer_key_id: &str,
    recipe: &GenerationRecipe,
    signing_key: &SigningKey,
    bundle: &PreopenedTree,
    manifest_parent: &PinnedExternalOutput,
) -> Result<Value> {
    let key_map_layout = generation_layout(recipe, &recipe.trust.key_map_payload_node_id)?;
    let key_map_value = parse_json(&bundle.read(&key_map_layout.path)?, "final signer key map")?;
    validate_generation_key_map(
        recipe,
        bundle,
        &key_map_value,
        Some(&signing_key.verifying_key()),
    )?;
    let mut entries = Vec::new();
    let declared_paths: BTreeSet<_> = recipe
        .layout
        .iter()
        .map(|layout| layout.path.clone())
        .collect();
    for layout in &recipe.layout {
        let bytes = bundle.read(&layout.path)?;
        if layout.media_type.contains("json") {
            let value = parse_json(&bytes, &layout.node_id)?;
            reject_derive_markers(&value, "")?;
            reject_placeholder_hashes(&value, "")?;
            if !matches!(
                layout.kind.as_str(),
                "schema" | "metaschema" | "interface_manifest"
            ) {
                scan_sensitive_contract(&value)?;
            }
        }
        entries.push(BundleEntry {
            node_id: layout.node_id.clone(),
            path: layout.path.clone(),
            kind: layout.kind.clone(),
            media_type: layout.media_type.clone(),
            role: layout.role.clone(),
            size_bytes: bytes.len() as u64,
            sha256: hex(&sha256(&bytes)),
        });
    }
    let actual_paths = bundle.paths();
    if actual_paths != declared_paths {
        bail!("generation bundle closure mismatch");
    }
    entries.sort_by(|left, right| left.node_id.cmp(&right.node_id));
    let manifest = BundleManifest {
        schema_version: "aos-cutover-bundle/v1".to_owned(),
        bundle_id: recipe.bundle_id.clone(),
        dialect: recipe.dialect.clone(),
        entries,
        edges: recipe.edges.clone(),
        documents: recipe.documents.clone(),
        schemas: recipe.schemas.clone(),
        trust: recipe.trust.clone(),
        verifier_node_id: recipe.verifier_node_id.clone(),
        complete: true,
    };
    validate_manifest_references(&manifest)?;
    let manifest_value = serde_json::to_value(&manifest)?;
    let canonical = canonical_json(&manifest_value)?;
    let digest = separated_digest(BUNDLE_DOMAIN.as_bytes(), &canonical);
    let signature = signing_key.sign(&digest).to_bytes();
    let signature_base64 = base64::engine::general_purpose::STANDARD.encode(signature);
    if base64::engine::general_purpose::STANDARD
        .decode(&signature_base64)
        .context("decoding generated bundle-root signature")?
        != signature
    {
        bail!("generated bundle-root signature byte identity mismatch");
    }
    let envelope = BundleManifestEnvelope {
        schema_version: "aos-cutover-bundle-envelope/v1".to_owned(),
        payload: manifest,
        payload_sha256: hex(&digest),
        signer_key_id: root_signer_key_id.to_owned(),
        signer_role: "bundle_root".to_owned(),
        algorithm: "ed25519".to_owned(),
        domain: BUNDLE_DOMAIN.to_owned(),
        signature_base64,
    };
    let envelope_value = serde_json::to_value(&envelope)?;
    let bundle_schema_layout = generation_layout(recipe, &recipe.schemas.bundle_node_id)?;
    let bundle_schema = parse_json(&bundle.read(&bundle_schema_layout.path)?, "bundle schema")?;
    validate_schema(&bundle_schema, &envelope_value, "bundle manifest envelope")?;
    bundle
        .assert_unchanged()
        .map_err(|error| classify_error(error, CutoverErrorCode::FilesystemBoundaryInvalid))?;
    let manifest_bytes = canonical_json(&envelope_value)?;
    bundle.budget.with_file(manifest_bytes.len() as u64)?;
    atomic_write_external_fresh(manifest_parent, &manifest_bytes)?;
    Ok(serde_json::json!({
        "schema_version":"aos.hub.topology-cutover-generator-result/v1",
        "result":"generated",
        "transaction":"complete",
        "signed_payload_count":4,
        "bundle_id":recipe.bundle_id,
        "entry_count":recipe.layout.len(),
        "payload_sha256":hex(&digest)
    }))
}

fn validate_recipe(recipe: &GenerationRecipe) -> Result<()> {
    if recipe.schema_version != "aos-cutover-bundle-generation/v1"
        || recipe.dialect != DIALECT_NAME
        || !recipe.complete
        || recipe.bundle_id.is_empty()
        || recipe.layout.is_empty()
    {
        bail!("invalid or incomplete generation recipe");
    }
    let nodes: BTreeSet<_> = recipe
        .layout
        .iter()
        .map(|layout| layout.node_id.as_str())
        .collect();
    let paths: BTreeSet<_> = recipe
        .layout
        .iter()
        .map(|layout| layout.path.as_str())
        .collect();
    for layout in &recipe.layout {
        validate_relative_path(&layout.path)?;
        if layout.node_id.is_empty()
            || layout.kind.is_empty()
            || layout.media_type.is_empty()
            || layout.role.is_empty()
        {
            bail!("generation layout has an empty node or classifier");
        }
    }
    if nodes.len() != recipe.layout.len()
        || paths.len() != recipe.layout.len()
        || recipe
            .layout
            .windows(2)
            .any(|pair| pair[0].node_id >= pair[1].node_id)
        || recipe.edges.windows(2).any(|pair| {
            (
                &pair[0].from_node_id,
                &pair[0].relation,
                &pair[0].to_node_id,
            ) >= (
                &pair[1].from_node_id,
                &pair[1].relation,
                &pair[1].to_node_id,
            )
        })
    {
        bail!("duplicate or noncanonical generation layout path or node ID");
    }
    for edge in &recipe.edges {
        if !nodes.contains(edge.from_node_id.as_str())
            || !nodes.contains(edge.to_node_id.as_str())
            || edge.relation.is_empty()
        {
            bail!("invalid generation edge");
        }
    }
    Ok(())
}

fn generated_output_paths(recipe: &GenerationRecipe) -> Result<Vec<String>> {
    let node_ids = [
        recipe.trust.key_map_payload_node_id.as_str(),
        recipe.trust.key_map_signature_envelope_node_id.as_str(),
        recipe.documents.plan_payload_node_id.as_str(),
        recipe.documents.plan_signature_envelope_node_id.as_str(),
        recipe.documents.report_payload_node_id.as_str(),
        recipe.documents.report_signature_envelope_node_id.as_str(),
        recipe.documents.verification_payload_node_id.as_str(),
        recipe
            .documents
            .verification_signature_envelope_node_id
            .as_str(),
    ];
    let mut paths = node_ids
        .iter()
        .map(|node_id| generation_layout(recipe, *node_id).map(|layout| layout.path.clone()))
        .collect::<Result<Vec<_>>>()?;
    for role in [
        "key_map_signature",
        "plan_signature",
        "report_signature",
        "verification_signature",
    ] {
        paths.push(unique_generation_role(recipe, role)?.path.clone());
    }
    if paths.len() != 12 || paths.iter().collect::<BTreeSet<_>>().len() != 12 {
        bail!("the generated output set must contain exactly 12 unique leaves");
    }
    Ok(paths)
}

fn require_absent_paths(tree: &PreopenedTree, paths: &[String]) -> Result<()> {
    if let Some(existing) = paths
        .iter()
        .find(|path| tree.files.contains_key(path.as_str()))
    {
        return Err(typed_error(
            CutoverErrorCode::OutputAlreadyExists,
            anyhow!("generated bundle output already exists before transaction: {existing}"),
        ));
    }
    Ok(())
}

fn validate_captured_tree_membership(
    tree: &PreopenedTree,
    recipe: &GenerationRecipe,
    label: &str,
) -> Result<()> {
    let declared: BTreeSet<_> = recipe
        .layout
        .iter()
        .map(|layout| layout.path.clone())
        .collect();
    let unexpected: Vec<_> = tree.paths().difference(&declared).cloned().collect();
    if !unexpected.is_empty() {
        bail!(
            "{label} tree contains undeclared files: {}",
            unexpected.join(", ")
        );
    }
    Ok(())
}

fn materialize_hash_markers(
    value: &mut Value,
    recipe: &GenerationRecipe,
    bundle_root: &PreopenedTree,
    executable_bytes: &[u8],
) -> Result<()> {
    match value {
        Value::String(text) => {
            if let Some(label) = text.strip_prefix("derive:sha256:") {
                if label.is_empty() {
                    bail!("fixture digest marker has an empty stable label");
                }
                *text = derive_fixture_value(label);
            } else if let Some(encoded) = text.strip_prefix("derive:domain-sha256:") {
                let (encoded_domain, encoded_preimage) = encoded
                    .split_once(':')
                    .ok_or_else(|| anyhow!("domain digest marker is missing its preimage"))?;
                if encoded_domain.is_empty()
                    || encoded_preimage.is_empty()
                    || encoded_preimage.contains(':')
                {
                    bail!("domain digest marker has invalid fields");
                }
                let engine = &base64::engine::general_purpose::URL_SAFE_NO_PAD;
                let domain = engine
                    .decode(encoded_domain)
                    .context("invalid domain marker base64url")?;
                let preimage = engine
                    .decode(encoded_preimage)
                    .context("invalid preimage marker base64url")?;
                if engine.encode(&domain) != encoded_domain
                    || engine.encode(&preimage) != encoded_preimage
                {
                    bail!("noncanonical domain digest marker base64url");
                }
                std::str::from_utf8(&domain).context("domain marker is not UTF-8")?;
                *text = hex(&separated_digest(&domain, &preimage));
            } else if let Some(node_id) = text.strip_prefix("derive:bundle-sha256:") {
                if node_id.is_empty() {
                    bail!("bundle digest marker has an empty node ID");
                }
                let layout = generation_layout(recipe, node_id)?;
                *text = hex(&sha256(&bundle_root.read(&layout.path)?));
            } else if let Some(node_id) = text.strip_prefix("derive:document-digest:") {
                if node_id.is_empty() {
                    bail!("document digest marker has an empty node ID");
                }
                let layout = generation_layout(recipe, node_id)?;
                *text = hex(&separated_digest(
                    DOCUMENT_DOMAIN.as_bytes(),
                    &bundle_root.read(&layout.path)?,
                ));
            } else if text == "derive:current-exe-sha256" {
                *text = hex(&sha256(executable_bytes));
            }
        }
        Value::Array(values) => {
            for child in values {
                materialize_hash_markers(child, recipe, bundle_root, executable_bytes)?;
            }
        }
        Value::Object(object) => {
            for child in object.values_mut() {
                materialize_hash_markers(child, recipe, bundle_root, executable_bytes)?;
            }
        }
        _ => {}
    }
    Ok(())
}

fn derive_fixture_value(label: &str) -> String {
    const DOMAIN: &[u8] = b"aos.hub.topology-cutover.fixture-value/v1";
    hex(&separated_digest(DOMAIN, label.as_bytes()))
}

fn reject_derive_markers(value: &Value, path: &str) -> Result<()> {
    match value {
        Value::String(text) if text.starts_with("derive:") => {
            bail!("unmaterialized fixture digest marker at {path}");
        }
        Value::Array(values) => {
            for (index, child) in values.iter().enumerate() {
                reject_derive_markers(child, &format!("{path}/{index}"))?;
            }
        }
        Value::Object(object) => {
            for (name, child) in object {
                reject_derive_markers(child, &format!("{path}/{name}"))?;
            }
        }
        _ => {}
    }
    Ok(())
}

fn validate_manifest_envelope_classifiers(envelope: &BundleManifestEnvelope) -> Result<()> {
    if envelope.schema_version != "aos-cutover-bundle-envelope/v1"
        || envelope.payload.schema_version != "aos-cutover-bundle/v1"
        || envelope.payload.dialect != DIALECT_NAME
        || !envelope.payload.complete
        || envelope.signer_role != "bundle_root"
        || envelope.algorithm != "ed25519"
        || envelope.domain != BUNDLE_DOMAIN
    {
        bail!("invalid bundle manifest envelope classifiers");
    }
    Ok(())
}

fn authenticate_bundle_manifest(inputs: &VerifiedInputs, root: &VerifyingKey) -> Result<()> {
    let payload = inputs
        .manifest_value
        .get("payload")
        .ok_or_else(|| anyhow!("bundle envelope payload absent"))?;
    let digest = separated_digest(BUNDLE_DOMAIN.as_bytes(), &canonical_json(payload)?);
    if inputs.manifest_envelope.payload_sha256 != hex(&digest) {
        bail!("bundle manifest payload digest mismatch");
    }
    let signature = base64::engine::general_purpose::STANDARD
        .decode(&inputs.manifest_envelope.signature_base64)
        .context("invalid bundle-root signature base64")?;
    verify_detached(root, &digest, &signature, "bundle manifest")
}

fn authenticate_running_verifier(inputs: &VerifiedInputs) -> Result<String> {
    let manifest = &inputs.manifest_envelope.payload;
    let verifier = manifest
        .entries
        .iter()
        .find(|entry| entry.node_id == manifest.verifier_node_id)
        .ok_or_else(|| anyhow!("verifier bundle node absent"))?;
    if verifier.role != "verifier" {
        bail!("verifier node has an invalid bundle role");
    }
    let bundled = inputs
        .bundle_files
        .get(&verifier.node_id)
        .ok_or_else(|| anyhow!("verifier bundle node absent"))?;
    if bundled != &inputs.running_executable_bytes {
        return Err(typed_error(
            CutoverErrorCode::RunningVerifierIdentityMismatch,
            anyhow!("running verifier bytes differ from authenticated bundle entry"),
        ));
    }
    Ok(hex(&sha256(&inputs.running_executable_bytes)))
}

fn authenticate_key_map(inputs: &VerifiedInputs, root: &VerifyingKey) -> Result<SignerKeyMap> {
    let manifest = &inputs.manifest_envelope.payload;
    let payload = parse_node(
        inputs,
        &manifest.trust.key_map_payload_node_id,
        "signer key map",
    )?;
    let envelope: SignatureEnvelope = serde_json::from_value(parse_node(
        inputs,
        &manifest.trust.key_map_signature_envelope_node_id,
        "key-map signature envelope",
    )?)?;
    if envelope.schema_version != "aos-cutover-signature-envelope/v1"
        || envelope.document_kind != "signer_key_map"
        || envelope.document_node_id != manifest.trust.key_map_payload_node_id
        || envelope.signer_role != "key_map_root"
        || envelope.signer_key_id != inputs.manifest_envelope.signer_key_id
        || envelope.algorithm != "ed25519"
        || envelope.domain != KEY_MAP_DOMAIN
        || !envelope.omitted_json_pointers.is_empty()
    {
        bail!("invalid key-map root envelope");
    }
    verify_envelope(inputs, root, &envelope, &payload)?;
    let key_map: SignerKeyMap = serde_json::from_value(payload)?;
    if key_map.schema_version != "aos-cutover-signer-key-map/v1" || key_map.keys.len() != 2 {
        bail!("invalid or empty signer key map");
    }
    validate_root_signer_id_separation(&inputs.manifest_envelope.signer_key_id, &key_map)?;
    let mut ids = BTreeSet::new();
    let mut fingerprints = BTreeSet::new();
    if key_map
        .keys
        .windows(2)
        .any(|pair| pair[0].key_id >= pair[1].key_id)
    {
        bail!("noncanonical signer key order");
    }
    for key in &key_map.keys {
        if !ids.insert(key.key_id.as_str())
            || key.roles.is_empty()
            || key.roles.windows(2).any(|pair| pair[0] >= pair[1])
            || key
                .roles
                .iter()
                .any(|role| !matches!(role.as_str(), "plan" | "report" | "verification"))
        {
            bail!("invalid signer identity or role set");
        }
        require_entry_classifier(
            manifest,
            &key.public_key_node_id,
            "public_key",
            "signer_public_key",
            "application/octet-stream",
        )?;
        let bytes = inputs
            .bundle_files
            .get(&key.public_key_node_id)
            .ok_or_else(|| anyhow!("signer public-key node absent"))?;
        if key.public_key_sha256 != hex(&sha256(bytes))
            || !fingerprints.insert(key.public_key_sha256.as_str())
        {
            bail!("signer public-key fingerprint mismatch or alias");
        }
        let public_key = parse_public_key(bytes)?;
        if public_key == *root {
            return Err(typed_error(
                CutoverErrorCode::SignerSeparationInvalid,
                anyhow!(
                    "authenticated signer {} aliases the trusted root key",
                    key.key_id
                ),
            ));
        }
    }
    let role_sets: BTreeSet<Vec<String>> =
        key_map.keys.iter().map(|key| key.roles.clone()).collect();
    if role_sets
        != BTreeSet::from([
            vec!["plan".to_owned(), "report".to_owned()],
            vec!["verification".to_owned()],
        ])
    {
        bail!("signer key map must contain distinct document and verification authorities");
    }
    Ok(key_map)
}

fn validate_root_signer_id_separation(
    root_signer_key_id: &str,
    key_map: &SignerKeyMap,
) -> Result<()> {
    if key_map
        .keys
        .iter()
        .any(|key| key.key_id == root_signer_key_id)
    {
        return Err(typed_error(
            CutoverErrorCode::SignerSeparationInvalid,
            anyhow!("bundle root signer ID aliases an authenticated document authority"),
        ));
    }
    Ok(())
}

pub(super) struct AuthenticatedDocument {
    signer_key_id: String,
    payload_node_id: String,
    canonical_payload_sha256: String,
    signature_node_id: String,
    signature_sha256: String,
}

pub(super) fn verify_document(
    inputs: &VerifiedInputs,
    key_map: &SignerKeyMap,
    kind: &str,
    payload: &Value,
) -> Result<AuthenticatedDocument> {
    let documents = &inputs.manifest_envelope.payload.documents;
    let (payload_node, envelope_node) = document_nodes(documents, kind)?;
    let envelope: SignatureEnvelope = serde_json::from_value(parse_node(
        inputs,
        envelope_node,
        "document signature envelope",
    )?)?;
    verify_document_envelope(inputs, key_map, kind, payload_node, payload, &envelope)?;
    Ok(AuthenticatedDocument {
        signer_key_id: envelope.signer_key_id,
        payload_node_id: payload_node.to_owned(),
        canonical_payload_sha256: envelope.canonical_payload_sha256,
        signature_node_id: envelope.signature_node_id,
        signature_sha256: envelope.signature_sha256,
    })
}

fn validate_verification_provenance(
    verification: &Value,
    report: &Value,
    plan: &AuthenticatedDocument,
    report_auth: &AuthenticatedDocument,
    verification_auth: &AuthenticatedDocument,
) -> Result<()> {
    if plan.signer_key_id != report_auth.signer_key_id
        || plan.signer_key_id == verification_auth.signer_key_id
    {
        bail!("verification authority is not distinct from the plan/report authority");
    }
    let provenance = verification
        .get("authenticated_documents")
        .and_then(Value::as_object)
        .ok_or_else(|| anyhow!("verification authenticated_documents is absent"))?;
    for (name, authenticated) in [("plan", plan), ("report", report_auth)] {
        let claimed = provenance
            .get(name)
            .and_then(Value::as_object)
            .ok_or_else(|| anyhow!("verification provenance is absent for {name}"))?;
        for (field, expected) in [
            ("payload_node_id", authenticated.payload_node_id.as_str()),
            (
                "canonical_payload_sha256",
                authenticated.canonical_payload_sha256.as_str(),
            ),
            (
                "signature_node_id",
                authenticated.signature_node_id.as_str(),
            ),
            ("signature_sha256", authenticated.signature_sha256.as_str()),
        ] {
            if claimed.get(field).and_then(Value::as_str) != Some(expected) {
                bail!("verification provenance mismatch for {name}.{field}");
            }
        }
    }
    let authored_at = verification
        .get("authored_at")
        .and_then(Value::as_str)
        .ok_or_else(|| anyhow!("verification authored_at is absent"))?;
    let finished_at = report
        .get("finished_at")
        .and_then(Value::as_str)
        .ok_or_else(|| anyhow!("report finished_at is absent"))?;
    if compare_instants(finished_at, authored_at)? != std::cmp::Ordering::Less {
        bail!("verification must be authored after report completion");
    }
    Ok(())
}

pub(super) fn verify_document_envelope(
    inputs: &VerifiedInputs,
    key_map: &SignerKeyMap,
    kind: &str,
    payload_node: &str,
    payload: &Value,
    envelope: &SignatureEnvelope,
) -> Result<()> {
    if envelope.schema_version != "aos-cutover-signature-envelope/v1"
        || envelope.document_node_id != payload_node
        || envelope.document_kind != kind
        || envelope.signer_role != kind
        || envelope.algorithm != "ed25519"
        || envelope.domain != DOCUMENT_DOMAIN
        || !envelope.omitted_json_pointers.is_empty()
    {
        bail!("signature_envelope_invalid");
    }
    let key = key_map
        .keys
        .iter()
        .find(|key| key.key_id == envelope.signer_key_id)
        .ok_or_else(|| anyhow!("unknown_signer"))?;
    if !key.roles.iter().any(|role| role == kind) {
        bail!("unauthorized_signer_role");
    }
    require_entry_classifier(
        &inputs.manifest_envelope.payload,
        &key.public_key_node_id,
        "public_key",
        "signer_public_key",
        "application/octet-stream",
    )?;
    let key_bytes = inputs
        .bundle_files
        .get(&key.public_key_node_id)
        .ok_or_else(|| anyhow!("signer public-key node absent"))?;
    if key.public_key_sha256 != hex(&sha256(key_bytes)) {
        bail!("signer public-key fingerprint mismatch");
    }
    let verifying_key = parse_public_key(key_bytes)?;
    verify_envelope(inputs, &verifying_key, envelope, payload)
}

fn verify_envelope(
    inputs: &VerifiedInputs,
    key: &VerifyingKey,
    envelope: &SignatureEnvelope,
    payload: &Value,
) -> Result<()> {
    let digest = separated_digest(envelope.domain.as_bytes(), &canonical_json(payload)?);
    if envelope.canonical_payload_sha256 != hex(&digest) {
        bail!("signature_payload_digest_invalid");
    }
    let signature_role = match envelope.document_kind.as_str() {
        "plan" => "plan_signature",
        "report" => "report_signature",
        "verification" => "verification_signature",
        "signer_key_map" => "key_map_signature",
        unknown => bail!("unknown signature document kind: {unknown}"),
    };
    require_entry_classifier(
        &inputs.manifest_envelope.payload,
        &envelope.signature_node_id,
        "signature",
        signature_role,
        "application/octet-stream",
    )?;
    let signature = inputs
        .bundle_files
        .get(&envelope.signature_node_id)
        .ok_or_else(|| anyhow!("raw signature node absent"))?;
    if envelope.signature_sha256 != hex(&sha256(signature)) {
        bail!("raw signature identity mismatch");
    }
    verify_detached(key, &digest, signature, &envelope.document_kind)
}

pub(super) fn authenticate_manifest_fixture(value: &Value, root: &VerifyingKey) -> Result<()> {
    let envelope: BundleManifestEnvelope = serde_json::from_value(value.clone())?;
    validate_manifest_envelope_classifiers(&envelope)?;
    let payload = value
        .get("payload")
        .ok_or_else(|| anyhow!("payload absent"))?;
    let digest = separated_digest(BUNDLE_DOMAIN.as_bytes(), &canonical_json(payload)?);
    if envelope.payload_sha256 != hex(&digest) {
        bail!("bundle_digest_invalid");
    }
    let signature = base64::engine::general_purpose::STANDARD.decode(envelope.signature_base64)?;
    verify_detached(root, &digest, &signature, "bundle")
}

/// Validates an ephemeral bundle fixture after the unmodified base was authenticated.
pub(super) fn validate_manifest_fixture_closure(
    inputs: &VerifiedInputs,
    value: &Value,
) -> Result<()> {
    let envelope: BundleManifestEnvelope = serde_json::from_value(value.clone())?;
    let base_entries = serde_json::to_value(&inputs.manifest_envelope.payload.entries)?;
    let fixture_entries = serde_json::to_value(&envelope.payload.entries)?;
    if fixture_entries != base_entries {
        bail!("bundle_not_closed");
    }
    let verifier = envelope
        .payload
        .entries
        .iter()
        .find(|entry| entry.node_id == envelope.payload.verifier_node_id)
        .ok_or_else(|| anyhow!("verifier_identity_mismatch"))?;
    let bytes = inputs
        .bundle_files
        .get(&verifier.node_id)
        .ok_or_else(|| anyhow!("verifier_identity_mismatch"))?;
    if bytes != &inputs.running_executable_bytes {
        bail!("verifier_identity_mismatch");
    }
    validate_manifest_references(&envelope.payload)
        .map_err(|error| error.context("bundle_not_closed"))?;
    Ok(())
}

pub(super) fn authenticate_key_map_fixture(
    inputs: &VerifiedInputs,
    root: &VerifyingKey,
    payload: &Value,
    envelope: &SignatureEnvelope,
) -> Result<()> {
    let key_map: SignerKeyMap = serde_json::from_value(payload.clone())?;
    if key_map.keys.iter().any(|key| {
        key.roles.is_empty()
            || key
                .roles
                .iter()
                .any(|role| !matches!(role.as_str(), "plan" | "report" | "verification"))
    }) {
        bail!("signer_role_not_authorized");
    }
    let manifest = &inputs.manifest_envelope.payload;
    if envelope.schema_version != "aos-cutover-signature-envelope/v1"
        || envelope.document_kind != "signer_key_map"
        || envelope.document_node_id != manifest.trust.key_map_payload_node_id
        || envelope.signer_role != "key_map_root"
        || envelope.signer_key_id != inputs.manifest_envelope.signer_key_id
        || envelope.algorithm != "ed25519"
        || envelope.domain != KEY_MAP_DOMAIN
        || !envelope.omitted_json_pointers.is_empty()
    {
        bail!("signature_envelope_invalid");
    }
    verify_envelope(inputs, root, envelope, payload)
}

fn validate_contract_schemas(inputs: &VerifiedInputs) -> Result<()> {
    let manifest = &inputs.manifest_envelope.payload;
    validate_manifest_references(manifest)?;
    let metaschema = parse_node(
        inputs,
        &manifest.schemas.dialect_metaschema_node_id,
        "metaschema",
    )?;
    validate_schema(&metaschema, &metaschema, "metaschema")?;
    let schema_nodes = [
        &manifest.schemas.plan_node_id,
        &manifest.schemas.report_node_id,
        &manifest.schemas.verification_node_id,
        &manifest.schemas.bundle_node_id,
        &manifest.schemas.signature_envelope_node_id,
        &manifest.schemas.signer_key_map_node_id,
        &manifest.schemas.fixtures_node_id,
        &manifest.schemas.bundle_generation_node_id,
    ];
    for node in schema_nodes {
        let schema = parse_node(inputs, node, "contract schema")?;
        validate_schema(&metaschema, &schema, "contract schema")?;
    }
    let bundle_schema = parse_node(inputs, &manifest.schemas.bundle_node_id, "bundle schema")?;
    validate_schema(
        &bundle_schema,
        &inputs.manifest_value,
        "bundle manifest envelope",
    )?;
    let envelope_schema = parse_node(
        inputs,
        &manifest.schemas.signature_envelope_node_id,
        "signature envelope schema",
    )?;
    for node in [
        &manifest.documents.plan_signature_envelope_node_id,
        &manifest.documents.report_signature_envelope_node_id,
        &manifest.documents.verification_signature_envelope_node_id,
        &manifest.trust.key_map_signature_envelope_node_id,
    ] {
        validate_schema(
            &envelope_schema,
            &parse_node(inputs, node, "signature envelope")?,
            "signature envelope",
        )?;
    }
    let key_map_schema = parse_node(
        inputs,
        &manifest.schemas.signer_key_map_node_id,
        "key-map schema",
    )?;
    validate_schema(
        &key_map_schema,
        &parse_node(inputs, &manifest.trust.key_map_payload_node_id, "key map")?,
        "key map",
    )?;
    let fixtures_schema = parse_node(
        inputs,
        &manifest.schemas.fixtures_node_id,
        "fixtures schema",
    )?;
    validate_schema(
        &fixtures_schema,
        &parse_unique_role(inputs, "fixture_manifest")?,
        "fixtures",
    )?;
    unique_role_entry(manifest, "fixture_manifest")?;
    unique_role_entry(manifest, "verifier")?;
    Ok(())
}

fn validate_manifest_references(manifest: &BundleManifest) -> Result<()> {
    if manifest
        .entries
        .windows(2)
        .any(|pair| pair[0].node_id >= pair[1].node_id)
        || manifest.edges.windows(2).any(|pair| {
            (
                &pair[0].from_node_id,
                &pair[0].relation,
                &pair[0].to_node_id,
            ) >= (
                &pair[1].from_node_id,
                &pair[1].relation,
                &pair[1].to_node_id,
            )
        })
    {
        bail!("noncanonical bundle graph order");
    }
    for (node_id, kind, role, media_type) in [
        (
            &manifest.documents.plan_payload_node_id,
            "document",
            "plan_payload",
            "application/json",
        ),
        (
            &manifest.documents.plan_signature_envelope_node_id,
            "signature_envelope",
            "plan_signature_envelope",
            "application/json",
        ),
        (
            &manifest.documents.report_payload_node_id,
            "document",
            "report_payload",
            "application/json",
        ),
        (
            &manifest.documents.report_signature_envelope_node_id,
            "signature_envelope",
            "report_signature_envelope",
            "application/json",
        ),
        (
            &manifest.documents.verification_payload_node_id,
            "document",
            "verification_payload",
            "application/json",
        ),
        (
            &manifest.documents.verification_signature_envelope_node_id,
            "signature_envelope",
            "verification_signature_envelope",
            "application/json",
        ),
        (
            &manifest.schemas.dialect_metaschema_node_id,
            "metaschema",
            "dialect_metaschema",
            "application/json",
        ),
        (
            &manifest.schemas.plan_node_id,
            "schema",
            "plan_schema",
            "application/json",
        ),
        (
            &manifest.schemas.report_node_id,
            "schema",
            "report_schema",
            "application/json",
        ),
        (
            &manifest.schemas.verification_node_id,
            "schema",
            "verification_schema",
            "application/json",
        ),
        (
            &manifest.schemas.bundle_node_id,
            "schema",
            "bundle_schema",
            "application/json",
        ),
        (
            &manifest.schemas.signature_envelope_node_id,
            "schema",
            "signature_envelope_schema",
            "application/json",
        ),
        (
            &manifest.schemas.signer_key_map_node_id,
            "schema",
            "signer_key_map_schema",
            "application/json",
        ),
        (
            &manifest.schemas.fixtures_node_id,
            "schema",
            "fixture_schema",
            "application/json",
        ),
        (
            &manifest.schemas.bundle_generation_node_id,
            "schema",
            "bundle_generation_schema",
            "application/json",
        ),
        (
            &manifest.trust.key_map_payload_node_id,
            "key_map",
            "signer_key_map",
            "application/json",
        ),
        (
            &manifest.trust.key_map_signature_envelope_node_id,
            "signature_envelope",
            "key_map_signature_envelope",
            "application/json",
        ),
        (
            &manifest.verifier_node_id,
            "tool",
            "verifier",
            "application/octet-stream",
        ),
    ] {
        require_entry_classifier(manifest, node_id, kind, role, media_type)?;
    }
    let nodes: BTreeSet<_> = manifest
        .entries
        .iter()
        .map(|entry| entry.node_id.as_str())
        .collect();
    let required = [
        &manifest.documents.plan_payload_node_id,
        &manifest.documents.plan_signature_envelope_node_id,
        &manifest.documents.report_payload_node_id,
        &manifest.documents.report_signature_envelope_node_id,
        &manifest.documents.verification_payload_node_id,
        &manifest.documents.verification_signature_envelope_node_id,
        &manifest.schemas.dialect_metaschema_node_id,
        &manifest.schemas.plan_node_id,
        &manifest.schemas.report_node_id,
        &manifest.schemas.verification_node_id,
        &manifest.schemas.bundle_node_id,
        &manifest.schemas.signature_envelope_node_id,
        &manifest.schemas.signer_key_map_node_id,
        &manifest.schemas.fixtures_node_id,
        &manifest.schemas.bundle_generation_node_id,
        &manifest.trust.key_map_payload_node_id,
        &manifest.trust.key_map_signature_envelope_node_id,
        &manifest.verifier_node_id,
    ];
    for node in required {
        if !nodes.contains(node.as_str()) {
            bail!("bundle contract references absent node: {node}");
        }
    }
    for edge in &manifest.edges {
        if !nodes.contains(edge.from_node_id.as_str())
            || !nodes.contains(edge.to_node_id.as_str())
            || edge.relation.is_empty()
        {
            bail!("bundle edge has an absent endpoint or relation");
        }
    }
    Ok(())
}

/// Requires one manifest node with the exact structural classifier triple.
pub(super) fn require_entry_classifier(
    manifest: &BundleManifest,
    node_id: &str,
    kind: &str,
    role: &str,
    media_type: &str,
) -> Result<()> {
    let entry = manifest
        .entries
        .iter()
        .find(|entry| entry.node_id == node_id)
        .ok_or_else(|| anyhow!("bundle_reference_invalid: {node_id}"))?;
    if entry.kind != kind || entry.role != role || entry.media_type != media_type {
        bail!("typed_bundle_reference_invalid: {node_id}");
    }
    Ok(())
}

fn load_closed_bundle(
    root: &PreopenedTree,
    manifest: &BundleManifest,
) -> Result<BTreeMap<String, Vec<u8>>> {
    let mut paths = BTreeSet::new();
    let mut nodes = BTreeSet::new();
    let mut files = BTreeMap::new();
    for entry in &manifest.entries {
        validate_relative_path(&entry.path)?;
        if !paths.insert(entry.path.clone()) || !nodes.insert(entry.node_id.clone()) {
            bail!("duplicate bundle path or node ID");
        }
        if entry.kind.is_empty() || entry.media_type.is_empty() || entry.role.is_empty() {
            bail!("empty bundle classifier");
        }
        let bytes = root.read(&entry.path)?;
        if bytes.len() as u64 != entry.size_bytes
            || sha256(&bytes) != parse_sha256(&entry.sha256, "bundle entry")?
        {
            bail!("bundle entry identity mismatch: {}", entry.node_id);
        }
        files.insert(entry.node_id.clone(), bytes);
    }
    let actual = root.paths();
    if actual != paths {
        bail!("bundle file closure mismatch");
    }
    validate_manifest_references(manifest)?;
    Ok(files)
}

fn parse_node(inputs: &VerifiedInputs, node_id: &str, label: &str) -> Result<Value> {
    parse_json(
        inputs
            .bundle_files
            .get(node_id)
            .ok_or_else(|| anyhow!("bundle node absent: {node_id}"))?,
        label,
    )
}

fn parse_unique_role(inputs: &VerifiedInputs, role: &str) -> Result<Value> {
    let entry = unique_role_entry(&inputs.manifest_envelope.payload, role)?;
    parse_node(inputs, &entry.node_id, role)
}

fn unique_role_entry<'a>(manifest: &'a BundleManifest, role: &str) -> Result<&'a BundleEntry> {
    let matches: Vec<_> = manifest
        .entries
        .iter()
        .filter(|entry| entry.role == role)
        .collect();
    if matches.len() != 1 {
        bail!("bundle requires exactly one {role} node");
    }
    Ok(matches[0])
}

fn document_nodes<'a>(documents: &'a BundleDocuments, kind: &str) -> Result<(&'a str, &'a str)> {
    Ok(match kind {
        "plan" => (
            &documents.plan_payload_node_id,
            &documents.plan_signature_envelope_node_id,
        ),
        "report" => (
            &documents.report_payload_node_id,
            &documents.report_signature_envelope_node_id,
        ),
        "verification" => (
            &documents.verification_payload_node_id,
            &documents.verification_signature_envelope_node_id,
        ),
        unknown => bail!("unknown document kind: {unknown}"),
    })
}

fn generation_layout<'a>(
    recipe: &'a GenerationRecipe,
    node_id: &str,
) -> Result<&'a GenerationLayout> {
    recipe
        .layout
        .iter()
        .find(|layout| layout.node_id == node_id)
        .ok_or_else(|| anyhow!("generation layout node absent: {node_id}"))
}

fn unique_generation_role<'a>(
    recipe: &'a GenerationRecipe,
    role: &str,
) -> Result<&'a GenerationLayout> {
    let matches: Vec<_> = recipe
        .layout
        .iter()
        .filter(|layout| layout.role == role)
        .collect();
    if matches.len() != 1 {
        bail!("generation layout requires exactly one {role} node");
    }
    Ok(matches[0])
}

fn validate_relative_path(path: &str) -> Result<()> {
    let path = Path::new(path);
    if path.as_os_str().is_empty()
        || path.is_absolute()
        || path
            .components()
            .any(|component| !matches!(component, Component::Normal(_)))
    {
        bail!("bundle path is not normalized: {}", path.display());
    }
    Ok(())
}

fn require_single_link(file: &File, label: &str) -> Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt as _;
        let links = file.metadata()?.nlink();
        if links != 1 {
            return Err(typed_error(
                CutoverErrorCode::InputIdentityAliased,
                anyhow!("{label} has link count {links}; exactly one is required"),
            ));
        }
    }
    Ok(())
}

#[cfg(unix)]
fn inode_identity(metadata: &std::fs::Metadata) -> InodeIdentity {
    use std::os::unix::fs::MetadataExt as _;
    InodeIdentity {
        device: metadata.dev(),
        inode: metadata.ino(),
    }
}

#[cfg(unix)]
fn file_identity(file: &File) -> Result<(u64, u64, u64, i64, i64)> {
    use std::os::unix::fs::MetadataExt as _;
    let metadata = file.metadata()?;
    Ok((
        metadata.dev(),
        metadata.ino(),
        metadata.len(),
        metadata.mtime(),
        metadata.mtime_nsec(),
    ))
}

#[cfg(not(unix))]
fn file_identity(file: &File) -> Result<(u64, std::time::SystemTime)> {
    let metadata = file.metadata()?;
    Ok((metadata.len(), metadata.modified()?))
}

fn read_bounded(file: &mut File, size: u64, maximum: u64, label: &str) -> Result<Vec<u8>> {
    if size > maximum {
        bail!("{label} exceeds maximum size of {maximum} bytes");
    }
    let capacity = usize::try_from(size).context("bounded input size exceeds address space")?;
    let mut bytes = Vec::new();
    bytes
        .try_reserve_exact(capacity)
        .with_context(|| format!("reserving bounded input buffer for {label}"))?;
    file.take(maximum.saturating_add(1))
        .read_to_end(&mut bytes)?;
    if bytes.len() as u64 > maximum {
        bail!("{label} exceeds maximum size of {maximum} bytes");
    }
    if bytes.len() as u64 != size {
        bail!("{label} size changed while reading");
    }
    Ok(bytes)
}

fn assert_namespace_steps(namespace: &[PinnedNamespaceStep], label: &str) -> Result<()> {
    for step in namespace {
        let reopened = openat(
            &step.parent,
            &step.name,
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .with_context(|| format!("reopening {label} ancestor without following links"))?;
        if inode_identity(&File::from(reopened).metadata()?) != step.identity {
            bail!("{label} ancestor identity changed");
        }
    }
    Ok(())
}

impl PinnedExternalOutput {
    fn assert_namespace_unchanged(&self, label: &str) -> Result<()> {
        assert_namespace_steps(&self.namespace, label)
    }

    fn rollback(&self, label: &str) -> Result<()> {
        let mut published = self.published.borrow_mut();
        let Some(publication) = published.as_ref() else {
            return Ok(());
        };
        remove_owned_name(
            &self.parent,
            &self.name,
            &publication.handle,
            publication.identity,
            1,
            label,
        )?;
        published.take();
        Ok(())
    }

    fn commit(&self) {
        self.published.borrow_mut().take();
    }
}

fn atomic_write_external_fresh(output: &PinnedExternalOutput, bytes: &[u8]) -> Result<()> {
    atomic_write_external_fresh_inner(output, bytes)
        .map_err(|error| classify_error(error, CutoverErrorCode::FilesystemBoundaryInvalid))
}

fn atomic_write_external_fresh_inner(output: &PinnedExternalOutput, bytes: &[u8]) -> Result<()> {
    if bytes.len() as u64 > MAX_CAPTURE_FILE_BYTES {
        bail!("bundle manifest output exceeds maximum size of {MAX_CAPTURE_FILE_BYTES} bytes");
    }
    output.assert_namespace_unchanged("bundle manifest output")?;
    let publication = atomic_publish_fresh(
        &output.parent,
        &output.name,
        bytes,
        "bundle manifest output",
        Mode::from_bits_truncate(0o600),
    )?;
    output.published.borrow_mut().replace(publication);
    let verification = (|| -> Result<()> {
        output.assert_namespace_unchanged("bundle manifest output")?;
        let mut published = output.published.borrow_mut();
        let publication = published
            .as_mut()
            .ok_or_else(|| anyhow!("bundle manifest publication ownership was lost"))?;
        assert_owned_name(
            &output.parent,
            &output.name,
            &publication.handle,
            publication.identity,
            1,
            "bundle manifest output",
        )?;
        publication.handle.seek(SeekFrom::Start(0))?;
        let observed = read_bounded(
            &mut publication.handle,
            bytes.len() as u64,
            MAX_CAPTURE_FILE_BYTES,
            "bundle manifest output",
        )?;
        if observed != bytes {
            bail!("bundle manifest output bytes changed during publication");
        }
        Ok(())
    })();
    if let Err(error) = verification {
        return match output.rollback("rejected bundle manifest output") {
            Ok(()) => Err(error),
            Err(cleanup) => Err(error.context(format!(
                "failed to remove rejected bundle manifest output: {cleanup:#}"
            ))),
        };
    }
    Ok(())
}

fn atomic_publish_fresh(
    parent: &OwnedFd,
    name: &std::ffi::OsStr,
    bytes: &[u8],
    label: &str,
    mode: Mode,
) -> Result<FreshPublication> {
    let temporary = OsString::from(format!(
        ".{}.{}.aos-cutover-tmp",
        name.to_string_lossy(),
        std::process::id()
    ));
    let mut temporary_owned = false;
    let mut final_owned = false;
    let mut unidentified_temporary = false;
    let mut publication = None;
    let result = (|| -> Result<()> {
        let handle = openat(
            &parent,
            &temporary,
            OFlags::RDWR | OFlags::CREATE | OFlags::EXCL | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            mode,
        )?;
        temporary_owned = true;
        unidentified_temporary = true;
        let file = File::from(handle);
        let identity = inode_identity(&file.metadata()?);
        publication = Some(FreshPublication {
            handle: file,
            identity,
        });
        unidentified_temporary = false;
        let retained = publication
            .as_mut()
            .ok_or_else(|| anyhow!("fresh publication descriptor was lost"))?;
        retained.handle.write_all(bytes)?;
        retained.handle.sync_all()?;
        link_retained_fresh(parent, name, retained, label)?;
        final_owned = true;
        let retained = publication
            .as_ref()
            .ok_or_else(|| anyhow!("fresh publication descriptor was lost"))?;
        assert_owned_name(
            parent,
            &temporary,
            &retained.handle,
            retained.identity,
            2,
            "temporary output",
        )?;
        unlinkat(parent, &temporary, AtFlags::empty())?;
        temporary_owned = false;
        File::from(parent.try_clone()?).sync_all()?;
        Ok(())
    })();
    if let Err(error) = result {
        let mut cleanup_failures = Vec::new();
        if let Some(retained) = publication.as_ref() {
            if final_owned {
                let expected_links = if temporary_owned { 2 } else { 1 };
                if let Err(cleanup) = remove_owned_name(
                    parent,
                    name,
                    &retained.handle,
                    retained.identity,
                    expected_links,
                    label,
                ) {
                    cleanup_failures.push(format!("final output: {cleanup:#}"));
                } else {
                    final_owned = false;
                }
            }
            if temporary_owned {
                let expected_links = if final_owned { 2 } else { 1 };
                if let Err(cleanup) = remove_owned_name(
                    parent,
                    &temporary,
                    &retained.handle,
                    retained.identity,
                    expected_links,
                    "temporary output",
                ) {
                    cleanup_failures.push(format!("temporary output: {cleanup:#}"));
                }
            }
        } else if temporary_owned && unidentified_temporary {
            cleanup_failures
                .push("temporary output: ownership identity could not be established".to_owned());
        }
        if cleanup_failures.is_empty() {
            return Err(error);
        }
        return Err(error.context(format!(
            "fresh-output cleanup failed: {}",
            cleanup_failures.join("; ")
        )));
    }
    publication.ok_or_else(|| anyhow!("fresh publication descriptor was lost"))
}

fn link_retained_fresh(
    parent: &OwnedFd,
    name: &std::ffi::OsStr,
    publication: &FreshPublication,
    label: &str,
) -> Result<()> {
    let retained_path = format!("/proc/self/fd/{}", publication.handle.as_raw_fd());
    linkat(
        parent,
        retained_path.as_str(),
        parent,
        name,
        AtFlags::SYMLINK_FOLLOW,
    )
    .map_err(|error| {
        if error == rustix::io::Errno::EXIST {
            typed_error(
                CutoverErrorCode::OutputAlreadyExists,
                anyhow!("{label} already exists"),
            )
        } else {
            typed_error(
                CutoverErrorCode::FilesystemBoundaryInvalid,
                anyhow!(error).context(format!("publishing {label} from retained descriptor")),
            )
        }
    })
}

fn assert_owned_name(
    parent: &OwnedFd,
    name: &std::ffi::OsStr,
    retained: &File,
    identity: InodeIdentity,
    expected_links: u64,
    label: &str,
) -> Result<()> {
    let reopened = openat(
        parent,
        name,
        OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .with_context(|| format!("reopening owned {label}"))?;
    let reopened = File::from(reopened);
    let retained_metadata = retained.metadata()?;
    let reopened_metadata = reopened.metadata()?;
    if inode_identity(&retained_metadata) != identity
        || inode_identity(&reopened_metadata) != identity
    {
        bail!("fresh {label} namespace no longer names the owned inode");
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt as _;
        if retained_metadata.nlink() != expected_links
            || reopened_metadata.nlink() != expected_links
        {
            bail!(
                "fresh {label} link count changed; expected {expected_links}, retained {}, namespace {}",
                retained_metadata.nlink(),
                reopened_metadata.nlink()
            );
        }
    }
    Ok(())
}

fn remove_owned_name(
    parent: &OwnedFd,
    name: &std::ffi::OsStr,
    retained: &File,
    identity: InodeIdentity,
    expected_links: u64,
    label: &str,
) -> Result<()> {
    assert_owned_name(parent, name, retained, identity, expected_links, label)?;
    unlinkat(parent, name, AtFlags::empty()).with_context(|| format!("removing fresh {label}"))?;
    File::from(parent.try_clone()?)
        .sync_all()
        .with_context(|| format!("synchronizing removal of fresh {label}"))?;
    Ok(())
}

fn open_absolute_parent_checked(
    path: &Path,
    label: &str,
    forbidden_roots: &[InodeIdentity],
) -> Result<(OwnedFd, OsString, Vec<InodeIdentity>)> {
    if !path.is_absolute() {
        return Err(typed_error(
            CutoverErrorCode::FilesystemBoundaryInvalid,
            anyhow!("{label} path must be absolute"),
        ));
    }
    let components: Vec<_> = path.components().collect();
    let (leaf, ancestors) = components
        .split_last()
        .ok_or_else(|| anyhow!("{label} path has no filename"))?;
    let mut current = open(
        "/",
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )?;
    let mut identities = vec![inode_identity(
        &File::from(current.try_clone()?).metadata()?,
    )];
    if forbidden_roots.iter().any(|root| identities.contains(root)) {
        bail!("{label} is within a forbidden root");
    }
    for component in ancestors {
        match component {
            Component::RootDir => continue,
            Component::Normal(name) => {
                current = openat(
                    &current,
                    *name,
                    OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
                    Mode::empty(),
                )
                .with_context(|| format!("opening {label} ancestor without following links"))?;
                let identity = inode_identity(&File::from(current.try_clone()?).metadata()?);
                if forbidden_roots.contains(&identity) {
                    return Err(typed_error(
                        CutoverErrorCode::FilesystemBoundaryInvalid,
                        anyhow!("{label} must be outside all bundle and source roots"),
                    ));
                }
                identities.push(identity);
            }
            _ => bail!("{label} path must be absolute and normalized"),
        }
    }
    let Component::Normal(name) = leaf else {
        bail!("{label} path has an invalid filename");
    };
    Ok((current, (*name).to_owned(), identities))
}

fn open_absolute_directory_pinned(
    path: &Path,
    label: &str,
) -> Result<(
    OwnedFd,
    OwnedFd,
    OsString,
    Vec<InodeIdentity>,
    Vec<PinnedNamespaceStep>,
)> {
    if !path.is_absolute() {
        bail!("{label} path must be absolute");
    }
    let components: Vec<_> = path.components().collect();
    let (leaf, path_ancestors) = components
        .split_last()
        .ok_or_else(|| anyhow!("{label} path has no filename"))?;
    let mut parent = open(
        "/",
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )?;
    let mut ancestors = vec![inode_identity(&File::from(parent.try_clone()?).metadata()?)];
    let mut namespace = Vec::new();
    for component in path_ancestors {
        match component {
            Component::RootDir => continue,
            Component::Normal(name) => {
                let namespace_parent = parent.try_clone()?;
                parent = openat(
                    &parent,
                    *name,
                    OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
                    Mode::empty(),
                )
                .with_context(|| format!("opening {label} ancestor without following links"))?;
                let identity = inode_identity(&File::from(parent.try_clone()?).metadata()?);
                ancestors.push(identity);
                namespace.push(PinnedNamespaceStep {
                    parent: namespace_parent,
                    name: (*name).to_owned(),
                    identity,
                });
            }
            _ => bail!("{label} path must be absolute and normalized"),
        }
    }
    let Component::Normal(name) = leaf else {
        bail!("{label} path has an invalid filename");
    };
    let handle = openat(
        &parent,
        *name,
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .with_context(|| format!("opening {label} without following links"))
    .map_err(|error| classify_error(error, CutoverErrorCode::FilesystemBoundaryInvalid))?;
    ancestors.push(inode_identity(&File::from(handle.try_clone()?).metadata()?));
    Ok((handle, parent, (*name).to_owned(), ancestors, namespace))
}

fn require_roots_disjoint(left: &PinnedRoot, right: &PinnedRoot) -> Result<()> {
    if left.ancestors.contains(&right.identity) || right.ancestors.contains(&left.identity) {
        return Err(typed_error(
            CutoverErrorCode::FilesystemBoundaryInvalid,
            anyhow!("bundle and source roots must not contain one another"),
        ));
    }
    Ok(())
}

fn read_external_pinned(
    path: &Path,
    label: &str,
    forbidden_roots: &[InodeIdentity],
    identities: &mut IdentitySet,
) -> Result<Vec<u8>> {
    let (parent, name, _) = open_absolute_parent_checked(path, label, forbidden_roots)
        .map_err(|error| classify_error(error, CutoverErrorCode::FilesystemBoundaryInvalid))?;
    let handle = openat(
        &parent,
        &name,
        OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .with_context(|| format!("opening {label} without following links"))
    .map_err(|error| classify_error(error, CutoverErrorCode::FilesystemBoundaryInvalid))?;
    let mut file = File::from(handle);
    if !file.metadata()?.is_file() {
        bail!("{label} is not a regular non-symlink file");
    }
    identities.insert_file(&file, label)?;
    let before = file_identity(&file)?;
    let size = file.metadata()?.len();
    let bytes = read_bounded(&mut file, size, MAX_EXTERNAL_INPUT_BYTES, label)?;
    if file_identity(&file)? != before {
        bail!("{label} identity changed while reading");
    }
    Ok(bytes)
}

fn pin_fresh_external_output(
    path: &Path,
    label: &str,
    forbidden_roots: &[InodeIdentity],
) -> Result<PinnedExternalOutput> {
    if !path.is_absolute() {
        return Err(typed_error(
            CutoverErrorCode::FilesystemBoundaryInvalid,
            anyhow!("{label} path must be absolute"),
        ));
    }
    let components: Vec<_> = path.components().collect();
    let (leaf, ancestors) = components
        .split_last()
        .ok_or_else(|| anyhow!("{label} path has no filename"))?;
    let mut directory = open(
        "/",
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )?;
    let root_identity = inode_identity(&File::from(directory.try_clone()?).metadata()?);
    if forbidden_roots.contains(&root_identity) {
        bail!("{label} is within a forbidden root");
    }
    let mut namespace = Vec::new();
    for component in ancestors {
        match component {
            Component::RootDir => continue,
            Component::Normal(component_name) => {
                let parent = directory.try_clone()?;
                directory = openat(
                    &directory,
                    *component_name,
                    OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
                    Mode::empty(),
                )
                .with_context(|| format!("opening {label} ancestor without following links"))?;
                let identity = inode_identity(&File::from(directory.try_clone()?).metadata()?);
                if forbidden_roots.contains(&identity) {
                    return Err(typed_error(
                        CutoverErrorCode::FilesystemBoundaryInvalid,
                        anyhow!("{label} must be outside all bundle and source roots"),
                    ));
                }
                namespace.push(PinnedNamespaceStep {
                    parent,
                    name: (*component_name).to_owned(),
                    identity,
                });
            }
            _ => bail!("{label} path must be absolute and normalized"),
        }
    }
    let Component::Normal(name) = leaf else {
        bail!("{label} path has an invalid filename");
    };
    match openat(
        &directory,
        *name,
        OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    ) {
        Ok(_) => {
            return Err(typed_error(
                CutoverErrorCode::OutputAlreadyExists,
                anyhow!("{label} already exists"),
            ));
        }
        Err(error) if error == rustix::io::Errno::NOENT => {}
        Err(error) => {
            return Err(typed_error(
                CutoverErrorCode::FilesystemBoundaryInvalid,
                anyhow!(error).context(format!("checking {label}")),
            ));
        }
    }
    Ok(PinnedExternalOutput {
        parent: directory,
        name: (*name).to_owned(),
        namespace,
        published: RefCell::new(None),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::commands::hub_cutover_verify::SignerKey;
    use anyhow::Context as _;
    use std::fs;

    #[test]
    fn equal_fixture_labels_materialize_equal_digests() -> Result<()> {
        let left = derive_fixture_value("same-label");
        let right = derive_fixture_value("same-label");
        assert_eq!(left, right);
        assert_eq!(left.len(), 64);
        Ok(())
    }

    #[test]
    fn preopened_tree_detects_descendant_directory_replacement() -> Result<()> {
        let temporary = tempfile::tempdir()?;
        let root_path = temporary.path().join("bundle");
        fs::create_dir_all(root_path.join("nested"))?;
        fs::write(root_path.join("nested/identity"), b"original")?;
        let mut identities = IdentitySet::default();
        let pinned = PreopenedTree::open(&root_path, "test root", &mut identities)?;

        fs::rename(root_path.join("nested"), root_path.join("moved-nested"))?;
        fs::create_dir(root_path.join("nested"))?;
        fs::write(root_path.join("nested/identity"), b"replacement")?;

        assert_eq!(pinned.read("nested/identity")?, b"original");
        assert!(pinned.assert_unchanged().is_err());
        Ok(())
    }

    #[test]
    fn preopened_tree_detects_root_replacement() -> Result<()> {
        let temporary = tempfile::tempdir()?;
        let root_path = temporary.path().join("bundle");
        fs::create_dir(&root_path)?;
        fs::write(root_path.join("identity"), b"original")?;
        let mut identities = IdentitySet::default();
        let pinned = PreopenedTree::open(&root_path, "test root", &mut identities)?;

        fs::rename(&root_path, temporary.path().join("moved-bundle"))?;
        fs::create_dir(&root_path)?;
        fs::write(root_path.join("identity"), b"replacement")?;

        assert_eq!(pinned.read("identity")?, b"original");
        assert!(pinned.assert_unchanged().is_err());
        Ok(())
    }

    #[test]
    fn preopened_tree_detects_ancestor_directory_replacement() -> Result<()> {
        let temporary = tempfile::tempdir()?;
        let ancestor = temporary.path().join("ancestor");
        let moved_ancestor = temporary.path().join("moved-ancestor");
        let root_path = ancestor.join("bundle");
        fs::create_dir_all(&root_path)?;
        fs::write(root_path.join("identity"), b"original")?;
        let mut identities = IdentitySet::default();
        let pinned = PreopenedTree::open(&root_path, "test root", &mut identities)?;

        fs::rename(&ancestor, &moved_ancestor)?;
        fs::create_dir_all(&root_path)?;
        fs::write(root_path.join("identity"), b"replacement")?;

        assert_eq!(pinned.read("identity")?, b"original");
        assert!(pinned.assert_unchanged().is_err());
        Ok(())
    }

    #[test]
    fn preopened_tree_rejects_excessive_depth_before_recursive_capture() -> Result<()> {
        let temporary = tempfile::tempdir()?;
        let root_path = temporary.path().join("bundle");
        fs::create_dir(&root_path)?;
        let mut nested = root_path.clone();
        for index in 0..=MAX_CAPTURE_DEPTH {
            nested.push(format!("d{index}"));
            fs::create_dir(&nested)?;
        }
        let mut identities = IdentitySet::default();
        let error = PreopenedTree::open(&root_path, "test root", &mut identities)
            .err()
            .context("an excessively deep tree must fail closed")?;
        assert!(error.to_string().contains("maximum depth"));
        Ok(())
    }

    #[test]
    fn capture_budget_rejects_excessive_entry_and_total_byte_counts() -> Result<()> {
        let mut entries = CaptureBudget {
            entries: MAX_CAPTURE_ENTRIES,
            bytes: 0,
        };
        assert!(entries.charge_entry().is_err());

        let mut bytes = CaptureBudget {
            entries: 0,
            bytes: MAX_CAPTURE_TOTAL_BYTES,
        };
        assert!(bytes.charge_file(1).is_err());
        Ok(())
    }

    #[test]
    fn preopened_tree_rejects_sparse_file_larger_than_limit() -> Result<()> {
        let temporary = tempfile::tempdir()?;
        let root_path = temporary.path().join("bundle");
        fs::create_dir(&root_path)?;
        File::create(root_path.join("oversized"))?.set_len(MAX_CAPTURE_FILE_BYTES + 1)?;
        let mut identities = IdentitySet::default();
        let error = PreopenedTree::open(&root_path, "test root", &mut identities)
            .err()
            .context("an oversized sparse file must fail before allocation")?;
        assert!(error.to_string().contains("maximum size"));
        Ok(())
    }

    #[test]
    fn external_input_rejects_sparse_file_larger_than_limit() -> Result<()> {
        let temporary = tempfile::tempdir()?;
        let input = temporary.path().join("input.json");
        File::create(&input)?.set_len(MAX_EXTERNAL_INPUT_BYTES + 1)?;
        let mut identities = IdentitySet::default();
        let error = read_external_pinned(&input, "external input", &[], &mut identities)
            .expect_err("an oversized external input must fail before allocation");
        assert!(error.to_string().contains("maximum size"));
        Ok(())
    }

    #[test]
    fn external_input_accepts_exact_size_limit() -> Result<()> {
        let temporary = tempfile::tempdir()?;
        let input = temporary.path().join("input.json");
        File::create(&input)?.set_len(MAX_EXTERNAL_INPUT_BYTES)?;
        let mut identities = IdentitySet::default();
        let bytes = read_external_pinned(&input, "external input", &[], &mut identities)?;
        assert_eq!(bytes.len() as u64, MAX_EXTERNAL_INPUT_BYTES);
        Ok(())
    }

    #[cfg(unix)]
    #[test]
    fn preopened_tree_rejects_symlinks_and_hardlinks() -> Result<()> {
        use std::os::unix::fs::symlink;

        let temporary = tempfile::tempdir()?;
        let symlink_root = temporary.path().join("symlink-root");
        fs::create_dir(&symlink_root)?;
        fs::write(temporary.path().join("outside"), b"outside")?;
        symlink(temporary.path().join("outside"), symlink_root.join("link"))?;
        let mut identities = IdentitySet::default();
        assert!(PreopenedTree::open(&symlink_root, "symlink root", &mut identities).is_err());

        let hardlink_root = temporary.path().join("hardlink-root");
        fs::create_dir(&hardlink_root)?;
        fs::write(hardlink_root.join("first"), b"same inode")?;
        fs::hard_link(hardlink_root.join("first"), hardlink_root.join("second"))?;
        let mut identities = IdentitySet::default();
        assert!(PreopenedTree::open(&hardlink_root, "hardlink root", &mut identities).is_err());
        Ok(())
    }

    #[test]
    fn manifest_publication_rejects_replaced_parent_namespace() -> Result<()> {
        let temporary = tempfile::tempdir()?;
        let parent = temporary.path().join("output");
        let moved_parent = temporary.path().join("moved-output");
        fs::create_dir(&parent)?;
        let output = parent.join("manifest.json");
        let pinned = pin_fresh_external_output(&output, "manifest", &[])?;

        fs::rename(&parent, &moved_parent)?;
        fs::create_dir(&parent)?;
        let error = atomic_write_external_fresh(&pinned, b"intended manifest")
            .expect_err("a replaced output namespace must fail closed");
        assert!(error.to_string().contains("ancestor identity changed"));
        assert_eq!(
            super::super::error_code(&error),
            CutoverErrorCode::FilesystemBoundaryInvalid
        );
        assert!(!output.exists());
        assert!(!moved_parent.join("manifest.json").exists());
        Ok(())
    }

    #[test]
    fn manifest_publication_rejects_post_pin_eexist_race() -> Result<()> {
        let temporary = tempfile::tempdir()?;
        let output = temporary.path().join("manifest.json");
        let pinned = pin_fresh_external_output(&output, "manifest", &[])?;
        fs::write(&output, b"racing writer")?;
        let error = atomic_write_external_fresh(&pinned, b"intended manifest")
            .expect_err("an EEXIST race must fail closed");
        let typed = error
            .chain()
            .find_map(|source| source.downcast_ref::<super::super::CutoverError>())
            .context("missing typed cutover error")?;
        assert_eq!(typed.code, CutoverErrorCode::OutputAlreadyExists);
        assert_eq!(fs::read(output)?, b"racing writer");
        Ok(())
    }

    #[test]
    fn post_publication_bundle_mutation_removes_fresh_manifest() -> Result<()> {
        let temporary = tempfile::tempdir()?;
        let root_path = temporary.path().join("bundle");
        fs::create_dir(&root_path)?;
        fs::write(root_path.join("identity"), b"original")?;
        let mut identities = IdentitySet::default();
        let mut bundle = PreopenedTree::open(&root_path, "test root", &mut identities)?;
        let output = temporary.path().join("manifest.json");
        let manifest = pin_fresh_external_output(&output, "manifest", &[bundle.root.identity])?;

        atomic_write_external_fresh(&manifest, b"signed manifest")?;
        fs::write(root_path.join("identity"), b"mutated")?;
        let error = bundle
            .assert_unchanged()
            .map_err(|error| classify_error(error, CutoverErrorCode::FilesystemBoundaryInvalid))
            .expect_err("post-publication mutation must fail final validation");
        let error = rollback_generation(&mut bundle, &manifest, error);

        assert_eq!(
            super::super::error_code(&error),
            CutoverErrorCode::FilesystemBoundaryInvalid
        );
        assert!(!output.exists());
        Ok(())
    }

    #[test]
    fn manifest_publication_preserves_unowned_preexisting_temporary() -> Result<()> {
        let temporary = tempfile::tempdir()?;
        let output = temporary.path().join("manifest.json");
        let temporary_output = temporary.path().join(format!(
            ".manifest.json.{}.aos-cutover-tmp",
            std::process::id()
        ));
        fs::write(&temporary_output, b"unowned")?;
        let pinned = pin_fresh_external_output(&output, "manifest", &[])?;
        let error = atomic_write_external_fresh(&pinned, b"intended manifest")
            .expect_err("an unowned temporary collision must fail closed");
        assert_eq!(
            super::super::error_code(&error),
            CutoverErrorCode::FilesystemBoundaryInvalid
        );
        assert_eq!(fs::read(temporary_output)?, b"unowned");
        assert!(!output.exists());
        Ok(())
    }

    #[test]
    fn owned_temporary_cleanup_preserves_concurrent_replacement() -> Result<()> {
        let temporary = tempfile::tempdir()?;
        let parent = open(
            temporary.path(),
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
        )?;
        let name = OsString::from("owned-temp");
        fs::write(temporary.path().join(&name), b"owned")?;
        let retained = File::open(temporary.path().join(&name))?;
        let identity = inode_identity(&retained.metadata()?);
        fs::rename(
            temporary.path().join(&name),
            temporary.path().join("moved-owned-temp"),
        )?;
        fs::write(temporary.path().join(&name), b"replacement")?;

        assert!(remove_owned_name(&parent, &name, &retained, identity, 1, "temporary").is_err());
        assert_eq!(fs::read(temporary.path().join(&name))?, b"replacement");
        Ok(())
    }

    #[test]
    fn retained_descriptor_link_ignores_replaced_temporary_name() -> Result<()> {
        let temporary = tempfile::tempdir()?;
        let parent = open(
            temporary.path(),
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
        )?;
        let temporary_name = temporary.path().join("publisher-temp");
        let moved_name = temporary.path().join("moved-publisher-temp");
        fs::write(&temporary_name, b"owned")?;
        let handle = File::options()
            .read(true)
            .write(true)
            .open(&temporary_name)?;
        let publication = FreshPublication {
            identity: inode_identity(&handle.metadata()?),
            handle,
        };
        fs::rename(&temporary_name, &moved_name)?;
        fs::write(&temporary_name, b"replacement")?;

        link_retained_fresh(
            &parent,
            std::ffi::OsStr::new("final"),
            &publication,
            "final",
        )?;

        assert_eq!(fs::read(temporary.path().join("final"))?, b"owned");
        assert_eq!(fs::read(&temporary_name)?, b"replacement");
        Ok(())
    }

    #[test]
    fn manifest_rollback_preserves_concurrent_replacement() -> Result<()> {
        let temporary = tempfile::tempdir()?;
        let output = temporary.path().join("manifest.json");
        let moved = temporary.path().join("moved-manifest.json");
        let manifest = pin_fresh_external_output(&output, "manifest", &[])?;
        atomic_write_external_fresh(&manifest, b"owned manifest")?;
        fs::rename(&output, &moved)?;
        fs::write(&output, b"replacement")?;

        assert!(manifest.rollback("manifest").is_err());
        assert_eq!(fs::read(&output)?, b"replacement");
        assert_eq!(fs::read(&moved)?, b"owned manifest");
        fs::remove_file(&output)?;
        fs::rename(&moved, &output)?;
        manifest.rollback("manifest")?;
        assert!(!output.exists());
        Ok(())
    }

    #[test]
    fn generated_output_rejects_oversize_before_publication() -> Result<()> {
        let temporary = tempfile::tempdir()?;
        let root_path = temporary.path().join("bundle");
        fs::create_dir(&root_path)?;
        let mut identities = IdentitySet::default();
        let mut tree = PreopenedTree::open(&root_path, "test root", &mut identities)?;
        let oversized = vec![0; usize::try_from(MAX_CAPTURE_FILE_BYTES + 1)?];
        assert!(
            tree.publish(
                "oversized",
                &oversized,
                Mode::from_bits_truncate(0o600),
                &mut identities,
            )
            .is_err()
        );
        assert!(!root_path.join("oversized").exists());
        Ok(())
    }

    #[test]
    fn generated_leaf_race_rolls_back_owned_transaction_outputs() -> Result<()> {
        let temporary = tempfile::tempdir()?;
        let root_path = temporary.path().join("bundle");
        fs::create_dir_all(root_path.join("generated"))?;
        let mut identities = IdentitySet::default();
        let mut tree = PreopenedTree::open(&root_path, "test root", &mut identities)?;
        tree.publish(
            "generated/first",
            b"first",
            Mode::from_bits_truncate(0o600),
            &mut identities,
        )?;
        fs::write(root_path.join("generated/second"), b"racing writer")?;
        let error = tree
            .publish(
                "generated/second",
                b"second",
                Mode::from_bits_truncate(0o600),
                &mut identities,
            )
            .expect_err("a late generated-leaf EEXIST race must fail closed");
        let typed = error
            .chain()
            .find_map(|source| source.downcast_ref::<super::super::CutoverError>())
            .context("missing typed cutover error")?;
        assert_eq!(typed.code, CutoverErrorCode::OutputAlreadyExists);
        tree.rollback_outputs()?;
        drop(tree);

        assert!(!root_path.join("generated/first").exists());
        assert_eq!(
            fs::read(root_path.join("generated/second"))?,
            b"racing writer"
        );
        Ok(())
    }

    #[test]
    fn generated_rollback_preserves_concurrent_replacement() -> Result<()> {
        let temporary = tempfile::tempdir()?;
        let root_path = temporary.path().join("bundle");
        fs::create_dir(&root_path)?;
        let mut identities = IdentitySet::default();
        let mut tree = PreopenedTree::open(&root_path, "test root", &mut identities)?;
        tree.publish(
            "generated",
            b"owned",
            Mode::from_bits_truncate(0o600),
            &mut identities,
        )?;
        fs::rename(
            root_path.join("generated"),
            root_path.join("moved-generated"),
        )?;
        fs::write(root_path.join("generated"), b"replacement")?;

        assert!(tree.rollback_outputs().is_err());
        assert_eq!(fs::read(root_path.join("generated"))?, b"replacement");
        assert_eq!(fs::read(root_path.join("moved-generated"))?, b"owned");
        fs::remove_file(root_path.join("generated"))?;
        fs::rename(
            root_path.join("moved-generated"),
            root_path.join("generated"),
        )?;
        tree.rollback_outputs()?;
        assert!(!root_path.join("generated").exists());
        Ok(())
    }

    #[test]
    fn manifest_root_signer_id_must_not_alias_document_authorities() {
        let key_map = SignerKeyMap {
            schema_version: "aos-cutover-signer-key-map/v1".to_owned(),
            keys: vec![
                SignerKey {
                    key_id: "key/document/example".to_owned(),
                    public_key_node_id: "key/document/example".to_owned(),
                    public_key_sha256: "00".repeat(32),
                    roles: vec!["plan".to_owned(), "report".to_owned()],
                },
                SignerKey {
                    key_id: "key/root/example".to_owned(),
                    public_key_node_id: "key/verification/example".to_owned(),
                    public_key_sha256: "11".repeat(32),
                    roles: vec!["verification".to_owned()],
                },
            ],
        };
        let error = validate_root_signer_id_separation("key/root/example", &key_map)
            .expect_err("root signer ID reuse must fail verification");
        assert_eq!(
            super::super::error_code(&error),
            CutoverErrorCode::SignerSeparationInvalid
        );
    }
}
