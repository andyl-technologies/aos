//! Signed release orchestration, container attachments, and static pack artifacts.
//!
//! This module keeps the ordered release transaction together: validation, tag
//! creation, metadata signing, pack generation, and distribution. Filesystem and
//! signing primitives belong to their dedicated modules. Release artifacts use
//! the registry object store layouts owned by `crate::registry::pack`,
//! `crate::registry::tuf`, and `crate::registry::nixcache`.

use crate::CacheUploadAuthArgs;
use crate::config::ApmConfig;
use crate::registry::channel::PartitionMap;
use crate::registry::membership::{CacheMembership, HeadMembership};
use crate::registry::{keys, nixcache, objectstore, tuf};
use crate::registry_ops::channels::{
    channel_advance_dir, channel_init_dir, select_partitions_for_advance,
};
use crate::registry_ops::config::{
    format_size, registry_cache_max_age_days, registry_upload_auth_config,
    resolve_effective_release_cache_url, resolve_registry_name, resolve_upload_urls,
    warn_on_cache_gc,
};
use crate::registry_ops::git::{git, git2_identity, git_try};
use crate::registry_ops::publish::{
    publish_to_registry_directory, validate_release_publish_metadata,
    validate_release_publish_signing_identity,
};
use crate::registry_ops::signing::{
    ResolvedSigningKey, registry_config_by_name, resolve_producer_signing_key,
    resolve_signing_key_source,
};
use crate::registry_ops::store_paths::{introspect_store_path, validate_store_path_release_policy};
use crate::registry_ops::tags::release_commit;
use crate::registry_ops::trust::derive_trust_key;
use crate::security::{key_fingerprint, parse_signing_key};
use anyhow::{Context, Result, bail};
use aos_cache::AuthOptions;
use aos_core::output::{OutputMode, Printer};
use aos_oci_types::limits::MAX_JSON_BYTES;
use aos_oci_types::{
    CONTAINER_RELEASE_SIDECAR_PATH, ContainerRelease, ContainerSignatureInput,
    definition_attribute_matches_image,
};
use sha2::{Digest as _, Sha256};
use std::collections::HashSet;
use std::fs;
use std::fs::OpenOptions;
use std::io::Write as _;
use std::path::{Path, PathBuf};

/// Options controlling [`release_registry_tree`].
///
/// Mirrors the flags of `apr release` once the optional `--store-path`
/// publish step has been handled by [`release`].
#[derive(Debug, Clone)]
pub struct ReleaseTreeOptions {
    /// Release version; doubles as the git tag name.
    pub version: semver::Version,
    /// Path to the OpenSSH Ed25519 private key used for tags and commits.
    pub signing_key: String,
    /// OpenSSH keys available for TUF role signatures.
    pub tuf_signing_keys: Vec<tuf::MetadataSigningKey>,
    /// Channel to initialize or advance after tagging, if any.
    pub channel: Option<String>,
    /// Initialize all 256 channel partitions instead of advancing a subset.
    pub init_channel: bool,
    /// Number of partitions to advance (ascending fill).
    pub count: Option<usize>,
    /// Explicit partition list to advance (decimal or hex buckets).
    pub partitions: Option<String>,
    /// Internal directory to stage static Nix cache files into.
    pub cache_dir: PathBuf,
    /// Nix cache signing key for the generated narinfos.
    pub cache_key: Option<PathBuf>,
    /// Effective public cache URL to upsert into the registry cache stack.
    pub cache_url: Option<String>,
    /// Whether `cache_url` came from an explicit `--cache-url`.
    pub cache_url_explicit: bool,
    /// Priority recorded for the cache pointer.
    pub cache_priority: u32,
    /// Whether `cache_priority` came from an explicit `--cache-priority`.
    pub cache_priority_explicit: bool,
    /// Whether the registry already has store roots or this release will
    /// publish one.
    pub has_store_roots: bool,
    /// Regenerate/reupload paths even if local or remote entries exist.
    pub no_skip: bool,
    /// Static-origin upload destinations.
    pub upload_urls: Vec<String>,
    /// Authentication used for cache and origin uploads.
    pub upload_auth: AuthOptions,
    /// Print the release plan without executing it.
    pub dry_run: bool,
    /// Reuse an existing tag and pack artifacts at HEAD instead of failing.
    pub resume: bool,
    /// Parallel compression jobs for the static cache (default: CPU count).
    pub jobs: Option<usize>,
    /// Optional package publish payload to run under the release lock.
    pub store_publish: Option<ReleaseStorePublish>,
    /// Canonical signed container sidecar validated against its Nix input.
    pub container_release: Option<ContainerReleaseAttachment>,
    /// Staged cache retention after a successful release.
    pub cache_max_age_days: u64,
}

/// Validated final container sidecar bytes to attach to one signed release.
#[derive(Debug, Clone)]
pub struct ContainerReleaseAttachment {
    /// Strict parsed sidecar used for release identity checks and reporting.
    pub release: ContainerRelease,
    /// Exact canonical bytes committed to [`CONTAINER_RELEASE_SIDECAR_PATH`].
    pub canonical_bytes: Vec<u8>,
}

/// Optional `--store-path` publish payload carried into the locked release.
#[derive(Debug, Clone)]
pub struct ReleaseStorePublish {
    pub config: ApmConfig,
    pub store_path: String,
    pub name: Option<String>,
    pub version: Option<String>,
    pub platform: Option<String>,
    pub description: Option<String>,
    pub homepage: Option<String>,
    pub license: Option<String>,
    pub maintainer: Option<String>,
    pub sysroot: bool,
    pub previous: Option<String>,
    pub source_drv: Option<String>,
    pub image_payload_paths: Vec<String>,
    pub image_disk_paths: Vec<String>,
    pub image_info_paths: Vec<String>,
    pub image_formats: Vec<String>,
    pub image_contract_schemas: Vec<String>,
    pub bless: bool,
    pub message: Option<String>,
    pub registry: String,
    /// Stable roster identity corresponding to the resolved release key.
    pub signing_key_id: Option<String>,
}

impl ReleaseStorePublish {
    pub(in crate::registry_ops) fn publish_signing_args(&self) -> (Option<&str>, Option<&str>) {
        (None, self.signing_key_id.as_deref())
    }
}

impl ReleaseTreeOptions {
    pub(in crate::registry_ops) fn publishing(&self) -> bool {
        !self.upload_urls.is_empty()
    }

    pub(in crate::registry_ops) fn should_publish_cache(&self) -> bool {
        self.publishing() && self.has_store_roots
    }
}

/// Summary of the artifacts produced by [`release_registry_tree`].
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ReleaseReport {
    /// Filename of the generated full pack, when the release kind needs one.
    pub full_pack: Option<String>,
    /// Filenames of the generated compressed thin-delta packs.
    pub deltas: Vec<String>,
    /// Static Nix cache generation report, when one was requested.
    pub cache: Option<nixcache::StaticCacheReport>,
    /// Whether the `registry.toml` cache pointer was updated and committed.
    pub cache_pointer_updated: bool,
    /// Number of channel partitions touched, when a channel was given.
    pub channel_partitions: Option<usize>,
    /// Files uploaded to the static origin, when uploads ran.
    pub uploaded_files: Option<usize>,
    /// Bytes uploaded to the static origin, when uploads ran.
    pub uploaded_bytes: Option<u64>,
}

/// Exclusive on-disk lock (`.git/apr-release.lock`) serializing release
/// publishers against one registry clone. The advisory lock is released by the
/// operating system after interruption; the persistent file is only diagnostic.
struct ReleaseLock {
    _file: fs::File,
}

impl ReleaseLock {
    fn acquire(dir: &Path) -> Result<Self> {
        let git_dir = objectstore::repo_git_dir(dir)?;
        let path = git_dir.join("apr-release.lock");
        let mut file = OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(false)
            .open(&path)
            .with_context(|| {
                format!(
                    "acquiring release lock {}; another publisher may be running",
                    path.display()
                )
            })?;
        rustix::fs::flock(&file, rustix::fs::FlockOperation::NonBlockingLockExclusive)
            .with_context(|| format!("another publisher holds {}", path.display()))?;
        file.set_len(0)?;
        writeln!(file, "pid={}", std::process::id())
            .with_context(|| format!("writing {}", path.display()))?;
        Ok(Self { _file: file })
    }
}

/// `apr release <SEMVER>` — runs the end-to-end registry release workflow.
///
/// When `--store-path` is given, first publishes that store path into the
/// release metadata under the release version (committed and SSH-signed),
/// including explicit `--source-drv` provenance when provided. Paired
/// `--container-release` and `--container-signature-input` paths bind and
/// attach one externally finalized canonical container sidecar. The command
/// then delegates to [`release_registry_tree`] to create the signed
/// release tag, generate pack artifacts, and run the optional cache,
/// channel, and upload steps. `--dry-run` prints the plan without changing
/// anything.
///
/// # Errors
///
/// Fails when the semver does not parse, the registry directory is
/// missing, the signing key cannot be resolved, the working tree is dirty,
/// a policy-bearing internal component is supplied as the store-path root,
/// an aggregate root does not directly retain its required corresponding
/// source, the publish step fails, or any delegated release step fails (see
/// [`release_registry_tree`]).
#[allow(clippy::too_many_arguments)]
pub async fn release(
    config: &ApmConfig,
    semver: &str,
    container_release: Option<&Path>,
    container_signature_input: Option<&Path>,
    store_path: Option<&str>,
    name: Option<&str>,
    version_override: Option<&str>,
    platform: Option<&str>,
    description: Option<&str>,
    homepage: Option<&str>,
    license: Option<&str>,
    maintainer: Option<&str>,
    sysroot: bool,
    previous: Option<&str>,
    source_drv: Option<&str>,
    image_payload_paths: &[String],
    image_disk_paths: &[String],
    image_info_paths: &[String],
    image_formats: &[String],
    image_contract_schemas: &[String],
    bless: bool,
    message: Option<&str>,
    channel: Option<&str>,
    init_channel: bool,
    count: Option<usize>,
    partitions: Option<&str>,
    key: Option<&str>,
    key_id: Option<&str>,
    rotate_from: Option<&Path>,
    cache_key: Option<&Path>,
    cache_url: Option<&str>,
    cache_priority: Option<u32>,
    no_skip: bool,
    upload_urls: &[String],
    auth: &CacheUploadAuthArgs,
    dry_run: bool,
    resume: bool,
    registry: Option<&str>,
    jobs: Option<usize>,
    container_layout: Option<&Path>,
    container_repository: Option<&str>,
    stage: Option<&str>,
    stage_revision: Option<u64>,
    from_stage: Option<&str>,
    printer: &Printer,
) -> Result<()> {
    let mut expected_stage_revision = stage_revision;
    if stage.is_some() && from_stage.is_some() {
        bail!("--stage and --from-stage cannot be combined");
    }
    if (stage.is_some() || from_stage.is_some())
        && (channel.is_some() || init_channel || count.is_some() || partitions.is_some())
    {
        bail!(
            "staged releases preserve channel assignments; publish the candidate, then use apr channel init or apr channel advance"
        );
    }
    if stage_revision.is_some() && stage.is_none() && from_stage.is_none() {
        bail!("--stage-revision requires --stage or --from-stage");
    }
    if let Some(id) = from_stage.or(stage.filter(|_| resume)) {
        let registry_name = resolve_registry_name(config, registry)?;
        let dir = config.scope.registries_path().join(&registry_name);
        let stages = if dry_run {
            crate::registry::staging::LocalStageStore::open_read_only(&dir)?
        } else {
            crate::registry::staging::LocalStageStore::open(&dir)?
        };
        let revision = stage_revision.context("an exact --stage-revision is required")?;
        let candidate = stages.find(id)?;
        if candidate
            .as_ref()
            .is_none_or(|candidate| candidate.revision.revision != revision)
        {
            if from_stage.is_some() {
                bail!("the exact requested stage revision is not available for publication");
            }
            let workspace = stages.workspace(id, revision)?;
            if !preparation_checkpoint_path(&workspace)?.is_file() {
                bail!("the requested stage revision has no preparation checkpoint");
            }
            expected_stage_revision = revision.checked_sub(1).filter(|value| *value > 0);
        } else {
            let candidate = candidate.context("stage disappeared while selecting its revision")?;
            if candidate.revision.release_id != semver {
                bail!("requested release version differs from the staged candidate");
            }
            let destinations = resolve_upload_urls(config, &registry_name, upload_urls);
            let auth =
                auth.auth_options_with_config(registry_upload_auth_config(config, &registry_name));
            if dry_run {
                printer.json(&serde_json::to_value(candidate)?);
                return Ok(());
            }
            let record = if from_stage.is_some() {
                if store_path.is_some() || container_release.is_some() || channel.is_some() {
                    bail!(
                        "candidate publication uses its exact prepared catalog and channel pointers"
                    );
                }
                stages.publish(id, revision, &destinations, &auth).await?
            } else {
                stages.upload(id, revision, &destinations, &auth).await?
            };
            print_stage_record(&record, printer)?;
            return Ok(());
        }
    }
    validate_release_publish_metadata(store_path, description, license, maintainer)?;
    validate_release_publish_signing_identity(store_path, key_id)?;

    let version = semver::Version::parse(semver)
        .with_context(|| format!("parsing release semver '{semver}'"))?;
    let container_release =
        load_container_release_attachment(&version, container_release, container_signature_input)?;
    let container_graph = match (&container_release, container_layout) {
        (Some(attachment), Some(layout)) => {
            Some(crate::registry::container_stage::prepare_container_stage(
                layout,
                container_repository.unwrap_or(&attachment.release.identity.image),
                &attachment.release,
            )?)
        }
        (None, Some(_)) => bail!("--container-layout requires a validated container release"),
        (Some(_), None) if stage.is_some() => {
            bail!("container staging requires --container-layout")
        }
        _ => None,
    };
    if let Some(store_path) = store_path {
        let info = introspect_store_path(store_path)?;
        validate_store_path_release_policy(&info)?;
    }
    let registry_name = resolve_registry_name(config, registry)?;
    let dir = config.scope.registries_path().join(&registry_name);
    if !dir.exists() {
        bail!("registry directory does not exist: {}", dir.display());
    }
    let signing_key = resolve_producer_signing_key(config, &dir, &registry_name, key, key_id)?;
    let (_tuf_key_owners, tuf_signing_keys) =
        resolve_tuf_metadata_signing_keys(config, &dir, &registry_name, &signing_key, rotate_from)?;

    let upload_auth =
        auth.auth_options_with_config(registry_upload_auth_config(config, &registry_name));
    let resolved_upload_urls = resolve_upload_urls(config, &registry_name, upload_urls);
    let has_store_roots = store_path.is_some() || nixcache::registry_has_store_roots(&dir)?;
    let cache_url_explicit = cache_url.is_some();
    // The preceding published catalog is composed in the isolated workspace.
    // Resolve implicit cache policy there, where inherited roots are visible.
    let effective_cache_url =
        resolve_effective_release_cache_url(cache_url, &resolved_upload_urls, false)?;
    let store_publish = store_path.map(|store_path| ReleaseStorePublish {
        config: config.clone(),
        store_path: store_path.to_string(),
        name: name.map(ToString::to_string),
        version: version_override.map(ToString::to_string),
        platform: platform.map(ToString::to_string),
        description: description.map(ToString::to_string),
        homepage: homepage.map(ToString::to_string),
        license: license.map(ToString::to_string),
        maintainer: maintainer.map(ToString::to_string),
        sysroot,
        previous: previous.map(ToString::to_string),
        source_drv: source_drv.map(ToString::to_string),
        image_payload_paths: image_payload_paths.to_vec(),
        image_disk_paths: image_disk_paths.to_vec(),
        image_info_paths: image_info_paths.to_vec(),
        image_formats: image_formats.to_vec(),
        image_contract_schemas: image_contract_schemas.to_vec(),
        bless,
        message: message.map(ToString::to_string),
        registry: registry_name.clone(),
        signing_key_id: key_id.map(ToString::to_string),
    });
    let options = ReleaseTreeOptions {
        version,
        signing_key: signing_key.path().to_string(),
        tuf_signing_keys,
        channel: channel.map(ToString::to_string),
        init_channel,
        count,
        partitions: partitions.map(ToString::to_string),
        cache_dir: config.registry_cache_path(&registry_name),
        cache_key: cache_key.map(Path::to_path_buf),
        cache_url: effective_cache_url,
        cache_url_explicit,
        cache_priority: cache_priority.unwrap_or(40),
        cache_priority_explicit: cache_priority.is_some(),
        has_store_roots,
        no_skip,
        upload_urls: resolved_upload_urls,
        upload_auth,
        dry_run,
        resume,
        jobs,
        store_publish,
        container_release,
        cache_max_age_days: registry_cache_max_age_days(config, &registry_name),
    };

    if let Some(id) = stage {
        stage_registry_release(
            &dir,
            &registry_name,
            id,
            expected_stage_revision,
            &options,
            container_layout,
            container_graph.as_ref(),
            printer,
        )
        .await?;
    } else {
        release_registry_tree(&dir, &registry_name, &options, printer).await?;
    }
    Ok(())
}

fn print_stage_record(
    record: &crate::registry::staging::StageRecord,
    printer: &Printer,
) -> Result<()> {
    if printer.mode() == OutputMode::Json {
        printer.json(&serde_json::to_value(record)?);
    } else {
        printer.success(&format!(
            "Stage {} revision {} {:?}: {} at {}.",
            record.revision.id,
            record.revision.revision,
            record.state,
            record.revision.release_id,
            record.revision.commit
        ));
    }
    Ok(())
}

async fn stage_registry_release(
    dir: &Path,
    registry: &str,
    id: &str,
    expected_revision: Option<u64>,
    options: &ReleaseTreeOptions,
    container_layout: Option<&Path>,
    container_graph: Option<&aos_registry_surface::staging::StageContainerGraph>,
    printer: &Printer,
) -> Result<()> {
    if options.dry_run {
        print_release_plan(dir, registry, options, printer);
        return Ok(());
    }
    let stages = crate::registry::staging::LocalStageStore::open(dir)?;
    let _source_lock = ReleaseLock::acquire(dir)?;
    let source_branch = git2::Repository::open(dir)?
        .head()?
        .shorthand()
        .context("stage authoring HEAD is not a named branch")?
        .to_string();
    stages.require_authoring_branch(&source_branch)?;
    ensure_release_worktree_clean(dir)?;
    let revision = expected_revision
        .map_or(Some(1), |value| value.checked_add(1))
        .context("stage revision overflow")?;
    if let Some(current) = stages.find(id)? {
        if Some(current.revision.revision) != expected_revision {
            bail!(
                "stage revision changed; supply --stage-revision with the exact current revision"
            );
        }
    } else if expected_revision.is_some() {
        bail!("stage does not exist; omit --stage-revision for its first revision");
    }
    let workspace = stages.workspace(id, revision)?;
    let parent = workspace
        .parent()
        .context("candidate workspace lacks a parent")?;
    fs::create_dir_all(parent)?;
    let mut prepared = options.clone();
    prepared.cache_dir = stages.cache_path(id, revision)?;
    let checkpoint =
        PreparationCheckpoint::new(dir, registry, &source_branch, options, container_graph)?;
    let signed_candidate = restore_preparation_checkpoint(&workspace, &checkpoint, options)?;
    if !signed_candidate {
        git2::build::RepoBuilder::new()
            .clone_local(git2::build::CloneLocal::NoLinks)
            .clone(dir.to_str().context("non-UTF-8 registry path")?, &workspace)?;
        let mut private_config = git2::Repository::open(&workspace)?.config()?;
        private_config.set_str("user.name", &checkpoint.author_name)?;
        private_config.set_str("user.email", &checkpoint.author_email)?;
        if git(&workspace, &["rev-parse", "HEAD"])? != checkpoint.source_commit {
            bail!("source branch moved while creating the candidate workspace");
        }
        for relative in ["aos-image-staging", "channels"] {
            let source = objectstore::repo_git_dir(dir)?.join(relative);
            if source.is_dir() {
                copy_stage_directory(
                    &source,
                    &objectstore::repo_git_dir(&workspace)?.join(relative),
                )?;
            }
        }
    }
    prepared.resume = signed_candidate;
    if signed_candidate {
        // The signed tree already contains the reviewed catalog and cache
        // pointer. Retrying artifact generation must never reauthor it.
        prepared.store_publish = None;
    }
    let preparation_printer = Printer::new(0, printer.mode() == OutputMode::Quiet, false);
    prepare_release_registry_tree(&workspace, registry, &prepared, false, &preparation_printer)
        .await?;
    let graph_objects = container_graph
        .map(crate::registry::container_stage::graph_objects)
        .unwrap_or_default();
    if let (Some(layout), Some(graph)) = (container_layout, container_graph) {
        crate::registry::container_stage::capture_layout_objects(
            layout,
            graph,
            &stages.objects_path(),
        )?;
    }
    let mut canonical_registry = registry.to_string();
    for destination in &options.upload_urls {
        if let Some(target) = crate::registry::staging::hub::target(destination, registry).await? {
            if canonical_registry != registry && canonical_registry != target.registry {
                bail!("stage destinations resolve to different canonical registries");
            }
            canonical_registry = target.registry;
        }
    }
    let captured = stages
        .capture(
            id,
            &canonical_registry,
            &options.version.to_string(),
            &source_branch,
            &workspace,
            expected_revision,
            Some(&prepared.cache_dir),
            &options.upload_urls,
            &options.upload_auth,
            container_graph,
            &graph_objects,
        )
        .await?;
    let record = stages
        .upload(
            id,
            captured.revision.revision,
            &options.upload_urls,
            &options.upload_auth,
        )
        .await?;
    print_stage_record(&record, printer)
}

fn copy_stage_directory(source: &Path, target: &Path) -> Result<()> {
    fs::create_dir_all(target)?;
    for entry in fs::read_dir(source)? {
        let entry = entry?;
        let path = entry.path();
        let metadata = fs::symlink_metadata(&path)?;
        let destination = target.join(entry.file_name());
        if metadata.is_dir() {
            copy_stage_directory(&path, &destination)?;
        } else if metadata.is_file() {
            fs::copy(path, destination)?;
        } else {
            bail!("candidate staging contains a symlink or special file");
        }
    }
    Ok(())
}

/// Binds an interrupted private preparation to its exact authoring inputs.
#[derive(Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
struct PreparationCheckpoint {
    registry: String,
    source_branch: String,
    source_commit: String,
    release_id: String,
    input_digest: String,
    author_name: String,
    author_email: String,
}

impl PreparationCheckpoint {
    fn new(
        directory: &Path,
        registry: &str,
        source_branch: &str,
        options: &ReleaseTreeOptions,
        container: Option<&aos_registry_surface::staging::StageContainerGraph>,
    ) -> Result<Self> {
        // Credentials and transfer concurrency are effects, so changes to
        // those inputs do not change the prepared release's identity.
        let inputs = serde_json::json!({
            "signing_key": options.signing_key,
            "metadata_keys": format!("{:?}", options.tuf_signing_keys),
            "store_publish": options.store_publish.as_ref().map(|publish| serde_json::json!({
                "store_path": publish.store_path,
                "name": publish.name,
                "version": publish.version,
                "platform": publish.platform,
                "description": publish.description,
                "homepage": publish.homepage,
                "license": publish.license,
                "maintainer": publish.maintainer,
                "sysroot": publish.sysroot,
                "previous": publish.previous,
                "source_drv": publish.source_drv,
                "image_payload_paths": publish.image_payload_paths,
                "image_disk_paths": publish.image_disk_paths,
                "image_info_paths": publish.image_info_paths,
                "image_formats": publish.image_formats,
                "image_contract_schemas": publish.image_contract_schemas,
                "bless": publish.bless,
                "message": publish.message,
                "registry": publish.registry,
                "signing_key_id": publish.signing_key_id,
            })),
            "container": container,
            "container_release": options.container_release.as_ref().map(|value| &value.canonical_bytes),
            "cache_key": options.cache_key,
            "cache_url": options.cache_url,
            "cache_priority": options.cache_priority,
            "cache_url_explicit": options.cache_url_explicit,
            "cache_priority_explicit": options.cache_priority_explicit,
            "destinations": options.upload_urls,
        });
        let input_digest = format!(
            "sha256:{}",
            hex::encode(Sha256::digest(serde_json::to_vec(&inputs)?))
        );
        let repository = git2::Repository::open(directory)?;
        // Resolve the identity like every other registry commit, so hermetic
        // environments may supply it through GIT_AUTHOR_*/GIT_COMMITTER_*.
        let author = git2_identity(&repository)?;
        Ok(Self {
            registry: registry.to_string(),
            source_branch: source_branch.to_string(),
            source_commit: git(directory, &["rev-parse", "HEAD"])?,
            release_id: options.version.to_string(),
            input_digest,
            author_name: author
                .name()
                .context("registry author lacks a name")?
                .to_string(),
            author_email: author
                .email()
                .context("registry author lacks an email")?
                .to_string(),
        })
    }
}

fn preparation_checkpoint_path(workspace: &Path) -> Result<PathBuf> {
    let parent = workspace
        .parent()
        .context("candidate workspace lacks a parent")?;
    let name = workspace
        .file_name()
        .context("candidate workspace lacks a revision")?;
    Ok(parent.join(format!("{}.preparation.json", name.to_string_lossy())))
}

/// Recovers only checkpoint-owned private bytes, retaining signed identities.
fn restore_preparation_checkpoint(
    workspace: &Path,
    checkpoint: &PreparationCheckpoint,
    options: &ReleaseTreeOptions,
) -> Result<bool> {
    let path = preparation_checkpoint_path(workspace)?;
    if path.exists() {
        if fs::metadata(&path)?.len() > 1024 * 1024 {
            bail!("stage preparation checkpoint exceeds its size limit");
        }
        let saved: PreparationCheckpoint = serde_json::from_slice(&fs::read(&path)?)?;
        if saved != *checkpoint {
            bail!(
                "interrupted preparation has different authoring inputs; restore its exact source commit and release options before resuming"
            );
        }
    } else {
        if workspace.exists() {
            bail!(
                "candidate workspace exists without a preparation checkpoint; inspect it before reuse"
            );
        }
        let mut temporary =
            tempfile::NamedTempFile::new_in(path.parent().context("checkpoint lacks a parent")?)?;
        temporary.write_all(&serde_json::to_vec(checkpoint)?)?;
        temporary.as_file().sync_all()?;
        temporary
            .persist_noclobber(&path)
            .map_err(|error| error.error)?;
        fs::File::open(path.parent().context("checkpoint lacks a parent")?)?.sync_all()?;
    }

    if !workspace.exists() {
        return Ok(false);
    }
    if let Ok(repository) = git2::Repository::open(workspace) {
        if crate::registry::release::RegistryReleaseLifecycle::restore_signed_candidate(
            workspace,
            &checkpoint.registry,
            &checkpoint.release_id,
            &checkpoint.source_commit,
        )? {
            return Ok(true);
        }
        let reference = format!("refs/tags/{}", options.version);
        if repository.find_reference(&reference).is_ok() {
            bail!("interrupted signed candidate lacks its original provider receipt");
        }
    }

    // No signed identity exists yet. Recreate only this private workspace from
    // the checkpoint's unchanged source; partial authoring is never published.
    fs::remove_dir_all(workspace)?;
    Ok(false)
}

/// Loads and binds an optional externally signed container-release attachment.
///
/// Both paths must be supplied together. The canonical sidecar must match its
/// Nix-produced signature input, the requested release version, and the
/// initial `aos` package/image publication policy.
///
/// # Errors
///
/// Returns an error when only one path is supplied, either input is malformed
/// or noncanonical, their signed identities differ, or the release, package,
/// image, or Nix definition identity violates policy.
pub fn load_container_release_attachment(
    version: &semver::Version,
    release_path: Option<&Path>,
    signature_input_path: Option<&Path>,
) -> Result<Option<ContainerReleaseAttachment>> {
    let (release_path, signature_input_path) = match (release_path, signature_input_path) {
        (None, None) => return Ok(None),
        (Some(_), None) => {
            bail!("--container-release requires the paired --container-signature-input")
        }
        (None, Some(_)) => {
            bail!("--container-signature-input requires the paired --container-release")
        }
        (Some(release_path), Some(signature_input_path)) => (release_path, signature_input_path),
    };

    let canonical_bytes = read_bounded_container_json(release_path, "container release sidecar")?;
    let release = ContainerRelease::from_canonical_json(&canonical_bytes)
        .context("validating --container-release")?;
    let signature_input_bytes =
        read_bounded_container_json(signature_input_path, "container signature input")?;
    let signature_input = ContainerSignatureInput::from_canonical_json(&signature_input_bytes)
        .context("validating --container-signature-input")?;
    signature_input
        .validate_final_release(&release)
        .context("binding container release to its Nix signature input")?;

    let release_version = version.to_string();
    if release.identity.release != release_version {
        bail!(
            "container release identity '{}' does not match apr release semver '{}'",
            release.identity.release,
            release_version,
        );
    }
    if release.identity.package != "aos" || release.identity.image != "aos" {
        bail!("the initial container release policy requires package 'aos' and image 'aos'");
    }
    if !definition_attribute_matches_image(&release.nix.definition.attribute, "aos") {
        bail!(
            "the initial container release policy requires the system-owned 'aos' Nix definition attribute"
        );
    }

    Ok(Some(ContainerReleaseAttachment {
        release,
        canonical_bytes,
    }))
}

fn read_bounded_container_json(path: &Path, label: &str) -> Result<Vec<u8>> {
    let metadata = fs::symlink_metadata(path)
        .with_context(|| format!("reading {label} metadata {}", path.display()))?;
    if !metadata.file_type().is_file() {
        bail!(
            "{label} is not a non-symlink regular file: {}",
            path.display()
        );
    }
    let size = usize::try_from(metadata.len()).unwrap_or(usize::MAX);
    if size > MAX_JSON_BYTES {
        bail!(
            "{label} is {size} bytes; the limit is {MAX_JSON_BYTES} bytes: {}",
            path.display()
        );
    }
    let bytes = fs::read(path).with_context(|| format!("reading {label} {}", path.display()))?;
    if bytes.len() > MAX_JSON_BYTES {
        bail!(
            "{label} grew to {} bytes; the limit is {MAX_JSON_BYTES} bytes: {}",
            bytes.len(),
            path.display()
        );
    }
    Ok(bytes)
}

/// Publish a release's `--store-path` into the registry tree.
///
/// The published package version is **not** the release tag. Like a plain
/// `apr publish`, it defaults to the store-path basename and can be overridden
/// explicitly, so a registry release tag and the package versions it snapshots
/// remain independent.
async fn publish_release_store_path(
    publish_opts: &ReleaseStorePublish,
    dir: &Path,
    printer: &Printer,
) -> Result<()> {
    let (key, key_id) = publish_opts.publish_signing_args();
    publish_to_registry_directory(
        &publish_opts.config,
        dir,
        &publish_opts.registry,
        &publish_opts.store_path,
        publish_opts.name.as_deref(),
        publish_opts.version.as_deref(),
        publish_opts.platform.as_deref(),
        publish_opts.description.as_deref(),
        publish_opts.homepage.as_deref(),
        publish_opts.license.as_deref(),
        publish_opts.maintainer.as_deref(),
        publish_opts.sysroot,
        publish_opts.previous.as_deref(),
        publish_opts.source_drv.as_deref(),
        &publish_opts.image_payload_paths,
        &publish_opts.image_disk_paths,
        &publish_opts.image_info_paths,
        &publish_opts.image_formats,
        &publish_opts.image_contract_schemas,
        publish_opts.bless,
        false,
        true,
        publish_opts.message.as_deref(),
        key,
        key_id,
        None,
        printer,
    )
    .await
}

/// Executes the release workflow against a registry directory.
///
/// Under an exclusive release lock, this: rejects up front a release whose
/// tag already exists (unless `resume`), so a doomed release fails before any
/// mutating work; optionally commits a canonical container sidecar and
/// publishes `--store-path` (whose package version comes from the store path,
/// independent of the release tag); optionally commits a `registry.toml`
/// cache pointer; creates the signed semver release
/// tag at HEAD (or reuses an existing tag there when `resume` is set);
/// generates the release pack artifacts under `.git/releases/<version>/` — a
/// full pack for major/minor releases plus zstd-compressed thin deltas from
/// the prior releases selected by the delta scheme; optionally generates the
/// static Nix cache; initializes or advances the rollout channel; and
/// uploads the static origin files. The dumb-HTTP object store is
/// refreshed after each ref-moving step. With `dry_run`, the plan is
/// printed and nothing is modified.
///
/// Returns a [`ReleaseReport`] describing the produced artifacts.
///
/// # Errors
///
/// Fails when the option combination is invalid (`--init-channel` or
/// partition selectors without `--channel`, cache flags without a publishing
/// destination or store roots); when another publisher holds the release
/// lock; when the working tree is dirty; when the tag or pack artifacts
/// already exist without `resume` (or the tag exists at a different commit);
/// or when pack generation, cache generation, channel updates, or uploads
/// fail.
pub async fn release_registry_tree(
    dir: &Path,
    registry_name: &str,
    options: &ReleaseTreeOptions,
    printer: &Printer,
) -> Result<ReleaseReport> {
    prepare_release_registry_tree(dir, registry_name, options, true, printer).await
}

async fn prepare_release_registry_tree(
    dir: &Path,
    registry_name: &str,
    options: &ReleaseTreeOptions,
    publish_origin: bool,
    printer: &Printer,
) -> Result<ReleaseReport> {
    if options.dry_run {
        validate_release_options(options)?;
        if printer.mode() == OutputMode::Json {
            printer.json(&release_result_json(
                "planned",
                registry_name,
                dir,
                options,
                &ReleaseReport::default(),
            ));
        } else {
            print_release_plan(dir, registry_name, options, printer);
        }
        return Ok(ReleaseReport::default());
    }

    let _lock = ReleaseLock::acquire(dir)?;
    objectstore::assert_sha256(dir)?;
    ensure_release_worktree_clean(dir)?;
    ensure_release_tag_available(dir, &options.version, options.resume)?;
    let base_commit = git(dir, &["rev-parse", "HEAD"])?;
    let predecessor_commit = if existing_release_tag_commit(dir, &options.version)?.is_none() {
        crate::registry::release::RegistryReleaseLifecycle::prepare_lineage(dir, &options.version)?
    } else {
        None
    };
    let effective_options = composed_cache_options(dir, options)?;
    let options = &effective_options;
    validate_release_options(options)?;
    attach_container_release(dir, registry_name, options, printer)?;

    let already_signed = existing_release_tag_commit(dir, &options.version)?.is_some();
    if !already_signed && let Some(publish) = &options.store_publish {
        publish_release_store_path(publish, dir, printer).await?;
    }

    // Publishing cache unit (§9): generate into the internal staging dir, push
    // the cache bytes, and only then commit the advertising pointer. A failed
    // upload aborts the release here with no tag and no `[caches]` change; a
    // committed pointer lands before the tag so it is part of the snapshot.
    let mut cache_report = None;
    let mut cache_pointer_updated = false;
    if !already_signed && options.should_publish_cache() {
        let membership = if options.no_skip || !publish_origin {
            None
        } else {
            Some(
                HeadMembership::from_urls(&options.upload_urls, &options.upload_auth)
                    .await
                    .context("creating remote cache membership checker")?,
            )
        };
        let membership_ref = membership
            .as_ref()
            .map(|membership| membership as &dyn CacheMembership);
        let generated = nixcache::generate_static_cache(
            dir,
            &options.cache_dir,
            options.cache_key.as_deref(),
            options.cache_priority,
            options.jobs,
            membership_ref,
            options.no_skip,
            printer,
        )
        .await?;
        printer.success(&format!(
            "Generated static cache: {} narinfos, {} NARs ({} reused, {} remote-skipped) in {}",
            generated.narinfos,
            generated.nars,
            generated.local_reused,
            generated.remote_skipped,
            generated.output_dir.display(),
        ));

        // Cache bytes first (NARs, then member narinfos, then root narinfos).
        // On failure the `?` aborts before any tag or pointer exists.
        if publish_origin {
            nixcache::upload_static_cache_to_all(
                &options.cache_dir,
                &options.upload_urls,
                &options.upload_auth,
                &generated.root_hashes,
                options.no_skip,
                printer,
            )
            .await?;
        }

        // Advertise only when at least one narinfo is present on the
        // destinations — freshly uploaded (`narinfos`) or already there
        // (`remote_skipped`). Never advertise an empty or unpublished cache.
        if let Some(cache_url) = &options.cache_url
            && generated.narinfos + generated.remote_skipped > 0
            && nixcache::upsert_registry_cache(dir, cache_url, options.cache_priority)?
        {
            cache_pointer_updated = true;
            printer.info(&format!("Updated registry.toml [caches] -> {cache_url}"));
        }
        cache_report = Some(generated);
    }

    let release_tag_exists = existing_release_tag_commit(dir, &options.version)?.is_some();
    if !release_tag_exists {
        write_tuf_release_metadata(dir, registry_name, options, printer)?;
    } else if options.resume {
        printer.info(&format!(
            "Release tag {} already exists; leaving committed TUF metadata unchanged.",
            options.version,
        ));
    }

    let artifacts = if release_tag_exists {
        let head = git(dir, &["rev-parse", "HEAD"])?;
        ensure_resumed_release_tag(dir, options, &head, printer)?;
        crate::registry::release::RegistryReleaseLifecycle::complete_signed_release(
            dir,
            &options.version,
            true,
            printer,
        )
        .await?
    } else {
        use crate::registry::release::{
            KeyPathRegistryObjectSigner, PreparedRegistryRelease, RegistryCommitIdentity,
            RegistryReleaseArtifacts, RegistryReleaseLifecycle,
        };
        let plan_digest = format!(
            "sha256:{}",
            hex::encode(Sha256::digest(
                format!(
                    "apr.registry-release/v1\0{registry_name}\0{}\0{base_commit}",
                    options.version
                )
                .as_bytes()
            ))
        );
        let prepared = PreparedRegistryRelease::from_authored_tree(
            dir,
            registry_name,
            &options.version.to_string(),
            &plan_digest,
            &base_commit,
            predecessor_commit,
        )?;
        let trust_key = derive_trust_key(registry_name, &options.signing_key)?;
        let key_id = tuf_signing_key_id(dir, &trust_key)?;
        let mut signer = KeyPathRegistryObjectSigner::new(
            dir,
            registry_name,
            Path::new(&options.signing_key),
            &key_id,
        )?;
        let repository = git2::Repository::open(dir)?;
        let signature = git2_identity(&repository)?;
        let identity = RegistryCommitIdentity {
            name: signature
                .name()
                .context("registry author identity lacks a name")?
                .to_string(),
            email: signature
                .email()
                .context("registry author identity lacks an email")?
                .to_string(),
            unix_seconds: signature.when().seconds(),
            offset_minutes: signature.when().offset_minutes(),
        };
        let finalized =
            RegistryReleaseLifecycle::finalize_prepared(&prepared, &identity, &mut signer).await?;
        RegistryReleaseArtifacts {
            full_pack: finalized.full_pack,
            deltas: finalized.deltas,
        }
    };

    let mut report = ReleaseReport {
        full_pack: artifacts.full_pack,
        deltas: artifacts.deltas,
        ..ReleaseReport::default()
    };
    report.cache_pointer_updated = cache_pointer_updated;
    report.cache = cache_report;

    if let Some(channel) = &options.channel {
        if options.init_channel {
            let partitions = channel_init_dir(
                dir,
                channel,
                &options.version,
                &options.signing_key,
                printer,
            )?;
            report.channel_partitions = Some(partitions);
        } else {
            let partitions = channel_advance_dir(
                dir,
                channel,
                &options.version,
                options.count,
                options.partitions.as_deref(),
                &options.signing_key,
                printer,
            )?;
            report.channel_partitions = Some(partitions);
        }
    }

    // Static git origin last: objects, refs, channel payloads, and the
    // committed cache pointer. Cache bytes, when any, were already uploaded
    // above, so this call carries the git surface only (`cache_dir = None`).
    if publish_origin && !options.upload_urls.is_empty() {
        let surface = crate::registry::release::collect_static_surface(dir)?;
        let upload = crate::registry::release::RegistryReleaseLifecycle::upload(
            dir,
            &surface,
            &options.upload_urls,
            &options.upload_auth,
            options.no_skip,
            printer,
        )
        .await?;
        report.uploaded_files = Some(upload.files);
        report.uploaded_bytes = Some(upload.bytes);
        printer.success(&format!(
            "Uploaded {} static origin file(s) ({}).",
            upload.files,
            format_size(upload.bytes),
        ));
    }

    if publish_origin {
        printer.success(&format!("Released {registry_name} {}.", options.version));
    } else {
        printer.info(&format!(
            "Prepared signed candidate {registry_name} {}.",
            options.version
        ));
    }
    if publish_origin && printer.mode() == OutputMode::Json {
        printer.json(&release_result_json(
            "released",
            registry_name,
            dir,
            options,
            &report,
        ));
    }
    if publish_origin && let Some(cache) = &report.cache {
        warn_on_cache_gc(dir, &cache.output_dir, options.cache_max_age_days, printer);
    }
    Ok(report)
}

/// Resolves cache policy against the complete composed candidate catalog.
fn composed_cache_options(
    directory: &Path,
    options: &ReleaseTreeOptions,
) -> Result<ReleaseTreeOptions> {
    let mut effective = options.clone();
    effective.has_store_roots |= nixcache::registry_has_store_roots(directory)?;
    if !effective.cache_url_explicit && effective.has_store_roots {
        let root: aos_registry_surface::manifest::RegistryRootConfig =
            toml::from_str(&fs::read_to_string(directory.join("registry.toml"))?)?;
        if let Some(primary) = root.cache_entries().first() {
            effective.cache_url = Some(primary.url.clone());
        }
    }
    if effective.cache_url.is_none() {
        effective.cache_url = resolve_effective_release_cache_url(
            None,
            &effective.upload_urls,
            effective.has_store_roots,
        )?;
    }
    Ok(effective)
}

fn write_tuf_release_metadata(
    dir: &Path,
    registry_name: &str,
    options: &ReleaseTreeOptions,
    printer: &Printer,
) -> Result<bool> {
    let tuf_signing_keys = if options.tuf_signing_keys.is_empty() {
        let trust_key = derive_trust_key(registry_name, &options.signing_key)?;
        vec![tuf::MetadataSigningKey {
            key_id: tuf_signing_key_id(dir, &trust_key)?,
            key_path: PathBuf::from(&options.signing_key),
            key: trust_key,
            role_key: true,
        }]
    } else {
        options.tuf_signing_keys.clone()
    };
    let changed = tuf::write_release_metadata_worktree(
        dir,
        registry_name,
        &options.version,
        &tuf_signing_keys,
    )?;
    if changed {
        printer.success("Updated TUF release metadata.");
    }
    Ok(changed)
}

fn tuf_signing_key_id(dir: &Path, trust_key: &str) -> Result<String> {
    if let Some(roster) = keys::load_keys_toml(dir)? {
        if let Some(entry) = roster.active.iter().find(|entry| entry.key == trust_key) {
            return Ok(entry.id.clone());
        }
    }
    let (_registry, _algorithm, public_key) = parse_signing_key(trust_key)?;
    Ok(format!("key-{}", key_fingerprint(&public_key)))
}

fn resolve_tuf_metadata_signing_keys(
    config: &ApmConfig,
    dir: &Path,
    registry_name: &str,
    primary: &ResolvedSigningKey,
    rotate_from: Option<&Path>,
) -> Result<(Vec<ResolvedSigningKey>, Vec<tuf::MetadataSigningKey>)> {
    let primary_trust_key = derive_trust_key(registry_name, primary.path())?;
    let primary_key = tuf::MetadataSigningKey {
        key_id: tuf_signing_key_id(dir, &primary_trust_key)?,
        key_path: PathBuf::from(primary.path()),
        key: primary_trust_key.clone(),
        role_key: true,
    };
    let mut metadata_keys = vec![primary_key];
    let mut owners = Vec::new();

    // An operator rotating the root signing key supplies the previous root key
    // explicitly with `--rotate-from`; it co-signs the new root so the
    // previous-root-role authorization check accepts the transition. It is not
    // a member of the new root policy (role_key=false). Its id must be a key id
    // in the *current* (previous) root role, matched by public key — a freshly
    // derived id would not satisfy the previous-root authorization check.
    if let Some(rotate_from) = rotate_from {
        let rotate_from_str = rotate_from.to_str().ok_or_else(|| {
            anyhow::anyhow!(
                "--rotate-from path is not valid UTF-8: {}",
                rotate_from.display()
            )
        })?;
        let rotate_public = derive_trust_key(registry_name, rotate_from_str)?;
        if rotate_public == primary_trust_key {
            bail!(
                "--rotate-from key is the same as the release signing key; \
                 omit --rotate-from when not rotating the root key"
            );
        }
        let previous_key_id = tuf::worktree_root_role_keys(dir)?
            .into_iter()
            .find(|(_, public)| *public == rotate_public)
            .map(|(key_id, _)| key_id)
            .ok_or_else(|| {
                anyhow::anyhow!(
                    "--rotate-from key is not a current root-role key; \
                     pass the previous root key being rotated away from"
                )
            })?;
        metadata_keys.push(tuf::MetadataSigningKey {
            key_id: previous_key_id,
            key_path: rotate_from.to_path_buf(),
            key: rotate_public,
            role_key: false,
        });
    }

    let Some(roster) = keys::load_keys_toml(dir)? else {
        return Ok((owners, metadata_keys));
    };
    let Some(registry_config) = registry_config_by_name(config, registry_name) else {
        return Ok((owners, metadata_keys));
    };
    let active_key_ids = roster
        .active
        .iter()
        .map(|entry| entry.id.clone())
        .collect::<HashSet<_>>();
    for entry in &roster.active {
        if metadata_keys.iter().any(|key| key.key == entry.key) {
            continue;
        }
        let Some(source) = registry_config.signing_keys.get(&entry.id) else {
            continue;
        };
        let resolved = resolve_signing_key_source(&entry.id, source)?;
        let trust_key = derive_trust_key(registry_name, resolved.path())?;
        if trust_key != entry.key {
            bail!(
                "configured private key for signing key id '{}' derives '{}', but keys.toml declares '{}'",
                entry.id,
                trust_key,
                entry.key,
            );
        }
        metadata_keys.push(tuf::MetadataSigningKey {
            key_id: entry.id.clone(),
            key_path: PathBuf::from(resolved.path()),
            key: trust_key,
            role_key: true,
        });
        owners.push(resolved);
    }
    for key_id in tuf::worktree_root_role_key_ids(dir)? {
        if active_key_ids.contains(&key_id) || metadata_keys.iter().any(|key| key.key_id == key_id)
        {
            continue;
        }
        let Some(source) = registry_config.signing_keys.get(&key_id) else {
            continue;
        };
        let resolved = resolve_signing_key_source(&key_id, source)?;
        let trust_key = derive_trust_key(registry_name, resolved.path())?;
        if metadata_keys.iter().any(|key| key.key == trust_key) {
            owners.push(resolved);
            continue;
        }
        metadata_keys.push(tuf::MetadataSigningKey {
            key_id,
            key_path: PathBuf::from(resolved.path()),
            key: trust_key,
            role_key: false,
        });
        owners.push(resolved);
    }

    Ok((owners, metadata_keys))
}

/// Reject invalid `apr release` flag combinations before any work happens.
fn validate_release_options(options: &ReleaseTreeOptions) -> Result<()> {
    match (&options.channel, options.init_channel) {
        (None, true) => bail!("--init-channel requires --channel"),
        (None, false) => {
            if options.count.is_some() || options.partitions.is_some() {
                bail!("--count and --partitions require --channel");
            }
        }
        (Some(_), true) => {
            if options.count.is_some() || options.partitions.is_some() {
                bail!("--init-channel cannot be combined with --count or --partitions");
            }
        }
        (Some(_), false) => {
            select_partitions_for_advance(
                options.count,
                options.partitions.as_deref(),
                &PartitionMap::new(),
                &options.version,
            )
            .map(|_| ())?;
        }
    }

    if !options.publishing() {
        if options.cache_url_explicit {
            bail!("--cache-url requires an upload destination");
        }
        if options.cache_key.is_some() {
            bail!("--cache-key signs published narinfos; it requires an upload destination");
        }
        if options.cache_priority_explicit {
            bail!("--cache-priority requires an upload destination");
        }
        if options.no_skip {
            bail!("--no-skip requires an upload destination");
        }
    } else if !options.has_store_roots {
        if options.cache_url_explicit
            || options.cache_key.is_some()
            || options.cache_priority_explicit
            || options.no_skip
        {
            bail!("cache flags require registry store paths when publishing");
        }
    } else if options.cache_url.is_none() {
        bail!(
            "publishing a release with store paths requires --cache-url unless exactly one upload URL is http(s)"
        );
    }
    Ok(())
}

fn release_result_json(
    status: &str,
    registry_name: &str,
    dir: &Path,
    options: &ReleaseTreeOptions,
    report: &ReleaseReport,
) -> serde_json::Value {
    let channel = options.channel.as_ref().map(|channel| {
        serde_json::json!({
            "name": channel,
            "action": if options.init_channel { "init" } else { "advance" },
            "count": options.count,
            "partitions": options.partitions.as_deref(),
            "touched_partitions": report.channel_partitions,
        })
    });
    serde_json::json!({
        "action": "release",
        "status": status,
        "registry": registry_name,
        "directory": dir.to_string_lossy().to_string(),
        "version": options.version.to_string(),
        "dry_run": options.dry_run,
        "resume": options.resume,
        "cache_dir": options.cache_dir.to_string_lossy().to_string(),
        "cache_url": options.cache_url.as_deref(),
        "cache_url_explicit": options.cache_url_explicit,
        "cache_priority": options.cache_priority,
        "cache_priority_explicit": options.cache_priority_explicit,
        "has_store_roots": options.has_store_roots,
        "no_skip": options.no_skip,
        "cache": report.cache.as_ref().map(static_cache_report_json),
        "cache_pointer_updated": report.cache_pointer_updated,
        "upload_urls": &options.upload_urls,
        "uploaded_files": report.uploaded_files,
        "uploaded_bytes": report.uploaded_bytes,
        "uploaded_bytes_human": report.uploaded_bytes.map(format_size),
        "channel": channel,
        "full_pack": report.full_pack.as_deref(),
        "deltas": &report.deltas,
        "planned_steps": release_plan_steps_json(options),
    })
}

fn static_cache_report_json(report: &nixcache::StaticCacheReport) -> serde_json::Value {
    serde_json::json!({
        "paths": report.paths,
        "narinfos": report.narinfos,
        "nars": report.nars,
        "local_reused": report.local_reused,
        "remote_skipped": report.remote_skipped,
        "root_hashes": report.root_hashes,
        "output_dir": report.output_dir.to_string_lossy().to_string(),
    })
}

fn release_plan_steps_json(options: &ReleaseTreeOptions) -> Vec<&'static str> {
    let mut steps = vec!["ensure_clean_worktree"];
    if options.container_release.is_some() {
        steps.push("commit_container_release_sidecar");
    }
    if options.store_publish.is_some() {
        steps.push("publish_store_path");
    }
    // Cache bytes upload and pointer commit precede the tag so the pointer is
    // part of the released snapshot and a failed upload leaves no tag.
    if options.should_publish_cache() {
        steps.push("generate_static_cache");
        steps.push("upload_static_cache");
        steps.push("commit_cache_pointer");
    }
    steps.push("create_signed_release_tag");
    steps.push("generate_release_packs");
    if options.channel.is_some() {
        steps.push(if options.init_channel {
            "initialize_channel"
        } else {
            "publish_channel_pointer"
        });
    }
    if !options.upload_urls.is_empty() {
        steps.push("upload_static_origin");
    }
    steps
}

fn print_release_plan(
    dir: &Path,
    registry_name: &str,
    options: &ReleaseTreeOptions,
    printer: &Printer,
) {
    printer.header("Release plan");
    printer.kv("Registry", registry_name);
    printer.kv("Directory", &dir.display().to_string());
    printer.kv("Release", &options.version.to_string());
    printer.plain("- ensure registry working tree is clean");
    if options.container_release.is_some() {
        printer.plain("- commit canonical containers/v1/index.json with the release signing key");
    }
    if options.store_publish.is_some() {
        printer.plain("- publish store path into release metadata");
    }
    if options.should_publish_cache() {
        printer.plain("- generate static Nix cache files");
        printer.plain("- upload cache NARs and narinfos to every destination");
        if let Some(cache_url) = &options.cache_url {
            printer.plain(&format!(
                "- commit registry.toml cache pointer {cache_url} once published"
            ));
        }
    }
    printer.plain("- create signed release tag if absent");
    printer.plain("- generate full pack and guaranteed compressed thin deltas");
    if let Some(channel) = &options.channel {
        let action = if options.init_channel {
            "initialize"
        } else {
            "advance"
        };
        printer.plain(&format!("- {action} channel {channel}"));
    }
    if !options.upload_urls.is_empty() {
        printer.plain("- upload static git origin (immutable objects first, refs last)");
    }
}

fn attach_container_release(
    dir: &Path,
    registry_name: &str,
    options: &ReleaseTreeOptions,
    printer: &Printer,
) -> Result<()> {
    let Some(attachment) = &options.container_release else {
        return Ok(());
    };

    if let Some(tagged_commit) = existing_release_tag_commit(dir, &options.version)? {
        if !options.resume {
            bail!(
                "release tag {} already exists; container sidecar attachment requires --resume",
                options.version
            );
        }
        let head = git(dir, &["rev-parse", "HEAD"])?;
        if tagged_commit != head {
            bail!(
                "release tag {} points at {}, but HEAD is {}; refusing to mutate a divergent resume",
                options.version,
                tagged_commit,
                head,
            );
        }
        let tagged_bytes = crate::registry::repo::read_blob_at_blocking(
            dir,
            &tagged_commit,
            CONTAINER_RELEASE_SIDECAR_PATH,
        )?
        .ok_or_else(|| {
            anyhow::anyhow!(
                "release tag {} does not contain {}; refusing container resume",
                options.version,
                CONTAINER_RELEASE_SIDECAR_PATH,
            )
        })?;
        if tagged_bytes != attachment.canonical_bytes {
            bail!(
                "release tag {} contains different {} bytes; refusing container resume",
                options.version,
                CONTAINER_RELEASE_SIDECAR_PATH,
            );
        }
        printer.info(&format!(
            "Release tag {} already contains the requested container sidecar; resuming.",
            options.version
        ));
        return Ok(());
    }

    let path = dir.join(CONTAINER_RELEASE_SIDECAR_PATH);
    if path.exists() {
        let existing_bytes =
            read_bounded_container_json(&path, "committed container release sidecar")?;
        if existing_bytes == attachment.canonical_bytes {
            let path_commit = git(
                dir,
                &[
                    "log",
                    "-1",
                    "--format=%H",
                    "--",
                    CONTAINER_RELEASE_SIDECAR_PATH,
                ],
            )?;
            if path_commit.is_empty() {
                bail!(
                    "{} exists but is not committed; refusing container release retry",
                    CONTAINER_RELEASE_SIDECAR_PATH
                );
            }
            let committed_bytes = crate::registry::repo::read_blob_at_blocking(
                dir,
                &path_commit,
                CONTAINER_RELEASE_SIDECAR_PATH,
            )?
            .ok_or_else(|| {
                anyhow::anyhow!(
                    "commit {path_commit} does not contain {}; refusing container release retry",
                    CONTAINER_RELEASE_SIDECAR_PATH
                )
            })?;
            if committed_bytes != attachment.canonical_bytes {
                bail!(
                    "working-tree {} does not match its introducing commit {path_commit}",
                    CONTAINER_RELEASE_SIDECAR_PATH
                );
            }
            let trusted_key = derive_trust_key(registry_name, &options.signing_key)?;
            if !crate::security::verify_commit_signature(
                dir,
                &path_commit,
                std::slice::from_ref(&trusted_key),
            )? {
                bail!(
                    "commit {path_commit} containing {} is not signed by the selected release key",
                    CONTAINER_RELEASE_SIDECAR_PATH
                );
            }
            printer.info(&format!(
                "Canonical container sidecar is already committed at {path_commit}; continuing release {}.",
                options.version
            ));
            return Ok(());
        }

        let existing = ContainerRelease::from_canonical_json(&existing_bytes)
            .context("validating the existing committed container sidecar before replacement")?;
        if existing.identity.release == attachment.release.identity.release {
            bail!(
                "committed {} has different bytes for release {}; refusing container release retry",
                CONTAINER_RELEASE_SIDECAR_PATH,
                options.version
            );
        }
    }

    let parent = path.parent().ok_or_else(|| {
        anyhow::anyhow!(
            "container release sidecar path has no parent: {}",
            path.display()
        )
    })?;
    fs::create_dir_all(parent)
        .with_context(|| format!("creating container release directory {}", parent.display()))?;
    fs::write(&path, &attachment.canonical_bytes)
        .with_context(|| format!("staging canonical container release {}", path.display()))?;
    printer.success(&format!(
        "Attached canonical container sidecar for release {}.",
        options.version
    ));
    Ok(())
}

/// Require a clean working tree before releasing; bare repositories pass
/// trivially.
fn ensure_release_worktree_clean(dir: &Path) -> Result<()> {
    let is_bare = git(dir, &["rev-parse", "--is-bare-repository"])? == "true";
    if is_bare {
        return Ok(());
    }
    let status = git(dir, &["status", "--porcelain"])?;
    if !status.is_empty() {
        bail!("registry working tree has uncommitted changes; commit them or use --store-path");
    }
    Ok(())
}

/// Requires the exact existing release tag at HEAD before resuming artifacts.
fn ensure_resumed_release_tag(
    dir: &Path,
    options: &ReleaseTreeOptions,
    head: &str,
    printer: &Printer,
) -> Result<()> {
    if let Some(existing_commit) = existing_release_tag_commit(dir, &options.version)? {
        if options.resume && existing_commit == head {
            printer.info(&format!(
                "Release tag {} already exists at HEAD; resuming.",
                options.version
            ));
            return Ok(());
        }
        if existing_commit == head {
            bail!(
                "release tag {} already exists at HEAD; pass --resume to reuse it",
                options.version,
            );
        }
        bail!(
            "release tag {} already exists at {}, but HEAD is {}",
            options.version,
            existing_commit,
            head,
        );
    }

    bail!(
        "release tag {} disappeared before its artifacts resumed",
        options.version
    )
}

/// Return the commit an existing release tag points at, or `None` when no
/// tag exists; a non-tag ref carrying the release name is an error.
fn existing_release_tag_commit(dir: &Path, version: &semver::Version) -> Result<Option<String>> {
    let tag = version.to_string();
    let (tag_ok, _, tag_stderr) = git_try(dir, &["rev-parse", &format!("{tag}^{{tag}}")])?;
    if !tag_ok {
        let commit_probe = git_try(dir, &["rev-parse", &format!("{tag}^{{commit}}")])?;
        if commit_probe.0 {
            bail!("release name '{tag}' exists but is not an annotated tag object");
        }
        if !tag_stderr.is_empty() {
            return Ok(None);
        }
        return Ok(None);
    }
    let commit = release_commit(dir, version)?;
    Ok(Some(commit))
}

/// Reject a release whose tag already exists, before any mutating work.
///
/// This is a best-effort preflight, not a lock. It runs before the store-path
/// publish and the static-cache generation/upload so that the common mistake —
/// re-using a version that is already released — fails fast and leaves the
/// registry untouched, instead of bailing only at tag-creation time after a
/// publish commit and a cache upload have already landed.
///
/// It is deliberately *not* sufficient on its own: the authoritative collision
/// check still happens in the shared prepared finalizer under the release lock.
/// A concurrent producer working from a different clone can create the same
/// tag after this check passes. That residual race resolves when the losing
/// producer pushes to the shared origin. Passing `resume` skips the preflight,
/// since resuming an interrupted release legitimately reuses an existing tag.
///
/// # Errors
///
/// Returns an error when `resume` is false and the release tag already exists,
/// or when probing the tag fails (for example, a non-annotated tag of the same
/// name).
fn ensure_release_tag_available(dir: &Path, version: &semver::Version, resume: bool) -> Result<()> {
    if resume {
        return Ok(());
    }
    if let Some(existing) = existing_release_tag_commit(dir, version)? {
        bail!(
            "release tag {version} already exists at {existing}; choose an unused version or pass --resume to resume that release"
        );
    }
    Ok(())
}

#[cfg(test)]
mod tests;
