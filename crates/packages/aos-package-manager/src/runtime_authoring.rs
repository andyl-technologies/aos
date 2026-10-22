//! Initializes mutable operator authoring from the authenticated committed source tree.
//!
//! A missing worktree inherits the current runtime role once. An existing tree,
//! including an empty one, is an explicit operator choice and is never reseeded.
//! Baseline configuration and evaluated values are not copied into authoring.

use std::collections::BTreeSet;
use std::fs;
use std::os::unix::fs::PermissionsExt as _;
use std::path::{Path, PathBuf};

use anyhow::{Context as _, Result, ensure};

use crate::profile::Profile;
use aos_deployment::input::ImportControl;
use aos_deployment::retention::ArtifactAdmission as _;
use aos_deployment::source_views::SourceViews;

/// Keeps a fully copied authoring tree private until publication or snapshotting.
pub(crate) struct StagedRuntime {
    _directory: tempfile::TempDir,
    pub(crate) path: PathBuf,
}

/// Initializes an absent worktree while its caller holds the authoring lock.
///
/// # Errors
/// Returns an error for an unsafe destination, unauthenticated or ambiguous
/// retained sources, failed copying, or failed atomic publication.
pub(crate) fn initialize(worktree: &Path) -> Result<()> {
    initialize_with(worktree, stage_current)
}

fn initialize_with(
    worktree: &Path,
    load: impl FnOnce(&Path) -> Result<StagedRuntime>,
) -> Result<()> {
    if exists(worktree)? {
        return Ok(());
    }
    let parent = worktree
        .parent()
        .context("authoring worktree has no parent")?;
    let staged = load(parent)?;
    publish(&staged.path, worktree)?;
    fs::File::open(parent)?.sync_all()?;
    Ok(())
}

fn exists(path: &Path) -> Result<bool> {
    match fs::symlink_metadata(path) {
        Ok(metadata) => {
            ensure!(
                metadata.is_dir(),
                "authoring worktree must be a real directory"
            );
            Ok(true)
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(error) => Err(error.into()),
    }
}

/// Restores authoring from committed sources, preserving the old tree as a backup.
///
/// # Errors
/// Returns an error for unsafe or unauthenticated sources, a conflicting backup,
/// failed copying, or failed publication. A moved old tree remains recoverable.
pub(crate) fn restore(worktree: &Path) -> Result<Option<PathBuf>> {
    let parent = worktree
        .parent()
        .context("authoring worktree has no parent")?;
    let profile = Profile::open_readonly(crate::runtime_boundary::configuration_scope());
    let generation = crate::profile::deployment::current_committed_generation(&profile.path)?
        .context("no active native profile generation")?;
    let staged = stage_generation(parent, &profile, Some(generation))?;
    let backup = if exists(worktree)? {
        let backup = parent.join(format!("modules.backup.{}", std::process::id()));
        publish(worktree, &backup)?;
        fs::File::open(parent)?.sync_all()?;
        Some(backup)
    } else {
        None
    };
    publish(&staged.path, worktree)?;
    fs::File::open(parent)?.sync_all()?;
    Ok(backup)
}

fn publish(source: &Path, destination: &Path) -> Result<()> {
    rustix::fs::renameat_with(
        rustix::fs::CWD,
        source,
        rustix::fs::CWD,
        destination,
        rustix::fs::RenameFlags::NOREPLACE,
    )
    .with_context(|| format!("publishing authoring worktree {}", destination.display()))
}

/// Copies the complete committed runtime tree into private staging.
///
/// # Errors
/// Returns an error for invalid publication or source admission, multiple source
/// roots, unsafe source objects, exceeded snapshot bounds, or transport failure.
pub(crate) fn stage_current(parent: &Path) -> Result<StagedRuntime> {
    let profile = Profile::open_readonly(crate::runtime_boundary::configuration_scope());
    let generation = crate::profile::deployment::current_committed_generation(&profile.path)?;
    stage_generation(parent, &profile, generation)
}

fn stage_generation(
    parent: &Path,
    profile: &Profile,
    generation: Option<u32>,
) -> Result<StagedRuntime> {
    let directory = tempfile::Builder::new()
        .prefix(".runtime-authoring-")
        .tempdir_in(parent)?;
    let destination = directory.path().join("tree");
    if let Some(generation) = generation {
        let committed = crate::profile::deployment::committed_generation_during_recovery(
            &profile.path,
            generation,
        )?;
        let nix_store = crate::install::native::packaged_path("AOS_NIX_STORE")?;
        let cancellation = Default::default();
        let (identity, descriptor) = crate::native_deployment::read_retained_evaluation_in(
            &profile
                .path
                .join(format!("gen-{generation}/evaluation.json")),
            &committed.deployment,
            &nix_store,
            &cancellation,
        )?;
        let mut admission = crate::native_registry::RegistryAdmission::new(
            nix_store.clone(),
            &profile.path.join("deployment/registry-admissions"),
        )?;
        let (descriptor_root, _) = aos_deployment::nix::store_root_and_suffix(&identity)?;
        admission.admit(
            descriptor_root
                .to_str()
                .context("descriptor root is not UTF-8")?,
        )?;
        if let Some(root) = retained_root(
            &descriptor.runtime_configuration,
            committed.deployment.inputs(),
        )? {
            let mut temporary_roots =
                aos_deployment::store::temp_roots::TemporaryRoots::open(&nix_store, &cancellation)?;
            temporary_roots.retain(
                [root
                    .to_str()
                    .context("runtime root is not UTF-8")?
                    .to_owned()],
                &cancellation,
            )?;
            let evidence =
                admission.evidence(root.to_str().context("runtime root is not UTF-8")?)?;
            let views = SourceViews::prepare(
                &nix_store,
                [root.as_path()],
                directory.path(),
                &ImportControl(&cancellation),
            )?;
            ensure!(
                views.nar_hash(&root)? == evidence.nar_hash.to_string(),
                "exported runtime source differs from authenticated admission"
            );
            let source = views.read_path(&root)?;
            validate_entrypoints(&source, &root, &descriptor.runtime_configuration)?;
            copy_tree(&source, &destination)?;
        } else {
            empty_tree(&destination)?;
        }
    } else {
        empty_tree(&destination)?;
    }
    Ok(StagedRuntime {
        _directory: directory,
        path: destination,
    })
}

fn retained_root(entrypoints: &[PathBuf], inputs: &[String]) -> Result<Option<PathBuf>> {
    let roots = entrypoints
        .iter()
        .map(|path| {
            let (root, suffix) = aos_deployment::nix::store_root_and_suffix(path)?;
            ensure!(
                !suffix.as_os_str().is_empty(),
                "runtime authoring requires a directory source tree"
            );
            ensure!(
                inputs.iter().any(|input| Path::new(input) == root),
                "committed deployment does not retain its runtime source"
            );
            Ok(root)
        })
        .collect::<Result<BTreeSet<_>>>()?;
    ensure!(
        roots.len() <= 1,
        "runtime authoring cannot restore multiple distinct source roots into one worktree; choose an explicit combined authoring tree"
    );
    Ok(roots.into_iter().next())
}

fn empty_tree(destination: &Path) -> Result<()> {
    fs::create_dir(destination)?;
    fs::set_permissions(destination, fs::Permissions::from_mode(0o700))?;
    fs::File::open(destination)?.sync_all()?;
    Ok(())
}

fn validate_entrypoints(source: &Path, root: &Path, entrypoints: &[PathBuf]) -> Result<()> {
    let wanted = entrypoints
        .iter()
        .map(|path| {
            path.strip_prefix(root)
                .map(Path::to_path_buf)
                .context("runtime entrypoint is outside its source root")
        })
        .collect::<Result<BTreeSet<_>>>()?;
    let discovered = crate::runtime_modules::list_entrypoints(source)?
        .into_iter()
        .collect::<BTreeSet<_>>();
    ensure!(
        wanted == discovered,
        "retained runtime entrypoints do not describe the complete authoring tree"
    );
    Ok(())
}

fn copy_tree(source: &Path, destination: &Path) -> Result<()> {
    // The private restored tree cannot change underneath this copy. Discovery
    // checks the same names/object kinds used by the normal snapshot boundary.
    crate::runtime_modules::list_entrypoints(source)?;
    copy_directory(source, destination, 0, &mut CopyLimits::default())
}

#[derive(Default)]
struct CopyLimits {
    files: usize,
    bytes: u64,
}

fn copy_directory(
    source: &Path,
    destination: &Path,
    depth: usize,
    limits: &mut CopyLimits,
) -> Result<()> {
    ensure!(
        depth <= crate::runtime_modules::MAX_DEPTH,
        "runtime authoring exceeds source depth limit"
    );
    empty_tree(destination)?;
    for entry in fs::read_dir(source)? {
        let entry = entry?;
        let kind = entry.file_type()?;
        let target = destination.join(entry.file_name());
        if kind.is_dir() {
            copy_directory(&entry.path(), &target, depth + 1, limits)?;
        } else {
            ensure!(
                kind.is_file(),
                "retained runtime source contains an unsupported object"
            );
            let size = entry.metadata()?.len();
            limits.files += 1;
            limits.bytes += size;
            ensure!(
                size <= crate::runtime_modules::MAX_FILE_BYTES
                    && limits.files <= crate::runtime_modules::MAX_FILES
                    && limits.bytes <= crate::runtime_modules::MAX_TOTAL_BYTES,
                "runtime authoring exceeds snapshot size limits"
            );
            fs::copy(entry.path(), &target)?;
            fs::set_permissions(&target, fs::Permissions::from_mode(0o600))?;
            fs::File::open(&target)?.sync_all()?;
        }
    }
    fs::File::open(destination)?.sync_all()?;
    Ok(())
}

#[cfg(test)]
mod tests;
