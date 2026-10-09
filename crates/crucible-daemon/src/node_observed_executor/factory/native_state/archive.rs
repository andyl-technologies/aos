//! Authenticated gem5 image materialization beneath reserved world custody.
//!
//! The source seal supplies historical preservation lineage. The installed
//! package independently selects executable, guest, model and codec identity.
//! Imported images remain inert until a separately qualified fresh peer exists.

use std::{
    fs::{self, File},
    io::{Read, Write},
    os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt},
    path::{Component, Path, PathBuf},
    rc::Rc,
    time::Duration,
};

use crucible::{
    node_adapters::gem5::{Gem5AuthenticatedContinuation, authenticate_gem5_continuation},
    node_admission::AdmittedGraph,
    node_contract::NativeCaptureArtifact,
    node_state::{AuthenticatedNativeSource, StateError, StateErrorCode},
};
use crucible_node_contract::{ContentRef, Id, U64, Validate};
use crucible_node_provider::{
    ProviderError,
    gem5::{
        Gem5ArchiveArtifact, Gem5ArchiveImport, Gem5ArchiveSourceVerifier,
        Gem5CapturedArtifactRole, Gem5CapturedImage, Gem5Launch, Gem5LaunchArtifact,
        Gem5OpaqueProfileVerifier, Gem5ProcessImageTools,
    },
};

use super::super::InstalledGem5ClosedProfile;
use super::profile::native_resources;

const MAX_ARTIFACTS: usize = 8192;
const MAX_ARTIFACT_BYTES: u64 = 2 * 1024 * 1024 * 1024;
const MAX_TOTAL_BYTES: u64 = 4 * 1024 * 1024 * 1024;

/// Retains the exact imported source, pinned readers and its native codec context.
///
/// The owning prepared capsule must retain this value and its managed directory
/// through actual child/helper reclamation. It grants no live execution authority.
pub(super) struct MaterializedGem5Archive {
    pub(super) image: Gem5CapturedImage,
    pub(super) continuation: Option<Gem5AuthenticatedContinuation>,
    pub(super) artifacts: Vec<NativeCaptureArtifact>,
    pub(super) root: PathBuf,
}

impl MaterializedGem5Archive {
    /// Copies complete signed artifacts only after the world slot is installed.
    ///
    /// The caller owns an empty private directory and the already reserved
    /// prepared capsule. Every partial file remains owned by that capsule on
    /// refusal; this method never removes backing or spawns native execution.
    ///
    /// # Errors
    /// Refuses another backend/codec, incomplete original prefixes or artifacts,
    /// incompatible installed models, unbounded geometry, unsafe private paths,
    /// corrupt streams, or failed independent historical source authentication.
    pub(super) fn prepare(
        graph: &AdmittedGraph,
        source: &AuthenticatedNativeSource<'_>,
        node: &Id,
        profile: Rc<InstalledGem5ClosedProfile>,
        root: &Path,
    ) -> Result<Self, StateError> {
        let continuation =
            authenticate_gem5_continuation(source, node, profile.maximum_microsteps())
                .map_err(|error| state_error(error.reason))?;
        // Historical native requests remain unchanged. The installed policy
        // must match them before any copied resource or native child allocation.
        validate_original_poll_credits(
            continuation.record().guest_isa(),
            continuation
                .record()
                .native_prefixes()
                .map(|prefix| prefix.original.maximum_events),
        )?;
        check_installed_binding(
            graph,
            source,
            node,
            &profile,
            continuation.record().guest_isa(),
        )?;
        check_geometry(source)?;
        check_empty_private_root(root)?;

        let image_root = root.join("images");
        let resource_root = root.join("resources");
        let temporary_root = root.join("temporary");
        for path in [&image_root, &resource_root, &temporary_root] {
            fs::create_dir(path).map_err(state_error)?;
            fs::set_permissions(path, fs::Permissions::from_mode(0o700)).map_err(state_error)?;
        }
        let artifacts = source.artifacts()?;
        let mut copied = Vec::new();
        copied
            .try_reserve_exact(artifacts.len())
            .map_err(state_error)?;
        for artifact in &artifacts {
            let (role, directory) = match artifact.role().as_str() {
                "image" => (Gem5CapturedArtifactRole::Image, &image_root),
                "resource" => (Gem5CapturedArtifactRole::Resource, &resource_root),
                _ => return Err(state_error("unsupported original gem5 artifact role")),
            };
            let relative = native_relative(artifact.role().as_str(), artifact.name())?;
            let path = directory.join(&relative);
            create_parents(directory, &relative)?;
            copy_original(artifact, &path)?;
            copied.push(Gem5ArchiveArtifact {
                role,
                relative,
                artifact: Gem5LaunchArtifact {
                    path,
                    content: artifact.reference().clone(),
                },
            });
        }

        let saved = continuation.record();
        let owner = source
            .runtime()
            .source_activation
            .owners
            .iter()
            .find(|owner| owner.owner == source.owner().owner)
            .ok_or_else(|| state_error("original gem5 owner authority absent"))?;
        let launch = Gem5Launch {
            executable: profile.artifact("native_executable").map_err(state_error)?,
            owner_script: profile.artifact("controller").map_err(state_error)?,
            model_script: profile.artifact("model").map_err(state_error)?,
            guest: profile.guest(saved.guest_isa()).map_err(state_error)?,
            guest_isa: saved.guest_isa().to_owned(),
            owner: owner.owner.clone(),
            incarnation: owner.incarnation.clone(),
            generation: owner.generation,
            resource_root: PathBuf::from(saved.source_layout_root()),
            timeout: Duration::from_secs(60),
            process_images: Some(Gem5ProcessImageTools {
                launcher: profile.artifact("dmtcp_launch").map_err(state_error)?,
                restarter: profile.artifact("dmtcp_restart").map_err(state_error)?,
                reconstruction_executable: profile.artifact("mtcp_restart").map_err(state_error)?,
                resource_helper: profile.artifact("image_guard").map_err(state_error)?,
                image_root,
                temporary_root,
            }),
        };
        let import = Gem5ArchiveImport {
            capture: saved.capture_id().clone(),
            source: launch,
            source_supplementary_files_root: PathBuf::from(saved.source_supplementary_files_root()),
            boundary: saved.native_boundary().clone(),
            completed: saved.native_prefixes().cloned().collect(),
            pending: saved.pending_prefix().cloned(),
            last_acknowledged: saved.last_acknowledged().cloned(),
            artifacts: copied,
        };
        let verifier = SourceVerifier {
            source,
            continuation: &continuation,
            profile: &profile,
        };
        let image = Gem5CapturedImage::import_authenticated_archive(import, &verifier)
            .map_err(state_error)?;
        Ok(Self {
            image,
            continuation: Some(continuation),
            artifacts,
            root: root.to_path_buf(),
        })
    }
}

struct SourceVerifier<'a, 'b> {
    source: &'a AuthenticatedNativeSource<'b>,
    continuation: &'a Gem5AuthenticatedContinuation,
    profile: &'a InstalledGem5ClosedProfile,
}

impl Gem5ArchiveSourceVerifier for SourceVerifier<'_, '_> {
    fn verify_archive(&self, import: &Gem5ArchiveImport) -> Result<(), ProviderError> {
        let saved = self.continuation.record();
        let owner = self
            .source
            .runtime()
            .source_activation
            .owners
            .iter()
            .find(|owner| owner.owner == self.source.owner().owner)
            .ok_or(ProviderError::Correlation(
                "authenticated original gem5 owner absent",
            ))?;
        if import.capture != *saved.capture_id()
            || import.boundary != *saved.native_boundary()
            || import.source.owner != owner.owner
            || import.source.incarnation != owner.incarnation
            || import.source.generation != owner.generation
            || import.source.guest_isa != saved.guest_isa()
            || import.source.resource_root != Path::new(saved.source_layout_root())
            || import.source_supplementary_files_root
                != Path::new(saved.source_supplementary_files_root())
            || import.pending.as_ref() != saved.pending_prefix()
            || import.last_acknowledged.as_ref() != saved.last_acknowledged()
            || import.completed.len() != saved.native_prefixes().len()
            || import
                .completed
                .iter()
                .zip(saved.native_prefixes())
                .any(|(left, right)| left != right)
            || import.artifacts.len() != saved.artifacts().len()
        {
            return Err(ProviderError::Correlation(
                "import differs from complete signed original native ledger",
            ));
        }
        for (actual, (role, name, reference)) in import.artifacts.iter().zip(saved.artifacts()) {
            let actual_role = match actual.role {
                Gem5CapturedArtifactRole::Image => "image",
                Gem5CapturedArtifactRole::Resource => "resource",
            };
            if actual_role != role.as_str()
                || actual.relative
                    != native_relative(actual_role, name).map_err(|_| {
                        ProviderError::Correlation("signed native reconstruction name differs")
                    })?
                || &actual.artifact.content != reference
            {
                return Err(ProviderError::Correlation(
                    "import differs from signed complete artifact roster",
                ));
            }
        }
        self.profile.verify_opaque_profile(
            &import.source,
            &self
                .profile
                .artifact("auditor")
                .map_err(|_| ProviderError::Correlation("installed auditor absent"))?,
        )
    }
}

pub(super) fn check_installed_binding(
    graph: &AdmittedGraph,
    source: &AuthenticatedNativeSource<'_>,
    node: &Id,
    profile: &InstalledGem5ClosedProfile,
    isa: &str,
) -> Result<(), StateError> {
    let binding = graph
        .binding(node)
        .ok_or_else(|| state_error("installed gem5 participant binding absent"))?;
    if graph.world_binding_hash() != &source.archive().manifest().world_binding_hash
        || binding.compatibility.capture_owner.id != source.owner().owner
        || binding.compatibility.execution_owner != binding.compatibility.capture_owner
        || binding
            .compatibility
            .implementation
            .implementation_id
            .as_str()
            != "gem5/native-process-v1"
    {
        return Err(state_error(
            "signed native source differs from installed admitted world",
        ));
    }
    let expected = [
        ("gem5", "emulator", profile.artifact("native_executable")),
        ("guest", "guest-image", profile.guest(isa)),
        ("model", "model-definition", profile.artifact("model")),
        ("owner", "native-controller", profile.artifact("controller")),
        (
            "image-launcher",
            "image-launcher",
            profile.artifact("dmtcp_launch"),
        ),
        (
            "image-restarter",
            "image-restarter",
            profile.artifact("dmtcp_restart"),
        ),
        (
            "image-runtime",
            "image-runtime",
            profile.artifact("mtcp_restart"),
        ),
        (
            "resource-helper",
            "resource-helper",
            profile.artifact("image_guard"),
        ),
    ];
    for (id, role, artifact) in expected {
        let artifact = artifact.map_err(state_error)?;
        if !binding
            .compatibility
            .implementation
            .artifacts
            .iter()
            .any(|actual| {
                actual.id.as_str() == id
                    && actual.role.as_str() == role
                    && actual.content == artifact.content
                    && actual.extensions.is_empty()
            })
        {
            return Err(state_error(
                "signed native source selects another installed artifact or model",
            ));
        }
    }
    Ok(())
}

fn check_geometry(source: &AuthenticatedNativeSource<'_>) -> Result<(), StateError> {
    let artifacts = &source.owner().artifacts;
    if artifacts.is_empty() || artifacts.len() > MAX_ARTIFACTS {
        return Err(state_error(
            "original gem5 artifact slots exceed installed capacity",
        ));
    }
    let mut total = 0u64;
    for artifact in artifacts {
        artifact.content.validate().map_err(state_error)?;
        native_relative(artifact.role.as_str(), &artifact.name)?;
        if !matches!(artifact.role.as_str(), "image" | "resource")
            || artifact.content.length.get() > MAX_ARTIFACT_BYTES
        {
            return Err(state_error(
                "original gem5 artifact exceeds installed geometry",
            ));
        }
        total = total
            .checked_add(artifact.content.length.get())
            .filter(|total| *total <= MAX_TOTAL_BYTES)
            .ok_or_else(|| state_error("original gem5 backing exceeds installed capacity"))?;
    }
    Ok(())
}

fn check_empty_private_root(root: &Path) -> Result<(), StateError> {
    let metadata = fs::symlink_metadata(root).map_err(state_error)?;
    if !metadata.is_dir()
        || metadata.uid() != rustix::process::geteuid().as_raw()
        || metadata.mode() & 0o777 != 0o700
        || fs::canonicalize(root).map_err(state_error)? != root
        || fs::read_dir(root).map_err(state_error)?.next().is_some()
    {
        return Err(state_error(
            "native materialization requires an owned empty canonical private root",
        ));
    }
    Ok(())
}

/// Removes only the authenticated generic namespace from a native-relative name.
///
/// The generic archive separates image and resource names explicitly. The native
/// importer selects those roots by role, so its relative name must exclude the
/// same role prefix without changing the signed artifact inventory.
fn native_relative(role: &str, name: &str) -> Result<PathBuf, StateError> {
    let prefix = match role {
        "image" => "image/",
        "resource" => "resource/",
        _ => return Err(state_error("unsupported original native namespace")),
    };
    let relative = name
        .strip_prefix(prefix)
        .ok_or_else(|| state_error("signed native namespace differs from artifact role"))?;
    checked_relative(relative)
}

fn checked_relative(name: &str) -> Result<PathBuf, StateError> {
    let path = Path::new(name);
    if name.is_empty()
        || name.len() > 4096
        || name
            .split('/')
            .any(|part| part.is_empty() || matches!(part, "." | ".."))
        || path.components().count() > 16
        || path
            .components()
            .any(|part| !matches!(part, Component::Normal(_)))
        || name.contains('\\')
    {
        return Err(state_error("unsafe original gem5 reconstruction name"));
    }
    Ok(path.to_path_buf())
}

fn create_parents(root: &Path, relative: &Path) -> Result<(), StateError> {
    let mut parent = root.to_path_buf();
    if let Some(prefix) = relative.parent() {
        for part in prefix.components() {
            parent.push(part.as_os_str());
            match fs::create_dir(&parent) {
                Ok(()) => fs::set_permissions(&parent, fs::Permissions::from_mode(0o700))
                    .map_err(state_error)?,
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
                    let metadata = fs::symlink_metadata(&parent).map_err(state_error)?;
                    if !metadata.is_dir()
                        || metadata.uid() != rustix::process::geteuid().as_raw()
                        || metadata.mode() & 0o777 != 0o700
                    {
                        return Err(state_error(
                            "native materialization parent changed ownership",
                        ));
                    }
                }
                Err(error) => return Err(state_error(error)),
            }
        }
    }
    Ok(())
}

fn copy_original(artifact: &NativeCaptureArtifact, path: &Path) -> Result<(), StateError> {
    let reference: &ContentRef = artifact.reference();
    let mut target = File::options()
        .create_new(true)
        .write(true)
        .mode(0o600)
        .custom_flags(rustix::fs::OFlags::NOFOLLOW.bits() as i32)
        .open(path)
        .map_err(state_error)?;
    let mut reader = artifact.reader();
    let mut hasher = blake3::Hasher::new();
    let domain = b"cnp.blob.v1";
    hasher.update(b"CNP/1\0");
    hasher.update(&(domain.len() as u32).to_be_bytes());
    hasher.update(domain);
    hasher.update(&reference.length.get().to_be_bytes());
    let mut remaining = reference.length.get();
    let mut buffer = [0u8; 64 * 1024];
    while remaining != 0 {
        let count = usize::try_from(remaining.min(buffer.len() as u64)).map_err(state_error)?;
        reader
            .read_exact(&mut buffer[..count])
            .map_err(state_error)?;
        hasher.update(&buffer[..count]);
        target.write_all(&buffer[..count]).map_err(state_error)?;
        remaining -= count as u64;
    }
    let mut excess = [0u8; 1];
    if reader.read(&mut excess).map_err(state_error)? != 0
        || hasher.finalize().to_hex().as_str() != reference.hash.digest
    {
        return Err(state_error(
            "original gem5 stream changed during materialization",
        ));
    }
    target.sync_all().map_err(state_error)
}

fn validate_original_poll_credits(
    isa: &str,
    original: impl IntoIterator<Item = U64>,
) -> Result<(), StateError> {
    let selected = native_resources(isa)
        .map_err(state_error)?
        .maximum_events_per_poll;
    if original.into_iter().any(|credit| credit != selected) {
        return Err(state_error(
            "original gem5 native poll credit differs from the selected configuration",
        ));
    }
    Ok(())
}

fn state_error(error: impl std::fmt::Display) -> StateError {
    StateError::new(
        StateErrorCode::NativeEvidence,
        "installed gem5 source",
        error.to_string(),
    )
}

#[cfg(test)]
mod tests {
    // These local data checks intentionally panic if preservation bytes change.
    // crucible-lint: allow panic-shortcut -- These archive tests deliberately panic on invalid fixtures or failed invariants.
    #![allow(clippy::unwrap_used, clippy::expect_used)]

    use super::*;
    use crucible_node_contract::canonical;

    #[test]
    fn original_poll_credit_mismatch_refuses_before_materialized_namespace_allocation() {
        let directory = tempfile::tempdir().unwrap();
        let target = directory.path().join("materialized");

        for (isa, credits) in [
            ("x86_64", vec![65_536, 1024]),
            ("aarch64", vec![262_144, 65_536]),
            ("foreign-isa", vec![65_536]),
        ] {
            let prepared = validate_original_poll_credits(isa, credits.into_iter().map(U64::new))
                .and_then(|()| fs::create_dir(&target).map_err(state_error));

            assert!(prepared.is_err());
            assert!(!target.exists());
        }

        assert!(validate_original_poll_credits("x86_64", [U64::new(65_536)]).is_ok());
        assert!(validate_original_poll_credits("aarch64", [U64::new(262_144)]).is_ok());
    }

    #[test]
    fn pinned_original_stream_survives_original_path_removal() {
        let directory = tempfile::tempdir().unwrap();
        let source = directory.path().join("original-image");
        let target = directory.path().join("retained-image");
        let bytes = (0..131_093)
            .map(|value| (value % 251) as u8)
            .collect::<Vec<_>>();
        fs::write(&source, &bytes).unwrap();
        let reference = canonical::content_ref(&bytes, "application/octet-stream").unwrap();
        let artifact = NativeCaptureArtifact::from_file(
            Id::new("image").unwrap(),
            "process.dmtcp".into(),
            reference,
            File::open(&source).unwrap(),
        )
        .unwrap();
        fs::remove_file(&source).unwrap();

        copy_original(&artifact, &target).unwrap();

        assert!(!source.exists());
        assert_eq!(fs::read(&target).unwrap(), bytes);
        assert_eq!(fs::metadata(target).unwrap().mode() & 0o777, 0o600);
    }

    #[test]
    fn changed_pinned_bytes_are_refused_without_losing_owned_partial_file() {
        let directory = tempfile::tempdir().unwrap();
        let source = directory.path().join("original-image");
        let target = directory.path().join("retained-image");
        fs::write(&source, b"original bytes").unwrap();
        let artifact = NativeCaptureArtifact::from_file(
            Id::new("resource").unwrap(),
            "guest.elf".into(),
            canonical::content_ref(b"original bytes", "application/octet-stream").unwrap(),
            File::open(&source).unwrap(),
        )
        .unwrap();
        fs::write(&source, b"modified bytes").unwrap();

        assert!(copy_original(&artifact, &target).is_err());

        // Preparation refusal keeps actual partial resources under the reserved
        // capsule; this helper cannot announce retirement or delete backing.
        assert_eq!(fs::read(target).unwrap(), b"modified bytes");
        assert_eq!(fs::read(source).unwrap(), b"modified bytes");
    }

    #[test]
    fn reconstruction_paths_cannot_escape_the_reserved_private_root() {
        for unsafe_name in [
            "",
            "../image",
            "/image",
            "images/../../image",
            "images\\image",
        ] {
            assert!(checked_relative(unsafe_name).is_err(), "{unsafe_name}");
        }
        assert_eq!(
            checked_relative("files/subdirectory/image").unwrap(),
            PathBuf::from("files/subdirectory/image")
        );
    }

    #[test]
    fn native_names_preserve_the_signed_role_without_duplicating_its_root() {
        assert_eq!(
            native_relative("resource", "resource/native-owner.py").unwrap(),
            PathBuf::from("native-owner.py")
        );
        assert_eq!(
            native_relative("image", "image/checkpoints/process.dmtcp").unwrap(),
            PathBuf::from("checkpoints/process.dmtcp")
        );
        for (role, name) in [
            ("resource", "image/native-owner.py"),
            ("image", "resource/process.dmtcp"),
            ("resource", "native-owner.py"),
            ("resource", "resource/../native-owner.py"),
            ("resource", "resource//native-owner.py"),
            ("resource", "resource/files//native-owner.py"),
            ("resource", "resource/files/./native-owner.py"),
        ] {
            assert!(native_relative(role, name).is_err(), "{role}: {name}");
        }
    }
}
