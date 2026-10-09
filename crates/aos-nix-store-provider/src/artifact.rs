//! Persistent content-addressed objects backed by the local Nix store.
//!
//! A checked runtime blob is copied into the immutable store, then retained by
//! a GC root owned by the logical ability resource. Provider metadata records
//! the provider-neutral request beside that root so admission can distinguish
//! a converged resource from an older semantic revision.

use std::fs::{self, File, OpenOptions};
use std::io::{self, Read as _, Write as _};
use std::os::unix::fs::{OpenOptionsExt as _, PermissionsExt as _, symlink};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use anyhow::{Context as _, Result, bail, ensure};
use aos_ability_model::{
    ArtifactClosureMemberInput, ArtifactReference, LocalKey, artifact_closure_identity,
    artifact_content_identity,
};
use aos_ability_runtime::activation::{Action, Invocation};
use aos_contract::Sha256Digest;
use serde::{Deserialize, Serialize};
use serde_json::json;

use crate::handler::remaining;
use crate::process::ProcessStoreCommands;

const MAX_CONTENT_BYTES: u64 = 1024 * 1024;
const METADATA_SCHEMA: &str = "aos.artifact.content-addressed-object-metadata/v1";
const ROOT_DIRECTORY: &str = "/nix/var/nix/gcroots/aos/content-addressed-objects";
const NIX_STORE_RELATIVE: &str = "../libexec/nix-store";
static TEMPORARY_SEQUENCE: AtomicU64 = AtomicU64::new(0);

/// Handles persistent content-addressed object methods for the Nix store.
pub(super) struct ContentArtifactProvider {
    root_directory: PathBuf,
    store_directory: PathBuf,
    executable: Option<PathBuf>,
    commands: Box<dyn ArtifactStoreCommands>,
    validate_executable_file: bool,
}

impl ContentArtifactProvider {
    /// Constructs the production provider rooted in Nix's permanent GC roots.
    pub(super) fn production() -> Self {
        Self {
            root_directory: ROOT_DIRECTORY.into(),
            store_directory: "/nix/store".into(),
            executable: None,
            commands: Box::new(ProcessStoreCommands),
            validate_executable_file: true,
        }
    }

    /// Executes the native persistent content-object lifecycle.
    pub(super) fn invoke(
        &self,
        purpose: &str,
        invocation: Invocation,
    ) -> Result<serde_json::Value> {
        let parameters: ContentObjectParameters = serde_json::from_value(invocation.input)?;
        ensure!(
            parameters.content.len() as u64 <= MAX_CONTENT_BYTES,
            "content object exceeds native string bound"
        );
        let desired = ContentObjectRequest {
            name: parameters.name,
            media_type: parameters.media_type,
            content_sha256: Sha256Digest::of_bytes(parameters.content.as_bytes()),
        };
        validate_request(&desired)?;
        let executable = self.executable()?;
        if purpose == "remove" {
            self.remove(&invocation.id)?;
            return Ok(json!({}));
        }
        if purpose == "apply" {
            self.commit(
                &invocation.id,
                &desired,
                parameters.content.as_bytes(),
                &executable,
                invocation.effect.timeout_ms,
            )?;
        }
        let inspection = self.inspect(
            &invocation.id,
            &desired,
            &executable,
            invocation.effect.timeout_ms,
        );
        if purpose == "apply" {
            return ready_outputs(&inspection);
        }
        Ok(match (invocation.action, inspection) {
            (_, Inspection::Absent) => json!({"status":"absent"}),
            (Action::Apply, Inspection::Ready(stored)) => {
                json!({"status":"current","outputs":ready_outputs(&Inspection::Ready(stored))?})
            }
            (Action::Remove, Inspection::Ready(_)) | (_, Inspection::Drifted) => {
                json!({"status":"retry-safe"})
            }
            (_, Inspection::Unknown) => json!({"status":"indeterminate"}),
        })
    }

    fn executable(&self) -> Result<PathBuf> {
        let executable = if let Some(executable) = &self.executable {
            executable.clone()
        } else {
            let current = std::env::current_exe().context("resolving provider executable")?;
            current
                .parent()
                .context("provider executable has no parent")?
                .join(NIX_STORE_RELATIVE)
        };
        let resolved = fs::canonicalize(&executable).context("resolving bundled nix-store")?;
        ensure!(
            resolved.starts_with("/nix/store") || !self.validate_executable_file,
            "bundled nix-store resolves outside the immutable store"
        );
        if self.validate_executable_file {
            let metadata = fs::metadata(&resolved).context("inspecting bundled nix-store")?;
            ensure!(
                metadata.is_file(),
                "bundled nix-store is not a regular file"
            );
            ensure!(
                metadata.permissions().mode() & 0o111 != 0,
                "bundled nix-store is not executable"
            );
        }
        // Nix dispatches its legacy CLI by argv[0]; resolving the symlink for
        // invocation would select `nix` instead of the bundled `nix-store`.
        Ok(executable)
    }

    fn inspect(
        &self,
        resource: &str,
        desired: &ContentObjectRequest,
        executable: &Path,
        remaining_millis: u64,
    ) -> Inspection {
        match self.inspect_checked(resource, desired, executable, remaining_millis) {
            Ok(inspection) => inspection,
            Err(_) => Inspection::Unknown,
        }
    }

    fn inspect_checked(
        &self,
        resource: &str,
        desired: &ContentObjectRequest,
        executable: &Path,
        remaining_millis: u64,
    ) -> Result<Inspection> {
        let paths = self.paths(resource)?;
        let root_metadata = fs::symlink_metadata(&paths.root);
        let state_metadata = fs::symlink_metadata(&paths.metadata);
        match (&root_metadata, &state_metadata) {
            (Err(root), Err(state))
                if root.kind() == io::ErrorKind::NotFound
                    && state.kind() == io::ErrorKind::NotFound =>
            {
                return Ok(Inspection::Absent);
            }
            _ => {}
        }
        let Ok(root_metadata) = root_metadata else {
            return Ok(Inspection::Drifted);
        };
        let Ok(state_metadata) = state_metadata else {
            return Ok(Inspection::Drifted);
        };
        if !root_metadata.file_type().is_symlink() || !state_metadata.is_file() {
            return Ok(Inspection::Drifted);
        }

        let metadata = match read_metadata(&paths.metadata) {
            Ok(metadata) => metadata,
            Err(_) => return Ok(Inspection::Drifted),
        };
        if metadata.schema != METADATA_SCHEMA || metadata.expected != *desired {
            return Ok(Inspection::Drifted);
        }
        let target = match fs::read_link(&paths.root) {
            Ok(target) if target == Path::new(&metadata.artifact.store_path) => target,
            _ => return Ok(Inspection::Drifted),
        };
        if !self
            .commands
            .is_valid(executable, &target, remaining_millis)?
        {
            return Ok(Inspection::Drifted);
        }
        let observed = self.describe_artifact(executable, &target, remaining_millis)?;
        if observed.artifact != metadata.artifact
            || observed.content_sha256 != metadata.content_sha256
            || observed.content_sha256 != desired.content_sha256
        {
            return Ok(Inspection::Drifted);
        }
        Ok(Inspection::Ready(observed))
    }

    fn commit(
        &self,
        resource: &str,
        desired: &ContentObjectRequest,
        content: &[u8],
        executable: &Path,
        remaining_millis: u64,
    ) -> Result<()> {
        let source =
            tempfile::NamedTempFile::new().context("creating private content-object input")?;
        source.as_file().write_all(content)?;
        source.as_file().sync_all()?;
        let deadline = crate::handler::deadline(remaining_millis)?;
        let store_path =
            self.commands
                .add_fixed(executable, source.path(), remaining(deadline)?)?;
        let stored = self.describe_artifact(executable, &store_path, remaining(deadline)?)?;
        ensure!(
            stored.content_sha256 == desired.content_sha256,
            "stored object differs from its exact native content input"
        );
        let metadata = ObjectMetadata {
            schema: METADATA_SCHEMA.into(),
            expected: desired.clone(),
            artifact: stored.artifact,
            content_sha256: stored.content_sha256,
        };
        self.publish_root(resource, &store_path, &metadata)
    }

    fn describe_artifact(
        &self,
        executable: &Path,
        store_path: &Path,
        remaining_millis: u64,
    ) -> Result<StoredArtifact> {
        validate_store_path(store_path, &self.store_directory)?;
        let deadline = crate::handler::deadline(remaining_millis)?;
        let references = self
            .commands
            .references(executable, store_path, remaining(deadline)?)?;
        ensure!(
            references.is_empty(),
            "content-addressed flat object unexpectedly carries store references"
        );
        let bytes = read_bounded_regular(store_path)?;
        let nar = self
            .commands
            .dump(executable, store_path, remaining(deadline)?)?;
        let nar_hash = Sha256Digest::of_bytes(&nar);
        let store_path_text = store_path
            .to_str()
            .context("content-addressed store path is not UTF-8")?
            .to_string();
        let store_key = store_path_key(&store_path_text)?;
        let closure = artifact_closure_identity(
            store_key,
            &[ArtifactClosureMemberInput {
                key: store_key.into(),
                nar_hash,
                references: Vec::new(),
            }],
        )?;
        Ok(StoredArtifact {
            artifact: ArtifactReference {
                content: artifact_content_identity(&nar_hash),
                store_path: store_path_text,
                nar_hash,
                closure,
            },
            content_sha256: Sha256Digest::of_bytes(bytes),
        })
    }

    fn publish_root(
        &self,
        resource: &str,
        store_path: &Path,
        metadata: &ObjectMetadata,
    ) -> Result<()> {
        let paths = self.paths(resource)?;
        create_real_directory(&self.root_directory)?;
        create_real_directory(&paths.directory)?;
        let suffix = temporary_suffix();
        let root_temporary = paths.directory.join(format!("root.{suffix}.tmp"));
        let metadata_temporary = paths.directory.join(format!("metadata.{suffix}.tmp"));
        remove_if_present(&root_temporary)?;
        remove_if_present(&metadata_temporary)?;

        symlink(store_path, &root_temporary).context("creating temporary Nix GC root")?;
        fs::rename(&root_temporary, &paths.root).context("publishing Nix GC root")?;
        sync_directory(&paths.directory)?;

        let encoded = aos_contract::canonical::to_vec(metadata)?;
        let mut file = OpenOptions::new()
            .create_new(true)
            .write(true)
            .mode(0o600)
            .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW)
            .open(&metadata_temporary)
            .context("creating content object metadata")?;
        file.write_all(&encoded)
            .context("writing content object metadata")?;
        file.sync_all().context("syncing content object metadata")?;
        drop(file);
        fs::rename(&metadata_temporary, &paths.metadata)
            .context("publishing content object metadata")?;
        sync_directory(&paths.directory)
    }

    fn remove(&self, resource: &str) -> Result<()> {
        let paths = self.paths(resource)?;
        remove_symlink_if_present(&paths.root)?;
        remove_regular_if_present(&paths.metadata)?;
        match fs::remove_dir(&paths.directory) {
            Ok(()) => sync_directory(&self.root_directory),
            Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
            Err(error) => Err(error).context("removing content object owner directory"),
        }
    }

    fn paths(&self, resource: &str) -> Result<ObjectPaths> {
        let digest = Sha256Digest::of_canonical(
            "aos.artifact.content-addressed-object-owner/v1",
            &resource,
        )?;
        let directory = self.root_directory.join(digest.hex());
        Ok(ObjectPaths {
            root: directory.join("root"),
            metadata: directory.join("metadata.json"),
            directory,
        })
    }

    #[cfg(test)]
    fn test(
        root_directory: PathBuf,
        store_directory: PathBuf,
        commands: Box<dyn ArtifactStoreCommands>,
    ) -> Self {
        Self {
            root_directory,
            store_directory,
            executable: Some(PathBuf::from("/test/nix-store")),
            commands,
            validate_executable_file: false,
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct ContentObjectRequest {
    name: LocalKey,
    media_type: String,
    content_sha256: Sha256Digest,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ContentObjectParameters {
    name: LocalKey,
    media_type: String,
    content: String,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct ObjectMetadata {
    schema: String,
    expected: ContentObjectRequest,
    artifact: ArtifactReference,
    content_sha256: Sha256Digest,
}

#[derive(Clone, Debug)]
struct StoredArtifact {
    artifact: ArtifactReference,
    content_sha256: Sha256Digest,
}

#[derive(Debug)]
enum Inspection {
    Absent,
    Ready(StoredArtifact),
    Drifted,
    Unknown,
}

struct ObjectPaths {
    directory: PathBuf,
    root: PathBuf,
    metadata: PathBuf,
}

pub(super) trait ArtifactStoreCommands: Send + Sync {
    fn add_fixed(&self, executable: &Path, source: &Path, remaining_millis: u64)
    -> Result<PathBuf>;

    fn dump(&self, executable: &Path, store_path: &Path, remaining_millis: u64) -> Result<Vec<u8>>;

    fn references(
        &self,
        executable: &Path,
        store_path: &Path,
        remaining_millis: u64,
    ) -> Result<Vec<PathBuf>>;

    fn is_valid(&self, executable: &Path, store_path: &Path, remaining_millis: u64)
    -> Result<bool>;
}

fn validate_request(request: &ContentObjectRequest) -> Result<()> {
    validate_media_type(&request.media_type)
}

fn validate_media_type(value: &str) -> Result<()> {
    ensure!(
        !value.is_empty() && value.len() <= 255,
        "content object media type is empty or oversized"
    );
    // Keep the exact version in resource identity while admitting only the
    // single canonical parameter emitted by native metadata producers.
    let (essence, version) = match value.split_once(';') {
        Some((essence, parameter)) => {
            let version = parameter
                .strip_prefix("version=")
                .context("content object media type has an unsupported parameter")?;
            (essence, Some(version))
        }
        None => (value, None),
    };
    if let Some(version) = version {
        ensure!(
            version.starts_with(|character: char| character.is_ascii_digit() && character != '0')
                && version.bytes().all(|byte| byte.is_ascii_digit()),
            "content object media type version is not a canonical positive integer"
        );
    }

    let mut parts = essence.split('/');
    let type_name = parts.next().unwrap_or_default();
    let subtype = parts.next().unwrap_or_default();
    ensure!(
        !type_name.is_empty()
            && !subtype.is_empty()
            && parts.next().is_none()
            && type_name.bytes().all(media_token_byte)
            && subtype.bytes().all(media_token_byte),
        "content object media type is not canonical"
    );
    Ok(())
}

fn media_token_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric()
        || matches!(
            byte,
            b'!' | b'#' | b'$' | b'&' | b'^' | b'_' | b'.' | b'+' | b'-'
        )
}

fn read_bounded_regular(path: &Path) -> Result<Vec<u8>> {
    let mut file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(path)
        .with_context(|| format!("opening regular file {}", path.display()))?;
    let metadata = file
        .metadata()
        .with_context(|| format!("inspecting regular file {}", path.display()))?;
    ensure!(metadata.is_file(), "checked object is not a regular file");
    ensure!(
        metadata.len() <= MAX_CONTENT_BYTES,
        "checked object exceeds the transaction blob bound"
    );
    let mut bytes = Vec::with_capacity(metadata.len() as usize);
    (&mut file)
        .take(MAX_CONTENT_BYTES + 1)
        .read_to_end(&mut bytes)
        .with_context(|| format!("reading regular file {}", path.display()))?;
    ensure!(
        bytes.len() as u64 <= MAX_CONTENT_BYTES,
        "checked object grew beyond the transaction blob bound"
    );
    let after = file
        .metadata()
        .with_context(|| format!("reinspecting regular file {}", path.display()))?;
    ensure!(
        after.len() == metadata.len(),
        "checked object changed while it was read"
    );
    Ok(bytes)
}

fn read_metadata(path: &Path) -> Result<ObjectMetadata> {
    let bytes = read_bounded_regular(path)?;
    aos_contract::canonical::from_slice(&bytes, "content object metadata")
}

fn ready_outputs(inspection: &Inspection) -> Result<serde_json::Value> {
    let Inspection::Ready(stored) = inspection else {
        bail!("content object did not converge to exact desired bytes");
    };
    Ok(json!({"path": stored.artifact.store_path,"content_sha256": stored.content_sha256}))
}

fn validate_store_path(path: &Path, store_directory: &Path) -> Result<()> {
    ensure!(
        path.is_absolute()
            && path.parent() == Some(store_directory)
            && path.file_name().is_some_and(|name| !name.is_empty()),
        "content-addressed object has an invalid store path"
    );
    Ok(())
}

fn store_path_key(path: &str) -> Result<&str> {
    let name = Path::new(path)
        .file_name()
        .and_then(|name| name.to_str())
        .context("content-addressed store path has no UTF-8 name")?;
    let (key, _) = name
        .split_once('-')
        .context("content-addressed store path has no store key")?;
    ensure!(
        key.len() == 32
            && key
                .bytes()
                .all(|byte| b"0123456789abcdfghijklmnpqrsvwxyz".contains(&byte)),
        "content-addressed store path has an invalid store key"
    );
    Ok(key)
}

fn create_real_directory(path: &Path) -> Result<()> {
    match fs::create_dir(path) {
        Ok(()) => {
            File::open(path)
                .context("opening new content object directory")?
                .sync_all()
                .context("syncing new content object directory")?;
        }
        Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {}
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            let parent = path
                .parent()
                .context("content object directory has no parent")?;
            create_real_directory(parent)?;
            fs::create_dir(path).context("creating content object directory")?;
            sync_directory(parent)?;
        }
        Err(error) => return Err(error).context("creating content object directory"),
    }
    let metadata = fs::symlink_metadata(path).context("inspecting content object directory")?;
    ensure!(
        metadata.is_dir(),
        "content object directory is not a real directory"
    );
    Ok(())
}

fn remove_if_present(path: &Path) -> Result<()> {
    match fs::symlink_metadata(path) {
        Ok(metadata) if metadata.is_file() || metadata.file_type().is_symlink() => {
            fs::remove_file(path).context("removing stale content object temporary")
        }
        Ok(_) => bail!("content object temporary path has an unexpected type"),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error).context("inspecting content object temporary"),
    }
}

fn remove_symlink_if_present(path: &Path) -> Result<()> {
    match fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_symlink() => {
            fs::remove_file(path).context("removing content object GC root")
        }
        Ok(_) => bail!("content object GC root is not a symlink"),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error).context("inspecting content object GC root"),
    }
}

fn remove_regular_if_present(path: &Path) -> Result<()> {
    match fs::symlink_metadata(path) {
        Ok(metadata) if metadata.is_file() => {
            fs::remove_file(path).context("removing content object metadata")
        }
        Ok(_) => bail!("content object metadata is not a regular file"),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error).context("inspecting content object metadata"),
    }
}

fn sync_directory(path: &Path) -> Result<()> {
    File::open(path)
        .with_context(|| format!("opening directory {}", path.display()))?
        .sync_all()
        .with_context(|| format!("syncing directory {}", path.display()))
}

fn temporary_suffix() -> String {
    format!(
        "{}-{}",
        std::process::id(),
        TEMPORARY_SEQUENCE.fetch_add(1, Ordering::Relaxed)
    )
}

#[cfg(test)]
mod tests;
