//! Native filesystem effects and durable identity claims.
//!
//! Claims record the inode established by an effect. Existing unclaimed paths
//! are never adopted, and interrupted creation without an inode receipt requires
//! intervention. Persistent retention is controlled by the activation runtime.

use super::*;
use aos_ability_runtime::activation::{Action, Invocation as NativeInvocation};
use std::os::unix::fs::MetadataExt as _;

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Claim {
    id: String,
    revision: String,
    path: PathBuf,
    device: u64,
    inode: u64,
    kind: String,
    mode: u32,
    uid: Option<u32>,
    gid: Option<u32>,
    digest: Option<Sha256Digest>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Input {
    path: PathBuf,
    mode: String,
    owner: Option<String>,
    group: Option<String>,
    #[serde(default = "directory_kind")]
    kind: String,
    source_path: Option<PathBuf>,
    #[serde(default = "default_max_bytes")]
    max_bytes: u64,
    parent_resource: Option<String>,
}

fn directory_kind() -> String {
    "directory".into()
}
fn default_max_bytes() -> u64 {
    16 * 1024 * 1024
}

/// Implements native filesystem operations against private durable claims.
pub struct NativeFilesystem {
    state_root: PathBuf,
    roots: Vec<PathBuf>,
    immutable_roots: Vec<PathBuf>,
}

impl NativeFilesystem {
    /// Selects production state and mutable path roots.
    pub fn production() -> Self {
        Self {
            state_root: "/var/lib/aos/native-filesystem".into(),
            immutable_roots: vec!["/nix/store".into()],
            // Platform directories remain shared roots even when their containing
            // /var tree is mutable. Effects may own entries beneath them only.
            roots: [
                "/run",
                "/var",
                "/var/lib",
                "/var/log",
                "/var/etc",
                "/var/cache",
                "/var/spool",
                "/var/tmp",
                "/var/home",
                "/var/srv",
                "/var/roothome",
                "/etc",
                "/opt",
                "/nix/var/nix/gcroots",
            ]
            .into_iter()
            .map(PathBuf::from)
            .collect(),
        }
    }

    /// Handles one resolved native invocation.
    ///
    /// # Errors
    /// Returns an error for invalid inputs, conflicting claims, unsafe paths,
    /// failed mutation, or an incompatible process action.
    pub fn handle(&self, purpose: &str, bytes: &[u8]) -> Result<Vec<u8>> {
        let invocation: NativeInvocation = serde_json::from_slice(bytes)?;
        ensure!(
            matches!(purpose, "apply" | "remove" | "observe"),
            "unsupported native filesystem action"
        );
        ensure!(
            purpose == "observe"
                || matches!(
                    (purpose, invocation.action),
                    ("apply", Action::Apply) | ("remove", Action::Remove)
                ),
            "process action differs from invocation"
        );
        let identity = &invocation.effect.identity;
        let domain = identity
            .iter()
            .position(|part| part == "filesystem")
            .context("filesystem invocation has no domain identity")?;
        let operation = identity
            .get(domain + 1)
            .context("filesystem operation is absent")?;
        if operation == "view" {
            return self.view(purpose, &invocation);
        }
        ensure!(
            matches!(
                operation.as_str(),
                "directory"
                    | "allocate"
                    | "persistentAllocate"
                    | "entry"
                    | "privilegedExecutable"
                    | "symlinkTree"
            ),
            "unknown filesystem operation"
        );
        validate_provider_owned_path(
            &self.state_root,
            &self.roots.iter().map(PathBuf::as_path).collect::<Vec<_>>(),
        )?;
        let _lock = StateLock::acquire(&self.state_root, invocation.effect.timeout_ms)?;
        let input: Input = if operation == "privilegedExecutable" {
            #[derive(Deserialize)]
            #[serde(deny_unknown_fields)]
            struct Privileged {
                name: String,
                source: PathBuf,
                owner: String,
                group: String,
                mode: String,
            }
            let privileged: Privileged = serde_json::from_value(invocation.input.clone())?;
            ensure!(
                !privileged.name.is_empty()
                    && privileged
                        .name
                        .bytes()
                        .all(|byte| byte.is_ascii_alphanumeric()
                            || matches!(byte, b'_' | b'-' | b'.'))
                    && privileged.name != "."
                    && privileged.name != "..",
                "invalid privileged executable name"
            );
            let input = Input {
                path: Path::new("/run/wrappers/bin").join(privileged.name),
                mode: privileged.mode,
                owner: Some(privileged.owner),
                group: Some(privileged.group),
                kind: "copied-file".into(),
                source_path: Some(privileged.source),
                max_bytes: default_max_bytes(),
                parent_resource: None,
            };
            input
        } else {
            serde_json::from_value(invocation.input.clone())?
        };
        let mut input = input;
        if operation == "symlinkTree" {
            input.kind = "symlink-tree".into();
        }
        self.validate_path(&input.path, input.kind == "symlink-tree")?;
        let claim_path = self.claim_path(&invocation.id);
        let claim: Option<Claim> = read_private_record(&claim_path, "native filesystem claim")?;
        if let Some(claim) = &claim {
            ensure!(
                claim.id == invocation.id,
                "filesystem claim belongs to another effect"
            );
        }
        let output = match purpose {
            "observe" => self.observe(&invocation, &input, claim.as_ref())?,
            "remove" => {
                self.remove(&input.path, claim.as_ref())?;
                if claim_path.exists() {
                    fs::remove_file(&claim_path)?;
                    File::open(&self.state_root)?.sync_all()?;
                }
                json!({})
            }
            "apply" => {
                parse_mode(&input.mode)?;
                self.ownership(&input)?;
                if operation == "privilegedExecutable" {
                    let source = input
                        .source_path
                        .as_ref()
                        .context("privileged executable has no source")?;
                    inspect_regular_file_nofollow(source, input.max_bytes)?;
                    create_directory_nofollow(
                        Path::new("/run/wrappers/bin"),
                        0o755,
                        StorageOwnership {
                            uid: Some(Uid::ROOT),
                            gid: Some(Gid::ROOT),
                        },
                        true,
                    )?;
                }
                if let Some(claim) = &claim {
                    if claim.path != input.path {
                        self.validate_path(&claim.path, claim.kind == "symlink-tree")?;
                        self.remove(&claim.path, Some(claim))?;
                        fs::remove_file(&claim_path)?;
                    }
                }
                let current = claim.as_ref().filter(|claim| claim.path == input.path);
                let installed = self.apply(&invocation, &input, current)?;
                write_private_record(&self.state_root, &claim_path, &installed)?;
                self.outputs(&invocation.id, &input.path)?
            }
            _ => bail!("unsupported native filesystem action"),
        };
        Ok(serde_json::to_vec(&output)?)
    }

    fn validate_path(&self, path: &Path, allow_symlink: bool) -> Result<()> {
        let roots = self.roots.iter().map(PathBuf::as_path).collect::<Vec<_>>();
        if allow_symlink {
            ensure!(
                path.is_absolute()
                    && path
                        .components()
                        .all(|part| matches!(part, Component::RootDir | Component::Normal(_)))
                    && !roots.contains(&path)
                    && roots.iter().any(|root| path.starts_with(root)),
                "tree destination is not a normalized mutable entry path"
            );
            // The final entry is deliberately a link; every containing directory
            // still has to be opened without following links.
            open_directory_nofollow(path.parent().context("tree entry has no parent")?)?;
        } else {
            validate_provider_owned_path(path, &roots)?;
        }
        ensure!(
            !path.starts_with(&self.state_root) && !self.state_root.starts_with(path),
            "filesystem path overlaps claim storage"
        );
        Ok(())
    }

    fn claim_path(&self, id: &str) -> PathBuf {
        self.state_root.join(format!(
            "{}.json",
            Sha256Digest::of_bytes(id.as_bytes()).hex()
        ))
    }

    fn ownership(&self, input: &Input) -> Result<StorageOwnership> {
        Ok(StorageOwnership {
            uid: input
                .owner
                .as_ref()
                .map(|name| {
                    resolve_identity(Path::new("/etc/passwd"), name, 2, "user").map(Uid::from_raw)
                })
                .transpose()?,
            gid: input
                .group
                .as_ref()
                .map(|name| {
                    resolve_identity(Path::new("/etc/group"), name, 2, "group").map(Gid::from_raw)
                })
                .transpose()?,
        })
    }

    fn apply(
        &self,
        invocation: &NativeInvocation,
        input: &Input,
        claim: Option<&Claim>,
    ) -> Result<Claim> {
        let mode = parse_mode(&input.mode)?;
        let ownership = self.ownership(input)?;
        for entry in fs::read_dir(&self.state_root)? {
            let entry = entry?;
            if entry
                .path()
                .extension()
                .is_none_or(|extension| extension != "json")
            {
                continue;
            }
            let other: Claim = read_private_record(&entry.path(), "filesystem ownership claim")?
                .context("claim disappeared under the mutation lock")?;
            if other.id != invocation.id {
                let authorized_parent = input.path.starts_with(&other.path)
                    && input.path != other.path
                    && other.kind == "directory"
                    && invocation.effect.dependencies.contains(&other.id)
                    && input.parent_resource.as_ref() == Some(&other.id);
                if authorized_parent {
                    let metadata = fs::symlink_metadata(&other.path)
                        .context("inspecting explicitly authorized parent directory")?;
                    self.ensure_identity(&metadata, &other)?;
                } else {
                    validate_storage_claim(&input.path, [other.path])?;
                }
            }
        }
        if let Some(claim) = claim {
            ensure!(
                claim.id == invocation.id,
                "filesystem claim belongs to another effect"
            );
            if let Ok(metadata) = fs::symlink_metadata(&input.path) {
                self.ensure_identity(&metadata, claim)?;
            }
        }
        let (identity, digest) = match input.kind.as_str() {
            "directory" => {
                ensure!(
                    input.source_path.is_none(),
                    "directory input has a file source"
                );
                let identity = if input.path.exists() {
                    let claim = claim.context("existing directory has no ownership claim")?;
                    let descriptor = open_directory_nofollow(&input.path)?;
                    let metadata = fstat(&descriptor)?;
                    ensure!(
                        (metadata.st_dev, metadata.st_ino) == (claim.device, claim.inode),
                        "directory changed before mutation"
                    );
                    apply_metadata(&descriptor, mode, ownership)?;
                    raw_storage_identity(&descriptor)?
                } else {
                    create_directory_nofollow(&input.path, mode, ownership, false)?
                };
                (identity, None)
            }
            "empty-file" => {
                ensure!(
                    input.source_path.is_none(),
                    "mutable file input has a source"
                );
                let identity = allocate_file_nofollow(
                    &input.path,
                    mode,
                    ownership,
                    claim
                        .filter(|_| input.path.exists())
                        .map(|claim| (claim.device, claim.inode)),
                )?;
                (identity, None)
            }
            "copied-file" => {
                let source = input
                    .source_path
                    .as_ref()
                    .context("copied entry has no source")?;
                let (identity, digest) = copy_file_atomic_with_identity(
                    source,
                    &input.path,
                    input.max_bytes,
                    mode,
                    ownership,
                    claim
                        .filter(|_| input.path.exists())
                        .map(|claim| (claim.device, claim.inode)),
                )?;
                (identity, Some(digest))
            }
            "symlink-tree" => {
                ensure!(
                    mode == 0o777,
                    "symlink modes are fixed; source tree retains its immutable modes"
                );
                let source = input
                    .source_path
                    .as_ref()
                    .context("tree entry has no source")?;
                ensure!(
                    source.is_absolute()
                        && self
                            .immutable_roots
                            .iter()
                            .any(|root| source.starts_with(root)),
                    "tree source is outside retained immutable roots"
                );
                let canonical = fs::canonicalize(source)?;
                ensure!(
                    self.immutable_roots
                        .iter()
                        .any(|root| canonical.starts_with(root))
                        && fs::metadata(&canonical)?.is_dir(),
                    "tree source is not an immutable directory"
                );
                let identity = symlink_tree_atomic(
                    &canonical,
                    &input.path,
                    ownership,
                    claim
                        .filter(|_| fs::symlink_metadata(&input.path).is_ok())
                        .map(|claim| (claim.device, claim.inode)),
                )?;
                (
                    identity,
                    Some(Sha256Digest::of_bytes(
                        canonical.as_os_str().as_encoded_bytes(),
                    )),
                )
            }
            _ => bail!("invalid filesystem entry kind"),
        };
        sync_parent(&input.path)?;
        Ok(Claim {
            id: invocation.id.clone(),
            revision: invocation.revision.clone(),
            path: input.path.clone(),
            device: identity.device,
            inode: identity.inode,
            kind: input.kind.clone(),
            mode,
            uid: ownership.uid.map(Uid::as_raw),
            gid: ownership.gid.map(Gid::as_raw),
            digest,
        })
    }

    fn ensure_identity(&self, metadata: &fs::Metadata, claim: &Claim) -> Result<()> {
        ensure!(
            (metadata.dev(), metadata.ino()) == (claim.device, claim.inode)
                && ((claim.kind == "directory"
                    && metadata.is_dir()
                    && !metadata.file_type().is_symlink())
                    || (matches!(claim.kind.as_str(), "copied-file" | "empty-file")
                        && metadata.is_file()
                        && !metadata.file_type().is_symlink())
                    || (claim.kind == "symlink-tree" && metadata.file_type().is_symlink())),
            "filesystem entry differs from its durable identity claim"
        );
        Ok(())
    }

    fn observe(
        &self,
        invocation: &NativeInvocation,
        input: &Input,
        claim: Option<&Claim>,
    ) -> Result<serde_json::Value> {
        let metadata = match fs::symlink_metadata(&input.path) {
            Ok(metadata) => metadata,
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                if let Some(claim) = claim {
                    let quarantine = input.path.with_file_name(format!(
                        ".aos-native-release-{}",
                        Sha256Digest::of_bytes(claim.id.as_bytes()).hex()
                    ));
                    if let Ok(metadata) = fs::symlink_metadata(&quarantine) {
                        return Ok(
                            json!({"status": if self.ensure_identity(&metadata, claim).is_ok() { "retry-safe" } else { "indeterminate" }}),
                        );
                    }
                }
                return Ok(
                    json!({"status": if invocation.action == Action::Remove && claim.is_none() { "absent" } else { "retry-safe" }}),
                );
            }
            Err(error) => return Err(error.into()),
        };
        let Some(claim) = claim else {
            return Ok(json!({"status":"indeterminate"}));
        };
        if claim.id != invocation.id
            || claim.path != input.path
            || self.ensure_identity(&metadata, claim).is_err()
        {
            return Ok(json!({"status":"indeterminate"}));
        }
        if invocation.action == Action::Remove {
            return Ok(json!({"status":"retry-safe"}));
        }
        let ownership = self.ownership(input)?;
        let exact = claim.revision == invocation.revision
            && metadata.permissions().mode() & 0o7777 == parse_mode(&input.mode)?
            && ownership
                .uid
                .is_none_or(|uid| metadata.uid() == uid.as_raw())
            && ownership
                .gid
                .is_none_or(|gid| metadata.gid() == gid.as_raw());
        let content_exact = if input.kind == "copied-file" {
            let source = input
                .source_path
                .as_ref()
                .context("copied entry has no source")?;
            let expected = inspect_regular_file_nofollow(source, input.max_bytes)?.digest;
            let actual = inspect_regular_file_nofollow(&input.path, input.max_bytes)?.digest;
            claim.digest == Some(expected) && expected == actual
        } else if input.kind == "symlink-tree" {
            let source = fs::canonicalize(
                input
                    .source_path
                    .as_ref()
                    .context("tree entry has no source")?,
            )?;
            let target = fs::read_link(&input.path)?;
            claim.kind == input.kind
                && target == source
                && claim.digest
                    == Some(Sha256Digest::of_bytes(
                        source.as_os_str().as_encoded_bytes(),
                    ))
        } else {
            claim.kind == input.kind
        };
        if exact && content_exact {
            Ok(json!({"status":"current", "outputs": self.outputs(&invocation.id, &input.path)?}))
        } else {
            Ok(json!({"status":"retry-safe"}))
        }
    }

    fn remove(&self, path: &Path, claim: Option<&Claim>) -> Result<()> {
        let Some(claim) = claim else {
            ensure!(
                matches!(fs::symlink_metadata(path), Err(error) if error.kind() == io::ErrorKind::NotFound),
                "refusing to remove an unclaimed path"
            );
            return Ok(());
        };
        ensure!(claim.path == path, "removal path differs from claim");
        let quarantine = path.with_file_name(format!(
            ".aos-native-release-{}",
            Sha256Digest::of_bytes(claim.id.as_bytes()).hex()
        ));
        match fs::symlink_metadata(path) {
            Ok(metadata) => {
                self.ensure_identity(&metadata, claim)?;
                rustix::fs::renameat_with(
                    rustix::fs::CWD,
                    path,
                    rustix::fs::CWD,
                    &quarantine,
                    rustix::fs::RenameFlags::NOREPLACE,
                )?;
                sync_parent(path)?;
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(error) => return Err(error.into()),
        }
        match fs::symlink_metadata(&quarantine) {
            Ok(metadata) => {
                self.ensure_identity(&metadata, claim)?;
                if claim.kind == "directory" {
                    fs::remove_dir_all(&quarantine)?;
                } else {
                    fs::remove_file(&quarantine)?;
                }
                sync_parent(&quarantine)?;
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(error) => return Err(error.into()),
        }
        Ok(())
    }

    fn outputs(&self, id: &str, path: &Path) -> Result<serde_json::Value> {
        Ok(json!({"path": path.to_str().context("filesystem path is not UTF-8")?, "resource": id}))
    }

    fn view(&self, purpose: &str, invocation: &NativeInvocation) -> Result<Vec<u8>> {
        #[derive(Deserialize)]
        #[serde(rename_all = "camelCase", deny_unknown_fields)]
        struct View {
            source_path: PathBuf,
            relative_path: Option<String>,
        }
        let input: View = serde_json::from_value(invocation.input.clone())?;
        let output = if purpose == "remove"
            || (purpose == "observe" && invocation.action == Action::Remove)
        {
            if purpose == "observe" {
                json!({"status":"absent"})
            } else {
                json!({})
            }
        } else {
            let path =
                resolve_storage_view_path(&input.source_path, input.relative_path.as_deref())?;
            let outputs = self.outputs(&invocation.id, &path)?;
            if purpose == "observe" {
                json!({"status":"current", "outputs":outputs})
            } else {
                outputs
            }
        };
        Ok(serde_json::to_vec(&output)?)
    }
}

#[cfg(test)]
mod tests;
