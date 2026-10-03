//! Pinned current disk contents distinct from architecture-keyed boot assets.
//!
//! The source root contains guest writes. Its digest is taken only after the
//! native seal has made it read-only. The original boot image and parentless
//! VMState inode remain separately owned through child file staging.

use std::fs::File;
use std::io::{Read, Seek, SeekFrom};
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};

use crucible::ContentHash;

use super::hot_fork_boundary_error;
use crucible::SchedulerError;

/// One independently admitted immutable ancestor in the complete backing chain.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(in crate::vm_lifecycle) struct ImmutableHotForkBackingFile {
    pub(super) path: PathBuf,
    pub(super) identity: (u64, u64),
    pub(super) content: ContentHash,
}

/// Process-neutral whole disk basis carried with a child continuation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(in crate::vm_lifecycle) struct ProductionVmHotForkDiskBasis {
    pub(super) source_pid: i64,
    pub(super) seal_generation: u64,
    pub(super) backend_id: u64,
    pub(super) snapshot_path: PathBuf,
    pub(super) snapshot_identity: (u64, u64),
    pub(super) snapshot_content: ContentHash,
    pub(super) boot_path: PathBuf,
    pub(super) boot_identity: (u64, u64),
    pub(super) boot_content: ContentHash,
    pub(super) vmstate_path: PathBuf,
    pub(super) vmstate_identity: (u64, u64),
    pub(super) vmstate_content: ContentHash,
    pub(super) detached_path: PathBuf,
    pub(super) detached_identity: (u64, u64),
    pub(super) detached_content: ContentHash,
    pub(super) backing_files: Vec<ImmutableHotForkBackingFile>,
}

impl ProductionVmHotForkDiskBasis {
    /// Returns the immutable source ancestors admitted for an actual child.
    pub(in crate::vm_lifecycle) fn immutable_backing_chain(
        &self,
    ) -> Vec<ImmutableHotForkBackingFile> {
        let mut backings = vec![ImmutableHotForkBackingFile {
            path: self.snapshot_path.clone(),
            identity: self.snapshot_identity,
            content: self.snapshot_content,
        }];
        backings.extend(self.backing_files.iter().cloned());
        backings
    }

    pub(in crate::vm_lifecycle) fn reopen_current(
        &self,
        expected_boot: ContentHash,
    ) -> Result<Vec<File>, SchedulerError> {
        if self.source_pid <= 0
            || self.seal_generation == 0
            || self.backend_id == 0
            || self.boot_content != expected_boot
        {
            return Err(hot_fork_boundary_error(
                "child disk basis differs from the authored boot image or native seal",
            ));
        }
        let immutable = [
            (
                &self.snapshot_path,
                self.snapshot_identity,
                self.snapshot_content,
            ),
            (&self.boot_path, self.boot_identity, self.boot_content),
        ];
        let mut files = Vec::with_capacity(4);
        for (path, identity, content) in immutable {
            let file = File::open(path).map_err(|error| {
                hot_fork_boundary_error(format!(
                    "reopen retained hot-fork disk {}: {error}",
                    path.display(),
                ))
            })?;
            if hash_owned_file(&file, path, "retained hot-fork disk")? != (identity, content) {
                return Err(hot_fork_boundary_error(format!(
                    "retained hot-fork disk {} changed before child construction",
                    path.display(),
                )));
            }
            files.push(file);
        }

        for backing in &self.backing_files {
            let file = File::open(&backing.path).map_err(|error| {
                hot_fork_boundary_error(format!("reopen immutable backing: {error}"))
            })?;
            if hash_owned_file(&file, &backing.path, "immutable backing")?
                != (backing.identity, backing.content)
            {
                return Err(hot_fork_boundary_error(
                    "immutable ancestor changed before child construction",
                ));
            }
            files.push(file);
        }

        // VMState and the detached overlay are writable transaction files.
        // Their fork-time contents belong to the native private-file plan;
        // retaining their original inodes does not claim immutable bytes.
        for (path, identity) in [
            (&self.vmstate_path, self.vmstate_identity),
            (&self.detached_path, self.detached_identity),
        ] {
            let file = File::open(path).map_err(|error| {
                hot_fork_boundary_error(format!(
                    "reopen mutable hot-fork file {}: {error}",
                    path.display(),
                ))
            })?;
            if !pinned_identity_current(&file, path, identity)? {
                return Err(hot_fork_boundary_error(format!(
                    "mutable hot-fork file {} no longer names its original inode",
                    path.display(),
                )));
            }
            files.push(file);
        }
        Ok(files)
    }
}

/// Identity copied only from an authenticated seal by the native adapter.
pub(super) struct NativeDiskSealIdentity {
    pub(super) source_pid: i64,
    pub(super) generation: u64,
    pub(super) backend_id: u64,
    pub(super) snapshot_identity: (u64, u64),
}

/// Original open inodes retained by the prepared source world.
pub(super) struct PinnedHotForkDiskFiles {
    basis: ProductionVmHotForkDiskBasis,
    snapshot: File,
    boot: File,
    vmstate: File,
    detached: File,
    backings: Vec<(File, ImmutableHotForkBackingFile)>,
}

impl PinnedHotForkDiskFiles {
    /// Authenticates the original files against the native seal and boot asset.
    ///
    /// # Errors
    ///
    /// Returns an error when inode custody, file contents, or the admitted boot
    /// image differs, or when a file changes while it is being hashed.
    pub(super) fn capture(
        seal: NativeDiskSealIdentity,
        snapshot: (File, &Path),
        boot: (File, &Path),
        expected_boot: ContentHash,
        vmstate: (File, &Path),
        detached: (File, &Path),
    ) -> Result<Self, SchedulerError> {
        let (snapshot, snapshot_path) = snapshot;
        let (boot, boot_path) = boot;
        let (vmstate, vmstate_path) = vmstate;
        let (detached, detached_path) = detached;

        let (snapshot_identity, snapshot_content) =
            hash_owned_file(&snapshot, snapshot_path, "sealed current root")?;
        if snapshot_identity != seal.snapshot_identity {
            return Err(hot_fork_boundary_error(
                "sealed root inode differs from the native open current file",
            ));
        }
        let (boot_identity, boot_content) =
            hash_owned_file(&boot, boot_path, "authored boot image")?;
        if boot_content != expected_boot {
            return Err(hot_fork_boundary_error(
                "authored boot image changed since production admission",
            ));
        }
        reject_external_qcow2_backing(&boot)?;

        let (vmstate_identity, vmstate_content) =
            hash_owned_file(&vmstate, vmstate_path, "parentless VMState container")?;
        let (detached_identity, detached_content) =
            hash_owned_file(&detached, detached_path, "new empty root overlay")?;
        let basis = ProductionVmHotForkDiskBasis {
            source_pid: seal.source_pid,
            seal_generation: seal.generation,
            backend_id: seal.backend_id,
            snapshot_path: snapshot_path.to_owned(),
            snapshot_identity,
            snapshot_content,
            boot_path: boot_path.to_owned(),
            boot_identity,
            boot_content,
            vmstate_path: vmstate_path.to_owned(),
            vmstate_identity,
            vmstate_content,
            detached_path: detached_path.to_owned(),
            detached_identity,
            detached_content,
            backing_files: Vec::new(),
        };
        Ok(Self {
            basis,
            snapshot,
            boot,
            vmstate,
            detached,
            backings: Vec::new(),
        })
    }

    /// Duplicates the actual current writable overlay retained by the source.
    ///
    /// # Errors
    ///
    /// Returns an error when original inode custody is no longer current.
    pub(super) fn open_current_overlay(&self) -> Result<File, SchedulerError> {
        if !pinned_identity_current(
            &self.detached,
            &self.basis.detached_path,
            self.basis.detached_identity,
        )? {
            return Err(hot_fork_boundary_error(
                "current writable overlay lost original inode custody",
            ));
        }
        self.detached.try_clone().map_err(|error| {
            hot_fork_boundary_error(format!("duplicate current writable overlay: {error}"))
        })
    }

    /// Retains every prior immutable snapshot when a new writable root is sealed.
    ///
    /// # Errors
    ///
    /// Returns an error when an original ancestor changed or cannot be retained.
    pub(super) fn retain_prior_backings(&mut self, prior: &Self) -> Result<(), SchedulerError> {
        let snapshot = ImmutableHotForkBackingFile {
            path: prior.basis.snapshot_path.clone(),
            identity: prior.basis.snapshot_identity,
            content: prior.basis.snapshot_content,
        };
        for (file, backing) in std::iter::once((&prior.snapshot, &snapshot))
            .chain(prior.backings.iter().map(|(file, backing)| (file, backing)))
        {
            if hash_owned_file(file, &backing.path, "retained immutable ancestor")?
                != (backing.identity, backing.content)
            {
                return Err(hot_fork_boundary_error(
                    "retained immutable ancestor changed before reacquisition",
                ));
            }
            let retained = file.try_clone().map_err(|error| {
                hot_fork_boundary_error(format!("retain immutable ancestor: {error}"))
            })?;
            self.basis.backing_files.push(backing.clone());
            self.backings.push((retained, backing.clone()));
        }
        Ok(())
    }

    /// Retains immutable ancestors admitted during actual child adoption.
    ///
    /// # Errors
    ///
    /// Returns an error on replacement, mutation or unavailable original files.
    pub(super) fn retain_adopted_backings(
        &mut self,
        backings: &[ImmutableHotForkBackingFile],
    ) -> Result<(), SchedulerError> {
        for backing in backings {
            let file = File::open(&backing.path).map_err(|error| {
                hot_fork_boundary_error(format!("open admitted child backing: {error}"))
            })?;
            if hash_owned_file(&file, &backing.path, "admitted child backing")?
                != (backing.identity, backing.content)
            {
                return Err(hot_fork_boundary_error(
                    "admitted child backing changed before descendant capture",
                ));
            }
            self.basis.backing_files.push(backing.clone());
            self.backings.push((file, backing.clone()));
        }
        Ok(())
    }

    /// Returns the independently authenticated continuation disk basis.
    pub(super) fn basis(&self) -> &ProductionVmHotForkDiskBasis {
        &self.basis
    }

    /// Independently authenticates every native graph file against admitted custody.
    ///
    /// The roster includes shared file visits. Each must bind one of the exact
    /// admitted inodes, and every admitted file must occur in the complete graph.
    ///
    /// # Errors
    ///
    /// Returns an error on missing or foreign files, changed size or content,
    /// or mutation while reading the retained descriptor.
    pub(super) fn authenticate_graph_files(
        &self,
        members: &[((u64, u64), u64, &str, bool)],
    ) -> Result<(), SchedulerError> {
        use sha2::{Digest, Sha256};
        use std::os::unix::fs::FileExt;

        let mut admitted = vec![
            (&self.snapshot, self.basis.snapshot_identity, false),
            (&self.boot, self.basis.boot_identity, false),
            (&self.vmstate, self.basis.vmstate_identity, true),
            (&self.detached, self.basis.detached_identity, true),
        ];
        admitted.extend(
            self.backings
                .iter()
                .map(|(file, backing)| (file, backing.identity, false)),
        );
        let mut seen = std::collections::BTreeMap::new();
        for &(identity, size, digest, originally_writable) in members {
            if let Some(prior) = seen.insert(identity, (size, digest, originally_writable))
                && prior != (size, digest, originally_writable)
            {
                return Err(hot_fork_boundary_error("shared graph file visits disagree"));
            }
            if !admitted.iter().any(|(_, admitted, writable)| {
                *admitted == identity && *writable == originally_writable
            }) {
                return Err(hot_fork_boundary_error(
                    "native graph contains a file outside independently admitted custody",
                ));
            }
        }
        let mut buffer = vec![0_u8; 64 * 1024];
        for (file, identity, _) in admitted {
            let &(size, digest, _) = seen.get(&identity).ok_or_else(|| {
                hot_fork_boundary_error("complete native graph omitted an admitted file")
            })?;
            let before = file
                .metadata()
                .map_err(|error| hot_fork_boundary_error(format!("inspect graph file: {error}")))?;
            if !before.is_file() || (before.dev(), before.ino()) != identity || before.len() != size
            {
                return Err(hot_fork_boundary_error(
                    "native graph differs from the admitted regular inode and size",
                ));
            }
            let mut hash = Sha256::new();
            let mut offset = 0_u64;
            while offset < size {
                let limit =
                    usize::try_from((size - offset).min(buffer.len() as u64)).map_err(|error| {
                        hot_fork_boundary_error(format!("bound graph file read: {error}"))
                    })?;
                let count = file
                    .read_at(&mut buffer[..limit], offset)
                    .map_err(|error| {
                        hot_fork_boundary_error(format!("hash retained graph file: {error}"))
                    })?;
                if count == 0 {
                    return Err(hot_fork_boundary_error(
                        "graph file became shorter during authentication",
                    ));
                }
                hash.update(&buffer[..count]);
                offset += count as u64;
            }
            let actual = hash
                .finalize()
                .iter()
                .map(|byte| format!("{byte:02x}"))
                .collect::<String>();
            let after = file.metadata().map_err(|error| {
                hot_fork_boundary_error(format!("reinspect graph file: {error}"))
            })?;
            if actual != digest
                || (after.dev(), after.ino()) != identity
                || after.len() != size
                || before.ctime() != after.ctime()
                || before.ctime_nsec() != after.ctime_nsec()
            {
                return Err(hot_fork_boundary_error(
                    "native complete-file digest differs from independently held bytes",
                ));
            }
        }
        Ok(())
    }

    /// Rechecks immutable bytes and all retained file identities.
    ///
    /// # Errors
    ///
    /// Returns an error when an original file cannot be inspected or changes
    /// during full content authentication.
    pub(super) fn current(&self) -> Result<bool, SchedulerError> {
        let immutable = [
            (
                &self.snapshot,
                self.basis.snapshot_path.as_path(),
                self.basis.snapshot_identity,
                self.basis.snapshot_content,
            ),
            (
                &self.boot,
                self.basis.boot_path.as_path(),
                self.basis.boot_identity,
                self.basis.boot_content,
            ),
        ];
        for (file, path, identity, content) in immutable {
            if hash_owned_file(file, path, "retained hot-fork disk file")? != (identity, content) {
                return Ok(false);
            }
        }
        for (file, backing) in &self.backings {
            if hash_owned_file(file, &backing.path, "retained immutable ancestor")?
                != (backing.identity, backing.content)
            {
                return Ok(false);
            }
        }
        Ok(pinned_identity_current(
            &self.vmstate,
            &self.basis.vmstate_path,
            self.basis.vmstate_identity,
        )? && pinned_identity_current(
            &self.detached,
            &self.basis.detached_path,
            self.basis.detached_identity,
        )?)
    }
}

fn hash_owned_file(
    file: &File,
    path: &Path,
    purpose: &str,
) -> Result<((u64, u64), ContentHash), SchedulerError> {
    let mut reader = file.try_clone().map_err(|error| {
        hot_fork_boundary_error(format!("duplicate {purpose} descriptor: {error}",))
    })?;
    let before = reader.metadata().map_err(|error| {
        hot_fork_boundary_error(format!("inspect {purpose} descriptor: {error}",))
    })?;
    let named = std::fs::symlink_metadata(path)
        .map_err(|error| hot_fork_boundary_error(format!("inspect {purpose} path: {error}",)))?;
    if !before.is_file()
        || !named.is_file()
        || before.dev() != named.dev()
        || before.ino() != named.ino()
    {
        return Err(hot_fork_boundary_error(format!(
            "{purpose} path no longer names its pinned regular inode",
        )));
    }
    reader
        .seek(SeekFrom::Start(0))
        .map_err(|error| hot_fork_boundary_error(format!("seek {purpose}: {error}",)))?;
    // Hashing runs on scheduler threads whose stacks also hold lifecycle state.
    // Keep the large streaming buffer on the heap without weakening full-file
    // authentication at any admission boundary.
    let mut buffer = vec![0_u8; 1024 * 1024];
    let mut hasher = blake3::Hasher::new();
    loop {
        let count = reader
            .read(&mut buffer)
            .map_err(|error| hot_fork_boundary_error(format!("hash {purpose}: {error}",)))?;
        if count == 0 {
            break;
        }
        hasher.update(&buffer[..count]);
    }
    let after = reader
        .metadata()
        .map_err(|error| hot_fork_boundary_error(format!("reinspect {purpose}: {error}",)))?;
    if before.dev() != after.dev()
        || before.ino() != after.ino()
        || before.len() != after.len()
        || before.modified().ok() != after.modified().ok()
        || before.ctime() != after.ctime()
        || before.ctime_nsec() != after.ctime_nsec()
    {
        return Err(hot_fork_boundary_error(format!(
            "{purpose} changed while its contents were authenticated",
        )));
    }
    Ok((
        (after.dev(), after.ino()),
        ContentHash {
            bytes: *hasher.finalize().as_bytes(),
        },
    ))
}

fn pinned_identity_current(
    file: &File,
    path: &Path,
    identity: (u64, u64),
) -> Result<bool, SchedulerError> {
    let descriptor = file.metadata().map_err(|error| {
        hot_fork_boundary_error(format!("inspect pinned file {}: {error}", path.display(),))
    })?;
    let named = std::fs::symlink_metadata(path).map_err(|error| {
        hot_fork_boundary_error(format!("inspect named file {}: {error}", path.display(),))
    })?;
    Ok(descriptor.is_file()
        && named.is_file()
        && (descriptor.dev(), descriptor.ino()) == identity
        && (named.dev(), named.ino()) == identity)
}

fn reject_external_qcow2_backing(file: &File) -> Result<(), SchedulerError> {
    let mut reader = file.try_clone().map_err(|error| {
        hot_fork_boundary_error(format!("duplicate boot image header: {error}",))
    })?;
    reader
        .seek(SeekFrom::Start(0))
        .map_err(|error| hot_fork_boundary_error(format!("seek boot image header: {error}",)))?;
    let mut header = [0_u8; 80];
    let count = reader
        .read(&mut header)
        .map_err(|error| hot_fork_boundary_error(format!("read boot image header: {error}",)))?;
    if count < 4 || &header[..4] != b"QFI\xfb" {
        return Ok(());
    }
    if count < 80 {
        return Err(hot_fork_boundary_error(
            "qcow2 boot image header is truncated",
        ));
    }
    let version = u32::from_be_bytes(
        header[4..8]
            .try_into()
            .map_err(|_error| hot_fork_boundary_error("qcow2 version header is truncated"))?,
    );
    let backing_offset = u64::from_be_bytes(
        header[8..16]
            .try_into()
            .map_err(|_error| hot_fork_boundary_error("qcow2 backing header is truncated"))?,
    );
    let backing_length = u32::from_be_bytes(
        header[16..20]
            .try_into()
            .map_err(|_error| hot_fork_boundary_error("qcow2 backing length is truncated"))?,
    );
    let incompatible = u64::from_be_bytes(
        header[72..80]
            .try_into()
            .map_err(|_error| hot_fork_boundary_error("qcow2 feature header is truncated"))?,
    );
    if !matches!(version, 2 | 3)
        || backing_offset != 0
        || backing_length != 0
        || (version == 3 && incompatible != 0)
    {
        return Err(hot_fork_boundary_error(
            "authored qcow2 boot image has an external backing or unsupported feature",
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    // crucible-lint: allow panic-shortcut -- failed filesystem fixtures must fail the custody test.
    #![allow(clippy::unwrap_used)]

    use super::*;
    use std::os::unix::fs::symlink;

    #[test]
    fn native_graph_files_require_full_independent_bytes_and_every_owned_inode()
    -> Result<(), Box<dyn std::error::Error>> {
        use sha2::{Digest, Sha256};
        let directory = tempfile::tempdir()?;
        let paths =
            ["snapshot", "boot", "vmstate", "detached"].map(|name| directory.path().join(name));
        for (index, path) in paths.iter().enumerate() {
            std::fs::write(path, [index as u8; 16])?;
        }
        let snapshot = File::open(&paths[0])?;
        let metadata = snapshot.metadata()?;
        let files = PinnedHotForkDiskFiles::capture(
            NativeDiskSealIdentity {
                source_pid: 451,
                generation: 1,
                backend_id: 2,
                snapshot_identity: (metadata.dev(), metadata.ino()),
            },
            (snapshot, &paths[0]),
            (File::open(&paths[1])?, &paths[1]),
            ContentHash::from_bytes(&[1_u8; 16]),
            (File::open(&paths[2])?, &paths[2]),
            (File::open(&paths[3])?, &paths[3]),
        )?;
        let digests = paths.each_ref().map(|path| {
            Sha256::digest(std::fs::read(path).unwrap())
                .iter()
                .map(|byte| format!("{byte:02x}"))
                .collect::<String>()
        });
        let mut members = Vec::new();
        for (index, path) in paths.iter().enumerate() {
            let metadata = std::fs::metadata(path)?;
            members.push((
                (metadata.dev(), metadata.ino()),
                metadata.len(),
                digests[index].as_str(),
                index >= 2,
            ));
        }
        files.authenticate_graph_files(&members)?;
        assert!(files.authenticate_graph_files(&members[..3]).is_err());
        let mut foreign = members.clone();
        foreign[0].0.1 += 1;
        assert!(files.authenticate_graph_files(&foreign).is_err());
        let mut size = members.clone();
        size[2].1 += 1;
        assert!(files.authenticate_graph_files(&size).is_err());
        let mut disposition = members.clone();
        disposition[2].3 = false;
        assert!(files.authenticate_graph_files(&disposition).is_err());

        let modified = std::fs::metadata(&paths[2])?.modified()?;
        std::fs::write(&paths[2], [9_u8; 16])?;
        File::options()
            .write(true)
            .open(&paths[2])?
            .set_times(std::fs::FileTimes::new().set_modified(modified))?;
        assert!(files.authenticate_graph_files(&members).is_err());
        std::fs::write(&paths[2], [2_u8; 16])?;
        files.authenticate_graph_files(&members)?;

        let fresh_path = directory.path().join("fresh-overlay");
        std::fs::write(&fresh_path, [4_u8; 16])?;
        let current_root = files.open_current_overlay()?;
        let current = current_root.metadata()?;
        let mut reacquired = PinnedHotForkDiskFiles::capture(
            NativeDiskSealIdentity {
                source_pid: 451,
                generation: 2,
                backend_id: 2,
                snapshot_identity: (current.dev(), current.ino()),
            },
            (current_root, &paths[3]),
            (File::open(&paths[1])?, &paths[1]),
            ContentHash::from_bytes(&[1_u8; 16]),
            (File::open(&paths[2])?, &paths[2]),
            (File::open(&fresh_path)?, &fresh_path),
        )?;
        reacquired.retain_prior_backings(&files)?;
        assert_eq!(reacquired.basis().backing_files.len(), 1);
        assert_eq!(
            reacquired
                .basis()
                .reopen_current(ContentHash::from_bytes(&[1_u8; 16]))?
                .len(),
            5
        );
        std::fs::write(&paths[0], [9_u8; 16])?;
        assert!(!reacquired.current()?);
        assert!(
            reacquired
                .basis()
                .reopen_current(ContentHash::from_bytes(&[1_u8; 16]))
                .is_err()
        );
        Ok(())
    }

    #[test]
    fn pinned_content_rejects_mutation_and_path_replacement() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("root.qcow2");
        std::fs::write(&path, b"first rooted content").unwrap();
        let file = File::open(&path).unwrap();
        let original = hash_owned_file(&file, &path, "root").unwrap();
        assert_eq!(original.1, ContentHash::from_bytes(b"first rooted content"));

        std::fs::write(&path, b"changed rooted content").unwrap();
        assert_ne!(hash_owned_file(&file, &path, "root").unwrap(), original);

        std::fs::rename(&path, directory.path().join("old-root.qcow2")).unwrap();
        std::fs::write(&path, b"replacement rooted content").unwrap();
        assert!(hash_owned_file(&file, &path, "root").is_err());
    }

    #[test]
    fn pinned_content_rejects_symlinked_name_and_external_boot_backing() {
        let directory = tempfile::tempdir().unwrap();
        let actual = directory.path().join("actual.qcow2");
        let alias = directory.path().join("alias.qcow2");
        std::fs::write(&actual, b"content").unwrap();
        symlink(&actual, &alias).unwrap();
        assert!(hash_owned_file(&File::open(&alias).unwrap(), &alias, "root").is_err());

        let mut header = [0_u8; 80];
        header[..4].copy_from_slice(b"QFI\xfb");
        header[4..8].copy_from_slice(&3_u32.to_be_bytes());
        header[8..16].copy_from_slice(&80_u64.to_be_bytes());
        header[16..20].copy_from_slice(&4_u32.to_be_bytes());
        std::fs::write(&actual, header).unwrap();
        assert!(reject_external_qcow2_backing(&File::open(&actual).unwrap()).is_err());
    }

    #[test]
    fn child_reopens_exact_sealed_basis_and_refuses_swapped_vmstate() {
        let directory = tempfile::tempdir().unwrap();
        let paths =
            ["source", "boot", "vmstate", "detached"].map(|name| directory.path().join(name));
        let bytes = [b"source".as_slice(), b"boot", b"vmstate", b"detached"];
        for (path, content) in paths.iter().zip(bytes) {
            std::fs::write(path, content).unwrap();
        }
        let identities = paths
            .each_ref()
            .map(|path| hash_owned_file(&File::open(path).unwrap(), path, "test basis").unwrap());
        let basis = ProductionVmHotForkDiskBasis {
            source_pid: 1,
            seal_generation: 1,
            backend_id: 1,
            snapshot_path: paths[0].clone(),
            snapshot_identity: identities[0].0,
            snapshot_content: identities[0].1,
            boot_path: paths[1].clone(),
            boot_identity: identities[1].0,
            boot_content: identities[1].1,
            vmstate_path: paths[2].clone(),
            vmstate_identity: identities[2].0,
            vmstate_content: identities[2].1,
            detached_path: paths[3].clone(),
            detached_identity: identities[3].0,
            detached_content: identities[3].1,
            backing_files: Vec::new(),
        };
        assert_eq!(basis.reopen_current(identities[1].1).unwrap().len(), 4);
        assert!(
            basis
                .reopen_current(ContentHash::from_bytes(b"wrong boot"))
                .is_err()
        );

        // A VMState write is permitted; replacing its pinned inode is not.
        std::fs::write(&paths[2], b"different vmstate").unwrap();
        assert_eq!(basis.reopen_current(identities[1].1).unwrap().len(), 4);
        std::fs::rename(&paths[2], directory.path().join("old-vmstate")).unwrap();
        std::fs::write(&paths[2], b"replacement vmstate").unwrap();
        assert!(basis.reopen_current(identities[1].1).is_err());
    }
}
