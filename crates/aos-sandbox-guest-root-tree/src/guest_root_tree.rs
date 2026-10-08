//! Exact physical comparison of a populated guest root with its pinned template.
//!
//! The caller supplies two independently protected, quiescent directory trees:
//! the immutable AOS package template and the workspace's mounted root. This
//! scanner compares every template entry and hashes its path, type, mode, and
//! content. Runtime-created files may exist outside that fixed entry set.
//!
//! The separate complete-root disposition measures every destination name
//! through an original directory descriptor. Its bounded resident capture
//! lends measurement DATA only; the caller still owns writer exclusion.

use std::fs::{self, File, Metadata};
use std::io::Read as _;
use std::os::unix::ffi::OsStrExt as _;
use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};
use std::path::{Path, PathBuf};

use sha2::{Digest as _, Sha256};

const DOMAIN: &[u8] = b"aos.sandbox.guest-root-tree.v1\0";
const MAXIMUM_ENTRIES: usize = 250_000;
const MAXIMUM_PATH_BYTES: usize = 4096;
const MAXIMUM_FILE_BYTES: u64 = 512 * 1_048_576;

/// Compares every package-template entry with a protected workspace root.
///
/// The returned digest covers every compared path, file type, mode, regular
/// file byte, and symlink target. The caller must prove the workspace is the
/// exact attached dataset and that neither tree can be mutated concurrently.
///
/// # Errors
///
/// Returns an error for missing or substituted entries, unsafe ownership or
/// modes, unsupported file types, oversized trees, or filesystem I/O failure.
pub fn compare_guest_root_template_v1(
    template: &Path,
    workspace: &Path,
) -> Result<[u8; 32], GuestRootTreeErrorV1> {
    compare_guest_root_tree(template, workspace, true)
}

/// Measures an offline build-user-owned template with the runtime tree algorithm.
///
/// Nix installs derivation outputs as root-owned only after the build phase.
/// This entry point keeps every type, mode, byte, and symlink check identical
/// while deferring UID-zero enforcement to the runtime protected readback.
///
/// # Errors
///
/// Returns an error for malformed or unsafe template entries, excessive
/// content, unsupported types, or filesystem failure.
pub fn measure_offline_guest_root_template_v1(
    template: &Path,
) -> Result<[u8; 32], GuestRootTreeErrorV1> {
    compare_guest_root_tree(template, template, false)
}

fn compare_guest_root_tree(
    template: &Path,
    workspace: &Path,
    require_root_ownership: bool,
) -> Result<[u8; 32], GuestRootTreeErrorV1> {
    if !template.is_absolute() || !workspace.is_absolute() {
        return Err(GuestRootTreeErrorV1::InvalidTree);
    }
    let source = fs::symlink_metadata(template)?;
    let destination = fs::symlink_metadata(workspace)?;
    verify_pair(
        &source,
        &destination,
        EntryKind::Directory,
        require_root_ownership,
    )?;

    let mut state = TreeHashState {
        digest: Sha256::new(),
        entries: 0,
    };
    state.digest.update(DOMAIN);
    compare_directory(
        template,
        workspace,
        Path::new(""),
        &mut state,
        require_root_ownership,
    )?;
    if state.entries == 0 {
        return Err(GuestRootTreeErrorV1::InvalidTree);
    }
    Ok(state.digest.finalize().into())
}

struct TreeHashState {
    digest: Sha256,
    entries: usize,
}

#[derive(Clone, Copy)]
enum EntryKind {
    Directory,
    Regular,
    Symlink,
}

fn compare_directory(
    template: &Path,
    workspace: &Path,
    relative: &Path,
    state: &mut TreeHashState,
    require_root_ownership: bool,
) -> Result<(), GuestRootTreeErrorV1> {
    let mut names = fs::read_dir(template)?
        .map(|entry| entry.map(|entry| entry.file_name()))
        .collect::<Result<Vec<_>, _>>()?;
    names.sort_by(|left, right| left.as_bytes().cmp(right.as_bytes()));

    for name in names {
        state.entries = state
            .entries
            .checked_add(1)
            .filter(|count| *count <= MAXIMUM_ENTRIES)
            .ok_or(GuestRootTreeErrorV1::InvalidTree)?;
        let child_relative = relative.join(&name);
        let path_bytes = child_relative.as_os_str().as_bytes();
        if path_bytes.is_empty() || path_bytes.len() > MAXIMUM_PATH_BYTES {
            return Err(GuestRootTreeErrorV1::InvalidTree);
        }

        let source_path = template.join(&name);
        let destination_path = workspace.join(&name);
        let source = fs::symlink_metadata(&source_path)?;
        let destination = fs::symlink_metadata(&destination_path)?;
        let kind = classify(&source)?;
        verify_pair(&source, &destination, kind, require_root_ownership)?;
        hash_entry_header(state, path_bytes, kind, source.permissions().mode());

        match kind {
            EntryKind::Directory => compare_directory(
                &source_path,
                &destination_path,
                &child_relative,
                state,
                require_root_ownership,
            )?,
            EntryKind::Regular => {
                let source_digest = hash_file(&source_path, source.len(), require_root_ownership)?;
                let destination_digest =
                    hash_file(&destination_path, destination.len(), require_root_ownership)?;
                if source_digest != destination_digest {
                    return Err(GuestRootTreeErrorV1::InvalidTree);
                }
                state.digest.update(source.len().to_be_bytes());
                state.digest.update(source_digest);
            }
            EntryKind::Symlink => {
                let source_target = fs::read_link(&source_path)?;
                let destination_target = fs::read_link(&destination_path)?;
                if source_target != destination_target {
                    return Err(GuestRootTreeErrorV1::InvalidTree);
                }
                let target = source_target.as_os_str().as_bytes();
                let length =
                    u32::try_from(target.len()).map_err(|_| GuestRootTreeErrorV1::InvalidTree)?;
                state.digest.update(length.to_be_bytes());
                state.digest.update(target);
            }
        }
    }
    Ok(())
}

fn classify(metadata: &Metadata) -> Result<EntryKind, GuestRootTreeErrorV1> {
    let kind = metadata.file_type();
    if kind.is_dir() {
        Ok(EntryKind::Directory)
    } else if kind.is_file() {
        Ok(EntryKind::Regular)
    } else if kind.is_symlink() {
        Ok(EntryKind::Symlink)
    } else {
        Err(GuestRootTreeErrorV1::InvalidTree)
    }
}

fn verify_pair(
    source: &Metadata,
    destination: &Metadata,
    kind: EntryKind,
    require_root_ownership: bool,
) -> Result<(), GuestRootTreeErrorV1> {
    let expected_type = match kind {
        EntryKind::Directory => source.is_dir() && destination.is_dir(),
        EntryKind::Regular => source.is_file() && destination.is_file(),
        EntryKind::Symlink => {
            source.file_type().is_symlink() && destination.file_type().is_symlink()
        }
    };
    let protected_mode = matches!(kind, EntryKind::Symlink)
        || source.mode() & 0o022 == 0 && destination.mode() & 0o022 == 0;
    if !expected_type
        || require_root_ownership && (source.uid() != 0 || destination.uid() != 0)
        || !protected_mode
        || source.mode() & 0o7777 != destination.mode() & 0o7777
        || !matches!(kind, EntryKind::Directory) && source.len() != destination.len()
    {
        return Err(GuestRootTreeErrorV1::InvalidTree);
    }
    Ok(())
}

fn hash_entry_header(state: &mut TreeHashState, path: &[u8], kind: EntryKind, mode: u32) {
    state.digest.update((path.len() as u16).to_be_bytes());
    state.digest.update(path);
    state.digest.update([match kind {
        EntryKind::Directory => 1,
        EntryKind::Regular => 2,
        EntryKind::Symlink => 3,
    }]);
    state.digest.update((mode & 0o7777).to_be_bytes());
}

fn hash_file(
    path: &PathBuf,
    length: u64,
    require_root_ownership: bool,
) -> Result<[u8; 32], GuestRootTreeErrorV1> {
    if length > MAXIMUM_FILE_BYTES {
        return Err(GuestRootTreeErrorV1::InvalidTree);
    }
    let mut file = File::open(path)?;
    let opened = file.metadata()?;
    if !opened.is_file() || opened.len() != length || require_root_ownership && opened.uid() != 0 {
        return Err(GuestRootTreeErrorV1::InvalidTree);
    }
    let mut digest = Sha256::new();
    let mut buffer = [0_u8; 64 * 1024];
    let mut remaining = length;
    while remaining != 0 {
        let count = file.read(&mut buffer)?;
        if count == 0 {
            return Err(GuestRootTreeErrorV1::InvalidTree);
        }
        digest.update(&buffer[..count]);
        remaining = remaining
            .checked_sub(count as u64)
            .ok_or(GuestRootTreeErrorV1::InvalidTree)?;
    }
    if file.read(&mut buffer[..1])? != 0 {
        return Err(GuestRootTreeErrorV1::InvalidTree);
    }
    Ok(digest.finalize().into())
}

/// Records the complete bounded destination-root traversal as nonauthorizing DATA.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CompleteGuestRootTreeObservationV1 {
    digest: [u8; 32],
    regular_bytes: u64,
    symlink_bytes: u64,
    namespace_entries: u64,
    peak_descriptors: u32,
    peak_name_arena_bytes: u32,
}

impl CompleteGuestRootTreeObservationV1 {
    /// Returns the commitment to every observed destination entry.
    #[must_use]
    pub const fn digest(&self) -> [u8; 32] {
        self.digest
    }

    /// Returns logical regular-file bytes, charging each hard-linked name.
    #[must_use]
    pub const fn regular_bytes(&self) -> u64 {
        self.regular_bytes
    }

    /// Returns the sum of all observed symlink-target byte lengths.
    #[must_use]
    pub const fn symlink_bytes(&self) -> u64 {
        self.symlink_bytes
    }

    /// Returns all namespace entries, including the root and publication marker.
    #[must_use]
    pub const fn namespace_entries(&self) -> u64 {
        self.namespace_entries
    }

    /// Returns the conservative per-name inode charge, not physical allocation.
    #[must_use]
    pub const fn conservative_inodes(&self) -> u64 {
        self.namespace_entries
    }

    /// Returns the peak actual cursor/file descriptors plus the original root loan.
    #[must_use]
    pub const fn peak_descriptors(&self) -> u32 {
        self.peak_descriptors
    }

    /// Returns peak actual retained name/index allocation during this traversal.
    #[must_use]
    pub const fn peak_name_arena_bytes(&self) -> u32 {
        self.peak_name_arena_bytes
    }
}

const COMPLETE_DOMAIN: &[u8] = b"aos.sandbox.guest-root-complete.v1\0";
const COMPLETE_MAXIMUM_DEPTH: usize = 64;
const COMPLETE_MAXIMUM_NAME_BYTES: usize = 16 * 1_048_576;
const COMPLETE_SCRATCH_BYTES: usize = 64 * 1024;

#[derive(Clone, Copy, Eq, PartialEq)]
struct CompleteEntryStamp {
    device: u64,
    inode: u64,
    uid: u32,
    mode: u32,
    links: u64,
    bytes: u64,
    modified_seconds: i64,
    modified_nanoseconds: i64,
    changed_seconds: i64,
    changed_nanoseconds: i64,
}

impl CompleteEntryStamp {
    fn from_metadata(metadata: &Metadata) -> Self {
        Self {
            device: metadata.dev(),
            inode: metadata.ino(),
            uid: metadata.uid(),
            mode: metadata.mode(),
            links: metadata.nlink(),
            bytes: metadata.len(),
            modified_seconds: metadata.mtime(),
            modified_nanoseconds: metadata.mtime_nsec(),
            changed_seconds: metadata.ctime(),
            changed_nanoseconds: metadata.ctime_nsec(),
        }
    }
}

#[derive(Clone, Copy)]
struct CompleteNameIndex {
    start: usize,
    length: usize,
    inode: u64,
    seen: bool,
}

struct CompleteDirectoryNames {
    arena: Vec<u8>,
    indices: Vec<CompleteNameIndex>,
}

impl CompleteDirectoryNames {
    fn new() -> Self {
        Self {
            arena: Vec::new(),
            indices: Vec::new(),
        }
    }
}

/// Retains the selected complete-root walk's actual partial originals and cause.
///
/// The caller must independently exclude every writer to the same destination
/// tree and retain the genuine root owner. This reservoir accepts a borrowed
/// original File and produces only measurement DATA: it is not a mount,
/// assignment, deadline, resource-funding or readiness authority factory.
///
/// An attempted failed/interrupted capture cannot be discarded normally.
/// Its Drop fence terminates the process instead of silently retiring actual
/// partial cursors; that termination is not worker-population drain.
pub struct CompleteGuestRootTreeCaptureV1 {
    directories: [Option<File>; COMPLETE_MAXIMUM_DEPTH],
    directory_stamps: [Option<CompleteEntryStamp>; COMPLETE_MAXIMUM_DEPTH],
    names: [CompleteDirectoryNames; COMPLETE_MAXIMUM_DEPTH],
    opened_entry: Option<File>,
    scratch: Vec<u8>,
    relative_path: Vec<u8>,
    hash: TreeHashState,
    mount: Option<aos_sandbox_linux::inventory::MountId>,
    regular_bytes: u64,
    symlink_bytes: u64,
    peak_descriptors: u32,
    peak_name_arena_bytes: u32,
    observation: Option<CompleteGuestRootTreeObservationV1>,
    first_failure: Option<GuestRootTreeErrorV1>,
    attempted: bool,
    finished: bool,
}

impl CompleteGuestRootTreeCaptureV1 {
    /// Creates an empty measurement reservoir without opening or admitting a root.
    #[must_use]
    pub fn new() -> Self {
        Self {
            directories: std::array::from_fn(|_| None),
            directory_stamps: [None; COMPLETE_MAXIMUM_DEPTH],
            names: std::array::from_fn(|_| CompleteDirectoryNames::new()),
            opened_entry: None,
            scratch: Vec::new(),
            relative_path: Vec::new(),
            hash: TreeHashState {
                digest: Sha256::new(),
                entries: 0,
            },
            mount: None,
            regular_bytes: 0,
            symlink_bytes: 0,
            peak_descriptors: 0,
            peak_name_arena_bytes: 0,
            observation: None,
            first_failure: None,
            attempted: false,
            finished: false,
        }
    }

    /// Captures every entry through the same original root under its original cutoff.
    ///
    /// Each returned cursor/file is parked before its physical checks. Names,
    /// count, depth, path and aggregate memory bounds precede reserve/open/read.
    /// The sole existing entry classification/header hashing rules are reused;
    /// the ordinary template walker remains unchanged.
    ///
    /// # Errors
    ///
    /// Refuses repeated capture, expiry, unsupported or changing entries,
    /// submounts, unsafe ownership/modes, exhausted bounds or native I/O. The
    /// actual first cause and partial resources stay resident; the returned
    /// InvalidTree marker does not move or stringify that cause.
    pub fn capture_original(
        &mut self,
        root: &File,
        deadline_boottime_nanoseconds: u64,
    ) -> Result<(), GuestRootTreeErrorV1> {
        if self.attempted {
            return Err(GuestRootTreeErrorV1::InvalidTree);
        }
        self.attempted = true;

        match self.capture_inner(root, deadline_boottime_nanoseconds) {
            Ok(()) => {
                self.finished = true;
                Ok(())
            }
            Err(cause) => {
                self.first_failure = Some(cause);
                Err(GuestRootTreeErrorV1::InvalidTree)
            }
        }
    }

    /// Borrows the unchanged actual first failed operation.
    #[must_use]
    pub fn first_failure(&self) -> Option<&GuestRootTreeErrorV1> {
        self.first_failure.as_ref()
    }

    /// Borrows completed traversal DATA without admitting any effect.
    ///
    /// # Errors
    ///
    /// Refuses an incomplete, interrupted or failed capture.
    pub fn observation(&self) -> Result<&CompleteGuestRootTreeObservationV1, GuestRootTreeErrorV1> {
        if !self.finished || self.first_failure.is_some() {
            return Err(GuestRootTreeErrorV1::InvalidTree);
        }
        self.observation.as_ref().ok_or(GuestRootTreeErrorV1::InvalidTree)
    }

    fn capture_inner(&mut self, root: &File, deadline: u64) -> Result<(), GuestRootTreeErrorV1> {
        use std::os::fd::AsFd as _;
        use rustix::fs::{Mode, OFlags};

        require_complete_deadline(deadline)?;
        self.scratch.try_reserve_exact(COMPLETE_SCRATCH_BYTES)?;
        self.relative_path.try_reserve_exact(MAXIMUM_PATH_BYTES)?;
        if self.scratch.capacity() > COMPLETE_SCRATCH_BYTES
            || self.relative_path.capacity() > MAXIMUM_PATH_BYTES
        {
            return Err(GuestRootTreeErrorV1::InvalidTree);
        }

        let descriptor = rustix::fs::openat(
            root,
            c".",
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
        )?;
        self.directories[0] = Some(File::from(descriptor));
        self.peak_descriptors = 2;

        let original = root.metadata()?;
        let opened = self.directories[0].as_ref()
            .ok_or(GuestRootTreeErrorV1::InvalidTree)?.metadata()?;
        verify_pair(&original, &opened, EntryKind::Directory, true)?;
        let original_stamp = CompleteEntryStamp::from_metadata(&original);
        if CompleteEntryStamp::from_metadata(&opened) != original_stamp {
            return Err(GuestRootTreeErrorV1::InvalidTree);
        }
        self.mount = Some(aos_sandbox_linux::inventory::MountId::from_fd(root.as_fd())?);
        self.require_same_mount(self.directories[0].as_ref()
            .ok_or(GuestRootTreeErrorV1::InvalidTree)?)?;
        self.directory_stamps[0] = Some(original_stamp);
        self.hash.digest.update(COMPLETE_DOMAIN);
        self.hash.entries = 1;
        hash_entry_header(&mut self.hash, b"", EntryKind::Directory, original.mode());

        self.walk_directory(0, deadline)?;
        if CompleteEntryStamp::from_metadata(&root.metadata()?) != original_stamp {
            return Err(GuestRootTreeErrorV1::InvalidTree);
        }
        if aos_sandbox_linux::inventory::MountId::from_fd(root.as_fd())? !=
            self.mount.ok_or(GuestRootTreeErrorV1::InvalidTree)?
        {
            return Err(GuestRootTreeErrorV1::InvalidTree);
        }
        require_complete_deadline(deadline)?;

        self.observation = Some(CompleteGuestRootTreeObservationV1 {
            digest: std::mem::take(&mut self.hash.digest).finalize().into(),
            regular_bytes: self.regular_bytes,
            symlink_bytes: self.symlink_bytes,
            namespace_entries: self.hash.entries as u64,
            peak_descriptors: self.peak_descriptors,
            peak_name_arena_bytes: self.peak_name_arena_bytes,
        });
        Ok(())
    }

    fn walk_directory(&mut self, depth: usize, deadline: u64) -> Result<(), GuestRootTreeErrorV1> {
        use std::ffi::CStr;
        use rustix::fs::{Mode, OFlags};

        self.capture_directory_names(depth, deadline)?;
        for index in 0..self.names[depth].indices.len() {
            require_complete_deadline(deadline)?;
            let name_index = self.names[depth].indices[index];
            let end = name_index.start.checked_add(name_index.length)
                .ok_or(GuestRootTreeErrorV1::InvalidTree)?;
            let name = CStr::from_bytes_with_nul(&self.names[depth].arena[name_index.start..=end])
                .map_err(|_| GuestRootTreeErrorV1::InvalidTree)?;
            let directory = self.directories[depth].as_ref()
                .ok_or(GuestRootTreeErrorV1::InvalidTree)?;
            let stat = rustix::fs::statat(
                directory,
                name,
                rustix::fs::AtFlags::SYMLINK_NOFOLLOW,
            )?;
            if stat.st_ino != name_index.inode {
                return Err(GuestRootTreeErrorV1::InvalidTree);
            }
            let file_type = rustix::fs::FileType::from_raw_mode(stat.st_mode);
            let flags = match file_type {
                rustix::fs::FileType::Directory =>
                    OFlags::RDONLY | OFlags::DIRECTORY,
                rustix::fs::FileType::RegularFile =>
                    OFlags::RDONLY | OFlags::NONBLOCK,
                rustix::fs::FileType::Symlink => OFlags::PATH,
                _ => return Err(GuestRootTreeErrorV1::InvalidTree),
            };
            if file_type == rustix::fs::FileType::Directory && depth + 1 >= COMPLETE_MAXIMUM_DEPTH {
                return Err(GuestRootTreeErrorV1::InvalidTree);
            }
            let old_path_bytes = self.relative_path.len();
            let added = name_index.length + usize::from(old_path_bytes != 0);
            if old_path_bytes.checked_add(added)
                .is_none_or(|length| length > MAXIMUM_PATH_BYTES)
            {
                return Err(GuestRootTreeErrorV1::InvalidTree);
            }

            let descriptor = rustix::fs::openat(
                directory,
                name,
                flags | OFlags::NOFOLLOW | OFlags::CLOEXEC,
                Mode::empty(),
            )?;
            self.opened_entry = Some(File::from(descriptor));
            self.peak_descriptors = self.peak_descriptors.max(
                u32::try_from(depth + 3).map_err(|_| GuestRootTreeErrorV1::InvalidTree)?,
            );

            let opened = self.opened_entry.as_ref()
                .ok_or(GuestRootTreeErrorV1::InvalidTree)?.metadata()?;
            if opened.dev() != stat.st_dev || opened.ino() != stat.st_ino
                || opened.mode() != stat.st_mode
            {
                return Err(GuestRootTreeErrorV1::InvalidTree);
            }
            let kind = classify(&opened)?;
            verify_pair(&opened, &opened, kind, true)?;
            self.require_same_mount(self.opened_entry.as_ref()
                .ok_or(GuestRootTreeErrorV1::InvalidTree)?)?;
            let before = CompleteEntryStamp::from_metadata(&opened);

            if old_path_bytes != 0 {
                self.relative_path.push(b'/');
            }
            self.relative_path.extend_from_slice(
                &self.names[depth].arena[name_index.start..end],
            );
            hash_entry_header(&mut self.hash, &self.relative_path, kind, opened.mode());

            match kind {
                EntryKind::Directory => {
                    self.directories[depth + 1] = self.opened_entry.take();
                    self.directory_stamps[depth + 1] = Some(before);
                    self.walk_directory(depth + 1, deadline)?;
                    self.directories[depth + 1] = None;
                    self.directory_stamps[depth + 1] = None;
                }
                EntryKind::Regular => self.hash_opened_file(before, deadline)?,
                EntryKind::Symlink => self.hash_opened_link(before, deadline)?,
            }

            self.relative_path.truncate(old_path_bytes);
            self.opened_entry = None;
        }
        self.recheck_directory_membership(depth, deadline)?;
        let opened = self.directories[depth].as_ref()
            .ok_or(GuestRootTreeErrorV1::InvalidTree)?.metadata()?;
        if Some(CompleteEntryStamp::from_metadata(&opened)) != self.directory_stamps[depth] {
            return Err(GuestRootTreeErrorV1::InvalidTree);
        }
        Ok(())
    }

    fn capture_directory_names(
        &mut self,
        depth: usize,
        deadline: u64,
    ) -> Result<(), GuestRootTreeErrorV1> {
        self.names[depth].arena.clear();
        self.names[depth].indices.clear();
        self.scratch.clear();
        let directory = self.directories[depth].as_ref()
            .ok_or(GuestRootTreeErrorV1::InvalidTree)?;
        let mut reader = rustix::fs::RawDir::new(directory, self.scratch.spare_capacity_mut());

        loop {
            require_complete_deadline(deadline)?;
            let Some(entry) = reader.next() else {
                require_complete_deadline(deadline)?;
                break;
            };
            require_complete_deadline(deadline)?;
            let entry = entry?;
            let name = entry.file_name().to_bytes();
            if matches!(name, b"." | b"..") {
                continue;
            }
            if name.is_empty() || name.len() > MAXIMUM_PATH_BYTES || entry.ino() == 0
                || name.contains(&b'/')
            {
                return Err(GuestRootTreeErrorV1::InvalidTree);
            }
            let entries = self.hash.entries.checked_add(1)
                .filter(|count| *count <= MAXIMUM_ENTRIES)
                .ok_or(GuestRootTreeErrorV1::InvalidTree)?;
            let current_bytes = complete_name_capacity(&self.names)?;
            let growth = name.len().checked_add(1)
                .and_then(|bytes| bytes.checked_add(std::mem::size_of::<CompleteNameIndex>()))
                .and_then(|bytes| bytes.checked_add(current_bytes))
                .filter(|bytes| *bytes <= COMPLETE_MAXIMUM_NAME_BYTES)
                .ok_or(GuestRootTreeErrorV1::InvalidTree)?;
            self.names[depth].arena.try_reserve_exact(name.len() + 1)?;
            self.names[depth].indices.try_reserve_exact(1)?;

            let names = &mut self.names[depth];
            let start = names.arena.len();
            names.arena.extend_from_slice(name);
            names.arena.push(0);
            names.indices.push(CompleteNameIndex {
                start,
                length: name.len(),
                inode: entry.ino(),
                seen: false,
            });
            self.hash.entries = entries;
            let allocated = complete_name_capacity(&self.names)?;
            if allocated > COMPLETE_MAXIMUM_NAME_BYTES || allocated > growth {
                return Err(GuestRootTreeErrorV1::InvalidTree);
            }
            self.peak_name_arena_bytes = self.peak_name_arena_bytes.max(
                u32::try_from(allocated).map_err(|_| GuestRootTreeErrorV1::InvalidTree)?,
            );
        }

        let names = &mut self.names[depth];
        let arena = &names.arena;
        names.indices.sort_unstable_by(|left, right| {
            arena[left.start..left.start + left.length]
                .cmp(&arena[right.start..right.start + right.length])
        });
        if names.indices.windows(2).any(|pair| {
            arena[pair[0].start..pair[0].start + pair[0].length] ==
                arena[pair[1].start..pair[1].start + pair[1].length]
        }) {
            return Err(GuestRootTreeErrorV1::InvalidTree);
        }
        Ok(())
    }

    fn recheck_directory_membership(
        &mut self,
        depth: usize,
        deadline: u64,
    ) -> Result<(), GuestRootTreeErrorV1> {
        let directory = self.directories[depth].as_ref()
            .ok_or(GuestRootTreeErrorV1::InvalidTree)?;
        rustix::fs::seek(directory, rustix::fs::SeekFrom::Start(0))?;
        self.scratch.clear();
        let mut reader = rustix::fs::RawDir::new(directory, self.scratch.spare_capacity_mut());
        let names = &mut self.names[depth];
        let mut count = 0_usize;

        loop {
            require_complete_deadline(deadline)?;
            let Some(entry) = reader.next() else {
                require_complete_deadline(deadline)?;
                break;
            };
            require_complete_deadline(deadline)?;
            let entry = entry?;
            let name = entry.file_name().to_bytes();
            if matches!(name, b"." | b"..") {
                continue;
            }
            let index = names.indices.binary_search_by(|index| {
                names.arena[index.start..index.start + index.length].cmp(name)
            }).map_err(|_| GuestRootTreeErrorV1::InvalidTree)?;
            let original = &mut names.indices[index];
            if original.seen || original.inode != entry.ino() {
                return Err(GuestRootTreeErrorV1::InvalidTree);
            }
            original.seen = true;
            count = count.checked_add(1).ok_or(GuestRootTreeErrorV1::InvalidTree)?;
        }
        if count != names.indices.len() {
            return Err(GuestRootTreeErrorV1::InvalidTree);
        }
        Ok(())
    }

    fn hash_opened_file(
        &mut self,
        before: CompleteEntryStamp,
        deadline: u64,
    ) -> Result<(), GuestRootTreeErrorV1> {
        use std::os::unix::fs::FileExt as _;

        if before.bytes > MAXIMUM_FILE_BYTES {
            return Err(GuestRootTreeErrorV1::InvalidTree);
        }
        self.regular_bytes = self.regular_bytes.checked_add(before.bytes)
            .ok_or(GuestRootTreeErrorV1::InvalidTree)?;
        self.regular_bytes.checked_add(self.symlink_bytes)
            .ok_or(GuestRootTreeErrorV1::InvalidTree)?;
        self.scratch.resize(COMPLETE_SCRATCH_BYTES, 0);
        let file = self.opened_entry.as_ref().ok_or(GuestRootTreeErrorV1::InvalidTree)?;
        let mut digest = Sha256::new();
        let mut offset = 0_u64;

        while offset < before.bytes {
            require_complete_deadline(deadline)?;
            let remaining = before.bytes - offset;
            let maximum = usize::try_from(remaining.min(COMPLETE_SCRATCH_BYTES as u64))
                .map_err(|_| GuestRootTreeErrorV1::InvalidTree)?;
            let count = file.read_at(&mut self.scratch[..maximum], offset)?;
            require_complete_deadline(deadline)?;
            if count == 0 || count > maximum {
                return Err(GuestRootTreeErrorV1::InvalidTree);
            }
            digest.update(&self.scratch[..count]);
            offset = offset.checked_add(count as u64).ok_or(GuestRootTreeErrorV1::InvalidTree)?;
        }
        require_complete_deadline(deadline)?;
        let trailing = file.read_at(&mut self.scratch[..1], before.bytes)?;
        require_complete_deadline(deadline)?;
        if trailing != 0
            || CompleteEntryStamp::from_metadata(&file.metadata()?) != before
        {
            return Err(GuestRootTreeErrorV1::InvalidTree);
        }
        self.hash.digest.update(before.bytes.to_be_bytes());
        self.hash.digest.update(digest.finalize());
        Ok(())
    }

    fn hash_opened_link(
        &mut self,
        before: CompleteEntryStamp,
        deadline: u64,
    ) -> Result<(), GuestRootTreeErrorV1> {
        if before.bytes > MAXIMUM_PATH_BYTES as u64 {
            return Err(GuestRootTreeErrorV1::InvalidTree);
        }
        self.symlink_bytes = self.symlink_bytes.checked_add(before.bytes)
            .ok_or(GuestRootTreeErrorV1::InvalidTree)?;
        self.regular_bytes.checked_add(self.symlink_bytes)
            .ok_or(GuestRootTreeErrorV1::InvalidTree)?;
        self.scratch.resize(COMPLETE_SCRATCH_BYTES, 0);
        let file = self.opened_entry.as_ref().ok_or(GuestRootTreeErrorV1::InvalidTree)?;
        require_complete_deadline(deadline)?;
        let length = rustix::fs::readlinkat_raw(file, c"", &mut self.scratch[..MAXIMUM_PATH_BYTES + 1])?;
        require_complete_deadline(deadline)?;
        if length as u64 != before.bytes || length > MAXIMUM_PATH_BYTES
            || CompleteEntryStamp::from_metadata(&file.metadata()?) != before
        {
            return Err(GuestRootTreeErrorV1::InvalidTree);
        }
        self.hash.digest.update((length as u32).to_be_bytes());
        self.hash.digest.update(&self.scratch[..length]);
        Ok(())
    }

    fn require_same_mount(&self, file: &File) -> Result<(), GuestRootTreeErrorV1> {
        use std::os::fd::AsFd as _;

        if Some(aos_sandbox_linux::inventory::MountId::from_fd(file.as_fd())?) != self.mount {
            return Err(GuestRootTreeErrorV1::InvalidTree);
        }
        Ok(())
    }
}

impl Default for CompleteGuestRootTreeCaptureV1 {
    fn default() -> Self {
        Self::new()
    }
}

impl Drop for CompleteGuestRootTreeCaptureV1 {
    fn drop(&mut self) {
        if self.attempted && !self.finished {
            std::process::abort();
        }
    }
}

fn complete_name_capacity(
    names: &[CompleteDirectoryNames; COMPLETE_MAXIMUM_DEPTH],
) -> Result<usize, GuestRootTreeErrorV1> {
    names.iter().try_fold(0_usize, |total, names| {
        names.indices.capacity().checked_mul(std::mem::size_of::<CompleteNameIndex>())
            .and_then(|bytes| bytes.checked_add(names.arena.capacity()))
            .and_then(|bytes| bytes.checked_add(total))
            .ok_or(GuestRootTreeErrorV1::InvalidTree)
    })
}

fn require_complete_deadline(deadline: u64) -> Result<(), GuestRootTreeErrorV1> {
    let now = rustix::time::clock_gettime(rustix::time::ClockId::Boottime);
    let nanoseconds = u64::try_from(now.tv_sec).ok()
        .and_then(|seconds| seconds.checked_mul(1_000_000_000))
        .and_then(|seconds| u64::try_from(now.tv_nsec).ok()
            .and_then(|nanoseconds| seconds.checked_add(nanoseconds)))
        .ok_or(GuestRootTreeErrorV1::InvalidTree)?;
    if deadline == 0 || nanoseconds >= deadline {
        return Err(GuestRootTreeErrorV1::InvalidTree);
    }
    Ok(())
}

/// Reports a physical guest-root mismatch or filesystem failure.
#[derive(Debug, thiserror::Error)]
pub enum GuestRootTreeErrorV1 {
    /// A bounded selected traversal could not reserve its resident storage.
    #[error("guest root traversal reservation failed: {0}")]
    Allocation(#[from] std::collections::TryReserveError),
    /// A selected FD-relative native operation failed.
    #[error("guest root traversal native operation failed: {0}")]
    Native(#[from] rustix::io::Errno),
    /// A selected original mount identity could not be observed.
    #[error("guest root traversal original mount failed: {0}")]
    Linux(#[from] aos_sandbox_linux::Error),
    /// The template or workspace tree is missing, unsafe, substituted, or oversized.
    #[error("guest root tree is invalid")]
    InvalidTree,
    /// A filesystem operation failed during physical comparison.
    #[error("guest root tree I/O failed: {0}")]
    Io(#[from] std::io::Error),
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use super::*;

    #[test]
    fn offline_digest_tracks_bytes_modes_and_links() {
        let directory = tempfile::tempdir().unwrap();
        let root = directory.path().join("root");
        fs::create_dir(&root).unwrap();
        fs::set_permissions(&root, fs::Permissions::from_mode(0o755)).unwrap();
        let file = root.join("agent");
        fs::write(&file, b"first").unwrap();
        fs::set_permissions(&file, fs::Permissions::from_mode(0o500)).unwrap();
        std::os::unix::fs::symlink("agent", root.join("current")).unwrap();

        let first = measure_offline_guest_root_template_v1(&root).unwrap();
        fs::set_permissions(&file, fs::Permissions::from_mode(0o700)).unwrap();
        fs::write(&file, b"second").unwrap();
        fs::set_permissions(&file, fs::Permissions::from_mode(0o500)).unwrap();
        let second = measure_offline_guest_root_template_v1(&root).unwrap();
        assert_ne!(first, second);

        fs::set_permissions(&file, fs::Permissions::from_mode(0o400)).unwrap();
        let third = measure_offline_guest_root_template_v1(&root).unwrap();
        assert_ne!(second, third);
    }
}
