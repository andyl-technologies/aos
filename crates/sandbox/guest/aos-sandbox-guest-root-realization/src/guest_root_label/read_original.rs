//! Optional native destinations for the one complete confinement projection.
//!
//! Successful local scopes dispose only after their original complete checks,
//! including the symlink restat. An error retains the active recursion, directory
//! iterators, raw acquisitions, label buffers and exact first returned cause.

use super::*;
use aos_sandbox_linux::path::{
    BeneathDirectoryOpenOriginalV2, BeneathRegularFileOpenOriginalV2,
    BeneathRootOpenOriginalV2, ResolvedFile, ResolvedPath,
};

/// Describes passive receiving storage for this existing bounded native walk.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct GuestRootLabelReadFootprintV1 {
    /// Dominant co-resident native, path, iterator, label and constructor bytes.
    pub memory_bytes: usize,
    /// Maximum additional simultaneously held native descriptor slots.
    pub open_files: usize,
    /// Named lookup count across the original maximum ten bounded subtrees.
    pub metadata_entries: usize,
}

/// Describes only the reached mechanical prefix of the canonical label walk.
///
/// Values are constructed by the walk before native entry or growth. They
/// confer no payment, mount authority, currentness or completion. The caller's
/// deny-only adapter must admit this whole highwater before returning `true`.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct GuestRootLabelReadReachedDataV2 {
    peak_depth: usize,
    named_entries: usize,
}

impl GuestRootLabelReadReachedDataV2 {
    /// Describes the complete co-live prefix and monotone reached name count.
    #[must_use]
    pub fn receiving_footprint_v2(self) -> Option<GuestRootLabelReadFootprintV1> {
        receiving_footprint_v2(self.peak_depth, self.named_entries)
    }
}

// Count the actual fixed lookup components used by the projection. Recursive
// entry names are added before iteration; a directory entry can additionally
// introduce its /proc/self/fd/<fd> iterator path. No Rust field is a name fee.
fn fixed_projection_names_v2() -> Option<usize> {
    let paths = |roster: &[&str]| roster.iter().try_fold(0usize, |total, path|
        total.checked_add(Path::new(path).components().count()));
    let private_trees = ["etc/aos/sandbox-agent", "etc/aos/sandbox-attach",
        "var/lib/aos-sandbox-agent", "var/empty", "run/systemd"];
    let executable_paths: [&str; 7] = EXECUTABLE_LABELS.map(|(path, _)| path);
    let mut names = paths(ANCHORS)?.checked_add(paths(CONFIG_DIRECTORIES)?)?
        .checked_add(paths(PRIVATE_DIRECTORIES)?)?
        .checked_add(paths(CONFIG_DIRECTORIES)?)?
        .checked_add(paths(&private_trees)?)?
        .checked_add(paths(&[PUBLICATION_DIRECTORY])?)?
        .checked_add(paths(CONFIG_FILES)?)?
        .checked_add(paths(RUNTIME_METADATA_FILES)?)?
        .checked_add(paths(&executable_paths)?)?
        .checked_add(paths(&["etc/aos/sandbox-agent/guest-executable-v1", "nix/store"])?)?;
    // Ten recursive roots each open this exact native iterator path once.
    names = names.checked_add(10usize.checked_mul(iterator_names_v2())?)?;
    Some(names)
}

fn iterator_names_v2() -> usize {
    // proc, self, fd and the actual descriptor's decimal basename.
    Path::new("proc/self/fd").components().count() + 1
}

/// Carries only denial and progress through the one existing native algorithm.
pub(super) struct WalkAdmissionV2<'gate> {
    reached: &'gate mut GuestRootLabelReadReachedDataV2,
    admit: &'gate mut dyn FnMut(GuestRootLabelReadReachedDataV2) -> bool,
    entered_names: usize,
}

impl WalkAdmissionV2<'_> {
    fn require_depth(&mut self, depth: usize) -> Result<(), GuestRootLabelErrorV1> {
        self.require(GuestRootLabelReadReachedDataV2 {
            peak_depth: self.reached.peak_depth.max(depth),
            named_entries: self.reached.named_entries.max(fixed_projection_names_v2()
                .ok_or(GuestRootLabelErrorV1::ReceivingAdmission)?),
        })
    }

    fn require_next_name(&mut self) -> Result<(), GuestRootLabelErrorV1> {
        let names = self.entered_names.checked_add(1 + iterator_names_v2())
            .ok_or(GuestRootLabelErrorV1::ReceivingAdmission)?;
        // A possible next entry is paid before ReadDir::next materializes it.
        // EOF leaves that one already-paid spare reusable for the next tree.
        self.require(GuestRootLabelReadReachedDataV2 {
            peak_depth: self.reached.peak_depth,
            named_entries: self.reached.named_entries.max(names),
        })
    }

    fn entered_name(&mut self) -> Result<(), GuestRootLabelErrorV1> {
        self.entered_names = self.entered_names.checked_add(1 + iterator_names_v2())
            .ok_or(GuestRootLabelErrorV1::ReceivingAdmission)?;
        Ok(())
    }

    fn require(&mut self, proposed: GuestRootLabelReadReachedDataV2)
        -> Result<(), GuestRootLabelErrorV1>
    {
        if !(self.admit)(proposed) {
            return Err(GuestRootLabelErrorV1::ReceivingAdmission);
        }
        *self.reached = proposed;
        Ok(())
    }
}

fn receiving_footprint_v2(maximum_depth: usize, named_entries: usize)
    -> Option<GuestRootLabelReadFootprintV1>
{
    let levels = maximum_depth.checked_add(1)?;
    // This is the same glibc DIR bound and actual retained Frame/path recipe
    // used by the maximum-limit adapter below. It is charged before read_dir.
    let per_level = (1_usize << 20).checked_add(64 * 1024)?
        .checked_add(std::mem::size_of::<Frame>().checked_mul(6)?)?
        .checked_add(MAXIMUM_PATH_BYTES.checked_mul(6)?)?;
    Some(GuestRootLabelReadFootprintV1 {
        memory_bytes: levels.checked_mul(per_level)?,
        open_files: levels.checked_mul(8)?.checked_add(16)?,
        metadata_entries: named_entries,
    })
}

/// Reports a closed native label-read attempt without replacing its real cause.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
#[error("retained Guest confinement read did not complete")]
pub struct GuestRootLabelReadClosedV1;

/// Retains the actual active and failed native prefix of a complete label walk.
///
/// This is a mechanical receiver, not mount authority, currentness, payment or
/// a Guest-ready proof. The caller must prepay the fixed and dynamic footprints
/// and keep this owner through its independently owed authenticated posts.
pub struct GuestRootLabelReadOriginalV1 {
    frame: Frame,
    result: Option<Result<(), GuestRootLabelErrorV1>>,
    maximum_depth: usize,
    maximum_entries_per_tree: usize,
    entered: bool,
    reached: GuestRootLabelReadReachedDataV2,
}

impl GuestRootLabelReadOriginalV1 {
    /// Returns the complete limits already enforced by the canonical walk.
    ///
    /// These are restrictive native DATA, not a budget or permission. A caller
    /// prepays either its whole admitted footprint or the fixed constructor
    /// followed by each actual reached shape through the deny-only adapter.
    #[must_use]
    pub const fn maximum_receiving_limits_v2() -> (usize, usize) {
        (MAXIMUM_PATH_BYTES / 2, MAXIMUM_ENTRIES)
    }

    /// Constructs an inert destination enforcing a prepaid recursion ceiling.
    ///
    /// Returns `None` if the ceiling exceeds the existing path bound. A smaller
    /// ceiling may refuse a deeper tree; it cannot make an invalid tree valid.
    #[must_use]
    pub fn new(maximum_depth: usize) -> Option<Self> {
        Self::with_receiving_limits_v2(maximum_depth, MAXIMUM_ENTRIES)
    }

    /// Creates inert custody bounded by the caller's prepaid native walk limits.
    ///
    /// Smaller limits only refuse work; every original inode, label, path and
    /// complete projection predicate remains unchanged. No financial allowance
    /// is inferred from these mechanical ceilings. The real payer admits the
    /// fixed constructor before construction, then either the whole native
    /// footprint or each reached prefix before its corresponding entry.
    #[must_use]
    pub fn with_receiving_limits_v2(maximum_depth: usize, maximum_entries_per_tree: usize) -> Option<Self> {
        (maximum_depth <= MAXIMUM_PATH_BYTES / 2 && maximum_entries_per_tree <= MAXIMUM_ENTRIES)
            .then(|| Self {
                frame: Frame::default(), result: None, maximum_depth,
                maximum_entries_per_tree, entered: false,
                reached: GuestRootLabelReadReachedDataV2::default(),
            })
    }

    /// Describes the owner and its by-value construction peak before allocation.
    #[must_use]
    pub fn fixed_receiving_footprint_v1() -> Option<GuestRootLabelReadFootprintV1> {
        Some(GuestRootLabelReadFootprintV1 {
            memory_bytes: std::mem::size_of::<Self>().checked_mul(2)?,
            open_files: 0, metadata_entries: 0,
        })
    }

    /// Describes the complete native walk peak for the enforced depth ceiling.
    ///
    /// The original entry count and path limits remain unchanged. The returned
    /// namespace count sums all ten possible recursive roots rather than
    /// charging Rust fields. Completed local scopes do not retain their FDs.
    #[must_use]
    pub fn dynamic_receiving_footprint_v1(maximum_depth: usize) -> Option<GuestRootLabelReadFootprintV1> {
        Self::receiving_footprint_with_limits_v2(maximum_depth, MAXIMUM_ENTRIES)
    }

    /// Bounds the same enforced receiving limits before native walk entry.
    ///
    /// Entry cardinality covers all ten original recursive roots. The depth
    /// ceiling bounds simultaneous active native scopes, including a retained
    /// refused next entry. Both are restrictive DATA and grant no authority.
    #[must_use]
    pub fn receiving_footprint_with_limits_v2(maximum_depth: usize, maximum_entries_per_tree: usize)
        -> Option<GuestRootLabelReadFootprintV1>
    {
        if maximum_depth > MAXIMUM_PATH_BYTES / 2 || maximum_entries_per_tree > MAXIMUM_ENTRIES { return None; }
        let names = maximum_entries_per_tree.checked_add(1)?.checked_mul(10)?.checked_add(64)?;
        receiving_footprint_v2(maximum_depth, names)
    }

    /// Runs the sole full fixed projection on the caller's actual pinned root.
    ///
    /// # Errors
    /// Rejects reentry, the prepaid recursion ceiling or any original physical
    /// root/path/metadata/xattr/label check. The real cause remains on this owner.
    pub fn verify_once_v1(&mut self, root: BorrowedFd<'_>) -> Result<(), GuestRootLabelReadClosedV1> {
        self.verify_before_once_v1(root, &mut || true)
    }

    /// Restricts the same full walk by the caller's original deny-only fence.
    ///
    /// The callback may only deny native entry; it supplies no payment, mount
    /// authority or renewed lifetime. The caller retains its original clock
    /// attempt/cause and independently owed posts outside this mechanical walk.
    ///
    /// # Errors
    /// Returns the same sticky native failure or original deadline refusal.
    /// A refused initial fence precedes root duplication and inspection.
    pub fn verify_before_once_v1(&mut self, root: BorrowedFd<'_>,
        before_deadline: &mut impl FnMut() -> bool) -> Result<(), GuestRootLabelReadClosedV1>
    {
        if self.entered { return Err(GuestRootLabelReadClosedV1); }
        self.entered = true;
        let maximum_depth = self.maximum_depth;
        let maximum_entries_per_tree = self.maximum_entries_per_tree;
        self.result = Some(check_deadline(before_deadline).and_then(|()|
            with_root(root, Some(&mut self.frame), |root, mut frame| {
                verify_root_engine(root.as_fd(), frame.as_deref_mut())?;
                project_engine(root.as_fd(), false, before_deadline, frame, maximum_depth, maximum_entries_per_tree, None)
            })));
        if self.result.as_ref().is_some_and(Result::is_ok) { Ok(()) }
        else { Err(GuestRootLabelReadClosedV1) }
    }

    /// Runs the same complete walk with reached-prefix denial before growth.
    ///
    /// The adapter can only refuse entry. Returning `true` cannot waive an
    /// inode, label, path, cardinality, deadline or whole-projection predicate.
    /// Its actual financial/native owners remain on the enclosing caller.
    ///
    /// # Errors
    /// Refuses reentry, a denied reached shape or any existing native/semantic
    /// check while retaining the same active prefix and first returned cause.
    pub fn verify_receiving_before_once_v2(
        &mut self,
        root: BorrowedFd<'_>,
        before_deadline: &mut impl FnMut() -> bool,
        admit: &mut impl FnMut(GuestRootLabelReadReachedDataV2) -> bool,
    ) -> Result<(), GuestRootLabelReadClosedV1> {
        if self.entered {
            if self.result.as_ref().is_some_and(Result::is_ok) {
                self.result = Some(Err(GuestRootLabelErrorV1::ReceivingAdmission));
            }
            return Err(GuestRootLabelReadClosedV1);
        }
        self.entered = true;
        let mut admission = WalkAdmissionV2 { reached: &mut self.reached, admit,
            entered_names: fixed_projection_names_v2().ok_or(GuestRootLabelReadClosedV1)? };
        self.result = Some((|| {
            check_deadline(before_deadline)?;
            // Root duplication and fixed projection paths precede recursion.
            admission.require_depth(2)?;
            with_root(root, Some(&mut self.frame), |root, mut frame| {
                verify_root_engine(root.as_fd(), frame.as_deref_mut())?;
                project_engine(root.as_fd(), false, before_deadline, frame,
                    self.maximum_depth, self.maximum_entries_per_tree, Some(&mut admission))
            })
        })());
        if self.result.as_ref().is_some_and(Result::is_ok) { Ok(()) }
        else { Err(GuestRootLabelReadClosedV1) }
    }

    /// Borrows the exact first native or semantic failure returned by the walk.
    #[must_use]
    pub fn failure(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.result.as_ref()?.as_ref().err().map(|error| error as _)
    }

    /// Reports actual complete mechanical validation, without role authority.
    #[must_use]
    pub fn completed_exact_v1(&self) -> bool {
        self.result.as_ref().is_some_and(Result::is_ok)
    }
}

pub(super) struct Frame {
    receiving_depth: usize,
    root: Option<RootOriginal>,
    directory: Option<DirectoryOriginal>,
    regular: Option<RegularOriginal>,
    enumeration: Option<std::fs::ReadDir>,
    entry: Option<std::fs::DirEntry>,
    pending_entry: Option<std::io::Result<std::fs::DirEntry>>,
    name: Option<std::ffi::OsString>,
    anchor: Option<String>,
    path: Option<std::path::PathBuf>,
    metadata: Option<rustix::fs::Stat>,
    inspected: [Option<rustix::fs::Stat>; 8],
    inspections: usize,
    after_metadata: Option<rustix::fs::Stat>,
    actual: [u8; MAXIMUM_LABEL_BYTES],
    actual_bytes: usize,
    child: Option<Box<Frame>>,
}

impl Default for Frame {
    fn default() -> Self {
        Self { receiving_depth: 0, root: None, directory: None, regular: None, enumeration: None,
            entry: None, pending_entry: None, name: None, anchor: None, path: None, metadata: None,
            inspected: [None; 8], inspections: 0,
            after_metadata: None, actual: [0; MAXIMUM_LABEL_BYTES], actual_bytes: 0, child: None }
    }
}

impl Default for RootOriginal {
    fn default() -> Self { Self { local: None, retained: None } }
}

struct RootOriginal {
    local: Option<BeneathRoot>,
    retained: Option<BeneathRootOpenOriginalV2>,
}

impl RootOriginal {
    fn capture(&mut self, fd: BorrowedFd<'_>, retaining: bool) -> Result<(), GuestRootLabelErrorV1> {
        if retaining {
            self.retained = Some(BeneathRootOpenOriginalV2::new());
            self.retained.as_mut().ok_or(GuestRootLabelErrorV1::UnsafeInode)?.capture_root_once_v1(fd)?;
        } else {
            self.local = Some(BeneathRoot::from_owned(rustix::io::fcntl_dupfd_cloexec(fd, 0)?)?);
        }
        Ok(())
    }

    fn root(&self) -> Result<&BeneathRoot, GuestRootLabelErrorV1> {
        self.local.as_ref().or_else(|| self.retained.as_ref()?.root_v1()).ok_or(GuestRootLabelErrorV1::UnsafeInode)
    }
}

#[derive(Default)]
struct DirectoryOriginal {
    root: RootOriginal,
    local_path: Option<ResolvedPath>,
    retained_path: Option<BeneathDirectoryOpenOriginalV2>,
    readable: Option<OwnedFd>,
    metadata: Option<rustix::fs::Stat>,
}

impl DirectoryOriginal {
    fn open(&mut self, root: BorrowedFd<'_>, path: &Path, retaining: bool) -> Result<(), GuestRootLabelErrorV1> {
        self.root.capture(root, retaining)?;
        let root = self.root.root()?;
        if retaining {
            self.retained_path = Some(BeneathDirectoryOpenOriginalV2::new());
            self.retained_path.as_mut().ok_or(GuestRootLabelErrorV1::UnsafeInode)?.resolve_directory_once_v1(root, path)?;
        } else {
            self.local_path = Some(root.resolve(path, aos_sandbox_linux::path::ResolveOptions {
                no_mount_crossing: true, require_directory: true,
            })?);
        }
        let pinned = self.local_path.as_ref().or_else(|| self.retained_path.as_ref()?.directory_v1())
            .ok_or(GuestRootLabelErrorV1::UnsafeInode)?;
        self.readable = Some(openat(pinned.as_fd(), ".", OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC, Mode::empty())?);
        let stat = inspect(self.fd()?, None)?;
        self.metadata = Some(stat);
        require_root_stat(&stat)?;
        // The ordinary helper historically disposes both intermediates before
        // returning its readable FD. Selected failures retain them until posts.
        if !retaining { self.local_path = None; self.root.local = None; }
        Ok(())
    }

    fn fd(&self) -> Result<BorrowedFd<'_>, GuestRootLabelErrorV1> {
        self.readable.as_ref().map(|fd| fd.as_fd()).ok_or(GuestRootLabelErrorV1::UnsafeInode)
    }
}

#[derive(Default)]
struct RegularOriginal {
    local: Option<ResolvedFile>,
    retained: Option<BeneathRegularFileOpenOriginalV2>,
}

impl RegularOriginal {
    fn open(&mut self, root: &BeneathRoot, path: &Path, retaining: bool) -> Result<(), GuestRootLabelErrorV1> {
        if retaining {
            self.retained = Some(BeneathRegularFileOpenOriginalV2::new());
            self.retained.as_mut().ok_or(GuestRootLabelErrorV1::UnsafeInode)?.open_regular_once_v1(root, path)?;
        } else { self.local = Some(root.open_regular(path)?); }
        Ok(())
    }

    fn fd(&self) -> Result<BorrowedFd<'_>, GuestRootLabelErrorV1> {
        self.local.as_ref().or_else(|| self.retained.as_ref()?.regular_v1())
            .map(|file| file.as_fd()).ok_or(GuestRootLabelErrorV1::UnsafeInode)
    }
}

fn scope(
    mut frame: Option<&mut Frame>,
    mut admission: Option<&mut WalkAdmissionV2<'_>>,
    action: impl FnOnce(Option<&mut Frame>, Option<&mut WalkAdmissionV2<'_>>)
        -> Result<(), GuestRootLabelErrorV1>,
) -> Result<(), GuestRootLabelErrorV1> {
    if let Some(frame) = frame.as_deref_mut() {
        let depth = frame.receiving_depth.checked_add(1)
            .ok_or(GuestRootLabelErrorV1::ReceivingAdmission)?;
        if let Some(admission) = admission.as_deref_mut() {
            admission.require_depth(depth)?;
        }
        // The full next Frame and native directory peak are paid first.
        let mut child = Frame::default();
        child.receiving_depth = depth;
        frame.child = Some(Box::new(child));
        let result = action(frame.child.as_deref_mut(), admission);
        if result.is_ok() { frame.child = None; }
        result
    } else {
        action(None, admission)
    }
}

fn with_root(root: BorrowedFd<'_>, mut frame: Option<&mut Frame>,
    action: impl FnOnce(&BeneathRoot, Option<&mut Frame>) -> Result<(), GuestRootLabelErrorV1>) -> Result<(), GuestRootLabelErrorV1>
{
    let mut original = RootOriginal::default();
    let result = original.capture(root, frame.is_some()).and_then(|()| action(original.root()?, frame.as_deref_mut()));
    if result.is_err() { if let Some(frame) = frame { frame.root = Some(original); } }
    result
}

fn with_directory(root: BorrowedFd<'_>, path: &Path, mut frame: Option<&mut Frame>,
    action: impl FnOnce(BorrowedFd<'_>, Option<&mut Frame>) -> Result<(), GuestRootLabelErrorV1>) -> Result<(), GuestRootLabelErrorV1>
{
    let mut original = DirectoryOriginal::default();
    let result = original.open(root, path, frame.is_some()).and_then(|()| action(original.fd()?, frame.as_deref_mut()));
    if result.is_err() { if let Some(frame) = frame { frame.directory = Some(original); } }
    result
}

fn with_regular(root: &BeneathRoot, path: &Path, mut frame: Option<&mut Frame>,
    action: impl FnOnce(BorrowedFd<'_>, Option<&mut Frame>) -> Result<(), GuestRootLabelErrorV1>) -> Result<(), GuestRootLabelErrorV1>
{
    let mut original = RegularOriginal::default();
    let result = original.open(root, path, frame.is_some()).and_then(|()| action(original.fd()?, frame.as_deref_mut()));
    if result.is_err() { if let Some(frame) = frame { frame.regular = Some(original); } }
    result
}

pub(super) fn open_directory_ordinary(root: BorrowedFd<'_>, path: &Path) -> Result<OwnedFd, GuestRootLabelErrorV1> {
    let mut original = DirectoryOriginal::default();
    original.open(root, path, false)?;
    original.readable.take().ok_or(GuestRootLabelErrorV1::UnsafeInode)
}

pub(super) fn verify_ordinary(root: BorrowedFd<'_>) -> Result<(), GuestRootLabelErrorV1> {
    with_root(root, None, |root, frame| {
        verify_root_engine(root.as_fd(), None)?;
        project_engine(root.as_fd(), false, &mut || true, frame, MAXIMUM_PATH_BYTES / 2, MAXIMUM_ENTRIES, None)
    })
}

pub(super) fn project_engine(root: BorrowedFd<'_>, install: bool, before_deadline: &mut impl FnMut() -> bool,
    mut frame: Option<&mut Frame>, maximum_depth: usize, maximum_entries_per_tree: usize,
    mut admission: Option<&mut WalkAdmissionV2<'_>>) -> Result<(), GuestRootLabelErrorV1>
{
    label(root, ANCHOR_LABEL, install, before_deadline, frame.as_deref_mut())?;
    for (paths, expected) in [(ANCHORS, ANCHOR_LABEL), (CONFIG_DIRECTORIES, CONFIG_LABEL), (PRIVATE_DIRECTORIES, PRIVATE_LABEL)] {
        for path in paths {
            scope(frame.as_deref_mut(), admission.as_deref_mut(), |frame, admission| {
                if frame.is_some() { check_deadline(before_deadline)?; }
                with_directory(root, Path::new(path), frame,
                    |directory, frame| label(directory, expected, install, before_deadline, frame))
            })?;
        }
    }
    for (paths, expected) in [
        (CONFIG_DIRECTORIES, CONFIG_LABEL),
        (&["etc/aos/sandbox-agent", "etc/aos/sandbox-attach", "var/lib/aos-sandbox-agent", "var/empty", "run/systemd"][..], PRIVATE_LABEL),
        (&[PUBLICATION_DIRECTORY][..], PUBLICATION_LABEL),
    ] {
        for path in paths {
            scope(frame.as_deref_mut(), admission.as_deref_mut(), |frame, admission| {
                if frame.is_some() { check_deadline(before_deadline)?; }
                with_directory(root, Path::new(path), frame,
                    |directory, frame| project_tree_engine(directory, 0, &mut 0, expected, true, install,
                        before_deadline, frame, 0, maximum_depth, maximum_entries_per_tree, admission))
            })?;
        }
    }
    scope(frame.as_deref_mut(), admission.as_deref_mut(), |frame, mut admission| {
        if frame.is_some() { check_deadline(before_deadline)?; }
        with_root(root, frame, |root, mut frame| {
        for (paths, expected) in [(CONFIG_FILES, CONFIG_LABEL), (RUNTIME_METADATA_FILES, RUNTIME_METADATA_LABEL)] {
            for path in paths {
                scope(frame.as_deref_mut(), admission.as_deref_mut(), |frame, admission| {
                    if frame.is_some() { check_deadline(before_deadline)?; }
                    with_regular(root, Path::new(path), frame, |file, mut frame| {
                    verify_root_engine(file, frame.as_deref_mut())?;
                    label(file, expected, install, before_deadline, frame)
                    })
                })?;
            }
        }
        for (path, expected) in EXECUTABLE_LABELS {
            scope(frame.as_deref_mut(), admission.as_deref_mut(), |frame, admission| {
                if frame.is_some() { check_deadline(before_deadline)?; }
                with_regular(root, Path::new(path), frame, |file, mut frame| {
                verify_executable_engine(file, frame.as_deref_mut())?;
                label(file, expected, install, before_deadline, frame)
                })
            })?;
        }
        scope(frame.as_deref_mut(), admission.as_deref_mut(), |frame, admission| {
            if frame.is_some() { check_deadline(before_deadline)?; }
            with_regular(root, Path::new("etc/aos/sandbox-agent/guest-executable-v1"), frame,
                |file, frame| label(file, PRIVATE_LABEL, install, before_deadline, frame))
        })?;
        scope(frame.as_deref_mut(), admission.as_deref_mut(), |frame, admission| {
            if frame.is_some() { check_deadline(before_deadline)?; }
            with_directory(root.as_fd(), Path::new("nix/store"), frame,
                |directory, frame| project_tree_engine(directory, 0, &mut 0, STORE_LABEL, true, install,
                    before_deadline, frame, 0, maximum_depth, maximum_entries_per_tree, admission))
        })
        })
    })
}

#[allow(clippy::too_many_arguments)]
pub(super) fn project_tree_engine(directory: BorrowedFd<'_>, path_bytes: usize, count: &mut usize,
    expected: &[u8], permit_symlinks: bool, install: bool, before_deadline: &mut impl FnMut() -> bool,
    mut frame: Option<&mut Frame>, depth: usize, maximum_depth: usize, maximum_entries_per_tree: usize,
    mut admission: Option<&mut WalkAdmissionV2<'_>>) -> Result<(), GuestRootLabelErrorV1>
{
    if frame.is_some() && depth > maximum_depth { return Err(GuestRootLabelErrorV1::ReceivingDepth); }
    verify_root_engine(directory, frame.as_deref_mut())?;
    label(directory, expected, install, before_deadline, frame.as_deref_mut())?;
    with_root(directory, frame.as_deref_mut(), |root, mut frame| {
        let anchor = format!("/proc/self/fd/{}", directory.as_raw_fd());
        let mut entries = None;
        let result = (|| {
            if let Some(admission) = admission.as_deref_mut() {
                let depth = frame.as_deref().map_or(0, |frame| frame.receiving_depth);
                admission.require_depth(depth)?;
            }
            entries = Some(std::fs::read_dir(&anchor)?);
            loop {
                if let Some(admission) = admission.as_deref_mut() {
                    admission.require_next_name()?;
                }
                let incoming = entries.as_mut().ok_or(GuestRootLabelErrorV1::UnsafeInode)?.next();
                let Some(incoming) = incoming else { break; };
                if let Some(admission) = admission.as_deref_mut() {
                    admission.entered_name()?;
                }
                let mut pending = Some(incoming);
                let entry_result = (|| {
                check_deadline(before_deadline)?;
                *count = count.checked_add(1).filter(|value| *value <= maximum_entries_per_tree)
                    .ok_or(GuestRootLabelErrorV1::UnsafeInode)?;
                let mut entry = Some(pending.take().ok_or(GuestRootLabelErrorV1::UnsafeInode)??);
                let name = entry.as_ref().ok_or(GuestRootLabelErrorV1::UnsafeInode)?.file_name();
                if frame.is_none() { drop(entry.take()); }
                let result = scope(frame.as_deref_mut(), admission.as_deref_mut(), |mut frame, admission| {
                    let child_bytes = path_bytes.checked_add(name.as_bytes().len() + 1)
                        .filter(|length| *length <= MAXIMUM_PATH_BYTES).ok_or(GuestRootLabelErrorV1::UnsafeInode)?;
                    let stat = statat(directory, &name, AtFlags::SYMLINK_NOFOLLOW)?;
                    if let Some(frame) = frame.as_deref_mut() { frame.metadata = Some(stat); }
                    if stat.st_uid != 0 { return Err(GuestRootLabelErrorV1::UnsafeInode); }
                    if frame.is_some() { check_deadline(before_deadline)?; }
                    match FileType::from_raw_mode(stat.st_mode) {
                        FileType::Directory => with_directory(root.as_fd(), Path::new(&name), frame, |child, mut frame| {
                            require_same_inode_engine(child, &stat, frame.as_deref_mut())?;
                            project_tree_engine(child, child_bytes, count, expected, permit_symlinks, install,
                                before_deadline, frame, depth + 1, maximum_depth, maximum_entries_per_tree, admission)
                        }),
                        FileType::RegularFile => with_regular(root, Path::new(&name), frame, |child, mut frame| {
                            require_same_inode_engine(child, &stat, frame.as_deref_mut())?;
                            verify_root_engine(child, frame.as_deref_mut())?;
                            label(child, expected, install, before_deadline, frame)
                        }),
                        FileType::Symlink => symlink(directory, &anchor, &name, &stat,
                            expected, permit_symlinks, install, frame),
                        _ => Err(GuestRootLabelErrorV1::UnsafeInode),
                    }
                });
                if result.is_err() {
                    if let Some(frame) = frame.as_deref_mut().and_then(|frame| frame.child.as_deref_mut()) {
                        frame.entry = entry; frame.name = Some(name);
                    }
                    return result;
                }
                Ok(())
                })();
                if entry_result.is_err() {
                    if let Some(frame) = frame.as_deref_mut() { frame.pending_entry = pending; }
                    return entry_result;
                }
            }
            // EOF completes the iterator's own native read scope before the
            // original directory sync/deadline frontier, as in the old loop.
            drop(entries.take());
            if install { fsync(directory)?; }
            check_deadline(before_deadline)
        })();
        if result.is_err() { if let Some(frame) = frame { frame.enumeration = entries; frame.anchor = Some(anchor); } }
        result
    })
}

pub(super) fn label(fd: BorrowedFd<'_>, expected: &[u8], install: bool,
    before_deadline: &mut impl FnMut() -> bool, mut frame: Option<&mut Frame>) -> Result<(), GuestRootLabelErrorV1>
{
    check_deadline(before_deadline)?;
    if install && attribute(fd, XATTR_NAME, expected, frame.as_deref_mut()).is_err() {
        fsetxattr(fd, XATTR_NAME, expected, XattrFlags::empty())?;
        fsync(fd)?;
    }
    attribute(fd, XATTR_NAME, expected, frame)
}

pub(super) fn attribute(fd: BorrowedFd<'_>, attribute: &str, expected: &[u8], mut frame: Option<&mut Frame>)
    -> Result<(), GuestRootLabelErrorV1>
{
    let mut local = [0_u8; MAXIMUM_LABEL_BYTES];
    let actual = frame.as_deref_mut().map(|frame| &mut frame.actual).unwrap_or(&mut local);
    let length = fgetxattr(fd, attribute, &mut actual[..])?;
    let mismatch = actual[..length] != *expected;
    if let Some(frame) = frame { frame.actual_bytes = length; }
    if mismatch { return Err(GuestRootLabelErrorV1::WrongLabel); }
    Ok(())
}


#[allow(clippy::too_many_arguments)]
fn symlink(directory: BorrowedFd<'_>, anchor: &str, name: &std::ffi::OsStr,
    stat: &rustix::fs::Stat, expected: &[u8], permit_symlinks: bool, install: bool,
    mut frame: Option<&mut Frame>) -> Result<(), GuestRootLabelErrorV1>
{
    if !permit_symlinks { return Err(GuestRootLabelErrorV1::UnsafeInode); }
    let path = Path::new(anchor).join(name);
    let result = (|| {
        let mut local = [0_u8; MAXIMUM_LABEL_BYTES];
        let actual = frame.as_deref_mut().map(|frame| &mut frame.actual).unwrap_or(&mut local);
        if install && !lgetxattr(&path, XATTR_NAME, &mut actual[..]).is_ok_and(|length| actual[..length] == *expected) {
            lsetxattr(&path, XATTR_NAME, expected, XattrFlags::empty())?;
        }
        let length = lgetxattr(&path, XATTR_NAME, &mut actual[..])?;
        let after = statat(directory, name, AtFlags::SYMLINK_NOFOLLOW)?;
        let mismatch = actual[..length] != *expected || stat.st_dev != after.st_dev || stat.st_ino != after.st_ino;
        if let Some(frame) = frame.as_deref_mut() { frame.after_metadata = Some(after); frame.actual_bytes = length; }
        if mismatch { return Err(GuestRootLabelErrorV1::WrongLabel); }
        Ok(())
    })();
    if result.is_err() { if let Some(frame) = frame { frame.path = Some(path); } }
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs::File;
    const ATTRIBUTE: &str = "user.aos_label_retained_test";

    #[test]
    fn failed_label_keeps_actual_file_raw_buffer_and_original_errno() {
        let directory = tempfile::tempdir().unwrap();
        let file = File::create(directory.path().join("file")).unwrap();
        fsetxattr(file.as_fd(), ATTRIBUTE, b"foreign", XattrFlags::empty()).unwrap();
        let root = BeneathRoot::from_owned(File::open(directory.path()).unwrap().into()).unwrap();
        let mut frame = Frame::default();

        let error = with_regular(&root, Path::new("file"), Some(&mut frame), |fd, frame|
            attribute(fd, ATTRIBUTE, b"expected", frame)).unwrap_err();
        assert!(matches!(error, GuestRootLabelErrorV1::WrongLabel));
        assert_eq!(&frame.actual[..frame.actual_bytes], b"foreign");
        let retained = frame.regular.as_ref().unwrap();
        let fd = retained.fd().unwrap();
        assert!(rustix::fs::fstat(fd).is_ok());
        let mut actual = [0; MAXIMUM_LABEL_BYTES];
        assert_eq!(fgetxattr(fd, ATTRIBUTE, &mut actual[..]).unwrap(), 7);

        let mut absent = Frame::default();
        let error = with_regular(&root, Path::new("file"), Some(&mut absent), |fd, frame|
            attribute(fd, "user.aos_label_absent", b"expected", frame)).unwrap_err();
        assert!(matches!(error, GuestRootLabelErrorV1::Io(rustix::io::Errno::NODATA)));
        assert!(absent.regular.as_ref().unwrap().fd().is_ok());
    }

    #[test]
    fn positive_file_scope_disposes_only_after_complete_exact_readback() {
        let directory = tempfile::tempdir().unwrap();
        let file = File::create(directory.path().join("file")).unwrap();
        fsetxattr(file.as_fd(), ATTRIBUTE, b"expected", XattrFlags::empty()).unwrap();
        let root = BeneathRoot::from_owned(File::open(directory.path()).unwrap().into()).unwrap();
        let mut frame = Frame::default();

        with_regular(&root, Path::new("file"), Some(&mut frame), |fd, frame|
            attribute(fd, ATTRIBUTE, b"expected", frame)).unwrap();
        assert_eq!(&frame.actual[..frame.actual_bytes], b"expected");
        assert!(frame.regular.is_none());
    }

    #[test]
    fn failed_root_is_sticky_and_reentry_preserves_actual_first_cause() {
        let file = tempfile::tempfile().unwrap();
        let mut original = GuestRootLabelReadOriginalV1::new(0).unwrap();
        assert!(original.verify_once_v1(file.as_fd()).is_err());
        let cause = original.failure().unwrap();
        assert!(matches!(cause.downcast_ref::<GuestRootLabelErrorV1>(), Some(GuestRootLabelErrorV1::Path(_))));
        let pointer = cause as *const dyn std::error::Error;
        assert!(original.frame.root.as_ref().unwrap().retained.is_some());
        assert!(original.verify_once_v1(file.as_fd()).is_err());
        assert!(std::ptr::eq(pointer, original.failure().unwrap() as *const dyn std::error::Error));
        assert!(!original.completed_exact_v1());
    }

    #[test]
    fn deny_only_original_deadline_precedes_native_root_entry_and_stays_sticky() {
        let file = tempfile::tempfile().unwrap();
        let mut original = GuestRootLabelReadOriginalV1::new(0).unwrap();
        let mut samples = 0;
        assert!(original.verify_before_once_v1(file.as_fd(), &mut || { samples += 1; false }).is_err());
        assert_eq!(samples, 1);
        assert!(original.frame.root.is_none());
        assert!(matches!(original.failure().unwrap().downcast_ref::<GuestRootLabelErrorV1>(), Some(GuestRootLabelErrorV1::Deadline)));
        assert!(original.verify_before_once_v1(file.as_fd(), &mut || panic!("reentry sampled the clock")).is_err());
    }

    #[test]
    fn denied_reached_prefix_precedes_root_duplication_and_stays_first() {
        let file = tempfile::tempfile().unwrap();
        let mut original = GuestRootLabelReadOriginalV1::new(4).unwrap();
        let mut offered = Vec::new();

        assert!(original.verify_receiving_before_once_v2(file.as_fd(), &mut || true,
            &mut |shape| { offered.push(shape); false }).is_err());

        assert_eq!(offered.len(), 1);
        assert_eq!(offered[0].named_entries, fixed_projection_names_v2().unwrap());
        assert!(original.frame.root.is_none());
        let first = original.failure().unwrap() as *const dyn std::error::Error;
        assert!(matches!(original.failure().unwrap().downcast_ref::<GuestRootLabelErrorV1>(),
            Some(GuestRootLabelErrorV1::ReceivingAdmission)));
        assert!(original.verify_receiving_before_once_v2(file.as_fd(), &mut || true,
            &mut |_| panic!("failed prefix was rearmed")).is_err());
        assert!(std::ptr::eq(first, original.failure().unwrap() as *const dyn std::error::Error));
    }

    #[test]
    fn denied_child_growth_retains_parent_and_allocates_no_child() {
        let directory = tempfile::tempdir().unwrap();
        let parent = File::open(directory.path()).unwrap();
        let mut frame = Frame::default();
        let mut root = RootOriginal::default();
        root.capture(parent.as_fd(), true).unwrap();
        frame.root = Some(root);
        let mut reached = GuestRootLabelReadReachedDataV2::default();
        let mut reject = |_| false;
        let mut admission = WalkAdmissionV2 {
            reached: &mut reached, admit: &mut reject, entered_names: fixed_projection_names_v2().unwrap(),
        };

        assert!(matches!(scope(Some(&mut frame), Some(&mut admission), |_, _|
            panic!("unpaid child entered")), Err(GuestRootLabelErrorV1::ReceivingAdmission)));

        assert!(frame.child.is_none());
        let retained = frame.root.as_ref().unwrap().root().unwrap();
        assert!(rustix::fs::fstat(retained.as_fd()).is_ok());
    }

    #[test]
    fn empty_directory_keeps_one_paid_spare_without_a_name_or_depth_refund() {
        let directory = tempfile::tempdir().unwrap();
        let mut iterator = std::fs::read_dir(directory.path()).unwrap();
        let mut reached = GuestRootLabelReadReachedDataV2::default();
        let mut offered = Vec::new();
        let mut accept = |shape| { offered.push(shape); true };
        let mut admission = WalkAdmissionV2 {
            reached: &mut reached, admit: &mut accept, entered_names: fixed_projection_names_v2().unwrap(),
        };

        admission.require_depth(2).unwrap();
        admission.require_next_name().unwrap();
        assert!(iterator.next().is_none());
        admission.require_depth(1).unwrap();
        admission.require_next_name().unwrap();
        drop(admission);
        drop(accept);

        assert_eq!(reached.named_entries, fixed_projection_names_v2().unwrap() + 1 + iterator_names_v2());
        assert_eq!(reached.peak_depth, 2);
        assert!(offered.windows(2).all(|pair|
            pair[0].named_entries <= pair[1].named_entries
                && pair[0].peak_depth <= pair[1].peak_depth));
    }

    #[test]
    fn depth_supplier_bounds_construction_and_rejects_unrepresentable_ceiling() {
        assert!(GuestRootLabelReadOriginalV1::new(MAXIMUM_PATH_BYTES / 2 + 1).is_none());
        let fixed = GuestRootLabelReadOriginalV1::fixed_receiving_footprint_v1().unwrap();
        let shallow = GuestRootLabelReadOriginalV1::dynamic_receiving_footprint_v1(0).unwrap();
        let deeper = GuestRootLabelReadOriginalV1::dynamic_receiving_footprint_v1(2).unwrap();
        assert_eq!(fixed.metadata_entries, 0);
        assert_eq!(deeper.metadata_entries, shallow.metadata_entries);
        assert!(deeper.memory_bytes > shallow.memory_bytes);
        assert!(deeper.open_files > shallow.open_files);
    }
}


fn inspect(fd: BorrowedFd<'_>, frame: Option<&mut Frame>) -> Result<rustix::fs::Stat, GuestRootLabelErrorV1> {
    let stat = fstat(fd)?;
    if let Some(frame) = frame {
        let slot = frame.inspected.get_mut(frame.inspections).ok_or(GuestRootLabelErrorV1::UnsafeInode)?;
        *slot = Some(stat);
        frame.inspections += 1;
    }
    Ok(stat)
}

fn require_root_stat(stat: &rustix::fs::Stat) -> Result<(), GuestRootLabelErrorV1> {
    if stat.st_uid != 0 || stat.st_mode & 0o022 != 0 { return Err(GuestRootLabelErrorV1::UnsafeInode); }
    Ok(())
}

pub(super) fn verify_root_engine(fd: BorrowedFd<'_>, frame: Option<&mut Frame>) -> Result<(), GuestRootLabelErrorV1> {
    require_root_stat(&inspect(fd, frame)?)
}

pub(super) fn verify_executable_engine(fd: BorrowedFd<'_>, frame: Option<&mut Frame>) -> Result<(), GuestRootLabelErrorV1> {
    let stat = inspect(fd, frame)?;
    if stat.st_uid != 0 || stat.st_mode & 0o022 != 0 || stat.st_mode & 0o100 == 0 || stat.st_nlink != 1 {
        return Err(GuestRootLabelErrorV1::UnsafeInode);
    }
    Ok(())
}

pub(super) fn require_same_inode_engine(fd: BorrowedFd<'_>, expected: &rustix::fs::Stat,
    frame: Option<&mut Frame>) -> Result<(), GuestRootLabelErrorV1>
{
    let actual = inspect(fd, frame)?;
    if actual.st_dev != expected.st_dev || actual.st_ino != expected.st_ino || actual.st_mode != expected.st_mode {
        return Err(GuestRootLabelErrorV1::UnsafeInode);
    }
    Ok(())
}


#[cfg(test)]
mod receiving_limits_tests {
    use super::*;

    #[test]
    fn restricted_limits_preserve_original_full_bound_and_refuse_overflow() {
        for depth in [0, 2, MAXIMUM_PATH_BYTES / 2] {
            let old = GuestRootLabelReadOriginalV1::dynamic_receiving_footprint_v1(depth).unwrap();
            let same = GuestRootLabelReadOriginalV1::receiving_footprint_with_limits_v2(depth, MAXIMUM_ENTRIES).unwrap();
            let restricted = GuestRootLabelReadOriginalV1::receiving_footprint_with_limits_v2(depth, 7).unwrap();

            assert_eq!(old, same);
            assert_eq!(restricted.memory_bytes, old.memory_bytes);
            assert_eq!(restricted.open_files, old.open_files);
            assert_eq!(restricted.metadata_entries, 10 * 8 + 64);
        }
        assert!(GuestRootLabelReadOriginalV1::with_receiving_limits_v2(0, MAXIMUM_ENTRIES + 1).is_none());
        assert!(GuestRootLabelReadOriginalV1::receiving_footprint_with_limits_v2(usize::MAX, 0).is_none());
    }
}
