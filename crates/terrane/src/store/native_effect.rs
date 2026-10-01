//! Owns native filesystem effects through physical completion and durability.
//!
//! A sealed producer supplies fixed paths, exact physical preimages, and an
//! owned authority refresh. The executor retains actual duplicated exclusions
//! inside its physical worker; dropping the asynchronous waiter does not release
//! them. These mechanics alone establish neither publication nor GC authority.
//!
//! ```text
//! held guards -> private fixed effect -> owned worker -> syscall + sync -> acknowledgment
//! ```

use std::fs::File;
use std::io;
use std::path::PathBuf;
use std::sync::Arc;

use super::StoreFailure;

#[path = "native_effect/range.rs"]
mod range;

#[path = "native_effect/directory_retention.rs"]
mod directory_retention;

/// Owns fixed initialization requests and genuine retained creator receipts.
#[path = "native_effect/initialization.rs"]
pub(super) mod initialization;

// The descendant can construct effects only from genuine sealed producer and
// held-backend inputs; ordinary callers cannot initialize the private mechanics.
#[path = "../bucket/publication/effects.rs"]
pub(crate) mod publication;

/// Retains a duplicate descriptor of an actually acquired native exclusion.
///
/// Its constructor and descriptor stay private. Retention preserves exclusion;
/// it does not establish actor, publication, selected-state or GC authority.
pub struct NativeExclusion {
    file: File,
}

impl NativeExclusion {
    /// Owns a duplicate of the binding's actual already held exclusion descriptor.
    ///
    /// Genuine bindings duplicate only their private acquired guard; this helper
    /// does not validate actor authority or acquire a lock from an arbitrary file.
    pub(super) fn from_held_descriptor(file: File) -> Self {
        Self { file }
    }
}

use crate::selected_bridge::OwnedFinalCheck;

#[derive(Clone, Copy)]
enum FencePolicy {
    ProtectedAncestor { owner: u32 },
    NamespaceDirectory { owner: u32 },
    PrivateControlDirectory { owner: u32 },
    NamespaceCoordination { owner: u32 },
    ProtectedRecord { owner: u32 },
    Payload { owner: u32 },
}

impl FencePolicy {
    /// Keeps ancestor ownership bound to the configured operator, even for a root-owned leaf.
    fn configured_owner(self) -> u32 {
        match self {
            Self::ProtectedAncestor { owner }
            | Self::NamespaceDirectory { owner }
            | Self::PrivateControlDirectory { owner }
            | Self::NamespaceCoordination { owner }
            | Self::ProtectedRecord { owner }
            | Self::Payload { owner } => owner,
        }
    }

    fn validate(self, stamp: MetadataStamp) -> io::Result<()> {
        let valid = match self {
            Self::ProtectedAncestor { owner } => {
                let sticky_root = stamp.owner == 0 && stamp.mode & 0o1000 != 0;
                stamp.kind == NodeKind::Directory
                    && (stamp.owner == 0 || stamp.owner == owner)
                    && (stamp.mode & 0o022 == 0 || sticky_root)
            }
            Self::NamespaceDirectory { owner } => {
                stamp.kind == NodeKind::Directory && stamp.owner == owner && stamp.mode & 0o022 == 0
            }
            Self::PrivateControlDirectory { owner } => {
                stamp.kind == NodeKind::Directory
                    && stamp.owner == owner
                    && stamp.mode & 0o777 == 0o700
            }
            Self::NamespaceCoordination { owner } | Self::Payload { owner } => {
                stamp.kind == NodeKind::Regular
                    && stamp.owner == owner
                    && stamp.links == 1
                    && stamp.mode & 0o022 == 0
            }
            Self::ProtectedRecord { owner } => {
                stamp.kind == NodeKind::Regular
                    && stamp.owner == owner
                    && stamp.links == 1
                    && stamp.mode & 0o777 == 0o600
            }
        };
        if !valid {
            return Err(io::Error::other("unsafe native physical fence"));
        }
        Ok(())
    }
}

struct ParentFence {
    path: PathBuf,
    stamp: MetadataStamp,
}

/// Retains a genuinely opened directory independently of acquired exclusions.
///
/// Only descendant native factories populate these private fields. A directory
/// descriptor is an incarnation observation, never a substitute for a lock.
struct NativeOpenedDirectory {
    file: File,
    path: PathBuf,
    stamp: MetadataStamp,
    policy: FencePolicy,
    parents: Vec<ParentFence>,
}

fn parent_paths(path: &std::path::Path) -> io::Result<Vec<PathBuf>> {
    if !path.is_absolute() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "native effect path is not absolute",
        ));
    }
    let parent = path
        .parent()
        .ok_or_else(|| io::Error::other("missing native effect parent"))?;
    let mut paths = Vec::new();
    let mut prefix = PathBuf::new();
    for component in parent.components() {
        if !matches!(
            component,
            std::path::Component::RootDir | std::path::Component::Normal(_)
        ) {
            return Err(io::Error::other("noncanonical native effect parent"));
        }
        prefix.push(component);
        paths.push(prefix.clone());
    }
    Ok(paths)
}

fn check_parents(path: &std::path::Path, parents: &[ParentFence], owner: u32) -> io::Result<()> {
    let paths = parent_paths(path)?;
    if paths.len() != parents.len() {
        return Err(io::Error::other("incomplete native parent fence"));
    }
    for (path, expected) in paths.iter().zip(parents) {
        if path != &expected.path {
            return Err(io::Error::other("misbound native parent fence"));
        }
        let actual = MetadataStamp::checked(&std::fs::symlink_metadata(path)?)?;
        FencePolicy::ProtectedAncestor { owner }.validate(actual)?;
        if !actual.same_incarnation(expected.stamp) {
            return Err(io::Error::other("native parent incarnation changed"));
        }
    }
    Ok(())
}

/// Records a physically checked name and, for coordination, its retained descriptor.
struct NamedFence {
    path: PathBuf,
    stamp: MetadataStamp,
    policy: FencePolicy,
    parents: Vec<ParentFence>,
    descriptor: Option<usize>,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum NodeKind {
    Directory,
    Regular,
}

#[derive(Clone, Copy, PartialEq, Eq)]
struct MetadataStamp {
    identity: (u64, u64),
    owner: u32,
    mode: u32,
    links: u64,
    kind: NodeKind,
}

impl MetadataStamp {
    fn same_incarnation(self, expected: Self) -> bool {
        self.identity == expected.identity
            && self.owner == expected.owner
            && self.mode == expected.mode
            && self.kind == expected.kind
            && (self.kind == NodeKind::Directory || self.links == expected.links)
    }

    #[cfg(unix)]
    fn checked(metadata: &std::fs::Metadata) -> io::Result<Self> {
        use std::os::unix::fs::MetadataExt;
        let kind = if metadata.is_dir() {
            NodeKind::Directory
        } else if metadata.is_file() {
            NodeKind::Regular
        } else {
            return Err(io::Error::other("nonregular physical fence"));
        };
        Ok(Self {
            identity: (metadata.dev(), metadata.ino()),
            owner: metadata.uid(),
            mode: metadata.mode(),
            links: metadata.nlink(),
            kind,
        })
    }

    #[cfg(not(unix))]
    fn checked(_metadata: &std::fs::Metadata) -> io::Result<Self> {
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "native metadata fences unavailable",
        ))
    }
}

impl NamedFence {
    fn check(&self, exclusions: &[NativeExclusion]) -> io::Result<()> {
        let named = std::fs::symlink_metadata(&self.path)?;
        let actual = MetadataStamp::checked(&named)?;
        self.policy.validate(actual)?;
        check_parents(&self.path, &self.parents, self.policy.configured_owner())?;
        if !actual.same_incarnation(self.stamp) {
            return Err(io::Error::other("current physical fence changed"));
        }
        if let Some(index) = self.descriptor {
            let retained = exclusions
                .get(index)
                .ok_or_else(|| io::Error::other("missing actual exclusion"))?;
            let opened = MetadataStamp::checked(&retained.file.metadata()?)?;
            self.policy.validate(opened)?;
            if !opened.same_incarnation(self.stamp) {
                return Err(io::Error::other(
                    "named coordination no longer matches retained exclusion",
                ));
            }
        }
        Ok(())
    }
}

/// Records an exact whole-value preimage for the final native dispatch.
struct ExactRead {
    path: PathBuf,
    expected: Option<Vec<u8>>,
    identity: Option<(u64, u64)>,
    metadata: Option<MetadataStamp>,
    policy: FencePolicy,
    owner: u32,
    parents: Vec<ParentFence>,
}

impl ExactRead {
    /// Rebinds only this operation's exact absent target to its created directory.
    fn check_created_directory(&self, created: &CreatedDirectory) -> io::Result<()> {
        if self.expected.is_some() || self.identity.is_some() || self.metadata.is_some() {
            return Err(io::Error::other(
                "created directory did not replace an absent preimage",
            ));
        }
        check_parents(&self.path, &self.parents, self.owner)?;
        if created.stamp.owner != self.owner {
            return Err(io::Error::other(
                "created directory owner differs from its absent preimage",
            ));
        }
        created.check()
    }

    #[cfg(unix)]
    fn check(&self) -> io::Result<()> {
        use std::io::Read;
        use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
        check_parents(&self.path, &self.parents, self.owner)?;
        let actual = match std::fs::OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
            .open(&self.path)
        {
            Ok(file) => {
                let metadata = file.metadata()?;
                let opened = MetadataStamp::checked(&metadata)?;
                self.policy.validate(opened)?;
                if self
                    .metadata
                    .is_none_or(|expected| !opened.same_incarnation(expected))
                {
                    return Err(io::Error::other("exact read metadata changed"));
                }
                if !metadata.is_file()
                    || metadata.nlink() != 1
                    || self.identity != Some((metadata.dev(), metadata.ino()))
                {
                    return Err(io::Error::other("physical preimage changed"));
                }
                let limit = self
                    .expected
                    .as_ref()
                    .map_or(1, |bytes| bytes.len().saturating_add(1));
                let mut bytes = Vec::new();
                (&file)
                    .take(u64::try_from(limit).map_err(io::Error::other)?)
                    .read_to_end(&mut bytes)?;
                let named = MetadataStamp::checked(&std::fs::symlink_metadata(&self.path)?)?;
                self.policy.validate(named)?;
                if !named.same_incarnation(opened) {
                    return Err(io::Error::other("exact read pathname changed"));
                }
                Some(bytes)
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound => None,
            Err(error) => return Err(error),
        };
        if actual != self.expected {
            return Err(io::Error::other("whole preimage changed"));
        }
        Ok(())
    }

    #[cfg(not(unix))]
    fn check(&self) -> io::Result<()> {
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "nofollow native receipts unavailable",
        ))
    }
}

/// Pins the freshly captured directory incarnation under this worker's exclusions.
struct CreatedDirectory {
    path: PathBuf,
    stamp: MetadataStamp,
}

impl CreatedDirectory {
    fn capture(path: &std::path::Path) -> io::Result<Self> {
        let stamp = MetadataStamp::checked(&std::fs::symlink_metadata(path)?)?;
        if stamp.kind != NodeKind::Directory || stamp.mode & 0o777 & !0o700 != 0 {
            return Err(io::Error::other(
                "new private directory has unexpected metadata",
            ));
        }
        Ok(Self {
            path: path.to_owned(),
            stamp,
        })
    }

    fn check(&self) -> io::Result<()> {
        let named = MetadataStamp::checked(&std::fs::symlink_metadata(&self.path)?)?;
        if !named.same_incarnation(self.stamp) {
            return Err(io::Error::other("created directory incarnation changed"));
        }
        Ok(())
    }

    fn check_descriptor(&self, file: &File) -> io::Result<()> {
        self.check()?;
        let opened = MetadataStamp::checked(&file.metadata()?)?;
        if !opened.same_incarnation(self.stamp) {
            return Err(io::Error::other(
                "opened directory differs from the created incarnation",
            ));
        }
        Ok(())
    }
}

/// Fixes one physical command from actual producer-owned paths.
enum Plan {
    // Initialization factories retain actual opened directories inside the
    // submitted command, independently of every genuinely acquired exclusion.
    RetainedDirectories {
        directories: Arc<[NativeOpenedDirectory]>,
        operation: Box<Plan>,
    },
    ProbeRange {
        path: PathBuf,
        start: u64,
        expected: Vec<u8>,
    },
    CreateDirectoryNew {
        path: PathBuf,
    },
    WriteNew {
        path: PathBuf,
        bytes: Vec<u8>,
    },
    SyncFile {
        path: PathBuf,
    },
    SyncDirectory {
        path: PathBuf,
    },
    RenameNoReplace {
        from: PathBuf,
        to: PathBuf,
    },
    Rename {
        from: PathBuf,
        to: PathBuf,
    },
    Remove {
        path: PathBuf,
    },
    Permissions {
        path: PathBuf,
        permissions: std::fs::Permissions,
    },
}

impl Plan {
    /// Borrows the actual primitive, refusing unexpected nested wrappers.
    #[cfg(test)]
    fn primitive(&self) -> Option<&Self> {
        match self {
            Self::RetainedDirectories { operation, .. } => {
                if matches!(operation.as_ref(), Self::RetainedDirectories { .. }) {
                    None
                } else {
                    Some(operation)
                }
            }
            _ => Some(self),
        }
    }
}

/// Opens a new staging inode with no permission exposure to other users.
fn create_private_file(path: &std::path::Path) -> io::Result<File> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
        let file = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
            .open(path)?;
        // Open never grants more than 0600, even with a permissive umask.
        // Restore exactly 0600 on the new descriptor if a restrictive umask
        // removed owner access; no later path reopen selects another inode.
        file.set_permissions(std::fs::Permissions::from_mode(0o600))?;
        Ok(file)
    }
    #[cfg(not(unix))]
    {
        let _ = path;
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "private native file creation unavailable",
        ))
    }
}

/// Binds an opened descriptor to the current nofollow name and complete metadata.
fn check_opened_name(file: &File, path: &std::path::Path, directory: bool) -> io::Result<()> {
    let opened = MetadataStamp::checked(&file.metadata()?)?;
    let named = MetadataStamp::checked(&std::fs::symlink_metadata(path)?)?;
    let kind = if directory {
        NodeKind::Directory
    } else {
        NodeKind::Regular
    };
    if opened.kind != kind || !named.same_incarnation(opened) {
        return Err(io::Error::other(
            "opened native descriptor no longer matches its name",
        ));
    }
    Ok(())
}

fn open_native(path: &std::path::Path, directory: bool) -> io::Result<File> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        let mut options = std::fs::OpenOptions::new();
        options
            .read(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK);
        let file = options.open(path)?;
        check_opened_name(&file, path, directory)?;
        Ok(file)
    }
    #[cfg(not(unix))]
    {
        let _ = (path, directory);
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "nofollow native effect opens unavailable",
        ))
    }
}

fn atomic_rename_no_replace(from: &std::path::Path, to: &std::path::Path) -> io::Result<()> {
    #[cfg(target_os = "linux")]
    {
        rustix::fs::renameat_with(
            rustix::fs::CWD,
            from,
            rustix::fs::CWD,
            to,
            rustix::fs::RenameFlags::NOREPLACE,
        )
        .map_err(io::Error::from)
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = (from, to);
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "atomic native no-replace rename unavailable",
        ))
    }
}

fn sync_parent(path: &std::path::Path) -> io::Result<()> {
    let parent = path
        .parent()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "missing parent"))?;
    open_native(parent, true)?.sync_all()
}

/// Preserves authority denial separately from physical I/O failure.
#[derive(Debug)]
pub enum NativeEffectFailure {
    /// A retained genuine producer check rejected a requested mutation.
    /// Earlier steps may already have become durable and require recovery.
    Rejected(StoreFailure),
    /// Physical execution or durable acknowledgment failed or was unavailable.
    /// A directory may already exist privately when the operator cannot open it
    /// for descriptor-bound mode repair; that refusal has kind `Unsupported`.
    Io(io::Error),
}

impl From<StoreFailure> for NativeEffectFailure {
    fn from(value: StoreFailure) -> Self {
        Self::Rejected(value)
    }
}

impl From<io::Error> for NativeEffectFailure {
    fn from(value: io::Error) -> Self {
        Self::Io(value)
    }
}

impl std::fmt::Display for NativeEffectFailure {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Rejected(error) => std::fmt::Display::fmt(error, formatter),
            Self::Io(error) => std::fmt::Display::fmt(error, formatter),
        }
    }
}

impl std::error::Error for NativeEffectFailure {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Rejected(error) => Some(error),
            Self::Io(error) => Some(error),
        }
    }
}

/// Identifies actual planned phases only for existing native fault wrappers.
#[cfg(test)]
pub(crate) enum EffectFaultProbe<'a> {
    /// Identifies the exact create-new file whose primitive is requested.
    WriteNew(&'a std::path::Path),
    /// Identifies an actual file durability command.
    FileSync,
    /// Identifies the directory whose durability is requested.
    DirectorySync(&'a std::path::Path),
    /// Identifies an atomic create-once destination.
    RenameNoReplace(&'a std::path::Path),
    /// Identifies a replacing rename destination.
    Rename(&'a std::path::Path),
    /// Identifies another privately fixed operation.
    Other,
}

/// Fixes injected physical failures inside the worker; it grants no authority.
#[cfg(test)]
#[derive(PartialEq, Eq)]
pub(crate) enum EffectFault {
    /// Fails the actual file sync before durable acknowledgment.
    BeforeFileSync,
    /// Fails before the actual rename syscall.
    BeforeRename,
    /// Fails directory sync after any preceding physical mutation.
    BeforeDirectorySync,
    /// Models a faulty binding replacing an existing create-once destination.
    ReplaceCreateOnce,
    /// Models failure to read this exact protected preimage.
    UnavailableRead(PathBuf),
}

/// Owns a fixed submitted operation and its actual exclusion through completion.
///
/// No public constructor, callback setter, Clone implementation or raw tuple
/// converts callers' data into this object. Public exposure is solely needed
/// to name an additive LocalFs consumer argument in the full repository.
pub struct NativeFsEffect {
    exclusions: Arc<[NativeExclusion]>,
    names: Vec<NamedFence>,
    preimages: Vec<ExactRead>,
    final_check: Option<OwnedFinalCheck>,
    plan: Plan,
    #[cfg(test)]
    faults: Vec<EffectFault>,
    #[cfg(all(test, feature = "tokio"))]
    gates: Vec<TestGate>,
}

#[cfg(all(test, feature = "tokio"))]
struct TestGate {
    phase: TestGatePhase,
    arrived: std::sync::mpsc::Sender<()>,
    release: std::sync::mpsc::Receiver<()>,
}

#[cfg(all(test, feature = "tokio"))]
#[derive(Clone, Copy, PartialEq, Eq)]
enum TestGatePhase {
    BeforeChecks,
    AfterDirectoryCreate,
    BeforeOpen,
    AfterOpen,
    AfterSourceSync,
    AfterRename,
}

#[cfg(all(test, feature = "tokio"))]
fn wait_test_gate(gates: &mut Vec<TestGate>, phase: TestGatePhase) -> io::Result<()> {
    if let Some(index) = gates.iter().position(|gate| gate.phase == phase) {
        let gate = gates.remove(index);
        gate.arrived.send(()).map_err(io::Error::other)?;
        gate.release.recv().map_err(io::Error::other)?;
    }
    Ok(())
}

impl NativeFsEffect {
    /// Identifies the fixed effect phase for an existing test fault wrapper.
    #[cfg(test)]
    pub(crate) fn fault_probe(&self) -> EffectFaultProbe<'_> {
        let Some(plan) = self.plan.primitive() else {
            return EffectFaultProbe::Other;
        };
        match plan {
            Plan::WriteNew { path, .. } => EffectFaultProbe::WriteNew(path),
            Plan::SyncFile { .. } => EffectFaultProbe::FileSync,
            Plan::SyncDirectory { path } => EffectFaultProbe::DirectorySync(path),
            Plan::RenameNoReplace { to, .. } => EffectFaultProbe::RenameNoReplace(to),
            Plan::Rename { to, .. } => EffectFaultProbe::Rename(to),
            _ => EffectFaultProbe::Other,
        }
    }

    /// Borrows the sealed create-once source for exact test boundary selection.
    ///
    /// Existing fault wrappers inspect the already staged slot and its fixed
    /// transaction to distinguish branch publication from preparation. This
    /// accessor supplies no constructor or replacement for the fixed operation.
    #[cfg(test)]
    pub(crate) fn rename_noreplace_source(&self) -> Option<&std::path::Path> {
        match self.plan.primitive()? {
            Plan::RenameNoReplace { from, .. } => Some(from),
            _ => None,
        }
    }

    /// Attaches closed test failure strategies to this already sealed effect.
    #[cfg(test)]
    pub(crate) fn inject_test_faults(mut self, faults: Vec<EffectFault>) -> Self {
        self.faults = faults;
        self
    }

    /// Executes this already fixed native operation within one synchronous poll.
    ///
    /// # Errors
    /// Rejects changed preimages, final-check denial and filesystem or sync errors.
    /// Returns `Unsupported` after private directory creation if restrictive
    /// permissions prevent the actual descriptor from opening for mode repair.
    pub(super) fn execute_inline(self) -> Result<(), NativeEffectFailure> {
        // Destructure first, and explicitly drop the actual guards only after
        // the syscall and directory sync. They must not be dropped after a
        // merely pre-dispatch check or retained only by an async parent.
        let Self {
            exclusions,
            names,
            preimages,
            final_check,
            plan,
            #[cfg(test)]
            faults,
            #[cfg(all(test, feature = "tokio"))]
            mut gates,
        } = self;

        let (plan, directories) = match plan {
            Plan::RetainedDirectories {
                directories,
                operation,
            } => (*operation, Some(directories)),
            primitive => (primitive, None),
        };

        let result = (|| {
            if matches!(&plan, Plan::RetainedDirectories { .. }) {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "nested native directory retention",
                )
                .into());
            }
            #[cfg(all(test, feature = "tokio"))]
            wait_test_gate(&mut gates, TestGatePhase::BeforeChecks)?;
            let durable_parent = |path: &std::path::Path| -> io::Result<()> {
                #[cfg(test)]
                if faults.contains(&EffectFault::BeforeDirectorySync) {
                    return Err(io::Error::other("injected retained directory sync failure"));
                }
                sync_parent(path)
            };
            let fresh_fence = || -> io::Result<()> {
                if let Some(directories) = &directories {
                    for directory in directories.iter() {
                        directory.check()?;
                    }
                }
                for name in &names {
                    name.check(&exclusions)?;
                }
                Ok(())
            };
            let fresh_projection =
                |created: Option<&CreatedDirectory>| -> Result<(), NativeEffectFailure> {
                    fresh_fence()?;
                    for preimage in &preimages {
                        #[cfg(test)]
                        if faults.contains(&EffectFault::UnavailableRead(preimage.path.clone())) {
                            return Err(
                                io::Error::other("injected retained exact read failure").into()
                            );
                        }
                        match created.filter(|created| created.path == preimage.path) {
                            Some(created) => preimage.check_created_directory(created)?,
                            None => preimage.check()?,
                        }
                    }
                    fresh_fence()?;
                    if let Some(created) = created {
                        created.check()?;
                    }
                    if let Some(final_check) = &final_check {
                        final_check.recheck()?;
                    }
                    Ok(())
                };
            fresh_projection(None)?;

            match plan {
                Plan::ProbeRange {
                    path,
                    start,
                    expected,
                } => {
                    range::verify(&path, start, &expected, &preimages)?;
                    fresh_projection(None)?;
                }
                Plan::CreateDirectoryNew { path } => {
                    #[cfg(unix)]
                    {
                        use std::os::unix::fs::DirBuilderExt;
                        let mut builder = std::fs::DirBuilder::new();
                        builder.mode(0o700).create(&path)?;
                        let mut created = CreatedDirectory::capture(&path)?;
                        #[cfg(all(test, feature = "tokio"))]
                        wait_test_gate(&mut gates, TestGatePhase::AfterDirectoryCreate)?;
                        created.check()?;
                        #[cfg(all(test, feature = "tokio"))]
                        wait_test_gate(&mut gates, TestGatePhase::BeforeOpen)?;
                        let directory = open_native(&path, true).map_err(|error| {
                            if error.kind() == io::ErrorKind::PermissionDenied {
                                io::Error::new(
                                    io::ErrorKind::Unsupported,
                                    "created directory cannot be safely opened for mode repair",
                                )
                            } else {
                                error
                            }
                        })?;
                        #[cfg(all(test, feature = "tokio"))]
                        wait_test_gate(&mut gates, TestGatePhase::AfterOpen)?;
                        fresh_projection(Some(&created))?;
                        created.check_descriptor(&directory)?;

                        use std::os::unix::fs::PermissionsExt;
                        directory.set_permissions(std::fs::Permissions::from_mode(0o700))?;
                        let mut final_stamp = created.stamp;
                        final_stamp.mode = (final_stamp.mode & !0o7777) | 0o700;
                        created.stamp = final_stamp;
                        created.check_descriptor(&directory)?;
                        directory.sync_all()?;
                        durable_parent(&path)?;
                    }
                    #[cfg(not(unix))]
                    return Err(io::Error::new(
                        io::ErrorKind::Unsupported,
                        "private native directories unavailable",
                    )
                    .into());
                }
                Plan::WriteNew { path, bytes } => {
                    use std::io::Write;
                    #[cfg(test)]
                    let mut file = if faults.contains(&EffectFault::ReplaceCreateOnce) {
                        // Model an actual broken create-new primitive, including
                        // its write and sync, rather than a fabricated success.
                        let mut options = std::fs::OpenOptions::new();
                        options.write(true).create(true).truncate(true);
                        #[cfg(unix)]
                        {
                            use std::os::unix::fs::OpenOptionsExt;
                            options
                                .mode(0o600)
                                .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK);
                        }
                        options.open(&path)?
                    } else {
                        create_private_file(&path)?
                    };
                    #[cfg(not(test))]
                    let mut file = create_private_file(&path)?;
                    file.write_all(&bytes)?;
                    file.sync_all()?;
                    durable_parent(&path)?;
                }
                Plan::SyncFile { path } => {
                    #[cfg(test)]
                    if faults.contains(&EffectFault::BeforeFileSync) {
                        return Err(io::Error::other("injected retained file sync failure").into());
                    }
                    let file = open_native(&path, false)?;
                    fresh_projection(None)?;
                    check_opened_name(&file, &path, false)?;
                    file.sync_all()?;
                }
                Plan::SyncDirectory { path } => {
                    #[cfg(test)]
                    if faults.contains(&EffectFault::BeforeDirectorySync) {
                        return Err(
                            io::Error::other("injected retained directory sync failure").into()
                        );
                    }
                    let directory = open_native(&path, true)?;
                    fresh_projection(None)?;
                    check_opened_name(&directory, &path, true)?;
                    directory.sync_all()?;
                }
                Plan::RenameNoReplace { from, to } => {
                    #[cfg(all(test, feature = "tokio"))]
                    wait_test_gate(&mut gates, TestGatePhase::BeforeOpen)?;
                    let source = open_native(&from, false)?;
                    #[cfg(all(test, feature = "tokio"))]
                    wait_test_gate(&mut gates, TestGatePhase::AfterOpen)?;
                    fresh_projection(None)?;
                    check_opened_name(&source, &from, false)?;
                    source.sync_all()?;
                    #[cfg(all(test, feature = "tokio"))]
                    wait_test_gate(&mut gates, TestGatePhase::AfterSourceSync)?;
                    fresh_projection(None)?;
                    check_opened_name(&source, &from, false)?;
                    #[cfg(test)]
                    {
                        if faults.contains(&EffectFault::BeforeRename) {
                            return Err(io::Error::other("injected retained rename failure").into());
                        }
                        if faults.contains(&EffectFault::ReplaceCreateOnce) {
                            std::fs::rename(&from, &to)?;
                            durable_parent(&to)?;
                            return Ok(());
                        }
                    }
                    atomic_rename_no_replace(&from, &to)?;
                    #[cfg(all(test, feature = "tokio"))]
                    wait_test_gate(&mut gates, TestGatePhase::AfterRename)?;
                    // The one syscall leaves no second hardlink alias. There
                    // is no post-rename authority gate which can skip cleanup.
                    durable_parent(&to)?;
                    if from.parent() != to.parent() {
                        durable_parent(&from)?;
                    }
                }
                Plan::Rename { from, to } => {
                    #[cfg(all(test, feature = "tokio"))]
                    wait_test_gate(&mut gates, TestGatePhase::BeforeOpen)?;
                    let source = open_native(&from, false)?;
                    #[cfg(all(test, feature = "tokio"))]
                    wait_test_gate(&mut gates, TestGatePhase::AfterOpen)?;
                    fresh_projection(None)?;
                    check_opened_name(&source, &from, false)?;
                    source.sync_all()?;
                    #[cfg(all(test, feature = "tokio"))]
                    wait_test_gate(&mut gates, TestGatePhase::AfterSourceSync)?;
                    fresh_projection(None)?;
                    check_opened_name(&source, &from, false)?;
                    std::fs::rename(&from, &to)?;
                    #[cfg(all(test, feature = "tokio"))]
                    wait_test_gate(&mut gates, TestGatePhase::AfterRename)?;
                    durable_parent(&to)?;
                    if from.parent() != to.parent() {
                        durable_parent(&from)?;
                    }
                }
                Plan::Remove { path } => {
                    std::fs::remove_file(&path)?;
                    durable_parent(&path)?;
                }
                Plan::Permissions { path, permissions } => {
                    #[cfg(all(test, feature = "tokio"))]
                    wait_test_gate(&mut gates, TestGatePhase::BeforeOpen)?;
                    let file = open_native(&path, false)?;
                    #[cfg(all(test, feature = "tokio"))]
                    wait_test_gate(&mut gates, TestGatePhase::AfterOpen)?;
                    fresh_projection(None)?;
                    check_opened_name(&file, &path, false)?;
                    file.set_permissions(permissions)?;
                    file.sync_all()?;
                }
                Plan::RetainedDirectories { .. } => {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidInput,
                        "nested native directory retention",
                    )
                    .into());
                }
            }
            if let Some(directories) = &directories {
                for directory in directories.iter() {
                    directory.check()?;
                }
            }
            Ok(())
        })();

        drop(directories);
        drop(exclusions);
        result
    }

    /// Executes the fixed operation in a worker which owns the actual guards.
    ///
    /// # Errors
    /// Returns final-check, native I/O, unavailable-runtime or worker failure.
    /// Dropping its waiter does not release guards retained by a queued or running
    /// worker.
    #[cfg(feature = "tokio")]
    pub(super) async fn execute_tokio(self) -> Result<(), NativeEffectFailure> {
        let runtime = tokio::runtime::Handle::try_current().map_err(io::Error::other)?;
        runtime
            .spawn_blocking(move || self.execute_inline())
            .await
            .map_err(io::Error::other)?
    }
}

#[cfg(all(test, unix))]
#[path = "native_effect/tests.rs"]
mod tests;
