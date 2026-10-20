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

#[path = "native_effect/immutable_cohort.rs"]
mod immutable_cohort;

#[cfg(all(feature = "surface-sdk", unix))]
pub(crate) mod checkout_metadata;

#[cfg(test)]
#[path = "native_effect/check_timings.rs"]
mod check_timings;

#[cfg(all(test, unix))]
#[path = "native_effect/check_timings_tests.rs"]
mod check_timings_tests;

#[path = "native_effect/parent_scratch.rs"]
mod parent_scratch;

#[cfg(all(test, unix))]
#[path = "native_effect/parent_scratch_tests.rs"]
mod parent_scratch_tests;

#[path = "native_effect/projection.rs"]
mod projection;

#[cfg(all(test, target_os = "linux"))]
#[path = "native_effect/body_read_eio_fixture.rs"]
mod body_read_eio_fixture;

#[path = "native_effect/range.rs"]
mod range;

#[path = "native_effect/payload_ranges.rs"]
mod payload_ranges;

pub use payload_ranges::{NativePayloadRangeRead, NativePayloadRangeRecord};

#[path = "native_effect/directory_retention.rs"]
mod directory_retention;

#[cfg(all(feature = "tokio", unix))]
#[path = "native_effect/read_projection.rs"]
mod read_projection;
#[cfg(all(feature = "tokio", unix))]
pub(super) use read_projection::NativeReadProjection;

#[path = "native_effect/artifact_seal.rs"]
mod artifact_seal;

// The descendant can construct effects only from genuine sealed producer and
// held-backend inputs; ordinary callers cannot initialize the private mechanics.
#[path = "../bucket/publication/effects.rs"]
pub(crate) mod publication;

#[cfg(unix)]
#[path = "../bucket/domain_deletion.rs"]
pub(crate) mod domain_deletion;

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
    #[cfg(any(feature = "tokio", test))]
    pub(super) fn from_held_descriptor(file: File) -> Self {
        Self { file }
    }
}

use crate::selected_bridge::OwnedFinalCheck;

#[derive(Clone, Copy, PartialEq, Eq)]
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

#[derive(PartialEq, Eq)]
struct ParentFence {
    path: PathBuf,
    stamp: MetadataStamp,
}

/// Retains a genuinely opened directory independently of acquired exclusions.
///
/// Only descendant native factories populate these private fields. A directory
/// descriptor is an incarnation observation, never a substitute for a lock.
struct NativeOpenedDirectory {
    file: Arc<File>,
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
    parent_scratch::check_parents(path, parents, owner, &mut PathBuf::new())
}

/// Records a physically checked name and, for coordination, its retained descriptor.
#[derive(PartialEq, Eq)]
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
        self.check_with_parent_scratch(exclusions, &mut PathBuf::new())
    }

    /// Reuses lexical path capacity while preserving every fresh physical check.
    fn check_with_parent_scratch(
        &self,
        exclusions: &[NativeExclusion],
        parent_prefix: &mut PathBuf,
    ) -> io::Result<()> {
        let named = std::fs::symlink_metadata(&self.path)?;
        let actual = MetadataStamp::checked(&named)?;
        self.policy.validate(actual)?;
        parent_scratch::check_parents(
            &self.path,
            &self.parents,
            self.policy.configured_owner(),
            parent_prefix,
        )?;
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
#[derive(PartialEq, Eq)]
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

    fn check(&self) -> io::Result<()> {
        self.check_with_scratch(&mut Vec::new())
    }

    /// Reuses capacity while freshly reading and comparing this whole preimage.
    #[cfg(unix)]
    fn check_with_scratch(&self, bytes: &mut Vec<u8>) -> io::Result<()> {
        self.check_with_parent_scratch(bytes, &mut PathBuf::new())
    }

    /// Reconstructs ancestry and reads the whole preimage using capacity only.
    #[cfg(unix)]
    fn check_with_parent_scratch(
        &self,
        bytes: &mut Vec<u8>,
        parent_prefix: &mut PathBuf,
    ) -> io::Result<()> {
        self.check_leaf(bytes, parent_prefix, true)
    }

    /// Refreshes every physical predicate, optionally comparing the whole body.
    #[cfg(unix)]
    fn check_leaf(
        &self,
        bytes: &mut Vec<u8>,
        parent_prefix: &mut PathBuf,
        body: bool,
    ) -> io::Result<()> {
        use std::io::Read;
        use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
        #[cfg(test)]
        let _leaf_span = check_timings::span(check_timings::Group::Leaf);
        #[cfg(test)]
        let parents_span = check_timings::span(check_timings::Group::Parents);
        parent_scratch::check_parents(&self.path, &self.parents, self.owner, parent_prefix)?;
        #[cfg(test)]
        drop(parents_span);
        #[cfg(test)]
        let mut open_span = Some(check_timings::span(check_timings::Group::Open));
        let actual = match std::fs::OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
            .open(&self.path)
        {
            Ok(file) => {
                #[cfg(test)]
                drop(open_span.take());
                #[cfg(test)]
                let descriptor_span = check_timings::span(check_timings::Group::Descriptor);
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
                #[cfg(test)]
                drop(descriptor_span);
                let limit = self
                    .expected
                    .as_ref()
                    .map_or(1, |bytes| bytes.len().saturating_add(1));
                if body {
                    #[cfg(test)]
                    let _body_span = check_timings::span(check_timings::Group::BodyRead);
                    #[cfg(test)]
                    check_timings::expected_bytes(self.expected.as_ref().map_or(0, Vec::len));
                    // Capacity is reusable; prior contents never establish evidence.
                    bytes.clear();
                    bytes.try_reserve_exact(limit)?;
                    (&file)
                        .take(u64::try_from(limit).map_err(io::Error::other)?)
                        .read_to_end(bytes)?;
                }
                #[cfg(test)]
                let named_span = check_timings::span(check_timings::Group::NamedAfter);
                let named = MetadataStamp::checked(&std::fs::symlink_metadata(&self.path)?)?;
                self.policy.validate(named)?;
                if !named.same_incarnation(opened) {
                    return Err(io::Error::other("exact read pathname changed"));
                }
                #[cfg(test)]
                drop(named_span);
                Some(bytes.as_slice())
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound => None,
            Err(error) => return Err(error),
        };
        #[cfg(test)]
        drop(open_span);
        #[cfg(test)]
        let _compare_span = check_timings::span(check_timings::Group::BodyCompare);
        if actual.is_some() != self.expected.is_some()
            || (body && actual != self.expected.as_deref())
        {
            return Err(io::Error::other("whole preimage changed"));
        }
        Ok(())
    }

    #[cfg(not(unix))]
    fn check_with_parent_scratch(
        &self,
        bytes: &mut Vec<u8>,
        _parent_prefix: &mut PathBuf,
    ) -> io::Result<()> {
        self.check_with_scratch(bytes)
    }

    #[cfg(not(unix))]
    fn check_with_scratch(&self, _bytes: &mut Vec<u8>) -> io::Result<()> {
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
    #[cfg(all(feature = "surface-sdk", unix))]
    CheckoutMetadata(Box<checkout_metadata::Request>),
    InstallImmutableCohort(immutable_cohort::Request),
    // Only the native worker can populate the result channel or consume a seal
    // into a protected creation-journal commitment.
    SealRetirementBarrier(Box<artifact_seal::retirement_barrier::BarrierRequest>),
    SealRestorePublication(Box<artifact_seal::restore_publication::RestoreRequest>),
    ObserveCurrentPair(Box<artifact_seal::current_pair::PairRequest>),
    ObserveLocalTriple(Box<artifact_seal::local_ownership::TripleRequest>),
    AcknowledgeLocalOwnership(Box<artifact_seal::local_ownership::ownership::OwnershipRequest>),
    ObserveLocalDeletion(Box<artifact_seal::local_deletion::observation::ObservationRequest>),
    AdvanceLocalDeletion(Box<artifact_seal::local_deletion::effects::StepRequest>),
    ObserveRestorePair(Box<artifact_seal::restore_pair::PairRequest>),
    SealLeasePublication(Box<artifact_seal::lease_publication::LeaseRequest>),
    SealMutationPublication(Box<artifact_seal::mutation_publication::MutationRequest>),
    SealRawPublication(Box<artifact_seal::raw_publication::RawRequest>),
    SealCopiedPreparation(Box<artifact_seal::copied_retirement::PreparationRequest>),
    ObserveCopiedBarrier(Box<artifact_seal::copied_retirement::BarrierRequest>),
    SealCopiedOwnership(Box<artifact_seal::copied_retirement::OwnershipRequest>),
    ObservePermanentLocal(Box<artifact_seal::permanent_local::observation::ObservationRequest>),
    ReclaimPermanentLocal(Box<artifact_seal::permanent_local::effects::ReclaimRequest>),
    SealPermanentLocalProgress(Box<artifact_seal::permanent_local::publication::ProgressRequest>),
    SealPendingCreation(Box<artifact_seal::PendingRequest>),
    SealArtifact(Box<artifact_seal::SealRequest>),
    CommitCreation(Box<artifact_seal::CommitRequest>),
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
    #[cfg(all(test, unix))]
    Permissions {
        path: PathBuf,
        permissions: std::fs::Permissions,
    },
}

impl Plan {
    /// Borrows the actual primitive, refusing unexpected nested wrappers.
    #[cfg(all(test, feature = "tokio"))]
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
#[cfg(all(test, feature = "tokio"))]
pub(crate) enum EffectFaultProbe<'a> {
    /// Identifies durability of the actual selected initial exclusion barrier.
    SealRetirementBarrier(&'a std::path::Path),

    /// Identifies durability of a genuinely checked Guard/ref selected slot.
    #[cfg(feature = "tokio")]
    SealMutationPublication(&'a std::path::Path),
    /// Identifies actual backend-only raw selected publication acknowledgment.
    #[cfg(feature = "tokio")]
    SealRawPublication(&'a std::path::Path),
    /// Identifies durability of the exact selected collector lease slot.
    SealLeasePublication(&'a std::path::Path),
    /// Identifies durability of a new copied destination retirement plan.
    CopiedPreparation(&'a std::path::Path),
    /// Identifies observation of the genuine copied destination barrier.
    CopiedBarrier(&'a std::path::Path),
    /// Identifies durability of checked first copied destination ownership.
    CopiedOwnership(&'a std::path::Path),
    /// Identifies an actual permanent-family observation or qualified extraction.
    PermanentLocalObservation(&'a std::path::Path),
    /// Identifies one exact permanently owned local residue request.
    PermanentLocalReclaim(&'a std::path::Path),
    /// Identifies durability of selected permanent recovery progress.
    PermanentLocalProgress(&'a std::path::Path),
    /// Identifies durability of Pending before the first artifact mutation.
    SealPendingCreation(&'a std::path::Path),
    /// Identifies descriptor-only qualification of one existing container pair.
    ObserveCurrentPair(&'a std::path::Path),
    /// Identifies actual descriptor qualification of a pack/index/Trash triple.
    ObserveLocalTriple(&'a std::path::Path),
    /// Identifies one native first-ownership boundary and its exact protected destination.
    LocalFirstOwnership(&'a std::path::Path, u8),
    /// Identifies an actual ordinary local deletion phase and protected destination.
    LocalDeletion(&'a std::path::Path, terrane_format::gc::DeletePhase),
    /// Identifies same-descriptor verification and durability of one artifact.
    SealArtifact(&'a std::path::Path),
    /// Identifies the exact protected Pending-to-Committed destination.
    CommitCreation(&'a std::path::Path),
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
    /// Fails after an actual targeted file descriptor has been synchronized.
    AfterFileSync,
    /// Fails immediately before an actual owned unlink.
    #[cfg(feature = "tokio")]
    BeforeUnlink,
    /// Fails after an actual owned unlink and before directory durability.
    #[cfg(feature = "tokio")]
    AfterUnlink,
    /// Fails after protected Cancelled intent has actually synchronized.
    #[cfg(feature = "tokio")]
    AfterCancelledIntentSync,
    /// Fails the first directory sync after one exact journal invalidation rename.
    #[cfg(feature = "tokio")]
    BeforeCancelledJournalDirectorySync(u8),
    /// Fails before the actual rename syscall.
    BeforeRename,
    /// Fails before the actual no-replace rename to this exact destination.
    BeforeRenameAt(PathBuf),
    /// Fails after a creation commitment has physically replaced Pending.
    AfterRename,
    /// Fails directory sync after any preceding physical mutation.
    BeforeDirectorySync,
    /// Fails before one exact creation directory descriptor is synchronized.
    BeforeDirectorySyncAt(PathBuf),
    /// Fails after one exact creation directory descriptor is synchronized.
    AfterDirectorySyncAt(PathBuf),
    /// Fails before an exact directory sync after Committed becomes visible.
    BeforeCommittedDirectorySyncAt(PathBuf),
    /// Fails after an exact directory sync after Committed becomes visible.
    AfterCommittedDirectorySyncAt(PathBuf),
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
    pairs: Vec<Arc<artifact_seal::current_pair::PairHold>>,
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
    AfterCohortStaging,
    AfterDirectoryCreate,
    BeforeOpen,
    AfterOpen,
    // Holds the actual bounded index read before its post-read metadata checks.
    AfterCurrentPairIndexRead,
    AfterSourceSync,
    BeforeRawSyncRefresh,
    AfterRawSyncBody,
    AfterRename,
    BeforeDirectorySync,
    AfterDirectorySync,
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
    /// Copies actual fixed cohort targets for explicit test callback observation.
    ///
    /// This test-only probe supplies no constructor, replacement command or
    /// physical completion claim. Ordinary primitive probes remain distinct.
    #[cfg(all(test, feature = "tokio"))]
    pub(crate) fn immutable_catalog_cohort_targets(&self) -> Option<Vec<PathBuf>> {
        let Plan::InstallImmutableCohort(request) = self.plan.primitive()? else {
            return None;
        };
        Some(request.targets())
    }

    /// Identifies the fixed effect phase for an existing test fault wrapper.
    #[cfg(all(test, feature = "tokio"))]
    pub(crate) fn fault_probe(&self) -> EffectFaultProbe<'_> {
        let Some(plan) = self.plan.primitive() else {
            return EffectFaultProbe::Other;
        };
        match plan {
            Plan::SealRestorePublication(request) => {
                EffectFaultProbe::SealRetirementBarrier(request.path())
            }
            Plan::SealRetirementBarrier(request) => {
                EffectFaultProbe::SealRetirementBarrier(request.path())
            }
            Plan::ObserveRestorePair(request) => {
                EffectFaultProbe::ObserveCurrentPair(request.path())
            }
            Plan::ObserveLocalTriple(request) => {
                EffectFaultProbe::ObserveLocalTriple(request.path())
            }
            Plan::AcknowledgeLocalOwnership(request) => {
                EffectFaultProbe::LocalFirstOwnership(request.path(), request.boundary())
            }
            Plan::AdvanceLocalDeletion(request) => {
                EffectFaultProbe::LocalDeletion(request.path(), request.phase())
            }
            Plan::ObserveCurrentPair(request) => {
                EffectFaultProbe::ObserveCurrentPair(request.path())
            }
            #[cfg(feature = "tokio")]
            Plan::SealMutationPublication(request) => {
                EffectFaultProbe::SealMutationPublication(request.path())
            }
            Plan::SealRawPublication(request) => {
                EffectFaultProbe::SealRawPublication(request.path())
            }
            Plan::SealLeasePublication(request) => {
                EffectFaultProbe::SealLeasePublication(request.path())
            }
            Plan::SealCopiedPreparation(request) => {
                EffectFaultProbe::CopiedPreparation(request.path())
            }
            Plan::ObserveCopiedBarrier(request) => EffectFaultProbe::CopiedBarrier(request.path()),
            Plan::SealCopiedOwnership(request) => EffectFaultProbe::CopiedOwnership(request.path()),
            Plan::ObservePermanentLocal(request) => {
                EffectFaultProbe::PermanentLocalObservation(request.path())
            }
            Plan::ReclaimPermanentLocal(request) => {
                EffectFaultProbe::PermanentLocalReclaim(request.path())
            }
            Plan::SealPermanentLocalProgress(request) => {
                EffectFaultProbe::PermanentLocalProgress(request.path())
            }
            Plan::SealPendingCreation(request) => {
                EffectFaultProbe::SealPendingCreation(request.journal_path())
            }
            Plan::SealArtifact(request) => EffectFaultProbe::SealArtifact(request.path()),
            Plan::CommitCreation(request) => {
                EffectFaultProbe::CommitCreation(request.journal_path())
            }
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
    #[cfg(all(test, feature = "tokio"))]
    pub(crate) fn rename_noreplace_source(&self) -> Option<&std::path::Path> {
        match self.plan.primitive()? {
            Plan::RenameNoReplace { from, .. } => Some(from),
            _ => None,
        }
    }

    /// Observes completed real syncs of this genuine common publication request.
    ///
    /// # Errors
    /// Rejects a different plan or unexpected nested retained-directory wrappers.
    #[cfg(all(test, feature = "tokio", unix))]
    pub(crate) fn observe_mutation_syncs(
        mut self,
        sender: std::sync::mpsc::Sender<artifact_seal::mutation_publication::MutationSyncEvent>,
    ) -> io::Result<Self> {
        let plan = match &mut self.plan {
            Plan::RetainedDirectories { operation, .. } => operation.as_mut(),
            plan => plan,
        };
        let Plan::SealMutationPublication(request) = plan else {
            return Err(io::Error::other(
                "sync observation requires checked mutation",
            ));
        };
        request.observe_syncs(sender);
        Ok(self)
    }

    /// Observes real retirement-barrier descriptors and completed syncs.
    ///
    /// # Errors
    /// Refuses a different plan or unsupported nested retention wrappers.
    #[cfg(all(test, feature = "tokio", unix))]
    pub(crate) fn observe_retirement_syncs(
        mut self,
        sender: std::sync::mpsc::Sender<RetirementSyncEvent>,
    ) -> io::Result<Self> {
        let plan = match &mut self.plan {
            Plan::RetainedDirectories { operation, .. } => operation.as_mut(),
            plan => plan,
        };
        let Plan::SealRetirementBarrier(request) = plan else {
            return Err(io::Error::other(
                "sync observation requires retirement barrier",
            ));
        };
        request.observe_syncs(sender);
        Ok(self)
    }

    /// Observes completed lease syncs after actual syscall and fresh checks.
    ///
    /// # Errors
    /// Refuses a different plan or unsupported nested retention wrappers.
    #[cfg(all(test, feature = "tokio", unix))]
    pub(crate) fn observe_lease_syncs(
        mut self,
        sender: std::sync::mpsc::Sender<artifact_seal::lease_publication::LeaseSyncEvent>,
    ) -> io::Result<Self> {
        let plan = match &mut self.plan {
            Plan::RetainedDirectories { operation, .. } => operation.as_mut(),
            plan => plan,
        };
        let Plan::SealLeasePublication(request) = plan else {
            return Err(io::Error::other("sync observation requires checked lease"));
        };
        request.observe_syncs(sender);
        Ok(self)
    }

    /// Attaches closed test failure strategies to this already sealed effect.
    #[cfg(test)]
    pub(crate) fn inject_test_faults(mut self, faults: Vec<EffectFault>) -> Self {
        self.faults = faults;
        self
    }

    /// Observes the actual before/after directory-sync handoffs without changing its plan.
    ///
    /// Only native tests use these channels. An after-sync signal proves the
    /// actual syscall boundary was reached; absence cannot create acknowledgment.
    #[cfg(all(test, feature = "tokio", unix))]
    pub(crate) fn test_directory_sync_handoff(
        mut self,
        before: std::sync::mpsc::Sender<()>,
        release: std::sync::mpsc::Receiver<()>,
        after: std::sync::mpsc::Sender<()>,
    ) -> Self {
        self.gates.push(TestGate {
            phase: TestGatePhase::BeforeDirectorySync,
            arrived: before,
            release,
        });
        let (released, resume) = std::sync::mpsc::channel();
        let _ = released.send(());
        self.gates.push(TestGate {
            phase: TestGatePhase::AfterDirectorySync,
            arrived: after,
            release: resume,
        });
        self
    }

    /// Completes the sealed native operation synchronously through durability.
    ///
    /// A [`crate::store::LocalFs`] adapter calls this method on its owned
    /// physical worker. The call blocks until the fixed operation and required
    /// synchronization finish, retaining all exclusions, descriptors and final
    /// checks throughout. It accepts no replacement plan or callback; the
    /// request's private producer has already fixed its complete inputs.
    /// Asynchronous adapters must retain that worker after waiter cancellation.
    ///
    /// # Examples
    ///
    /// A binding's physical worker consumes the request it received:
    ///
    /// ```no_run
    /// # fn complete(effect: terrane_sdk::store::NativeFsEffect)
    /// #     -> Result<(), terrane_sdk::store::NativeEffectFailure> {
    /// effect.execute_inline()
    /// # }
    /// ```
    ///
    /// # Errors
    /// Rejects changed preimages, final-check denial and filesystem or sync errors.
    /// Returns `Unsupported` after private directory creation if restrictive
    /// permissions prevent the actual descriptor from opening for mode repair.
    pub fn execute_inline(self) -> Result<(), NativeEffectFailure> {
        #[cfg(all(feature = "surface-sdk", unix))]
        if matches!(&self.plan, Plan::CheckoutMetadata(_)) {
            return checkout_metadata::execute(self);
        }
        if artifact_seal::owns(&self.plan) {
            return artifact_seal::execute(self);
        }
        let Self {
            exclusions,
            names,
            preimages,
            final_check,
            pairs,
            plan,
            #[cfg(test)]
            faults,
            #[cfg(all(test, feature = "tokio"))]
            gates,
        } = self;
        let (plan, directories) = match plan {
            Plan::RetainedDirectories {
                directories,
                operation,
            } => (*operation, Some(directories)),
            primitive => (primitive, None),
        };
        let mut worker = PrimitiveWorker {
            exclusions,
            names,
            preimages,
            final_check,
            pairs,
            #[cfg(test)]
            faults,
            #[cfg(all(test, feature = "tokio"))]
            gates,
        };
        let result = match plan {
            Plan::InstallImmutableCohort(request) if directories.is_none() => {
                immutable_cohort::execute(&mut worker, request)
            }
            primitive => worker.execute(primitive, directories.as_deref()),
        };

        // The physical worker retains every actual hold through all commands,
        // recapture, durability and final acknowledgment, even without a waiter.
        let PrimitiveWorker {
            exclusions,
            pairs,
            names: _names,
            preimages: _preimages,
            final_check: _final_check,
            #[cfg(test)]
                faults: _faults,
            #[cfg(all(test, feature = "tokio"))]
                gates: _gates,
        } = worker;
        drop(pairs);
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

/// Owns one complete projection throughout a primitive or immutable cohort.
struct PrimitiveWorker {
    exclusions: Arc<[NativeExclusion]>,
    names: Vec<NamedFence>,
    preimages: Vec<ExactRead>,
    final_check: Option<OwnedFinalCheck>,
    pairs: Vec<Arc<artifact_seal::current_pair::PairHold>>,
    #[cfg(test)]
    faults: Vec<EffectFault>,
    #[cfg(all(test, feature = "tokio"))]
    gates: Vec<TestGate>,
}

impl PrimitiveWorker {
    /// Runs the original primitive checks and durability under borrowed holds.
    fn execute(
        &mut self,
        plan: Plan,
        directories: Option<&[NativeOpenedDirectory]>,
    ) -> Result<(), NativeEffectFailure> {
        self.execute_scoped(plan, directories, None)
    }

    /// Applies only the closed Raw producer's unrelated-output body scope.
    fn execute_scoped(
        &mut self,
        plan: Plan,
        directories: Option<&[NativeOpenedDirectory]>,
        scope: Option<&immutable_cohort::scope::Scope>,
    ) -> Result<(), NativeEffectFailure> {
        let Self {
            exclusions,
            names,
            preimages,
            final_check,
            pairs,
            #[cfg(test)]
            faults,
            #[cfg(all(test, feature = "tokio"))]
            gates,
        } = self;
        if matches!(&plan, Plan::RetainedDirectories { .. }) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "nested native directory retention",
            )
            .into());
        }
        #[cfg(all(test, feature = "tokio"))]
        wait_test_gate(gates, TestGatePhase::BeforeChecks)?;
        let durable_parent = |path: &std::path::Path| -> io::Result<()> {
            #[cfg(test)]
            let parent = path
                .parent()
                .ok_or_else(|| io::Error::other("missing sync parent"))?;
            #[cfg(test)]
            if faults.contains(&EffectFault::BeforeDirectorySync)
                || faults.contains(&EffectFault::BeforeDirectorySyncAt(parent.to_owned()))
            {
                return Err(io::Error::other("injected retained directory sync failure"));
            }
            sync_parent(path)?;
            #[cfg(test)]
            if faults.contains(&EffectFault::AfterDirectorySyncAt(parent.to_owned())) {
                return Err(io::Error::other(
                    "injected failure after retained directory sync",
                ));
            }
            Ok(())
        };
        let projection = projection::Projection {
            exclusions,
            names,
            preimages,
            final_check: final_check.as_ref(),
            pairs,
            #[cfg(test)]
            faults,
        };
        let fresh_projection = |created: Option<&CreatedDirectory>| {
            projection.check_scoped(directories, created, scope)
        };
        fresh_projection(None)?;

        match plan {
            #[cfg(all(feature = "surface-sdk", unix))]
            Plan::CheckoutMetadata(_) => {
                return Err(io::Error::other("incorrect checkout metadata dispatch").into());
            }
            Plan::SealMutationPublication(_)
            | Plan::SealRawPublication(_)
            | Plan::SealRestorePublication(_)
            | Plan::SealRetirementBarrier(_)
            | Plan::ObserveCurrentPair(_)
            | Plan::ObserveLocalTriple(_)
            | Plan::AcknowledgeLocalOwnership(_)
            | Plan::ObserveLocalDeletion(_)
            | Plan::AdvanceLocalDeletion(_)
            | Plan::ObserveRestorePair(_)
            | Plan::SealLeasePublication(_)
            | Plan::SealCopiedPreparation(_)
            | Plan::ObserveCopiedBarrier(_)
            | Plan::SealCopiedOwnership(_)
            | Plan::ObservePermanentLocal(_)
            | Plan::ReclaimPermanentLocal(_)
            | Plan::SealPermanentLocalProgress(_)
            | Plan::SealPendingCreation(_)
            | Plan::SealArtifact(_)
            | Plan::CommitCreation(_) => {
                return Err(io::Error::other("incorrect artifact-seal dispatch").into());
            }
            Plan::ProbeRange {
                path,
                start,
                expected,
            } => {
                range::verify(&path, start, &expected, preimages)?;
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
                    wait_test_gate(gates, TestGatePhase::AfterDirectoryCreate)?;
                    created.check()?;
                    #[cfg(all(test, feature = "tokio"))]
                    wait_test_gate(gates, TestGatePhase::BeforeOpen)?;
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
                    wait_test_gate(gates, TestGatePhase::AfterOpen)?;
                    fresh_projection(Some(&created))?;
                    created.check_descriptor(&directory)?;

                    use std::os::unix::fs::PermissionsExt;
                    directory.set_permissions(std::fs::Permissions::from_mode(0o700))?;
                    let mut final_stamp = created.stamp;
                    final_stamp.mode = (final_stamp.mode & !0o7777) | 0o700;
                    created.stamp = final_stamp;
                    created.check_descriptor(&directory)?;
                    #[cfg(test)]
                    let syscall_span = check_timings::span(check_timings::Group::DirectorySync);
                    directory.sync_all()?;
                    #[cfg(test)]
                    drop(syscall_span);
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
                #[cfg(test)]
                let syscall_span = check_timings::span(check_timings::Group::Write);
                file.write_all(&bytes)?;
                #[cfg(test)]
                drop(syscall_span);
                #[cfg(test)]
                if faults.contains(&EffectFault::BeforeFileSync) {
                    return Err(io::Error::other("injected retained file sync failure").into());
                }
                #[cfg(test)]
                let syscall_span = check_timings::span(check_timings::Group::FileSync);
                file.sync_all()?;
                #[cfg(test)]
                drop(syscall_span);
                #[cfg(test)]
                if faults.contains(&EffectFault::AfterFileSync) {
                    return Err(
                        io::Error::other("injected failure after retained file sync").into(),
                    );
                }
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
                #[cfg(test)]
                let syscall_span = check_timings::span(check_timings::Group::FileSync);
                file.sync_all()?;
                #[cfg(test)]
                drop(syscall_span);
                #[cfg(test)]
                if faults.contains(&EffectFault::AfterFileSync) {
                    return Err(
                        io::Error::other("injected failure after retained file sync").into(),
                    );
                }
            }
            Plan::SyncDirectory { path } => {
                #[cfg(test)]
                if faults.contains(&EffectFault::BeforeDirectorySync)
                    || faults.contains(&EffectFault::BeforeDirectorySyncAt(path.clone()))
                {
                    return Err(io::Error::other("injected retained directory sync failure").into());
                }
                let directory = open_native(&path, true)?;
                fresh_projection(None)?;
                check_opened_name(&directory, &path, true)?;
                #[cfg(test)]
                let syscall_span = check_timings::span(check_timings::Group::DirectorySync);
                directory.sync_all()?;
                #[cfg(test)]
                drop(syscall_span);
                #[cfg(all(test, feature = "tokio"))]
                wait_test_gate(gates, TestGatePhase::AfterDirectorySync)?;
                #[cfg(test)]
                if faults.contains(&EffectFault::AfterDirectorySyncAt(path)) {
                    return Err(
                        io::Error::other("injected failure after retained directory sync").into(),
                    );
                }
            }
            Plan::RenameNoReplace { from, to } => {
                #[cfg(all(test, feature = "tokio"))]
                wait_test_gate(gates, TestGatePhase::BeforeOpen)?;
                let source = open_native(&from, false)?;
                #[cfg(all(test, feature = "tokio"))]
                wait_test_gate(gates, TestGatePhase::AfterOpen)?;
                fresh_projection(None)?;
                check_opened_name(&source, &from, false)?;
                #[cfg(test)]
                if faults.contains(&EffectFault::BeforeFileSync) {
                    return Err(io::Error::other("injected retained file sync failure").into());
                }
                #[cfg(test)]
                let syscall_span = check_timings::span(check_timings::Group::FileSync);
                source.sync_all()?;
                #[cfg(test)]
                drop(syscall_span);
                #[cfg(test)]
                if faults.contains(&EffectFault::AfterFileSync) {
                    return Err(
                        io::Error::other("injected failure after retained file sync").into(),
                    );
                }
                #[cfg(all(test, feature = "tokio"))]
                wait_test_gate(gates, TestGatePhase::AfterSourceSync)?;
                fresh_projection(None)?;
                check_opened_name(&source, &from, false)?;
                #[cfg(test)]
                {
                    if faults.contains(&EffectFault::BeforeRename)
                        || faults.iter().any(|fault| {
                            matches!(fault, EffectFault::BeforeRenameAt(target) if target == &to)
                        })
                    {
                        return Err(io::Error::other("injected retained rename failure").into());
                    }
                    if faults.contains(&EffectFault::ReplaceCreateOnce) {
                        #[cfg(test)]
                        let syscall_span = check_timings::span(check_timings::Group::Rename);
                        std::fs::rename(&from, &to)?;
                        #[cfg(test)]
                        drop(syscall_span);
                        durable_parent(&to)?;
                        return Ok(());
                    }
                }
                #[cfg(test)]
                let syscall_span = check_timings::span(check_timings::Group::RenameNoReplace);
                atomic_rename_no_replace(&from, &to)?;
                #[cfg(test)]
                drop(syscall_span);
                #[cfg(all(test, feature = "tokio"))]
                wait_test_gate(gates, TestGatePhase::AfterRename)?;
                #[cfg(test)]
                if faults.contains(&EffectFault::AfterRename) {
                    return Err(io::Error::other("injected failure after retained rename").into());
                }
                // The one syscall leaves no second hardlink alias. There
                // is no post-rename authority gate which can skip cleanup.
                durable_parent(&to)?;
                if from.parent() != to.parent() {
                    durable_parent(&from)?;
                }
            }
            Plan::Rename { from, to } => {
                #[cfg(all(test, feature = "tokio"))]
                wait_test_gate(gates, TestGatePhase::BeforeOpen)?;
                let source = open_native(&from, false)?;
                #[cfg(all(test, feature = "tokio"))]
                wait_test_gate(gates, TestGatePhase::AfterOpen)?;
                fresh_projection(None)?;
                check_opened_name(&source, &from, false)?;
                #[cfg(test)]
                if faults.contains(&EffectFault::BeforeFileSync) {
                    return Err(io::Error::other("injected retained file sync failure").into());
                }
                #[cfg(test)]
                let syscall_span = check_timings::span(check_timings::Group::FileSync);
                source.sync_all()?;
                #[cfg(test)]
                drop(syscall_span);
                #[cfg(test)]
                if faults.contains(&EffectFault::AfterFileSync) {
                    return Err(
                        io::Error::other("injected failure after retained file sync").into(),
                    );
                }
                #[cfg(all(test, feature = "tokio"))]
                wait_test_gate(gates, TestGatePhase::AfterSourceSync)?;
                fresh_projection(None)?;
                check_opened_name(&source, &from, false)?;
                #[cfg(test)]
                if faults.contains(&EffectFault::BeforeRename) {
                    return Err(io::Error::other("injected retained rename failure").into());
                }
                #[cfg(test)]
                let syscall_span = check_timings::span(check_timings::Group::Rename);
                std::fs::rename(&from, &to)?;
                #[cfg(test)]
                drop(syscall_span);
                #[cfg(all(test, feature = "tokio"))]
                wait_test_gate(gates, TestGatePhase::AfterRename)?;
                #[cfg(test)]
                if faults.contains(&EffectFault::AfterRename) {
                    return Err(io::Error::other("injected failure after retained rename").into());
                }
                durable_parent(&to)?;
                if from.parent() != to.parent() {
                    durable_parent(&from)?;
                }
            }
            Plan::Remove { path } => {
                #[cfg(test)]
                let syscall_span = check_timings::span(check_timings::Group::Remove);
                std::fs::remove_file(&path)?;
                #[cfg(test)]
                drop(syscall_span);
                durable_parent(&path)?;
            }
            #[cfg(all(test, unix))]
            Plan::Permissions { path, permissions } => {
                #[cfg(all(test, feature = "tokio"))]
                wait_test_gate(gates, TestGatePhase::BeforeOpen)?;
                let file = open_native(&path, false)?;
                #[cfg(all(test, feature = "tokio"))]
                wait_test_gate(gates, TestGatePhase::AfterOpen)?;
                fresh_projection(None)?;
                check_opened_name(&file, &path, false)?;
                file.set_permissions(permissions)?;
                #[cfg(test)]
                let syscall_span = check_timings::span(check_timings::Group::FileSync);
                file.sync_all()?;
                #[cfg(test)]
                drop(syscall_span);
            }
            Plan::InstallImmutableCohort(_) | Plan::RetainedDirectories { .. } => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "nested native directory retention",
                )
                .into());
            }
        }
        if let Some(directories) = directories {
            for directory in directories.iter() {
                #[cfg(test)]
                let _final_span = check_timings::span(check_timings::Group::FinalDirectory);
                directory.check()?;
            }
        }
        for pair in pairs.iter() {
            #[cfg(test)]
            let _final_span = check_timings::span(check_timings::Group::FinalPair);
            pair.recheck()?;
        }
        // Pair verification performs bounded reads after the effect. Refresh
        // the genuine producer's clock and authority after that final work.
        if let Some(check) = &final_check {
            #[cfg(test)]
            let _final_span = check_timings::span(check_timings::Group::FinalCurrent);
            check.recheck()?;
        }
        Ok(())
    }
}

#[cfg(all(test, unix))]
#[path = "native_effect/tests.rs"]
mod tests;

#[cfg(all(test, feature = "tokio", unix))]
pub(crate) use artifact_seal::mutation_publication::MutationSyncEvent;

/// Reports actual successful lease syncs without exposing the private result channel.
#[cfg(all(test, feature = "tokio", unix))]
pub(crate) use artifact_seal::lease_publication::LeaseSyncEvent;

/// Reports retirement durability observations independently from its private ACK.
#[cfg(all(test, feature = "tokio", unix))]
pub(crate) use artifact_seal::retirement_barrier::RetirementSyncEvent;
