//! Read-only idmapped mount observations for independently owned signer views.
//!
//! Callers select the source, view, mount parent and protected ancestry. This
//! module checks Linux mount and inode facts without journal replay, writer
//! exclusion, role admission or policy authority. The returned witness is an
//! observation that callers must bind to their own retained custody.

use std::error::Error;
use std::fmt;
use std::fs;
use std::io::{self, Read as _};
use std::os::unix::fs::MetadataExt as _;

use rustix::fs::{
    AtFlags, CWD, StatVfs, StatVfsMountFlags, Statx, StatxAttributes, StatxFlags, statvfs, statx,
};

/// Identifies the mounted inode and its mount across one bounded readback.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SignerMountWitness {
    mount_id: u64,
    device: u64,
    inode: u64,
    source_uid: u32,
}

impl SignerMountWitness {
    /// Returns the exact mounted root inode expected from an opened descriptor.
    pub const fn root_identity(self) -> (u64, u64) {
        (self.device, self.inode)
    }

    /// Returns the source directory owner UID before the signer-only idmap.
    pub const fn source_uid(self) -> u32 {
        self.source_uid
    }

    /// Rejects a descriptor opened through a transient replacement mount.
    pub fn matches_opened_root(self, device: u64, inode: u64) -> bool {
        (device, inode) == self.root_identity()
    }
}

/// Identifies a prepared mounted view compared to authenticated original names.
///
/// This carries only actual mounted device/inode/mount DATA. It does not expose
/// an original owner UID as though the inaccessible source had been observed.
/// The caller must retain its genuine prepared-view/profile/install original.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PreparedSignerMountWitnessV1 {
    mount_id: u64,
    device: u64,
    inode: u64,
}

impl PreparedSignerMountWitnessV1 {
    /// Returns the actual mounted root's device/inode comparison DATA.
    #[must_use]
    pub const fn root_identity(self) -> (u64, u64) {
        (self.device, self.inode)
    }

    /// Returns the actual distinct Linux mount ID observed on this view.
    #[must_use]
    pub const fn mount_id(self) -> u64 {
        self.mount_id
    }
}

#[derive(Clone, Copy)]
enum SourceComparison<'a> {
    RootPrepared {
        target: RootReadonlyViewV1,
        original_root: Option<(u64, u64)>,
        uid: u32,
        gid: u32,
    },
    OriginalPath(&'a str),
    Prepared {
        source_path: &'a str,
        root: (u64, u64),
        uid: u32,
        gid: u32,
    },
}

/// Selects one installed readonly view for the normal Root role.
///
/// These paths are compiled deployment DATA. The selected unit/profile and
/// genuine receiving owner remain mandatory; a mount observation grants no
/// authority to replay, issue a policy statement or spend a receiving account.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RootReadonlyViewV1 {
    /// Selects the original Controller directory's readonly mapping.
    Controller,
    /// Selects the fixed Controller Storage Session directory.
    StorageSession,
    /// Selects the fixed Controller Host Session directory.
    HostSession,
    /// Selects the fixed Controller Mount Session directory.
    MountSession,
    /// Selects the fixed Controller Network Session directory.
    NetworkSession,
    /// Selects the protected Source journal directory.
    Source,
    /// Selects the Controller's private Cache bootstrap directory.
    CacheBootstrap,
    /// Selects the four protected Cache journals.
    CacheJournals,
    /// Selects the physical Cache object inventory.
    CacheObjects,
}

impl RootReadonlyViewV1 {
    /// Returns the fixed Root mount target as nonauthorizing path DATA.
    #[must_use]
    pub const fn view_path_v1(self) -> &'static str {
        match self {
            Self::Controller => "/run/aos/sandbox-root-controller",
            Self::StorageSession => "/run/aos/sandbox-root-storage-session",
            Self::HostSession => "/run/aos/sandbox-root-host-session",
            Self::MountSession => "/run/aos/sandbox-root-mount-session",
            Self::NetworkSession => "/run/aos/sandbox-root-network-session",
            Self::Source => "/run/aos/sandbox-root-source",
            Self::CacheBootstrap => "/run/aos/sandbox-root-cache-bootstrap",
            Self::CacheJournals => "/run/aos/sandbox-policy-cache-journals",
            Self::CacheObjects => "/run/aos/sandbox-root-cache-objects",
        }
    }

    /// Returns the original writer directory named by the installed mapping.
    #[must_use]
    pub const fn source_path_v1(self) -> &'static str {
        match self {
            Self::Controller => "/var/lib/aos/sandboxd",
            Self::StorageSession => "/var/lib/aos/sandboxd/broker-session/storage",
            Self::HostSession => "/var/lib/aos/sandboxd/broker-session/host",
            Self::MountSession => "/var/lib/aos/sandboxd/broker-session/mount",
            Self::NetworkSession => "/var/lib/aos/sandboxd/broker-session/network",
            Self::Source => "/var/lib/aos/sandbox/source-domains",
            Self::CacheBootstrap => "/var/lib/aos/sandboxd/cache-residency-authority",
            Self::CacheJournals => "/var/lib/aos/sandbox/cache-residency-journals",
            Self::CacheObjects => "/var/lib/aos/sandbox/cache-residency-objects",
        }
    }

    const fn source_metadata_is_reachable_v1(self) -> bool {
        !matches!(self, Self::StorageSession | Self::HostSession | Self::MountSession
            | Self::NetworkSession | Self::CacheBootstrap)
    }

    const fn source_observation_path_v1(self) -> &'static str {
        match self {
            Self::StorageSession => "/run/aos/sandbox-root-controller/broker-session/storage",
            Self::HostSession => "/run/aos/sandbox-root-controller/broker-session/host",
            Self::MountSession => "/run/aos/sandbox-root-controller/broker-session/mount",
            Self::NetworkSession => "/run/aos/sandbox-root-controller/broker-session/network",
            Self::CacheBootstrap => "/run/aos/sandbox-root-controller/cache-residency-authority",
            _ => self.source_path_v1(),
        }
    }
}

const MAXIMUM_PROTECTED_PARENTS: usize = 6;
const MAXIMUM_MOUNTINFO_BYTES: usize = 1024 * 1024;
const MOUNTINFO_READ_LIMIT: usize = MAXIMUM_MOUNTINFO_BYTES + 1;

/// Reports a closed or failed retained mount observation.
///
/// The owning attempt retains the original reached native error and partial
/// readback. This marker supplies neither a witness nor permission to retry.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SignerMountReadbackClosedV1;

impl fmt::Display for SignerMountReadbackClosedV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("signer mount readback is closed")
    }
}

impl Error for SignerMountReadbackClosedV1 {}

#[derive(Clone, Copy)]
enum ObservationFailure {
    Closed,
    Invalid,
    Parent(usize),
    Source,
    RootSource,
    RootView,
    RootMounted,
    RootFilesystem,
    View,
    Mounted,
    MountParent,
    Filesystem,
    MountinfoOpen,
    MountinfoRead,
}

#[derive(Clone, Copy)]
enum ObservationDisposition {
    Ordinary,
    Retained,
}

/// Retains one bounded mount observation and all reached native readback.
///
/// The selected caller prepays this owner before observation, keeps it resident
/// on failure, and independently joins any witness to its actual custody. At
/// most six protected parent names are accepted in this retained profile. The
/// ordinary wrapper keeps its existing unrestricted parent slice contract.
/// Neither names, a successful read nor this owner establish role authority.
#[must_use = "retain partial mount readback and native results on failure"]
pub struct SignerMountReadbackAttemptV1 {
    started: bool,
    first: Option<ObservationFailure>,
    parents: [Option<io::Result<fs::Metadata>>; MAXIMUM_PROTECTED_PARENTS],
    source: Option<io::Result<fs::Metadata>>,
    root_source: Option<io::Result<fs::Metadata>>,
    root_view: Option<io::Result<fs::Metadata>>,
    root_mounted: Option<Result<Statx, rustix::io::Errno>>,
    root_filesystem: Option<Result<StatVfs, rustix::io::Errno>>,
    view: Option<io::Result<fs::Metadata>>,
    mounted: Option<Result<Statx, rustix::io::Errno>>,
    mount_parent: Option<Result<Statx, rustix::io::Errno>>,
    filesystem: Option<Result<StatVfs, rustix::io::Errno>>,
    mountinfo_file: Option<io::Result<fs::File>>,
    mountinfo: String,
    read: Option<io::Result<usize>>,
    invalid: Option<io::Error>,
    witness: Option<SignerMountWitness>,
    prepared_witness: Option<PreparedSignerMountWitnessV1>,
}

impl SignerMountReadbackAttemptV1 {
    /// Creates empty inline result storage without allocation or native work.
    #[must_use]
    pub fn new() -> Self {
        Self {
            started: false,
            first: None,
            parents: std::array::from_fn(|_| None),
            source: None,
            root_source: None, root_view: None, root_mounted: None, root_filesystem: None,
            view: None,
            mounted: None,
            mount_parent: None,
            filesystem: None,
            mountinfo_file: None,
            mountinfo: String::new(),
            read: None,
            invalid: None,
            witness: None,
            prepared_witness: None,
        }
    }

    /// Prices the dominant retained and growing read representation as DATA.
    ///
    /// This includes this actual inline owner, a one-MiB-plus-one read limit,
    /// old/new String growth overlap, fixed read scratch and bounded native
    /// error/control carriers. It pays nothing. A caller retaining several
    /// attempts charges every complete bound before the first observation.
    /// Allocator metadata and kernel residency need independent backstops.
    #[must_use]
    pub fn receiving_memory_bound_v1() -> Option<usize> {
        std::mem::size_of::<Self>()
            .checked_add(MOUNTINFO_READ_LIMIT.checked_mul(3)?)?
            .checked_add(64 * 1024)?
            .checked_add(16 * 256)?
            .checked_add(std::mem::size_of::<SourceComparison<'static>>())?
            .checked_add(std::mem::size_of::<((u64, u64), u32, u32, bool, u32)>())?
            .checked_add(std::mem::size_of::<SignerMountWitness>())?
            .checked_add(std::mem::size_of::<PreparedSignerMountWitnessV1>())?
            .checked_add(28usize.checked_mul(std::mem::size_of::<usize>())?)
    }

    /// Counts fixed reached custody and comparison controls as passive DATA.
    ///
    /// The census includes fourteen owner fields, six parent destinations,
    /// seven source-comparison controls, six projected source scalars, three
    /// native flag/identity locals and eight mountinfo iterator/field controls.
    /// Seven witness output scalars, five invocation scalars, four parent-loop
    /// controls, three branch/result controls, two filter/count controls and
    /// seven fixed borrowed argument controls additionally coexist with them.
    /// Dynamic mountinfo storage has one allocation/growth lane, priced by the
    /// memory helper; its allocator metadata remains a separate backstop.
    #[must_use]
    pub const fn receiving_metadata_cells_v1() -> usize {
        14 + MAXIMUM_PROTECTED_PARENTS + 7 + 6 + 3 + 8
            + 7 + 5 + 4 + 3 + 2 + 7
    }

    /// Performs this owner's single mount observation in the supplied order.
    ///
    /// The actual mountinfo File and partial String remain here even when
    /// reading or validation fails. No failed attempt can observe again or
    /// replace its first native cause with a later refusal.
    ///
    /// # Errors
    /// Refuses reentry, more than six protected parents, original observation
    /// errors, unsafe ownership/mount facts, or nonmatching bounded mountinfo.
    pub fn observe_once(
        &mut self,
        view: &str,
        source: &str,
        signer_uid: u32,
        view_parent: &str,
        protected_parents: &[&str],
    ) -> Result<(), SignerMountReadbackClosedV1> {
        if self.started {
            self.first.get_or_insert(ObservationFailure::Closed);
            return Err(SignerMountReadbackClosedV1);
        }
        self.started = true;
        if protected_parents.len() > MAXIMUM_PROTECTED_PARENTS {
            self.first = Some(ObservationFailure::Closed);
            return Err(SignerMountReadbackClosedV1);
        }
        match observe_mount(
            self, view, SourceComparison::OriginalPath(source), signer_uid, view_parent, protected_parents,
            ObservationDisposition::Retained,
        ) {
            Ok(witness) => {
                self.witness = Some(witness);
                Ok(())
            }
            Err(first) => {
                self.first = Some(first);
                Err(SignerMountReadbackClosedV1)
            }
        }
    }

    /// Observes the fixed prepared Controller Bootstrap view without source search.
    ///
    /// The actual Cache purpose supplies its authenticated Root/Held original
    /// directory identity and measured Controller UID/GID comparison DATA. The
    /// private original pathname is never resolved; exact compiled mountinfo
    /// source root, mapped owner/mode, separate mount, readonly/nosuid/nodev/
    /// noexec/nosymfollow and actual root inode must all agree. This supplies
    /// no standalone proof of the Root/Held/profile/install originals.
    ///
    /// # Errors
    /// Retains reentry, unsafe /run parents, unavailable view/statx/mountinfo,
    /// wrong original comparison identity, mapping, flags or mount root.
    pub fn observe_prepared_cache_bootstrap_once(
        &mut self,
        signer_uid: u32,
        original_root: (u64, u64),
        original_uid: u32,
        original_gid: u32,
    ) -> Result<(), SignerMountReadbackClosedV1> {
        if self.started {
            self.first.get_or_insert(ObservationFailure::Closed);
            return Err(SignerMountReadbackClosedV1);
        }
        self.started = true;
        let source = SourceComparison::Prepared {
            source_path: "/var/lib/aos/sandboxd/cache-residency-authority",
            root: original_root,
            uid: original_uid,
            gid: original_gid,
        };
        match observe_mount(self, "/run/aos/sandbox-cache-signer-controller-journal",
            source, signer_uid, "/run/aos", &["/run", "/run/aos"],
            ObservationDisposition::Retained)
        {
            Ok(witness) => {
                self.prepared_witness = Some(PreparedSignerMountWitnessV1 {
                    mount_id: witness.mount_id,
                    device: witness.device,
                    inode: witness.inode,
                });
                Ok(())
            }
            Err(first) => {
                self.first = Some(first);
                Err(SignerMountReadbackClosedV1)
            }
        }
    }

    /// Observes one fixed Root readonly mapping through the same native engine.
    ///
    /// Root must run with effective UID zero. The compiled unit maps the
    /// Controller UID/GID to zero; this method checks that mapped ownership,
    /// exact mountinfo source root, flags and an optional original inode pair.
    /// Public source roots are independently statted. Private Session/bootstrap
    /// names are statted through the separately checked Controller mapping. Its
    /// original root metadata, mapped inode, readonly mount and exact source all
    /// agree before the current mapped child can match the dedicated view.
    /// No inaccessible private raw ancestry is searched or claimed observed.
    /// Root's genuine caller supplies the Controller identity from its profile.
    ///
    /// # Errors
    /// Retains reentry, a non-Root caller, invalid original identities, native
    /// errors, a different source/view inode or an unsafe fixed mount.
    pub fn observe_root_readonly_once(
        &mut self,
        target: RootReadonlyViewV1,
        controller_uid: u32,
        controller_gid: u32,
        original_root: Option<(u64, u64)>,
    ) -> Result<(), SignerMountReadbackClosedV1> {
        if self.started {
            self.first.get_or_insert(ObservationFailure::Closed);
            return Err(SignerMountReadbackClosedV1);
        }
        self.started = true;
        if rustix::process::geteuid().as_raw() != 0 {
            self.first = Some(self.invalid());
            return Err(SignerMountReadbackClosedV1);
        }
        let source = SourceComparison::RootPrepared {
            target, original_root, uid: controller_uid, gid: controller_gid,
        };
        match observe_mount(self, target.view_path_v1(), source, 0,
            "/run/aos", &["/run", "/run/aos"], ObservationDisposition::Retained)
        {
            Ok(witness) => { self.witness = Some(witness); Ok(()) }
            Err(first) => { self.first = Some(first); Err(SignerMountReadbackClosedV1) }
        }
    }

    /// Borrows only actual completed prepared-view mount identity DATA.
    #[must_use]
    pub fn prepared_witness(&self) -> Option<PreparedSignerMountWitnessV1> {
        if self.first.is_none() { self.prepared_witness } else { None }
    }

    /// Returns only this attempt's completed observation as nonauthorizing DATA.
    #[must_use]
    pub fn witness(&self) -> Option<SignerMountWitness> {
        if self.first.is_some() {
            return None;
        }
        self.witness
    }

    /// Borrows this attempt's first original refusal without extracting custody.
    #[must_use]
    pub fn failure(&self) -> Option<&(dyn Error + 'static)> {
        let first = self.first?;
        let cause: Option<&(dyn Error + 'static)> = match first {
            ObservationFailure::Closed => Some(&SignerMountReadbackClosedV1),
            ObservationFailure::Invalid => self.invalid.as_ref().map(|error| error as &dyn Error),
            ObservationFailure::Parent(index) => io_failure(&self.parents[index]),
            ObservationFailure::Source => io_failure(&self.source),
            ObservationFailure::RootSource => io_failure(&self.root_source),
            ObservationFailure::RootView => io_failure(&self.root_view),
            ObservationFailure::RootMounted => native_failure(&self.root_mounted),
            ObservationFailure::RootFilesystem => native_failure(&self.root_filesystem),
            ObservationFailure::View => io_failure(&self.view),
            ObservationFailure::Mounted => native_failure(&self.mounted),
            ObservationFailure::MountParent => native_failure(&self.mount_parent),
            ObservationFailure::Filesystem => native_failure(&self.filesystem),
            ObservationFailure::MountinfoOpen => io_failure(&self.mountinfo_file),
            ObservationFailure::MountinfoRead => io_failure(&self.read),
        };
        Some(cause.unwrap_or(&SignerMountReadbackClosedV1))
    }

    fn invalid(&mut self) -> ObservationFailure {
        self.invalid.get_or_insert_with(invalid_mount);
        ObservationFailure::Invalid
    }

    fn read_open_mountinfo(
        &mut self,
        disposition: ObservationDisposition,
    ) -> Result<(), ObservationFailure> {
        // The ordinary branch consumes exactly the old File/Take temporary:
        // its descriptor drops after read_to_string, before result projection.
        // The selected branch borrows and retains that same opened File.
        self.read = Some(match disposition {
            ObservationDisposition::Ordinary => match self.mountinfo_file.take() {
                Some(Ok(file)) => read_mountinfo_bytes(file, &mut self.mountinfo),
                other => {
                    self.mountinfo_file = other;
                    return Err(ObservationFailure::MountinfoOpen);
                }
            },
            ObservationDisposition::Retained => match self.mountinfo_file.as_mut() {
                Some(Ok(file)) => read_mountinfo_bytes(file, &mut self.mountinfo),
                _ => return Err(ObservationFailure::MountinfoOpen),
            },
        });
        if self.read.as_ref().is_none_or(Result::is_err) {
            return Err(ObservationFailure::MountinfoRead);
        }
        Ok(())
    }

    fn into_io_error(mut self, first: ObservationFailure) -> io::Error {
        match first {
            ObservationFailure::Closed => invalid_mount(),
            ObservationFailure::Invalid => self.invalid.take().unwrap_or_else(invalid_mount),
            ObservationFailure::Parent(index) => take_io_error(&mut self.parents[index]),
            ObservationFailure::Source => take_io_error(&mut self.source),
            ObservationFailure::RootSource => take_io_error(&mut self.root_source),
            ObservationFailure::RootView => take_io_error(&mut self.root_view),
            ObservationFailure::RootMounted => take_native_error(&mut self.root_mounted),
            ObservationFailure::RootFilesystem => take_native_error(&mut self.root_filesystem),
            ObservationFailure::View => take_io_error(&mut self.view),
            ObservationFailure::Mounted => take_native_error(&mut self.mounted),
            ObservationFailure::MountParent => take_native_error(&mut self.mount_parent),
            ObservationFailure::Filesystem => take_native_error(&mut self.filesystem),
            ObservationFailure::MountinfoOpen => take_io_error(&mut self.mountinfo_file),
            ObservationFailure::MountinfoRead => take_io_error(&mut self.read),
        }
    }
}

impl Default for SignerMountReadbackAttemptV1 {
    fn default() -> Self {
        Self::new()
    }
}

fn read_mountinfo_bytes<R: io::Read>(file: R, contents: &mut String) -> io::Result<usize> {
    file.take(MOUNTINFO_READ_LIMIT as u64).read_to_string(contents)
}

fn io_failure<T>(result: &Option<io::Result<T>>) -> Option<&(dyn Error + 'static)> {
    result.as_ref().and_then(|result| result.as_ref().err())
        .map(|error| error as &dyn Error)
}

fn native_failure<T>(
    result: &Option<Result<T, rustix::io::Errno>>,
) -> Option<&(dyn Error + 'static)> {
    result.as_ref().and_then(|result| result.as_ref().err())
        .map(|error| error as &dyn Error)
}

fn take_io_error<T>(result: &mut Option<io::Result<T>>) -> io::Error {
    result.take().and_then(Result::err).unwrap_or_else(invalid_mount)
}

fn take_native_error<T>(result: &mut Option<Result<T, rustix::io::Errno>>) -> io::Error {
    result.take().and_then(Result::err)
        .map(io::Error::from).unwrap_or_else(invalid_mount)
}

/// Checks a read-only signer mount and its original source directory name.
///
/// Callers supply protected parent names in the order they must be observed.
/// The witness contains no descriptor, writer exclusion or role authority.
///
/// # Errors
/// Returns the original I/O error for failed observations, or a permission
/// error for unsafe ownership, modes, mount attributes or mountinfo.
pub fn require_signer_mount(
    view: &str,
    source: &str,
    signer_uid: u32,
    view_parent: &str,
    protected_parents: &[&str],
) -> io::Result<SignerMountWitness> {
    let mut readback = SignerMountReadbackAttemptV1::new();
    match observe_mount(
        &mut readback, view, SourceComparison::OriginalPath(source), signer_uid, view_parent, protected_parents,
        ObservationDisposition::Ordinary,
    ) {
        Ok(witness) => Ok(witness),
        Err(first) => Err(readback.into_io_error(first)),
    }
}

// The ordinary wrapper and retained attempt share this one observation engine.
// Disposition changes custody only. OriginalPath preserves the ordinary source
// observation; Prepared compares the fixed view to an independently held root
// identity without resolving its inaccessible original parent.
fn observe_mount(
    readback: &mut SignerMountReadbackAttemptV1,
    view: &str,
    source: SourceComparison<'_>,
    signer_uid: u32,
    view_parent: &str,
    protected_parents: &[&str],
    disposition: ObservationDisposition,
) -> Result<SignerMountWitness, ObservationFailure> {
    let root_view = matches!(source, SourceComparison::RootPrepared { .. });
    let signer_gid = if root_view { 0 } else { rustix::process::getegid().as_raw() };
    if !root_view && (signer_uid == 0 || signer_gid == 0) {
        return Err(readback.invalid());
    }

    for (position, &parent) in protected_parents.iter().enumerate() {
        let index = match disposition {
            ObservationDisposition::Ordinary => 0,
            ObservationDisposition::Retained => position,
        };
        readback.parents[index] = Some(fs::symlink_metadata(parent));
        let Some(Ok(metadata)) = readback.parents[index].as_ref() else {
            return Err(ObservationFailure::Parent(index));
        };
        if !metadata.file_type().is_dir() || metadata.uid() != 0 || metadata.mode() & 0o022 != 0 {
            return Err(readback.invalid());
        }
        if matches!(disposition, ObservationDisposition::Ordinary) {
            drop(readback.parents[index].take());
        }
    }

    let original_path = match source {
        SourceComparison::OriginalPath(path) => Some(path),
        SourceComparison::RootPrepared { target, .. } => Some(target.source_observation_path_v1()),
        _ => None,
    };
    let private_root_child = matches!(source, SourceComparison::RootPrepared { target, .. }
        if !target.source_metadata_is_reachable_v1());
    if private_root_child {
        readback.root_source = Some(fs::symlink_metadata(RootReadonlyViewV1::Controller.source_path_v1()));
        if readback.root_source.as_ref().is_none_or(Result::is_err) {
            return Err(ObservationFailure::RootSource);
        }
        readback.root_view = Some(fs::symlink_metadata(RootReadonlyViewV1::Controller.view_path_v1()));
        if readback.root_view.as_ref().is_none_or(Result::is_err) {
            return Err(ObservationFailure::RootView);
        }
    }
    if let Some(path) = original_path {
        readback.source = Some(fs::symlink_metadata(path));
        if readback.source.as_ref().is_none_or(Result::is_err) {
            return Err(ObservationFailure::Source);
        }
    }
    readback.view = Some(fs::symlink_metadata(view));
    let Some(Ok(mapped)) = readback.view.as_ref() else {
        return Err(ObservationFailure::View);
    };
    let (source_root, source_uid, source_gid, source_is_directory, source_mode) = match source {
        SourceComparison::OriginalPath(_) => {
            let Some(Ok(original)) = readback.source.as_ref() else {
                return Err(ObservationFailure::Source);
            };
            ((original.dev(), original.ino()), original.uid(), original.gid(),
                original.file_type().is_dir(), original.mode())
        }
        SourceComparison::Prepared { root, uid, gid, .. } => {
            (root, uid, gid, true, 0o700)
        }
        SourceComparison::RootPrepared { target, original_root, uid, gid } => {
            let root = original_root.unwrap_or((mapped.dev(), mapped.ino()));
            if target.source_metadata_is_reachable_v1() {
                let Some(Ok(original)) = readback.source.as_ref() else {
                    return Err(ObservationFailure::Source);
                };
                if original.uid() != uid || original.gid() != gid
                    || (original.dev(), original.ino()) != root {
                    return Err(readback.invalid());
                }
                (root, uid, gid, original.file_type().is_dir(), original.mode())
            } else {
                let (Some(Ok(original)), Some(Ok(parent)), Some(Ok(child))) =
                    (&readback.root_source, &readback.root_view, &readback.source) else {
                    return Err(readback.invalid());
                };
                if !original.file_type().is_dir() || original.uid() != uid || original.gid() != gid
                    || original.mode() & 0o7777 != 0o700
                    || !parent.file_type().is_dir() || parent.uid() != 0 || parent.gid() != 0
                    || parent.mode() & 0o7777 != 0o700
                    || (original.dev(), original.ino()) != (parent.dev(), parent.ino())
                    || !child.file_type().is_dir() || child.uid() != 0 || child.gid() != 0
                    || child.mode() & 0o7777 != 0o700 || (child.dev(), child.ino()) != root {
                    return Err(readback.invalid());
                }
                (root, uid, gid, true, child.mode())
            }
        }
    };
    if !source_is_directory
        || !mapped.file_type().is_dir()
        || source_uid == 0
        || source_uid == signer_uid
        || source_gid == 0
        || source_gid == signer_gid
        || source_mode & 0o7777 != 0o700
        || mapped.uid() != signer_uid
        || mapped.gid() != signer_gid
        || mapped.mode() & 0o7777 != 0o700
        || matches!(source, SourceComparison::Prepared { .. })
            && (source_root.0 == 0 || source_root.1 == 0)
        || source_root != (mapped.dev(), mapped.ino())
    {
        return Err(readback.invalid());
    }

    readback.mounted = Some(statx(
        CWD,
        view,
        AtFlags::SYMLINK_NOFOLLOW,
        StatxFlags::BASIC_STATS | StatxFlags::MNT_ID,
    ));
    if readback.mounted.as_ref().is_none_or(Result::is_err) {
        return Err(ObservationFailure::Mounted);
    }
    readback.mount_parent = Some(statx(
        CWD,
        view_parent,
        AtFlags::SYMLINK_NOFOLLOW,
        StatxFlags::BASIC_STATS | StatxFlags::MNT_ID,
    ));
    if readback.mount_parent.as_ref().is_none_or(Result::is_err) {
        return Err(ObservationFailure::MountParent);
    }
    readback.filesystem = Some(statvfs(view));
    let Some(Ok(filesystem)) = readback.filesystem.as_ref() else {
        return Err(ObservationFailure::Filesystem);
    };
    let Some(Ok(mounted)) = readback.mounted.as_ref() else {
        return Err(ObservationFailure::Mounted);
    };
    let Some(Ok(parent)) = readback.mount_parent.as_ref() else {
        return Err(ObservationFailure::MountParent);
    };
    if !readonly_mount_facts_v1(mounted, parent, filesystem) {
        return Err(readback.invalid());
    }
    if private_root_child {
        readback.root_mounted = Some(statx(CWD, RootReadonlyViewV1::Controller.view_path_v1(),
            AtFlags::SYMLINK_NOFOLLOW, StatxFlags::BASIC_STATS | StatxFlags::MNT_ID));
        if readback.root_mounted.as_ref().is_none_or(Result::is_err) {
            return Err(ObservationFailure::RootMounted);
        }
        readback.root_filesystem = Some(statvfs(RootReadonlyViewV1::Controller.view_path_v1()));
        let Some(Ok(root_filesystem)) = readback.root_filesystem.as_ref() else {
            return Err(ObservationFailure::RootFilesystem);
        };
        let Some(Ok(root_mounted)) = readback.root_mounted.as_ref() else {
            return Err(ObservationFailure::RootMounted);
        };
        if !readonly_mount_facts_v1(root_mounted, parent, root_filesystem) {
            return Err(readback.invalid());
        }
    }

    readback.mountinfo_file = Some(fs::File::open("/proc/self/mountinfo"));
    if readback.mountinfo_file.as_ref().is_none_or(Result::is_err) {
        return Err(ObservationFailure::MountinfoOpen);
    }
    readback.read_open_mountinfo(disposition)?;
    let Some(Ok(mounted)) = readback.mounted.as_ref() else {
        return Err(ObservationFailure::Mounted);
    };
    if readback.mountinfo.len() > MAXIMUM_MOUNTINFO_BYTES
        || !match source {
            SourceComparison::OriginalPath(_) => has_exact_mount(&readback.mountinfo, mounted.stx_mnt_id, view),
            SourceComparison::Prepared { source_path, .. } =>
                has_exact_prepared_source_mount_v1(&readback.mountinfo, mounted.stx_mnt_id,
                    (mounted.stx_dev_major, mounted.stx_dev_minor), view, source_path),
            SourceComparison::RootPrepared { target, .. } =>
                has_exact_prepared_source_mount_v1(&readback.mountinfo, mounted.stx_mnt_id,
                    (mounted.stx_dev_major, mounted.stx_dev_minor), view, target.source_path_v1()),
        }
    {
        return Err(readback.invalid());
    }

    if private_root_child {
        let Some(Ok(root_mounted)) = readback.root_mounted.as_ref() else {
            return Err(ObservationFailure::RootMounted);
        };
        if !has_exact_prepared_source_mount_v1(&readback.mountinfo, root_mounted.stx_mnt_id,
            (root_mounted.stx_dev_major, root_mounted.stx_dev_minor),
            RootReadonlyViewV1::Controller.view_path_v1(), RootReadonlyViewV1::Controller.source_path_v1()) {
            return Err(readback.invalid());
        }
    }
    let Some(Ok(mapped)) = readback.view.as_ref() else {
        return Err(ObservationFailure::View);
    };
    Ok(SignerMountWitness {
        mount_id: mounted.stx_mnt_id,
        device: mapped.dev(),
        inode: mapped.ino(),
        source_uid,
    })
}

// One predicate owns the existing readonly native mount facts for every role.
fn readonly_mount_facts_v1(mounted: &Statx, parent: &Statx, filesystem: &StatVfs) -> bool {
    let flags = filesystem.f_flag;
    let required = StatVfsMountFlags::RDONLY | StatVfsMountFlags::NOSUID
        | StatVfsMountFlags::NODEV | StatVfsMountFlags::NOEXEC;
    !(mounted.stx_mask & StatxFlags::MNT_ID.bits() == 0
        || parent.stx_mask & StatxFlags::MNT_ID.bits() == 0
        || mounted.stx_mnt_id == parent.stx_mnt_id
        || !mounted.stx_attributes_mask.contains(StatxAttributes::MOUNT_ROOT)
        || !mounted.stx_attributes.contains(StatxAttributes::MOUNT_ROOT)
        || !flags.contains(required))
}

fn has_exact_mount(mountinfo: &str, mount_id: u64, view: &str) -> bool {
    has_exact_mount_root(mountinfo, mount_id, view, None)
}

fn has_exact_mount_root(mountinfo: &str, mount_id: u64, view: &str, source: Option<&str>) -> bool {
    mountinfo
        .lines()
        .filter(|line| {
            let mut fields = line.split_whitespace();
            let id = fields.next().and_then(|value| value.parse::<u64>().ok());
            let _parent = fields.next();
            let _device = fields.next();
            let root = fields.next();
            let path = fields.next();
            let options = fields.next();
            id == Some(mount_id)
                && path == Some(view)
                && source.is_none_or(|source| root == Some(source))
                && options.is_some_and(|options| {
                    ["ro", "nosuid", "nodev", "noexec", "nosymfollow"]
                        .into_iter()
                        .all(|required| options.split(',').any(|option| option == required))
                })
        })
        .count()
        == 1
}

// A bind mount's root is relative to its source filesystem, not necessarily
// the process's absolute source pathname. The image-selected preparer supports
// exactly /var ext4 or /var/lib ZFS rooted at their filesystem root. Joining
// that same native mount's device/type/source to the mapped view avoids private
// Controller ancestry search and never accepts a basename-only substitution.
fn has_exact_prepared_source_mount_v1(
    mountinfo: &str,
    mount_id: u64,
    device: (u32, u32),
    view: &str,
    source: &str,
) -> bool {
    let mut matching_sources = 0usize;
    for original in mountinfo.lines() {
        let Some((prefix, filesystem)) = original.split_once(" - ") else { continue; };
        let mut fields = prefix.split_whitespace();
        let id = fields.next().and_then(|value| value.parse::<u64>().ok());
        let parent = fields.next().and_then(|value| value.parse::<u64>().ok());
        let original_device = fields.next();
        let root = fields.next();
        let path = fields.next();
        let mut filesystem = filesystem.split_whitespace();
        let kind = filesystem.next();
        let backing = filesystem.next();
        let base = match (path, kind) {
            (Some("/var"), Some("ext4")) => "/var",
            (Some("/var/lib"), Some("zfs")) => "/var/lib",
            _ => continue,
        };
        if id.is_none() || parent.is_none() || backing.is_none()
            || root != Some("/") || original_device.and_then(mount_device_v1) != Some(device) {
            continue;
        }
        let Some(relative) = source.strip_prefix(base).filter(|value| value.starts_with('/')) else {
            continue;
        };
        if !has_exact_mount_root(mountinfo, mount_id, view, Some(relative)) {
            continue;
        }
        let matching_views = mountinfo.lines().filter(|line| {
            let Some((prefix, filesystem)) = line.split_once(" - ") else { return false; };
            let mut fields = prefix.split_whitespace();
            let id = fields.next().and_then(|value| value.parse::<u64>().ok());
            let _parent = fields.next();
            let actual_device = fields.next().and_then(mount_device_v1);
            let mut filesystem = filesystem.split_whitespace();
            id == Some(mount_id) && actual_device == Some(device)
                && filesystem.next() == kind && filesystem.next() == backing
        }).count();
        if matching_views == 1 { matching_sources += 1; }
    }
    matching_sources == 1
}

fn mount_device_v1(value: &str) -> Option<(u32, u32)> {
    let (major, minor) = value.split_once(':')?;
    Some((major.parse().ok()?, minor.parse().ok()?))
}

fn invalid_mount() -> io::Error {
    io::Error::new(io::ErrorKind::PermissionDenied, "unsafe signer view")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn signer_mount_requires_one_exact_read_only_name() {
        let view = "/run/aos/sandbox-cache-signer-objects";
        let valid =
            format!("42 1 0:2 / {view} ro,nosuid,nodev,noexec,nosymfollow - ext4 /dev/test rw");
        assert!(has_exact_mount(&valid, 42, view));
        assert!(!has_exact_mount(&valid, 43, view));
        assert!(!has_exact_mount(
            &valid.replace("nosymfollow", "symfollow"),
            42,
            view
        ));
        assert!(!has_exact_mount(&format!("{valid}\n{valid}"), 42, view));
    }

    #[test]
    fn opened_inode_must_match_mount_witness() {
        let mount = SignerMountWitness {
            mount_id: 42,
            device: 7,
            inode: 11,
            source_uid: 811,
        };

        assert!(mount.matches_opened_root(7, 11));
        assert!(!mount.matches_opened_root(7, 12));
        assert!(!mount.matches_opened_root(8, 11));
    }
}

#[cfg(test)]
mod retained_readback_tests {
    use super::*;
    use std::io::{Seek as _, Write as _};
    use std::os::fd::AsRawFd as _;

    fn readable_file(bytes: &[u8]) -> fs::File {
        let descriptor = rustix::fs::memfd_create(
            c"signer-mount-readback-test",
            rustix::fs::MemfdFlags::CLOEXEC,
        ).expect("fixture memfd");
        let mut file = fs::File::from(descriptor);
        file.write_all(bytes).expect("fixture contents");
        file.rewind().expect("fixture rewind");
        file
    }

    #[test]
    fn retained_utf8_failure_keeps_actual_file_error_and_buffer_capacity() {
        // Only the private byte reader is exercised, never a mount witness.
        let file = readable_file(b"valid-prefix\n\xff");
        let descriptor = file.as_raw_fd();
        let mut attempt = SignerMountReadbackAttemptV1::new();
        attempt.mountinfo_file = Some(Ok(file));
        let result = attempt.read_open_mountinfo(ObservationDisposition::Retained);

        assert!(matches!(result, Err(ObservationFailure::MountinfoRead)));
        let Some(Err(error)) = &attempt.read else {
            panic!("missing read failure");
        };
        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
        assert!(attempt.mountinfo.capacity() >= b"valid-prefix\n\xff".len());
        let retained_file = attempt.mountinfo_file.as_ref().unwrap().as_ref().unwrap();
        assert_eq!(retained_file.as_raw_fd(), descriptor);
    }

    #[test]
    fn retained_reader_stops_at_existing_plus_one_limit_without_cloning_the_file() {
        let bytes = vec![b'x'; MOUNTINFO_READ_LIMIT + 4096];
        let file = readable_file(&bytes);
        let descriptor = file.as_raw_fd();
        let mut attempt = SignerMountReadbackAttemptV1::new();
        attempt.mountinfo_file = Some(Ok(file));

        assert!(attempt.read_open_mountinfo(ObservationDisposition::Retained).is_ok());
        assert_eq!(attempt.mountinfo.len(), MOUNTINFO_READ_LIMIT);
        let file = attempt.mountinfo_file.as_mut().unwrap().as_mut().unwrap();
        assert_eq!(file.as_raw_fd(), descriptor);
        assert_eq!(file.stream_position().unwrap(), MOUNTINFO_READ_LIMIT as u64);
    }

    #[test]
    fn ordinary_reader_consumes_its_file_while_selected_reentry_keeps_first_error() {
        let mut ordinary = SignerMountReadbackAttemptV1::new();
        ordinary.mountinfo_file = Some(Ok(readable_file(b"contents\n")));
        assert!(ordinary.read_open_mountinfo(ObservationDisposition::Ordinary).is_ok());
        assert!(ordinary.mountinfo_file.is_none());

        let mut selected = SignerMountReadbackAttemptV1::new();
        assert!(selected.observe_once("unused", "unused", 0, "unused", &[]).is_err());
        let first = selected.failure().unwrap().downcast_ref::<io::Error>().unwrap();
        let first_pointer = std::ptr::from_ref(first);
        assert!(selected.observe_once("different", "different", 1, "different", &[]).is_err());
        let retained = selected.failure().unwrap().downcast_ref::<io::Error>().unwrap();
        assert_eq!(std::ptr::from_ref(retained), first_pointer);
        assert!(selected.witness().is_none());
    }
}

#[cfg(test)]
mod prepared_view_tests {
    use super::*;

    #[test]
    fn prepared_mount_requires_exact_compiled_source_root() {
        let view = "/run/aos/sandbox-cache-signer-controller-journal";
        let root = "/var/lib/aos/sandboxd/cache-residency-authority";
        let valid = format!(
            "42 1 0:2 {root} {view} ro,nosuid,nodev,noexec,nosymfollow - ext4 /dev/test rw"
        );

        assert!(has_exact_mount_root(&valid, 42, view, Some(root)));
        assert!(!has_exact_mount_root(
            &valid.replace(root, "/var/lib/aos/sandboxd/other"),
            42, view, Some(root),
        ));
        // Existing observations do not invent the new source-root restriction.
        assert!(has_exact_mount(&valid.replace(root, "/"), 42, view));
        assert!(!has_exact_mount_root(
            &valid.replace("nosymfollow", "symfollow"), 42, view, Some(root),
        ));
        assert!(!has_exact_mount_root(
            &format!("{valid}\n{valid}"), 42, view, Some(root),
        ));
    }

    #[test]
    fn prepared_refusal_preserves_first_error_without_source_search() {
        let mut attempt = SignerMountReadbackAttemptV1::new();

        assert!(attempt.observe_prepared_cache_bootstrap_once(0, (1, 2), 3, 4).is_err());
        let first = attempt.failure().expect("actual invalid-identity error")
            as *const dyn Error as *const ();
        assert!(attempt.observe_prepared_cache_bootstrap_once(9, (1, 2), 3, 4).is_err());

        assert_eq!(attempt.failure().expect("same retained error")
            as *const dyn Error as *const (), first);
        assert!(attempt.source.is_none());
        assert!(attempt.view.is_none());
        assert!(attempt.mountinfo_file.is_none());
        assert!(attempt.witness().is_none());
        assert!(attempt.prepared_witness().is_none());
    }
    #[test]
    fn fixed_root_views_bind_distinct_targets_to_exact_writer_roots() {
        let targets = [RootReadonlyViewV1::Controller, RootReadonlyViewV1::StorageSession,
            RootReadonlyViewV1::HostSession, RootReadonlyViewV1::MountSession,
            RootReadonlyViewV1::NetworkSession,
            RootReadonlyViewV1::Source, RootReadonlyViewV1::CacheBootstrap,
            RootReadonlyViewV1::CacheJournals, RootReadonlyViewV1::CacheObjects];
        let mut views = std::collections::BTreeSet::new();
        for target in targets {
            assert!(views.insert(target.view_path_v1()));
            let line = format!("42 17 0:9 {} {} ro,nosuid,nodev,noexec,nosymfollow - ext4 /dev/root ro\n",
                target.source_path_v1(), target.view_path_v1());
            assert!(has_exact_mount_root(&line, 42, target.view_path_v1(), Some(target.source_path_v1())));
            assert!(!has_exact_mount_root(&line, 42, target.view_path_v1(), Some("/var/lib/aos/wrong")));
        }
        assert!(!RootReadonlyViewV1::StorageSession.source_metadata_is_reachable_v1());
        assert!(!RootReadonlyViewV1::HostSession.source_metadata_is_reachable_v1());
        assert!(!RootReadonlyViewV1::MountSession.source_metadata_is_reachable_v1());
        assert!(!RootReadonlyViewV1::NetworkSession.source_metadata_is_reachable_v1());
        assert!(!RootReadonlyViewV1::CacheBootstrap.source_metadata_is_reachable_v1());
    }

    #[test]
    fn prepared_views_join_the_real_ext4_and_zfs_source_mounts() {
        for target in [
            RootReadonlyViewV1::StorageSession,
            RootReadonlyViewV1::HostSession,
            RootReadonlyViewV1::MountSession,
            RootReadonlyViewV1::NetworkSession,
        ] {
            let view = target.view_path_v1();
            for (base, kind, backing) in [
                ("/var", "ext4", "/dev/vdb"),
                ("/var/lib", "zfs", "tank/var/lib"),
            ] {
                let relative = target.source_path_v1().strip_prefix(base)
                    .expect("fixed source below mount");
                let original = format!("17 1 0:9 / {base} rw,nosuid,nodev - {kind} {backing} rw");
                let mapped = format!("42 5 0:9 {relative} {view} ro,nosuid,nodev,noexec,nosymfollow - {kind} {backing} rw");
                let both = format!("{original}\n{mapped}");

                assert!(has_exact_prepared_source_mount_v1(
                    &both, 42, (0, 9), view, target.source_path_v1()));
                assert!(!has_exact_prepared_source_mount_v1(
                    &both, 42, (0, 8), view, target.source_path_v1()));
                assert!(!has_exact_prepared_source_mount_v1(
                    &both.replace(relative, "/other"), 42, (0, 9), view, target.source_path_v1()));
                assert!(!has_exact_prepared_source_mount_v1(
                    &format!("{both}\n{original}"), 42, (0, 9), view, target.source_path_v1()));
                assert!(!has_exact_prepared_source_mount_v1(
                    &mapped, 42, (0, 9), view, target.source_path_v1()));
            }
        }
    }

}
