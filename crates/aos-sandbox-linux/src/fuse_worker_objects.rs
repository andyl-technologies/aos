//! Owner-created, labelled kernel objects for the fixed filesystem worker.
//!
//! The fixed Mount process creates these objects before launch. This module
//! owns no Controller authorization, Root policy claim, current attachment or
//! lease. Its objects cannot be converted into consumer authority from labels,
//! inode numbers, a sealed plan, or a historical journal record.

use std::ffi::CString;
use std::fs::File;
use std::io::{Read as _, Write as _};
use std::os::fd::{AsFd as _, BorrowedFd, OwnedFd};

use rustix::fs::{FileType, Mode, OFlags};

use crate::fuse_mount::FreshDetachedFuseMountV1;
use crate::immutable_file::{ImmutableFileError, SealedReadOnlyCredential};
use crate::inventory::MountId;
use crate::mount::MountAttributes;
use crate::pidfd::{NamespaceFd, NamespaceIdentity, NamespaceKind};
use crate::seqpacket::{SeqpacketError, SeqpacketSocket};
use crate::uapi::{self, OpenHow, RESOLVE_BENEATH, RESOLVE_NO_MAGICLINKS, RESOLVE_NO_SYMLINKS};
use crate::{Error, Result};

/// Names the sole enforcing worker process context.
pub const FUSE_WORKER_CONTEXT_V1: &str = "system_u:system_r:aos_filesystem_fuse_worker_t";
/// Names the fixed worker executable object's label.
pub const FUSE_WORKER_EXECUTABLE_CONTEXT_V1: &str =
    "system_u:object_r:aos_filesystem_fuse_worker_exec_t";
/// Names the anonymous, fully sealed launch-plan object's label.
pub const FUSE_WORKER_PLAN_CONTEXT_V1: &str = "system_u:object_r:aos_filesystem_fuse_worker_plan_t";
/// Names both original endpoints of the Mount-created private channel.
pub const FUSE_WORKER_CHANNEL_CONTEXT_V1: &str =
    "system_u:object_r:aos_filesystem_fuse_worker_channel_t";
/// Names the unlinked cancellation FIFO object.
pub const FUSE_WORKER_CANCEL_CONTEXT_V1: &str =
    "system_u:object_r:aos_filesystem_fuse_worker_cancel_t";
/// Names the actual fixed kernel FUSE device object's label.
pub const FUSE_WORKER_DEVICE_CONTEXT_V1: &str = "system_u:object_r:fuse_device_t";

const MOUNT_CONTEXT: &str = "system_u:system_r:init_t";
const MOUNT_CGROUP: &str = "0::/aos.slice/aos-control.slice/aos-sandbox-mountd.service\n";
const RUNTIME_ROOT: &str = "run/aos/sandbox-mount-catalog";
const SOCKCREATE_ATTRIBUTE: &str = "/proc/thread-self/attr/sockcreate";
const MAXIMUM_CONTEXT_BYTES: usize = 256;

/// Reports fixed worker kernel-object creation and readback failure.
#[derive(Debug, thiserror::Error)]
pub enum FuseWorkerObjectError {
    /// A kernel operation or fixed object invariant failed.
    #[error("fixed worker object failed: {0}")]
    Kernel(#[from] Error),
    /// The original plan could not be fully sealed and retained.
    #[error("fixed worker plan failed: {0}")]
    Plan(#[from] ImmutableFileError),
    /// The actual private channel could not be created or inspected.
    #[error("fixed worker channel failed: {0}")]
    Channel(#[from] SeqpacketError),
}

/// Retains the actual fresh detached mount, plan, channel and cancellation ends.
///
/// There is no incoming-descriptor constructor. These are nonauthorizing
/// preparation objects; the real held Mount dispatch must separately retain
/// its original request, reservation, namespace and worker. Device metadata
/// cannot reconstruct the connection: this owner retains the original OFD
/// opened internally and actually used for detached mount creation.
pub struct MountCreatedFuseWorkerObjectsV1 {
    fuse: FreshDetachedFuseMountV1,
    user_namespace: NamespaceFd,
    plan: SealedReadOnlyCredential,
    channel: SeqpacketSocket,
    worker_channel: Option<OwnedFd>,
    cancellation_reader: OwnedFd,
    cancellation_writer: OwnedFd,
    idmap: OriginalWorkerIdmap,
}

// A local record of the real kernel effect, never a decoded/read authority.
// Only a successful operation on this owner's original objects sets Applied.
enum OriginalWorkerIdmap {
    Pending,
    Ambiguous,
    Applied {
        mount: MountId,
        namespace: NamespaceIdentity,
    },
}

impl OriginalWorkerIdmap {
    fn begin(&mut self) -> Result<()> {
        if !matches!(self, Self::Pending) {
            return Err(Error::invalid(
                "worker idmap",
                "original attempt is not reusable",
            ));
        }
        *self = Self::Ambiguous;
        Ok(())
    }
}

impl MountCreatedFuseWorkerObjectsV1 {
    /// Creates the closed objects inside the existing fixed Mount process.
    ///
    /// The worker-instance locator must already be durably reserved before
    /// this operation. A crash can leave its fixed FIFO name behind; a later
    /// attempt refuses that name until protected recovery reconciles it. This
    /// method never removes a pre-existing object or reconstructs live custody.
    /// The original user namespace is retained without applying its idmap:
    /// pinned FUSE refuses idmapping until INIT accepts FUSE_ALLOW_IDMAP and
    /// default permissions. Genuine guarded initialization and idmap completion
    /// remain mandatory before attachment or positive readiness.
    ///
    /// # Errors
    ///
    /// Returns an error for another producer, unsupported labels, an occupied
    /// cancellation name, unsafe runtime ancestry, incomplete sealing, or any
    /// kernel-object creation/readback failure. A context-reset failure aborts
    /// the producer instead of returning it with altered creation context.
    pub fn create(
        worker_instance: [u8; 16],
        plan: &[u8],
        user_namespace: &NamespaceFd,
    ) -> std::result::Result<Self, FuseWorkerObjectError> {
        require_fixed_mount_process()?;
        if worker_instance == [0; 16] {
            return Err(Error::invalid("worker instance", "zero is reserved").into());
        }
        if user_namespace.kind() != NamespaceKind::User {
            return Err(Error::invalid("worker user namespace", "not a user namespace").into());
        }
        let namespace_copy = user_namespace
            .as_fd()
            .try_clone_to_owned()
            .map_err(|source| Error::Syscall {
                operation: "retain original worker user namespace",
                source,
            })?;
        let retained_namespace = NamespaceFd::from_owned(namespace_copy, NamespaceKind::User)?;
        if retained_namespace.identity() != user_namespace.identity() {
            return Err(
                Error::invalid("worker user namespace", "original identity changed").into(),
            );
        }
        let fuse = FreshDetachedFuseMountV1::open_fixed_worker_read_only()?;
        let plan = SealedReadOnlyCredential::create_fuse_worker_plan(plan)?;
        require_object_context(plan.as_fd(), FUSE_WORKER_PLAN_CONTEXT_V1)?;
        let (channel, worker_channel) = create_private_channel()?;
        let (cancellation_reader, cancellation_writer) = create_cancellation(worker_instance)?;
        require_fixed_mount_process()?;
        Ok(Self {
            fuse,
            user_namespace: retained_namespace,
            plan,
            channel,
            worker_channel: Some(worker_channel),
            cancellation_reader,
            cancellation_writer,
            idmap: OriginalWorkerIdmap::Pending,
        })
    }

    /// Borrows the original fresh FUSE OFD and its retained detached mount.
    ///
    /// The fixed profile is read-only, no-exec, no-suid and no-dev. This borrow
    /// supplies no permission to attach the mount, consume FUSE requests or
    /// send backing without the genuine held Controller/Root/Mount join.
    /// Creation applies no idmap. Successful guarded INIT and applying the
    /// exact retained namespace idmap must both complete before publication.
    pub fn fuse(&self) -> &FreshDetachedFuseMountV1 {
        &self.fuse
    }

    /// Borrows the original structural namespace retained for later idmapping.
    ///
    /// This does not prove a current assignment or permit skipping negotiated
    /// INIT, idmap completion, or the genuine held owners before publication.
    pub fn user_namespace(&self) -> &NamespaceFd {
        &self.user_namespace
    }

    /// Applies the required idmap to the same original detached FUSE mount.
    ///
    /// The kernel refuses this operation until genuine INIT selects ALLOW_IDMAP
    /// with default permissions. It consumes only the internally retained
    /// original user namespace, never a received initialized FUSE connection
    /// or a caller's namespace/INIT assertion. Success records the real kernel
    /// effect while both original objects remain held; it is not a detached
    /// statmount readback, Host/worker proof, readiness, or a Root read grant.
    ///
    /// # Errors
    ///
    /// Rejects another producer, a repeated/ambiguous attempt, changed original
    /// object/namespace, absent INIT support, or a kernel/access failure. Failed
    /// attempts remain fenced; the genuine Mount owner must retain its durable
    /// reservation and reconciliation obligation rather than reissue objects.
    pub fn apply_original_user_namespace_idmap(&mut self) -> Result<()> {
        self.idmap.begin()?;
        require_fixed_mount_process()?;
        self.require_original_user_namespace()?;
        require_object_context(self.fuse.device(), FUSE_WORKER_DEVICE_CONTEXT_V1)?;
        let original_mount = self.fuse.mount_id();
        if MountId::from_fd(self.fuse.mount().as_fd())? != original_mount {
            return Err(Error::invalid("worker idmap", "original mount changed"));
        }

        self.fuse.mount().set_attributes(
            false,
            fixed_worker_mount_attributes(),
            Some(&self.user_namespace),
        )?;
        if MountId::from_fd(self.fuse.mount().as_fd())? != original_mount {
            return Err(Error::invalid("worker idmap", "original mount changed"));
        }
        self.require_original_user_namespace()?;
        require_object_context(self.fuse.device(), FUSE_WORKER_DEVICE_CONTEXT_V1)?;
        require_fixed_mount_process()?;
        self.idmap = OriginalWorkerIdmap::Applied {
            mount: original_mount,
            namespace: self.user_namespace.identity(),
        };
        Ok(())
    }

    /// Rechecks original idmap-effect custody and reapplies secure mount flags.
    ///
    /// The same mount cannot have its idmap replaced by mount_setattr; pinned
    /// Linux permits replacement only on an OPEN_TREE_CLONE copy, which has a
    /// different mount ID. This checks retained effect custody, not statmount
    /// readback or remote authority. Metadata/backing still requires genuine
    /// current Host/worker and held Root/Mount owner joins.
    ///
    /// # Errors
    ///
    /// Rejects incomplete/ambiguous effect custody, changed original mount or
    /// namespace, another producer, or failed fixed secure attributes.
    pub fn recheck_original_user_namespace_idmap_custody(&self) -> Result<()> {
        let OriginalWorkerIdmap::Applied { mount, namespace } = &self.idmap else {
            return Err(Error::invalid(
                "worker idmap",
                "original effect is incomplete",
            ));
        };
        require_fixed_mount_process()?;
        self.require_original_user_namespace()?;
        if self.user_namespace.identity() != *namespace
            || self.fuse.mount_id() != *mount
            || MountId::from_fd(self.fuse.mount().as_fd())? != *mount
        {
            return Err(Error::invalid(
                "worker idmap",
                "original effect custody changed",
            ));
        }
        // Do not apply IDMAP a second time. The actual kernel reconfiguration
        // restores only fixed secure flags on the same retained original mount.
        self.fuse
            .mount()
            .set_attributes(false, fixed_worker_mount_attributes(), None)?;
        if MountId::from_fd(self.fuse.mount().as_fd())? != *mount {
            return Err(Error::invalid("worker idmap", "original mount changed"));
        }
        self.require_original_user_namespace()?;
        require_object_context(self.fuse.device(), FUSE_WORKER_DEVICE_CONTEXT_V1)?;
        require_fixed_mount_process()
    }

    fn require_original_user_namespace(&self) -> Result<()> {
        let duplicate = self
            .user_namespace
            .as_fd()
            .try_clone_to_owned()
            .map_err(|source| Error::Syscall {
                operation: "recheck original worker user namespace",
                source,
            })?;
        let observed = NamespaceFd::from_owned(duplicate, NamespaceKind::User)?;
        if observed.identity() != self.user_namespace.identity() {
            return Err(Error::invalid("worker idmap", "original namespace changed"));
        }
        Ok(())
    }

    /// Borrows the exact sealed original launch plan.
    pub fn plan(&self) -> BorrowedFd<'_> {
        self.plan.as_fd()
    }

    /// Borrows the private worker endpoint before its one-shot handoff.
    pub fn worker_channel(&self) -> Option<BorrowedFd<'_>> {
        self.worker_channel
            .as_ref()
            .map(|descriptor| descriptor.as_fd())
    }

    /// Takes the sole original worker endpoint into the fixed four-role table.
    ///
    /// The plan, fresh FUSE OFD and cancellation reader are duplicated from
    /// this actual producer; the channel endpoint is moved, not duplicated.
    /// The retained cancellation writer never enters the table. Taking the
    /// endpoint precedes every fallible inspection/duplication, so failure
    /// cannot make this object's launch table available a second time.
    ///
    /// This is descriptor custody, not Host admission or a copy-close proof.
    /// The sender must retain its owning Mount borrow, and account for every
    /// outgoing packet/transport copy before any fresh worker challenge. Local
    /// callers can still duplicate borrowed descriptors; this method cannot
    /// establish their absence or infer live worker authority.
    ///
    /// # Errors
    ///
    /// Rejects another producer, a taken/closed endpoint, changed object labels,
    /// or failed duplication. The original detached mount and namespace remain
    /// retained, but the endpoint cannot be reissued after an error.
    pub fn take_original_worker_launch_roles(&mut self) -> Result<[OwnedFd; 4]> {
        let endpoint = self.worker_channel.take().ok_or_else(|| {
            Error::invalid("worker launch roles", "original endpoint already consumed")
        })?;
        require_fixed_mount_process()?;
        require_object_context(self.plan.as_fd(), FUSE_WORKER_PLAN_CONTEXT_V1)?;
        require_object_context(self.fuse.device(), FUSE_WORKER_DEVICE_CONTEXT_V1)?;
        require_object_context(endpoint.as_fd(), FUSE_WORKER_CHANNEL_CONTEXT_V1)?;
        require_object_context(
            self.cancellation_reader.as_fd(),
            FUSE_WORKER_CANCEL_CONTEXT_V1,
        )?;

        let duplicate = |descriptor: BorrowedFd<'_>| {
            descriptor
                .try_clone_to_owned()
                .map_err(|source| Error::Syscall {
                    operation: "retain original worker launch role",
                    source,
                })
        };
        let roles = [
            duplicate(self.plan.as_fd())?,
            duplicate(self.fuse.device())?,
            endpoint,
            duplicate(self.cancellation_reader.as_fd())?,
        ];
        require_fixed_mount_process()?;
        Ok(roles)
    }

    /// Closes Mount's worker-end copy after the exact Host handoff barrier.
    ///
    /// The enclosing dispatch must also drop its consumed receive message and
    /// transport copies before permitting HELLO. Repeated calls are harmless.
    pub fn close_worker_channel_copy(&mut self) {
        self.worker_channel.take();
    }

    /// Borrows Mount's original private receive/send endpoint.
    pub fn channel(&self) -> &SeqpacketSocket {
        &self.channel
    }

    /// Mutably borrows only Mount's original preparation endpoint.
    ///
    /// This is not a copy-closure assertion or a consumer grant. Trusted
    /// callers must retain the owning Mount writer, exclude competing I/O and
    /// separately join the actual Host continuation and record subject.
    #[doc(hidden)]
    pub fn channel_mut(&mut self) -> &mut SeqpacketSocket {
        &mut self.channel
    }

    /// Borrows the cancellation reader; no writer travels in the launch table.
    pub fn cancellation_reader(&self) -> BorrowedFd<'_> {
        self.cancellation_reader.as_fd()
    }

    /// Signals cancellation without exposing or duplicating the retained writer.
    ///
    /// # Errors
    ///
    /// Returns an error when the nonblocking reader is gone or the one-byte
    /// cancellation signal cannot be published. Dropping this owner also
    /// closes the sole writer, so owner loss is observable as EOF.
    pub fn cancel(&self) -> Result<()> {
        let written = rustix::io::write(&self.cancellation_writer, &[1])
            .map_err(|source| kernel_error("signal original worker cancellation", source))?;
        if written != 1 {
            return Err(Error::invalid(
                "worker cancellation",
                "short cancellation write",
            ));
        }
        Ok(())
    }
}

fn fixed_worker_mount_attributes() -> MountAttributes {
    MountAttributes::secure_read_only()
        .with_no_exec(true)
        .with_no_atime(true)
}

pub(crate) fn require_object_context(fd: BorrowedFd<'_>, expected: &str) -> Result<()> {
    let mut context = [0; MAXIMUM_CONTEXT_BYTES];
    let length = rustix::fs::fgetxattr(fd, "security.selinux", &mut context)
        .map_err(|source| kernel_error("read worker object SID", source))?;
    if !context_matches(&context[..length], expected.as_bytes()) {
        return Err(Error::invalid("worker object SID", "unexpected label"));
    }
    Ok(())
}

pub(crate) fn context_matches(observed: &[u8], expected: &[u8]) -> bool {
    observed == expected
        || (observed.len() == expected.len() + 1
            && observed.starts_with(expected)
            && observed.last() == Some(&0))
}

fn require_fixed_mount_process() -> Result<()> {
    if rustix::process::geteuid().as_raw() != 0
        || read_bounded("/proc/self/cgroup", 4096)? != MOUNT_CGROUP.as_bytes()
        || !context_matches(
            &read_bounded("/proc/self/attr/current", MAXIMUM_CONTEXT_BYTES)?,
            MOUNT_CONTEXT.as_bytes(),
        )
    {
        return Err(Error::invalid(
            "worker object producer",
            "not the fixed Mount process",
        ));
    }
    Ok(())
}

fn create_private_channel() -> std::result::Result<(SeqpacketSocket, OwnedFd), FuseWorkerObjectError>
{
    crate::startup_fd_table::with_blocked_signals(|| {
        if !read_bounded(SOCKCREATE_ATTRIBUTE, MAXIMUM_CONTEXT_BYTES)?.is_empty() {
            return Err(Error::invalid(
                "worker channel creation",
                "prior socket context is not empty",
            )
            .into());
        }
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            write_context(FUSE_WORKER_CHANNEL_CONTEXT_V1.as_bytes())?;
            if !context_matches(
                &read_bounded(SOCKCREATE_ATTRIBUTE, MAXIMUM_CONTEXT_BYTES)?,
                FUSE_WORKER_CHANNEL_CONTEXT_V1.as_bytes(),
            ) {
                return Err(
                    Error::invalid("worker channel creation", "creation context changed").into(),
                );
            }
            let pair = SeqpacketSocket::pair_with_record_subjects()?;
            require_object_context(pair.0.as_fd()?, FUSE_WORKER_CHANNEL_CONTEXT_V1)?;
            require_object_context(pair.1.as_fd(), FUSE_WORKER_CHANNEL_CONTEXT_V1)?;
            Ok(pair)
        }));
        // This is synchronous and contains no await, fork, thread spawn or
        // logging. Never resume the owner if exact context restoration fails.
        if write_context(&[0]).is_err()
            || !read_bounded(SOCKCREATE_ATTRIBUTE, MAXIMUM_CONTEXT_BYTES)
                .is_ok_and(|value| value.is_empty())
        {
            std::process::abort();
        }
        match result {
            Ok(result) => result,
            Err(panic) => std::panic::resume_unwind(panic),
        }
    })
}

fn write_context(context: &[u8]) -> Result<()> {
    let mut attribute = File::options()
        .write(true)
        .open(SOCKCREATE_ATTRIBUTE)
        .map_err(|source| Error::Syscall {
            operation: "open worker socket creation context",
            source,
        })?;
    attribute
        .write_all(context)
        .map_err(|source| Error::Syscall {
            operation: "set worker socket creation context",
            source,
        })
}

fn open_cancellation_directory() -> Result<OwnedFd> {
    let mut directory = rustix::fs::open(
        "/",
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(|source| kernel_error("open worker cancellation path root", source))?;
    for component in RUNTIME_ROOT.split('/') {
        let ancestor = rustix::fs::fstat(&directory)
            .map_err(|source| kernel_error("inspect cancellation path ancestry", source))?;
        if ancestor.st_uid != 0 || ancestor.st_gid != 0 || ancestor.st_mode & 0o022 != 0 {
            return Err(Error::invalid(
                "worker runtime ancestry",
                "mutable or foreign owner",
            ));
        }
        let component = CString::new(component)
            .map_err(|_| Error::invalid("worker runtime path", "contains NUL"))?;
        directory = uapi::openat2(
            directory.as_fd(),
            &component,
            &OpenHow {
                flags: (libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC | libc::O_NOFOLLOW)
                    as u64,
                mode: 0,
                resolve: RESOLVE_BENEATH | RESOLVE_NO_MAGICLINKS | RESOLVE_NO_SYMLINKS,
            },
        )?;
    }
    let directory_stat = rustix::fs::fstat(&directory)
        .map_err(|source| kernel_error("inspect worker cancellation directory", source))?;
    if directory_stat.st_uid != 0
        || directory_stat.st_gid != 0
        || directory_stat.st_mode & 0o7777 != 0o700
        || uapi::filesystem_type(directory.as_fd())? != 0x0102_1994
    {
        return Err(Error::invalid(
            "worker cancellation directory",
            "not protected root-owned 0700 runtime tmpfs",
        ));
    }
    Ok(directory)
}

fn create_cancellation(instance: [u8; 16]) -> Result<(OwnedFd, OwnedFd)> {
    let directory = open_cancellation_directory()?;
    let directory_stat = rustix::fs::fstat(&directory)
        .map_err(|source| kernel_error("inspect cancellation directory identity", source))?;
    let mut name = String::from(".aos-fuse-cancel-");
    for byte in instance {
        use std::fmt::Write as _;
        write!(&mut name, "{byte:02x}")
            .map_err(|_| Error::invalid("worker cancellation name", "encoding failed"))?;
    }
    rustix::fs::mknodat(
        &directory,
        name.as_str(),
        FileType::Fifo,
        Mode::RUSR | Mode::WUSR,
        0,
    )
    .map_err(|source| kernel_error("create original worker cancellation FIFO", source))?;
    let reader = rustix::fs::openat(
        &directory,
        name.as_str(),
        OFlags::RDONLY | OFlags::NONBLOCK | OFlags::CLOEXEC | OFlags::NOFOLLOW,
        Mode::empty(),
    )
    .map_err(|source| kernel_error("open original cancellation reader", source))?;
    rustix::fs::fsetxattr(
        &reader,
        "security.selinux",
        FUSE_WORKER_CANCEL_CONTEXT_V1.as_bytes(),
        rustix::fs::XattrFlags::empty(),
    )
    .map_err(|source| kernel_error("label original cancellation FIFO", source))?;
    let writer = rustix::fs::openat(
        &directory,
        name.as_str(),
        OFlags::WRONLY | OFlags::NONBLOCK | OFlags::CLOEXEC | OFlags::NOFOLLOW,
        Mode::empty(),
    )
    .map_err(|source| kernel_error("open original cancellation writer", source))?;
    let first = rustix::fs::fstat(&reader)
        .map_err(|source| kernel_error("inspect cancellation reader", source))?;
    let second = rustix::fs::fstat(&writer)
        .map_err(|source| kernel_error("inspect cancellation writer", source))?;
    if first.st_dev != second.st_dev
        || first.st_ino != second.st_ino
        || first.st_uid != 0
        || first.st_gid != 0
        || first.st_mode & 0o7777 != 0o600
        || FileType::from_raw_mode(first.st_mode) != FileType::Fifo
    {
        return Err(Error::invalid(
            "worker cancellation FIFO",
            "original inode or owner changed",
        ));
    }
    require_object_context(reader.as_fd(), FUSE_WORKER_CANCEL_CONTEXT_V1)?;
    require_object_context(writer.as_fd(), FUSE_WORKER_CANCEL_CONTEXT_V1)?;
    let named = rustix::fs::statat(
        &directory,
        name.as_str(),
        rustix::fs::AtFlags::SYMLINK_NOFOLLOW,
    )
    .map_err(|source| kernel_error("read back original cancellation name", source))?;
    if named.st_dev != first.st_dev || named.st_ino != first.st_ino {
        return Err(Error::invalid(
            "worker cancellation FIFO",
            "name no longer identifies original inode",
        ));
    }
    rustix::fs::unlinkat(&directory, name.as_str(), rustix::fs::AtFlags::empty())
        .map_err(|source| kernel_error("unlink original cancellation FIFO", source))?;
    if rustix::fs::fstat(&reader)
        .map_err(|source| kernel_error("verify unlinked cancellation FIFO", source))?
        .st_nlink
        != 0
    {
        return Err(Error::invalid(
            "worker cancellation FIFO",
            "name survived unlink",
        ));
    }
    let current_directory = open_cancellation_directory()?;
    let current_stat = rustix::fs::fstat(&current_directory)
        .map_err(|source| kernel_error("recheck cancellation directory identity", source))?;
    if current_stat.st_dev != directory_stat.st_dev || current_stat.st_ino != directory_stat.st_ino
    {
        return Err(Error::invalid(
            "worker cancellation directory",
            "fixed runtime name changed during creation",
        ));
    }
    Ok((reader, writer))
}

fn read_bounded(path: &str, maximum: usize) -> Result<Vec<u8>> {
    let file = File::open(path).map_err(|source| Error::Syscall {
        operation: "open fixed worker process attribute",
        source,
    })?;
    let mut bytes = Vec::new();
    file.take((maximum + 1) as u64)
        .read_to_end(&mut bytes)
        .map_err(|source| Error::Syscall {
            operation: "read fixed worker process attribute",
            source,
        })?;
    if bytes.len() > maximum {
        return Err(Error::invalid(
            "fixed worker process attribute",
            "exceeds hard bound",
        ));
    }
    Ok(bytes)
}

fn kernel_error(operation: &'static str, source: rustix::io::Errno) -> Error {
    Error::Syscall {
        operation,
        source: std::io::Error::from_raw_os_error(source.raw_os_error()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn original_idmap_attempt_never_restarts_after_ambiguity_or_success() {
        let mut pending = OriginalWorkerIdmap::Pending;
        assert!(pending.begin().is_ok());
        assert!(matches!(pending, OriginalWorkerIdmap::Ambiguous));
        assert!(pending.begin().is_err());

        // State-machine regression only: this test does not mint kernel
        // effect custody, exercise INIT/idmapping, or construct a live guard.
        let mut completed = OriginalWorkerIdmap::Applied {
            mount: MountId::new(7).unwrap(),
            namespace: NamespaceIdentity {
                device: 1,
                inode: 2,
            },
        };
        assert!(completed.begin().is_err());
        assert!(matches!(completed, OriginalWorkerIdmap::Applied { .. }));
    }

    #[test]
    fn accepts_only_exact_non_mls_context_with_optional_kernel_nul() {
        let expected = FUSE_WORKER_CONTEXT_V1.as_bytes();
        assert!(context_matches(expected, expected));
        assert!(context_matches(&[expected, &[0]].concat(), expected));

        for suffix in [b":s0".as_slice(), b"\n", b" ", b"\0\0"] {
            assert!(!context_matches(&[expected, suffix].concat(), expected));
        }
        assert!(!context_matches(b"system_u:system_r:init_t", expected));
    }
}
