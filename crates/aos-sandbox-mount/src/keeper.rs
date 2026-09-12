//! Restart-safe custody for detached mount descriptors.
//!
//! [`SystemdFdStore`] implements the systemd file-descriptor-store protocol
//! directly over `NOTIFY_SOCKET`. A successful mutation includes a systemd
//! barrier, so callers may durably record the mutation only after PID 1 has
//! consumed the preceding notification. Descriptors returned through socket
//! activation are adopted into [`ImportedKernelMount`] values with strict
//! names and close-on-exec semantics.

use std::collections::{BTreeMap, BTreeSet};
use std::ffi::OsStr;
use std::io::IoSlice;
use std::mem::MaybeUninit;
use std::os::fd::{AsFd, AsRawFd as _, BorrowedFd, FromRawFd as _, OwnedFd, RawFd};
use std::path::Path;
use std::sync::Arc;
use std::sync::Mutex;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use aos_sandbox_linux::inherited_fd::duplicate_inherited_descriptor;
use aos_sandbox_linux::mount::DetachedMount;
use aos_sandbox_linux::path::ResolvedPath;
use rustix::io::{FdFlags, fcntl_getfd, fcntl_setfd};
use rustix::net::sockopt::{Timeout, set_socket_timeout};
use rustix::net::{
    AddressFamily, RecvFlags, SendAncillaryBuffer, SendAncillaryMessage, SendFlags, SocketAddrUnix,
    SocketFlags, SocketType, recv, sendmsg_addr, socket_with, socketpair,
};

use crate::{MountError, Result};

const ACTIVATION_FD_BASE: RawFd = 3;
const NAME_PREFIX: &str = "aos-mount-v1-";
const SOURCE_NAME_PREFIX: &str = "aos-source-v1-";
const DIGEST_HEX_LENGTH: usize = 64;
const MAXIMUM_IMPORTED_DESCRIPTORS: usize = 1_024;
const BARRIER_TIMEOUT: Duration = Duration::from_secs(5);

/// An opaque, versioned name used to associate a descriptor with durable state.
///
/// Names have the exact form `aos-mount-v1-` followed by 64 lowercase
/// hexadecimal digits. Keeping the accepted language this narrow makes names
/// safe both in systemd's newline protocol and in colon-separated
/// `LISTEN_FDNAMES`.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct KernelMountName(String);

impl KernelMountName {
    /// Constructs a stable opaque name from a 256-bit resource digest.
    #[must_use]
    pub fn from_digest(digest: [u8; 32]) -> Self {
        const HEX: &[u8; 16] = b"0123456789abcdef";
        let mut name = String::with_capacity(NAME_PREFIX.len() + DIGEST_HEX_LENGTH);
        name.push_str(NAME_PREFIX);
        for byte in digest {
            name.push(char::from(HEX[usize::from(byte >> 4)]));
            name.push(char::from(HEX[usize::from(byte & 0x0f)]));
        }
        Self(name)
    }

    /// Parses an exact systemd descriptor-store name.
    ///
    /// # Errors
    ///
    /// Returns an error for an unknown version, wrong length, uppercase digit,
    /// delimiter, control byte, or any non-hexadecimal suffix byte.
    pub fn parse(value: &str) -> Result<Self> {
        let suffix = value
            .strip_prefix(NAME_PREFIX)
            .ok_or_else(|| state_error("descriptor-store name has an unknown prefix"))?;
        if suffix.len() != DIGEST_HEX_LENGTH
            || !suffix
                .as_bytes()
                .iter()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(byte))
        {
            return Err(state_error("descriptor-store name is not canonical"));
        }
        Ok(Self(value.to_owned()))
    }

    /// Returns the exact name transmitted to and restored by systemd.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Decodes the canonical 256-bit resource digest carried by the name.
    #[must_use]
    pub fn digest(&self) -> [u8; 32] {
        let bytes = self.0.as_bytes();
        let suffix = &bytes[NAME_PREFIX.len()..];
        let mut digest = [0_u8; 32];
        for (index, pair) in suffix.chunks_exact(2).enumerate() {
            digest[index] = (hex_value(pair[0]) << 4) | hex_value(pair[1]);
        }
        digest
    }
}

/// An opaque descriptor-store name for one broker-minted source realization.
///
/// Names use `aos-source-v1-` followed by the lowercase hexadecimal realization
/// handle. The disjoint prefix prevents a retained source descriptor from ever
/// being adopted as a detached resource mount.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct SourcePinName(String);

impl SourcePinName {
    /// Constructs the sole canonical name for a source-realization handle.
    #[must_use]
    pub fn from_digest(digest: [u8; 32]) -> Self {
        Self(hex_name(SOURCE_NAME_PREFIX, digest))
    }

    /// Parses one canonical source descriptor-store name.
    ///
    /// # Errors
    ///
    /// Returns an error for an unknown prefix, wrong length, uppercase or
    /// non-hexadecimal suffix, or protocol delimiter.
    pub fn parse(value: &str) -> Result<Self> {
        validate_digest_name(value, SOURCE_NAME_PREFIX)?;
        Ok(Self(value.to_owned()))
    }

    /// Returns the exact name transmitted to systemd.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Decodes the source-realization handle embedded in this name.
    #[must_use]
    pub fn digest(&self) -> [u8; 32] {
        decode_name_digest(&self.0, SOURCE_NAME_PREFIX)
    }
}

fn hex_name(prefix: &str, digest: [u8; 32]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut name = String::with_capacity(prefix.len() + DIGEST_HEX_LENGTH);
    name.push_str(prefix);
    for byte in digest {
        name.push(char::from(HEX[usize::from(byte >> 4)]));
        name.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    name
}

fn validate_digest_name(value: &str, prefix: &str) -> Result<()> {
    let suffix = value
        .strip_prefix(prefix)
        .ok_or_else(|| state_error("descriptor-store name has an unknown prefix"))?;
    if suffix.len() != DIGEST_HEX_LENGTH
        || !suffix
            .as_bytes()
            .iter()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(byte))
    {
        return Err(state_error("descriptor-store name is not canonical"));
    }
    Ok(())
}

fn decode_name_digest(value: &str, prefix: &str) -> [u8; 32] {
    let suffix = &value.as_bytes()[prefix.len()..];
    let mut digest = [0_u8; 32];
    for (index, pair) in suffix.chunks_exact(2).enumerate() {
        digest[index] = (hex_value(pair[0]) << 4) | hex_value(pair[1]);
    }
    digest
}

const fn hex_value(byte: u8) -> u8 {
    match byte {
        b'0'..=b'9' => byte - b'0',
        b'a'..=b'f' => byte - b'a' + 10,
        _ => 0,
    }
}

/// Owns one mount descriptor returned by the configured kernel descriptor keeper.
#[derive(Debug)]
pub struct ImportedKernelMount {
    name: KernelMountName,
    mount: DetachedMount,
}

impl ImportedKernelMount {
    /// Returns the durable name associated with this descriptor.
    #[must_use]
    pub fn name(&self) -> &KernelMountName {
        &self.name
    }

    /// Borrows the close-on-exec kernel descriptor.
    #[must_use]
    pub fn as_fd(&self) -> BorrowedFd<'_> {
        self.mount.as_fd()
    }

    /// Returns the exact kernel-lifetime unique identity of the mount object.
    #[must_use]
    pub const fn mount_id(&self) -> aos_sandbox_linux::inventory::MountId {
        self.mount.mount_id()
    }

    /// Splits the typed value into its durable name and detached mount.
    #[must_use]
    pub fn into_parts(self) -> (KernelMountName, DetachedMount) {
        (self.name, self.mount)
    }
}

/// Owns the exact socket-activation table accepted by the mount daemon.
#[derive(Debug)]
pub struct ActivatedMountDescriptors {
    /// The sole named service listener at descriptor 3.
    pub listener: OwnedFd,
    /// Canonically named, kernel-validated retained mount descriptors.
    pub mounts: BTreeMap<KernelMountName, DetachedMount>,
    /// Canonically named source O_PATH descriptors restored from PID 1.
    pub source_pins: BTreeMap<SourcePinName, ResolvedPath>,
}

/// Provides synchronous restart-safe custody for kernel mount descriptors.
pub trait KernelMountStore {
    /// Reports whether the keeper's authoritative inventory contains `name`.
    ///
    /// Callers must perform this lookup before creating a resource that would
    /// be stored under `name`. A lookup error is a fail-stop condition: the
    /// process must restart and rebuild the inventory from socket activation.
    ///
    /// # Errors
    ///
    /// Returns an error when a prior mutation may have reached the keeper but
    /// its barrier was not acknowledged, or when inventory access fails.
    fn contains(&self, name: &KernelMountName) -> Result<bool>;

    /// Stores a duplicate of `descriptor` under `name` and waits for acceptance.
    ///
    /// Implementations must not consume the caller's descriptor. Returning
    /// success means the keeper acknowledged all notifications issued before
    /// the operation's barrier.
    ///
    /// # Errors
    ///
    /// Returns an error when the keeper cannot accept or acknowledge the
    /// descriptor.
    fn store(&self, name: &KernelMountName, descriptor: BorrowedFd<'_>) -> Result<()>;

    /// Removes all descriptors stored under `name` and waits for acceptance.
    ///
    /// # Errors
    ///
    /// Returns an error when the keeper cannot accept or acknowledge removal.
    fn remove(&self, name: &KernelMountName) -> Result<()>;
}

pub(crate) mod sealed {
    pub trait SourceDescriptorStore {}
}

/// Reports whether PID 1 custody was proved by an authoritative manager view.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SourceCustodyEvidence {
    /// The manager's complete state proves the requested postcondition.
    ManagerConfirmed,
    /// The mutation barrier completed, but no manager query proved the result.
    Unconfirmed,
}

/// Provides restart-safe PID 1 custody for source O_PATH descriptors.
///
/// The trait is sealed so an external caller cannot manufacture manager proof.
/// A mutation barrier alone is not manager-confirmed custody evidence.
#[allow(private_bounds)]
pub trait SourceDescriptorStore: sealed::SourceDescriptorStore {
    /// Confirms that no prior keeper mutation has an ambiguous outcome.
    ///
    /// # Errors
    ///
    /// Returns an error until process restart after an unacknowledged barrier.
    fn ensure_source_reconcilable(&self) -> Result<()> {
        Ok(())
    }

    /// Stores a duplicate source descriptor and waits for PID 1's barrier.
    ///
    /// # Errors
    ///
    /// Returns an error when storage or barrier acknowledgement fails.
    fn store_source(
        &self,
        name: &SourcePinName,
        descriptor: BorrowedFd<'_>,
    ) -> Result<SourceCustodyEvidence>;

    /// Removes every descriptor under `name` and waits for acknowledgement.
    ///
    /// # Errors
    ///
    /// Returns an error when removal or barrier acknowledgement fails.
    fn remove_source(&self, name: &SourcePinName) -> Result<SourceCustodyEvidence>;
}

/// Uses systemd's service-manager descriptor store as restart-safe custody.
#[derive(Debug)]
pub struct SystemdFdStore {
    socket: OwnedFd,
    notify_address: SocketAddrUnix,
    inventory: Mutex<BTreeSet<KernelMountName>>,
    source_inventory: Mutex<BTreeSet<SourcePinName>>,
    maximum_entries: usize,
    poisoned: AtomicBool,
}

impl SystemdFdStore {
    /// Connects a keeper to the `NOTIFY_SOCKET` supplied by systemd.
    ///
    /// This constructor is valid only for a service with no retained startup
    /// descriptors. After adopting retained descriptors, use
    /// [`Self::from_environment_with_inventory`] with their complete name set.
    ///
    /// Filesystem and Linux abstract-namespace notification sockets are
    /// accepted. This does not adopt activation descriptors; call
    /// [`Self::adopt_activation`] during single-threaded process startup.
    ///
    /// # Errors
    ///
    /// Returns an error if `NOTIFY_SOCKET` is absent, non-Unicode, empty,
    /// malformed, too long, or a notification datagram socket cannot be made.
    pub fn from_environment() -> Result<Self> {
        Self::from_environment_with_inventory(BTreeSet::new(), MAXIMUM_IMPORTED_DESCRIPTORS)
    }

    /// Connects a keeper and seeds its bounded restart inventory.
    ///
    /// `retained_names` must be the complete name set returned by the same
    /// startup's socket activation. Seeding it makes lookup authoritative from
    /// process start and prevents an already-restored name from being stored a
    /// second time.
    ///
    /// # Errors
    ///
    /// Returns an error if the bound exceeds the hard descriptor ceiling, the
    /// initial inventory exceeds its bound, or `NOTIFY_SOCKET` is invalid.
    pub fn from_environment_with_inventory(
        retained_names: BTreeSet<KernelMountName>,
        maximum_entries: usize,
    ) -> Result<Self> {
        Self::from_environment_with_inventories(retained_names, BTreeSet::new(), maximum_entries)
    }

    /// Connects a keeper and seeds complete mount and source inventories.
    ///
    /// # Errors
    ///
    /// Returns an error for invalid bounds, overlapping capacity, or an
    /// unavailable/malformed systemd notification socket.
    pub fn from_environment_with_inventories(
        retained_names: BTreeSet<KernelMountName>,
        retained_sources: BTreeSet<SourcePinName>,
        maximum_entries: usize,
    ) -> Result<Self> {
        if maximum_entries > MAXIMUM_IMPORTED_DESCRIPTORS {
            return Err(state_error("descriptor-store ceiling exceeds hard limit"));
        }
        if retained_names.len().saturating_add(retained_sources.len()) > maximum_entries {
            return Err(state_error(
                "initial descriptor-store inventory exceeds limit",
            ));
        }
        let value = std::env::var_os("NOTIFY_SOCKET")
            .ok_or_else(|| state_error("NOTIFY_SOCKET is absent"))?;
        Self::from_notify_socket_with_inventories(
            &value,
            retained_names,
            retained_sources,
            maximum_entries,
        )
    }

    /// Adopts systemd file-descriptor-store entries after caller-owned sockets.
    ///
    /// `reserved_descriptors` is the count of leading activation descriptors
    /// consumed by other subsystems, normally the service's listening socket.
    /// `LISTEN_PID`, `LISTEN_FDS`, and `LISTEN_FDNAMES` must describe this exact
    /// process and every inherited descriptor. The imported tail is limited to
    /// `maximum_imported`, and names must be unique canonical mount names.
    ///
    /// This function must run before threads are created and before any code
    /// closes or reallocates descriptors beginning at FD 3. It deliberately
    /// leaves the activation environment intact; child processes must receive
    /// an explicitly sanitized environment.
    ///
    /// # Errors
    ///
    /// Returns an error for mismatched activation metadata, a count above the
    /// configured or hard ceiling, duplicate/invalid names, descriptor-number
    /// overflow, or inability to set close-on-exec.
    ///
    /// # Safety
    ///
    /// The caller must exclusively own every descriptor in the imported tail
    /// of the systemd activation range. No Rust owner may exist for those raw
    /// descriptors. This function consumes and closes that tail on every path
    /// after ownership is claimed.
    pub unsafe fn adopt_activation(
        reserved_descriptors: usize,
        maximum_imported: usize,
    ) -> Result<Vec<ImportedKernelMount>> {
        if maximum_imported > MAXIMUM_IMPORTED_DESCRIPTORS {
            return Err(state_error("descriptor import ceiling exceeds hard limit"));
        }
        let listen_pid = environment_u32("LISTEN_PID")?;
        let current_pid = u32::try_from(rustix::process::getpid().as_raw_nonzero().get())
            .map_err(|_| state_error("current PID does not fit u32"))?;
        if listen_pid != current_pid {
            return Err(state_error("LISTEN_PID does not name this process"));
        }

        let descriptor_count = environment_usize("LISTEN_FDS")?;
        if descriptor_count < reserved_descriptors
            || descriptor_count - reserved_descriptors > MAXIMUM_IMPORTED_DESCRIPTORS
        {
            return Err(state_error("invalid imported descriptor count"));
        }
        let imported_count = descriptor_count - reserved_descriptors;

        let first_index = ACTIVATION_FD_BASE
            .checked_add(raw_fd_from_usize(reserved_descriptors)?)
            .ok_or_else(|| state_error("activation descriptor number overflow"))?;
        // SAFETY: upheld by this function's caller for the validated imported
        // tail. The range is claimed once and immediately moved into owned
        // storage.
        let originals = unsafe { claim_inherited_descriptor_range(first_index, imported_count)? };
        if imported_count > maximum_imported {
            return Err(state_error("too many descriptor-store entries"));
        }
        let descriptors = duplicate_and_close_owned_descriptors(originals)?;

        let names = std::env::var("LISTEN_FDNAMES")
            .map_err(|_| state_error("LISTEN_FDNAMES is absent or non-Unicode"))?;
        let imported_names = validate_activation_names(
            descriptor_count,
            &names,
            reserved_descriptors,
            maximum_imported,
        )?;

        let mut imported = Vec::with_capacity(imported_count);
        for (name, descriptor) in imported_names.into_iter().zip(descriptors) {
            ensure_cloexec(descriptor.as_fd())?;
            let mount = DetachedMount::from_inherited(descriptor).map_err(|error| {
                state_error(format!("retained descriptor is not a mount: {error}"))
            })?;
            imported.push(ImportedKernelMount { name, mount });
        }
        Ok(imported)
    }

    /// Adopts one named listener followed by retained mounts and sources.
    ///
    /// This is the mount daemon's only supported activation shape. Metadata is
    /// parsed in one startup call before any inherited descriptor may be
    /// reused. The complete table is first claimed, then safely duplicated;
    /// all process-start entries are closed before validation continues.
    ///
    /// # Errors
    ///
    /// Returns an error unless descriptor 3 has exactly `listener_name`, every
    /// remaining descriptor has a unique canonical mount or source-pin name, the
    /// configured bound is respected, and every retained descriptor yields an
    /// exact `STATX_MNT_ID_UNIQUE` mount identity.
    ///
    /// # Safety
    ///
    /// The caller must exclusively own every open descriptor in the systemd
    /// activation range beginning at FD 3. No Rust owner may exist for those
    /// raw descriptors. This function consumes and closes all open entries in
    /// the complete range on every path after ownership is claimed, including
    /// when malformed metadata describes a gap.
    pub unsafe fn adopt_service_activation(
        listener_name: &str,
        maximum_imported: usize,
    ) -> Result<ActivatedMountDescriptors> {
        if maximum_imported > MAXIMUM_IMPORTED_DESCRIPTORS {
            return Err(state_error("descriptor import ceiling exceeds hard limit"));
        }
        validate_listener_name(listener_name)?;
        let descriptor_count = environment_usize("LISTEN_FDS")?;
        if descriptor_count == 0 || descriptor_count - 1 > MAXIMUM_IMPORTED_DESCRIPTORS {
            return Err(state_error("too many descriptor-store entries"));
        }
        let listen_pid = environment_u32("LISTEN_PID")?;
        let current_pid = u32::try_from(rustix::process::getpid().as_raw_nonzero().get())
            .map_err(|_| state_error("current PID does not fit u32"))?;
        if listen_pid != current_pid {
            return Err(state_error("LISTEN_PID does not name this process"));
        }

        // SAFETY: upheld by this function's caller for the validated complete
        // activation table. The range is claimed exactly once.
        let originals =
            unsafe { claim_inherited_descriptor_range(ACTIVATION_FD_BASE, descriptor_count)? };
        if descriptor_count - 1 > maximum_imported {
            return Err(state_error("too many descriptor-store entries"));
        }
        let descriptors = duplicate_and_close_owned_descriptors(originals)?;

        let names = std::env::var("LISTEN_FDNAMES")
            .map_err(|_| state_error("LISTEN_FDNAMES is absent or non-Unicode"))?;
        let names: Vec<&str> = names.split(':').collect();
        if names.len() != descriptor_count {
            return Err(state_error("LISTEN_FDNAMES count differs from LISTEN_FDS"));
        }
        if names.first().copied() != Some(listener_name) {
            return Err(state_error(
                "activation descriptor 3 is not the named listener",
            ));
        }

        let mut descriptors = descriptors.into_iter();
        let listener = descriptors
            .next()
            .ok_or_else(|| state_error("activation listener is absent"))?;
        let mut mounts = BTreeMap::new();
        let mut source_pins = BTreeMap::new();
        for (name, descriptor) in names.into_iter().skip(1).zip(descriptors) {
            ensure_cloexec(descriptor.as_fd())?;
            if name.starts_with(NAME_PREFIX) {
                let name = KernelMountName::parse(name)?;
                let mount = DetachedMount::from_inherited(descriptor).map_err(|error| {
                    state_error(format!("retained descriptor is not a mount: {error}"))
                })?;
                if mounts.insert(name, mount).is_some() {
                    return Err(state_error("duplicate descriptor-store name"));
                }
            } else {
                let name = SourcePinName::parse(name)?;
                let source = ResolvedPath::from_inherited(descriptor).map_err(|error| {
                    state_error(format!("retained source descriptor is invalid: {error}"))
                })?;
                if source.identity().file_type != aos_sandbox_linux::path::FileType::Directory {
                    return Err(state_error("retained source descriptor is not a directory"));
                }
                if source_pins.insert(name, source).is_some() {
                    return Err(state_error("duplicate descriptor-store name"));
                }
            }
        }
        ensure_cloexec(listener.as_fd())?;
        Ok(ActivatedMountDescriptors {
            listener,
            mounts,
            source_pins,
        })
    }

    #[cfg(test)]
    fn from_notify_socket(value: &OsStr) -> Result<Self> {
        Self::from_notify_socket_with_inventory(
            value,
            BTreeSet::new(),
            MAXIMUM_IMPORTED_DESCRIPTORS,
        )
    }

    #[cfg(test)]
    fn from_notify_socket_with_inventory(
        value: &OsStr,
        inventory: BTreeSet<KernelMountName>,
        maximum_entries: usize,
    ) -> Result<Self> {
        Self::from_notify_socket_with_inventories(
            value,
            inventory,
            BTreeSet::new(),
            maximum_entries,
        )
    }

    fn from_notify_socket_with_inventories(
        value: &OsStr,
        inventory: BTreeSet<KernelMountName>,
        source_inventory: BTreeSet<SourcePinName>,
        maximum_entries: usize,
    ) -> Result<Self> {
        if maximum_entries > MAXIMUM_IMPORTED_DESCRIPTORS {
            return Err(state_error("descriptor-store ceiling exceeds hard limit"));
        }
        if inventory.len().saturating_add(source_inventory.len()) > maximum_entries {
            return Err(state_error(
                "initial descriptor-store inventory exceeds limit",
            ));
        }
        let value = value
            .to_str()
            .ok_or_else(|| state_error("NOTIFY_SOCKET is not Unicode"))?;
        if value.is_empty() {
            return Err(state_error("NOTIFY_SOCKET is empty"));
        }
        let notify_address = if let Some(abstract_name) = value.strip_prefix('@') {
            if abstract_name.is_empty() {
                return Err(state_error("NOTIFY_SOCKET abstract name is empty"));
            }
            SocketAddrUnix::new_abstract_name(abstract_name.as_bytes())
        } else {
            SocketAddrUnix::new(Path::new(value))
        }
        .map_err(notify_error)?;
        let socket = socket_with(
            AddressFamily::UNIX,
            SocketType::DGRAM,
            SocketFlags::CLOEXEC,
            None,
        )
        .map_err(notify_error)?;
        Ok(Self {
            socket,
            notify_address,
            inventory: Mutex::new(inventory),
            source_inventory: Mutex::new(source_inventory),
            maximum_entries,
            poisoned: AtomicBool::new(false),
        })
    }

    fn ensure_reconcilable(&self) -> Result<()> {
        if self.poisoned.load(Ordering::Acquire) {
            return Err(state_error(
                "descriptor-store mutation outcome is ambiguous; service restart is required",
            ));
        }
        Ok(())
    }

    fn ambiguous(&self, error: &MountError) -> MountError {
        self.poisoned.store(true, Ordering::Release);
        state_error(format!(
            "descriptor-store mutation outcome is ambiguous; service restart is required: {error}"
        ))
    }

    fn notify(&self, payload: &[u8], descriptor: Option<BorrowedFd<'_>>) -> Result<()> {
        let iov = [IoSlice::new(payload)];
        let borrowed = descriptor.into_iter().collect::<Vec<_>>();
        let mut control_space = [MaybeUninit::uninit(); rustix::cmsg_space!(ScmRights(1))];
        let mut control = SendAncillaryBuffer::new(&mut control_space);
        if !borrowed.is_empty() && !control.push(SendAncillaryMessage::ScmRights(&borrowed)) {
            return Err(state_error("notification ancillary buffer is exhausted"));
        }
        let written = sendmsg_addr(
            &self.socket,
            &self.notify_address,
            &iov,
            &mut control,
            SendFlags::NOSIGNAL,
        )
        .map_err(notify_error)?;
        if written != payload.len() {
            return Err(state_error("systemd notification was partially written"));
        }
        Ok(())
    }

    fn barrier(&self) -> Result<()> {
        let (waiter, manager_end) = socketpair(
            AddressFamily::UNIX,
            SocketType::STREAM,
            SocketFlags::CLOEXEC,
            None,
        )
        .map_err(notify_error)?;
        set_socket_timeout(&waiter, Timeout::Recv, Some(BARRIER_TIMEOUT)).map_err(notify_error)?;
        self.notify(b"BARRIER=1", Some(manager_end.as_fd()))?;
        drop(manager_end);

        let mut byte = [0_u8; 1];
        let (received, _) = recv(&waiter, &mut byte, RecvFlags::empty()).map_err(notify_error)?;
        if received != 0 {
            return Err(state_error("systemd barrier descriptor carried data"));
        }
        Ok(())
    }
}

fn validate_listener_name(name: &str) -> Result<()> {
    if name.is_empty()
        || name.len() > 255
        || name
            .bytes()
            .any(|byte| byte == b':' || byte == b'\n' || byte == b'\0')
    {
        return Err(state_error("activation listener name is not canonical"));
    }
    Ok(())
}

fn validate_activation_names(
    descriptor_count: usize,
    names: &str,
    reserved_descriptors: usize,
    maximum_imported: usize,
) -> Result<Vec<KernelMountName>> {
    if descriptor_count < reserved_descriptors {
        return Err(state_error("LISTEN_FDS omits reserved descriptors"));
    }
    if descriptor_count - reserved_descriptors > maximum_imported {
        return Err(state_error("too many descriptor-store entries"));
    }
    let names: Vec<&str> = names.split(':').collect();
    if names.len() != descriptor_count {
        return Err(state_error("LISTEN_FDNAMES count differs from LISTEN_FDS"));
    }
    let imported_names = names
        .into_iter()
        .skip(reserved_descriptors)
        .map(KernelMountName::parse)
        .collect::<Result<Vec<_>>>()?;
    let unique_names: BTreeSet<_> = imported_names.iter().collect();
    if unique_names.len() != imported_names.len() {
        return Err(state_error("duplicate descriptor-store name"));
    }
    Ok(imported_names)
}

impl KernelMountStore for SystemdFdStore {
    fn contains(&self, name: &KernelMountName) -> Result<bool> {
        self.ensure_reconcilable()?;
        let inventory = self
            .inventory
            .lock()
            .map_err(|_| state_error("descriptor-store inventory lock is poisoned"))?;
        self.ensure_reconcilable()?;
        Ok(inventory.contains(name))
    }

    fn store(&self, name: &KernelMountName, descriptor: BorrowedFd<'_>) -> Result<()> {
        self.ensure_reconcilable()?;
        let mut inventory = self
            .inventory
            .lock()
            .map_err(|_| state_error("descriptor-store inventory lock is poisoned"))?;
        let source_inventory = self
            .source_inventory
            .lock()
            .map_err(|_| state_error("source descriptor-store inventory lock is poisoned"))?;
        self.ensure_reconcilable()?;
        if inventory.contains(name) {
            return Ok(());
        }
        if inventory.len().saturating_add(source_inventory.len()) >= self.maximum_entries {
            return Err(state_error("descriptor-store inventory is full"));
        }

        let payload = format!("FDSTORE=1\nFDPOLL=0\nFDNAME={}", name.as_str());
        self.notify(payload.as_bytes(), Some(descriptor))?;
        self.barrier().map_err(|error| self.ambiguous(&error))?;
        inventory.insert(name.clone());
        Ok(())
    }

    fn remove(&self, name: &KernelMountName) -> Result<()> {
        self.ensure_reconcilable()?;
        let mut inventory = self
            .inventory
            .lock()
            .map_err(|_| state_error("descriptor-store inventory lock is poisoned"))?;
        self.ensure_reconcilable()?;
        if !inventory.contains(name) {
            return Ok(());
        }

        let payload = format!("FDSTOREREMOVE=1\nFDNAME={}", name.as_str());
        self.notify(payload.as_bytes(), None)?;
        self.barrier().map_err(|error| self.ambiguous(&error))?;
        inventory.remove(name);
        Ok(())
    }
}

impl<T: KernelMountStore + ?Sized> KernelMountStore for Arc<T> {
    fn contains(&self, name: &KernelMountName) -> Result<bool> {
        (**self).contains(name)
    }

    fn store(&self, name: &KernelMountName, descriptor: BorrowedFd<'_>) -> Result<()> {
        (**self).store(name, descriptor)
    }

    fn remove(&self, name: &KernelMountName) -> Result<()> {
        (**self).remove(name)
    }
}

impl sealed::SourceDescriptorStore for SystemdFdStore {}

impl SourceDescriptorStore for SystemdFdStore {
    fn ensure_source_reconcilable(&self) -> Result<()> {
        SystemdFdStore::ensure_reconcilable(self)
    }

    fn store_source(
        &self,
        name: &SourcePinName,
        descriptor: BorrowedFd<'_>,
    ) -> Result<SourceCustodyEvidence> {
        self.ensure_reconcilable()?;
        let mount_inventory = self
            .inventory
            .lock()
            .map_err(|_| state_error("descriptor-store inventory lock is poisoned"))?;
        let mut inventory = self
            .source_inventory
            .lock()
            .map_err(|_| state_error("source descriptor-store inventory lock is poisoned"))?;
        self.ensure_reconcilable()?;
        if inventory.contains(name) {
            return Err(state_error(
                "fresh source custody collides with startup manager inventory",
            ));
        }
        if mount_inventory.len().saturating_add(inventory.len()) >= self.maximum_entries {
            return Err(state_error("source descriptor-store inventory is full"));
        }

        let payload = format!("FDSTORE=1\nFDPOLL=0\nFDNAME={}", name.as_str());
        self.notify(payload.as_bytes(), Some(descriptor))?;
        self.barrier().map_err(|error| self.ambiguous(&error))?;
        inventory.insert(name.clone());
        Ok(SourceCustodyEvidence::Unconfirmed)
    }

    fn remove_source(&self, name: &SourcePinName) -> Result<SourceCustodyEvidence> {
        self.ensure_reconcilable()?;
        let inventory = self
            .source_inventory
            .lock()
            .map_err(|_| state_error("source descriptor-store inventory lock is poisoned"))?;
        self.ensure_reconcilable()?;
        if !inventory.contains(name) {
            return Ok(SourceCustodyEvidence::ManagerConfirmed);
        }

        let payload = format!("FDSTOREREMOVE=1\nFDNAME={}", name.as_str());
        self.notify(payload.as_bytes(), None)?;
        self.barrier().map_err(|error| self.ambiguous(&error))?;
        // Without an exact manager query, the process cannot turn its own
        // removal request into proof of absence. Keep the startup observation
        // live so every same-process retry remains unconfirmed.
        Ok(SourceCustodyEvidence::Unconfirmed)
    }
}

impl<T: SourceDescriptorStore + ?Sized> sealed::SourceDescriptorStore for Arc<T> {}

impl<T: SourceDescriptorStore + ?Sized> SourceDescriptorStore for Arc<T> {
    fn ensure_source_reconcilable(&self) -> Result<()> {
        (**self).ensure_source_reconcilable()
    }

    fn store_source(
        &self,
        name: &SourcePinName,
        descriptor: BorrowedFd<'_>,
    ) -> Result<SourceCustodyEvidence> {
        (**self).store_source(name, descriptor)
    }

    fn remove_source(&self, name: &SourcePinName) -> Result<SourceCustodyEvidence> {
        (**self).remove_source(name)
    }
}

fn environment_u32(name: &'static str) -> Result<u32> {
    std::env::var(name)
        .map_err(|_| state_error(format!("{name} is absent or non-Unicode")))?
        .parse()
        .map_err(|_| state_error(format!("{name} is not a decimal u32")))
}

fn environment_usize(name: &'static str) -> Result<usize> {
    std::env::var(name)
        .map_err(|_| state_error(format!("{name} is absent or non-Unicode")))?
        .parse()
        .map_err(|_| state_error(format!("{name} is not a decimal usize")))
}

fn raw_fd_from_usize(value: usize) -> Result<RawFd> {
    RawFd::try_from(value).map_err(|_| state_error("activation descriptor number overflow"))
}

/// Claims a complete contiguous activation range without allocating an FD.
///
/// # Safety
///
/// The caller must have exclusive ownership of every open descriptor in the
/// specified range, and no Rust owner may exist for one of those descriptors.
/// A malformed range is closed completely before an error is returned.
unsafe fn claim_inherited_descriptor_range(first: RawFd, count: usize) -> Result<Vec<OwnedFd>> {
    let mut raw_descriptors = Vec::with_capacity(count);
    for offset in 0..count {
        let raw = first
            .checked_add(raw_fd_from_usize(offset)?)
            .ok_or_else(|| state_error("activation descriptor number overflow"))?;
        raw_descriptors.push(raw);
    }

    let complete = raw_descriptors.iter().all(|raw| {
        // SAFETY: F_GETFD observes only the numeric descriptor-table entry and
        // accepts closed descriptor numbers, reporting EBADF for a gap.
        unsafe { libc::fcntl(*raw, libc::F_GETFD) >= 0 }
    });
    if !complete {
        for raw in raw_descriptors {
            // SAFETY: the caller granted exclusive ownership of every open
            // entry in this exact bounded range. `close` also safely reports
            // EBADF for the missing entry that caused validation to fail.
            unsafe { libc::close(raw) };
        }
        return Err(state_error(
            "systemd activation descriptor range is incomplete",
        ));
    }

    let mut descriptors = Vec::with_capacity(count);
    for raw in raw_descriptors {
        // SAFETY: the complete range was checked without allocating an FD, the
        // caller grants exclusive ownership, and each number is consumed once.
        descriptors.push(unsafe { OwnedFd::from_raw_fd(raw) });
    }
    Ok(descriptors)
}

fn duplicate_and_close_owned_descriptors(originals: Vec<OwnedFd>) -> Result<Vec<OwnedFd>> {
    let duplicates = originals
        .iter()
        .map(|original| {
            duplicate_inherited_descriptor(original.as_raw_fd()).map_err(|error| {
                state_error(format!(
                    "could not duplicate activation descriptor: {error}"
                ))
            })
        })
        .collect();

    // Close the entire process-start table together. Keeping every original
    // open until duplication finishes prevents F_DUPFD_CLOEXEC from filling a
    // later activation slot if malformed input contains a gap.
    drop(originals);
    duplicates
}

fn ensure_cloexec(fd: BorrowedFd<'_>) -> Result<()> {
    let flags = fcntl_getfd(fd).map_err(notify_error)?;
    fcntl_setfd(fd, flags | FdFlags::CLOEXEC).map_err(notify_error)
}

fn notify_error(error: rustix::io::Errno) -> MountError {
    state_error(format!("systemd descriptor store failed: {error}"))
}

fn state_error(message: impl Into<String>) -> MountError {
    MountError::State(message.into())
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use std::fs::File;
    use std::io::IoSliceMut;
    use std::process::Command;
    use std::sync::mpsc;

    use rustix::net::{RecvAncillaryBuffer, RecvAncillaryMessage, bind, recvmsg};

    use super::*;

    const ACTIVATION_RANGE_FIXTURE: &str = "AOS_MOUNT_ACTIVATION_RANGE_FIXTURE";

    fn raw_descriptor_is_open(raw: RawFd) -> bool {
        // SAFETY: F_GETFD observes a numeric table entry and reports EBADF for
        // a closed descriptor without assuming ownership.
        unsafe { libc::fcntl(raw, libc::F_GETFD) >= 0 }
    }

    #[test]
    fn opaque_names_are_canonical_and_round_trip() {
        let name = KernelMountName::from_digest([0xab; 32]);
        assert_eq!(
            name.as_str(),
            "aos-mount-v1-abababababababababababababababababababababababababababababababab"
        );
        assert_eq!(KernelMountName::parse(name.as_str()).unwrap(), name);
        assert_eq!(name.digest(), [0xab; 32]);

        for invalid in [
            "aos-mount-v2-abababababababababababababababababababababababababababababababab",
            "aos-mount-v1-ABababababababababababababababababababababababababababababababab",
            "aos-mount-v1-abababababababababababababababababababababababababababababababag",
            "aos-mount-v1-abab",
            "aos-mount-v1-abababababababababababababababababababababababababababababababa:",
        ] {
            assert!(
                KernelMountName::parse(invalid).is_err(),
                "accepted {invalid}"
            );
        }
    }

    #[test]
    fn listener_names_reject_activation_delimiters() {
        for invalid in ["", "mount:other", "mount\nother", "mount\0other"] {
            assert!(validate_listener_name(invalid).is_err());
        }
        assert!(validate_listener_name("aos-sandbox-mount").is_ok());
        // SAFETY: the excessive configured bound is rejected before any
        // activation descriptor ownership can be claimed.
        assert!(unsafe {
            SystemdFdStore::adopt_service_activation(
                "aos-sandbox-mount",
                MAXIMUM_IMPORTED_DESCRIPTORS + 1,
            )
            .is_err()
        });
    }

    #[test]
    fn service_activation_closes_originals_and_cleans_incomplete_ranges() {
        for scenario in [
            "complete",
            "over-configured-limit",
            "missing-first",
            "missing-middle",
            "missing-last",
            "regular-source",
        ] {
            let status = Command::new(std::env::current_exe().unwrap())
                .args([
                    "--exact",
                    "keeper::tests::service_activation_range_fixture",
                    "--nocapture",
                ])
                .env(ACTIVATION_RANGE_FIXTURE, scenario)
                .status()
                .unwrap();
            assert!(status.success(), "activation fixture failed: {scenario}");
        }
    }

    #[test]
    fn service_activation_range_fixture() {
        let Some(scenario) = std::env::var_os(ACTIVATION_RANGE_FIXTURE) else {
            return;
        };
        let scenario = scenario.to_string_lossy();

        for raw in ACTIVATION_FD_BASE..=ACTIVATION_FD_BASE + 2 {
            // SAFETY: this exact-test subprocess owns its descriptor table and
            // intentionally clears the bounded fixture range before rebuilding it.
            unsafe { libc::close(raw) };
            let regular_source = scenario == "regular-source" && raw == ACTIVATION_FD_BASE + 2;
            let path = if regular_source {
                c"/proc/self/status"
            } else {
                c"/proc/self"
            };
            let flags =
                libc::O_PATH | libc::O_CLOEXEC | if regular_source { 0 } else { libc::O_DIRECTORY };
            // SAFETY: `path` is a static NUL-terminated pathname and open
            // returns a fresh descriptor with no Rust owner.
            let opened = unsafe { libc::open(path.as_ptr(), flags) };
            assert_eq!(opened, raw);
        }

        let missing = match scenario.as_ref() {
            "complete" | "over-configured-limit" | "regular-source" => None,
            "missing-first" => Some(ACTIVATION_FD_BASE),
            "missing-middle" => Some(ACTIVATION_FD_BASE + 1),
            "missing-last" => Some(ACTIVATION_FD_BASE + 2),
            other => panic!("unknown activation fixture: {other}"),
        };
        if let Some(raw) = missing {
            // SAFETY: the fixture created and exclusively owns this raw entry.
            assert_eq!(unsafe { libc::close(raw) }, 0);
        }

        // SAFETY: the exact-test subprocess runs no concurrent tests while it
        // mutates its process environment.
        unsafe {
            std::env::set_var("LISTEN_PID", std::process::id().to_string());
            std::env::set_var("LISTEN_FDS", "3");
            std::env::set_var(
                "LISTEN_FDNAMES",
                format!(
                    "aos-sandbox-mount:{}:{}",
                    SourcePinName::from_digest([1; 32]).as_str(),
                    SourcePinName::from_digest([2; 32]).as_str(),
                ),
            );
        }

        // SAFETY: the fixture exclusively owns every open entry in the exact
        // FD 3..=5 activation range and has constructed no Rust owners for it.
        let maximum_imported = if scenario == "over-configured-limit" {
            1
        } else {
            2
        };
        let activation = unsafe {
            SystemdFdStore::adopt_service_activation("aos-sandbox-mount", maximum_imported)
        };
        for raw in ACTIVATION_FD_BASE..=ACTIVATION_FD_BASE + 2 {
            assert!(!raw_descriptor_is_open(raw));
        }

        if missing.is_some()
            || matches!(
                scenario.as_ref(),
                "over-configured-limit" | "regular-source"
            )
        {
            assert!(activation.is_err());
            return;
        }

        let activation = activation.unwrap();
        let duplicate_raws = std::iter::once(activation.listener.as_raw_fd())
            .chain(
                activation
                    .source_pins
                    .values()
                    .map(|source| source.as_fd().as_raw_fd()),
            )
            .collect::<Vec<_>>();
        assert!(
            duplicate_raws
                .iter()
                .all(|raw| raw_descriptor_is_open(*raw))
        );

        drop(activation);
        assert!(
            duplicate_raws
                .iter()
                .all(|raw| !raw_descriptor_is_open(*raw))
        );
    }

    #[test]
    fn restart_activation_names_are_bounded_unique_and_canonical() {
        let first = KernelMountName::from_digest([1; 32]);
        let second = KernelMountName::from_digest([2; 32]);
        let names = format!("aos-sandbox-mount:{}:{}", first.as_str(), second.as_str());
        assert_eq!(
            validate_activation_names(3, &names, 1, 2).unwrap(),
            vec![first.clone(), second]
        );
        assert!(validate_activation_names(3, &names, 1, 1).is_err());
        assert!(validate_activation_names(2, &names, 1, 2).is_err());

        let duplicate = format!("aos-sandbox-mount:{}:{}", first.as_str(), first.as_str());
        assert!(validate_activation_names(3, &duplicate, 1, 2).is_err());
        assert!(validate_activation_names(0, "", 1, 2).is_err());
    }

    #[test]
    fn seeded_inventory_is_bounded_and_supports_exact_lookup() {
        let name = KernelMountName::from_digest([3; 32]);
        let inventory = BTreeSet::from([name.clone()]);
        assert!(
            SystemdFdStore::from_notify_socket_with_inventory(
                OsStr::new("/unused"),
                inventory.clone(),
                0,
            )
            .is_err()
        );

        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("notify.sock");
        let keeper =
            SystemdFdStore::from_notify_socket_with_inventory(path.as_os_str(), inventory, 1)
                .unwrap();
        assert!(keeper.contains(&name).unwrap());
        assert!(
            !keeper
                .contains(&KernelMountName::from_digest([4; 32]))
                .unwrap()
        );
    }

    #[test]
    fn store_and_remove_are_barrier_ordered() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("notify.sock");
        let server = socket_with(
            AddressFamily::UNIX,
            SocketType::DGRAM,
            SocketFlags::CLOEXEC,
            None,
        )
        .unwrap();
        bind(&server, &SocketAddrUnix::new(&path).unwrap()).unwrap();
        let keeper = SystemdFdStore::from_notify_socket(path.as_os_str()).unwrap();
        let descriptor: OwnedFd = File::open(directory.path()).unwrap().into();
        let name = KernelMountName::from_digest([7; 32]);
        let (sender, receiver) = mpsc::channel();

        let manager = std::thread::spawn(move || {
            let mut observed = Vec::new();
            for _ in 0..4 {
                let (payload, descriptors) = receive_notification(&server);
                observed.push((payload, descriptors.len()));
                drop(descriptors);
            }
            sender.send(observed).unwrap();
        });

        keeper.store(&name, descriptor.as_fd()).unwrap();
        keeper.remove(&name).unwrap();
        manager.join().unwrap();
        let observed = receiver.recv().unwrap();
        assert_eq!(
            observed,
            vec![
                (format!("FDSTORE=1\nFDPOLL=0\nFDNAME={}", name.as_str()), 1),
                ("BARRIER=1".to_owned(), 1),
                (format!("FDSTOREREMOVE=1\nFDNAME={}", name.as_str()), 0),
                ("BARRIER=1".to_owned(), 1),
            ]
        );
        assert!(fcntl_getfd(&descriptor).unwrap().contains(FdFlags::CLOEXEC));
    }

    #[test]
    fn source_barriers_do_not_claim_manager_confirmed_custody() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("notify.sock");
        let server = socket_with(
            AddressFamily::UNIX,
            SocketType::DGRAM,
            SocketFlags::CLOEXEC,
            None,
        )
        .unwrap();
        bind(&server, &SocketAddrUnix::new(&path).unwrap()).unwrap();
        let keeper = SystemdFdStore::from_notify_socket(path.as_os_str()).unwrap();
        let descriptor: OwnedFd = File::open(directory.path()).unwrap().into();
        let name = SourcePinName::from_digest([17; 32]);

        let manager = std::thread::spawn(move || {
            for _ in 0..6 {
                let (_, descriptors) = receive_notification(&server);
                drop(descriptors);
            }
        });

        assert_eq!(
            keeper.store_source(&name, descriptor.as_fd()).unwrap(),
            SourceCustodyEvidence::Unconfirmed
        );
        assert_eq!(
            keeper.remove_source(&name).unwrap(),
            SourceCustodyEvidence::Unconfirmed
        );
        assert_eq!(
            keeper.remove_source(&name).unwrap(),
            SourceCustodyEvidence::Unconfirmed
        );
        manager.join().unwrap();
    }

    #[test]
    fn ambiguous_barrier_failure_poisons_inventory_lookup() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("notify.sock");
        let server = socket_with(
            AddressFamily::UNIX,
            SocketType::DGRAM,
            SocketFlags::CLOEXEC,
            None,
        )
        .unwrap();
        bind(&server, &SocketAddrUnix::new(&path).unwrap()).unwrap();
        let keeper = SystemdFdStore::from_notify_socket(path.as_os_str()).unwrap();
        let descriptor: OwnedFd = File::open(directory.path()).unwrap().into();
        let name = KernelMountName::from_digest([8; 32]);

        let manager = std::thread::spawn(move || {
            let (store_payload, stored) = receive_notification(&server);
            assert!(store_payload.starts_with("FDSTORE=1\n"));
            assert_eq!(stored.len(), 1);

            let (barrier_payload, barrier) = receive_notification(&server);
            assert_eq!(barrier_payload, "BARRIER=1");
            assert_eq!(barrier.len(), 1);
            rustix::io::write(&barrier[0], b"ambiguous").unwrap();
        });

        let error = keeper.store(&name, descriptor.as_fd()).unwrap_err();
        assert!(error.to_string().contains("outcome is ambiguous"));
        manager.join().unwrap();

        let error = keeper.contains(&name).unwrap_err();
        assert!(error.to_string().contains("service restart is required"));
        assert!(keeper.ensure_source_reconcilable().is_err());
        let other = KernelMountName::from_digest([9; 32]);
        assert!(keeper.store(&other, descriptor.as_fd()).is_err());
    }

    fn receive_notification(socket: &OwnedFd) -> (String, Vec<OwnedFd>) {
        let mut payload = [0_u8; 256];
        let mut iov = [IoSliceMut::new(&mut payload)];
        let mut control_space = [MaybeUninit::uninit(); rustix::cmsg_space!(ScmRights(1))];
        let mut control = RecvAncillaryBuffer::new(&mut control_space);
        let message = recvmsg(socket, &mut iov, &mut control, RecvFlags::CMSG_CLOEXEC).unwrap();
        let bytes = message.bytes;
        let mut descriptors = Vec::new();
        for ancillary in control.drain() {
            if let RecvAncillaryMessage::ScmRights(received) = ancillary {
                descriptors.extend(received);
            }
        }
        let payload = String::from_utf8(payload[..bytes].to_vec()).unwrap();
        for descriptor in &descriptors {
            assert!(fcntl_getfd(descriptor).unwrap().contains(FdFlags::CLOEXEC));
        }
        (payload, descriptors)
    }
}
