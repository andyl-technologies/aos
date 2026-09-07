//! Bounded `listmount(2)` and `statmount(2)` topology observation.
//!
//! Queries may target the caller's mount namespace or a pinned mount namespace
//! descriptor. Variable-length kernel strings and idmap arrays are decoded only
//! after validating the returned size, field mask, offsets, counts, and NUL
//! terminators.

use std::collections::BTreeSet;
use std::ffi::OsString;
use std::num::NonZeroU64;
use std::os::fd::{AsRawFd, BorrowedFd, RawFd};
use std::os::unix::ffi::OsStringExt;

use crate::pidfd::{NamespaceFd, NamespaceKind};
use crate::uapi::{
    self, LISTMOUNT_REVERSE, LSMT_ROOT, MountIdRequest, STATMOUNT_FS_TYPE, STATMOUNT_MNT_BASIC,
    STATMOUNT_MNT_GIDMAP, STATMOUNT_MNT_NS_ID, STATMOUNT_MNT_POINT, STATMOUNT_MNT_ROOT,
    STATMOUNT_MNT_UIDMAP, STATMOUNT_SB_BASIC, STATMOUNT_SB_SOURCE, STATMOUNT_SUPPORTED_MASK,
    StatMountBuffer,
};
use crate::{Error, Result};

const REQUEST_SIZE_CURRENT_NAMESPACE: u32 = 24;
const REQUEST_SIZE_NAMESPACE_FD: u32 = 32;
const MAX_LIST_PAGE: usize = 4096;
const MAX_INVENTORY_MOUNTS: usize = 65_536;
const MAX_IDMAP_EXTENTS: usize = 340;
const REQUIRED_OBSERVATION_MASK: u64 = STATMOUNT_SB_BASIC
    | STATMOUNT_MNT_BASIC
    | STATMOUNT_MNT_ROOT
    | STATMOUNT_MNT_POINT
    | STATMOUNT_FS_TYPE
    | STATMOUNT_MNT_NS_ID
    | STATMOUNT_SB_SOURCE;
const OBSERVATION_MASK: u64 = REQUIRED_OBSERVATION_MASK
    | STATMOUNT_SUPPORTED_MASK
    | STATMOUNT_MNT_UIDMAP
    | STATMOUNT_MNT_GIDMAP;

/// A non-zero unique mount ID returned by the modern mount API.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct MountId(NonZeroU64);

impl MountId {
    /// Validates a kernel unique mount ID.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidInput`] when `value` is zero or the special
    /// `LSMT_ROOT` selector rather than an observed mount ID.
    pub fn new(value: u64) -> Result<Self> {
        if value == LSMT_ROOT {
            return Err(Error::invalid(
                "mount ID",
                "root selector is not an observed mount ID",
            ));
        }
        NonZeroU64::new(value)
            .map(Self)
            .ok_or_else(|| Error::invalid("mount ID", "must be non-zero"))
    }

    /// Returns the kernel unique mount ID.
    #[must_use]
    pub const fn get(self) -> u64 {
        self.0.get()
    }

    /// Reads the unique ID of the mount containing a pinned object.
    ///
    /// This uses `statx(AT_EMPTY_PATH, STATX_MNT_ID_UNIQUE)` and never parses
    /// `/proc`. The identifier is not reused during the running kernel's
    /// lifetime and is directly accepted by `statmount(2)` and `listmount(2)`.
    /// Linux 6.8 or newer is required.
    ///
    /// # Errors
    ///
    /// Returns an error when the descriptor cannot be inspected, the running
    /// kernel does not implement `STATX_MNT_ID_UNIQUE`, the kernel omits the
    /// requested field, or the returned identifier is invalid.
    pub fn from_fd(fd: BorrowedFd<'_>) -> Result<Self> {
        Self::new(uapi::statx_unique_mount_id(fd)?)
    }
}

/// One bounded page returned by `listmount(2)`.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MountIdPage {
    /// Mount IDs in kernel traversal order.
    pub mounts: Vec<MountId>,
    /// Cursor to pass as `after` for the next page.
    pub next_after: Option<MountId>,
    /// Whether the page filled the caller's limit and may have a successor.
    pub may_have_more: bool,
}

/// One complete, caller-bounded mount namespace observation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MountInventory {
    /// Observed mounts in the requested kernel traversal order.
    pub mounts: Vec<MountObservation>,
}

/// Kernel traversal order for one `listmount(2)` page.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum MountListOrder {
    /// Lists earlier mounts before later mounts.
    #[default]
    Forward,
    /// Lists later mounts before earlier mounts.
    Reverse,
}

/// Validated metadata returned by `statmount(2)`.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MountObservation {
    /// Unique mount ID.
    pub mount_id: MountId,
    /// Unique parent mount ID; equal to `mount_id` for the namespace root.
    pub parent_mount_id: MountId,
    /// Unique mount namespace ID.
    pub mount_namespace_id: u64,
    /// Device major number.
    pub device_major: u32,
    /// Device minor number.
    pub device_minor: u32,
    /// Filesystem magic value.
    pub superblock_magic: u64,
    /// Superblock flags.
    pub superblock_flags: u32,
    /// Per-mount `MOUNT_ATTR_*` flags.
    pub mount_attributes: u64,
    /// Mount propagation flags.
    pub propagation: u64,
    /// Mask of fields supported by the running kernel, when available.
    pub supported_mask: Option<u64>,
    /// Root within the underlying filesystem.
    pub root: OsString,
    /// Mountpoint relative to the namespace root.
    pub mount_point: OsString,
    /// Filesystem type.
    pub filesystem_type: OsString,
    /// Kernel-reported superblock source.
    pub superblock_source: OsString,
    /// UID idmap extents when supported by the running kernel.
    pub uid_map: Option<Vec<String>>,
    /// GID idmap extents when supported by the running kernel.
    pub gid_map: Option<Vec<String>>,
}

/// A mount-topology query bound to the current or a pinned mount namespace.
#[derive(Clone, Copy, Debug)]
pub struct MountNamespace<'a> {
    namespace: Option<&'a NamespaceFd>,
}

impl MountNamespace<'static> {
    /// Selects the calling thread's current mount namespace.
    #[must_use]
    pub const fn current() -> Self {
        Self { namespace: None }
    }
}

impl<'a> MountNamespace<'a> {
    /// Selects an explicitly pinned mount namespace.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidInput`] if `namespace` is not attested as a
    /// mount namespace.
    pub fn pinned(namespace: &'a NamespaceFd) -> Result<Self> {
        if namespace.kind() != NamespaceKind::Mount {
            return Err(Error::invalid(
                "mount namespace",
                "descriptor kind is not mount",
            ));
        }
        Ok(Self {
            namespace: Some(namespace),
        })
    }

    /// Lists a bounded page of mounts below `parent`.
    ///
    /// `parent = None` selects the namespace root. A non-empty full page uses
    /// its final mount ID as the next cursor.
    ///
    /// # Errors
    ///
    /// Returns an error for a zero or excessive limit, invalid namespace fd,
    /// stale cursor, malformed kernel IDs, access denial, or syscall failure.
    pub fn list(
        self,
        parent: Option<MountId>,
        after: Option<MountId>,
        limit: usize,
    ) -> Result<MountIdPage> {
        self.list_ordered(parent, after, limit, MountListOrder::Forward)
    }

    /// Lists a bounded page of mounts below `parent` in an explicit order.
    ///
    /// `MountListOrder::Reverse` requests `LISTMOUNT_REVERSE`, which visits
    /// later mounts before earlier mounts and is available on the AOS Linux
    /// 6.18 baseline. Pagination cursors are order-specific and must not be
    /// reused with the opposite order.
    ///
    /// # Errors
    ///
    /// Returns an error for a zero or excessive limit, invalid namespace fd,
    /// stale or order-mismatched cursor, unsupported reverse traversal,
    /// malformed kernel IDs, access denial, or syscall failure.
    pub fn list_ordered(
        self,
        parent: Option<MountId>,
        after: Option<MountId>,
        limit: usize,
        order: MountListOrder,
    ) -> Result<MountIdPage> {
        if !(1..=MAX_LIST_PAGE).contains(&limit) {
            return Err(Error::invalid(
                "listmount limit",
                format!("must be in 1..={MAX_LIST_PAGE}"),
            ));
        }
        let request = self.request(
            parent.map_or(LSMT_ROOT, MountId::get),
            after.map_or(0, MountId::get),
        )?;
        let mut raw_ids = vec![0; limit];
        let flags = match order {
            MountListOrder::Forward => 0,
            MountListOrder::Reverse => LISTMOUNT_REVERSE,
        };
        let count = uapi::listmount(&request, &mut raw_ids, flags)?;
        if count > raw_ids.len() {
            return Err(malformed("kernel returned more mount IDs than requested"));
        }
        raw_ids.truncate(count);
        let mounts = raw_ids
            .into_iter()
            .map(MountId::new)
            .collect::<Result<Vec<_>>>()?;
        let may_have_more = mounts.len() == limit;
        let next_after = may_have_more.then(|| mounts.last().copied()).flatten();
        Ok(MountIdPage {
            mounts,
            next_after,
            may_have_more,
        })
    }

    /// Reads and validates mount identity, attributes, paths, and idmaps.
    ///
    /// # Errors
    ///
    /// Returns an error for a stale/foreign mount ID, access denial, syscall
    /// failure, missing requested fields, inconsistent IDs, or malformed
    /// variable-length output.
    pub fn observe(self, mount: MountId) -> Result<MountObservation> {
        let request = self.request(mount.get(), OBSERVATION_MASK)?;
        let observation = uapi::statmount(&request)?;
        decode_observation(mount, observation.as_ref())
    }

    /// Lists and observes a complete mount namespace within a hard bound.
    ///
    /// This method follows `listmount(2)` cursors until the kernel returns an
    /// empty page, then resolves every unique ID through `statmount(2)`. It is
    /// suitable for correlating mounts that report the same mountpoint without
    /// assuming that a mount's parent ID encodes overmount stack order.
    ///
    /// `maximum_mounts` is an admission bound rather than a truncation limit.
    /// The method probes for another ID after reaching the bound and fails
    /// closed if the namespace contains more mounts. Concurrent topology
    /// changes that repeat IDs, invalidate cursors, or remove mounts also fail
    /// rather than producing a partial inventory. Callers that require a
    /// coherent mutation proof must additionally serialize namespace changes.
    ///
    /// # Errors
    ///
    /// Returns an error for a zero or excessive bound, an inventory exceeding
    /// the admitted bound, repeated kernel IDs, stale cursors or mount IDs,
    /// malformed observations, access denial, or syscall failure.
    pub fn inventory(self, maximum_mounts: usize, order: MountListOrder) -> Result<MountInventory> {
        if !(1..=MAX_INVENTORY_MOUNTS).contains(&maximum_mounts) {
            return Err(Error::invalid(
                "mount inventory limit",
                format!("must be in 1..={MAX_INVENTORY_MOUNTS}"),
            ));
        }

        let mut ids = Vec::with_capacity(maximum_mounts.min(MAX_LIST_PAGE));
        let mut seen = BTreeSet::new();
        let mut after = None;
        loop {
            let remaining = maximum_mounts.saturating_sub(ids.len());
            let page_limit = remaining.saturating_add(1).min(MAX_LIST_PAGE);
            let page = self.list_ordered(None, after, page_limit, order)?;
            if page.mounts.is_empty() {
                break;
            }
            for mount in page.mounts {
                if !seen.insert(mount) {
                    return Err(malformed("listmount repeated a mount ID"));
                }
                if ids.len() == maximum_mounts {
                    return Err(Error::ObservationLimitExceeded {
                        object: "mount inventory",
                        limit: maximum_mounts,
                    });
                }
                ids.push(mount);
            }
            after = ids.last().copied();
        }

        let mounts = ids
            .into_iter()
            .map(|mount| self.observe(mount))
            .collect::<Result<Vec<_>>>()?;
        Ok(MountInventory { mounts })
    }

    fn request(self, mount_id: u64, parameter: u64) -> Result<MountIdRequest> {
        let (size, mount_namespace_fd) = match self.namespace {
            Some(namespace) => (
                REQUEST_SIZE_NAMESPACE_FD,
                descriptor_u32(namespace.as_fd().as_raw_fd())?,
            ),
            None => (REQUEST_SIZE_CURRENT_NAMESPACE, 0),
        };
        Ok(MountIdRequest {
            size,
            mount_namespace_fd,
            mount_id,
            parameter,
            mount_namespace_id: 0,
        })
    }
}

fn descriptor_u32(fd: RawFd) -> Result<u32> {
    u32::try_from(fd).map_err(|_| Error::invalid("mount namespace", "descriptor is negative"))
}

fn decode_observation(requested: MountId, buffer: &StatMountBuffer) -> Result<MountObservation> {
    let header = &buffer.header;
    let header_bytes = std::mem::size_of_val(header);
    let total_bytes =
        usize::try_from(header.size).map_err(|_| malformed("returned size does not fit usize"))?;
    if total_bytes < header_bytes || total_bytes > std::mem::size_of_val(buffer) {
        return Err(malformed(format!(
            "returned size {total_bytes} is outside {header_bytes}..={} bytes",
            std::mem::size_of_val(buffer)
        )));
    }
    if header.mask & REQUIRED_OBSERVATION_MASK != REQUIRED_OBSERVATION_MASK {
        return Err(malformed(format!(
            "kernel omitted requested mask bits {:#x}",
            REQUIRED_OBSERVATION_MASK & !header.mask
        )));
    }
    let mount_id = MountId::new(header.mount_id)?;
    if mount_id != requested {
        return Err(malformed(format!(
            "requested mount {} but kernel returned {}",
            requested.get(),
            mount_id.get()
        )));
    }
    let strings_used = total_bytes - header_bytes;
    let strings = &buffer.strings[..strings_used];
    Ok(MountObservation {
        mount_id,
        parent_mount_id: MountId::new(header.parent_mount_id)?,
        mount_namespace_id: header.mount_namespace_id,
        device_major: header.device_major,
        device_minor: header.device_minor,
        superblock_magic: header.superblock_magic,
        superblock_flags: header.superblock_flags,
        mount_attributes: header.mount_attributes,
        propagation: header.propagation,
        supported_mask: (header.mask & STATMOUNT_SUPPORTED_MASK != 0)
            .then_some(header.supported_mask),
        root: decode_os_string(strings, header.mount_root, "mount root")?,
        mount_point: decode_os_string(strings, header.mount_point, "mount point")?,
        filesystem_type: decode_os_string(strings, header.filesystem_type, "filesystem type")?,
        superblock_source: decode_os_string(
            strings,
            header.superblock_source,
            "superblock source",
        )?,
        uid_map: if header.mask & STATMOUNT_MNT_UIDMAP != 0 {
            Some(decode_string_array(
                strings,
                header.uid_map,
                header.uid_map_count,
                "UID map",
            )?)
        } else {
            None
        },
        gid_map: if header.mask & STATMOUNT_MNT_GIDMAP != 0 {
            Some(decode_string_array(
                strings,
                header.gid_map,
                header.gid_map_count,
                "GID map",
            )?)
        } else {
            None
        },
    })
}

fn decode_os_string(bytes: &[u8], offset: u32, field: &'static str) -> Result<OsString> {
    let offset =
        usize::try_from(offset).map_err(|_| malformed(format!("{field} offset overflow")))?;
    let tail = bytes
        .get(offset..)
        .ok_or_else(|| malformed(format!("{field} offset is outside string data")))?;
    let length = tail
        .iter()
        .position(|byte| *byte == 0)
        .ok_or_else(|| malformed(format!("{field} is not NUL terminated")))?;
    Ok(OsString::from_vec(tail[..length].to_vec()))
}

fn decode_string_array(
    bytes: &[u8],
    offset: u32,
    count: u32,
    field: &'static str,
) -> Result<Vec<String>> {
    let count = usize::try_from(count).map_err(|_| malformed(format!("{field} count overflow")))?;
    if count > MAX_IDMAP_EXTENTS {
        return Err(malformed(format!(
            "{field} has {count} extents, limit is {MAX_IDMAP_EXTENTS}"
        )));
    }
    if count == 0 {
        return Ok(Vec::new());
    }
    let mut cursor =
        usize::try_from(offset).map_err(|_| malformed(format!("{field} offset overflow")))?;
    let mut output = Vec::with_capacity(count);
    for _ in 0..count {
        let tail = bytes
            .get(cursor..)
            .ok_or_else(|| malformed(format!("{field} offset is outside string data")))?;
        let length = tail
            .iter()
            .position(|byte| *byte == 0)
            .ok_or_else(|| malformed(format!("{field} entry is not NUL terminated")))?;
        output.push(
            String::from_utf8(tail[..length].to_vec())
                .map_err(|_| malformed(format!("{field} entry is not UTF-8")))?,
        );
        cursor = cursor
            .checked_add(length + 1)
            .ok_or_else(|| malformed(format!("{field} offset overflow")))?;
    }
    Ok(output)
}

fn malformed(message: impl Into<String>) -> Error {
    Error::MalformedKernelResponse {
        object: "statmount/listmount",
        message: message.into(),
    }
}

#[cfg(test)]
mod tests {
    use std::fs::File;
    use std::os::fd::AsFd as _;

    use super::*;

    #[test]
    fn mount_ids_reject_sentinels() {
        assert!(MountId::new(0).is_err());
        assert!(MountId::new(LSMT_ROOT).is_err());
        assert_eq!(MountId::new(7).unwrap().get(), 7);
    }

    #[test]
    fn list_limits_are_bounded_before_syscall() {
        let current = MountNamespace::current();
        assert!(current.list(None, None, 0).is_err());
        assert!(current.list(None, None, MAX_LIST_PAGE + 1).is_err());
        assert!(current.inventory(0, MountListOrder::Forward).is_err());
        assert!(
            current
                .inventory(MAX_INVENTORY_MOUNTS + 1, MountListOrder::Forward)
                .is_err()
        );
    }

    #[test]
    fn descriptor_mount_ids_are_unique_and_stable() {
        let root = File::open("/").unwrap();
        let first = MountId::from_fd(root.as_fd()).unwrap();
        let second = MountId::from_fd(root.as_fd()).unwrap();
        assert_eq!(first, second);
        assert_ne!(first.get(), 0);
    }

    #[test]
    fn string_decoder_preserves_bytes_and_rejects_bad_bounds() {
        assert_eq!(decode_os_string(b"root\0tail", 0, "test").unwrap(), "root");
        assert!(decode_os_string(b"root", 0, "test").is_err());
        assert!(decode_os_string(b"x\0", 3, "test").is_err());
        assert_eq!(
            decode_os_string(&[0xff, 0], 0, "test").unwrap().into_vec(),
            vec![0xff]
        );
    }

    #[test]
    fn idmap_decoder_enforces_count_and_extent_bounds() {
        assert_eq!(
            decode_string_array(b"0 1 2\x001 3 4\x00", 0, 2, "map").unwrap(),
            vec!["0 1 2", "1 3 4"]
        );
        let excessive_count = u32::try_from(MAX_IDMAP_EXTENTS + 1).unwrap();
        assert!(decode_string_array(b"x\0", 0, excessive_count, "map").is_err());
        assert!(decode_string_array(b"x", 0, 1, "map").is_err());
    }

    #[test]
    fn current_namespace_round_trips_when_kernel_permits_inventory() {
        let namespace = MountNamespace::current();
        match namespace.list(None, None, 16) {
            Ok(page) => {
                assert!(!page.mounts.is_empty());
                let observation = namespace.observe(page.mounts[0]).unwrap();
                assert_eq!(observation.mount_id, page.mounts[0]);
                assert!(!observation.mount_point.is_empty());
                assert!(!observation.filesystem_type.is_empty());
            }
            Err(Error::Syscall { source, .. })
                if matches!(
                    source.raw_os_error(),
                    Some(libc::ENOSYS | libc::EINVAL | libc::EPERM | libc::EACCES)
                ) => {}
            Err(error) => panic!("unexpected mount inventory failure: {error}"),
        }
    }
}
