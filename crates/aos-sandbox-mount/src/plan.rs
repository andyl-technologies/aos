//! Fixed, checksummed, sealed mount-helper plans.
//!
//! The long-lived broker compiles one closed action and exact descriptor-role
//! bitmap into this format, writes it to a sealable memfd, and adds all four
//! content seals before spawning the helper. The helper rejects unknown bits,
//! noncanonical paths, sentinels, trailing bytes, checksum failure, and any
//! memfd missing a required seal.
//!
//! ```text
//! header | identities | effect-deadline | target-relative-path | sha256
//! ```

use std::io::{Read as _, Seek as _, SeekFrom, Write as _};
use std::os::fd::{AsFd, OwnedFd};
use std::os::unix::ffi::OsStringExt as _;
use std::path::{Component, PathBuf};

use aos_sandbox_linux::path::FileIdentity;
use aos_sandbox_linux::pidfd::NamespaceIdentity;
use rustix::fs::{MemfdFlags, SealFlags, fcntl_add_seals, fcntl_get_seals, memfd_create};
use sha2::{Digest as _, Sha256};

use crate::{MountError, Result};

const MAGIC: &[u8; 8] = b"AOSMNT01";
const VERSION: u16 = 5;
const FIXED_PREFIX_BYTES: usize =
    8 + 2 + 1 + 1 + 8 + 8 + 8 + 8 + 16 + 16 + 32 + (11 * 8) + 16 + 16 + 8 + 2;
const CHECKSUM_BYTES: usize = 32;
const MAXIMUM_TARGET_PATH_BYTES: usize = 4096;
const MAXIMUM_PLAN_BYTES: usize = FIXED_PREFIX_BYTES + MAXIMUM_TARGET_PATH_BYTES + CHECKSUM_BYTES;
const REQUIRED_SEALS: SealFlags = SealFlags::SHRINK
    .union(SealFlags::GROW)
    .union(SealFlags::WRITE)
    .union(SealFlags::SEAL);

/// Selects the only namespace-helper programs.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum HelperAction {
    /// Observes the target without mutation.
    Observe = 1,
    /// Installs a detached mount at an empty destination.
    Install = 2,
    /// Inserts beneath and detaches the former top mount.
    Replace = 3,
    /// Detaches the exact installed mount.
    Detach = 4,
}

/// Describes the exact inherited descriptor set accepted by a helper.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DescriptorRoles(u8);

impl DescriptorRoles {
    /// Detached mount descriptor.
    pub const DETACHED_MOUNT: u8 = 1 << 0;
    /// Payload mount namespace descriptor.
    pub const MOUNT_NAMESPACE: u8 = 1 << 1;
    /// Pinned payload root descriptor.
    pub const TARGET_ROOT: u8 = 1 << 2;
    /// Pre-effect destination-slot descriptor.
    pub const TARGET_SLOT: u8 = 1 << 3;
    const KNOWN: u8 =
        Self::DETACHED_MOUNT | Self::MOUNT_NAMESPACE | Self::TARGET_ROOT | Self::TARGET_SLOT;

    /// Returns the exact roles required by an action.
    #[must_use]
    pub const fn for_action(action: HelperAction) -> Self {
        let common = Self::MOUNT_NAMESPACE | Self::TARGET_ROOT | Self::TARGET_SLOT;
        match action {
            HelperAction::Observe | HelperAction::Detach => Self(common),
            HelperAction::Install | HelperAction::Replace => Self(common | Self::DETACHED_MOUNT),
        }
    }

    /// Returns the raw closed bitmap for descriptor-table comparison.
    #[must_use]
    pub const fn bits(self) -> u8 {
        self.0
    }

    /// Reports whether one fixed descriptor role is required.
    #[must_use]
    pub const fn contains(self, role: u8) -> bool {
        self.0 & role != 0
    }
}

/// Captures a file descriptor's expected device and inode identity.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ExpectedFileIdentity {
    /// Filesystem device number.
    pub device: u64,
    /// Inode number.
    pub inode: u64,
}

impl From<FileIdentity> for ExpectedFileIdentity {
    fn from(identity: FileIdentity) -> Self {
        Self {
            device: identity.device,
            inode: identity.inode,
        }
    }
}

/// Captures an `nsfs` descriptor's expected device and inode identity.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ExpectedNamespaceIdentity {
    /// `nsfs` device number.
    pub device: u64,
    /// Namespace inode number.
    pub inode: u64,
}

impl From<NamespaceIdentity> for ExpectedNamespaceIdentity {
    fn from(identity: NamespaceIdentity) -> Self {
        Self {
            device: identity.device,
            inode: identity.inode,
        }
    }
}

/// Immutable syscall plan consumed by one helper process.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HelperPlan {
    /// Closed helper action.
    pub action: HelperAction,
    /// Exact required descriptor roles.
    pub roles: DescriptorRoles,
    /// Immutable source generation.
    pub source_generation: u64,
    /// Payload namespace generation.
    pub namespace_generation: u64,
    /// Current desired attachment generation authorizing the effect.
    pub desired_attachment_generation: u64,
    /// Attachment generation of the resource recipe being affected.
    pub resource_attachment_generation: u64,
    /// Attachment identity.
    pub attachment_id: [u8; 16],
    /// Destination-slot identity.
    pub destination_slot_id: [u8; 16],
    /// Digest of the exact admitted request bytes.
    pub request_digest: [u8; 32],
    /// Exact unique mount identity that may be observed or published.
    pub expected_mount_id: u64,
    /// Exact predecessor required before replacement, or zero otherwise.
    pub expected_predecessor_mount_id: u64,
    /// Exact mount identity beneath an absent destination slot.
    pub target_slot_mount_id: u64,
    /// Protected paired-clock reader identity, or zero for observation.
    pub clock_provenance: [u8; 16],
    /// Host boot identity under which a mutation deadline is valid.
    pub host_boot_id: [u8; 16],
    /// Exclusive mutation deadline on `CLOCK_BOOTTIME`, or zero for observation.
    pub effect_deadline_boottime_nanoseconds: u64,
    /// Source-root identity expected after attachment.
    pub source: ExpectedFileIdentity,
    /// Payload mount-namespace identity.
    pub mount_namespace: ExpectedNamespaceIdentity,
    /// Pinned payload-root identity.
    pub target_root: ExpectedFileIdentity,
    /// Pre-effect slot identity.
    pub target_slot: ExpectedFileIdentity,
    /// Catalog-selected path beneath the pinned target root.
    pub target_relative_path: PathBuf,
}

impl HelperPlan {
    /// Validates and encodes one fixed helper plan.
    ///
    /// # Errors
    ///
    /// Returns an error for sentinels, a mismatched role table, or a target
    /// path that is empty, absolute, noncanonical, or overlong.
    pub fn encode(&self) -> Result<Vec<u8>> {
        self.validate()?;
        let path = self.target_relative_path.as_os_str().as_encoded_bytes();
        let path_length = u16::try_from(path.len())
            .map_err(|_| MountError::Worker("helper target path exceeds u16".to_owned()))?;
        let mut bytes = Vec::with_capacity(FIXED_PREFIX_BYTES + path.len() + CHECKSUM_BYTES);
        bytes.extend_from_slice(MAGIC);
        bytes.extend_from_slice(&VERSION.to_le_bytes());
        bytes.push(self.action as u8);
        bytes.push(self.roles.bits());
        bytes.extend_from_slice(&self.source_generation.to_le_bytes());
        bytes.extend_from_slice(&self.namespace_generation.to_le_bytes());
        bytes.extend_from_slice(&self.desired_attachment_generation.to_le_bytes());
        bytes.extend_from_slice(&self.resource_attachment_generation.to_le_bytes());
        bytes.extend_from_slice(&self.attachment_id);
        bytes.extend_from_slice(&self.destination_slot_id);
        bytes.extend_from_slice(&self.request_digest);
        for value in [
            self.source.device,
            self.source.inode,
            self.mount_namespace.device,
            self.mount_namespace.inode,
            self.target_root.device,
            self.target_root.inode,
            self.target_slot.device,
            self.target_slot.inode,
            self.expected_mount_id,
            self.expected_predecessor_mount_id,
            self.target_slot_mount_id,
        ] {
            bytes.extend_from_slice(&value.to_le_bytes());
        }
        bytes.extend_from_slice(&self.clock_provenance);
        bytes.extend_from_slice(&self.host_boot_id);
        bytes.extend_from_slice(&self.effect_deadline_boottime_nanoseconds.to_le_bytes());
        bytes.extend_from_slice(&path_length.to_le_bytes());
        bytes.extend_from_slice(path);
        let checksum = Sha256::digest(&bytes);
        bytes.extend_from_slice(&checksum);
        Ok(bytes)
    }

    /// Decodes and validates one bounded fixed helper plan.
    ///
    /// # Errors
    ///
    /// Returns an error for bad framing, checksum, version, action, roles,
    /// reserved fields, identities, generations, or target path.
    pub fn decode(bytes: &[u8]) -> Result<Self> {
        if bytes.len() < FIXED_PREFIX_BYTES + CHECKSUM_BYTES || bytes.len() > MAXIMUM_PLAN_BYTES {
            return Err(invalid_plan("helper plan length is invalid"));
        }
        let payload_length = bytes.len() - CHECKSUM_BYTES;
        if Sha256::digest(&bytes[..payload_length]).as_slice() != &bytes[payload_length..] {
            return Err(invalid_plan("helper plan checksum differs"));
        }
        let mut decoder = Decoder::new(&bytes[..payload_length]);
        if decoder.take(8)? != MAGIC || decoder.u16()? != VERSION {
            return Err(invalid_plan("helper plan magic or version is unknown"));
        }
        let action = match decoder.u8()? {
            1 => HelperAction::Observe,
            2 => HelperAction::Install,
            3 => HelperAction::Replace,
            4 => HelperAction::Detach,
            _ => return Err(invalid_plan("helper action is unknown")),
        };
        let roles = DescriptorRoles(decoder.u8()?);
        if roles.0 & !DescriptorRoles::KNOWN != 0 || roles != DescriptorRoles::for_action(action) {
            return Err(invalid_plan("helper descriptor roles do not match action"));
        }
        let mut plan = Self {
            action,
            roles,
            source_generation: decoder.u64()?,
            namespace_generation: decoder.u64()?,
            desired_attachment_generation: decoder.u64()?,
            resource_attachment_generation: decoder.u64()?,
            attachment_id: decoder.array()?,
            destination_slot_id: decoder.array()?,
            request_digest: decoder.array()?,
            expected_mount_id: 0,
            expected_predecessor_mount_id: 0,
            target_slot_mount_id: 0,
            clock_provenance: [0; 16],
            host_boot_id: [0; 16],
            effect_deadline_boottime_nanoseconds: 0,
            source: ExpectedFileIdentity {
                device: decoder.u64()?,
                inode: decoder.u64()?,
            },
            mount_namespace: ExpectedNamespaceIdentity {
                device: decoder.u64()?,
                inode: decoder.u64()?,
            },
            target_root: ExpectedFileIdentity {
                device: decoder.u64()?,
                inode: decoder.u64()?,
            },
            target_slot: ExpectedFileIdentity {
                device: decoder.u64()?,
                inode: decoder.u64()?,
            },
            target_relative_path: PathBuf::new(),
        };
        plan.expected_mount_id = decoder.u64()?;
        plan.expected_predecessor_mount_id = decoder.u64()?;
        plan.target_slot_mount_id = decoder.u64()?;
        plan.clock_provenance = decoder.array()?;
        plan.host_boot_id = decoder.array()?;
        plan.effect_deadline_boottime_nanoseconds = decoder.u64()?;
        let path_length = usize::from(decoder.u16()?);
        let path = decoder.take(path_length)?;
        if !decoder.remaining().is_empty() {
            return Err(invalid_plan("helper plan has trailing bytes"));
        }
        plan.target_relative_path = PathBuf::from(std::ffi::OsString::from_vec(path.to_vec()));
        plan.validate()?;
        Ok(plan)
    }

    fn validate(&self) -> Result<()> {
        if self.roles != DescriptorRoles::for_action(self.action)
            || self.source_generation == 0
            || self.namespace_generation == 0
            || self.desired_attachment_generation == 0
            || self.resource_attachment_generation == 0
            || self.attachment_id == [0; 16]
            || self.destination_slot_id == [0; 16]
            || self.request_digest == [0; 32]
            || self.expected_mount_id == 0
            || self.target_slot_mount_id == 0
            || [
                self.source.device,
                self.source.inode,
                self.mount_namespace.device,
                self.mount_namespace.inode,
                self.target_root.device,
                self.target_root.inode,
                self.target_slot.device,
                self.target_slot.inode,
            ]
            .contains(&0)
        {
            return Err(invalid_plan("helper plan contains a sentinel"));
        }
        if self.desired_attachment_generation < self.resource_attachment_generation {
            return Err(invalid_plan(
                "helper resource generation is newer than desired state",
            ));
        }
        let predecessor_valid = match self.action {
            HelperAction::Replace => self.expected_predecessor_mount_id != 0,
            HelperAction::Observe => true,
            HelperAction::Install | HelperAction::Detach => self.expected_predecessor_mount_id == 0,
        };
        if !predecessor_valid {
            return Err(invalid_plan(
                "helper predecessor identity does not match action",
            ));
        }
        let deadline_valid = match self.action {
            HelperAction::Observe => {
                self.clock_provenance == [0; 16]
                    && self.host_boot_id == [0; 16]
                    && self.effect_deadline_boottime_nanoseconds == 0
            }
            HelperAction::Install | HelperAction::Replace | HelperAction::Detach => {
                self.clock_provenance != [0; 16]
                    && self.host_boot_id != [0; 16]
                    && self.effect_deadline_boottime_nanoseconds != 0
            }
        };
        if !deadline_valid {
            return Err(invalid_plan(
                "helper effect deadline does not match the action",
            ));
        }
        let path = &self.target_relative_path;
        if path.as_os_str().as_encoded_bytes().len() > MAXIMUM_TARGET_PATH_BYTES
            || path.as_os_str().is_empty()
            || path.is_absolute()
            || path
                .as_os_str()
                .as_encoded_bytes()
                .split(|byte| *byte == b'/')
                .any(|component| component.is_empty() || matches!(component, b"." | b".."))
            || path
                .components()
                .any(|component| !matches!(component, Component::Normal(_)))
        {
            return Err(invalid_plan(
                "helper target path is not canonical and relative",
            ));
        }
        Ok(())
    }
}

/// Owns a fully content-sealed plan memfd positioned at byte zero.
#[derive(Debug)]
pub struct SealedHelperPlan {
    fd: OwnedFd,
}

impl SealedHelperPlan {
    /// Encodes a plan into a new memfd and irreversibly seals its contents.
    ///
    /// # Errors
    ///
    /// Returns an error for invalid plan data or any memfd write/seal failure.
    pub fn create(plan: &HelperPlan) -> Result<Self> {
        let bytes = plan.encode()?;
        let fd = memfd_create(
            "aos-sandbox-mount-plan",
            MemfdFlags::CLOEXEC | MemfdFlags::ALLOW_SEALING,
        )
        .map_err(plan_io)?;
        let mut file = std::fs::File::from(fd);
        file.write_all(&bytes).map_err(plan_io_std)?;
        file.sync_data().map_err(plan_io_std)?;
        fcntl_add_seals(&file, REQUIRED_SEALS).map_err(plan_io)?;
        file.seek(SeekFrom::Start(0)).map_err(plan_io_std)?;
        Ok(Self { fd: file.into() })
    }

    /// Borrows the sealed plan descriptor for helper inheritance.
    #[must_use]
    pub fn as_fd(&self) -> std::os::fd::BorrowedFd<'_> {
        self.fd.as_fd()
    }

    /// Reads and validates a plan from an inherited, fully sealed memfd.
    ///
    /// # Errors
    ///
    /// Returns an error if any required seal is absent, the input exceeds the
    /// fixed bound, reading fails, or plan decoding fails.
    pub fn read_inherited(fd: OwnedFd) -> Result<HelperPlan> {
        let seals = fcntl_get_seals(&fd).map_err(plan_io)?;
        if !seals.contains(REQUIRED_SEALS) {
            return Err(invalid_plan("helper plan memfd lacks content seals"));
        }
        let mut file = std::fs::File::from(fd);
        file.seek(SeekFrom::Start(0)).map_err(plan_io_std)?;
        let mut bytes = Vec::with_capacity(MAXIMUM_PLAN_BYTES + 1);
        file.take((MAXIMUM_PLAN_BYTES + 1) as u64)
            .read_to_end(&mut bytes)
            .map_err(plan_io_std)?;
        if bytes.len() > MAXIMUM_PLAN_BYTES {
            return Err(invalid_plan("helper plan exceeds its byte bound"));
        }
        HelperPlan::decode(&bytes)
    }
}

struct Decoder<'a> {
    bytes: &'a [u8],
    cursor: usize,
}

impl<'a> Decoder<'a> {
    const fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, cursor: 0 }
    }
    fn take(&mut self, count: usize) -> Result<&'a [u8]> {
        let end = self
            .cursor
            .checked_add(count)
            .ok_or_else(|| invalid_plan("helper plan offset overflow"))?;
        let value = self
            .bytes
            .get(self.cursor..end)
            .ok_or_else(|| invalid_plan("helper plan is truncated"))?;
        self.cursor = end;
        Ok(value)
    }
    fn u8(&mut self) -> Result<u8> {
        Ok(self.take(1)?[0])
    }
    fn u16(&mut self) -> Result<u16> {
        Ok(u16::from_le_bytes(self.array()?))
    }
    fn u64(&mut self) -> Result<u64> {
        Ok(u64::from_le_bytes(self.array()?))
    }
    fn array<const N: usize>(&mut self) -> Result<[u8; N]> {
        self.take(N)?
            .try_into()
            .map_err(|_| invalid_plan("helper plan field is truncated"))
    }
    fn remaining(&self) -> &'a [u8] {
        &self.bytes[self.cursor..]
    }
}

fn invalid_plan(message: &str) -> MountError {
    MountError::Worker(message.to_owned())
}
fn plan_io(error: rustix::io::Errno) -> MountError {
    MountError::Worker(error.to_string())
}
fn plan_io_std(error: std::io::Error) -> MountError {
    let message = error.to_string();
    drop(error);
    MountError::Worker(message)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::*;

    fn plan() -> HelperPlan {
        HelperPlan {
            action: HelperAction::Replace,
            roles: DescriptorRoles::for_action(HelperAction::Replace),
            source_generation: 7,
            namespace_generation: 9,
            desired_attachment_generation: 10,
            resource_attachment_generation: 9,
            attachment_id: [1; 16],
            destination_slot_id: [2; 16],
            request_digest: [3; 32],
            expected_mount_id: 12,
            expected_predecessor_mount_id: 13,
            target_slot_mount_id: 14,
            clock_provenance: [15; 16],
            host_boot_id: [16; 16],
            effect_deadline_boottime_nanoseconds: 17,
            source: ExpectedFileIdentity {
                device: 4,
                inode: 5,
            },
            mount_namespace: ExpectedNamespaceIdentity {
                device: 6,
                inode: 7,
            },
            target_root: ExpectedFileIdentity {
                device: 8,
                inode: 9,
            },
            target_slot: ExpectedFileIdentity {
                device: 10,
                inode: 11,
            },
            target_relative_path: PathBuf::from("run/aos/attachments/slot"),
        }
    }

    #[test]
    fn fixed_plan_round_trips_and_rejects_tampering() {
        let encoded = plan().encode().unwrap();
        assert_eq!(HelperPlan::decode(&encoded).unwrap(), plan());
        let mut tampered = encoded;
        tampered[20] ^= 1;
        assert!(HelperPlan::decode(&tampered).is_err());
    }

    #[test]
    fn sealed_memfd_round_trips_and_cannot_be_written() {
        let sealed = SealedHelperPlan::create(&plan()).unwrap();
        let duplicate = rustix::io::dup(sealed.as_fd()).unwrap();
        assert_eq!(SealedHelperPlan::read_inherited(duplicate).unwrap(), plan());
        assert!(rustix::io::write(sealed.as_fd(), b"x").is_err());
    }

    #[test]
    fn helper_target_path_rejects_noncanonical_components() {
        for invalid in ["", "/slot", "../slot", "a/../slot", "a//slot", "./slot"] {
            let mut candidate = plan();
            candidate.target_relative_path = PathBuf::from(invalid);
            assert!(candidate.encode().is_err(), "accepted {invalid:?}");
        }
    }
}
