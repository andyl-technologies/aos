//! Retains the existing Guardian credential checker's actual native prefix.
//!
//! The caller supplies already-held descriptors. This owner provides no trust,
//! key, launch, ledger or service-manager authority. Ordinary construction and
//! retained construction use the same role validation and duplication engine.

use std::fs::File;
use std::os::fd::{AsFd as _, BorrowedFd, OwnedFd};

use super::{
    GuardianCredentialDescriptor, GuardianCredentialDescriptors, GuardianCredentialRole,
    GuardianDescriptorSnapshot, invalid,
};
use crate::error::Result;

#[derive(Debug, Default)]
pub(super) struct DescriptorCheckOriginalV2 {
    metadata: [Option<std::result::Result<rustix::fs::Stat, rustix::io::Errno>>; 2],
    flags: Option<std::result::Result<rustix::fs::OFlags, rustix::io::Errno>>,
    seals: Option<std::result::Result<rustix::fs::SealFlags, rustix::io::Errno>>,
    file: Option<std::io::Result<File>>,
    read_error: Option<std::io::Error>,
}

impl DescriptorCheckOriginalV2 {
    pub(super) fn failure(&self) -> Option<&(dyn std::error::Error + 'static)> {
        native_error(&self.metadata[0])
            .or_else(|| native_error(&self.flags))
            .or_else(|| native_error(&self.seals))
            .or_else(|| native_error(&self.file))
            .or_else(|| self.read_error.as_ref().map(|cause| cause as _))
            .or_else(|| native_error(&self.metadata[1]))
    }
}

fn native_error<T, E: std::error::Error + 'static>(
    slot: &Option<std::result::Result<T, E>>,
) -> Option<&(dyn std::error::Error + 'static)> {
    slot.as_ref()?.as_ref().err().map(|cause| cause as _)
}

/// Retains native checks and pinned descriptors for one exact ten-role set.
///
/// Completed pin entries share the same underlying descriptor through an Arc;
/// the representation never duplicates a file merely to report a failure.
#[derive(Debug)]
pub struct GuardianCredentialAcquisitionOriginalV2 {
    checks: [DescriptorCheckOriginalV2; 10],
    duplicates: [Option<std::io::Result<OwnedFd>>; 10],
    pins: [Option<GuardianCredentialDescriptor>; 10],
    map: std::collections::BTreeMap<GuardianCredentialRole, GuardianCredentialDescriptor>,
    entered: bool,
    returned: Option<Result<()>>,
}

impl GuardianCredentialAcquisitionOriginalV2 {
    /// Constructs an inert destination without IO or resource admission.
    #[must_use]
    pub fn new() -> Self {
        Self {
            checks: std::array::from_fn(|_| DescriptorCheckOriginalV2::default()),
            duplicates: std::array::from_fn(|_| None),
            pins: std::array::from_fn(|_| None),
            map: std::collections::BTreeMap::new(),
            entered: false,
            returned: None,
        }
    }

    /// Bounds construction bytes, simultaneous files and logical role entries.
    ///
    /// The enclosing role must admit this passive geometry before constructing
    /// the owner. Input descriptors and later transferred aliases are separate.
    #[must_use]
    pub fn receiving_obligations_v2() -> Option<(usize, usize, usize)> {
        // One complete conservative BTree node per logical role. Key/value
        // heaps are absent; each value's Arc allocation is counted separately.
        let node = 11_usize.checked_mul(
            std::mem::size_of::<GuardianCredentialRole>()
                .checked_add(std::mem::size_of::<GuardianCredentialDescriptor>())?
                .checked_add(std::mem::align_of::<GuardianCredentialRole>())?
                .checked_add(std::mem::align_of::<GuardianCredentialDescriptor>())?,
        )?.checked_add(16_usize.checked_mul(std::mem::size_of::<usize>())?)?;
        let map = node.checked_mul(10)?;
        let arcs = 10_usize.checked_mul(
            std::mem::size_of::<OwnedFd>()
                .checked_add(2 * std::mem::size_of::<usize>())?
                .checked_add(std::mem::align_of::<OwnedFd>())?
                .checked_add(std::mem::align_of::<usize>())?,
        )?;
        let entries = std::mem::size_of::<Vec<(GuardianCredentialRole, BorrowedFd<'static>)>>()
            .checked_mul(2)?
            .checked_add(10_usize.checked_mul(
                std::mem::size_of::<(GuardianCredentialRole, BorrowedFd<'static>)>(),
            )?)?;
        let largest = usize::try_from(super::MAXIMUM_PLAN_BYTES).ok()?;
        let bytes = std::mem::size_of::<Self>().checked_mul(2)?
            .checked_add(map)?
            .checked_add(arcs)?
            .checked_add(entries)?
            .checked_add(largest.checked_mul(2)?)?;
        // Ten reached final pins coexist with at most one validation File.
        // A failed validation stops the loop, preserving that original File.
        Some((bytes, 11, 10))
    }

    /// Borrows the actual first failed native observation or returned error.
    #[must_use]
    pub fn failure(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.checks.iter().zip(&self.duplicates)
            .find_map(|(check, duplicate)| check.failure().or_else(|| native_error(duplicate)))
            .or_else(|| native_error(&self.returned))
    }
}

impl Default for GuardianCredentialAcquisitionOriginalV2 {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(target_os = "linux")]
fn validate_descriptor_engine(
    role: GuardianCredentialRole,
    descriptor: BorrowedFd<'_>,
    original: &mut DescriptorCheckOriginalV2,
) -> Result<GuardianDescriptorSnapshot> {
    use rustix::fs::{FileType, OFlags, SealFlags, fcntl_get_seals, fcntl_getfl, fstat};
    use sha2::{Digest as _, Sha256};
    use std::fs::File;

    const REQUIRED_SEALS: SealFlags = SealFlags::SEAL
        .union(SealFlags::SHRINK)
        .union(SealFlags::GROW)
        .union(SealFlags::WRITE);

    original.metadata[0] = Some(fstat(descriptor));
    let metadata = match original.metadata[0].as_ref() {
        Some(Ok(metadata)) => *metadata,
        Some(Err(error)) => return Err(invalid(format!("cannot inspect guardian descriptor: {error}"))),
        None => std::process::abort(),
    };
    let bytes = u64::try_from(metadata.st_size)
        .ok()
        .filter(|bytes| *bytes > 0 && *bytes <= role.maximum_bytes())
        .ok_or_else(|| invalid("guardian descriptor size is invalid"))?;
    if FileType::from_raw_mode(metadata.st_mode) != FileType::RegularFile
        || metadata.st_uid != rustix::process::geteuid().as_raw()
        || {
            original.flags = Some(fcntl_getfl(descriptor));
            match original.flags.as_ref() {
                Some(Ok(flags)) => *flags,
                Some(Err(error)) => return Err(invalid(format!("cannot read guardian descriptor flags: {error}"))),
                None => std::process::abort(),
            }
        } & OFlags::ACCMODE
            != OFlags::RDONLY
    {
        return Err(invalid(
            "guardian descriptor type, owner, or access mode is invalid",
        ));
    }
    if role.is_dynamic() {
        original.seals = Some(fcntl_get_seals(descriptor));
        let seals = match original.seals.as_ref() {
            Some(Ok(seals)) => *seals,
            Some(Err(_)) => return Err(invalid("guardian dynamic descriptor is not a sealable memfd")),
            None => std::process::abort(),
        };
        if metadata.st_nlink != 0 || !seals.contains(REQUIRED_SEALS) {
            return Err(invalid(
                "guardian dynamic descriptor is not anonymous and fully sealed",
            ));
        }
    } else if metadata.st_nlink != 1 || !matches!(metadata.st_mode & 0o7777, 0o400 | 0o600) {
        return Err(invalid(
            "guardian static descriptor is not a protected singly-linked file",
        ));
    }

    let length = usize::try_from(bytes)
        .map_err(|_| invalid("guardian descriptor size does not fit memory"))?;
    original.file = Some(descriptor.try_clone_to_owned().map(File::from));
    let file = match original.file.as_ref() {
        Some(Ok(file)) => file,
        Some(Err(error)) => return Err(invalid(format!("cannot duplicate guardian descriptor: {error}"))),
        None => std::process::abort(),
    };
    let content = read_guardian_descriptor(file, length, &mut original.read_error)?;
    if !role.is_dynamic() && read_guardian_descriptor(file, length, &mut original.read_error)? != content {
        return Err(invalid(
            "guardian static descriptor changed during exact readback",
        ));
    }
    original.metadata[1] = Some(fstat(descriptor));
    let after = match original.metadata[1].as_ref() {
        Some(Ok(metadata)) => *metadata,
        Some(Err(error)) => return Err(invalid(format!("cannot recheck guardian descriptor: {error}"))),
        None => std::process::abort(),
    };
    if after.st_dev != metadata.st_dev
        || after.st_ino != metadata.st_ino
        || after.st_size != metadata.st_size
        || after.st_mtime != metadata.st_mtime
        || after.st_mtime_nsec != metadata.st_mtime_nsec
        || after.st_ctime != metadata.st_ctime
        || after.st_ctime_nsec != metadata.st_ctime_nsec
    {
        return Err(invalid("guardian descriptor changed during exact readback"));
    }

    Ok(GuardianDescriptorSnapshot {
        device: metadata.st_dev,
        inode: metadata.st_ino,
        bytes,
        sha256: Sha256::digest(content).into(),
    })
}

#[cfg(target_os = "linux")]
fn read_guardian_descriptor(
    file: &std::fs::File,
    length: usize,
    native_error: &mut Option<std::io::Error>,
) -> Result<Vec<u8>> {
    use std::os::unix::fs::FileExt as _;

    let mut content = vec![0; length];
    let mut offset = 0;
    while offset < content.len() {
        let read = file
            .read_at(&mut content[offset..], offset as u64)
            .map_err(|error| {
                let returned = invalid(format!("cannot read guardian descriptor: {error}"));
                *native_error = Some(error);
                returned
            })?;
        if read == 0 {
            return Err(invalid(
                "guardian descriptor ended before its declared size",
            ));
        }
        offset += read;
    }
    Ok(content)
}


pub(super) fn construct(
    entries: Vec<(GuardianCredentialRole, BorrowedFd<'_>)>,
    destination: Option<&mut GuardianCredentialAcquisitionOriginalV2>,
) -> Result<GuardianCredentialDescriptors> {
    let retained = destination.is_some();
    let mut local = GuardianCredentialAcquisitionOriginalV2::new();
    let original = destination.unwrap_or(&mut local);
    if original.entered {
        return Err(invalid("guardian credential acquisition is already entered"));
    }
    original.entered = true;
    let result = construct_body(entries, original, retained);
    match result {
        Ok(()) => {
            original.returned = Some(Ok(()));
            Ok(GuardianCredentialDescriptors {
                descriptors: std::mem::take(&mut original.map),
            })
        }
        Err(error) if retained => {
            original.returned = Some(Err(error));
            Err(invalid("guardian credential acquisition failed; original retained"))
        }
        Err(error) => Err(error),
    }
}

fn construct_body(
    entries: Vec<(GuardianCredentialRole, BorrowedFd<'_>)>,
    original: &mut GuardianCredentialAcquisitionOriginalV2,
    retained: bool,
) -> Result<()> {
    if entries.len() != GuardianCredentialRole::ALL.len() {
        return Err(invalid("guardian requires exactly ten authority descriptors"));
    }
    for (index, (role, descriptor)) in entries.into_iter().enumerate() {
        let snapshot = validate_once(role, descriptor, Some(&mut original.checks[index]))?;
        original.duplicates[index] = Some(descriptor.try_clone_to_owned());
        let owned = match original.duplicates[index].take() {
            Some(Ok(owned)) => owned,
            Some(Err(error)) => {
                let returned = invalid(format!("cannot duplicate guardian descriptor: {error}"));
                original.duplicates[index] = Some(Err(error));
                return Err(returned);
            }
            None => std::process::abort(),
        };
        let pin = GuardianCredentialDescriptor {
            descriptor: std::sync::Arc::new(owned),
            snapshot,
        };
        if retained {
            original.pins[index] = Some(pin.clone());
        }
        if original.map.insert(role, pin).is_some() {
            return Err(invalid("guardian authority descriptor role is duplicated"));
        }
    }
    if !GuardianCredentialRole::ALL.iter().all(|role| original.map.contains_key(role)) {
        return Err(invalid("guardian authority descriptor role is missing"));
    }
    Ok(())
}

pub(super) fn validate_once(
    role: GuardianCredentialRole,
    descriptor: BorrowedFd<'_>,
    destination: Option<&mut DescriptorCheckOriginalV2>,
) -> Result<GuardianDescriptorSnapshot> {
    let mut local = DescriptorCheckOriginalV2::default();
    let original = destination.unwrap_or(&mut local);
    #[cfg(target_os = "linux")]
    let result = validate_descriptor_engine(role, descriptor, original);
    #[cfg(not(target_os = "linux"))]
    let result = super::validate_guardian_descriptor(role, descriptor);
    if result.is_ok() {
        // The exact readback is complete. Its temporary duplicate had the same
        // return boundary in the original checker; the source FD remains held.
        drop(original.file.take());
    }
    result
}

#[cfg(all(test, target_os = "linux"))]
mod tests {
    use std::os::unix::fs::PermissionsExt as _;

    use super::*;

    #[test]
    fn failed_positional_read_keeps_its_actual_duplicate_and_errno() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("policy");
        std::fs::write(&path, b"policy").unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o400)).unwrap();
        let source = rustix::fs::open(
            &path,
            rustix::fs::OFlags::PATH | rustix::fs::OFlags::CLOEXEC,
            rustix::fs::Mode::empty(),
        ).unwrap();
        let mut original = DescriptorCheckOriginalV2::default();

        let returned = validate_once(
            GuardianCredentialRole::BrokerPlanPolicy,
            source.as_fd(),
            Some(&mut original),
        );

        assert!(returned.is_err());
        assert!(matches!(original.metadata[0], Some(Ok(_))));
        assert_eq!(original.read_error.as_ref().unwrap().raw_os_error(), Some(rustix::io::Errno::BADF.raw_os_error()));
        let duplicate = original.file.as_ref().unwrap().as_ref().unwrap();
        assert!(rustix::fs::fstat(duplicate.as_fd()).is_ok());
        assert!(original.metadata[1].is_none());
        assert!(original.failure().is_some());
    }

    #[test]
    fn a_later_role_refusal_keeps_the_same_earlier_native_pin() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("policy");
        std::fs::write(&path, b"policy").unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o400)).unwrap();
        let policy = File::open(&path).unwrap();
        let invalid = File::open("/dev/null").unwrap();
        let entries = GuardianCredentialRole::ALL.iter().enumerate()
            .map(|(index, role)| (*role, if index == 0 { policy.as_fd() } else { invalid.as_fd() }))
            .collect();
        let mut original = GuardianCredentialAcquisitionOriginalV2::new();

        let returned = GuardianCredentialDescriptors::from_descriptors_retaining_v2(entries, &mut original);

        assert!(returned.is_err());
        let first = original.pins[0].as_ref().unwrap();
        let source = rustix::fs::fstat(policy.as_fd()).unwrap();
        let retained = rustix::fs::fstat(first.descriptor.as_fd()).unwrap();
        assert_eq!((retained.st_dev, retained.st_ino), (source.st_dev, source.st_ino));
        assert_eq!(original.map.len(), 1);
        assert!(original.pins[1].is_none());
        assert!(original.failure().is_some());
        assert!(original.returned.as_ref().unwrap().is_err());
    }
}
