//! Admits existing process mappings and descriptor indices under real ceilings.
//!
//! A lowered RLIMIT_AS/NOFILE limits future growth without evicting old owners.
//! This bounded streaming census closes that admission gap. Its proc directory
//! descriptor is included; no descriptor roster or complete proc file is built.

use super::*;
use std::{fs, io::Read, os::unix::ffi::OsStrExt};

fn decimal(bytes: &[u8]) -> Result<u64, LinuxProcessSupervisorError> {
    if bytes.is_empty() || bytes.len() > 20 {
        return Err(LinuxProcessSupervisorError::UnsupportedFacet);
    }
    bytes.iter().try_fold(0u64, |number, byte| {
        if !byte.is_ascii_digit() {
            return Err(LinuxProcessSupervisorError::UnsupportedFacet);
        }
        number
            .checked_mul(10)
            .and_then(|value| value.checked_add(u64::from(byte - b'0')))
            .ok_or(LinuxProcessSupervisorError::ResourceLimit)
    })
}

fn mapped_bytes(prefix: &[u8], page_size: u64) -> Result<u64, LinuxProcessSupervisorError> {
    let end = prefix
        .iter()
        .position(|byte| *byte == b' ')
        .ok_or(LinuxProcessSupervisorError::UnsupportedFacet)?;
    if page_size == 0 {
        return Err(LinuxProcessSupervisorError::UnsupportedFacet);
    }
    decimal(&prefix[..end])?
        .checked_mul(page_size)
        .ok_or(LinuxProcessSupervisorError::ResourceLimit)
}

fn descriptor_index(name: &[u8], soft_limit: u64) -> Result<(), LinuxProcessSupervisorError> {
    if decimal(name)? >= soft_limit {
        return Err(LinuxProcessSupervisorError::ResourceLimit);
    }
    Ok(())
}

pub(super) fn authenticate(
    ceilings: LinuxProcessCeilingsData,
) -> Result<(), LinuxProcessSupervisorError> {
    let cpu_limit = ceilings
        .cpu
        .current
        .ok_or(LinuxProcessSupervisorError::ResourceLimit)?;
    let cpu = rustix::time::clock_gettime(rustix::time::ClockId::ProcessCPUTime);
    if cpu_limit == 0
        || u64::try_from(cpu.tv_sec).map_err(|_| LinuxProcessSupervisorError::ResourceLimit)?
            >= cpu_limit
    {
        return Err(LinuxProcessSupervisorError::ResourceLimit);
    }
    let address_limit = ceilings
        .address_space
        .current
        .ok_or(LinuxProcessSupervisorError::ResourceLimit)?;
    let descriptor_limit = ceilings
        .descriptors
        .current
        .ok_or(LinuxProcessSupervisorError::ResourceLimit)?;
    if address_limit == 0 || descriptor_limit == 0 {
        return Err(LinuxProcessSupervisorError::ResourceLimit);
    }
    let mut statm = fs::File::open("/proc/self/statm")
        .map_err(|_| LinuxProcessSupervisorError::UnsupportedFacet)?;
    let mut prefix = [0u8; 128];
    let mut length = 0;
    loop {
        let count = match statm.read(&mut prefix[length..]) {
            Ok(count) => count,
            Err(error) if error.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(_) => return Err(LinuxProcessSupervisorError::UnsupportedFacet),
        };
        length += count;
        if prefix[..length].contains(&b' ') {
            break;
        }
        if count == 0 || length == prefix.len() {
            return Err(LinuxProcessSupervisorError::UnsupportedFacet);
        }
    }
    let page_size = u64::try_from(rustix::param::page_size())
        .map_err(|_| LinuxProcessSupervisorError::ResourceLimit)?;
    if mapped_bytes(&prefix[..length], page_size)? > address_limit {
        return Err(LinuxProcessSupervisorError::ResourceLimit);
    }
    drop(statm);

    let descriptors =
        fs::read_dir("/proc/self/fd").map_err(|_| LinuxProcessSupervisorError::UnsupportedFacet)?;
    let mut count = 0u64;
    for descriptor in descriptors {
        let descriptor = descriptor.map_err(|_| LinuxProcessSupervisorError::UnsupportedFacet)?;
        descriptor_index(descriptor.file_name().as_bytes(), descriptor_limit)?;
        count = count
            .checked_add(1)
            .ok_or(LinuxProcessSupervisorError::ResourceLimit)?;
        if count > descriptor_limit {
            return Err(LinuxProcessSupervisorError::ResourceLimit);
        }
    }
    // With the same hard ceiling still installed, subsequent opens/dup/received
    // descriptors cannot create a new index above it. Existing high indices
    // were individually refused rather than hidden by a low total count.
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn existing_mapping_extent_uses_reserved_pages_and_checked_arithmetic()
    -> Result<(), LinuxProcessSupervisorError> {
        assert_eq!(mapped_bytes(b"17 3 1 0", 4096)?, 69_632);
        assert!(mapped_bytes(b"18446744073709551615 1", 4096).is_err());
        assert!(mapped_bytes(b"17x 1", 4096).is_err());
        assert!(mapped_bytes(b"17", 4096).is_err());
        assert!(mapped_bytes(b"17 1", 0).is_err());
        Ok(())
    }

    #[test]
    fn high_existing_descriptor_refuses_even_with_only_one_live_row()
    -> Result<(), LinuxProcessSupervisorError> {
        descriptor_index(b"16", 17)?;
        assert_eq!(
            descriptor_index(b"17", 17),
            Err(LinuxProcessSupervisorError::ResourceLimit)
        );
        assert_eq!(
            descriptor_index(b"9999", 17),
            Err(LinuxProcessSupervisorError::ResourceLimit)
        );
        assert!(descriptor_index(b"17x", 32).is_err());
        assert!(descriptor_index(b"18446744073709551616", u64::MAX).is_err());
        Ok(())
    }
}
