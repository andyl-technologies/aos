//! Linux process-generation identity capture for supervised QEMU children.

use super::QemuNodeError;
use std::path::{Path, PathBuf};

/// Stable Linux identity for one launched QEMU process generation.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct QemuProcessIdentity {
    /// Operating-system process identifier.
    pub process_id: u32,
    /// Linux `/proc` start-time ticks, which prevent PID-reuse confusion.
    pub start_time_ticks: u64,
    /// Canonical executable reached through `/proc/<pid>/exe`.
    pub executable: PathBuf,
}

/// Returns the current Linux identity for `process_id`, when it still exists.
///
/// # Errors
///
/// Returns [`QemuNodeError`] when `/proc` exists for the PID but its identity
/// cannot be read or decoded.
pub fn linux_process_identity(
    process_id: u32,
) -> Result<Option<QemuProcessIdentity>, QemuNodeError> {
    let proc_directory = PathBuf::from("/proc").join(process_id.to_string());
    let stat = match std::fs::read_to_string(proc_directory.join("stat")) {
        Ok(stat) => stat,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => {
            return Err(QemuNodeError::fault_command(format!(
                "read process identity for PID {process_id}: {error}"
            )));
        }
    };
    let suffix = stat
        .rsplit_once(") ")
        .map(|(_, suffix)| suffix)
        .ok_or_else(|| {
            QemuNodeError::fault_command(format!("malformed /proc/{process_id}/stat"))
        })?;
    let start_time_ticks = suffix
        .split_ascii_whitespace()
        .nth(19)
        .ok_or_else(|| {
            QemuNodeError::fault_command(format!("missing start time in /proc/{process_id}/stat"))
        })?
        .parse::<u64>()
        .map_err(|error| {
            QemuNodeError::fault_command(format!(
                "invalid start time in /proc/{process_id}/stat: {error}"
            ))
        })?;
    let executable = match std::fs::read_link(proc_directory.join("exe")) {
        Ok(executable) => executable,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => {
            return Err(QemuNodeError::fault_command(format!(
                "read executable identity for PID {process_id}: {error}"
            )));
        }
    };
    Ok(Some(QemuProcessIdentity {
        process_id,
        start_time_ticks,
        executable,
    }))
}

pub(super) fn linux_process_identity_components(
    process_id: u32,
    expected_executable: &Path,
) -> Result<(u32, u64), QemuNodeError> {
    use std::io::Read as _;
    use std::os::unix::ffi::OsStrExt as _;
    use std::os::unix::fs::MetadataExt as _;

    fn proc_path<'a>(storage: &'a mut [u8; 64], process_id: u32, suffix: &[u8]) -> &'a Path {
        let prefix = b"/proc/";
        storage[..prefix.len()].copy_from_slice(prefix);
        let mut digits = [0_u8; 10];
        let mut cursor = digits.len();
        let mut remaining = process_id;
        loop {
            cursor -= 1;
            digits[cursor] = b'0' + (remaining % 10) as u8;
            remaining /= 10;
            if remaining == 0 {
                break;
            }
        }
        let digit_count = digits.len() - cursor;
        storage[prefix.len()..prefix.len() + digit_count].copy_from_slice(&digits[cursor..]);
        let suffix_start = prefix.len() + digit_count;
        storage[suffix_start..suffix_start + suffix.len()].copy_from_slice(suffix);
        Path::new(std::ffi::OsStr::from_bytes(
            &storage[..suffix_start + suffix.len()],
        ))
    }

    fn parse_u64(bytes: &[u8]) -> Option<u64> {
        if bytes.is_empty() {
            return None;
        }
        bytes.iter().try_fold(0_u64, |value, byte| {
            byte.is_ascii_digit()
                .then_some(())
                .and_then(|()| value.checked_mul(10))
                .and_then(|value| value.checked_add(u64::from(byte - b'0')))
        })
    }

    let mut path_storage = [0_u8; 64];
    let stat_path = proc_path(&mut path_storage, process_id, b"/stat");
    let mut stat = [0_u8; 4096];
    let mut file = std::fs::File::open(stat_path).map_err(|error| {
        QemuNodeError::fault_command(format!(
            "open process identity for PID {process_id}: {error}"
        ))
    })?;
    let mut length = 0_usize;
    loop {
        if length == stat.len() {
            return Err(QemuNodeError::fault_command(format!(
                "/proc/{process_id}/stat exceeds bounded identity storage"
            )));
        }
        let read = file.read(&mut stat[length..]).map_err(|error| {
            QemuNodeError::fault_command(format!(
                "read process identity for PID {process_id}: {error}"
            ))
        })?;
        if read == 0 {
            break;
        }
        length += read;
    }
    let suffix = stat[..length]
        .windows(2)
        .rposition(|window| window == b") ")
        .map(|index| &stat[index + 2..length])
        .ok_or_else(|| {
            QemuNodeError::fault_command(format!("malformed /proc/{process_id}/stat"))
        })?;
    let start_time_ticks = suffix
        .split(|byte| byte.is_ascii_whitespace())
        .filter(|field| !field.is_empty())
        .nth(19)
        .and_then(parse_u64)
        .ok_or_else(|| {
            QemuNodeError::fault_command(format!(
                "missing or invalid start time in /proc/{process_id}/stat"
            ))
        })?;

    let proc_executable = std::fs::metadata(proc_path(&mut path_storage, process_id, b"/exe"))
        .map_err(|error| {
            QemuNodeError::fault_command(format!(
                "inspect executable identity for PID {process_id}: {error}"
            ))
        })?;
    let expected = std::fs::metadata(expected_executable).map_err(|error| {
        QemuNodeError::fault_command(format!(
            "inspect expected executable {}: {error}",
            expected_executable.display()
        ))
    })?;
    if proc_executable.dev() != expected.dev() || proc_executable.ino() != expected.ino() {
        return Err(QemuNodeError::fault_command(format!(
            "QEMU child PID {process_id} does not match its preallocated executable identity"
        )));
    }
    Ok((process_id, start_time_ticks))
}
