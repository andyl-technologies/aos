//! Pidfd, cgroup, executable, and launcher capture for startup authority.

use std::fs::File;
use std::io::Read as _;
use std::num::NonZeroU32;
use std::os::fd::{AsFd as _, OwnedFd};
use std::os::unix::fs::FileExt as _;
use std::path::Path;

use crate::boot::KernelBootId;
use crate::cgroup::{CgroupV2Root, RetainedCgroupAnchor};
use crate::pidfd::PidFd;
use crate::uapi;
use crate::{Error, Result};

use super::model::{
    RetainedStartupProcessV1, StartupExecutableObservationV1, StartupProcessObservationV1,
    build_identity,
};

const MAXIMUM_CGROUP_RECORD_BYTES: usize = 4_096;
const ELF_HEADER_BYTES: usize = 64;
const ELF_PROGRAM_HEADER_BYTES: usize = 56;
const MAXIMUM_PROGRAM_HEADERS: usize = 128;
const MAXIMUM_NOTE_BYTES: usize = 64 * 1_024;
const PT_NOTE: u32 = 4;
const NT_GNU_BUILD_ID: u32 = 3;

pub(super) fn capture_current_and_launcher(
    boot_id: [u8; 16],
) -> Result<(RetainedStartupProcessV1, RetainedStartupProcessV1)> {
    let current_pid = NonZeroU32::new(std::process::id())
        .ok_or_else(|| Error::invalid("startup execution", "current PID is zero"))?;
    let execution = capture_process(current_pid, boot_id)?;
    let launcher_pid =
        NonZeroU32::new(execution.observation.process.parent_pid()).ok_or_else(|| {
            Error::invalid("startup launcher", "current process has no direct parent")
        })?;
    let launcher = capture_process(launcher_pid, boot_id)?;
    if execution.observation.process.parent_pid() != launcher.observation.process.pid()
        || execution.observation.process.pid() != execution.observation.process.thread_group_id()
        || launcher.observation.process.pid() != launcher.observation.process.thread_group_id()
    {
        return Err(Error::invalid(
            "startup launcher",
            "process/launcher relationship is not exact",
        ));
    }
    Ok((execution, launcher))
}

pub(super) fn revalidate_process(process: &RetainedStartupProcessV1) -> Result<()> {
    let before_boot = KernelBootId::current()?.into_bytes();
    let identity = process.pidfd.process_identity()?;
    let info = process.cgroup.verify_exact_membership(&process.pidfd)?;
    let retained_executable = observe_executable(&process.executable)?;
    let current_executable = observe_current_executable(identity.pid())?;
    let after_boot = KernelBootId::current()?.into_bytes();
    if before_boot != process.observation.kernel_boot_id
        || after_boot != process.observation.kernel_boot_id
        || identity != process.observation.process
        || info.credentials() != Some(process.observation.credentials)
        || info.cgroup_id() != Some(process.observation.cgroup_id)
        || process.cgroup.kernel_id() != process.observation.cgroup_id
        || retained_executable != process.observation.executable
        || current_executable != process.observation.executable
        || !process.pidfd.is_alive()?
    {
        return Err(Error::invalid(
            "startup execution",
            "retained process identity changed",
        ));
    }
    process.cgroup.validate_current()
}

fn capture_process(pid: NonZeroU32, boot_id: [u8; 16]) -> Result<RetainedStartupProcessV1> {
    let pidfd = PidFd::open(pid)?;
    let before_identity = pidfd.process_identity()?;
    let before_info = pidfd.info()?;
    let credentials = before_info
        .credentials()
        .ok_or_else(|| Error::invalid("startup execution", "pidfd omitted credentials"))?;
    let cgroup_id = before_info
        .cgroup_id()
        .ok_or_else(|| Error::invalid("startup execution", "pidfd omitted cgroup ID"))?;
    let cgroup_path = read_cgroup_path(pid.get())?;
    let unit = cgroup_unit(&cgroup_path)?;
    let cgroup = open_exact_cgroup(&cgroup_path)?;
    cgroup.verify_exact_membership(&pidfd)?;
    if cgroup.kernel_id() != cgroup_id {
        return Err(Error::invalid(
            "startup execution",
            "procfs cgroup path differs from pidfd cgroup ID",
        ));
    }

    let executable = open_process_executable(pid.get())?;
    let executable_observation = observe_executable(&executable)?;
    cgroup.verify_exact_membership(&pidfd)?;
    let after_identity = pidfd.process_identity()?;
    let after_info = pidfd.info()?;
    let current_executable = observe_current_executable(pid.get())?;
    let final_boot = KernelBootId::current()?.into_bytes();
    if before_identity != after_identity
        || before_info != after_info
        || before_identity.pid() != pid.get()
        || before_identity.thread_group_id() != pid.get()
        || current_executable != executable_observation
        || final_boot != boot_id
        || !pidfd.is_alive()?
    {
        return Err(Error::invalid(
            "startup execution",
            "process changed during identity capture",
        ));
    }

    Ok(RetainedStartupProcessV1 {
        pidfd,
        cgroup,
        executable,
        observation: StartupProcessObservationV1 {
            kernel_boot_id: boot_id,
            process: after_identity,
            credentials,
            cgroup_id,
            cgroup_path,
            unit,
            executable: executable_observation,
        },
    })
}

fn read_cgroup_path(pid: u32) -> Result<String> {
    let path = format!("/proc/{pid}/cgroup");
    let file = File::open(path).map_err(|source| Error::Syscall {
        operation: "open /proc/PID/cgroup",
        source,
    })?;
    let mut bytes = Vec::new();
    file.take((MAXIMUM_CGROUP_RECORD_BYTES + 1) as u64)
        .read_to_end(&mut bytes)
        .map_err(|source| Error::Syscall {
            operation: "read /proc/PID/cgroup",
            source,
        })?;
    if bytes.len() > MAXIMUM_CGROUP_RECORD_BYTES {
        return Err(Error::invalid(
            "startup cgroup",
            "procfs cgroup record exceeds its fixed bound",
        ));
    }
    let text = std::str::from_utf8(&bytes)
        .map_err(|_| Error::invalid("startup cgroup", "record is not UTF-8"))?;
    let text = text.strip_suffix('\n').unwrap_or(text);
    if text.contains('\n') || !text.starts_with("0::/") {
        return Err(Error::invalid(
            "startup cgroup",
            "record is not one canonical cgroup-v2 membership",
        ));
    }
    let cgroup_path = text
        .strip_prefix("0::")
        .ok_or_else(|| Error::invalid("startup cgroup", "record prefix changed"))?;
    if cgroup_path.len() <= 1
        || cgroup_path.len() > 1_024
        || cgroup_path.split('/').any(|part| part == "..")
    {
        return Err(Error::invalid(
            "startup cgroup",
            "cgroup path is outside the closed profile",
        ));
    }
    Ok(cgroup_path.to_owned())
}

fn cgroup_unit(path: &str) -> Result<String> {
    let unit = path
        .rsplit('/')
        .next()
        .filter(|unit| !unit.is_empty() && unit.len() <= 255)
        .ok_or_else(|| Error::invalid("startup cgroup", "unit component is absent"))?;
    if unit
        .bytes()
        .any(|byte| matches!(byte, b'\0' | b'\n' | b'\r'))
    {
        return Err(Error::invalid(
            "startup cgroup",
            "unit component is noncanonical",
        ));
    }
    Ok(unit.to_owned())
}

fn open_exact_cgroup(path: &str) -> Result<RetainedCgroupAnchor> {
    let root: OwnedFd = File::open("/sys/fs/cgroup")
        .map_err(|source| Error::Syscall {
            operation: "open cgroup-v2 root",
            source,
        })?
        .into();
    let root = CgroupV2Root::from_owned(root)?;
    let relative = path
        .strip_prefix('/')
        .ok_or_else(|| Error::invalid("startup cgroup", "path is not absolute"))?;
    root.resolve(Path::new(relative))
}

fn open_process_executable(pid: u32) -> Result<OwnedFd> {
    rustix::fs::open(
        format!("/proc/{pid}/exe"),
        rustix::fs::OFlags::RDONLY | rustix::fs::OFlags::CLOEXEC,
        rustix::fs::Mode::empty(),
    )
    .map_err(|source| Error::Syscall {
        operation: "open /proc/PID/exe",
        source: source.into(),
    })
}

fn observe_current_executable(pid: u32) -> Result<StartupExecutableObservationV1> {
    let executable = open_process_executable(pid)?;
    observe_executable(&executable)
}

fn observe_executable(executable: &OwnedFd) -> Result<StartupExecutableObservationV1> {
    let before = rustix::fs::fstat(executable).map_err(|source| Error::Syscall {
        operation: "fstat startup executable",
        source: source.into(),
    })?;
    let measurement = uapi::measure_verity(executable.as_fd())?;
    if measurement.algorithm != 1 || measurement.length != 32 {
        return Err(Error::invalid(
            "startup executable",
            "executable lacks the required SHA-256 fs-verity profile",
        ));
    }
    let build_identity = read_gnu_build_id(executable)?;
    let after = rustix::fs::fstat(executable).map_err(|source| Error::Syscall {
        operation: "fstat startup executable",
        source: source.into(),
    })?;
    if before.st_dev == 0
        || before.st_ino == 0
        || before.st_size <= 0
        || before.st_mode & libc::S_IFMT != libc::S_IFREG
        || before.st_dev != after.st_dev
        || before.st_ino != after.st_ino
        || before.st_size != after.st_size
        || before.st_mode != after.st_mode
    {
        return Err(Error::invalid(
            "startup executable",
            "executable identity changed or is not one regular file",
        ));
    }
    let mut fs_verity_sha256 = [0; 32];
    fs_verity_sha256.copy_from_slice(&measurement.digest[..32]);
    Ok(StartupExecutableObservationV1 {
        device: before.st_dev,
        inode: before.st_ino,
        size: u64::try_from(before.st_size)
            .map_err(|_| Error::invalid("startup executable", "size is negative"))?,
        mode: before.st_mode,
        fs_verity_sha256,
        build_identity,
    })
}

fn read_gnu_build_id(executable: &OwnedFd) -> Result<super::ExecutableBuildIdentityV1> {
    let file = File::from(executable.try_clone().map_err(|source| Error::Syscall {
        operation: "duplicate startup executable",
        source,
    })?);
    let mut header = [0; ELF_HEADER_BYTES];
    read_exact_at(&file, &mut header, 0)?;
    if &header[..4] != b"\x7fELF" || header[4] != 2 || header[5] != 1 || header[6] != 1 {
        return Err(Error::invalid(
            "startup executable",
            "executable is not canonical ELF64 little-endian",
        ));
    }
    let program_offset = u64::from_le_bytes(
        header[32..40]
            .try_into()
            .map_err(|_| Error::invalid("startup executable", "ELF header is truncated"))?,
    );
    let entry_size =
        usize::from(u16::from_le_bytes(header[54..56].try_into().map_err(
            |_| Error::invalid("startup executable", "ELF header is truncated"),
        )?));
    let entry_count =
        usize::from(u16::from_le_bytes(header[56..58].try_into().map_err(
            |_| Error::invalid("startup executable", "ELF header is truncated"),
        )?));
    if entry_size != ELF_PROGRAM_HEADER_BYTES
        || entry_count == 0
        || entry_count > MAXIMUM_PROGRAM_HEADERS
    {
        return Err(Error::invalid(
            "startup executable",
            "ELF program-header table is outside the closed profile",
        ));
    }

    let mut found = None;
    for index in 0..entry_count {
        let offset = program_offset
            .checked_add((index * entry_size) as u64)
            .ok_or_else(|| Error::invalid("startup executable", "program header overflows"))?;
        let mut program = [0; ELF_PROGRAM_HEADER_BYTES];
        read_exact_at(&file, &mut program, offset)?;
        let kind = u32::from_le_bytes(
            program[..4]
                .try_into()
                .map_err(|_| Error::invalid("startup executable", "program header is invalid"))?,
        );
        if kind != PT_NOTE {
            continue;
        }
        let note_offset = u64::from_le_bytes(
            program[8..16]
                .try_into()
                .map_err(|_| Error::invalid("startup executable", "program header is invalid"))?,
        );
        let note_size =
            usize::try_from(u64::from_le_bytes(program[32..40].try_into().map_err(
                |_| Error::invalid("startup executable", "program header is invalid"),
            )?))
            .map_err(|_| Error::invalid("startup executable", "note size overflows"))?;
        if note_size == 0 || note_size > MAXIMUM_NOTE_BYTES {
            return Err(Error::invalid(
                "startup executable",
                "ELF note segment exceeds its fixed bound",
            ));
        }
        let mut notes = vec![0; note_size];
        read_exact_at(&file, &mut notes, note_offset)?;
        for build_id in gnu_build_ids(&notes)? {
            if found.replace(build_id).is_some() {
                return Err(Error::invalid(
                    "startup executable",
                    "executable contains multiple GNU build IDs",
                ));
            }
        }
    }
    found.ok_or_else(|| Error::invalid("startup executable", "executable omits a GNU build ID"))
}

fn gnu_build_ids(notes: &[u8]) -> Result<Vec<super::ExecutableBuildIdentityV1>> {
    let mut found = Vec::new();
    let mut offset = 0usize;
    while offset < notes.len() {
        if notes[offset..].iter().all(|byte| *byte == 0) {
            break;
        }
        let header_end = offset
            .checked_add(12)
            .ok_or_else(|| Error::invalid("startup executable", "ELF note overflows"))?;
        let header = notes
            .get(offset..header_end)
            .ok_or_else(|| Error::invalid("startup executable", "ELF note is truncated"))?;
        let name_size =
            usize::try_from(u32::from_le_bytes(header[..4].try_into().map_err(
                |_| Error::invalid("startup executable", "ELF note is invalid"),
            )?))
            .map_err(|_| Error::invalid("startup executable", "note name length overflows"))?;
        let value_size =
            usize::try_from(u32::from_le_bytes(header[4..8].try_into().map_err(
                |_| Error::invalid("startup executable", "ELF note is invalid"),
            )?))
            .map_err(|_| Error::invalid("startup executable", "note value length overflows"))?;
        let note_type = u32::from_le_bytes(
            header[8..12]
                .try_into()
                .map_err(|_| Error::invalid("startup executable", "ELF note is invalid"))?,
        );
        let name_end = header_end
            .checked_add(name_size)
            .ok_or_else(|| Error::invalid("startup executable", "ELF note overflows"))?;
        let value_start = align4(name_end)?;
        let value_end = value_start
            .checked_add(value_size)
            .ok_or_else(|| Error::invalid("startup executable", "ELF note overflows"))?;
        let next = align4(value_end)?;
        let name = notes
            .get(header_end..name_end)
            .ok_or_else(|| Error::invalid("startup executable", "ELF note name is truncated"))?;
        let value = notes
            .get(value_start..value_end)
            .ok_or_else(|| Error::invalid("startup executable", "ELF note value is truncated"))?;
        if note_type == NT_GNU_BUILD_ID && name == b"GNU\0" {
            found.push(build_identity(value)?);
        }
        if next <= offset {
            return Err(Error::invalid(
                "startup executable",
                "ELF note does not advance",
            ));
        }
        offset = next;
    }
    Ok(found)
}

fn align4(value: usize) -> Result<usize> {
    value
        .checked_add(3)
        .map(|aligned| aligned & !3)
        .ok_or_else(|| Error::invalid("startup executable", "ELF note alignment overflows"))
}

fn read_exact_at(file: &File, mut output: &mut [u8], mut offset: u64) -> Result<()> {
    while !output.is_empty() {
        let read = file
            .read_at(output, offset)
            .map_err(|source| Error::Syscall {
                operation: "pread startup executable",
                source,
            })?;
        if read == 0 {
            return Err(Error::invalid(
                "startup executable",
                "executable is truncated",
            ));
        }
        offset = offset
            .checked_add(read as u64)
            .ok_or_else(|| Error::invalid("startup executable", "read offset overflows"))?;
        output = &mut output[read..];
    }
    Ok(())
}
