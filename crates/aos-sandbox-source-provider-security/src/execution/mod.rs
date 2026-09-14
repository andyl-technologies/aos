//! Retained process, boot, cgroup, and death evidence.

mod boot;
mod death;
mod remote_process;
mod self_process;

pub use boot::CurrentKernelBootV1;
pub use death::DeadProviderExecutionV1;
pub(crate) use remote_process::ProcessExecutionEvidenceV1;
pub(crate) use self_process::RetainedSelfExecutionV1;

use aos_sandbox_core::ObjectDigest;
use sha2::{Digest as _, Sha256};

use crate::SourceProviderSecurityError;

const CGROUP_DOMAIN: &[u8] = b"aos-source-provider-cgroup-v2-path-v1\0";
const MAXIMUM_CGROUP_PATH_BYTES: usize = 4096;

pub(crate) fn read_cgroup_path_digest(
    pid: u32,
) -> Result<([u8; 32], u64), SourceProviderSecurityError> {
    let path = format!("/proc/{pid}/cgroup");
    let first = read_bounded(&path)?;
    let second = read_bounded(&path)?;
    if first != second {
        return Err(SourceProviderSecurityError::ExecutionChanged);
    }
    let unified = parse_unified_cgroup(&first)?;
    let mut hasher = Sha256::new();
    hasher.update(CGROUP_DOMAIN);
    hasher.update(
        u32::try_from(unified.len())
            .map_err(|_| SourceProviderSecurityError::ExecutionChanged)?
            .to_be_bytes(),
    );
    hasher.update(unified);
    Ok((hasher.finalize().into(), unified.len() as u64))
}

pub(crate) fn cgroup_object_digest(bytes: [u8; 32]) -> ObjectDigest {
    ObjectDigest::from_bytes(bytes)
}

fn read_bounded(path: &str) -> Result<Vec<u8>, SourceProviderSecurityError> {
    use std::io::Read as _;

    let descriptor = rustix::fs::open(
        path,
        rustix::fs::OFlags::RDONLY | rustix::fs::OFlags::NOFOLLOW | rustix::fs::OFlags::CLOEXEC,
        rustix::fs::Mode::empty(),
    )
    .map_err(|_| SourceProviderSecurityError::filesystem("process cgroup", "open"))?;
    let mut bytes = Vec::new();
    std::fs::File::from(descriptor)
        .take((MAXIMUM_CGROUP_PATH_BYTES + 32) as u64)
        .read_to_end(&mut bytes)
        .map_err(|_| SourceProviderSecurityError::filesystem("process cgroup", "read"))?;
    if bytes.len() > MAXIMUM_CGROUP_PATH_BYTES + 16 {
        return Err(SourceProviderSecurityError::ExecutionChanged);
    }
    Ok(bytes)
}

fn parse_unified_cgroup(bytes: &[u8]) -> Result<&[u8], SourceProviderSecurityError> {
    let mut lines = bytes
        .split(|byte| *byte == b'\n')
        .filter(|line| !line.is_empty());
    let line = lines
        .next()
        .ok_or(SourceProviderSecurityError::ExecutionChanged)?;
    if lines.next().is_some() || !line.starts_with(b"0::") {
        return Err(SourceProviderSecurityError::ExecutionChanged);
    }
    let path = &line[3..];
    let normalized = path.starts_with(b"/")
        && path.len() <= MAXIMUM_CGROUP_PATH_BYTES
        && !path.contains(&0)
        && (path == b"/"
            || (!path.ends_with(b"/")
                && path[1..]
                    .split(|byte| *byte == b'/')
                    .all(|part| !part.is_empty() && !matches!(part, b"." | b".."))));
    if !normalized {
        return Err(SourceProviderSecurityError::ExecutionChanged);
    }
    Ok(path)
}
