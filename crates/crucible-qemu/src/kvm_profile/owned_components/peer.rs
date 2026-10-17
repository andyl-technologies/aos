//! Original OS peer and process-generation evidence for native preparation.
//!
//! This evidence authenticates one owned connection and executable inode. It
//! does not assert a matching source build, original guest initialization,
//! native stopped readiness, complete modeled domains or execution permission.

use std::{
    fs::File,
    io::Read,
    os::unix::{fs::MetadataExt, net::UnixStream},
    process::Child,
};

use crucible::node_contract::{EffectKnowledge, OperationFailure};

/// Retains OS observations of one original owned process generation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct KvmNativePeerIdentity {
    pub(crate) process_id: u32,
    pub(crate) start_time_ticks: u64,
    pub(crate) executable_device: u64,
    pub(crate) executable_inode: u64,
    pub(crate) peer_uid: u32,
    pub(crate) peer_gid: u32,
}

/// Owns the same stream whose actual OS credentials were authenticated.
///
/// The stream and evidence cannot be reconstructed from serialized labels.
/// Keeping them together prevents installing a different socket after checking
/// another peer's PID. The sole child wait authority remains in its pre-reserved
/// prepared resource capsule throughout this operation.
pub(crate) struct KvmAuthenticatedPeer {
    pub(crate) stream: UnixStream,
    pub(crate) identity: KvmNativePeerIdentity,
}

/// Authenticates the actual owned child before consuming its control stream.
///
/// The expected executable is the independently measured pinned installation
/// descriptor. Exact content authentication occurs in the installed artifact
/// path; device/inode equality connects that descriptor to `/proc/<pid>/exe`.
/// Both process observations must agree across credential and inode checks.
pub(crate) fn authenticate_owned_peer(
    child: &Child,
    stream: UnixStream,
    expected_executable: &File,
) -> Result<KvmAuthenticatedPeer, OperationFailure> {
    let process_id = child.id();
    let before = process_generation(process_id)?;
    let credentials = rustix::net::sockopt::socket_peercred(&stream).map_err(|error| {
        failure(&format!(
            "original OS peer credential query failed: {error}"
        ))
    })?;
    let peer_pid = u32::try_from(credentials.pid.as_raw_nonzero().get())
        .map_err(|_| failure("original peer PID is unrepresentable"))?;
    if peer_pid != process_id {
        return Err(failure(
            "native control peer is not the original owned child",
        ));
    }

    let expected = expected_executable.metadata().map_err(|error| {
        failure(&format!(
            "pinned original executable observation failed: {error}"
        ))
    })?;
    let actual = File::open(format!("/proc/{process_id}/exe"))
        .and_then(|file| file.metadata())
        .map_err(|error| {
            failure(&format!(
                "actual original executable observation failed: {error}"
            ))
        })?;
    if !expected.is_file()
        || !actual.is_file()
        || expected.dev() != actual.dev()
        || expected.ino() != actual.ino()
        || expected.len() != actual.len()
    {
        return Err(failure(
            "original native executable differs from its pinned installation",
        ));
    }
    let after = process_generation(process_id)?;
    let after_executable = File::open(format!("/proc/{process_id}/exe"))
        .and_then(|file| file.metadata())
        .map_err(|error| {
            failure(&format!(
                "original executable reobservation failed: {error}"
            ))
        })?;
    if before != after
        || actual.dev() != after_executable.dev()
        || actual.ino() != after_executable.ino()
        || actual.len() != after_executable.len()
    {
        return Err(failure(
            "original native process generation changed during peer authentication",
        ));
    }
    Ok(KvmAuthenticatedPeer {
        stream,
        identity: KvmNativePeerIdentity {
            process_id,
            start_time_ticks: before,
            executable_device: actual.dev(),
            executable_inode: actual.ino(),
            peer_uid: credentials.uid.as_raw(),
            peer_gid: credentials.gid.as_raw(),
        },
    })
}

/// Reads a finite original Linux generation record; malformed evidence refuses.
pub(super) fn process_generation(process_id: u32) -> Result<u64, OperationFailure> {
    let mut record = [0_u8; 4096];
    let mut file = File::open(format!("/proc/{process_id}/stat"))
        .map_err(|error| failure(&format!("original process observation failed: {error}")))?;
    let mut length = 0_usize;
    loop {
        if length == record.len() {
            return Err(failure(
                "original process generation exceeds finite observation credit",
            ));
        }
        let count = file
            .read(&mut record[length..])
            .map_err(|error| failure(&format!("original process observation failed: {error}")))?;
        if count == 0 {
            break;
        }
        length += count;
    }
    let suffix = record[..length]
        .windows(2)
        .rposition(|pair| pair == b") ")
        .map(|index| &record[index + 2..length])
        .ok_or_else(|| failure("original process generation is malformed"))?;
    let ticks = suffix
        .split(|byte| byte.is_ascii_whitespace())
        .filter(|field| !field.is_empty())
        .nth(19)
        .ok_or_else(|| failure("original process generation is incomplete"))?;
    if ticks.is_empty() {
        return Err(failure("original process generation is empty"));
    }
    ticks.iter().try_fold(0_u64, |value, byte| {
        if !byte.is_ascii_digit() {
            return Err(failure(
                "original process generation is not an unsigned integer",
            ));
        }
        value
            .checked_mul(10)
            .and_then(|value| value.checked_add(u64::from(byte - b'0')))
            .ok_or_else(|| failure("original process generation is unrepresentable"))
    })
}

fn failure(reason: &str) -> OperationFailure {
    OperationFailure {
        effects: EffectKnowledge::Unknown,
        reason: reason.into(),
    }
}
