//! Bounded root ingress to the separate Source-only readback signer.
//!
//! The signer accepts only the root policy peer (UID 0, Controller GID) and
//! opens its private read-only Source journal view for each request. Root
//! supplies an independently spent challenge and verifies the reply against
//! its protected public pin and expected hold.
//! This transport neither adopts Controller's writer nor authorizes Q04/Create.
//!
//! ```text
//! AOSSSR01 | nonce[16] | root-cut[32] | project[16]
//! AOSSSP01 | AOSSRB01 packet[288]
//! ```

use std::error::Error;
use std::fs;
use std::io::{self, Read as _, Write as _};
use std::os::fd::AsFd as _;
use std::os::unix::fs::{FileTypeExt as _, MetadataExt as _};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::Path;
use std::time::Duration;

use aos_sandbox::journal::SourceDomainPolicyHoldV1;
use aos_sandbox::policy_compiler::{
    PinnedSourceHoldReadbackSignerV1, SOURCE_HOLD_READBACK_BYTES_V1, SourceHoldReadbackChallengeV1,
    StagedClosedPolicySignerChallengeV2, sign_fixed_source_signer_readback_v1,
    verify_current_source_hold_readback_v1,
};
use aos_sandbox_core::{ObjectDigest, ProjectId};
use rustix::net::sockopt::{socket_acceptconn, socket_peercred};

use crate::source_signer_credential::SourceSignerCredentialV1;

/// Names the sole systemd-owned Source signer ingress socket.
pub const SOURCE_SIGNER_SOCKET_PATH_V1: &str = "/run/aos/sandbox-source-signerd.sock";

const CREDENTIAL_DIRECTORY: &str = "/run/credentials/aos-sandbox-source-signerd.service";
const REQUEST_MAGIC: &[u8; 8] = b"AOSSSR01";
const REPLY_MAGIC: &[u8; 8] = b"AOSSSP01";
const REQUEST_BYTES: usize = 72;
const REPLY_BYTES: usize = 8 + SOURCE_HOLD_READBACK_BYTES_V1;
const FLIGHT_TIMEOUT: Duration = Duration::from_secs(5);
const REPLY_TIMEOUT: Duration = Duration::from_secs(60);

/// Requests a Source-only signature as the root policy peer and checks its expected hold.
///
/// The caller must supply a root-spent challenge and a separately provisioned
/// public pin. A valid reply attests only the signer's typed Source replay;
/// the caller must still establish Controller, Cache, and Root held custody.
///
/// # Errors
///
/// Rejects unsafe socket custody, malformed or incomplete framing, transport
/// loss, wrong signer key or generation, or a Source hold that differs from the
/// independently expected root record.
pub fn request_root_source_signer_readback_v1(
    challenge: SourceHoldReadbackChallengeV1,
    project: ProjectId,
    expected_hold: SourceDomainPolicyHoldV1,
    signer: &PinnedSourceHoldReadbackSignerV1,
    signer_uid: u32,
    socket_gid: u32,
) -> io::Result<[u8; SOURCE_HOLD_READBACK_BYTES_V1]> {
    if project.as_bytes() == &[0; 16] || signer_uid == 0 || socket_gid == 0 {
        return Err(invalid_data("invalid Source signer request identity"));
    }
    require_socket_path_custody(signer_uid, socket_gid)?;
    let mut stream = UnixStream::connect(SOURCE_SIGNER_SOCKET_PATH_V1)?;
    require_socket_path_custody(signer_uid, socket_gid)?;
    stream.set_read_timeout(Some(REPLY_TIMEOUT))?;
    stream.set_write_timeout(Some(FLIGHT_TIMEOUT))?;

    let request = encode_request(challenge, project);
    stream.write_all(&request)?;
    stream.shutdown(std::net::Shutdown::Write)?;
    let packet = read_reply(&mut stream)?;
    verify_current_source_hold_readback_v1(&packet, signer, challenge, project, expected_hold)
        .map_err(io::Error::other)?;
    Ok(packet)
}

/// Requests the Source-only packet for a staged Q04 nonce and cut.
///
/// The existing Source wire protocol already accepts this exact typed
/// challenge from the Root peer. Root must first validate the durable Q04
/// stage; this adapter neither does so nor grants CAS or Create authority.
///
/// # Errors
///
/// Rejects an invalid challenge, unsafe socket, mismatched Source signer or
/// held claim, and transport loss.
pub fn request_root_staged_q04_source_readback_v2(
    challenge: StagedClosedPolicySignerChallengeV2,
    project: ProjectId,
    expected_hold: SourceDomainPolicyHoldV1,
    signer: &PinnedSourceHoldReadbackSignerV1,
    signer_uid: u32,
    socket_gid: u32,
) -> io::Result<[u8; SOURCE_HOLD_READBACK_BYTES_V1]> {
    let readback = SourceHoldReadbackChallengeV1::new(challenge.nonce(), challenge.cut())
        .map_err(io::Error::other)?;
    request_root_source_signer_readback_v1(
        readback,
        project,
        expected_hold,
        signer,
        signer_uid,
        socket_gid,
    )
}

fn encode_request(
    challenge: SourceHoldReadbackChallengeV1,
    project: ProjectId,
) -> [u8; REQUEST_BYTES] {
    let mut bytes = [0; REQUEST_BYTES];
    bytes[..8].copy_from_slice(REQUEST_MAGIC);
    bytes[8..24].copy_from_slice(&challenge.nonce());
    bytes[24..56].copy_from_slice(challenge.cut().as_bytes());
    bytes[56..72].copy_from_slice(project.as_bytes());
    bytes
}

fn decode_request(
    bytes: &[u8; REQUEST_BYTES],
) -> io::Result<(SourceHoldReadbackChallengeV1, ProjectId)> {
    if &bytes[..8] != REQUEST_MAGIC {
        return Err(invalid_data("foreign Source signer request"));
    }
    let nonce = bytes[8..24]
        .try_into()
        .map_err(|_| invalid_data("invalid Source nonce"))?;
    let cut = ObjectDigest::from_bytes(
        bytes[24..56]
            .try_into()
            .map_err(|_| invalid_data("invalid Source root cut"))?,
    );
    let project = ProjectId::from_bytes(
        bytes[56..72]
            .try_into()
            .map_err(|_| invalid_data("invalid Source project"))?,
    );
    if project.as_bytes() == &[0; 16] {
        return Err(invalid_data("zero Source project"));
    }
    let challenge = SourceHoldReadbackChallengeV1::new(nonce, cut)
        .map_err(|_| invalid_data("noncanonical Source challenge"))?;
    Ok((challenge, project))
}

fn read_reply(stream: &mut UnixStream) -> io::Result<[u8; SOURCE_HOLD_READBACK_BYTES_V1]> {
    let mut reply = [0; REPLY_BYTES];
    stream.read_exact(&mut reply)?;
    let mut trailing = [0];
    if &reply[..8] != REPLY_MAGIC || stream.read(&mut trailing)? != 0 {
        return Err(invalid_data("invalid Source signer reply"));
    }
    reply[8..]
        .try_into()
        .map_err(|_| invalid_data("invalid Source signer packet length"))
}

fn require_socket_path_custody(signer_uid: u32, socket_gid: u32) -> io::Result<()> {
    for parent in ["/run", "/run/aos"] {
        let metadata = fs::symlink_metadata(parent)?;
        if !metadata.file_type().is_dir()
            || metadata.uid() != 0
            || metadata.gid() != 0
            || metadata.mode() & 0o022 != 0
        {
            return Err(invalid_data("unsafe Source signer socket parent"));
        }
    }
    let socket = fs::symlink_metadata(SOURCE_SIGNER_SOCKET_PATH_V1)?;
    if !socket.file_type().is_socket()
        || socket.uid() != signer_uid
        || socket.gid() != socket_gid
        || socket.mode() & 0o777 != 0o660
        || socket.nlink() != 1
    {
        return Err(invalid_data("unsafe Source signer socket node"));
    }
    Ok(())
}

fn invalid_data(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}

/// Serves root requests using only the read-only Source view and private seed.
///
/// # Errors
///
/// Rejects wrong process identity, socket activation, credentials, or listener
/// custody. Rejected individual requests receive no packet.
pub fn run_source_signer_service_v1(
    controller_uid: u32,
    controller_gid: u32,
    signer_uid: u32,
    signer_gid: u32,
) -> Result<(), Box<dyn Error>> {
    if controller_uid == 0
        || controller_gid == 0
        || signer_uid == 0
        || signer_gid == 0
        || controller_uid == signer_uid
        || rustix::process::getuid().as_raw() != signer_uid
        || rustix::process::geteuid().as_raw() != signer_uid
        || rustix::process::getgid().as_raw() != signer_gid
        || rustix::process::getegid().as_raw() != signer_gid
    {
        return Err(invalid_data("wrong Source signer process identity").into());
    }
    if std::env::var_os("CREDENTIALS_DIRECTORY").as_deref()
        != Some(std::ffi::OsStr::new(CREDENTIAL_DIRECTORY))
        || std::env::var_os("LISTEN_FDS").is_some()
        || std::env::var_os("LISTEN_PID").is_some()
    {
        return Err(invalid_data("wrong Source signer activation custody").into());
    }
    let credentials = SourceSignerCredentialV1::load()?;
    let listener = UnixListener::from(rustix::io::dup(io::stdin().as_fd())?);
    if !socket_acceptconn(&listener)?
        || listener.local_addr()?.as_pathname() != Some(Path::new(SOURCE_SIGNER_SOCKET_PATH_V1))
    {
        return Err(invalid_data("wrong Source signer listening socket").into());
    }
    require_socket_path_custody(signer_uid, controller_gid)?;

    loop {
        let (mut stream, _) = listener.accept()?;
        if let Err(error) = serve_request(&mut stream, controller_uid, controller_gid, &credentials)
        {
            eprintln!("aos-sandbox-source-signerd: rejected request: {error}");
        }
    }
}

fn serve_request(
    stream: &mut UnixStream,
    controller_uid: u32,
    controller_gid: u32,
    credentials: &SourceSignerCredentialV1,
) -> Result<(), Box<dyn Error>> {
    let peer = socket_peercred(&*stream)?;
    if peer.uid.as_raw() != 0 || peer.gid.as_raw() != controller_gid {
        return Err(invalid_data("unexpected Source signer peer").into());
    }
    stream.set_read_timeout(Some(FLIGHT_TIMEOUT))?;
    stream.set_write_timeout(Some(FLIGHT_TIMEOUT))?;
    let mut request = [0; REQUEST_BYTES];
    stream.read_exact(&mut request)?;
    let mut trailing = [0];
    if stream.read(&mut trailing)? != 0 {
        return Err(invalid_data("trailing Source signer request bytes").into());
    }
    let (challenge, project) = decode_request(&request)?;
    let signing_key = credentials.signing_key()?;
    let packet = sign_fixed_source_signer_readback_v1(
        controller_uid,
        project,
        challenge,
        credentials.generation(),
        &signing_key,
    )?;
    let mut reply = [0; REPLY_BYTES];
    reply[..8].copy_from_slice(REPLY_MAGIC);
    reply[8..].copy_from_slice(&packet);
    stream.write_all(&reply)?;
    stream.shutdown(std::net::Shutdown::Write)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn request_frame_rejects_foreign_and_noncanonical_source_claims() {
        let challenge =
            SourceHoldReadbackChallengeV1::new([1; 16], ObjectDigest::from_bytes([2; 32]))
                .expect("challenge");
        let project = ProjectId::from_bytes([3; 16]);
        let bytes = encode_request(challenge, project);
        assert_eq!(
            decode_request(&bytes).expect("canonical request"),
            (challenge, project)
        );

        let mut foreign = bytes;
        foreign[..8].copy_from_slice(b"AOSCSC02");
        assert!(decode_request(&foreign).is_err());
        let mut zero_project = bytes;
        zero_project[56..72].fill(0);
        assert!(decode_request(&zero_project).is_err());
        let mut zero_nonce = bytes;
        zero_nonce[8..24].fill(0);
        assert!(decode_request(&zero_nonce).is_err());
    }
}
