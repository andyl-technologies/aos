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
//! AOSSSR08 | fresh-nonce[16] | intent[32] | project[16] | AOSSGX01[664]
//! AOSSSP08 | unchanged AOSSGO01 observation[928]
//! ```

use std::error::Error;
use std::fs;
use std::io::{self, Read as _, Write as _};
use std::os::fd::AsFd as _;
use std::os::unix::fs::{FileTypeExt as _, MetadataExt as _};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::Path;
use std::time::Duration;

use aos_sandbox::journal::{
    ProtectedJournalNamesV1, SourceDomainPolicyHoldV1, SourceProjectAdmissionChallengeV1,
    SourceProjectAdmissionReservationV1,
};
use aos_sandbox::policy_compiler::{
    PinnedSourceHoldReadbackSignerV1, SOURCE_HOLD_READBACK_BYTES_V1, SOURCE_HOLD_READBACK_BYTES_V2,
    SOURCE_PROJECT_ADMISSION_READBACK_BYTES_V1,
    SOURCE_PROJECT_COMPLETED_TERMINAL_READBACK_BYTES_V1,
    SOURCE_PROJECT_RESERVATION_READBACK_BYTES_V1, SOURCE_TREE_GENESIS_INTENT_CONTEXT_BYTES_V1,
    SOURCE_TREE_GENESIS_READBACK_BYTES_V1, SourceHoldReadbackChallengeV1,
    SourceTreeGenesisChallengeV1, SourceTreeGenesisIntentContextV1,
    StagedClosedPolicySignerChallengeV2, sign_fixed_source_project_admission_readback_v1,
    sign_fixed_source_project_completed_terminal_readback_v1,
    sign_fixed_source_project_reservation_readback_v1,
    sign_fixed_source_project_retirement_readback_v1, sign_fixed_source_signer_readback_v1,
    sign_fixed_source_signer_readback_v2, sign_fixed_source_tree_genesis_readback_v2,
    verify_current_source_hold_readback_v1, verify_source_hold_readback_with_names_v2,
    verify_source_project_admission_readback_v1,
    verify_source_project_completed_terminal_readback_v1,
    verify_source_project_reservation_readback_v1, verify_source_project_retirement_readback_v1,
    verify_source_tree_genesis_readback_v1,
};
use aos_sandbox_core::{ObjectDigest, ProjectId};
use rustix::net::sockopt::{socket_acceptconn, socket_peercred};

use crate::source_signer_credential::SourceSignerCredentialV1;

/// Names the sole systemd-owned Source signer ingress socket.
pub const SOURCE_SIGNER_SOCKET_PATH_V1: &str = "/run/aos/sandbox-source-signerd.sock";

const CREDENTIAL_DIRECTORY: &str = "/run/credentials/aos-sandbox-source-signerd.service";
const REQUEST_MAGIC: &[u8; 8] = b"AOSSSR01";
const REPLY_MAGIC: &[u8; 8] = b"AOSSSP01";
const REQUEST_NAMES_MAGIC: &[u8; 8] = b"AOSSSR02";
const REPLY_NAMES_MAGIC: &[u8; 8] = b"AOSSSP02";
const REQUEST_PROJECT_MAGIC: &[u8; 8] = b"AOSSSR03";
const REPLY_PROJECT_MAGIC: &[u8; 8] = b"AOSSSP03";
const REQUEST_RETIREMENT_MAGIC: &[u8; 8] = b"AOSSSR04";
const REPLY_RETIREMENT_MAGIC: &[u8; 8] = b"AOSSSP04";
const REQUEST_RESERVATION_MAGIC: &[u8; 8] = b"AOSSSR05";
const REPLY_RESERVATION_MAGIC: &[u8; 8] = b"AOSSSP05";
const REQUEST_COMPLETED_MAGIC: &[u8; 8] = b"AOSSSR06";
const REPLY_COMPLETED_MAGIC: &[u8; 8] = b"AOSSSP06";
const REQUEST_GENESIS_MAGIC: &[u8; 8] = b"AOSSSR08";
const REPLY_GENESIS_MAGIC: &[u8; 8] = b"AOSSSP08";
const REPLY_GENESIS_BYTES: usize = 8 + SOURCE_TREE_GENESIS_READBACK_BYTES_V1;
const REPLY_COMPLETED_BYTES: usize = 8 + SOURCE_PROJECT_COMPLETED_TERMINAL_READBACK_BYTES_V1;
const REQUEST_BYTES: usize = 72;
const REQUEST_GENESIS_BYTES: usize = REQUEST_BYTES + SOURCE_TREE_GENESIS_INTENT_CONTEXT_BYTES_V1;
const REPLY_BYTES: usize = 8 + SOURCE_HOLD_READBACK_BYTES_V1;
const REPLY_NAMES_BYTES: usize = 8 + SOURCE_HOLD_READBACK_BYTES_V2;
const REPLY_PROJECT_BYTES: usize = 8 + SOURCE_PROJECT_ADMISSION_READBACK_BYTES_V1;
const REPLY_RESERVATION_BYTES: usize = 8 + SOURCE_PROJECT_RESERVATION_READBACK_BYTES_V1;
const FLIGHT_TIMEOUT: Duration = Duration::from_secs(5);
const REPLY_TIMEOUT: Duration = Duration::from_secs(60);

/// Requests an actual Source genesis observation through the existing signer.
///
/// A missing project/intent requests global Empty, not per-project NotFound.
/// The caller must independently retain genuine Controller/Source and Root
/// flight custody; these authenticated observation bytes cannot reconstruct it.
/// Populated observations require untrusted original-intent comparison data;
/// global Empty requires zero context padding. Legacy AOSSSR07 is unsupported.
///
/// # Errors
///
/// Rejects mixed Empty/populated scope, unsafe signer custody, changed Source
/// role/key/correlation, malformed reply or transport loss.
pub fn request_root_source_tree_genesis_readback_v2(
    challenge: SourceTreeGenesisChallengeV1,
    project: Option<ProjectId>,
    intent_context: Option<&SourceTreeGenesisIntentContextV1>,
    signer: &PinnedSourceHoldReadbackSignerV1,
    signer_uid: u32,
    socket_gid: u32,
) -> io::Result<[u8; SOURCE_TREE_GENESIS_READBACK_BYTES_V1]> {
    if signer_uid == 0 || socket_gid == 0 {
        return Err(invalid_data("invalid Source genesis signer identity"));
    }
    let request = encode_genesis_request(challenge, project, intent_context)?;
    let mut stream = connect_source_signer(signer_uid, socket_gid)?;
    stream.write_all(&request)?;
    stream.shutdown(std::net::Shutdown::Write)?;
    let packet = read_framed_reply::<REPLY_GENESIS_BYTES, SOURCE_TREE_GENESIS_READBACK_BYTES_V1>(
        &mut stream,
        REPLY_GENESIS_MAGIC,
    )?;
    let verified = verify_source_tree_genesis_readback_v1(&packet, signer, challenge)
        .map_err(io::Error::other)?;
    if verified.receipt().map(|receipt| receipt.project()) != project {
        return Err(invalid_data("changed Source genesis project"));
    }
    Ok(packet)
}

fn encode_genesis_request(
    challenge: SourceTreeGenesisChallengeV1,
    project: Option<ProjectId>,
    intent_context: Option<&SourceTreeGenesisIntentContextV1>,
) -> io::Result<[u8; REQUEST_GENESIS_BYTES]> {
    if project.is_some() != challenge.intent().is_some()
        || project.is_some_and(|project| project.as_bytes() == &[0; 16])
        || project.is_some() != intent_context.is_some()
        || intent_context.is_some_and(|context| Some(context.project()) != project)
    {
        return Err(invalid_data("mixed Source genesis scope"));
    }
    let mut request = [0; REQUEST_GENESIS_BYTES];
    request[..8].copy_from_slice(REQUEST_GENESIS_MAGIC);
    request[8..24].copy_from_slice(&challenge.nonce());
    if let Some(intent) = challenge.intent() {
        request[24..56].copy_from_slice(intent.as_bytes());
    }
    if let Some(project) = project {
        request[56..72].copy_from_slice(project.as_bytes());
    }
    if let Some(context) = intent_context {
        request[REQUEST_BYTES..].copy_from_slice(&context.encode());
    }
    Ok(request)
}

fn decode_genesis_request(
    request: &[u8; REQUEST_GENESIS_BYTES],
) -> io::Result<(
    SourceTreeGenesisChallengeV1,
    Option<ProjectId>,
    Option<SourceTreeGenesisIntentContextV1>,
)> {
    if request[..8] != *REQUEST_GENESIS_MAGIC {
        return Err(invalid_data("foreign Source genesis request"));
    }
    let nonce = request[8..24]
        .try_into()
        .map_err(|_| invalid_data("invalid genesis nonce"))?;
    let intent_bytes: [u8; 32] = request[24..56]
        .try_into()
        .map_err(|_| invalid_data("invalid genesis intent"))?;
    let project_bytes: [u8; 16] = request[56..72]
        .try_into()
        .map_err(|_| invalid_data("invalid genesis project"))?;
    let intent = (intent_bytes != [0; 32]).then_some(ObjectDigest::from_bytes(intent_bytes));
    let project = (project_bytes != [0; 16]).then_some(ProjectId::from_bytes(project_bytes));
    let challenge = SourceTreeGenesisChallengeV1::new(nonce, intent).map_err(io::Error::other)?;
    let context = project
        .map(|_| SourceTreeGenesisIntentContextV1::decode(&request[REQUEST_BYTES..]))
        .transpose()
        .map_err(io::Error::other)?;
    if encode_genesis_request(challenge, project, context.as_ref())? != *request {
        return Err(invalid_data("noncanonical Source genesis request"));
    }
    Ok((challenge, project, context))
}

/// Requests only the exact completed Source terminal from its existing reader.
///
/// # Errors
///
/// Rejects foreign fixed peer/custody, pin or completed issue substitution,
/// changed physical names, framing, and transport loss. This packet never
/// establishes positive ancestry or latest deployment authority.
pub fn request_root_source_project_completed_terminal_readback_v1(
    expected: SourceProjectAdmissionReservationV1,
    root_terminal: ObjectDigest,
    signer: &PinnedSourceHoldReadbackSignerV1,
    signer_uid: u32,
    socket_gid: u32,
) -> io::Result<[u8; SOURCE_PROJECT_COMPLETED_TERMINAL_READBACK_BYTES_V1]> {
    if signer_uid == 0 || socket_gid == 0 {
        return Err(invalid_data("invalid Source signer identity"));
    }
    let challenge = SourceHoldReadbackChallengeV1::new(expected.client_nonce(), root_terminal)
        .map_err(io::Error::other)?;
    let mut stream = connect_source_signer(signer_uid, socket_gid)?;
    let mut request = encode_request(challenge, expected.project());
    request[..8].copy_from_slice(REQUEST_COMPLETED_MAGIC);
    stream.write_all(&request)?;
    stream.shutdown(std::net::Shutdown::Write)?;
    let packet = read_framed_reply::<
        REPLY_COMPLETED_BYTES,
        SOURCE_PROJECT_COMPLETED_TERMINAL_READBACK_BYTES_V1,
    >(&mut stream, REPLY_COMPLETED_MAGIC)?;
    let verified = verify_source_project_completed_terminal_readback_v1(&packet, signer, challenge)
        .map_err(io::Error::other)?;
    if verified.reservation() != expected || verified.names() != expected.names() {
        return Err(invalid_data("changed Source completed issue"));
    }
    Ok(packet)
}

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
    let mut stream = connect_source_signer(signer_uid, socket_gid)?;

    let request = encode_request(challenge, project);
    stream.write_all(&request)?;
    stream.shutdown(std::net::Shutdown::Write)?;
    let packet = read_reply(&mut stream)?;
    verify_current_source_hold_readback_v1(&packet, signer, challenge, project, expected_hold)
        .map_err(io::Error::other)?;
    Ok(packet)
}

/// Requests a Source-only signature over the held head and fixed physical names.
///
/// This remains nonauthorizing. Root must spend the challenge under the
/// matching Source writer and join its Controller/Cache cut before SUBMIT.
///
/// # Errors
///
/// Rejects unsafe signer custody, malformed transport, changed pin or hold,
/// and mismatched directory, journal, or lock inode identities.
#[allow(clippy::too_many_arguments)]
pub fn request_root_source_signer_readback_with_names_v2(
    challenge: SourceHoldReadbackChallengeV1,
    project: ProjectId,
    expected_hold: SourceDomainPolicyHoldV1,
    expected_names: ProtectedJournalNamesV1,
    signer: &PinnedSourceHoldReadbackSignerV1,
    signer_uid: u32,
    socket_gid: u32,
) -> io::Result<[u8; SOURCE_HOLD_READBACK_BYTES_V2]> {
    if project.as_bytes() == &[0; 16] || signer_uid == 0 || socket_gid == 0 {
        return Err(invalid_data("invalid Source signer request identity"));
    }
    let mut stream = connect_source_signer(signer_uid, socket_gid)?;

    let mut request = encode_request(challenge, project);
    request[..8].copy_from_slice(REQUEST_NAMES_MAGIC);
    stream.write_all(&request)?;
    stream.shutdown(std::net::Shutdown::Write)?;
    let packet = read_names_reply(&mut stream)?;
    verify_source_hold_readback_with_names_v2(
        &packet,
        signer,
        challenge,
        project,
        expected_hold,
        expected_names,
    )
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

/// Requests an independent Source-only pre-Q04 ancestry readback as Root.
///
/// The expected AOSQPA01 row must come from the Controller-retained Source
/// writer. The signer independently replays its read-only idmapped view and
/// Root compares the reply to its pinned Source key and stage challenge.
///
/// # Errors
///
/// Rejects unsafe socket custody, wrong signer, stale row or ancestry,
/// malformed framing, transport loss, or substituted names.
pub fn request_root_source_project_admission_readback_v1(
    challenge: SourceHoldReadbackChallengeV1,
    expected: SourceProjectAdmissionChallengeV1,
    reservation_digest: ObjectDigest,
    signer: &PinnedSourceHoldReadbackSignerV1,
    signer_uid: u32,
    socket_gid: u32,
) -> io::Result<[u8; SOURCE_PROJECT_ADMISSION_READBACK_BYTES_V1]> {
    let project = expected.project();
    if project.as_bytes() == &[0; 16]
        || signer_uid == 0
        || socket_gid == 0
        || expected.nonce() != challenge.nonce()
        || expected.cut() != challenge.cut()
    {
        return Err(invalid_data("invalid Source project-admission challenge"));
    }
    let mut stream = connect_source_signer(signer_uid, socket_gid)?;
    let mut request = encode_request(challenge, project);
    request[..8].copy_from_slice(REQUEST_PROJECT_MAGIC);
    stream.write_all(&request)?;
    stream.shutdown(std::net::Shutdown::Write)?;
    let packet = read_project_reply(&mut stream)?;
    verify_source_project_admission_readback_v1(
        &packet,
        signer,
        challenge,
        project,
        expected,
        reservation_digest,
    )
    .map_err(io::Error::other)?;
    Ok(packet)
}

/// Requests a Source-only exact-row retirement proof as Root.
///
/// This separate signer mode never attests current ancestry and cannot be
/// substituted for an admission packet. Root uses it only for durable abort.
///
/// # Errors
///
/// Rejects foreign signer/socket custody, changed row/names, malformed frame,
/// or signature mismatch against the pinned Source-only role.
pub fn request_root_source_project_retirement_readback_v1(
    challenge: SourceHoldReadbackChallengeV1,
    expected: SourceProjectAdmissionChallengeV1,
    reservation_digest: ObjectDigest,
    signer: &PinnedSourceHoldReadbackSignerV1,
    signer_uid: u32,
    socket_gid: u32,
) -> io::Result<[u8; SOURCE_PROJECT_ADMISSION_READBACK_BYTES_V1]> {
    if expected.nonce() != challenge.nonce()
        || expected.cut() != challenge.cut()
        || signer_uid == 0
        || socket_gid == 0
    {
        return Err(invalid_data("invalid Source project-retirement challenge"));
    }
    let mut stream = connect_source_signer(signer_uid, socket_gid)?;
    let mut request = encode_request(challenge, expected.project());
    request[..8].copy_from_slice(REQUEST_RETIREMENT_MAGIC);
    stream.write_all(&request)?;
    stream.shutdown(std::net::Shutdown::Write)?;
    let packet = read_project_retirement_reply(&mut stream)?;
    verify_source_project_retirement_readback_v1(
        &packet,
        signer,
        challenge,
        expected.project(),
        expected,
        reservation_digest,
    )
    .map_err(io::Error::other)?;
    Ok(packet)
}

/// Reads an independently signed exact Source reservation before Root stage.
///
/// Root supplies the Controller-held typed row but accepts it only after the
/// fixed Source signer replays the same unconsumed row and physical names.
///
/// # Errors
///
/// Rejects changed custody, row, signer pin, framing, or transport.
pub fn request_root_source_project_reservation_readback_v1(
    expected: SourceProjectAdmissionReservationV1,
    signer: &PinnedSourceHoldReadbackSignerV1,
    signer_uid: u32,
    socket_gid: u32,
) -> io::Result<[u8; SOURCE_PROJECT_RESERVATION_READBACK_BYTES_V1]> {
    if signer_uid == 0 || socket_gid == 0 {
        return Err(invalid_data("invalid Source reservation signer identity"));
    }
    let challenge =
        SourceHoldReadbackChallengeV1::new(expected.client_nonce(), expected.record_digest())
            .map_err(io::Error::other)?;
    let mut stream = connect_source_signer(signer_uid, socket_gid)?;
    let mut request = encode_request(challenge, expected.project());
    request[..8].copy_from_slice(REQUEST_RESERVATION_MAGIC);
    stream.write_all(&request)?;
    stream.shutdown(std::net::Shutdown::Write)?;
    let packet = read_framed_reply::<
        REPLY_RESERVATION_BYTES,
        SOURCE_PROJECT_RESERVATION_READBACK_BYTES_V1,
    >(&mut stream, REPLY_RESERVATION_MAGIC)?;
    verify_source_project_reservation_readback_v1(&packet, signer, expected)
        .map_err(io::Error::other)?;
    Ok(packet)
}

fn connect_source_signer(signer_uid: u32, socket_gid: u32) -> io::Result<UnixStream> {
    require_socket_path_custody(signer_uid, socket_gid)?;
    let stream = UnixStream::connect(SOURCE_SIGNER_SOCKET_PATH_V1)?;
    require_socket_path_custody(signer_uid, socket_gid)?;
    stream.set_read_timeout(Some(REPLY_TIMEOUT))?;
    stream.set_write_timeout(Some(FLIGHT_TIMEOUT))?;
    Ok(stream)
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
    read_framed_reply::<REPLY_BYTES, SOURCE_HOLD_READBACK_BYTES_V1>(stream, REPLY_MAGIC)
}

fn read_names_reply(stream: &mut UnixStream) -> io::Result<[u8; SOURCE_HOLD_READBACK_BYTES_V2]> {
    read_framed_reply::<REPLY_NAMES_BYTES, SOURCE_HOLD_READBACK_BYTES_V2>(stream, REPLY_NAMES_MAGIC)
}

fn read_project_reply(
    stream: &mut UnixStream,
) -> io::Result<[u8; SOURCE_PROJECT_ADMISSION_READBACK_BYTES_V1]> {
    read_framed_reply::<REPLY_PROJECT_BYTES, SOURCE_PROJECT_ADMISSION_READBACK_BYTES_V1>(
        stream,
        REPLY_PROJECT_MAGIC,
    )
}

fn read_project_retirement_reply(
    stream: &mut UnixStream,
) -> io::Result<[u8; SOURCE_PROJECT_ADMISSION_READBACK_BYTES_V1]> {
    read_framed_reply::<REPLY_PROJECT_BYTES, SOURCE_PROJECT_ADMISSION_READBACK_BYTES_V1>(
        stream,
        REPLY_RETIREMENT_MAGIC,
    )
}

fn read_framed_reply<const REPLY: usize, const PACKET: usize>(
    stream: &mut UnixStream,
    magic: &[u8; 8],
) -> io::Result<[u8; PACKET]> {
    let mut reply = [0; REPLY];
    stream.read_exact(&mut reply)?;
    let mut trailing = [0];
    if reply.get(..8) != Some(magic.as_slice()) || stream.read(&mut trailing)? != 0 {
        return Err(invalid_data("invalid Source signer reply"));
    }
    reply
        .get(8..)
        .ok_or_else(|| invalid_data("invalid Source signer packet length"))?
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
    if request[..8] == *REQUEST_GENESIS_MAGIC {
        let mut expanded = [0; REQUEST_GENESIS_BYTES];
        expanded[..REQUEST_BYTES].copy_from_slice(&request);
        stream.read_exact(&mut expanded[REQUEST_BYTES..])?;
        require_request_eof(stream)?;
        let (challenge, project, context) = decode_genesis_request(&expanded)?;
        let signing_key = credentials.signing_key()?;
        let packet = sign_fixed_source_tree_genesis_readback_v2(
            controller_uid,
            project,
            challenge,
            context.as_ref(),
            credentials.generation(),
            &signing_key,
        )?;
        write_framed_reply::<REPLY_GENESIS_BYTES>(stream, REPLY_GENESIS_MAGIC, &packet)?;
        stream.shutdown(std::net::Shutdown::Write)?;
        return Ok(());
    }
    require_request_eof(stream)?;
    let (challenge, project, mode) = decode_request_mode(&request)?;
    let signing_key = credentials.signing_key()?;
    if mode == SourceSignerRequestModeV1::ProjectCompletedTerminal {
        let packet = sign_fixed_source_project_completed_terminal_readback_v1(
            controller_uid,
            challenge,
            credentials.generation(),
            &signing_key,
        )?;
        write_framed_reply::<REPLY_COMPLETED_BYTES>(stream, REPLY_COMPLETED_MAGIC, &packet)?;
    } else if mode == SourceSignerRequestModeV1::ProjectAdmission {
        let packet = sign_fixed_source_project_admission_readback_v1(
            controller_uid,
            project,
            challenge,
            credentials.generation(),
            &signing_key,
        )?;
        write_framed_reply::<REPLY_PROJECT_BYTES>(stream, REPLY_PROJECT_MAGIC, &packet)?;
    } else if mode == SourceSignerRequestModeV1::ProjectReservation {
        let packet = sign_fixed_source_project_reservation_readback_v1(
            controller_uid,
            challenge.nonce(),
            project,
            challenge.cut(),
            credentials.generation(),
            &signing_key,
        )?;
        write_framed_reply::<REPLY_RESERVATION_BYTES>(stream, REPLY_RESERVATION_MAGIC, &packet)?;
    } else if mode == SourceSignerRequestModeV1::ProjectRetirement {
        let packet = sign_fixed_source_project_retirement_readback_v1(
            controller_uid,
            project,
            challenge,
            credentials.generation(),
            &signing_key,
        )?;
        write_framed_reply::<REPLY_PROJECT_BYTES>(stream, REPLY_RETIREMENT_MAGIC, &packet)?;
    } else if mode == SourceSignerRequestModeV1::HeldNames {
        let packet = sign_fixed_source_signer_readback_v2(
            controller_uid,
            project,
            challenge,
            credentials.generation(),
            &signing_key,
        )?;
        write_framed_reply::<REPLY_NAMES_BYTES>(stream, REPLY_NAMES_MAGIC, &packet)?;
    } else {
        let packet = sign_fixed_source_signer_readback_v1(
            controller_uid,
            project,
            challenge,
            credentials.generation(),
            &signing_key,
        )?;
        write_framed_reply::<REPLY_BYTES>(stream, REPLY_MAGIC, &packet)?;
    }
    stream.shutdown(std::net::Shutdown::Write)?;
    Ok(())
}

fn require_request_eof(stream: &mut UnixStream) -> io::Result<()> {
    let mut trailing = [0];
    if stream.read(&mut trailing)? != 0 {
        return Err(invalid_data("trailing Source signer request bytes"));
    }
    Ok(())
}

fn write_framed_reply<const REPLY: usize>(
    stream: &mut UnixStream,
    magic: &[u8; 8],
    packet: &[u8],
) -> io::Result<()> {
    let mut reply = [0; REPLY];
    let payload = reply
        .get_mut(8..)
        .filter(|payload| payload.len() == packet.len())
        .ok_or_else(|| invalid_data("invalid Source signer reply length"))?;
    payload.copy_from_slice(packet);
    reply[..8].copy_from_slice(magic);
    stream.write_all(&reply)
}

fn decode_request_mode(
    request: &[u8; REQUEST_BYTES],
) -> io::Result<(
    SourceHoldReadbackChallengeV1,
    ProjectId,
    SourceSignerRequestModeV1,
)> {
    let mode = match request.get(..8) {
        Some(magic) if magic == REQUEST_MAGIC => SourceSignerRequestModeV1::Held,
        Some(magic) if magic == REQUEST_NAMES_MAGIC => SourceSignerRequestModeV1::HeldNames,
        Some(magic) if magic == REQUEST_PROJECT_MAGIC => {
            SourceSignerRequestModeV1::ProjectAdmission
        }
        Some(magic) if magic == REQUEST_RETIREMENT_MAGIC => {
            SourceSignerRequestModeV1::ProjectRetirement
        }
        Some(magic) if magic == REQUEST_RESERVATION_MAGIC => {
            SourceSignerRequestModeV1::ProjectReservation
        }
        Some(magic) if magic == REQUEST_COMPLETED_MAGIC => {
            SourceSignerRequestModeV1::ProjectCompletedTerminal
        }
        _ => return Err(invalid_data("foreign Source signer request")),
    };
    let mut canonical = *request;
    canonical[..8].copy_from_slice(REQUEST_MAGIC);
    let (challenge, project) = decode_request(&canonical)?;
    Ok((challenge, project, mode))
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum SourceSignerRequestModeV1 {
    Held,
    HeldNames,
    ProjectAdmission,
    ProjectRetirement,
    ProjectReservation,
    ProjectCompletedTerminal,
}

#[cfg(test)]
mod tests {
    use super::*;

    // Independent canonical DATA bytes for framing, not issuer or owner trust.
    fn genesis_context(project: ProjectId) -> SourceTreeGenesisIntentContextV1 {
        let mut context = [0; SOURCE_TREE_GENESIS_INTENT_CONTEXT_BYTES_V1];
        context[..8].copy_from_slice(b"AOSSGX01");
        context[8..10].copy_from_slice(&1_u16.to_be_bytes());
        context[16..20].copy_from_slice(&1000_u32.to_be_bytes());
        context[24..56].fill(9);
        let acceptance = &mut context[56..];
        acceptance[..8].copy_from_slice(b"AOSSGC01");
        acceptance[8..10].copy_from_slice(&1_u16.to_be_bytes());
        acceptance[16..32].copy_from_slice(project.as_bytes());
        acceptance[480..512].fill(4);
        acceptance[512..544].fill(5);
        acceptance[544..576].fill(6);
        acceptance[576..608].fill(7);

        for (offset, magic, version) in [(32, b"AOSCSE01", 1_u16), (256, b"AOSPSC02", 2_u16)] {
            let packet = &mut acceptance[offset..offset + 224];
            packet[..8].copy_from_slice(magic);
            packet[8..10].copy_from_slice(&version.to_be_bytes());
            packet[12..20].copy_from_slice(&1_u64.to_be_bytes());
            packet[20..36].copy_from_slice(project.as_bytes());
            packet[36..44].copy_from_slice(&2_u64.to_be_bytes());
            packet[44..76].fill(4);
            packet[76..108].fill(if version == 1 { 6 } else { 5 });
            packet[108..124].fill(8);
            packet[124..132].copy_from_slice(&1_u64.to_be_bytes());
            for (limit, value) in packet[132..160]
                .chunks_exact_mut(4)
                .zip([1_u32, 2, 1, 1, 1, 1, 1])
            {
                limit.copy_from_slice(&value.to_be_bytes());
            }
        }
        SourceTreeGenesisIntentContextV1::decode(&context).unwrap()
    }

    #[test]
    fn genesis_requests_keep_global_empty_distinct_from_populated_and_legacy_modes() {
        let empty = SourceTreeGenesisChallengeV1::new([1; 16], None).unwrap();
        let bytes = encode_genesis_request(empty, None, None).unwrap();
        assert_eq!(decode_genesis_request(&bytes).unwrap(), (empty, None, None));
        assert!(decode_request_mode(bytes[..REQUEST_BYTES].try_into().unwrap()).is_err());
        assert_eq!(bytes.len(), 736);
        assert_eq!(&bytes[..8], b"AOSSSR08");
        assert!(bytes[REQUEST_BYTES..].iter().all(|byte| *byte == 0));

        let project = ProjectId::from_bytes([2; 16]);
        let populated =
            SourceTreeGenesisChallengeV1::new([3; 16], Some(ObjectDigest::from_bytes([4; 32])))
                .unwrap();
        let context = genesis_context(project);
        let bytes = encode_genesis_request(populated, Some(project), Some(&context)).unwrap();
        assert_eq!(
            decode_genesis_request(&bytes).unwrap(),
            (populated, Some(project), Some(context.clone()))
        );
        assert!(encode_genesis_request(populated, None, Some(&context)).is_err());
        assert!(encode_genesis_request(empty, Some(project), Some(&context)).is_err());
        assert!(encode_genesis_request(populated, Some(project), None).is_err());
        assert!(encode_genesis_request(empty, None, Some(&context)).is_err());
        assert!(
            encode_genesis_request(
                populated,
                Some(project),
                Some(&genesis_context(ProjectId::from_bytes([5; 16])))
            )
            .is_err()
        );
        for range in [8..24, 24..56, 56..72, REQUEST_BYTES..REQUEST_GENESIS_BYTES] {
            let mut malformed = bytes;
            malformed[range].fill(0);
            assert!(decode_genesis_request(&malformed).is_err());
        }
        let mut foreign = bytes;
        foreign[..8].copy_from_slice(REQUEST_NAMES_MAGIC);
        assert!(decode_genesis_request(&foreign).is_err());
        foreign[..8].copy_from_slice(b"AOSSSR07");
        assert!(decode_genesis_request(&foreign).is_err());
        assert!(decode_request_mode(foreign[..REQUEST_BYTES].try_into().unwrap()).is_err());

        let mut empty = encode_genesis_request(empty, None, None).unwrap();
        empty[REQUEST_BYTES] = 1;
        assert!(decode_genesis_request(&empty).is_err());
    }

    #[test]
    fn genesis_replies_require_exact_domain_width_and_eof() {
        let payload = [7; SOURCE_TREE_GENESIS_READBACK_BYTES_V1];
        let (mut sender, mut receiver) = UnixStream::pair().unwrap();
        write_framed_reply::<REPLY_GENESIS_BYTES>(&mut sender, REPLY_GENESIS_MAGIC, &payload)
            .unwrap();
        sender.shutdown(std::net::Shutdown::Write).unwrap();
        assert_eq!(
            read_framed_reply::<REPLY_GENESIS_BYTES, SOURCE_TREE_GENESIS_READBACK_BYTES_V1>(
                &mut receiver,
                REPLY_GENESIS_MAGIC,
            )
            .unwrap(),
            payload
        );

        for mutation in 0..3 {
            let (mut sender, mut receiver) = UnixStream::pair().unwrap();
            let mut bytes = vec![7; REPLY_GENESIS_BYTES];
            bytes[..8].copy_from_slice(REPLY_GENESIS_MAGIC);
            match mutation {
                0 => bytes[..8].copy_from_slice(REPLY_COMPLETED_MAGIC),
                1 => {
                    bytes.pop();
                }
                _ => bytes.push(0),
            }
            sender.write_all(&bytes).unwrap();
            sender.shutdown(std::net::Shutdown::Write).unwrap();
            assert!(
                read_framed_reply::<REPLY_GENESIS_BYTES, SOURCE_TREE_GENESIS_READBACK_BYTES_V1>(
                    &mut receiver,
                    REPLY_GENESIS_MAGIC,
                )
                .is_err()
            );
        }
    }

    #[test]
    fn framed_project_replies_require_exact_magic_length_and_eof() {
        let mut canonical = [0; REPLY_PROJECT_BYTES];
        canonical[..8].copy_from_slice(REPLY_PROJECT_MAGIC);
        canonical[8..].fill(7);
        let (mut client, mut server) = UnixStream::pair().unwrap();
        write_framed_reply::<REPLY_PROJECT_BYTES>(
            &mut client,
            REPLY_PROJECT_MAGIC,
            &[7; SOURCE_PROJECT_ADMISSION_READBACK_BYTES_V1],
        )
        .unwrap();
        client.shutdown(std::net::Shutdown::Write).unwrap();
        assert_eq!(
            read_project_reply(&mut server).unwrap(),
            [7; SOURCE_PROJECT_ADMISSION_READBACK_BYTES_V1]
        );

        for changed in [
            {
                let mut changed = canonical.to_vec();
                changed[0] ^= 1;
                changed
            },
            canonical[..canonical.len() - 1].to_vec(),
            {
                let mut changed = canonical.to_vec();
                changed.push(1);
                changed
            },
        ] {
            let (mut client, mut server) = UnixStream::pair().unwrap();
            client.write_all(&changed).unwrap();
            client.shutdown(std::net::Shutdown::Write).unwrap();
            assert!(read_project_reply(&mut server).is_err());
        }

        let mut reservation = [0; REPLY_RESERVATION_BYTES];
        reservation[..8].copy_from_slice(REPLY_RESERVATION_MAGIC);
        let (mut client, mut server) = UnixStream::pair().unwrap();
        assert!(
            write_framed_reply::<REPLY_RESERVATION_BYTES>(
                &mut client,
                REPLY_RESERVATION_MAGIC,
                &[0; 1],
            )
            .is_err()
        );
        client.write_all(&reservation).unwrap();
        client.shutdown(std::net::Shutdown::Write).unwrap();
        assert!(
            read_framed_reply::<
                REPLY_RESERVATION_BYTES,
                SOURCE_PROJECT_RESERVATION_READBACK_BYTES_V1,
            >(&mut server, REPLY_RESERVATION_MAGIC,)
            .is_ok()
        );
    }

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
        let mut names = bytes;
        names[..8].copy_from_slice(REQUEST_NAMES_MAGIC);
        assert_eq!(
            decode_request_mode(&names).expect("names request"),
            (challenge, project, SourceSignerRequestModeV1::HeldNames)
        );
        let mut project_admission = bytes;
        project_admission[..8].copy_from_slice(REQUEST_PROJECT_MAGIC);
        assert_eq!(
            decode_request_mode(&project_admission).expect("project admission request"),
            (
                challenge,
                project,
                SourceSignerRequestModeV1::ProjectAdmission
            )
        );
        let mut retirement = bytes;
        retirement[..8].copy_from_slice(REQUEST_RETIREMENT_MAGIC);
        assert_eq!(
            decode_request_mode(&retirement).expect("project retirement request"),
            (
                challenge,
                project,
                SourceSignerRequestModeV1::ProjectRetirement
            )
        );
        let mut reservation = bytes;
        reservation[..8].copy_from_slice(REQUEST_RESERVATION_MAGIC);
        assert_eq!(
            decode_request_mode(&reservation).expect("project reservation request"),
            (
                challenge,
                project,
                SourceSignerRequestModeV1::ProjectReservation
            )
        );
        let mut completed = bytes;
        completed[..8].copy_from_slice(REQUEST_COMPLETED_MAGIC);
        assert_eq!(
            decode_request_mode(&completed).unwrap(),
            (
                challenge,
                project,
                SourceSignerRequestModeV1::ProjectCompletedTerminal
            )
        );
        completed[8..24].fill(0);
        assert!(decode_request_mode(&completed).is_err());

        let mut foreign = bytes;
        foreign[..8].copy_from_slice(b"AOSCSC02");
        assert!(decode_request(&foreign).is_err());
        assert!(decode_request_mode(&foreign).is_err());
        let mut zero_project = bytes;
        zero_project[56..72].fill(0);
        assert!(decode_request(&zero_project).is_err());
        let mut zero_nonce = bytes;
        zero_nonce[8..24].fill(0);
        assert!(decode_request(&zero_nonce).is_err());
        names[8..24].fill(0);
        assert!(decode_request_mode(&names).is_err());
    }

    #[test]
    fn names_reply_requires_distinct_version_and_exact_eof() {
        let read = |magic: &[u8; 8], extra: &[u8]| {
            let (mut root, mut signer) = UnixStream::pair().expect("Source signer pair");
            let mut reply = [0; REPLY_NAMES_BYTES];
            reply[..8].copy_from_slice(magic);
            signer.write_all(&reply).expect("reply");
            signer.write_all(extra).expect("extra");
            signer.shutdown(std::net::Shutdown::Write).expect("EOF");
            read_names_reply(&mut root)
        };
        assert!(read(REPLY_NAMES_MAGIC, &[]).is_ok());
        assert!(read(REPLY_MAGIC, &[]).is_err());
        assert!(read(REPLY_NAMES_MAGIC, &[1]).is_err());
    }

    #[test]
    fn completed_terminal_reply_rejects_pending_domain_width_and_trailing_bytes() {
        let read = |bytes: &[u8]| {
            let (mut root, mut signer) = UnixStream::pair().unwrap();
            signer.write_all(bytes).unwrap();
            signer.shutdown(std::net::Shutdown::Write).unwrap();
            read_framed_reply::<
                REPLY_COMPLETED_BYTES,
                SOURCE_PROJECT_COMPLETED_TERMINAL_READBACK_BYTES_V1,
            >(&mut root, REPLY_COMPLETED_MAGIC)
        };
        let mut completed = [0; REPLY_COMPLETED_BYTES];
        completed[..8].copy_from_slice(REPLY_COMPLETED_MAGIC);
        completed[8..].fill(7);
        assert_eq!(
            read(&completed).unwrap(),
            [7; SOURCE_PROJECT_COMPLETED_TERMINAL_READBACK_BYTES_V1]
        );
        let mut pending_domain = completed;
        pending_domain[..8].copy_from_slice(REPLY_PROJECT_MAGIC);
        assert!(read(&pending_domain).is_err());
        assert!(read(&completed[..completed.len() - 1]).is_err());
        assert!(read(&[completed.as_slice(), &[1]].concat()).is_err());
    }
}
