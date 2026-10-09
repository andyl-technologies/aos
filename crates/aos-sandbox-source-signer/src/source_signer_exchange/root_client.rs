//! Fixed Root-client exchanges with the independently pinned Source signer.
//!
//! Each complete recipe retains its original signer stream through request
//! send, write shutdown, exact reply framing/EOF and purpose verification.
//! Public entries are directly reexported by the parent, which owns canonical
//! wire codecs and fixed socket custody checks.
//!
//! Returned packets remain nonauthorizing DATA. Protected Root and Controller
//! loans, currentness decisions and retained result reservoirs stay with the
//! existing upper callers; this owner creates no writer or paid grant.

use std::io::{self, Read as _, Write as _};
use std::os::unix::net::UnixStream;
use std::time::Duration;

use aos_sandbox::journal::{
    ProtectedJournalNamesV1, SourceDomainPolicyHoldV1, SourceProjectAdmissionChallengeV1,
    SourceProjectAdmissionReservationV1,
};
use aos_sandbox::policy_compiler::{
    PinnedSourceHoldReadbackSignerV1,
    RootFirstSourceSuccessorIntentV2,
    SOURCE_FIRST_SUCCESSOR_READBACK_BYTES_V2,
    SOURCE_HOLD_READBACK_BYTES_V1,
    SOURCE_HOLD_READBACK_BYTES_V2,
    SOURCE_PROJECT_ADMISSION_READBACK_BYTES_V1,
    SOURCE_PROJECT_COMPLETED_TERMINAL_READBACK_BYTES_V1,
    SOURCE_PROJECT_CONTINUATION_READBACK_BYTES_V3,
    SOURCE_PROJECT_GENESIS_READBACK_BYTES_V3,
    SOURCE_PROJECT_RESERVATION_READBACK_BYTES_V1,
    SOURCE_PROJECT_RESOURCE_GENESIS_READBACK_BYTES_V4,
    SOURCE_TREE_GENESIS_READBACK_BYTES_V1,
    SOURCE_TREE_GENESIS_READBACK_BYTES_V2,
    SourceHoldReadbackChallengeV1,
    SourceProjectGenesisChallengeV3,
    SourceProjectGenesisReadbackPacketV4,
    SourceTreeGenesisChallengeV1,
    SourceTreeGenesisIntentContextV1,
    SourceTreeGenesisReadbackPacketV2,
    StagedClosedPolicySignerChallengeV2,
    verify_current_source_hold_readback_v1,
    verify_source_first_successor_readback_v2,
    verify_source_hold_readback_with_names_v2,
    verify_source_project_admission_readback_v1,
    verify_source_project_completed_terminal_readback_v1,
    verify_source_project_continuation_readback_v3,
    verify_source_project_genesis_readback_v3,
    verify_source_project_reservation_readback_v1,
    verify_source_project_retirement_readback_v1,
    verify_source_tree_genesis_readback_v1,
    verify_source_tree_genesis_readback_v2,
};
use aos_sandbox_core::{ObjectDigest, ProjectId};

use super::{
    FLIGHT_TIMEOUT,
    REPLY_COMPLETED_BYTES,
    REPLY_COMPLETED_MAGIC,
    REPLY_FIRST_SUCCESSOR_BYTES,
    REPLY_GENESIS_BYTES,
    REPLY_GENESIS_MAGIC,
    REPLY_PROJECT_GENESIS_MAGIC_V3,
    REPLY_PROJECT_RESOURCE_GENESIS_BYTES_V4,
    REPLY_PROJECT_RESOURCE_GENESIS_MAGIC_V4,
    REPLY_RESERVATION_BYTES,
    REPLY_RESERVATION_MAGIC,
    REPLY_RESOURCE_CONTINUATION_MAGIC_V5,
    REPLY_RESOURCE_GENESIS_MAGIC,
    REPLY_RESOURCE_SUCCESSOR_MAGIC_V4,
    REQUEST_COMPLETED_MAGIC,
    REQUEST_NAMES_MAGIC,
    REQUEST_PROJECT_MAGIC,
    REQUEST_PROJECT_RESOURCE_GENESIS_BYTES_V4,
    REQUEST_RESERVATION_MAGIC,
    REQUEST_RETIREMENT_MAGIC,
    SOURCE_SIGNER_SOCKET_PATH_V1,
    SourceSuccessorRequestRecipe,
    encode_first_successor_request,
    encode_genesis_request,
    encode_project_genesis_request,
    encode_project_genesis_request_v3,
    encode_request,
    encode_resource_successor_request,
    encode_source_successor_request,
    encode_strict_genesis_request,
    invalid_data,
    read_framed_reply,
    read_names_reply,
    read_project_reply,
    read_project_retirement_reply,
    read_reply,
    require_socket_path_custody,
};

const REPLY_TIMEOUT: Duration = Duration::from_secs(60);

/// Requests approval-free selected genesis DATA from the same independent signer.
///
/// # Errors
/// Rejects endpoint custody, incomplete context, exact framing/EOF or the
/// independently pinned Source03 signature. No response is a writer loan.
pub fn request_root_source_project_genesis_readback_v3(
    challenge: SourceProjectGenesisChallengeV3,
    context: &SourceTreeGenesisIntentContextV1,
    signer: &PinnedSourceHoldReadbackSignerV1,
    signer_uid: u32,
    socket_gid: u32,
) -> io::Result<[u8; SOURCE_PROJECT_GENESIS_READBACK_BYTES_V3]> {
    if signer_uid == 0 || socket_gid == 0 { return Err(invalid_data("invalid selected genesis signer identity")); }
    let request = encode_project_genesis_request_v3(challenge, context)?;
    let packet = exchange_project_genesis_request::<REPLY_GENESIS_BYTES, SOURCE_PROJECT_GENESIS_READBACK_BYTES_V3>(
        &request, REPLY_PROJECT_GENESIS_MAGIC_V3, signer_uid, socket_gid, signer, challenge,
    )?;
    Ok(packet)
}

/// Requests the full resource Project observation through the existing signer.
///
/// Legacy context uses the unchanged request11 path. Full context selects only
/// resource request12 and the same endpoint, peer policy, key and verifier.
///
/// # Errors
/// Rejects foreign endpoint custody, mismatched context, framing/EOF, signature
/// or the existing signer's full-family replay and current-cut conditions.
pub fn request_root_source_project_genesis_readback_v4(
    challenge: SourceProjectGenesisChallengeV3,
    context: &SourceTreeGenesisIntentContextV1,
    signer: &PinnedSourceHoldReadbackSignerV1,
    signer_uid: u32,
    socket_gid: u32,
) -> io::Result<SourceProjectGenesisReadbackPacketV4> {
    if !context.has_resource_authorization() {
        return request_root_source_project_genesis_readback_v3(
            challenge, context, signer, signer_uid, socket_gid,
        ).map(SourceProjectGenesisReadbackPacketV4::Legacy);
    }
    if signer_uid == 0 || socket_gid == 0 {
        return Err(invalid_data("invalid selected genesis signer identity"));
    }
    let request = encode_project_genesis_request::<REQUEST_PROJECT_RESOURCE_GENESIS_BYTES_V4>(challenge, context)?;
    let packet = exchange_project_genesis_request::<REPLY_PROJECT_RESOURCE_GENESIS_BYTES_V4, SOURCE_PROJECT_RESOURCE_GENESIS_READBACK_BYTES_V4>(
        &request, REPLY_PROJECT_RESOURCE_GENESIS_MAGIC_V4, signer_uid, socket_gid, signer, challenge,
    )?;
    Ok(SourceProjectGenesisReadbackPacketV4::Resource(packet))
}

fn exchange_project_genesis_request<const REPLY: usize, const PACKET: usize>(
    request: &[u8], reply_magic: &[u8; 8], signer_uid: u32, socket_gid: u32,
    signer: &PinnedSourceHoldReadbackSignerV1, challenge: SourceProjectGenesisChallengeV3,
) -> io::Result<[u8; PACKET]> {
    exchange_source_genesis_request::<REPLY, PACKET>(
        request, reply_magic, signer_uid, socket_gid, |packet| {
            verify_source_project_genesis_readback_v3(packet, signer, challenge)
                .map(|_| ()).map_err(io::Error::other)
        },
    )
}

fn exchange_source_genesis_request<const REPLY: usize, const PACKET: usize>(
    request: &[u8], reply_magic: &[u8; 8], signer_uid: u32, socket_gid: u32,
    verify: impl FnOnce(&[u8]) -> io::Result<()>,
) -> io::Result<[u8; PACKET]> {
    let mut stream = connect_source_signer(signer_uid, socket_gid)?;
    stream.write_all(request)?;
    stream.shutdown(std::net::Shutdown::Write)?;
    let packet = read_framed_reply::<REPLY, PACKET>(&mut stream, reply_magic)?;
    // Verification stays inside the same original endpoint lifetime, exactly
    // as in the legacy request path; a helper return cannot release it early.
    verify(&packet)?;
    Ok(packet)
}

/// Requests fixed successor DATA from the existing independently pinned signer.
///
/// The actual Root observation loan parks this returned Result before later
/// Root/stream/pin checks. The ordinary signer connection helper retains its
/// existing pre-return partial-transport boundary; this is not a new writer.
///
/// # Errors
/// Rejects wrong signer/socket custody, exact framing/EOF, context or signature.
pub fn request_root_source_first_successor_readback_v2(
    fresh_nonce: [u8; 16], context: &RootFirstSourceSuccessorIntentV2,
    signer: &PinnedSourceHoldReadbackSignerV1, signer_uid: u32, socket_gid: u32,
) -> io::Result<[u8; SOURCE_FIRST_SUCCESSOR_READBACK_BYTES_V2]> {
    request_root_source_successor_readback(
        fresh_nonce, context, signer, signer_uid, socket_gid,
        SourceSuccessorRequestRecipe::SingleProjectV2,
    )
}

/// Requests explicit mixed-family Source DATA over the existing signer socket.
///
/// # Errors
/// Rejects wrong endpoint custody, framing/EOF, selected context or v3-purpose
/// signature. The returned bytes cannot enter the strict-v2 Root verifier.
pub fn request_root_source_project_continuation_readback_v3(
    fresh_nonce: [u8; 16], context: &RootFirstSourceSuccessorIntentV2,
    signer: &PinnedSourceHoldReadbackSignerV1, signer_uid: u32, socket_gid: u32,
) -> io::Result<[u8; SOURCE_PROJECT_CONTINUATION_READBACK_BYTES_V3]> {
    request_root_source_successor_readback(
        fresh_nonce, context, signer, signer_uid, socket_gid,
        SourceSuccessorRequestRecipe::MixedProjectsV3,
    )
}

fn request_root_source_successor_readback(
    fresh_nonce: [u8; 16], context: &RootFirstSourceSuccessorIntentV2,
    signer: &PinnedSourceHoldReadbackSignerV1, signer_uid: u32, socket_gid: u32,
    recipe: SourceSuccessorRequestRecipe,
) -> io::Result<[u8; SOURCE_FIRST_SUCCESSOR_READBACK_BYTES_V2]> {
    if signer_uid == 0 || socket_gid == 0 || fresh_nonce == [0; 16] {
        return Err(invalid_data("invalid first-successor signer identity"));
    }
    if context.as_bytes().len() != 1248 {
        return Err(invalid_data("legacy successor request requires legacy context"));
    }
    let request = match recipe {
        SourceSuccessorRequestRecipe::SingleProjectV2 => encode_first_successor_request(fresh_nonce, context),
        SourceSuccessorRequestRecipe::MixedProjectsV3 => encode_source_successor_request(fresh_nonce, context, recipe),
        _ => return Err(invalid_data("resource successor requires full request recipe")),
    };
    let mut stream = connect_source_signer(signer_uid, socket_gid)?;
    stream.write_all(&request)?;
    stream.shutdown(std::net::Shutdown::Write)?;
    let packet = read_framed_reply::<REPLY_FIRST_SUCCESSOR_BYTES, SOURCE_FIRST_SUCCESSOR_READBACK_BYTES_V2>(
        &mut stream, recipe.reply_magic(),
    )?;
    match recipe {
        SourceSuccessorRequestRecipe::SingleProjectV2 => {
            verify_source_first_successor_readback_v2(&packet, signer, fresh_nonce, context).map_err(io::Error::other)?;
        }
        SourceSuccessorRequestRecipe::MixedProjectsV3 => {
            verify_source_project_continuation_readback_v3(&packet, signer, fresh_nonce, context).map_err(io::Error::other)?;
        }
        _ => return Err(invalid_data("resource successor requires full reply recipe")),
    }
    Ok(packet)
}

/// Requests a full-resource successor observation on the existing signer role.
///
/// The `mixed` selector is closed comparison framing, not a currentness or
/// resource-bank proof. Complete authentication stays inside this original
/// signer stream, before its packet Result returns to the held Root caller.
///
/// # Errors
/// Rejects legacy context, foreign signer/socket custody, unknown historical
/// genesis width, trailing bytes or an invalid complete purpose signature.
pub fn request_root_source_resource_successor_readback_v4(
    fresh_nonce: [u8; 16], context: &RootFirstSourceSuccessorIntentV2,
    signer: &PinnedSourceHoldReadbackSignerV1, signer_uid: u32, socket_gid: u32,
    mixed: bool,
) -> io::Result<Vec<u8>> {
    if signer_uid == 0 || socket_gid == 0 || fresh_nonce == [0; 16]
        || context.as_bytes().len() != 1424
    {
        return Err(invalid_data("invalid resource successor signer context"));
    }
    let request = encode_resource_successor_request(fresh_nonce, context, mixed)?;
    let mut stream = connect_source_signer(signer_uid, socket_gid)?;
    stream.write_all(&request)?;
    stream.shutdown(std::net::Shutdown::Write)?;
    let reply_magic = if mixed { REPLY_RESOURCE_CONTINUATION_MAGIC_V5 } else { REPLY_RESOURCE_SUCCESSOR_MAGIC_V4 };
    let packet = read_resource_successor_reply(&mut stream, reply_magic)?;
    if mixed {
        aos_sandbox::policy_compiler::verify_source_resource_project_continuation_readback_v5(
            &packet, signer, fresh_nonce, context,
        ).map_err(io::Error::other)?;
    } else {
        aos_sandbox::policy_compiler::verify_source_resource_first_successor_readback_v4(
            &packet, signer, fresh_nonce, context,
        ).map_err(io::Error::other)?;
    }
    Ok(packet)
}

fn read_resource_successor_reply(stream: &mut UnixStream, magic: &[u8; 8]) -> io::Result<Vec<u8>> {
    // Read the smallest closed packet first. The nested historical receipt
    // header supplies sizing DATA only; the complete signature remains required.
    let mut reply = vec![0; 8 + aos_sandbox::policy_compiler::SOURCE_RESOURCE_SUCCESSOR_LEGACY_GENESIS_BYTES_V4];
    stream.read_exact(&mut reply)?;
    if reply[..8] != *magic {
        return Err(invalid_data("invalid resource successor reply purpose"));
    }
    let genesis = 8 + 64 + 1072;
    match (&reply[genesis..genesis + 8], &reply[genesis + 8..genesis + 10]) {
        (b"AOSSGR01", [0, 1]) => {}
        (b"AOSSGR02", [0, 2]) => {
            let old_length = reply.len();
            reply.resize(8 + aos_sandbox::policy_compiler::SOURCE_RESOURCE_SUCCESSOR_READBACK_BYTES_V4, 0);
            stream.read_exact(&mut reply[old_length..])?;
        }
        _ => return Err(invalid_data("unknown successor genesis receipt recipe")),
    }
    let mut trailing = [0];
    if stream.read(&mut trailing)? != 0 {
        return Err(invalid_data("trailing resource successor reply"));
    }
    reply.drain(..8);
    Ok(reply)
}

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

/// Requests a complete resource strict observation through the existing signer.
///
/// Legacy context delegates to request08 unchanged. Resource context uses the
/// distinct request13 purpose on the same original endpoint and pinned key.
///
/// # Errors
/// Rejects mixed context/project/intent, foreign socket or peer custody, exact
/// framing/EOF, changed original joins or a bad Source-purpose signature.
pub fn request_root_source_tree_genesis_readback_v3(
    challenge: SourceTreeGenesisChallengeV1,
    project: Option<ProjectId>,
    intent_context: Option<&SourceTreeGenesisIntentContextV1>,
    signer: &PinnedSourceHoldReadbackSignerV1,
    signer_uid: u32,
    socket_gid: u32,
) -> io::Result<SourceTreeGenesisReadbackPacketV2> {
    if !intent_context.is_some_and(SourceTreeGenesisIntentContextV1::has_resource_authorization) {
        return request_root_source_tree_genesis_readback_v2(
            challenge, project, intent_context, signer, signer_uid, socket_gid,
        ).map(SourceTreeGenesisReadbackPacketV2::Legacy);
    }
    if signer_uid == 0 || socket_gid == 0 {
        return Err(invalid_data("invalid Source genesis signer identity"));
    }
    let request = encode_strict_genesis_request::<REQUEST_PROJECT_RESOURCE_GENESIS_BYTES_V4>(
        challenge, project, intent_context,
    )?;
    let packet = exchange_source_genesis_request::<REPLY_PROJECT_RESOURCE_GENESIS_BYTES_V4, SOURCE_TREE_GENESIS_READBACK_BYTES_V2>(
        &request, REPLY_RESOURCE_GENESIS_MAGIC, signer_uid, socket_gid, |packet| {
            let verified = verify_source_tree_genesis_readback_v2(packet, signer, challenge)
                .map_err(io::Error::other)?;
            if verified.receipt().map(|receipt| receipt.project()) != project {
                return Err(invalid_data("changed Source genesis project"));
            }
            Ok(())
        },
    )?;
    Ok(SourceTreeGenesisReadbackPacketV2::Resource(packet))
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

