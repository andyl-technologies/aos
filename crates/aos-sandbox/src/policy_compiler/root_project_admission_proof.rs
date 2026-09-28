//! Opaque Root project-admission outcome from its peer-checked fixed socket.
//!
//! ```text
//! AOSPHQPA | query-nonce:16 | reserved[8]=0 | stage-digest:32 | EOF
//! AOSPHRPA | query-nonce:16 | stage-digest:32 |
//! status:absent|committed|aborted | reserved[7]=0 |
//! AOSQPO01[312] or zero[312] | EOF
//! ```
//!
//! A local decoder cannot mint this proof. Only an exact Root socket reply
//! can retire the matching Source challenge after durable Root replay.

use std::io::{self, Read as _, Write as _};
use std::net::Shutdown;
use std::os::unix::net::UnixStream;
use std::path::Path;
use std::time::Duration;

use crate::journal::{SourceProjectAdmissionChallengeV1, SourceProjectAdmissionReservationV1};
use aos_sandbox_core::ObjectDigest;

use super::controller_readback_session::fresh_root_nonce;
use super::project_admission_root::{
    RootProjectAdmissionIntentV1, RootProjectAdmissionOutcomeKindV1, RootProjectAdmissionOutcomeV1,
    RootProjectAdmissionStageV1, RootProjectReservationCancellationV1,
};
use super::root_v8_released_proof::POLICY_AUTHORITY_FIXED_SOCKET_PATH_V2;

/// Selects the distinct Root outcome query without touching a staged attempt.
pub const ROOT_PROJECT_ADMISSION_OUTCOME_QUERY_MAGIC: &[u8; 8] = b"AOSPHQPA";
/// Selects an exact, effect-owned project admission stage.
pub const ROOT_PROJECT_ADMISSION_STAGE_QUERY_MAGIC: &[u8; 8] = b"AOSPHSP1";
/// Reserves Root cancellation capacity before Source appends its row.
pub const ROOT_PROJECT_ADMISSION_INTENT_QUERY_MAGIC: &[u8; 8] = b"AOSPHI01";
/// Replays an exact active Root intent after an ambiguous prepare reply.
pub const ROOT_PROJECT_ADMISSION_INTENT_REPLAY_MAGIC: &[u8; 8] = b"AOSPHIQ1";
/// Submits the two signed owner proofs under a Root-last CAS.
pub const ROOT_PROJECT_ADMISSION_COMMIT_QUERY_MAGIC: &[u8; 8] = b"AOSPHCM1";
/// Durably aborts a stage only after a Source challenge exists.
pub const ROOT_PROJECT_ADMISSION_ABORT_QUERY_MAGIC: &[u8; 8] = b"AOSPHAB1";
/// Selects an unresolved Root stage for post-crash Source-row completion.
pub const ROOT_PROJECT_ADMISSION_CURRENT_QUERY_MAGIC: &[u8; 8] = b"AOSPHCS1";
/// Durably forbids a late stage after Controller lost its Source reservation.
pub const ROOT_PROJECT_RESERVATION_CANCEL_MAGIC: &[u8; 8] = b"AOSPHCX1";
/// Replays the immutable Root cancellation for Source reservation settlement.
pub const ROOT_PROJECT_RESERVATION_CANCEL_QUERY_MAGIC: &[u8; 8] = b"AOSPHQX1";
const RESERVATION_CANCEL_REPLY_MAGIC: &[u8; 8] = b"AOSPHRX1";
const STAGE_REPLY_MAGIC: &[u8; 8] = b"AOSPHSA1";
const INTENT_REPLY_MAGIC: &[u8; 8] = b"AOSPHIR1";
const INTENT_REPLAY_REPLY_MAGIC: &[u8; 8] = b"AOSPHIR3";
const CURRENT_REPLY_MAGIC: &[u8; 8] = b"AOSPHCR1";
const TERMINAL_REPLY_MAGIC: &[u8; 8] = b"AOSPHOR1";
const REPLY_MAGIC: &[u8; 8] = b"AOSPHRPA";
const QUERY_BYTES: usize = 64;
const REPLY_BYTES: usize = 376;
const OUTCOME_BYTES: usize = 312;
const ROOT_WAIT: Duration = Duration::from_secs(35);
const STAGE_REPLY_BYTES: usize = 8 + 16 + 336;
const INTENT_REPLY_BYTES: usize = 8 + 16 + 304;
const INTENT_REPLAY_REPLY_BYTES: usize = 8 + 16 + 8 + 304;
const CURRENT_REPLY_BYTES: usize = 8 + 16 + 8 + 336;
const TERMINAL_REPLY_BYTES: usize = 8 + 16 + OUTCOME_BYTES;
const CONTROLLER_PACKET_BYTES: usize = 364;
const RESERVATION_CANCEL_REPLY_BYTES: usize = 8 + 16 + 32 + 8 + 112;

/// Proves an exact Root cancellation only after peer-checked fixed-socket replay.
#[derive(Clone, Copy, Debug)]
pub struct RootProjectReservationCancellationProofV1 {
    marker: RootProjectReservationCancellationV1,
}

impl RootProjectReservationCancellationProofV1 {
    /// Returns the Root-owned immutable cancellation marker.
    pub const fn marker(self) -> RootProjectReservationCancellationV1 {
        self.marker
    }

    #[cfg(test)]
    pub(crate) const fn from_test_marker(marker: RootProjectReservationCancellationV1) -> Self {
        Self { marker }
    }
}

/// Requests Root's durable no-stage cancellation of an exact Source row.
///
/// The reply is not Source-retirement authority; callers must separately
/// query the immutable marker through the fixed Root peer.
///
/// # Errors
///
/// Rejects foreign Root custody, changed row, or transport loss.
pub fn cancel_fixed_root_project_reservation_over_socket_v1(
    reservation: SourceProjectAdmissionReservationV1,
) -> io::Result<()> {
    let mut stream = connect_root()?;
    stream.write_all(&request_header(
        ROOT_PROJECT_RESERVATION_CANCEL_MAGIC,
        reservation.client_nonce(),
    )?)?;
    stream.write_all(&reservation.record_bytes())?;
    stream.shutdown(Shutdown::Write)?;
    let reply = read_exact_reply::<RESERVATION_CANCEL_REPLY_BYTES>(&mut stream)?;
    let marker = decode_reservation_cancel_reply(
        &reply,
        reservation.client_nonce(),
        reservation.record_digest(),
    )?
    .ok_or_else(invalid_reply)?;
    if marker.client_nonce() != reservation.client_nonce()
        || marker.project() != reservation.project()
    {
        return Err(invalid_reply());
    }
    Ok(())
}

/// Queries a durable Root cancellation as an opaque Source-retirement proof.
///
/// # Errors
///
/// Rejects foreign Root custody, malformed framing, or mismatched marker.
pub fn query_fixed_root_project_reservation_cancellation_v1(
    reservation: SourceProjectAdmissionReservationV1,
) -> io::Result<Option<RootProjectReservationCancellationProofV1>> {
    let mut stream = connect_root()?;
    stream.write_all(&request_header(
        ROOT_PROJECT_RESERVATION_CANCEL_QUERY_MAGIC,
        reservation.client_nonce(),
    )?)?;
    stream.write_all(reservation.record_digest().as_bytes())?;
    stream.shutdown(Shutdown::Write)?;
    let reply = read_exact_reply::<RESERVATION_CANCEL_REPLY_BYTES>(&mut stream)?;
    let marker = decode_reservation_cancel_reply(
        &reply,
        reservation.client_nonce(),
        reservation.record_digest(),
    )?;
    if marker.is_some_and(|marker| {
        marker.client_nonce() != reservation.client_nonce()
            || marker.project() != reservation.project()
    }) {
        return Err(invalid_reply());
    }
    Ok(marker.map(|marker| RootProjectReservationCancellationProofV1 { marker }))
}

fn decode_reservation_cancel_reply(
    reply: &[u8; RESERVATION_CANCEL_REPLY_BYTES],
    nonce: [u8; 16],
    expected: ObjectDigest,
) -> io::Result<Option<RootProjectReservationCancellationV1>> {
    if reply[..8] != RESERVATION_CANCEL_REPLY_MAGIC[..]
        || reply[8..24] != nonce
        || reply[24..56] != expected.as_bytes()[..]
        || reply[57..64] != [0; 7]
    {
        return Err(invalid_reply());
    }
    match reply[56] {
        0 if reply[64..] == [0; 112] => Ok(None),
        1 => {
            let marker = RootProjectReservationCancellationV1::from_record_bytes(&reply[64..])
                .map_err(io::Error::other)?;
            if marker.reservation() != expected {
                return Err(invalid_reply());
            }
            Ok(Some(marker))
        }
        _ => Err(invalid_reply()),
    }
}

/// Encodes Root's fixed-width cancellation readback without granting proof.
///
/// # Errors
///
/// Rejects zero query identity or changed reservation digest.
pub fn encode_root_project_reservation_cancel_reply_v1(
    nonce: [u8; 16],
    reservation: ObjectDigest,
    marker: Option<RootProjectReservationCancellationV1>,
) -> io::Result<[u8; RESERVATION_CANCEL_REPLY_BYTES]> {
    if nonce == [0; 16]
        || reservation.as_bytes() == &[0; 32]
        || marker.is_some_and(|marker| marker.reservation() != reservation)
    {
        return Err(invalid_reply());
    }
    let mut reply = [0; RESERVATION_CANCEL_REPLY_BYTES];
    reply[..8].copy_from_slice(RESERVATION_CANCEL_REPLY_MAGIC);
    reply[8..24].copy_from_slice(&nonce);
    reply[24..56].copy_from_slice(reservation.as_bytes());
    if let Some(marker) = marker {
        reply[56] = 1;
        reply[64..].copy_from_slice(&marker.record_bytes());
    }
    Ok(reply)
}

fn connect_root() -> io::Result<UnixStream> {
    let stream = UnixStream::connect(POLICY_AUTHORITY_FIXED_SOCKET_PATH_V2)?;
    require_root_peer(&stream)?;
    stream.set_read_timeout(Some(ROOT_WAIT))?;
    stream.set_write_timeout(Some(ROOT_WAIT))?;
    Ok(stream)
}

fn request_header(magic: &[u8; 8], nonce: [u8; 16]) -> io::Result<[u8; 32]> {
    if nonce == [0; 16] {
        return Err(invalid_reply());
    }
    let mut header = [0; 32];
    header[..8].copy_from_slice(magic);
    header[8..24].copy_from_slice(&nonce);
    Ok(header)
}

fn read_exact_reply<const N: usize>(stream: &mut UnixStream) -> io::Result<[u8; N]> {
    let mut reply = [0; N];
    stream.read_exact(&mut reply)?;
    let mut trailing = [0];
    if stream.read(&mut trailing)? != 0 {
        return Err(invalid_reply());
    }
    require_root_peer(stream)?;
    Ok(reply)
}

/// Reserves Root's durable no-stage cancellation branch for one Source row.
///
/// The caller must commit the exact Source row under its retained writer
/// before requesting a stage. This Root proof is not Source currentness.
///
/// # Errors
///
/// Rejects a foreign Root peer, mismatched intent, or transport failure.
pub fn prepare_fixed_root_project_intent_over_socket_v1(
    reservation: SourceProjectAdmissionReservationV1,
) -> io::Result<RootProjectAdmissionIntentV1> {
    let mut stream = connect_root()?;
    stream.write_all(&request_header(
        ROOT_PROJECT_ADMISSION_INTENT_QUERY_MAGIC,
        reservation.client_nonce(),
    )?)?;
    stream.write_all(&reservation.record_bytes())?;
    stream.shutdown(Shutdown::Write)?;
    let reply = read_exact_reply::<INTENT_REPLY_BYTES>(&mut stream)?;
    if reply[..8] != INTENT_REPLY_MAGIC[..] || reply[8..24] != reservation.client_nonce() {
        return Err(invalid_reply());
    }
    let intent =
        RootProjectAdmissionIntentV1::from_record_bytes(&reply[24..]).map_err(io::Error::other)?;
    if intent.client_nonce() != reservation.client_nonce()
        || intent.project() != reservation.project()
        || intent.source_reservation() != reservation.record_digest()
    {
        return Err(invalid_reply());
    }
    Ok(intent)
}

/// Encodes Root's exact durable capacity intent for a fixed-socket reply.
///
/// # Errors
///
/// Rejects a nonce not bound to the intended Source row.
pub fn encode_root_project_intent_reply_v1(
    nonce: [u8; 16],
    intent: RootProjectAdmissionIntentV1,
) -> io::Result<[u8; INTENT_REPLY_BYTES]> {
    if nonce == [0; 16] || intent.client_nonce() != nonce {
        return Err(invalid_reply());
    }
    let mut reply = [0; INTENT_REPLY_BYTES];
    reply[..8].copy_from_slice(INTENT_REPLY_MAGIC);
    reply[8..24].copy_from_slice(&nonce);
    reply[24..].copy_from_slice(&intent.record_bytes());
    Ok(reply)
}

/// Replays only the matching active Root intent without staging or canceling.
///
/// # Errors
///
/// Rejects a foreign Root peer, malformed row or response, or transport loss.
pub fn query_fixed_root_project_intent_v1(
    reservation: SourceProjectAdmissionReservationV1,
) -> io::Result<Option<RootProjectAdmissionIntentV1>> {
    let mut stream = connect_root()?;
    stream.write_all(&request_header(
        ROOT_PROJECT_ADMISSION_INTENT_REPLAY_MAGIC,
        reservation.client_nonce(),
    )?)?;
    stream.write_all(&reservation.record_bytes())?;
    stream.shutdown(Shutdown::Write)?;
    let reply = read_exact_reply::<INTENT_REPLAY_REPLY_BYTES>(&mut stream)?;
    decode_root_project_intent_replay_reply_v1(&reply, reservation)
}

pub(super) fn decode_root_project_intent_replay_reply_v1(
    reply: &[u8; INTENT_REPLAY_REPLY_BYTES],
    reservation: SourceProjectAdmissionReservationV1,
) -> io::Result<Option<RootProjectAdmissionIntentV1>> {
    if reply[..8] != INTENT_REPLAY_REPLY_MAGIC[..]
        || reply[8..24] != reservation.client_nonce()
        || reply[25..32] != [0; 7]
    {
        return Err(invalid_reply());
    }
    match reply[24] {
        0 if reply[32..] == [0; 304] => Ok(None),
        1 => {
            let intent = RootProjectAdmissionIntentV1::from_record_bytes(&reply[32..])
                .map_err(io::Error::other)?;
            if intent.client_nonce() != reservation.client_nonce()
                || intent.project() != reservation.project()
                || intent.source_reservation() != reservation.record_digest()
            {
                return Err(invalid_reply());
            }
            Ok(Some(intent))
        }
        _ => Err(invalid_reply()),
    }
}

/// Encodes Root's read-only exact active-intent response.
///
/// # Errors
///
/// Rejects a nonce or intent not bound to the requested Source row.
pub fn encode_root_project_intent_replay_reply_v1(
    reservation: SourceProjectAdmissionReservationV1,
    intent: Option<RootProjectAdmissionIntentV1>,
) -> io::Result<[u8; INTENT_REPLAY_REPLY_BYTES]> {
    if reservation.client_nonce() == [0; 16]
        || intent.is_some_and(|intent| {
            intent.client_nonce() != reservation.client_nonce()
                || intent.project() != reservation.project()
                || intent.source_reservation() != reservation.record_digest()
        })
    {
        return Err(invalid_reply());
    }
    let mut reply = [0; INTENT_REPLAY_REPLY_BYTES];
    reply[..8].copy_from_slice(INTENT_REPLAY_REPLY_MAGIC);
    reply[8..24].copy_from_slice(&reservation.client_nonce());
    if let Some(intent) = intent {
        reply[24] = 1;
        reply[32..].copy_from_slice(&intent.record_bytes());
    }
    Ok(reply)
}

/// Requests a Root stage bound to the retained Source reservation.
///
/// # Errors
///
/// Rejects a foreign Root peer, malformed/stale stage, or transport failure.
pub fn stage_fixed_root_project_admission_over_socket_v1(
    reservation: SourceProjectAdmissionReservationV1,
) -> io::Result<RootProjectAdmissionStageV1> {
    let client_nonce = reservation.client_nonce();
    let mut stream = connect_root()?;
    stream.write_all(&request_header(
        ROOT_PROJECT_ADMISSION_STAGE_QUERY_MAGIC,
        client_nonce,
    )?)?;
    stream.write_all(&reservation.record_bytes())?;
    stream.shutdown(Shutdown::Write)?;
    let reply = read_exact_reply::<STAGE_REPLY_BYTES>(&mut stream)?;
    if reply[..8] != STAGE_REPLY_MAGIC[..] || reply[8..24] != client_nonce {
        return Err(invalid_reply());
    }
    let stage =
        RootProjectAdmissionStageV1::from_record_bytes(&reply[24..]).map_err(io::Error::other)?;
    if stage.client_nonce() != client_nonce
        || stage.project() != reservation.project()
        || stage.source_reservation_digest() != reservation.record_digest()
    {
        return Err(invalid_reply());
    }
    Ok(stage)
}

/// Queries the one unresolved Root stage without changing it.
///
/// This is used after a crash between durable Root staging and Source-row
/// creation. Controller must hold its protected writer, then create and abort
/// the matching Source row before another stage can be attempted.
///
/// # Errors
///
/// Rejects a foreign Root peer, malformed response, or transport failure.
pub fn query_fixed_root_current_project_admission_stage_v1()
-> io::Result<Option<RootProjectAdmissionStageV1>> {
    let nonce = fresh_root_nonce()?;
    let mut stream = connect_root()?;
    stream.write_all(&request_header(
        ROOT_PROJECT_ADMISSION_CURRENT_QUERY_MAGIC,
        nonce,
    )?)?;
    stream.shutdown(Shutdown::Write)?;
    let reply = read_exact_reply::<CURRENT_REPLY_BYTES>(&mut stream)?;
    if reply[..8] != CURRENT_REPLY_MAGIC[..] || reply[8..24] != nonce || reply[25..32] != [0; 7] {
        return Err(invalid_reply());
    }
    match reply[24] {
        0 if reply[32..].iter().all(|byte| *byte == 0) => Ok(None),
        1 => RootProjectAdmissionStageV1::from_record_bytes(&reply[32..])
            .map(Some)
            .map_err(io::Error::other),
        _ => Err(invalid_reply()),
    }
}

/// Encodes a Root-journal current-stage readback for its fixed socket.
///
/// # Errors
///
/// Rejects an empty transport nonce.
pub fn encode_root_current_project_admission_stage_reply_v1(
    nonce: [u8; 16],
    stage: Option<RootProjectAdmissionStageV1>,
) -> io::Result<[u8; CURRENT_REPLY_BYTES]> {
    if nonce == [0; 16] {
        return Err(invalid_reply());
    }
    let mut reply = [0; CURRENT_REPLY_BYTES];
    reply[..8].copy_from_slice(CURRENT_REPLY_MAGIC);
    reply[8..24].copy_from_slice(&nonce);
    if let Some(stage) = stage {
        reply[24] = 1;
        reply[32..].copy_from_slice(&stage.record_bytes());
    }
    Ok(reply)
}

/// Encodes the Root stage's exact durable row for a peer-checked response.
///
/// # Errors
///
/// Rejects a nonce from a different stage.
pub fn encode_root_project_admission_stage_reply_v1(
    client_nonce: [u8; 16],
    stage: RootProjectAdmissionStageV1,
) -> io::Result<[u8; STAGE_REPLY_BYTES]> {
    if client_nonce == [0; 16] || stage.client_nonce() != client_nonce {
        return Err(invalid_reply());
    }
    let mut reply = [0; STAGE_REPLY_BYTES];
    reply[..8].copy_from_slice(STAGE_REPLY_MAGIC);
    reply[8..24].copy_from_slice(&client_nonce);
    reply[24..].copy_from_slice(&stage.record_bytes());
    Ok(reply)
}

/// Submits actual signed Controller and durable Source rows to Root last.
///
/// The reply only describes the attempted RPC. Callers must query the fixed
/// Root outcome socket after either success or ambiguity before Source release.
///
/// # Errors
///
/// Rejects a foreign peer, changed terminal row, or transport failure.
pub fn submit_fixed_root_project_admission_over_socket_v1(
    stage: RootProjectAdmissionStageV1,
    controller_packet: &[u8; CONTROLLER_PACKET_BYTES],
    source_row: SourceProjectAdmissionChallengeV1,
) -> io::Result<()> {
    if source_row.project() != stage.project()
        || source_row.nonce() != stage.root_nonce()
        || source_row.cut() != stage.cut()
        || source_row.stage() != stage.record_digest()
    {
        return Err(invalid_reply());
    }
    let nonce = fresh_root_nonce()?;
    let mut stream = connect_root()?;
    stream.write_all(&request_header(
        ROOT_PROJECT_ADMISSION_COMMIT_QUERY_MAGIC,
        nonce,
    )?)?;
    stream.write_all(stage.record_digest().as_bytes())?;
    stream.write_all(controller_packet)?;
    stream.write_all(&source_row.record_bytes())?;
    stream.shutdown(Shutdown::Write)?;
    read_terminal_reply(&mut stream, nonce, stage, source_row)
}

/// Aborts only after the matching durable Source row has been acquired.
///
/// A caller must still query Root's terminal outcome through the fixed socket
/// and settle Source with the resulting opaque proof, including after loss of
/// this reply.
///
/// # Errors
///
/// Rejects a foreign peer, mismatched Source row, or transport failure.
pub fn abort_fixed_root_project_admission_over_socket_v1(
    stage_digest: ObjectDigest,
    source_row: SourceProjectAdmissionChallengeV1,
) -> io::Result<()> {
    if source_row.stage() != stage_digest {
        return Err(invalid_reply());
    }
    let nonce = fresh_root_nonce()?;
    let mut stream = connect_root()?;
    stream.write_all(&request_header(
        ROOT_PROJECT_ADMISSION_ABORT_QUERY_MAGIC,
        nonce,
    )?)?;
    stream.write_all(stage_digest.as_bytes())?;
    stream.write_all(&source_row.record_bytes())?;
    stream.shutdown(Shutdown::Write)?;
    read_terminal_reply_for_stage(&mut stream, nonce, stage_digest, source_row)
}

fn read_terminal_reply(
    stream: &mut UnixStream,
    nonce: [u8; 16],
    stage: RootProjectAdmissionStageV1,
    source_row: SourceProjectAdmissionChallengeV1,
) -> io::Result<()> {
    read_terminal_reply_for_stage(stream, nonce, stage.record_digest(), source_row)
}

fn read_terminal_reply_for_stage(
    stream: &mut UnixStream,
    nonce: [u8; 16],
    stage_digest: ObjectDigest,
    source_row: SourceProjectAdmissionChallengeV1,
) -> io::Result<()> {
    let reply = read_exact_reply::<TERMINAL_REPLY_BYTES>(stream)?;
    if reply[..8] != TERMINAL_REPLY_MAGIC[..] || reply[8..24] != nonce {
        return Err(invalid_reply());
    }
    let outcome =
        RootProjectAdmissionOutcomeV1::from_record_bytes(&reply[24..]).map_err(io::Error::other)?;
    if outcome.stage() != stage_digest || outcome.source_row() != source_row.record_digest() {
        return Err(invalid_reply());
    }
    Ok(())
}

/// Encodes a terminal Root decision without granting Source retirement.
///
/// # Errors
///
/// Rejects an empty transport nonce.
pub fn encode_root_project_admission_terminal_reply_v1(
    nonce: [u8; 16],
    outcome: RootProjectAdmissionOutcomeV1,
) -> io::Result<[u8; TERMINAL_REPLY_BYTES]> {
    if nonce == [0; 16] {
        return Err(invalid_reply());
    }
    let mut reply = [0; TERMINAL_REPLY_BYTES];
    reply[..8].copy_from_slice(TERMINAL_REPLY_MAGIC);
    reply[8..24].copy_from_slice(&nonce);
    reply[24..].copy_from_slice(&outcome.record_bytes());
    Ok(reply)
}

/// Retains a Root-verified project admission or abort for Source retirement.
///
/// Its private constructor requires the exact fixed Root socket peer. The
/// proof does not grant Q04, Create, or policy publication by itself.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RootProjectAdmissionOutcomeProofV1 {
    outcome: RootProjectAdmissionOutcomeV1,
}

impl RootProjectAdmissionOutcomeProofV1 {
    /// Returns the exact durable Root outcome.
    #[must_use]
    pub const fn outcome(self) -> RootProjectAdmissionOutcomeV1 {
        self.outcome
    }

    #[cfg(test)]
    pub(crate) const fn from_test_outcome(outcome: RootProjectAdmissionOutcomeV1) -> Self {
        Self { outcome }
    }
}

/// Queries an immutable Root outcome through the fixed policy-authority socket.
///
/// Absence grants nothing. Caller must compare the proof's Source-row digest
/// to its retained protected Source writer before retiring the challenge.
///
/// # Errors
///
/// Rejects a foreign or substituted Root peer/socket, changed challenge,
/// malformed or trailing reply, timeout, or noncanonical terminal row.
pub fn query_fixed_root_project_admission_outcome_v1(
    stage_digest: ObjectDigest,
) -> io::Result<Option<RootProjectAdmissionOutcomeProofV1>> {
    if stage_digest.as_bytes() == &[0; 32] {
        return Err(invalid_reply());
    }
    let nonce = fresh_root_nonce()?;
    let mut stream = connect_root()?;
    let mut query = [0; QUERY_BYTES];
    query[..8].copy_from_slice(ROOT_PROJECT_ADMISSION_OUTCOME_QUERY_MAGIC);
    query[8..24].copy_from_slice(&nonce);
    query[32..64].copy_from_slice(stage_digest.as_bytes());
    stream.write_all(&query)?;
    stream.shutdown(Shutdown::Write)?;

    let reply = read_exact_reply::<REPLY_BYTES>(&mut stream)?;
    decode_reply(&reply, nonce, stage_digest)
}

/// Encodes Root's exact durable outcome for one challenged query.
///
/// The server must load `outcome` from its protected Root journal, not from a
/// Controller request. This encoder alone cannot mint a peer-checked proof.
///
/// # Errors
///
/// Rejects invalid query fields or an outcome from another stage.
pub fn encode_root_project_admission_outcome_reply_v1(
    nonce: [u8; 16],
    stage_digest: ObjectDigest,
    outcome: Option<RootProjectAdmissionOutcomeV1>,
) -> io::Result<[u8; REPLY_BYTES]> {
    if nonce == [0; 16]
        || stage_digest.as_bytes() == &[0; 32]
        || outcome.is_some_and(|row| row.stage() != stage_digest)
    {
        return Err(invalid_reply());
    }
    let mut reply = [0; REPLY_BYTES];
    reply[..8].copy_from_slice(REPLY_MAGIC);
    reply[8..24].copy_from_slice(&nonce);
    reply[24..56].copy_from_slice(stage_digest.as_bytes());
    if let Some(outcome) = outcome {
        reply[56] = match outcome.kind() {
            RootProjectAdmissionOutcomeKindV1::Committed => 1,
            RootProjectAdmissionOutcomeKindV1::Aborted => 2,
        };
        reply[64..].copy_from_slice(&outcome.record_bytes());
    }
    Ok(reply)
}

fn decode_reply(
    reply: &[u8; REPLY_BYTES],
    nonce: [u8; 16],
    stage_digest: ObjectDigest,
) -> io::Result<Option<RootProjectAdmissionOutcomeProofV1>> {
    if reply[..8] != REPLY_MAGIC[..]
        || reply[8..24] != nonce
        || reply[24..56] != *stage_digest.as_bytes()
        || reply[57..64] != [0; 7]
    {
        return Err(invalid_reply());
    }
    match reply[56] {
        0 if reply[64..].iter().all(|byte| *byte == 0) => Ok(None),
        1 | 2 => {
            let outcome = RootProjectAdmissionOutcomeV1::from_record_bytes(&reply[64..])
                .map_err(io::Error::other)?;
            let status = match outcome.kind() {
                RootProjectAdmissionOutcomeKindV1::Committed => 1,
                RootProjectAdmissionOutcomeKindV1::Aborted => 2,
            };
            if outcome.stage() != stage_digest || reply[56] != status {
                return Err(invalid_reply());
            }
            Ok(Some(RootProjectAdmissionOutcomeProofV1 { outcome }))
        }
        _ => Err(invalid_reply()),
    }
}

fn require_root_peer(stream: &UnixStream) -> io::Result<()> {
    let peer = rustix::net::sockopt::socket_peercred(stream)?;
    if !peer.uid.is_root()
        || stream.peer_addr()?.as_pathname()
            != Some(Path::new(POLICY_AUTHORITY_FIXED_SOCKET_PATH_V2))
    {
        return Err(invalid_reply());
    }
    Ok(())
}

fn invalid_reply() -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidData,
        "invalid Root project-admission outcome",
    )
}

#[cfg(test)]
mod tests {
    use aos_sandbox_core::ProjectId;

    use super::*;

    #[test]
    fn reservation_cancellation_reply_requires_exact_nonce_and_marker() {
        let marker = RootProjectReservationCancellationV1::from_test_claims(
            ObjectDigest::from_bytes([1; 32]),
            [2; 16],
            ProjectId::from_bytes([3; 16]),
        );
        let mut reply = encode_root_project_reservation_cancel_reply_v1(
            [2; 16],
            marker.reservation(),
            Some(marker),
        )
        .unwrap();
        assert_eq!(
            decode_reservation_cancel_reply(&reply, [2; 16], marker.reservation()).unwrap(),
            Some(marker),
        );
        assert!(decode_reservation_cancel_reply(&reply, [4; 16], marker.reservation()).is_err());
        reply[24] ^= 1;
        assert!(decode_reservation_cancel_reply(&reply, [2; 16], marker.reservation()).is_err());
    }
}
