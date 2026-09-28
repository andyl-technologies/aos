//! Actual normal-Root writer and Source-signer joins on one original stream.
//!
//! The Controller already retains its real Controller and Source writers.
//! This producer opens Root last, verifies actual role-pinned observations,
//! and retains Root through floor, Controller/Source ACKs and a final stream
//! acknowledgement. It never reads Controller's private DAC-owned journal.
//! Replies are data: the shared Controller coordinator must independently join
//! its selected immutable profile and original per-fragment Root peer before
//! constructing a non-detachable proof. Installed qualification stays separate.

use std::io::{self, Read as _, Write as _};
use std::net::Shutdown;
use std::os::unix::net::UnixStream;
use std::time::{Duration, Instant};

use aos_sandbox::hierarchy::genesis_profile::SourceGenesisErrorV1;
use aos_sandbox::policy_compiler::{
    ROOT_SOURCE_GENESIS_FRAME_HEADER_BYTES_V1, ROOT_SOURCE_GENESIS_HELLO_MAGIC_V1,
    RootSourceGenesisAuthorityV1, RootSourceGenesisFrameKindV1,
    SOURCE_TREE_GENESIS_READBACK_BYTES_V1, SourceHierarchyFloorRecordV1,
    decode_root_source_genesis_frame_v1, encode_root_source_genesis_frame_v1,
};

use crate::source_signer_exchange::request_root_source_tree_genesis_readback_v2;

// The client's original 60-second deadline starts before connection. Root's
// phase deadline begins later and is 65 seconds; it never expires before the
// client's maximum custody interval. Every stream fragment uses its remaining
// bound. Blocking owner/signature RPC work may delay release, but cannot admit
// a late phase or extend the client's original custody deadline.
const ROOT_HOLD_LIMIT: Duration = Duration::from_secs(65);

/// Serves genuine genesis preparation, anchoring and ACK readback under Root.
///
/// This must be called only by the existing normal Root daemon after its fixed
/// Controller peer check. Source's physical owner UID is explicitly the same
/// privileged configuration used by its Controller-owned journal/view; the
/// separate Source signer UID identifies only the readback endpoint process.
/// The original accepted stream is shut down before Root's writer is released
/// on success, error or unwind. It is never forked, handed off or duplicated.
///
/// # Errors
/// Rejects malformed phases, a different original nonce or input, changed
/// actual owner cuts/pins, unavailable current admission for new mutation,
/// insufficient reserved suffixes, unanchored final ACKs or transport loss.
pub fn serve_root_source_genesis_flight_v1(
    stream: &mut UnixStream,
    startup: Option<&crate::production_normal_root::ProductionNormalRootStartupV1>,
    client_nonce: [u8; 16],
    controller_uid: u32,
    controller_gid: u32,
    source_uid: u32,
    source_signer_uid: u32,
) -> Result<(), SourceGenesisErrorV1> {
    serve(
        stream,
        startup,
        client_nonce,
        controller_uid,
        controller_gid,
        source_uid,
        source_signer_uid,
        AdmissionScope::Current,
    )
}

/// Serves only exact materialized genesis recovery when current inputs are absent.
///
/// # Errors
/// Rejects every current Empty or vacant admission packet, missing original
/// receipt/intent/floor custody, and the same unsafe owner/transport conditions
/// as the normal flight. This entry cannot admit a new expired genesis.
pub fn serve_root_source_genesis_recovery_v1(
    stream: &mut UnixStream,
    startup: Option<&crate::production_normal_root::ProductionNormalRootStartupV1>,
    client_nonce: [u8; 16],
    controller_uid: u32,
    controller_gid: u32,
    source_uid: u32,
    source_signer_uid: u32,
) -> Result<(), SourceGenesisErrorV1> {
    serve(
        stream,
        startup,
        client_nonce,
        controller_uid,
        controller_gid,
        source_uid,
        source_signer_uid,
        AdmissionScope::HistoricalOnly,
    )
}

enum AdmissionScope {
    Current,
    HistoricalOnly,
}

fn serve(
    stream: &mut UnixStream,
    startup: Option<&crate::production_normal_root::ProductionNormalRootStartupV1>,
    client_nonce: [u8; 16],
    controller_uid: u32,
    controller_gid: u32,
    source_uid: u32,
    source_signer_uid: u32,
    scope: AdmissionScope,
) -> Result<(), SourceGenesisErrorV1> {
    let stream = ClosingOriginalStream(stream);
    if client_nonce == [0; 16]
        || controller_uid == 0
        || controller_gid == 0
        || source_uid == 0
        || source_signer_uid == 0
    {
        return Err(SourceGenesisErrorV1::NonCanonical);
    }
    let peer = rustix::net::sockopt::socket_peercred(&*stream.0).map_err(std::io::Error::from)?;
    if peer.uid.as_raw() != controller_uid || peer.gid.as_raw() != controller_gid {
        return Err(SourceGenesisErrorV1::Stale);
    }
    let owner = RootSourceGenesisAuthorityV1::open_fixed(controller_uid, source_uid)?;
    let mut flight = RootHeldStreamFlight {
        stream,
        startup,
        owner,
        deadline: Instant::now() + ROOT_HOLD_LIMIT,
        source_signer_uid,
        controller_gid,
        scope,
    };
    let nonce = flight.owner.nonce();
    let mut hello = [0; 56];
    hello[..8].copy_from_slice(ROOT_SOURCE_GENESIS_HELLO_MAGIC_V1);
    hello[8..10].copy_from_slice(&1_u16.to_be_bytes());
    hello[16..32].copy_from_slice(&client_nonce);
    hello[32..48].copy_from_slice(&nonce);
    hello[48..52].copy_from_slice(&source_uid.to_be_bytes());
    hello[52..56].copy_from_slice(&controller_uid.to_be_bytes());
    flight.write(&hello)?;

    let prepared = flight.read(RootSourceGenesisFrameKindV1::Prepare)?;
    let source = flight.source_observation(&prepared)?;
    let floor = if let Some(floor) = flight
        .owner
        .recover_floor(source.as_ref().map(|packet| packet.as_slice()))?
    {
        floor
    } else {
        flight.recheck()?;
        let intent = flight
            .owner
            .prepare(source.as_ref().map(|packet| packet.as_slice()))?;
        let expires = flight.owner.current_admission_expiry()?;
        let mut payload = Vec::with_capacity(8 + intent.record_bytes().len());
        payload.extend_from_slice(&expires.to_be_bytes());
        payload.extend_from_slice(intent.record_bytes());
        flight.send(RootSourceGenesisFrameKindV1::Prepared, &payload)?;

        let appended = flight.read(RootSourceGenesisFrameKindV1::Anchor)?;
        let source = flight
            .source_observation(&appended)?
            .ok_or(SourceGenesisErrorV1::Conflict)?;
        flight.recheck()?;
        flight.owner.anchor(&source)?
    };
    flight.send(RootSourceGenesisFrameKindV1::Anchored, floor.record_bytes())?;

    let completed = flight.read(RootSourceGenesisFrameKindV1::Complete)?;
    let source = flight
        .source_observation(&completed)?
        .ok_or(SourceGenesisErrorV1::Conflict)?;
    flight.recheck()?;
    // Borrow the actual settled Root row through the original final exchange.
    // This stays local; the client independently verifies original-stream
    // custody. Neither this record nor its signature grants a later read.
    let current = flight.owner.current_anchored_floor(&source)?;
    if current.floor() != &floor {
        return Err(SourceGenesisErrorV1::Conflict);
    }
    current.recheck()?;
    flight.send(
        RootSourceGenesisFrameKindV1::Completed,
        current.floor().digest().as_bytes(),
    )?;
    let final_ack = flight.read(RootSourceGenesisFrameKindV1::Finish)?;
    require_final_ack(&final_ack, current.floor())?;
    current.recheck()?;
    flight.recheck()
}

// Field drop order is deliberate: closing the original receive queue must
// precede releasing Root's actual writer on every return/unwind path.
struct RootHeldStreamFlight<'stream, 'startup> {
    stream: ClosingOriginalStream<'stream>,
    startup: Option<&'startup crate::production_normal_root::ProductionNormalRootStartupV1>,
    owner: RootSourceGenesisAuthorityV1,
    deadline: Instant,
    source_signer_uid: u32,
    controller_gid: u32,
    scope: AdmissionScope,
}

struct ClosingOriginalStream<'stream>(&'stream mut UnixStream);

impl Drop for ClosingOriginalStream<'_> {
    fn drop(&mut self) {
        let _ = self.0.shutdown(Shutdown::Both);
    }
}

impl RootHeldStreamFlight<'_, '_> {
    fn recheck(&self) -> Result<(), SourceGenesisErrorV1> {
        crate::production_normal_root::recheck_optional(self.startup)
            .map_err(|_| SourceGenesisErrorV1::Stale)?;
        if Instant::now() >= self.deadline {
            return Err(SourceGenesisErrorV1::Stale);
        }
        self.owner.recheck()
    }

    fn set_remaining_timeout(&self) -> Result<(), SourceGenesisErrorV1> {
        self.recheck()?;
        let remaining = self
            .deadline
            .checked_duration_since(Instant::now())
            .filter(|duration| !duration.is_zero())
            .ok_or(SourceGenesisErrorV1::Stale)?;
        self.stream.0.set_read_timeout(Some(remaining))?;
        self.stream.0.set_write_timeout(Some(remaining))?;
        Ok(())
    }

    fn read(&self, kind: RootSourceGenesisFrameKindV1) -> Result<Vec<u8>, SourceGenesisErrorV1> {
        let mut frame = vec![0; ROOT_SOURCE_GENESIS_FRAME_HEADER_BYTES_V1 + kind.payload_bytes()];
        let mut received = 0;
        let mut stream = &*self.stream.0;
        while received < frame.len() {
            self.set_remaining_timeout()?;
            match stream.read(&mut frame[received..]) {
                Ok(0) => {
                    return Err(io::Error::new(
                        io::ErrorKind::UnexpectedEof,
                        "original Root genesis request ended before its exact frame",
                    )
                    .into());
                }
                Ok(count) => received += count,
                Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
                Err(error) => return Err(error.into()),
            }
        }
        self.recheck()?;
        decode_root_source_genesis_frame_v1(&frame, kind, self.owner.nonce()).map(Vec::from)
    }

    fn write(&self, bytes: &[u8]) -> Result<(), SourceGenesisErrorV1> {
        let mut written = 0;
        let mut stream = &*self.stream.0;
        while written < bytes.len() {
            self.set_remaining_timeout()?;
            match stream.write(&bytes[written..]) {
                Ok(0) => {
                    return Err(io::Error::new(
                        io::ErrorKind::WriteZero,
                        "original Root genesis reply made no progress",
                    )
                    .into());
                }
                Ok(count) => written += count,
                Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
                Err(error) => return Err(error.into()),
            }
        }
        self.recheck()
    }

    fn send(
        &self,
        kind: RootSourceGenesisFrameKindV1,
        payload: &[u8],
    ) -> Result<(), SourceGenesisErrorV1> {
        let frame = encode_root_source_genesis_frame_v1(kind, self.owner.nonce(), payload)?;
        self.write(&frame)
    }

    fn source_observation(
        &mut self,
        controller_packet: &[u8],
    ) -> Result<Option<[u8; SOURCE_TREE_GENESIS_READBACK_BYTES_V1]>, SourceGenesisErrorV1> {
        self.recheck()?;
        let probe = match self.scope {
            AdmissionScope::Current => self.owner.accept_controller_readback(controller_packet)?,
            AdmissionScope::HistoricalOnly => self
                .owner
                .accept_historical_controller_readback(controller_packet)?,
        };
        let observed = probe
            .map(|(project, challenge)| {
                let context = project
                    .map(|_| self.owner.source_genesis_intent_context_v1())
                    .transpose()?;
                request_root_source_tree_genesis_readback_v2(
                    challenge,
                    project,
                    context.as_ref(),
                    self.owner.source_readback_pin(),
                    self.source_signer_uid,
                    self.controller_gid,
                )
                .map_err(SourceGenesisErrorV1::from)
            })
            .transpose()?;
        self.recheck()?;
        Ok(observed)
    }
}

fn require_final_ack(
    payload: &[u8],
    floor: &SourceHierarchyFloorRecordV1,
) -> Result<(), SourceGenesisErrorV1> {
    if payload != floor.digest().as_bytes() {
        return Err(SourceGenesisErrorV1::Conflict);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepted_endpoint_closes_when_hold_scope_exits() {
        let (mut server, mut client) = UnixStream::pair().unwrap();
        {
            let _held = ClosingOriginalStream(&mut server);
        }
        let mut byte = [0; 1];
        assert_eq!(client.read(&mut byte).unwrap(), 0);
        assert_eq!(
            server.write(&[1]).unwrap_err().kind(),
            io::ErrorKind::BrokenPipe
        );
    }
}
