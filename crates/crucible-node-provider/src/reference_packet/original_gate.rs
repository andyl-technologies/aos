//! Reopens the original finite packet gate from actual received proof frames.
//!
//! Kernel-measured transport origin and complete native bodies remain distinct
//! from behavioral acceptance. This inspector grants no Admit, Ready, grant,
//! output ACK or class permission. An installed host policy must also join the
//! privately issued runner witness and independently measured source selection.

use crucible_node_contract::{ContentRef, Id, canonical};

use super::{
    PacketProgramDefinition,
    control::{PacketControlSelection, PacketNativeRecord},
};
use crate::{
    ProviderError,
    bodies::{MethodResult, RequestBody, decode_request, decode_response},
    conformance::{
        CheckKind, ConformanceReport, EndpointMeasurement, OriginalProbeResponseState,
        OriginalProbeResponses,
    },
    envelope::{Envelope, MessageKind, Method, RequestOrigin},
};

const BODY_BYTES: usize = 65_536;
const MAXIMUM_FRAMES: usize = 64;
const MAXIMUM_CHUNKS: usize = 16;

/// Owns the complete original gate body reopened from actual Unix receive rows.
///
/// This nonserialized observation supplies byte custody and correlation only.
/// It is not a qualification token or a reusable native gate permission.
pub struct OriginalPacketGate {
    peer: EndpointMeasurement,
    reference: ContentRef,
    bytes: Vec<u8>,
    native: PacketNativeRecord,
}

impl OriginalPacketGate {
    /// Borrows the actual original SO_PEERCRED and executable measurement.
    pub fn peer(&self) -> &EndpointMeasurement {
        &self.peer
    }

    /// Borrows the full native body identity reported by original Realize.
    pub fn reference(&self) -> &ContentRef {
        &self.reference
    }

    /// Borrows every original native body byte without copying its inventory.
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// Borrows the original gate, request and complete native pending inventory.
    pub fn native(&self) -> &PacketNativeRecord {
        &self.native
    }
}

/// Inspects complete initial gate custody under the exact finite source2 tuple.
///
/// The report is portable data. A production installed authority must obtain it
/// through the owning runner's private original-witness hook before trusting
/// its origin. This function additionally requires the opaque actual-response
/// journal, all received frame bodies and the independently selected program.
/// Outgoing credentials and incoming Hello bodies are never exported here.
///
/// # Errors
/// Refuses overwide direct data before copying, failed/pending receives, changed
/// kernel peers or native source bindings, incomplete/duplicate/out-of-order
/// Blob custody, changed original Realize, or any noninitial native inventory.
pub fn inspect_original_packet_gate(
    originals: &OriginalProbeResponses,
    selection: &PacketControlSelection,
    program: &PacketProgramDefinition,
    report: &ConformanceReport,
) -> Result<OriginalPacketGate, ProviderError> {
    crate::connection::serialized_credit(&(selection, program, report), 256 * 1024)?;
    if !report.passed()
        || report.endpoints.len() != 1
        || report.results.len() != 5
        || program.schema != "source-owned.packet-program.v1"
        || program.events.len() != 2
        || selection.provider.implementation.implementation_id.as_str()
            != "source-owned.packet-native/2"
        || selection.realization.bindings.len() != 1
    {
        return Err(refused());
    }
    let expected_peer = &report.endpoints[0];
    if !selection
        .provider
        .implementation
        .artifacts
        .iter()
        .any(|artifact| {
            artifact.role.as_str() == "executable" && artifact.content == expected_peer.executable
        })
    {
        return Err(refused());
    }
    let rows = originals.records()?;
    if rows.is_empty() || rows.len() > MAXIMUM_FRAMES {
        return Err(refused());
    }

    let mut transfer: Option<Id> = None;
    let mut reference: Option<ContentRef> = None;
    let mut body = Vec::new();
    let mut chunks = 0;
    let mut finished = false;
    for row in rows.iter() {
        if row.state() != OriginalProbeResponseState::Received || row.peer() != expected_peer {
            return Err(refused());
        }
        row.reference().ok_or_else(refused)?.verify(row.bytes())?;
        let value = canonical::parse_json(row.bytes(), BODY_BYTES)?;
        let original: Envelope =
            serde_json::from_value(value).map_err(crucible_node_contract::ContractError::from)?;
        if original.message == MessageKind::Response {
            if original.method == Method::Realize {
                if reference.is_some() {
                    return Err(refused());
                }
                let request = RequestBody::Realize(selection.realize.clone());
                let reply = decode_response(&request, &original.body)?;
                let Some(MethodResult::Realize(realized)) = reply.result else {
                    return Err(refused());
                };
                if realized.realization_manifest != selection.realization
                    || realized.prepared_token != selection.prepared_token
                    || realized.closed_gate_receipt.length.get() > BODY_BYTES as u64
                {
                    return Err(refused());
                }
                body.try_reserve_exact(realized.closed_gate_receipt.length.get() as usize)
                    .map_err(|_| ProviderError::ResourceExhausted("original gate body credit"))?;
                reference = Some(realized.closed_gate_receipt);
            }
            continue;
        }
        match decode_request(original.method, &original.body)? {
            RequestBody::BlobBegin(begin) => {
                if transfer.is_some() || Some(&begin.content) != reference.as_ref() {
                    return Err(refused());
                }
                transfer = Some(begin.transfer_id);
            }
            RequestBody::BlobChunk(chunk) => {
                chunks += 1;
                let next = body
                    .len()
                    .checked_add(chunk.bytes.as_slice().len())
                    .ok_or_else(refused)?;
                if transfer.as_ref() != Some(&chunk.transfer_id)
                    || finished
                    || chunks > MAXIMUM_CHUNKS
                    || chunk.offset.get() != body.len() as u64
                    || chunk.bytes.as_slice().is_empty()
                    || chunk.bytes.as_slice().len() > 4096
                    || next as u64 > reference.as_ref().ok_or_else(refused)?.length.get()
                {
                    return Err(refused());
                }
                body.extend_from_slice(chunk.bytes.as_slice());
            }
            RequestBody::BlobFinish(finish) => {
                if finished || transfer.as_ref() != Some(&finish.transfer_id) {
                    return Err(refused());
                }
                reference.as_ref().ok_or_else(refused)?.verify(&body)?;
                finished = true;
            }
            _ => return Err(refused()),
        }
    }
    if !finished {
        return Err(refused());
    }
    let native: PacketNativeRecord =
        serde_json::from_value(canonical::parse_json(&body, BODY_BYTES)?)
            .map_err(crucible_node_contract::ContractError::from)?;
    let expected = &selection.realization.bindings[0].authority;
    let realize = report
        .results
        .iter()
        .find(|row| row.check == Some(CheckKind::PausedActivation))
        .ok_or_else(refused)?;
    let original_body = serde_json::to_value(&selection.realize)
        .map_err(crucible_node_contract::ContractError::from)?;
    if native.schema != "source-owned.packet-native/2"
        || native.native_pid != expected_peer.peer_pid
        || native.original.message != MessageKind::Request
        || native.original.method != Method::Realize
        || native.original.session_id.0.as_ref() != Some(&expected.session_id)
        || native.original.incarnation_id.0.as_ref() != Some(&expected.incarnation_id)
        || native.original.body != *original_body.as_object().ok_or_else(refused)?
        || realize.request_identity.as_ref()
            != Some(&native.original.request_hash(RequestOrigin::Controller)?)
        || native.grant.is_some()
        || !native.inventory.gate_closed
        || native.inventory.private_mutations.get() != 0
        || native.inventory.packet_effects.get() != 0
        || native.inventory.pending != program.events
        || !native.inventory.retained_outputs.is_empty()
        || native.inventory.reached
            != crucible_node_contract::Position::new(
                crucible_node_contract::U64::new(0),
                crucible_node_contract::U64::new(0),
                crucible_node_contract::Phase::BoundaryControl,
            )
    {
        return Err(refused());
    }
    Ok(OriginalPacketGate {
        peer: expected_peer.clone(),
        reference: reference.ok_or_else(refused)?,
        bytes: body,
        native,
    })
}

fn refused() -> ProviderError {
    ProviderError::Correlation("original finite packet gate custody differs")
}
