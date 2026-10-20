//! Retains durable-record codec DATA through every reached packet/link boundary.
//!
//! Captures are once-only comparison storage, without journal or session authority.
//! Failed raw packets, parsed models and canonical encodings remain with the caller.
//! Fully compared pure scratch is disposed only at its original final borrower.

use super::*;
use crate::projection::{
    CanonicalBrokerRequestDecodeCaptureV1, CanonicalBrokerResponseDecodeCaptureV1,
    decode_canonical_request_retaining_v1, decode_canonical_response_retaining_v1,
};
use crate::projection::CaptureValueV1;

#[derive(Default)]
pub(super) struct PacketLinkCaptureV1 {
    request: CanonicalBrokerRequestDecodeCaptureV1,
    outcome: CanonicalBrokerResponseDecodeCaptureV1,
}

/// Retains one durable record decode, including raw partial packets and validation.
#[derive(Default)]
pub struct BrokerSessionDurableRecordDecodeCaptureV1 {
    request_packet: Option<Vec<u8>>,
    outcome_packet: Option<Vec<u8>>,
    record: Option<BrokerSessionDurableRecordV1>,
    validation: PacketLinkCaptureV1,
    canonical: BrokerSessionDurableRecordEncodeCaptureV1,
    result: Option<Result<(), BrokerSessionDurableError>>,
    attempted: bool,
    closed: Option<BrokerSessionDurableError>,
}

/// Retains one durable record encode and its reached packet validation.
#[derive(Default)]
pub struct BrokerSessionDurableRecordEncodeCaptureV1 {
    validation: PacketLinkCaptureV1,
    encoded: Option<Vec<u8>>,
    result: Option<Result<(), BrokerSessionDurableError>>,
    attempted: bool,
    closed: Option<BrokerSessionDurableError>,
}

macro_rules! capture_accessors {
    ($capture:ty, $output:ty, $field:ident, $borrow:ident, $take:ident) => {
        impl $capture {
            /// Constructs an empty once-only codec capture.
            #[must_use]
            pub fn new() -> Self { Self::default() }

            /// Borrows the original complete codec error.
            #[must_use]
            pub fn failure(&self) -> Option<&BrokerSessionDurableError> {
                self.result.as_ref().and_then(|result| result.as_ref().err()).or(self.closed.as_ref())
            }

            /// Borrows a fully completed codec output.
            #[must_use]
            pub fn $borrow(&self) -> Option<&$output> {
                if self.closed.is_none() && matches!(self.result, Some(Ok(()))) {
                    self.$field.as_ref()
                } else {
                    None
                }
            }

            /// Moves a fully completed output once, leaving failed partials resident.
            ///
            /// # Errors
            /// Returns the original failure or invalid format before completion
            /// and after this output has already moved.
            pub fn $take(&mut self) -> Result<$output, BrokerSessionDurableError> {
                if let Some(error) = self.failure() { return Err(error.clone()); }
                if !matches!(self.result, Some(Ok(()))) {
                    return Err(BrokerSessionDurableError::InvalidFormat);
                }
                self.$field.take().ok_or(BrokerSessionDurableError::InvalidFormat)
            }

            /// Returns this concrete inline owner extent, without dynamic storage.
            #[must_use]
            pub const fn inline_bytes_v1() -> usize { std::mem::size_of::<Self>() }
        }
    };
}

capture_accessors!(BrokerSessionDurableRecordDecodeCaptureV1, BrokerSessionDurableRecordV1,
    record, record, take_record_once);
capture_accessors!(BrokerSessionDurableRecordEncodeCaptureV1, Vec<u8>,
    encoded, encoded_vec, take_encoded_once);

impl BrokerSessionDurableRecordEncodeCaptureV1 {
    /// Borrows the completed canonical backing without cloning it.
    #[must_use]
    pub fn encoded(&self) -> Option<&[u8]> { self.encoded_vec().map(Vec::as_slice) }
}

impl BrokerSessionDurableRecordV1 {
    /// Decodes through the shared engine while retaining all reached outer DATA.
    ///
    /// # Errors
    /// Returns the ordinary record classification; reentry retains the first attempt.
    pub fn decode_retaining(bytes: &[u8], capture: &mut BrokerSessionDurableRecordDecodeCaptureV1)
        -> Result<(), BrokerSessionDurableError>
    {
        if capture.attempted {
            capture.closed = Some(BrokerSessionDurableError::InvalidFormat);
            return Err(capture.failure().cloned().unwrap_or(BrokerSessionDurableError::InvalidFormat));
        }
        capture.attempted = true;
        match decode_engine(bytes, Some(capture)) {
            Ok(record) => {
                capture.record = Some(record);
                capture.result = Some(Ok(()));
                Ok(())
            }
            Err(error) => {
                capture.result = Some(Err(error));
                Err(capture.failure().cloned().unwrap_or(BrokerSessionDurableError::InvalidFormat))
            }
        }
    }

    /// Encodes through the shared engine while retaining reached validation DATA.
    ///
    /// # Errors
    /// Returns the ordinary record classification or rejects a repeated attempt.
    pub fn encode_retaining(&self, capture: &mut BrokerSessionDurableRecordEncodeCaptureV1)
        -> Result<(), BrokerSessionDurableError>
    {
        if capture.attempted {
            capture.closed = Some(BrokerSessionDurableError::InvalidFormat);
            return Err(capture.failure().cloned().unwrap_or(BrokerSessionDurableError::InvalidFormat));
        }
        capture.attempted = true;
        match encode_engine(self, Some(capture)) {
            Ok(encoded) => {
                capture.encoded = Some(encoded);
                capture.result = Some(Ok(()));
                Ok(())
            }
            Err(error) => {
                capture.result = Some(Err(error));
                Err(capture.failure().cloned().unwrap_or(BrokerSessionDurableError::InvalidFormat))
            }
        }
    }

    /// Hashes the exact retained encoding without creating a second encoder.
    ///
    /// The backing stays resident for a caller's later pair/link comparison.
    ///
    /// # Errors
    /// Returns the ordinary encode failure or rejects a repeated attempt.
    pub fn commitment_retaining(&self, capture: &mut BrokerSessionDurableRecordEncodeCaptureV1)
        -> Result<[u8; 32], BrokerSessionDurableError>
    {
        self.encode_retaining(capture)?;
        let encoded = capture.encoded().ok_or(BrokerSessionDurableError::InvalidFormat)?;
        Ok(digest(b"aos-sandbox-broker-session-durable-record-v1\0", encoded))
    }
}

pub(super) fn decode_engine(bytes: &[u8], capture: Option<&mut BrokerSessionDurableRecordDecodeCaptureV1>)
    -> Result<BrokerSessionDurableRecordV1, BrokerSessionDurableError>
{
    if bytes.len() < HEADER_BYTES + BROKER_SESSION_REQUEST_COMPANION_BYTES
        || bytes.len() > BROKER_SESSION_DURABLE_RECORD_MAXIMUM_BYTES
    {
        return Err(BrokerSessionDurableError::InvalidLength);
    }
    if bytes.get(..8) != Some(MAGIC.as_slice()) || read_u16(bytes, 8)? != VERSION {
        return Err(BrokerSessionDurableError::InvalidFormat);
    }

    let kind = bytes
        .get(10)
        .copied()
        .ok_or(BrokerSessionDurableError::InvalidLength)?;
    let protocol = decode_protocol(bytes.get(11).copied())?;
    let method = decode_method(bytes.get(12).copied())?;
    let endpoint = decode_endpoint(bytes.get(13).copied())?;
    let revision = read_u64(bytes, 14)?;
    let session_binding = read_array(bytes, 22)?;
    let peer_binding = BrokerSessionPeerBindingV1::new(read_array(bytes, 54)?)?;
    let protected_bindings = BrokerSessionProtectedBindingsV1::new(
        read_array(bytes, 86)?,
        read_array(bytes, 118)?,
        read_array(bytes, 150)?,
    )?;
    let request_id = read_array(bytes, 182)?;
    let client_sequence = read_u64(bytes, 198)?;
    let broker_sequence = read_u64(bytes, 206)?;
    let maximum_response_bytes = read_u32(bytes, 214)?;
    let predecessor = read_array(bytes, 218)?;
    let profile_binding = read_array(bytes, 250)?;
    let request_semantic_binding = read_array(bytes, 282)?;
    let outcome_semantic_binding = read_array(bytes, 314)?;
    let request_length = usize::try_from(read_u32(bytes, 346)?)
        .map_err(|_| BrokerSessionDurableError::InvalidLength)?;
    let outcome_length = usize::try_from(read_u32(bytes, 350)?)
        .map_err(|_| BrokerSessionDurableError::InvalidLength)?;

    let (request_capture, outcome_capture, record_capture, validation_capture, canonical_capture) = match capture {
        Some(capture) => (Some(&mut capture.request_packet), Some(&mut capture.outcome_packet),
            Some(&mut capture.record), Some(&mut capture.validation), Some(&mut capture.canonical)),
        None => (None, None, None, None, None),
    };
    let mut cursor = HEADER_BYTES;
    let request_companion_bytes =
        take(bytes, &mut cursor, BROKER_SESSION_REQUEST_COMPANION_BYTES)?;
    let request_companion = BrokerSessionRequestCompanionV1::decode(request_companion_bytes)?;
    let request_packet = CaptureValueV1::new(
        take(bytes, &mut cursor, request_length)?.to_vec(), request_capture);

    let (outcome_companion, outcome_packet) = match kind {
        REQUEST_KIND if outcome_length == 0 && broker_sequence == 0 => (None, None),
        TERMINAL_KIND if outcome_length != 0 && broker_sequence != 0 => {
            let companion_bytes =
                take(bytes, &mut cursor, BROKER_SESSION_OUTCOME_COMPANION_BYTES)?;
            let companion = BrokerSessionOutcomeCompanionV1::decode(companion_bytes)?;
            let packet = CaptureValueV1::new(
                take(bytes, &mut cursor, outcome_length)?.to_vec(), outcome_capture);
            (Some(companion), Some(packet))
        }
        _ => return Err(BrokerSessionDurableError::InvalidClosedValue),
    };
    if cursor != bytes.len() || revision == 0 || client_sequence == 0 {
        return Err(BrokerSessionDurableError::InvalidLength);
    }

    let mut local_record = None;
    let record = record_capture.unwrap_or(&mut local_record);
    *record = Some(BrokerSessionDurableRecordV1 {
        revision,
        protocol,
        endpoint,
        method,
        session_binding,
        peer_binding,
        protected_bindings,
        request_id,
        client_sequence,
        broker_sequence,
        maximum_response_bytes,
        predecessor,
        profile_binding,
        request_semantic_binding,
        outcome_semantic_binding,
        request_companion,
        request_packet: request_packet.take(),
        outcome_companion,
        outcome_packet: outcome_packet.map(CaptureValueV1::take),
    });
    let complete = record.as_ref().ok_or(BrokerSessionDurableError::InvalidFormat)?;
    validate_cross_links(complete, validation_capture)?;
    match canonical_capture {
        Some(capture) => {
            complete.encode_retaining(capture)?;
            if capture.encoded() != Some(bytes) {
                return Err(BrokerSessionDurableError::InvalidFormat);
            }
            // Exact equality is this backing's final borrower.
            drop(capture.take_encoded_once()?);
        }
        None => {
            if complete.encode()?.as_slice() != bytes {
                return Err(BrokerSessionDurableError::InvalidFormat);
            }
        }
    }
    record.take().ok_or(BrokerSessionDurableError::InvalidFormat)
}

pub(super) fn encode_engine(record: &BrokerSessionDurableRecordV1, capture: Option<&mut BrokerSessionDurableRecordEncodeCaptureV1>)
    -> Result<Vec<u8>, BrokerSessionDurableError>
{
    validate_cross_links(record, capture.map(|capture| &mut capture.validation))?;
    if record.request_packet.len() > REQUEST_PACKET_MAXIMUM_BYTES
        || record
            .outcome_packet
            .as_ref()
            .is_some_and(|packet| packet.len() > OUTCOME_PACKET_MAXIMUM_BYTES)
    {
        return Err(BrokerSessionDurableError::InvalidLength);
    }
    let outcome_length = record.outcome_packet.as_ref().map_or(0, Vec::len);
    let capacity = HEADER_BYTES
        + BROKER_SESSION_REQUEST_COMPANION_BYTES
        + record.request_packet.len()
        + record
            .outcome_companion
            .as_ref()
            .map_or(0, |_| BROKER_SESSION_OUTCOME_COMPANION_BYTES)
        + outcome_length;
    if capacity > BROKER_SESSION_DURABLE_RECORD_MAXIMUM_BYTES {
        return Err(BrokerSessionDurableError::InvalidLength);
    }

    let request_length = u32::try_from(record.request_packet.len())
        .map_err(|_| BrokerSessionDurableError::InvalidLength)?;
    let outcome_length_u32 =
        u32::try_from(outcome_length).map_err(|_| BrokerSessionDurableError::InvalidLength)?;
    let mut bytes = Vec::with_capacity(capacity);
    bytes.extend_from_slice(MAGIC);
    bytes.extend_from_slice(&VERSION.to_be_bytes());
    bytes.push(match record.phase() {
        BrokerSessionDurablePhaseV1::RequestPrepared => REQUEST_KIND,
        BrokerSessionDurablePhaseV1::Terminal => TERMINAL_KIND,
    });
    bytes.push(record.protocol as u8);
    bytes.push(record.method as u8);
    bytes.push(record.endpoint as u8);
    bytes.extend_from_slice(&record.revision.to_be_bytes());
    bytes.extend_from_slice(&record.session_binding);
    bytes.extend_from_slice(&record.peer_binding.digest());
    bytes.extend_from_slice(&record.protected_bindings.protected_context());
    bytes.extend_from_slice(&record.protected_bindings.endpoint_publication());
    bytes.extend_from_slice(&record.protected_bindings.current_catalog());
    bytes.extend_from_slice(&record.request_id);
    bytes.extend_from_slice(&record.client_sequence.to_be_bytes());
    bytes.extend_from_slice(&record.broker_sequence.to_be_bytes());
    bytes.extend_from_slice(&record.maximum_response_bytes.to_be_bytes());
    bytes.extend_from_slice(&record.predecessor);
    bytes.extend_from_slice(&record.profile_binding);
    bytes.extend_from_slice(&record.request_semantic_binding);
    bytes.extend_from_slice(&record.outcome_semantic_binding);
    bytes.extend_from_slice(&request_length.to_be_bytes());
    bytes.extend_from_slice(&outcome_length_u32.to_be_bytes());
    bytes.extend_from_slice(&record.request_companion.encode());
    bytes.extend_from_slice(&record.request_packet);
    if let (Some(companion), Some(packet)) = (&record.outcome_companion, &record.outcome_packet) {
        bytes.extend_from_slice(&companion.encode());
        bytes.extend_from_slice(packet);
    }
    Ok(bytes)
}

pub(super) fn validate_cross_links(record: &BrokerSessionDurableRecordV1, capture: Option<&mut PacketLinkCaptureV1>)
    -> Result<(), BrokerSessionDurableError>
{
    if record.revision == 0 || record.client_sequence == 0 {
        return Err(BrokerSessionDurableError::ZeroRequiredField);
    }
    let terminal_offset = match record.phase() {
        BrokerSessionDurablePhaseV1::RequestPrepared => 1,
        BrokerSessionDurablePhaseV1::Terminal => 0,
    };
    let expected_revision = record
        .client_sequence
        .checked_mul(2)
        .and_then(|revision| revision.checked_sub(terminal_offset))
        .ok_or(BrokerSessionDurableError::SequenceExhausted)?;
    if record.revision != expected_revision
        || (record.revision == 1 && record.predecessor.iter().any(|byte| *byte != 0))
        || (record.revision != 1 && record.predecessor.iter().all(|byte| *byte == 0))
    {
        return Err(BrokerSessionDurableError::Continuity);
    }
    require_nonzero(&record.session_binding)?;
    require_nonzero(&record.request_id)?;
    require_nonzero(&record.request_semantic_binding)?;
    match record.phase() {
        BrokerSessionDurablePhaseV1::RequestPrepared
            if record.outcome_semantic_binding != [0; 32] =>
        {
            return Err(BrokerSessionDurableError::Continuity);
        }
        BrokerSessionDurablePhaseV1::Terminal => {
            require_nonzero(&record.outcome_semantic_binding)?;
        }
        BrokerSessionDurablePhaseV1::RequestPrepared => {}
    }
    if record.profile_binding != profile_binding(record.method)? {
        return Err(BrokerSessionDurableError::Continuity);
    }
    if record.request_companion.protocol() != record.protocol
        || record.request_companion.method() != record.method
        || record.request_companion.maximum_response_bytes() != record.maximum_response_bytes
        || record.request_companion.signed_request().subject().sequence() != record.client_sequence
    {
        return Err(BrokerSessionDurableError::Continuity);
    }
    let (request_capture, outcome_capture) = match capture {
        Some(capture) => (Some(&mut capture.request), Some(&mut capture.outcome)),
        None => (None, None),
    };
    validate_request_packet(
        &record.request_companion,
        &record.request_packet,
        record.session_binding,
        record.request_id,
        request_capture,
    )?;
    match (&record.outcome_companion, &record.outcome_packet) {
        (None, None) if record.broker_sequence == 0 => Ok(()),
        (Some(companion), Some(packet)) if record.broker_sequence != 0 => {
            validate_outcome_packet(
                companion,
                packet,
                record.session_binding,
                record.request_id,
                record.client_sequence,
                record.maximum_response_bytes,
                record.method,
                record.protocol,
                outcome_capture,
            )?;
            if companion.signed_outcome().subject().sequence() != record.broker_sequence
                || record.broker_sequence != record.client_sequence
            {
                return Err(BrokerSessionDurableError::Continuity);
            }
            Ok(())
        }
        _ => Err(BrokerSessionDurableError::InvalidClosedValue),
    }
}

pub(super) fn validate_request_packet(
    companion: &BrokerSessionRequestCompanionV1,
    packet: &[u8],
    session_binding: [u8; 32],
    request_id: [u8; 16],
    mut capture: Option<&mut CanonicalBrokerRequestDecodeCaptureV1>,
) -> Result<(), BrokerSessionDurableError> {
    if packet.is_empty() || packet.len() > REQUEST_PACKET_MAXIMUM_BYTES {
        return Err(BrokerSessionDurableError::InvalidLength);
    }
    let canonical_local;
    let canonical = match capture.as_deref_mut() {
        Some(capture) => {
            decode_canonical_request_retaining_v1(packet, capture)
                .map_err(|_| BrokerSessionDurableError::PacketMismatch)?;
            capture.model().ok_or(BrokerSessionDurableError::PacketMismatch)?
        }
        None => {
            canonical_local = decode_canonical_request_v1(packet)
                .map_err(|_| BrokerSessionDurableError::PacketMismatch)?;
            &canonical_local
        }
    };
    let signed = canonical.signed_artifact();
    if canonical.message().method.as_known() != Some(companion.method())
        || signed != companion.signed_request()
        || signed.subject().session_binding() != session_binding
        || signed.subject().request_id() != request_id
        || authenticated_broker_method_profile_v1(companion.method())
            .is_none_or(|profile| profile.protocol() != companion.protocol())
    {
        return Err(BrokerSessionDurableError::PacketMismatch);
    }
    if let Some(capture) = capture {
        // The complete packet/companion predicate is the original final borrower.
        drop(capture.take_model_once().map_err(|_| BrokerSessionDurableError::PacketMismatch)?);
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
pub(super) fn validate_outcome_packet(
    companion: &BrokerSessionOutcomeCompanionV1,
    packet: &[u8],
    session_binding: [u8; 32],
    request_id: [u8; 16],
    client_sequence: u64,
    maximum_response_bytes: u32,
    method: BrokerMethod,
    protocol: BrokerSessionProtocolV1,
    mut capture: Option<&mut CanonicalBrokerResponseDecodeCaptureV1>,
) -> Result<(), BrokerSessionDurableError> {
    if packet.is_empty()
        || packet.len() > OUTCOME_PACKET_MAXIMUM_BYTES
        || packet.len() > maximum_response_bytes as usize
    {
        return Err(BrokerSessionDurableError::InvalidLength);
    }
    let canonical_local;
    let canonical = match capture.as_deref_mut() {
        Some(capture) => {
            decode_canonical_response_retaining_v1(packet, capture)
                .map_err(|_| BrokerSessionDurableError::PacketMismatch)?;
            capture.model().ok_or(BrokerSessionDurableError::PacketMismatch)?
        }
        None => {
            canonical_local = decode_canonical_response_v1(packet)
                .map_err(|_| BrokerSessionDurableError::PacketMismatch)?;
            &canonical_local
        }
    };
    let signed = canonical.signed_artifact();
    if companion.protocol() != protocol
        || companion.method() != method
        || companion.request_id() != request_id
        || companion.client_sequence() != client_sequence
        || companion.maximum_response_bytes() != maximum_response_bytes
        || canonical.message().method.as_known() != Some(method)
        || signed != companion.signed_outcome()
        || signed.subject().session_binding() != session_binding
        || signed.subject().request_id() != request_id
    {
        return Err(BrokerSessionDurableError::PacketMismatch);
    }
    if let Some(capture) = capture {
        // The complete packet/companion predicate is the original final borrower.
        drop(capture.take_model_once().map_err(|_| BrokerSessionDurableError::PacketMismatch)?);
    }
    Ok(())
}

impl PacketLinkCaptureV1 {
    fn receiving_metadata_cells_v1() -> Option<usize> {
        2usize.checked_add(CanonicalBrokerRequestDecodeCaptureV1::receiving_metadata_cells_v1()?)?
            .checked_add(CanonicalBrokerResponseDecodeCaptureV1::receiving_metadata_cells_v1()?)
    }
}

impl BrokerSessionDurableRecordDecodeCaptureV1 {
    /// Bounds fixed retained field/control cells, excluding dynamic model storage.
    #[must_use]
    pub fn receiving_metadata_cells_v1() -> Option<usize> {
        // Two raw slots, model, validation and canonical owners, result and
        // attempted/closed state. Both embedded validation marker sets coexist.
        8usize.checked_add(PacketLinkCaptureV1::receiving_metadata_cells_v1()?)?
            .checked_add(BrokerSessionDurableRecordEncodeCaptureV1::receiving_metadata_cells_v1()?)
    }
}

impl BrokerSessionDurableRecordEncodeCaptureV1 {
    /// Bounds fixed retained field/control cells, excluding dynamic model storage.
    #[must_use]
    pub fn receiving_metadata_cells_v1() -> Option<usize> {
        // Validation, encoded output, Result and attempted/closed state.
        5usize.checked_add(PacketLinkCaptureV1::receiving_metadata_cells_v1()?)
    }
}

impl BrokerSessionDurableRecordDecodeCaptureV1 {
    /// Borrows reached request bytes without claiming a complete valid record.
    #[must_use]
    pub fn retained_request_packet(&self) -> Option<&[u8]> {
        self.record.as_ref().map(BrokerSessionDurableRecordV1::request_packet)
            .or_else(|| self.request_packet.as_deref())
    }

    /// Borrows reached outcome bytes without claiming a complete valid record.
    #[must_use]
    pub fn retained_outcome_packet(&self) -> Option<&[u8]> {
        self.record.as_ref().and_then(BrokerSessionDurableRecordV1::outcome_packet)
            .or_else(|| self.outcome_packet.as_deref())
    }
}
