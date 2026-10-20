//! Checks a first Root Hello against the exact original inert Open query.
//!
//! ```text
//! frame[612] = Hello-header[112] | RootOpen-record[500]
//! coordinates = Hello, sequence1, original lane and Controller nonce,
//!               Root nonce from that checked RootOpen body
//! ```
//!
//! This passive framing check cannot authenticate Root. The actual client must
//! retain its protected peer/profile/original socket and independently compare
//! PID, UID/GID, boot and both immutable cutoffs before accepting the exchange.

use super::{ROOT_OPEN_BODY_BYTES_V1, RootOpenBodyDataV1};
use super::super::{
    HistoryErrorV1, KeyV1, OwnerV1, PhaseV1, RECORD_OVERHEAD_BYTES, RecordEnvelopeV1,
};
use super::super::transport::{
    FRAME_HEADER_BYTES, FrameCoordinatesV1, FrameEnvelopeV1, FrameKindV1, OpenQueryV1,
};

const ROOT_OPEN_RECORD_BYTES: usize = RECORD_OVERHEAD_BYTES + ROOT_OPEN_BODY_BYTES_V1;

/// Holds the exact first Hello frame and fixed RootOpen record width.
pub const ROOT_HELLO_FRAME_BYTES_V1: usize = FRAME_HEADER_BYTES + ROOT_OPEN_RECORD_BYTES;

/// Borrows a checked first Hello as comparison data beside its original frame.
///
/// The copied body and checksum grant no Root currentness or Use permission.
#[derive(Clone, Copy)]
pub struct RootHelloDataV1<'frame> {
    /// The exact complete record borrowed from the original received frame.
    pub record: &'frame [u8; ROOT_OPEN_RECORD_BYTES],
    /// The canonical body whose Open must equal the client's original Open.
    pub body: RootOpenBodyDataV1,
    /// The checksum of that exact RootOpen envelope, not a native readback.
    pub checksum: [u8; 32],
}

impl<'frame> RootHelloDataV1<'frame> {
    /// Checks all original correlations without trusting an unparsed header nonce.
    ///
    /// The fixed payload is checked first to derive the expected Root nonce;
    /// the existing frame decoder then checks the entire header and payload.
    ///
    /// # Errors
    /// Rejects wrong extent, malformed record/body/frame, a noninitial Root row,
    /// nonzero predecessor, or changed original Open, seed or frame coordinates.
    pub fn decode(bytes: &'frame [u8], expected: OpenQueryV1) -> Result<Self, HistoryErrorV1> {
        if bytes.len() != ROOT_HELLO_FRAME_BYTES_V1 {
            return Err(HistoryErrorV1::Extent);
        }
        let record: &[u8; ROOT_OPEN_RECORD_BYTES] = bytes[FRAME_HEADER_BYTES..].try_into()
            .map_err(|_| HistoryErrorV1::Extent)?;
        let envelope = RecordEnvelopeV1::decode(record,
            KeyV1::new(expected.lane, OwnerV1::Root, 1)?,
            PhaseV1::new(OwnerV1::Root, 1)?)?;
        let body = RootOpenBodyDataV1::decode(envelope.body())?;
        if body.open != expected || envelope.coordinates().predecessor != [0; 32]
            || envelope.coordinates().correlation != expected.seed {
            return Err(HistoryErrorV1::Correlation);
        }
        FrameEnvelopeV1::decode(bytes, FrameCoordinatesV1 {
            kind: FrameKindV1::Hello, lane: expected.lane, sequence: 1,
            root_nonce: body.root_nonce, controller_nonce: expected.controller_nonce,
        })?;
        Ok(Self { record, body, checksum: envelope.checksum() })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use super::super::super::RecordCoordinatesV1;

    #[test]
    fn hello_checks_same_original_open_and_root_nonce_across_record_and_frame() {
        let body = super::super::tests::body();
        let mut record = [0; ROOT_OPEN_RECORD_BYTES];
        RecordEnvelopeV1::encode_into(RecordCoordinatesV1 {
            key: KeyV1::new(body.open.lane, OwnerV1::Root, 1).unwrap(),
            phase: PhaseV1::new(OwnerV1::Root, 1).unwrap(),
            predecessor: [0; 32], correlation: body.open.seed,
        }, &body.encode().unwrap(), &mut record).unwrap();
        let coordinates = FrameCoordinatesV1 {
            kind: FrameKindV1::Hello, lane: body.open.lane, sequence: 1,
            root_nonce: body.root_nonce, controller_nonce: body.open.controller_nonce,
        };
        let mut frame = Vec::from(coordinates.encode_header(&record).unwrap());
        frame.extend_from_slice(&record);

        assert_eq!(RootHelloDataV1::decode(&frame, body.open).unwrap().body, body);
        let mut changed = body.open;
        changed.ready[0] ^= 1;
        assert!(RootHelloDataV1::decode(&frame, changed).is_err());
        let mut changed = coordinates;
        changed.root_nonce[0] ^= 1;
        frame[..FRAME_HEADER_BYTES].copy_from_slice(&changed.encode_header(&record).unwrap());
        assert!(RootHelloDataV1::decode(&frame, body.open).is_err());
    }
}
