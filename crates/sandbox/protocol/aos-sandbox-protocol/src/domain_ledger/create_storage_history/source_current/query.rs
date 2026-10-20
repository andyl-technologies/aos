//! Borrows the exact original RootOpen and SourceHeld for a fresh cut query.
//!
//! ```text
//! AOSSSR17 | committed-RootOpen-record[500] | SourceHeld-receipt[508]
//! query-digest = SHA256("aos.sandbox.create-storage.source-current.query.v1\0"
//!                      || complete-query[1016])
//! ```
//!
//! Source07 remains absent and Source16 retains its separate semantics. The
//! nonce, lane, Ready, accepted association and cutoffs come from these complete
//! original records. No separate caller scalar can replace or renew them.

use sha2::{Digest as _, Sha256};

use super::super::{HistoryErrorV1, KeyV1, OwnerV1, PhaseV1, RecordEnvelopeV1,
    RECORD_HEADER_BYTES, RECORD_OVERHEAD_BYTES};
use super::super::root_open::{ROOT_OPEN_BODY_BYTES_V1, RootOpenBodyDataV1};
use super::super::source_held::{SOURCE_HELD_RECEIPT_BYTES_V1, SourceHeldReceiptDataV1};

/// Selects only the fresh Source CurrentCut request.
pub const SOURCE_CURRENT_QUERY_MAGIC_V1: &[u8; 8] = b"AOSSSR17";

/// Selects only the corresponding freshly signed Source CurrentCut reply.
pub const SOURCE_CURRENT_REPLY_MAGIC_V1: &[u8; 8] = b"AOSSSP17";

const ROOT_RECORD_BYTES: usize = RECORD_OVERHEAD_BYTES + ROOT_OPEN_BODY_BYTES_V1;
const QUERY_DOMAIN: &[u8] = b"aos.sandbox.create-storage.source-current.query.v1\0";

/// Gives the complete fixed query, derived from the two existing exact formats.
pub const SOURCE_CURRENT_QUERY_BYTES_V1: usize =
    8 + ROOT_RECORD_BYTES + SOURCE_HELD_RECEIPT_BYTES_V1;

/// Borrows complete canonical comparison records without granting currentness.
///
/// A genuine Root caller derives both slices from its same committed RootOpen
/// and strictly received complete B. A genuine Source responder additionally
/// validates its live Root peer, exact current Source pair and Native suffix,
/// complete current project ancestry and unchanged original accepted cutoff.
#[derive(Clone, Copy)]
pub struct SourceCurrentQueryDataV1<'records> {
    root_open: &'records [u8; ROOT_RECORD_BYTES],
    source_held: &'records [u8; SOURCE_HELD_RECEIPT_BYTES_V1],
}

impl<'records> SourceCurrentQueryDataV1<'records> {
    /// Borrows two exact records and checks their passive shared association.
    ///
    /// # Errors
    /// Rejects incorrect widths, malformed records, foreign lane/seed/nonce/boot,
    /// invalid original cutoffs or a RootOpen already beyond the Source cutoff.
    /// This performs no IO, typed model allocation or signature acceptance.
    pub fn from_records(root_open: &'records [u8], source_held: &'records [u8])
        -> Result<Self, HistoryErrorV1>
    {
        let value = Self {
            root_open: root_open.try_into().map_err(|_| HistoryErrorV1::Extent)?,
            source_held: source_held.try_into().map_err(|_| HistoryErrorV1::Extent)?,
        };
        value.require_association()?;
        Ok(value)
    }

    /// Borrows exact complete request framing without allocating.
    ///
    /// # Errors
    /// Rejects wrong selector, nonexact extent or the same invalid original
    /// association as [`Self::from_records`]. No decoded query grants a view.
    pub fn decode(bytes: &'records [u8]) -> Result<Self, HistoryErrorV1> {
        if bytes.len() != SOURCE_CURRENT_QUERY_BYTES_V1
            || &bytes[..8] != SOURCE_CURRENT_QUERY_MAGIC_V1 {
            return Err(HistoryErrorV1::Malformed);
        }
        Self::from_records(&bytes[8..8 + ROOT_RECORD_BYTES], &bytes[8 + ROOT_RECORD_BYTES..])
    }

    /// Encodes the complete fixed request into caller-owned inline storage.
    ///
    /// # Errors
    /// Rejects an invalid passive association before writing output.
    pub fn encode(self) -> Result<[u8; SOURCE_CURRENT_QUERY_BYTES_V1], HistoryErrorV1> {
        self.require_association()?;
        let mut bytes = [0; SOURCE_CURRENT_QUERY_BYTES_V1];
        bytes[..8].copy_from_slice(SOURCE_CURRENT_QUERY_MAGIC_V1);
        bytes[8..8 + ROOT_RECORD_BYTES].copy_from_slice(self.root_open);
        bytes[8 + ROOT_RECORD_BYTES..].copy_from_slice(self.source_held);
        Ok(bytes)
    }

    /// Commits the complete exact query for the new purpose's signed response.
    ///
    /// The digest is correlation DATA. It establishes no live Root or Source
    /// writer, current cut or permit independently of the genuine consumers.
    ///
    /// # Errors
    /// Rejects an invalid original association before computing the commitment.
    pub fn digest_v1(self) -> Result<[u8; 32], HistoryErrorV1> {
        let bytes = self.encode()?;
        Ok(Sha256::new().chain_update(QUERY_DOMAIN).chain_update(bytes).finalize().into())
    }

    /// Borrows the exact RootOpen record retained by the query's genuine caller.
    #[must_use]
    pub const fn root_open_record(self) -> &'records [u8; ROOT_RECORD_BYTES] {
        self.root_open
    }

    /// Borrows the exact original Source receipt supplied in complete B.
    #[must_use]
    pub const fn source_held_receipt(self) -> &'records [u8; SOURCE_HELD_RECEIPT_BYTES_V1] {
        self.source_held
    }

    /// Decodes fixed Root correlation without proving a live Root invocation.
    ///
    /// # Errors
    /// Rejects any changed original record framing or passive association.
    pub fn root_body(self) -> Result<RootOpenBodyDataV1, HistoryErrorV1> {
        self.require_association()
    }

    /// Borrows the canonical Source receipt under the same original lane.
    ///
    /// # Errors
    /// Rejects invalid framing or any changed original association. The actual
    /// Source replay must independently validate exact current pair and suffix.
    pub fn source_receipt(self) -> Result<SourceHeldReceiptDataV1<'records>, HistoryErrorV1> {
        let root = self.require_association()?;
        SourceHeldReceiptDataV1::decode(self.source_held, root.open.lane)
    }

    fn require_association(self) -> Result<RootOpenBodyDataV1, HistoryErrorV1> {
        // The fixed body first supplies the expected lane; the existing whole
        // record decoder then authenticates its framing/checksum and that lane.
        let root = RootOpenBodyDataV1::decode(&self.root_open[RECORD_HEADER_BYTES..
            RECORD_HEADER_BYTES + ROOT_OPEN_BODY_BYTES_V1])?;
        let record = RecordEnvelopeV1::decode(self.root_open,
            KeyV1::new(root.open.lane, OwnerV1::Root, 1)?,
            PhaseV1::new(OwnerV1::Root, 1)?)?;
        let source = SourceHeldReceiptDataV1::decode(self.source_held, root.open.lane)?;
        let body = source.body(root.open.lane)?;
        if record.coordinates().predecessor != [0; 32]
            || record.coordinates().correlation != root.open.seed
            || body.seed != root.open.seed || body.controller_nonce != root.open.controller_nonce
            || body.boot != root.boot || root.started < body.started || root.started >= body.cutoff {
            return Err(HistoryErrorV1::Correlation);
        }
        Ok(root)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use super::super::super::{LatestHeadV1, RecordCoordinatesV1,
        source_held::{SOURCE_HELD_RECORD_BYTES_V1, SourceHeldBodyDataV1}, transport::OpenQueryV1};
    use super::super::super::super::protected_names::ProtectedJournalNamesV1;

    fn records(root_nonce: u8, controller_nonce: u8, source_cutoff: u64)
        -> ([u8; ROOT_RECORD_BYTES], [u8; SOURCE_HELD_RECEIPT_BYTES_V1])
    {
        // These are format DATA fixtures, never genuine Root/Source loans.
        let names = ProtectedJournalNamesV1::from_historical_fields((1, 2), (3, 4), (5, 6));
        let lane = [1; 16];
        let source = SourceHeldBodyDataV1 {
            operation: [2; 16], project: [3; 16], sandbox: [4; 16],
            accepted_request: [5; 32], coissuance_binding: [6; 32], seed: [7; 32],
            controller_nonce: [8; 16], boot: [9; 16], started: 10, cutoff: source_cutoff,
            source_names: names, source_before_next: 11, source_before_end: 12,
        };
        let mut source_record = [0; SOURCE_HELD_RECORD_BYTES_V1];
        let checksum = RecordEnvelopeV1::encode_into(RecordCoordinatesV1 {
            key: KeyV1::new(lane, OwnerV1::Source, 1).unwrap(),
            phase: PhaseV1::new(OwnerV1::Source, 1).unwrap(),
            predecessor: [0; 32], correlation: source.seed,
        }, &source.encode().unwrap(), &mut source_record).unwrap();
        let source_receipt = SourceHeldReceiptDataV1 {
            record: &source_record, latest_head: LatestHeadV1::new(1, checksum).unwrap().encode(),
            source_names: names, source_after_next: 15, source_after_end: 16,
        }.encode(lane).unwrap();
        let root = RootOpenBodyDataV1 {
            open: OpenQueryV1 { controller_nonce: [controller_nonce; 16], lane,
                seed: source.seed, ready: [11; 32] },
            root_nonce: [root_nonce; 16], boot: source.boot, started: 100, cutoff: 200,
            authority_names: names, policy_names: names, authority_next: 17, policy_next: 18,
            root_profile: [12; 32], root_recipient: [13; 16], root_producer: [14; 16],
            root_pid: 15, controller_pid: 16, controller_uid: 17, controller_gid: 18,
        };
        let mut root_record = [0; ROOT_RECORD_BYTES];
        RecordEnvelopeV1::encode_into(RecordCoordinatesV1 {
            key: KeyV1::new(lane, OwnerV1::Root, 1).unwrap(),
            phase: PhaseV1::new(OwnerV1::Root, 1).unwrap(),
            predecessor: [0; 32], correlation: source.seed,
        }, &root.encode().unwrap(), &mut root_record).unwrap();
        (root_record, source_receipt)
    }

    #[test]
    fn exact_query_borrows_whole_originals_and_commits_the_actual_root_nonce() {
        let (root, source) = records(19, 8, 300);
        let query = SourceCurrentQueryDataV1::from_records(&root, &source).unwrap();
        let encoded = query.encode().unwrap();
        let parsed = SourceCurrentQueryDataV1::decode(&encoded).unwrap();
        assert_eq!(encoded.len(), 1_016);
        assert_eq!(parsed.root_open_record(), &root);
        assert_eq!(parsed.source_held_receipt(), &source);
        assert!(std::ptr::eq(parsed.root_open_record().as_ptr(), encoded[8..].as_ptr()));
        assert_eq!(parsed.digest_v1().unwrap(), query.digest_v1().unwrap());
        let (other_root, _) = records(20, 8, 300);
        let other = SourceCurrentQueryDataV1::from_records(&other_root, &source).unwrap();
        assert_ne!(other.digest_v1().unwrap(), query.digest_v1().unwrap());
    }

    #[test]
    fn query_rejects_foreign_nonce_expired_cutoffs_and_all_nonexact_frames() {
        let (root, source) = records(19, 8, 300);
        let encoded = SourceCurrentQueryDataV1::from_records(&root, &source).unwrap().encode().unwrap();
        for width in 0..encoded.len() {
            assert!(SourceCurrentQueryDataV1::decode(&encoded[..width]).is_err());
        }
        assert!(SourceCurrentQueryDataV1::decode(&[encoded.as_slice(), &[0]].concat()).is_err());
        let (foreign, _) = records(19, 21, 300);
        assert!(SourceCurrentQueryDataV1::from_records(&foreign, &source).is_err());
        let (expired, old_source) = records(19, 8, 100);
        assert!(SourceCurrentQueryDataV1::from_records(&expired, &old_source).is_err());
        let mut other_purpose = encoded;
        other_purpose[..8].copy_from_slice(b"AOSSSR16");
        assert!(SourceCurrentQueryDataV1::decode(&other_purpose).is_err());
    }
}
