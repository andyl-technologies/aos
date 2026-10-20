//! Encodes the fresh Source17 current-cut comparison and signature bytes.
//!
//! ```text
//! body[504] = AOSSCU17 | version:u16be=1 | reserved[6]=0 |
//!             fixed signed fields | empty-generation-one/released flags[8]
//! packet[568] = body[504] | Ed25519-signature[64]
//! frame[576] = AOSSSP17 | packet[568]
//! signature = Ed25519(Source17-domain || complete-body[504])
//! ```
//!
//! Every field is comparison DATA. Source's actual consumer independently
//! proves Root identity, the exact Held suffix, full current empty project and
//! native posts. Root independently verifies its pinned signer and original
//! query, full coissuance/legacy-cut association and still-live invocation.

use super::{SourceCurrentQueryDataV1, SOURCE_CURRENT_REPLY_MAGIC_V1};
use super::super::{HistoryErrorV1, KeyV1, OwnerV1, PhaseV1, RecordEnvelopeV1, reader};
use super::super::super::protected_names::ProtectedJournalNamesV1;

/// Bounds the complete canonical signed Source17 body.
pub const SOURCE_CURRENT_BODY_BYTES_V1: usize = 504;
/// Bounds the complete Source17 body and signature.
pub const SOURCE_CURRENT_PACKET_BYTES_V1: usize = SOURCE_CURRENT_BODY_BYTES_V1 + 64;
/// Bounds the complete Source17 transport selector, body and signature.
pub const SOURCE_CURRENT_REPLY_FRAME_BYTES_V1: usize = 8 + SOURCE_CURRENT_PACKET_BYTES_V1;
/// Separates Source17 from every prior Source signing purpose.
pub const SOURCE_CURRENT_SIGNATURE_DOMAIN_V1: &[u8] =
    b"aos.sandbox.create-storage.source-current.signature.v1\0";

/// Describes an exact empty-generation-one, released-hold Source observation.
///
/// Public assembly grants no currentness, ownership, ancestry or admission.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SourceCurrentReplyFieldsV1 {
    /// The generation of the actual retained Source signing key.
    pub signer_generation: u64,
    /// The domain-separated digest of the entire exact query.
    pub query_digest: [u8; 32],
    /// The host boot identity from the fresh paired kernel sample.
    pub boot: [u8; 16],
    /// The fresh paired Unix wall-clock second.
    pub wall_seconds: i64,
    /// The fresh paired BOOTTIME nanoseconds before both original cutoffs.
    pub boottime_nanoseconds: u64,
    /// The actual independently observed Source directory, journal and lock.
    pub source_names: ProtectedJournalNamesV1,
    /// The exact current Source NEXT after the one Held pair suffix.
    pub source_next: u64,
    /// The exact complete current Source physical end.
    pub source_end: u64,
    /// The checksum of the exact currently materialized Source Held record.
    pub held_head: [u8; 32],
    /// The project whose whole current empty tree was replayed.
    pub project: [u8; 16],
    /// The accepted target sandbox, absent from the current empty tree.
    pub sandbox: [u8; 16],
    /// The exact CAS revision of the current ancestry Tree envelope.
    pub ancestry_record_revision: u64,
    /// The actual current logical Tree generation, exactly one for this purpose.
    pub tree_generation: u64,
    /// The commitment recomputed from the whole canonical current Tree.
    pub tree_commitment: [u8; 32],
    /// The exact current Tree envelope head.
    pub tree_head: [u8; 32],
    /// The exact independently replayed closed lineage envelope head.
    pub lineage_head: [u8; 32],
    /// The operation in the actual last released legacy Source hold.
    pub released_operation: [u8; 16],
    /// The sandbox in that same released legacy Source hold.
    pub released_sandbox: [u8; 16],
    /// The historical Controller-source commitment in that Source row.
    pub controller_source: [u8; 32],
    /// The Source hold ancestry, independently matched to the current Tree head.
    pub released_ancestry: [u8; 32],
    /// The legacy cut binding, distinct from the full coissuance commitment.
    pub cut_binding: [u8; 32],
    /// The actual monotone legacy Source hold epoch.
    pub released_epoch: u64,
    /// The digest of the whole actual released Source hold record.
    pub released_record_digest: [u8; 32],
}

impl SourceCurrentReplyFieldsV1 {
    /// Encodes the fixed body without allocating or issuing a live proof.
    ///
    /// # Errors
    /// Rejects empty identities, malformed names, a nonempty-generation state
    /// or internal mismatch among the declared project and released hold.
    pub fn encode_body(self) -> Result<[u8; SOURCE_CURRENT_BODY_BYTES_V1], HistoryErrorV1> {
        self.require_canonical()?;
        let mut bytes = [0; SOURCE_CURRENT_BODY_BYTES_V1];
        bytes[..8].copy_from_slice(b"AOSSCU17");
        bytes[8..10].copy_from_slice(&1_u16.to_be_bytes());
        bytes[16..24].copy_from_slice(&self.signer_generation.to_be_bytes());
        bytes[24..56].copy_from_slice(&self.query_digest);
        bytes[56..72].copy_from_slice(&self.boot);
        bytes[72..80].copy_from_slice(&self.wall_seconds.to_be_bytes());
        bytes[80..88].copy_from_slice(&self.boottime_nanoseconds.to_be_bytes());
        bytes[88..136].copy_from_slice(&self.source_names.to_bytes());
        bytes[136..144].copy_from_slice(&self.source_next.to_be_bytes());
        bytes[144..152].copy_from_slice(&self.source_end.to_be_bytes());
        bytes[152..184].copy_from_slice(&self.held_head);
        bytes[184..200].copy_from_slice(&self.project);
        bytes[200..216].copy_from_slice(&self.sandbox);
        bytes[216..224].copy_from_slice(&self.ancestry_record_revision.to_be_bytes());
        bytes[224..232].copy_from_slice(&self.tree_generation.to_be_bytes());
        bytes[232..264].copy_from_slice(&self.tree_commitment);
        bytes[264..296].copy_from_slice(&self.tree_head);
        bytes[296..328].copy_from_slice(&self.lineage_head);
        bytes[328..344].copy_from_slice(&self.released_operation);
        bytes[344..360].copy_from_slice(&self.released_sandbox);
        bytes[360..392].copy_from_slice(&self.controller_source);
        bytes[392..424].copy_from_slice(&self.released_ancestry);
        bytes[424..456].copy_from_slice(&self.cut_binding);
        bytes[456..464].copy_from_slice(&self.released_epoch.to_be_bytes());
        bytes[464..496].copy_from_slice(&self.released_record_digest);
        bytes[496..504].copy_from_slice(&[1, 1, 0, 0, 0, 0, 0, 0]);
        Ok(bytes)
    }

    /// Decodes exactly this purpose's fixed comparison body.
    ///
    /// # Errors
    /// Rejects wrong magic/version/extent, nonzero reserved bytes, unsupported
    /// state flags or malformed comparison fields.
    pub fn decode_body(bytes: &[u8]) -> Result<Self, HistoryErrorV1> {
        let mut input = reader(bytes);
        if input.array::<8>()? != *b"AOSSCU17" || input.array::<2>()? != 1_u16.to_be_bytes()
            || input.array::<6>()? != [0; 6] {
            return Err(HistoryErrorV1::Malformed);
        }
        let fields = Self {
            signer_generation: input.u64()?,
            query_digest: input.array()?,
            boot: input.array()?,
            wall_seconds: i64::from_be_bytes(input.array()?),
            boottime_nanoseconds: input.u64()?,
            source_names: ProtectedJournalNamesV1::from_bytes(input.bytes(48)?).map_err(|_| HistoryErrorV1::Malformed)?,
            source_next: input.u64()?,
            source_end: input.u64()?,
            held_head: input.array()?,
            project: input.array()?,
            sandbox: input.array()?,
            ancestry_record_revision: input.u64()?,
            tree_generation: input.u64()?,
            tree_commitment: input.array()?,
            tree_head: input.array()?,
            lineage_head: input.array()?,
            released_operation: input.array()?,
            released_sandbox: input.array()?,
            controller_source: input.array()?,
            released_ancestry: input.array()?,
            cut_binding: input.array()?,
            released_epoch: input.u64()?,
            released_record_digest: input.array()?,
        };
        if input.array::<8>()? != [1, 1, 0, 0, 0, 0, 0, 0] {
            return Err(HistoryErrorV1::Malformed);
        }
        input.finish()?;
        fields.require_canonical()?;
        Ok(fields)
    }

    /// Compares the entire original query and its exact claimed Source cut.
    ///
    /// This is allocation-free correlation only. Actual signature acceptance,
    /// fresh peer/native evidence and the full Intent/coissuance join remain
    /// with Root's genuine owning caller.
    ///
    /// # Errors
    /// Rejects a substituted query, signer generation, original boot/cutoff,
    /// operation/project/sandbox, physical names, Held head or exact NEXT/end.
    pub fn require_query(self, query: SourceCurrentQueryDataV1<'_>, signer_generation: u64)
        -> Result<(), HistoryErrorV1>
    {
        self.require_canonical()?;
        let root = query.root_body()?;
        let receipt = query.source_receipt()?;
        let source = receipt.body(root.open.lane)?;
        let record = RecordEnvelopeV1::decode(receipt.record,
            KeyV1::new(root.open.lane, OwnerV1::Source, 1)?, PhaseV1::new(OwnerV1::Source, 1)?)?;
        if self.signer_generation != signer_generation || self.query_digest != query.digest_v1()?
            || self.boot != root.boot || self.boot != source.boot
            || self.boottime_nanoseconds < root.started.max(source.started)
            || self.boottime_nanoseconds >= root.cutoff.min(source.cutoff)
            || self.source_names != receipt.source_names
            || self.source_next != receipt.source_after_next || self.source_end != receipt.source_after_end
            || self.held_head != record.checksum() || self.project != source.project
            || self.sandbox != source.sandbox || self.released_operation != source.operation {
            return Err(HistoryErrorV1::Correlation);
        }
        Ok(())
    }

    fn require_canonical(self) -> Result<(), HistoryErrorV1> {
        ProtectedJournalNamesV1::from_bytes(&self.source_names.to_bytes())
            .map_err(|_| HistoryErrorV1::Malformed)?;
        if self.signer_generation == 0 || self.boot == [0; 16] || self.wall_seconds < 0
            || self.source_next == 0 || self.source_end == 0 || self.ancestry_record_revision == 0
            || self.tree_generation != 1 || self.released_epoch == 0
            || self.project == [0; 16] || self.sandbox == [0; 16]
            || self.released_operation == [0; 16] || self.released_sandbox != self.sandbox
            || self.released_ancestry != self.tree_head {
            return Err(HistoryErrorV1::Malformed);
        }
        for digest in [self.query_digest, self.held_head, self.tree_commitment,
            self.tree_head, self.lineage_head, self.controller_source,
            self.released_ancestry, self.cut_binding, self.released_record_digest] {
            if digest == [0; 32] { return Err(HistoryErrorV1::Malformed); }
        }
        Ok(())
    }
}

/// Holds comparison fields and signature bytes without authenticating either.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SourceCurrentReplyDataV1 {
    /// The canonical Source-only current-cut claims.
    pub fields: SourceCurrentReplyFieldsV1,
    /// The Source signature, requiring Root's independently pinned key.
    pub signature: [u8; 64],
}

impl SourceCurrentReplyDataV1 {
    /// Encodes one complete fixed body/signature packet without allocating.
    ///
    /// # Errors
    /// Rejects malformed fields or an empty signature representation.
    pub fn encode(self) -> Result<[u8; SOURCE_CURRENT_PACKET_BYTES_V1], HistoryErrorV1> {
        let body = self.fields.encode_body()?;
        if self.signature == [0; 64] { return Err(HistoryErrorV1::Malformed); }
        let mut packet = [0; SOURCE_CURRENT_PACKET_BYTES_V1];
        packet[..SOURCE_CURRENT_BODY_BYTES_V1].copy_from_slice(&body);
        packet[SOURCE_CURRENT_BODY_BYTES_V1..].copy_from_slice(&self.signature);
        Ok(packet)
    }

    /// Decodes exact body/signature bytes without accepting the signature.
    ///
    /// # Errors
    /// Rejects nonexact extent, malformed fields or an empty signature.
    pub fn decode(packet: &[u8]) -> Result<Self, HistoryErrorV1> {
        if packet.len() != SOURCE_CURRENT_PACKET_BYTES_V1 { return Err(HistoryErrorV1::Extent); }
        let value = Self {
            fields: SourceCurrentReplyFieldsV1::decode_body(&packet[..SOURCE_CURRENT_BODY_BYTES_V1])?,
            signature: packet[SOURCE_CURRENT_BODY_BYTES_V1..].try_into().map_err(|_| HistoryErrorV1::Extent)?,
        };
        if value.signature == [0; 64] { return Err(HistoryErrorV1::Malformed); }
        Ok(value)
    }

    /// Encodes the corresponding exact selected transport response.
    ///
    /// # Errors
    /// Rejects the same malformed packet data as [`Self::encode`].
    pub fn encode_frame(self) -> Result<[u8; SOURCE_CURRENT_REPLY_FRAME_BYTES_V1], HistoryErrorV1> {
        let mut frame = [0; SOURCE_CURRENT_REPLY_FRAME_BYTES_V1];
        frame[..8].copy_from_slice(SOURCE_CURRENT_REPLY_MAGIC_V1);
        frame[8..].copy_from_slice(&self.encode()?);
        Ok(frame)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use super::super::super::{LatestHeadV1, RecordCoordinatesV1,
        source_held::{SOURCE_HELD_RECORD_BYTES_V1, SourceHeldBodyDataV1, SourceHeldReceiptDataV1}, transport::OpenQueryV1};
    use super::super::super::root_open::{ROOT_OPEN_BODY_BYTES_V1, RootOpenBodyDataV1};
    use super::super::super::{RECORD_OVERHEAD_BYTES, source_held::SOURCE_HELD_RECEIPT_BYTES_V1};
    const ROOT_RECORD_BYTES: usize = RECORD_OVERHEAD_BYTES + ROOT_OPEN_BODY_BYTES_V1;

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

    fn fields(query: SourceCurrentQueryDataV1<'_>) -> SourceCurrentReplyFieldsV1 {
        let root = query.root_body().unwrap();
        let receipt = query.source_receipt().unwrap();
        let source = receipt.body(root.open.lane).unwrap();
        let record = RecordEnvelopeV1::decode(receipt.record,
            KeyV1::new(root.open.lane, OwnerV1::Source, 1).unwrap(),
            PhaseV1::new(OwnerV1::Source, 1).unwrap()).unwrap();
        SourceCurrentReplyFieldsV1 {
            signer_generation: 3, query_digest: query.digest_v1().unwrap(),
            boot: root.boot, wall_seconds: 500, boottime_nanoseconds: 150,
            source_names: receipt.source_names, source_next: receipt.source_after_next,
            source_end: receipt.source_after_end, held_head: record.checksum(),
            project: source.project, sandbox: source.sandbox, ancestry_record_revision: 1,
            tree_generation: 1, tree_commitment: [20; 32], tree_head: [21; 32],
            lineage_head: [22; 32], released_operation: source.operation,
            released_sandbox: source.sandbox, controller_source: [23; 32],
            released_ancestry: [21; 32], cut_binding: [24; 32], released_epoch: 2,
            released_record_digest: [25; 32],
        }
    }

    #[test]
    fn exact_reply_roundtrip_binds_original_query_and_both_unrenewed_cutoffs() {
        let (root, source) = records(19, 8, 180);
        let query = SourceCurrentQueryDataV1::from_records(&root, &source).unwrap();
        let fields = fields(query);
        let reply = SourceCurrentReplyDataV1 { fields, signature: [26; 64] };
        let packet = reply.encode().unwrap();
        let frame = reply.encode_frame().unwrap();

        assert_eq!(frame.len(), 576);
        assert_eq!(&frame[..8], b"AOSSSP17");
        assert_eq!(&frame[8..], &packet);
        assert_eq!(SourceCurrentReplyDataV1::decode(&packet).unwrap(), reply);
        fields.require_query(query, 3).unwrap();
        let (other_root, _) = records(20, 8, 180);
        let other = SourceCurrentQueryDataV1::from_records(&other_root, &source).unwrap();
        assert!(fields.require_query(other, 3).is_err());
        assert!(fields.require_query(query, 4).is_err());
        assert!(SourceCurrentReplyFieldsV1 { boottime_nanoseconds: 180, ..fields }.require_query(query, 3).is_err());
        assert!(SourceCurrentReplyFieldsV1 { boottime_nanoseconds: 200, ..fields }.require_query(query, 3).is_err());
        assert!(SourceCurrentReplyFieldsV1 { source_end: fields.source_end + 1, ..fields }.require_query(query, 3).is_err());
        assert!(SourceCurrentReplyFieldsV1 { source_next: fields.source_next + 1, ..fields }.require_query(query, 3).is_err());
    }

    #[test]
    fn codec_refuses_nonexact_extent_reserved_flags_and_false_tree_state() {
        let (root, source) = records(19, 8, 300);
        let query = SourceCurrentQueryDataV1::from_records(&root, &source).unwrap();
        let reply = SourceCurrentReplyDataV1 { fields: fields(query), signature: [27; 64] };
        let packet = reply.encode().unwrap();
        for width in 0..packet.len() { assert!(SourceCurrentReplyDataV1::decode(&packet[..width]).is_err()); }
        assert!(SourceCurrentReplyDataV1::decode(&[packet.as_slice(), &[0]].concat()).is_err());
        let mut bad = packet;
        bad[496] = 0;
        assert!(SourceCurrentReplyDataV1::decode(&bad).is_err());
        let mut bad = packet;
        bad[10] = 1;
        assert!(SourceCurrentReplyDataV1::decode(&bad).is_err());
        assert!(SourceCurrentReplyFieldsV1 { tree_generation: 2, ..reply.fields }.encode_body().is_err());
        assert!(SourceCurrentReplyFieldsV1 { released_ancestry: [28; 32], ..reply.fields }.encode_body().is_err());
    }
}
