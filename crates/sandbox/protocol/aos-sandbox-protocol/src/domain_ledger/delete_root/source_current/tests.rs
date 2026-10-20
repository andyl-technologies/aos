//! Exercises exact Delete-purpose framing and native/query associations.

use super::*;

fn query() -> SourceDeleteCurrentQueryDataV1 {
    SourceDeleteCurrentQueryDataV1 {
        nonce: [1; 16],
        project: [2; 16],
        operation: [3; 16],
        batch: [4; 32],
        boot: [5; 16],
        started: 100,
        cutoff: 1_000,
    }
}

fn fields() -> SourceDeleteCurrentReplyFieldsV1 {
    let query = query();
    SourceDeleteCurrentReplyFieldsV1 {
        generation: 7,
        query: query.digest_v1().unwrap(),
        boot: query.boot,
        wall_seconds: 1_700_000_000,
        boottime_nanoseconds: 200,
        names: ProtectedJournalNamesV1::from_historical_fields((1, 2), (3, 4), (5, 6)),
        next: 5,
        end: 512,
        pending_native: super::super::super::delete_batch::encode_native_commit_data_v1(
            query.operation, 4, 512, &[9; 32],
        ).unwrap(),
        batch: query.batch,
        project: query.project,
        operation: query.operation,
        tree_generation: 2,
        tree_commitment: [10; 32],
        tree_head: [11; 32],
        lineage_head: [12; 32],
    }
}

#[test]
fn query_requires_exact_extent_version_reserved_bytes_and_original_horizon() {
    let original = query();
    let encoded = original.encode().unwrap();
    assert_eq!(SourceDeleteCurrentQueryDataV1::decode(&encoded).unwrap(), original);
    for length in 0..encoded.len() {
        assert!(SourceDeleteCurrentQueryDataV1::decode(&encoded[..length]).is_err());
    }
    let mut extended = encoded.to_vec();
    extended.push(0);
    assert!(SourceDeleteCurrentQueryDataV1::decode(&extended).is_err());
    for index in [8, 9, 10, 15] {
        let mut changed = encoded;
        changed[index] ^= 1;
        assert!(SourceDeleteCurrentQueryDataV1::decode(&changed).is_err());
    }

    let mut changed = original;
    changed.cutoff = changed.started + SOURCE_DELETE_CURRENT_MAXIMUM_DURATION_NANOSECONDS_V1;
    assert!(changed.encode().is_ok());
    changed.cutoff += 1;
    assert_eq!(changed.encode().unwrap_err(), SourceDeleteCurrentDataErrorV1::Clock);
    changed.cutoff = changed.started;
    assert_eq!(changed.encode().unwrap_err(), SourceDeleteCurrentDataErrorV1::Clock);
}

#[test]
fn reply_binds_query_generation_and_clamped_original_cutoff() {
    let original = query();
    let reply = fields();
    assert!(reply.require_query(original, 7).is_ok());

    let mut different = original;
    different.nonce[0] ^= 1;
    assert_eq!(reply.require_query(different, 7).unwrap_err(), SourceDeleteCurrentDataErrorV1::Association);
    assert_eq!(reply.require_query(original, 8).unwrap_err(), SourceDeleteCurrentDataErrorV1::Association);

    let mut expired = reply;
    expired.boottime_nanoseconds = original.cutoff;
    assert_eq!(expired.require_query(original, 7).unwrap_err(), SourceDeleteCurrentDataErrorV1::Clock);
    expired.boottime_nanoseconds = original.started - 1;
    assert_eq!(expired.require_query(original, 7).unwrap_err(), SourceDeleteCurrentDataErrorV1::Clock);
    expired = reply;
    expired.boot[0] ^= 1;
    assert_eq!(expired.require_query(original, 7).unwrap_err(), SourceDeleteCurrentDataErrorV1::Clock);
}

#[test]
fn reply_requires_exact_native_last_commit_and_nonzero_structural_heads() {
    let original = fields();
    let encoded = original.encode_body().unwrap();
    assert_eq!(SourceDeleteCurrentReplyFieldsV1::decode_body(&encoded).unwrap(), original);

    for offset in [152, 200, 208] {
        let mut changed = encoded;
        changed[offset] ^= 1;
        assert_eq!(SourceDeleteCurrentReplyFieldsV1::decode_body(&changed).unwrap_err(), SourceDeleteCurrentDataErrorV1::Native);
    }
    let mut changed = original;
    changed.next += 1;
    assert_eq!(changed.encode_body().unwrap_err(), SourceDeleteCurrentDataErrorV1::Native);
    changed = original;
    changed.tree_head = [0; 32];
    assert_eq!(changed.encode_body().unwrap_err(), SourceDeleteCurrentDataErrorV1::Tree);
}

#[test]
fn signed_packet_is_only_exact_data_and_never_a_signature_verifier() {
    let packet = SourceDeleteCurrentReplyDataV1 { fields: fields(), signature: [13; 64] };
    let encoded = packet.encode().unwrap();
    assert_eq!(encoded.len(), SOURCE_DELETE_CURRENT_PACKET_BYTES_V1);
    assert_eq!(SourceDeleteCurrentReplyDataV1::decode(&encoded).unwrap(), packet);
    assert_eq!(SOURCE_DELETE_CURRENT_REPLY_MAGIC_V1.len() + encoded.len(), SOURCE_DELETE_CURRENT_REPLY_BYTES_V1);

    for length in 0..encoded.len() {
        assert!(SourceDeleteCurrentReplyDataV1::decode(&encoded[..length]).is_err());
    }
    let mut no_signature = encoded;
    no_signature[SOURCE_DELETE_CURRENT_BODY_BYTES_V1..].fill(0);
    assert_eq!(SourceDeleteCurrentReplyDataV1::decode(&no_signature).unwrap_err(), SourceDeleteCurrentDataErrorV1::Format);
}

#[test]
fn planned_query_bytes_remain_exact_and_committed_purpose_never_adopts_them() {
    let original = query();
    let planned = original.encode().unwrap();
    let purpose = SourceDeleteCurrentPurposeDataV3::ControllerCommitted;
    let committed = original.encode_for_purpose_v3(purpose).unwrap();

    assert_eq!(<[u8; 32]>::from(Sha256::digest(planned)), [61, 231, 131, 210, 227, 79, 116, 136, 68, 107, 10, 161, 171, 124, 75, 56, 46, 133, 220, 122, 129, 126, 250, 83, 123, 207, 189, 101, 226, 209, 212, 37]);
    assert_eq!(planned, original.encode_for_purpose_v3(SourceDeleteCurrentPurposeDataV3::Planned).unwrap());
    assert_eq!(SourceDeleteCurrentQueryDataV1::decode_for_purpose_v3(&committed, purpose).unwrap(), original);
    assert!(SourceDeleteCurrentQueryDataV1::decode(&committed).is_err());
    assert!(SourceDeleteCurrentQueryDataV1::decode_for_purpose_v3(&planned, purpose).is_err());
    assert_ne!(original.digest_v1().unwrap(), original.digest_for_purpose_v3(purpose).unwrap());
    assert_ne!(purpose.signature_domain_v3(), SOURCE_DELETE_CURRENT_SIGNATURE_DOMAIN_V1);

    for index in [8, 9, 10, 15] {
        let mut changed = committed;
        changed[index] ^= 1;
        assert!(SourceDeleteCurrentQueryDataV1::decode_for_purpose_v3(&changed, purpose).is_err());
    }
}

#[test]
fn committed_reply_shape_uses_actual_source_transaction_and_separate_domain() {
    let purpose = SourceDeleteCurrentPurposeDataV3::ControllerCommitted;
    let mut observed = fields();
    observed.pending_native[0] ^= 1;
    observed.query = query().digest_for_purpose_v3(purpose).unwrap();
    let encoded = observed.encode_body_for_purpose_v3(purpose).unwrap();

    assert_eq!(SourceDeleteCurrentReplyFieldsV1::decode_body_for_purpose_v3(&encoded, purpose).unwrap(), observed);
    assert!(SourceDeleteCurrentReplyFieldsV1::decode_body(&encoded).is_err());
    assert!(observed.encode_body().is_err());
    observed.require_query_for_purpose_v3(query(), 7, purpose).unwrap();
    let mut different = query();
    different.batch[0] ^= 1;
    assert!(observed.require_query_for_purpose_v3(different, 7, purpose).is_err());

    observed.next += 1;
    assert_eq!(observed.encode_body_for_purpose_v3(purpose).unwrap_err(), SourceDeleteCurrentDataErrorV1::Native);
}
