//! Exercises only closed DATA, fixed codecs and non-authoritative ledgers.

use super::super::{
    PacketNativeInvocationPreambleData, PacketNativeInvocationPurposeData,
    authenticate_original_native_invocation_preamble_data,
    decode_original_native_invocation_preamble_data,
    encode_original_native_invocation_preamble_data,
};
use super::*;
use crucible_node_format::canonical;
use serde_json::json;
use std::io::Write;

fn row(retained: u64, transient: u64, scratch: u64) -> PacketNativeStartupAllocationRow {
    PacketNativeStartupAllocationRow {
        retained_requested_bytes: U64::new(retained),
        maximum_simultaneous_transient_bytes: U64::new(transient),
        declared_counter_scratch_bytes: U64::new(scratch),
    }
}

fn reservation() -> PacketRestoredSuffixReservationData {
    PacketRestoredSuffixReservationData {
        maximum_originals: U64::new(2),
        ingress: row(10, 20, 30),
        actions: row(40, 50, 60),
    }
}

fn preamble() -> PacketNativeSuffixPreambleData {
    PacketNativeSuffixPreambleData {
        invocation: PacketNativeInvocationPreambleData {
            controller_pid: 7,
            controller_uid: 8,
            launch_bytes: 200,
            maximum_boot_bytes: 300,
            birth_id: [1; 32],
            launch_digest: [2; 32],
            source_digest: [3; 32],
            registration_digest: [4; 32],
            private_launch_digest: [5; 32],
            private_bootstrap: row(100, 200, 300),
            native_birth: row(400, 500, 600),
            restore_prepare: Some(row(700, 800, 900)),
        },
        suffix_reservation: reservation(),
    }
}

#[test]
fn the_new_private_prefix_binds_every_separate_axis_and_refuses_legacy_decoders() {
    let key = [11; 32];
    let original = preamble();
    let bytes = encode_original_native_suffix_preamble_data(&original, &key).unwrap();
    assert!(decode_original_native_suffix_preamble_data(&bytes).unwrap() == original);
    authenticate_original_native_suffix_preamble_data(&bytes, &key).unwrap();
    assert!(decode_original_native_invocation_preamble_data(&bytes).is_err());
    assert!(authenticate_original_native_invocation_preamble_data(&bytes, &key).is_err());

    let old = encode_original_native_invocation_preamble_data(&original.invocation, &key).unwrap();
    assert!(decode_original_native_suffix_preamble_data(&old).is_err());
    assert!(authenticate_original_native_suffix_preamble_data(&old, &key).is_err());
    for offset in [272, 280, 288, 296, 304, 312, 320] {
        let mut changed = bytes;
        changed[offset + 7] ^= 1;
        assert!(authenticate_original_native_suffix_preamble_data(&changed, &key).is_err());
    }
    assert!(authenticate_original_native_suffix_preamble_data(&bytes, &[12; 32]).is_err());
    let mut changed = bytes;
    changed[72] ^= 1;
    assert!(authenticate_original_native_suffix_preamble_data(&changed, &key).is_err());
}

#[test]
fn reservation_comparison_keeps_both_complete_rows_and_refuses_equal_total_substitution() {
    let exact = reservation();
    assert_eq!(exact.requested_bytes_data().unwrap(), 210);
    exact.authenticate_actual_data(&exact).unwrap();

    let mut changed = exact;
    changed.ingress = row(11, 19, 30);
    assert_eq!(changed.requested_bytes_data().unwrap(), 210);
    assert!(exact.authenticate_actual_data(&changed).is_err());
    let mut changed = exact;
    changed.actions = row(40, 51, 59);
    assert!(exact.authenticate_actual_data(&changed).is_err());
    let mut changed = exact;
    changed.maximum_originals = U64::new(1);
    assert!(exact.authenticate_actual_data(&changed).is_err());
    for count in [0, 257] {
        let mut changed = exact;
        changed.maximum_originals = U64::new(count);
        assert!(changed.requested_bytes_data().is_err());
    }
    let mut changed = exact;
    changed.actions.retained_requested_bytes = U64::new(u64::MAX);
    assert!(changed.requested_bytes_data().is_err());
}

fn purpose() -> PacketNativeInvocationPurposeData {
    // These full references and labels are inert DATA for writer boundaries;
    // no Source member, ticket, native bootstrap or live scope is constructed.
    let value = json!({
        "schema":"source-owned.packet-native-invocation-purpose/1",
        "purpose":"restoration_target",
        "source": {
            "runtime":canonical::content_ref(b"runtime", "application/runtime;note=\"quoted\"").unwrap(),
            "native_state":canonical::content_ref(b"native", "application/native;note=\\path").unwrap(),
            "owner":"owner"
        },
        "target": {
            "admission":"admission", "binding":canonical::hash("cnp.node-binding.v1", b"binding").unwrap(),
            "incarnation":"incarnation", "node":"node", "owner":"owner",
            "owner_generation":"2", "prepared_token":"prepared", "session":"session",
            "world":canonical::hash("cnp.world-binding.v1", b"world").unwrap()
        }
    });
    PacketNativeInvocationPurposeData::from_original_value_data(&value).unwrap()
}

#[test]
fn the_streamed_wrapper_matches_canonical_full_fields_and_the_exact_same_raw_child() {
    let purpose = purpose();
    let reservation = reservation();
    let child = json!({"schema_version":5,"escaped":"quote\" and slash\\"});
    let child_bytes = canonical::canonical_json(&child).unwrap();
    let mut actual = Vec::new();
    write_original_native_suffix_launch_data(&purpose, &child_bytes, &reservation, &mut actual)
        .unwrap();
    let expected = canonical::canonical_json(&json!({
        "schema_version":7, "invocation":purpose, "launch":child,
        "suffix_reservation":reservation
    }))
    .unwrap();
    assert_eq!(actual, expected);
    assert!(
        actual
            .windows(child_bytes.len())
            .any(|bytes| bytes == child_bytes)
    );
    let identity =
        original_native_suffix_launch_identity_data(&purpose, &child_bytes, &reservation).unwrap();
    assert_eq!(identity.encoded_bytes, actual.len());
    assert_eq!(identity.raw_digest, *blake3::hash(&actual).as_bytes());

    let mut changed = reservation;
    changed.actions.retained_requested_bytes = U64::new(41);
    assert_ne!(
        original_native_suffix_launch_identity_data(&purpose, &child_bytes, &changed)
            .unwrap()
            .raw_digest,
        identity.raw_digest
    );
}

struct RefusingWriter {
    bytes: Vec<u8>,
    maximum: usize,
}

impl Write for RefusingWriter {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        let count = bytes
            .len()
            .min(self.maximum.saturating_sub(self.bytes.len()));
        if count == 0 {
            return Err(std::io::Error::from(std::io::ErrorKind::WriteZero));
        }
        self.bytes.extend_from_slice(&bytes[..count]);
        Ok(count)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

#[test]
fn a_short_actual_writer_keeps_the_exact_canonical_partial_in_its_original_bank() {
    let purpose = purpose();
    let reservation = reservation();
    let child = b"{\"schema_version\":5}";
    let mut complete = Vec::new();
    write_original_native_suffix_launch_data(&purpose, child, &reservation, &mut complete).unwrap();
    let mut short = RefusingWriter {
        bytes: Vec::new(),
        maximum: complete.len() - 1,
    };
    assert!(
        write_original_native_suffix_launch_data(&purpose, child, &reservation, &mut short)
            .is_err()
    );
    assert_eq!(short.bytes, complete[..complete.len() - 1]);
}

#[test]
fn the_full_suffix_definition_comparison_refuses_each_changed_reference_field() {
    let original = restoration_suffix_schema().unwrap();
    authenticate_restoration_suffix_schema_data(&original).unwrap();
    for field in 0..8 {
        let mut changed = original.clone();
        match field {
            0 => changed.version += 1,
            1 => changed.id = crucible_node_format::Id::new("foreign-suffix").unwrap(),
            2 => changed.definition.hash.algorithm = "other".into(),
            3 => changed.definition.hash.domain = "other".into(),
            4 => changed.definition.hash.digest = "0".repeat(64),
            5 => changed.definition.length = U64::new(changed.definition.length.get() + 1),
            6 => changed.definition.media_type = "text/plain".into(),
            _ => {
                changed
                    .extensions
                    .insert("unknown".into(), serde_json::Value::Null);
            }
        }
        assert!(authenticate_restoration_suffix_schema_data(&changed).is_err());
    }
}

#[test]
fn carrier_quote_keeps_reservation_credit_separate_and_refuses_one_short() {
    let purpose = purpose();
    // This is an inert canonical writer child, not an admitted launch fixture.
    let child = b"{\"schema_version\":5}";
    let admitted = reservation();
    let full =
        original_native_suffix_construction_storage_data(&purpose, child, &admitted, usize::MAX)
            .unwrap();
    let maximum = [
        full.native_retained_requested_bytes(),
        full.native_transient_requested_bytes(),
        full.private_retained_requested_bytes(),
        full.private_transient_requested_bytes(),
        full.source_finalization_requested_bytes(),
        full.wire_growth_requested_bytes(),
    ]
    .into_iter()
    .max()
    .unwrap();

    let exact =
        original_native_suffix_construction_storage_data(&purpose, child, &admitted, maximum)
            .unwrap();
    assert_eq!(exact.launch_identity_data(), full.launch_identity_data());
    assert!(
        original_native_suffix_construction_storage_data(&purpose, child, &admitted, maximum - 1,)
            .is_err()
    );
    assert!(full.native_retained_requested_bytes() > 0);
    assert!(full.private_retained_requested_bytes() > 0);
    assert!(full.source_finalization_requested_bytes() > 0);
    assert_eq!(admitted.requested_bytes_data().unwrap(), 210);
}
