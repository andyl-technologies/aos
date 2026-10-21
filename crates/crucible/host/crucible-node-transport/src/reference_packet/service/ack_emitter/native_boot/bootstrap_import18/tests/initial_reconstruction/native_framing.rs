//! Tests bounded nonowning native framing under actual bootstrap/input custody.
//!
//! The structured role fixtures establish framing only. Their inert model and
//! lineage objects cannot produce a sealed native graph, recipe or installation.

use super::*;
use crate::bodies::{BlobBeginRequest, BlobChunkRequest, BlobFinishRequest};
use crate::protocol_snapshot::{
    compact_bytes::BorrowedCompactBytes,
    restored_settled17::{
        NativeCold17Admission, NativeCold17ConstructionData, NativeCold17PrewalkData,
        NativeCold17Work, restored_settled_native17_counter_scratch_data,
    },
};
use crate::reference_packet::service::complete_restore::import18::{
    PacketNativeImport18SemanticSpendFamily, native_import18_reference_identity_data,
};
use crucible_node_format::{ContentRef, Extensions, U64};
use std::cell::Cell;

fn roles(case: &str) -> [(ContentRef, Vec<u8>); 7] {
    fn body(bytes: Vec<u8>) -> (ContentRef, Vec<u8>) {
        (
            canonical::content_ref(&bytes, "application/json").unwrap(),
            bytes,
        )
    }
    let before = body(br#"{"framing":"before"}"#.to_vec());
    let control = body(br#"{"framing":"control"}"#.to_vec());
    let after = body(br#"{"framing":"after"}"#.to_vec());
    let anchor = body(br#"{"framing":"anchor"}"#.to_vec());
    let mut snapshot = json!({
        "capture": {}, "capture_request": {},
        "control": canonical::parse_json(&control.1, usize::MAX).unwrap(),
        "control_reference": control.0,
        "protocol": ["source-private.native-before-protocol/17", before.0,
            before.1.capacity(), BorrowedCompactBytes::new(&before.1)],
        "schema": "source-owned.packet-native-continuation/17",
    });
    if case == "initial_framing_snapshot" {
        snapshot["schema"] = json!("source-owned.packet-native-continuation/18");
    }
    let snapshot = body(canonical::canonical_json(&snapshot).unwrap());
    let mut journal = json!({
        "ancestry": {}, "capture_request": {}, "capture_terminal": {},
        "confirmation_request": {}, "confirmation_terminal": {}, "history_cut": {},
        "objects": {"snapshot": snapshot.0, "before": before.0, "control": control.0,
            "anchor": anchor.0, "after": after.0, "host_protocol": after.0,
            "semantic": after.0, "runtime_object": after.0, "coordinator_checkpoint": after.0},
        "schema": "source-private.source-restored-settled-journal/17",
    });
    if case == "initial_framing_journal" {
        journal["objects"].as_object_mut().unwrap().remove("anchor");
    }
    if case == "initial_framing_before" {
        journal["objects"]["before"] = json!(after.0);
    }
    let journal = body(canonical::canonical_json(&journal).unwrap());
    let control = if case == "initial_framing_control" {
        body(br#"{"framing":"changed"}"#.to_vec())
    } else {
        control
    };
    let semantic = b"semantic-spend DATA".to_vec();
    let semantic_ref = canonical::content_ref(
        &semantic,
        PacketNativeImport18SemanticSpendFamily::Complete18.media_type_data(),
    )
    .unwrap();
    [
        after,
        control,
        anchor,
        snapshot,
        journal,
        body(b"normalization DATA".to_vec()),
        (semantic_ref, semantic),
    ]
}

pub(super) fn commit_recipe(case: &str, recipe: &mut Value) {
    let roles = roles(case);
    let [after, control, anchor, snapshot, journal, _, semantic] = roles.each_ref();
    let archive = [snapshot, after, control, anchor, journal];
    recipe["archived_reference_identities"] = json!(
        archive.map(|(reference, _)| native_import18_reference_identity_data(reference).unwrap())
    );
    recipe["archived_lengths"] = json!(archive.map(|(reference, _)| reference.length));
    recipe["semantic_reference_identity"] =
        json!(native_import18_reference_identity_data(&semantic.0).unwrap());
    recipe["semantic_length"] = json!(semantic.0.length);
    recipe["semantic_spend_maximum"] = json!(semantic.0.length);
    for (index, (reference, _)) in archive.into_iter().enumerate() {
        recipe["decoder_limits"][index] = json!(reference.length);
    }
    if case == "initial_framing_family" {
        recipe["native_family"] = json!("snapshot18");
    }
}

fn fill(owner: &mut OriginalImport18RawBootstrap, roles: &[(ContentRef, Vec<u8>); 7]) {
    owner
        .inputs
        .reserve_data(
            roles.each_ref().map(|(reference, _)| reference),
            roles.each_ref().map(|(_, body)| body.len()),
            usize::MAX,
        )
        .unwrap();
    for (index, (reference, bytes)) in roles.iter().enumerate() {
        let transfer_id = Id::new(format!("framed-{index}")).unwrap();
        owner
            .inputs
            .begin_data(&BlobBeginRequest {
                transfer_id: transfer_id.clone(),
                content: reference.clone(),
                extensions: Extensions::new(),
            })
            .unwrap();
        for (chunk_index, bytes) in bytes.chunks(4096).enumerate() {
            owner
                .inputs
                .chunk_data(&BlobChunkRequest {
                    transfer_id: transfer_id.clone(),
                    offset: U64::new((chunk_index * 4096) as u64),
                    bytes: Bytes::new(bytes.to_vec()),
                    extensions: Extensions::new(),
                })
                .unwrap();
        }
        owner
            .inputs
            .finish_data(&BlobFinishRequest {
                transfer_id,
                extensions: Extensions::new(),
            })
            .unwrap();
    }
}

struct Admission {
    calls: Cell<usize>,
    stop: usize,
    scratch: usize,
}

impl Admission {
    fn step(&self, scratch: usize) -> Result<(), ProviderError> {
        let call = self.calls.get() + 1;
        self.calls.set(call);
        if call == self.stop || scratch > self.scratch {
            return Err(ProviderError::ResourceExhausted(
                "actual native framing admission",
            ));
        }
        Ok(())
    }
}

impl NativeCold17Admission for Admission {
    fn begin_data(&self, row: NativeCold17PrewalkData) -> Result<(), ProviderError> {
        assert_eq!(row.work_data(), NativeCold17Work::Framing);
        assert_eq!(row.prior_native_cache_retained_bytes_data(), 0);
        assert_eq!(row.quote_transient_bytes_data(), 0);
        self.step(row.counter_scratch_bytes_data())
    }

    fn construct_data(&self, row: NativeCold17ConstructionData) -> Result<(), ProviderError> {
        assert_eq!(row.work_data(), NativeCold17Work::Framing);
        assert_eq!(row.maximum_new_retained_bytes_data(), 0);
        assert_eq!(row.constructor_transient_bytes_data(), 0);
        self.step(row.counter_scratch_bytes_data())
    }

    fn finish_data(&self, work: NativeCold17Work, retained: usize) -> Result<(), ProviderError> {
        assert_eq!(work, NativeCold17Work::Framing);
        assert_eq!(retained, 0);
        self.step(0)
    }
}

pub(super) fn assert_child(case: &str, owner: &mut OriginalImport18RawBootstrap) {
    fill(owner, &roles(case));
    let retained = owner.retained_requested_bytes().unwrap();
    let admission = Admission {
        calls: Cell::new(0),
        stop: match case {
            "initial_framing_stop_begin" => 1,
            "initial_framing_stop_construct" => 2,
            "initial_framing_stop_finish" => 3,
            _ => 0,
        },
        scratch: restored_settled_native17_counter_scratch_data()
            - usize::from(case == "initial_framing_short_scratch"),
    };
    let mut inspected = false;
    let outcome = owner.with_native17_framing_data(&admission, |_| {
        inspected = true;
        Ok(())
    });
    assert_eq!(outcome.is_ok(), case == "initial_framing_complete");
    assert_eq!(inspected, case == "initial_framing_complete");
    assert_eq!(
        admission.calls.get(),
        match case {
            "initial_framing_family" => 0,
            "initial_framing_stop_begin" | "initial_framing_short_scratch" => 1,
            "initial_framing_complete" | "initial_framing_stop_finish" => 3,
            _ => 2,
        }
    );
    assert_eq!(owner.retained_requested_bytes().unwrap(), retained);
    assert!(owner.inputs.bodies_data().is_ok());
}

#[test]
fn native_role_framing_uses_actual_banks_and_each_original_admission_boundary() {
    for case in [
        "initial_framing_complete",
        "initial_framing_control",
        "initial_framing_before",
        "initial_framing_journal",
        "initial_framing_snapshot",
        "initial_framing_family",
        "initial_framing_stop_begin",
        "initial_framing_stop_construct",
        "initial_framing_stop_finish",
        "initial_framing_short_scratch",
    ] {
        flight(case);
    }
}
