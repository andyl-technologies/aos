//! Exercises admitted normalization decoding from the actual original input bank.
//!
//! These inert fixtures establish DATA decoding and correspondence only. They
//! construct no signed Prepare, opaque recipe, native model or fresh authority.

use super::super::super::normalization::OriginalImport18NormalizationAdmission;
use super::*;
use crate::bodies::{BlobBeginRequest, BlobChunkRequest, BlobFinishRequest};
use crate::reference_packet::service::complete_restore::import18::{
    OriginalImport18NormalizationAttempt, PacketNativeImport18SemanticSpendFamily,
    PacketNativeImport18SourceFamily, native_import18_reference_identity_data,
};
use crucible_node_format::{ContentRef, Extensions, U64};
use std::cell::Cell;

fn base_bodies() -> [Vec<u8>; 7] {
    [
        "after", "control", "anchor", "snapshot", "journal", "", "spend",
    ]
    .map(|body| body.as_bytes().to_vec())
}

fn references(bodies: &[Vec<u8>; 7]) -> [ContentRef; 7] {
    std::array::from_fn(|index| {
        canonical::content_ref(
            &bodies[index],
            if index == 6 {
                PacketNativeImport18SemanticSpendFamily::Complete18.media_type_data()
            } else {
                "application/json"
            },
        )
        .unwrap()
    })
}

pub(super) fn normalization(case: &str) -> Value {
    let bodies = base_bodies();
    let refs = references(&bodies);
    let [after, control, anchor, snapshot, journal, _, semantic] = refs.each_ref();
    let reference = canonical::content_ref(b"{}", "application/json").unwrap();
    let source = canonical::content_ref(
        b"{}",
        PacketNativeImport18SourceFamily::Captured17.media_type_data(),
    )
    .unwrap();
    let binding = canonical::hash("cnp.world-binding.v1", b"inert normalization").unwrap();
    let mut value = json!({
        "schema": "source-private.native-import-normalization/18",
        "archive_index": reference, "capture_manifest": reference,
        "source_runtime": reference, "native_family": "snapshot17",
        "native_snapshot": snapshot, "native_after": after,
        "native_control": control, "native_anchor": anchor,
        "native_journal": journal, "native_before": reference,
        "controller17": reference, "source_family": "captured17",
        "source17": source, "node25": reference,
        "backend_implementation": reference, "backend_profile": "inert-profile",
        "backend_schema": {"id":"inert-backend", "version":1, "definition":reference, "extensions":{}},
        "archived_cut": {"time_ps":"0", "microstep":"0", "phase":0},
        "archived_ordinal": "1", "host_registration": {"actual":"host DATA"},
        "target_world": binding, "target_owner": "inert-owner",
        "target_owner_binding": binding, "target_activation": "inert-activation",
        "target_generation": "1", "target_owner_generation": "1",
        "transaction_id": "inert-transaction", "commit_request_id": "inert-commit",
        "lease_generation": "1",
        "nonce": Bytes::new(native_import18_mapping_nonce_data(&[23; 32]).to_vec()),
        "limits": {
            "role_maximums": [snapshot.length, after.length, control.length, anchor.length, journal.length],
            "immutable_objects":"32", "immutable_bytes":"4096", "immutable_depth":"4",
            "maximum_nodes":"4096", "maximum_requested_bytes":"268435456",
            "maximum_target_requested_bytes":"16777216", "maximum_before_bytes":"16777216"
        },
        "semantic_spend_family":"complete18", "semantic_spend":semantic,
        "semantic_spend_maximum": semantic.length
    });
    if let Some(axis) = case.strip_prefix("initial_normalization_limit_") {
        let axis: usize = axis.parse().unwrap();
        if axis < 5 {
            let current: u64 = value["limits"]["role_maximums"][axis]
                .as_str()
                .unwrap()
                .parse()
                .unwrap();
            value["limits"]["role_maximums"][axis] = json!((current + 1).to_string());
        } else {
            let field = [
                "immutable_objects",
                "immutable_bytes",
                "immutable_depth",
                "maximum_nodes",
                "maximum_requested_bytes",
                "maximum_target_requested_bytes",
                "maximum_before_bytes",
            ][axis - 5];
            let current: u64 = value["limits"][field].as_str().unwrap().parse().unwrap();
            value["limits"][field] = json!((current + 1).to_string());
        }
    }
    match case {
        "initial_normalization_nonce" => value["nonce"] = json!(Bytes::new(vec![1; 32])),
        "initial_normalization_generation" => value["lease_generation"] = json!("2"),
        "initial_normalization_host" => value["host_registration"] = json!({"actual":"other DATA"}),
        "initial_normalization_reader" => value["limits"]["immutable_objects"] = json!("33"),
        "initial_normalization_target" => {
            value["limits"]["maximum_target_requested_bytes"] = json!("16777215")
        }
        "initial_normalization_before" => {
            value["limits"]["maximum_before_bytes"] = json!("16777215")
        }
        "initial_normalization_role" => value["native_after"] = value["native_control"].clone(),
        "initial_normalization_semantic" => {
            value["semantic_spend"]["hash"]["digest"] = json!("a".repeat(64))
        }
        "initial_normalization_missing" => {
            value.as_object_mut().unwrap().remove("transaction_id");
        }
        "initial_normalization_extra" => value["unselected_field"] = json!(true),
        "initial_normalization_native_family" => value["native_family"] = json!("snapshot18"),
        "initial_normalization_source_family" => {
            value["source_family"] = json!("captured18");
            value["source17"]["media_type"] =
                json!(PacketNativeImport18SourceFamily::Captured18.media_type_data());
        }
        "initial_normalization_semantic_family" => {
            value["semantic_spend_family"] = json!("legacy17");
            value["semantic_spend"]["media_type"] =
                json!(PacketNativeImport18SemanticSpendFamily::Legacy17.media_type_data());
        }
        "initial_normalization_oversized" => value["host_registration"] = json!("x".repeat(65_536)),
        _ => {}
    }
    value
}

fn bodies(case: &str) -> [Vec<u8>; 7] {
    let mut bodies = base_bodies();
    bodies[5] = canonical::canonical_json(&normalization(case)).unwrap();
    bodies
}

pub(super) fn commit_recipe(case: &str, recipe: &mut Value) {
    let bodies = bodies(case);
    let refs = references(&bodies);
    let [after, control, anchor, snapshot, journal, _, semantic] = refs.each_ref();
    let archive = [snapshot, after, control, anchor, journal];
    recipe["archived_reference_identities"] =
        json!(archive.map(|reference| native_import18_reference_identity_data(reference).unwrap()));
    recipe["archived_lengths"] = json!(archive.map(|reference| reference.length));
    recipe["semantic_reference_identity"] =
        json!(native_import18_reference_identity_data(semantic).unwrap());
    recipe["semantic_length"] = json!(semantic.length);
    recipe["semantic_spend_maximum"] = json!(semantic.length);
    let normal = normalization("initial_normalization_complete");
    let limits = &normal["limits"];
    recipe["decoder_limits"] = json!([
        snapshot.length,
        after.length,
        control.length,
        anchor.length,
        journal.length,
        limits["immutable_objects"],
        limits["immutable_bytes"],
        limits["immutable_depth"],
        limits["maximum_nodes"],
        limits["maximum_requested_bytes"]
    ]);
    recipe["maximum_target_requested_bytes"] = limits["maximum_target_requested_bytes"].clone();
    recipe["maximum_before_bytes"] = limits["maximum_before_bytes"].clone();
    recipe["normalization_projection_bytes"] = json!(U64::new(refs[5].length.get().min(65_536)));
    recipe["normalization_maximum"] = json!("65536");
    if case == "initial_normalization_projection_short" {
        recipe["normalization_projection_bytes"] = json!("1");
    }
    if case == "initial_normalization_maximum_changed" {
        recipe["normalization_maximum"] = json!("65537");
    }
}

fn fill(case: &str, owner: &mut OriginalImport18RawBootstrap) {
    let bodies = bodies(case);
    let refs = references(&bodies);
    owner
        .inputs
        .reserve_data(refs.each_ref(), bodies.each_ref().map(Vec::len), usize::MAX)
        .unwrap();
    for index in 0..7 {
        let transfer_id = Id::new(format!("normalization-input-{index}")).unwrap();
        owner
            .inputs
            .begin_data(&BlobBeginRequest {
                transfer_id: transfer_id.clone(),
                content: refs[index].clone(),
                extensions: Extensions::new(),
            })
            .unwrap();
        for (chunk, bytes) in bodies[index].chunks(4096).enumerate() {
            owner
                .inputs
                .chunk_data(&BlobChunkRequest {
                    transfer_id: transfer_id.clone(),
                    offset: U64::new((chunk * 4096) as u64),
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

struct Admission<'a> {
    case: &'a str,
    calls: Cell<usize>,
    row: Cell<Option<[usize; 3]>>,
}

impl OriginalImport18NormalizationAdmission for Admission<'_> {
    fn construct_data(
        &self,
        attempt: &OriginalImport18NormalizationAttempt,
        row: [usize; 3],
    ) -> Result<(), ProviderError> {
        assert!(attempt.started_data());
        assert!(!attempt.completed_data());
        assert!(attempt.decoded.is_none());
        assert_eq!(self.calls.replace(1), 0);
        self.row.set(Some(row));
        for axis in 0..3 {
            assert!(row[axis] > 0);
        }
        if self.case == "initial_normalization_construct_refused" {
            return Err(ProviderError::ResourceExhausted(
                "actual normalization admission",
            ));
        }
        Ok(())
    }

    fn finish_data(
        &self,
        attempt: &OriginalImport18NormalizationAttempt,
        actual: usize,
    ) -> Result<(), ProviderError> {
        assert_eq!(self.calls.replace(2), 1);
        assert!(actual <= self.row.get().unwrap()[0]);
        assert_eq!(attempt.retained_backing_data().unwrap(), actual);
        if self.case == "initial_normalization_finish_refused" {
            return Err(ProviderError::Conflict(
                "actual normalization terminal admission",
            ));
        }
        if self.case == "initial_normalization_terminal_expired" {
            std::thread::sleep(Duration::from_secs(5));
        }
        Ok(())
    }
}

pub(super) fn assert_child(case: &str, owner: &OriginalImport18RawBootstrap) {
    let retained = owner.retained_requested_bytes().unwrap();
    let mut attempt = OriginalImport18NormalizationAttempt::empty();
    let admission = Admission {
        case,
        calls: Cell::new(0),
        row: Cell::new(None),
    };
    let result = owner.decode_normalization_data(&mut attempt, &admission);
    assert_eq!(
        attempt.completed_data(),
        case == "initial_normalization_complete"
    );
    assert_eq!(result.is_ok(), attempt.completed_data());
    assert_eq!(
        admission.calls.get(),
        if case == "initial_normalization_oversized" {
            0
        } else if case == "initial_normalization_construct_refused" {
            1
        } else {
            2
        }
    );
    assert!(attempt.started_data());
    assert_eq!(
        attempt.decoded.is_none(),
        matches!(
            case,
            "initial_normalization_construct_refused"
                | "initial_normalization_missing"
                | "initial_normalization_extra"
                | "initial_normalization_oversized"
        )
    );
    assert!(
        owner
            .decode_normalization_data(&mut attempt, &admission)
            .is_err()
    );
    assert_eq!(owner.retained_requested_bytes().unwrap(), retained);
    assert_eq!(owner.inputs.bodies_data().unwrap()[5], bodies(case)[5]);
}

pub(super) fn fill_child(case: &str, owner: &mut OriginalImport18RawBootstrap) {
    fill(case, owner);
}

#[test]
fn normalization_decoding_preserves_original_banks_and_each_refused_partial() {
    for case in [
        "initial_normalization_complete",
        "initial_normalization_nonce",
        "initial_normalization_generation",
        "initial_normalization_host",
        "initial_normalization_reader",
        "initial_normalization_target",
        "initial_normalization_before",
        "initial_normalization_role",
        "initial_normalization_semantic",
        "initial_normalization_missing",
        "initial_normalization_extra",
        "initial_normalization_construct_refused",
        "initial_normalization_finish_refused",
        "initial_normalization_terminal_expired",
        "initial_normalization_native_family",
        "initial_normalization_source_family",
        "initial_normalization_semantic_family",
        "initial_normalization_projection_short",
        "initial_normalization_maximum_changed",
        "initial_normalization_oversized",
    ] {
        flight(case);
    }
    for axis in 0..12 {
        flight(&format!("initial_normalization_limit_{axis}"));
    }
}

#[test]
fn normalization_quote_requires_its_original_bytes_and_exact_complete_budget() {
    let contract = canonical::parse_json(
        &crate::reference_packet::service::complete_restore::import18::native_import18_contract_data().unwrap(),
        65_536,
    ).unwrap();
    let mut declared: Vec<_> = contract["normalization_fields"]
        .as_array()
        .unwrap()
        .iter()
        .map(|field| field.as_str().unwrap())
        .collect();
    declared.sort_unstable();
    let normal = normalization("initial_normalization_complete");
    let actual: Vec<_> = normal
        .as_object()
        .unwrap()
        .keys()
        .map(String::as_str)
        .collect();
    assert_eq!(declared, actual);

    let raw = bodies("initial_normalization_complete")[5].clone();
    let mut quoted = OriginalImport18NormalizationAttempt::empty();
    let row = quoted.quote_data(&raw, 268_435_456).unwrap();
    let peak: usize = row.into_iter().sum();

    let mut exact = OriginalImport18NormalizationAttempt::empty();
    assert_eq!(exact.quote_data(&raw, peak).unwrap(), row);
    let mut short = OriginalImport18NormalizationAttempt::empty();
    assert!(short.quote_data(&raw, peak - 1).is_err());
    assert!(short.started_data());
    assert!(short.decode_data(&raw).is_err());
    assert!(short.quote_data(&raw, peak).is_err());
    assert!(short.decoded.is_none());

    let mut changed = raw.clone();
    changed[0] ^= 1;
    assert!(quoted.decode_data(&changed).is_err());
    assert!(quoted.decode_data(&raw).is_err());
    assert!(!quoted.completed_data());
    assert!(quoted.decoded.is_none());
    assert_eq!(raw, bodies("initial_normalization_complete")[5]);
}
