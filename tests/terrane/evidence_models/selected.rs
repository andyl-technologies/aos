//! Compares all side-evidence tuple fields and sorted selected-row projections.
//!
//! Ordinary payloads name distinct full view, carrying and producer paths.
//! The serialization seam accepts data fields, never verified evidence holders.
//!
//! ```text
//! row = [location, name, domain, full-view-path, nine-field-evidence]
//! ```

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    reason = "complete bounded fixture assertions"
)]

#[allow(
    clippy::duplicate_mod,
    reason = "isolated private consumer modules share the primitive fixture oracle"
)]
#[path = "support.rs"]
mod support;

use super::*;
use crate::provenance::validate_canonical_context;
use Value::Array;
use alloc::{collections::BTreeMap, string::String, vec};
use support::{Value, compare, digest, evidence, fields, reference, row};

#[derive(Clone)]
struct Model {
    record: Digest,
    object: Digest,
    name: String,
    function: String,
    version: String,
    value: Vec<u8>,
    producer: Digest,
    location: EntryLocation,
    producer_domain: String,
    producer_path: Vec<u8>,
    view_path: Vec<u8>,
}

impl Model {
    fn new(carrying: bool) -> Self {
        Self {
            record: [5; 32],
            object: [6; 32],
            name: "hash.sha256".into(),
            function: "sha256".into(),
            version: "v1".into(),
            value: digest(7).encode(),
            producer: [8; 32],
            location: EntryLocation {
                commit: [if carrying { 9 } else { 8 }; 32],
                root: [10; 32],
                path: b"carrying/item".to_vec(),
            },
            producer_domain: "public".into(),
            producer_path: b"producer/full/item".to_vec(),
            view_path: b"view/full/item".to_vec(),
        }
    }

    fn fields(&self) -> EvidenceFields<'_> {
        EvidenceFields {
            record: &self.record,
            object: &self.object,
            name: &self.name,
            function: &self.function,
            version: &self.version,
            value: &self.value,
            producer: &self.producer,
            location: &self.location,
            producer_domain: &self.producer_domain,
            producer_path: &self.producer_path,
        }
    }
}

fn key(view: u8, root: u8, domain: &str) -> SideAttributeKey {
    (
        EntryLocation {
            commit: [view; 32],
            root: [root; 32],
            path: b"relative/item".to_vec(),
        },
        "hash.sha256".into(),
        domain.into(),
    )
}

fn actual(rows: &BTreeMap<SideAttributeKey, Model>, view: Digest, domain: &str) -> Vec<u8> {
    selected(
        rows,
        view,
        domain,
        |value| &value.view_path,
        |output, value| encode_evidence(output, value.fields()),
    )
}

#[test]
fn reference_selected_evidence_models_preserve_all_tuple_fields() {
    for (carrying, label) in [(false, "producer"), (true, "carrying")] {
        let model = Model::new(carrying);
        let published = compare(
            &alloc::format!("evidence-tuple-{label}"),
            &evidence(carrying),
        );
        let mut encoded = vec![];
        encode_evidence(&mut encoded, model.fields());

        assert_eq!(encoded, published);
        assert_eq!(fields(&encoded), evidence(carrying), "all nine tuple slots");
        assert_eq!(
            fields(&model.value),
            digest(7),
            "complete nested canonical value"
        );
        assert_eq!(model.location.commit == model.producer, !carrying);
        assert_ne!(model.location.path, model.producer_path);
        assert_ne!(model.view_path, model.location.path);
    }

    let rows_in_order = vec![
        (key(0, 1, "private:target"), Model::new(false)),
        (key(1, 1, "public"), Model::new(false)),
        (key(1, 2, "private:target"), Model::new(false)),
        (key(1, 3, "private:target"), Model::new(true)),
        (key(2, 1, "private:target"), Model::new(true)),
    ];
    let rows: BTreeMap<_, _> = rows_in_order.clone().into_iter().rev().collect();
    let independently_ordered: BTreeMap<_, _> = rows_in_order.into_iter().collect();
    let expected_two = Array(vec![row(0, false), row(1, true)]);
    let published_two = compare("evidence-selected-two", &expected_two);
    let encoded_two = actual(&rows, [1; 32], "private:target");

    assert_eq!(
        encoded_two, published_two,
        "filtering preserves unsigned tuple order"
    );
    assert_eq!(
        fields(&encoded_two),
        expected_two,
        "every row/location/evidence field"
    );
    assert_eq!(
        actual(&independently_ordered, [1; 32], "private:target"),
        encoded_two,
        "insertion history does not alter projection"
    );
    let context = support::context(2, None, None).encode();
    assert_eq!(
        validate_canonical_context(&context),
        Ok(()),
        "syntax only, not producer authority"
    );

    let mut one = rows.clone();
    one.remove(&key(1, 3, "private:target"));
    let expected_one = Array(vec![row(0, false)]);
    let published_one = compare("evidence-selected-one", &expected_one);
    let encoded_one = actual(&one, [1; 32], "private:target");
    assert_eq!(encoded_one, published_one);
    assert_eq!(fields(&encoded_one), expected_one);

    let empty = actual(&rows, [1; 32], "group:none");
    assert_eq!(empty, reference("evidence-selected-none"));
    assert!(
        empty.is_empty(),
        "no rows selects absent bytes, not an empty CBOR array"
    );
}
