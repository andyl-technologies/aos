//! Exercises actual FrameReader receipt, immutable movement and bounded selections.

use super::*;
use crate::transport::FrameReader;
use std::io::Cursor;

fn received(body: &[u8]) -> RetainedFrame {
    let mut wire = Vec::new();
    wire.extend_from_slice(&u32::try_from(body.len()).unwrap().to_be_bytes());
    wire.extend_from_slice(body);
    FrameReader::new(Cursor::new(wire), body.len())
        .unwrap()
        .read_retained()
        .unwrap()
        .unwrap()
}

fn frozen(body: &[u8]) -> NativeImport18ImmutableRawCustodyData {
    let mut source = Some(received(body));
    let mut output = None;
    NativeImport18ImmutableRawCustodyData::take_into_data(&mut source, &mut output).unwrap();
    assert!(source.is_none());
    let owner = output.as_mut().unwrap();
    owner.quote_into_data(usize::MAX).unwrap();
    owner.freeze_data().unwrap();
    output.unwrap()
}

fn assert_censused(owner: &NativeImport18ImmutableRawCustodyData) {
    let bytes = owner.retained_requested_storage_data(usize::MAX).unwrap();
    assert_eq!(
        owner.census_data(),
        NativeImport18ImmutableRawCensusData::Observed {
            requested_bytes: bytes,
            within_row: owner
                .row
                .as_ref()
                .map(|row| bytes <= row.requested_storage_data().0),
        }
    );
}

fn select(row: NativeImport18RawSelectionConstructionData<'_>) -> NativeImport18RawSelectionData {
    let mut output = None;
    NativeImport18RawSelectionData::read_into_data(&row, &mut output).unwrap();
    let owner = output.unwrap();
    assert_eq!(
        owner.retained_requested_storage_data(usize::MAX).unwrap(),
        row.requested_storage_data().0
    );
    assert_eq!(
        owner.census_data(),
        NativeImport18ImmutableRawCensusData::Observed {
            requested_bytes: row.requested_storage_data().0,
            within_row: Some(true),
        }
    );
    owner
}

#[test]
fn actual_received_bytes_and_child_allocations_move_without_a_dom_clone() {
    let body = br#"{ "a" : [null,true,{"b":"x"}], "n" : 1e0 }"#;
    let mut source = Some(received(body));
    let bytes = source.as_ref().unwrap().bytes.as_ptr();
    let children = source.as_ref().unwrap().value["a"]
        .as_array()
        .unwrap()
        .as_ptr();
    let mut output = None;

    NativeImport18ImmutableRawCustodyData::take_into_data(&mut source, &mut output).unwrap();
    let owner = output.as_mut().unwrap();
    assert!(source.is_none());
    assert_eq!(owner.retained_frame_data().unwrap().bytes.as_ptr(), bytes);
    owner.quote_into_data(usize::MAX).unwrap();
    let row = owner.row.unwrap();
    owner.freeze_data().unwrap();

    let bank = owner.completed_bank_data().unwrap();
    assert_eq!(bank.frame_data().bytes, body);
    assert_eq!(bank.frame_data().bytes.as_ptr(), bytes);
    assert_eq!(
        bank.frame_data().value["a"].as_array().unwrap().as_ptr(),
        children
    );
    assert_eq!(bank.population_data(), 7);
    assert_eq!(
        owner.retained_requested_storage_data(usize::MAX).unwrap(),
        row.requested_storage_data().0
    );
    assert_censused(owner);
}

#[test]
fn owning_selection_survives_old_slot_replacement_and_original_custody_drop() {
    let mut source = Some(received(b"null"));
    let mut output = None;
    NativeImport18ImmutableRawCustodyData::take_into_data(&mut source, &mut output).unwrap();
    let owner = output.as_mut().unwrap();
    owner.quote_into_data(usize::MAX).unwrap();
    owner.freeze_data().unwrap();
    let selection = select(
        owner
            .completed_bank_data()
            .unwrap()
            .root_selection_row_data(usize::MAX)
            .unwrap(),
    );

    source = Some(received(b"true"));
    drop(output);

    assert!(selection.value_data().unwrap().is_null());
    assert_eq!(selection.retained_frame_data().unwrap().bytes, b"null");
    assert_eq!(source.as_ref().unwrap().bytes, b"true");
    assert_eq!(source.as_ref().unwrap().value, Value::Bool(true));
    assert!(matches!(
        selection.census_data(),
        NativeImport18ImmutableRawCensusData::Observed {
            within_row: Some(true),
            ..
        }
    ));
}

#[test]
fn exact_frozen_row_succeeds_but_each_one_short_axis_keeps_the_original_frame() {
    let exact = frozen(b"{\"k\":[1,2]}");
    assert_censused(&exact);
    for axis in 0..3 {
        let body = b"{\"k\":[1,2]}";
        let mut source = Some(received(body));
        let original = source.as_ref().unwrap().bytes.as_ptr();
        let mut output = None;
        NativeImport18ImmutableRawCustodyData::take_into_data(&mut source, &mut output).unwrap();
        let owner = output.as_mut().unwrap();
        owner.quote_into_data(usize::MAX).unwrap();
        let row = owner.row.as_mut().unwrap();
        row.shorten_axis_data(axis);

        assert!(matches!(
            owner.freeze_data(),
            Err(ProviderError::ResourceExhausted(_))
        ));
        assert_eq!(owner.stage, Stage::Failed);
        assert!(owner.bank.is_none());
        assert_eq!(owner.retained_frame_data().unwrap().bytes, body);
        assert_eq!(
            owner.retained_frame_data().unwrap().bytes.as_ptr(),
            original
        );
        assert!(owner.completed_bank_data().is_err());
        assert!(owner.freeze_data().is_err());
        assert_censused(owner);
    }
}

#[test]
fn quote_refusal_and_reused_transfer_leave_their_actual_frames_in_custody() {
    let body = b"{\"k\":1}";
    let mut source = Some(received(body));
    let mut output = None;
    NativeImport18ImmutableRawCustodyData::take_into_data(&mut source, &mut output).unwrap();
    let owner = output.as_mut().unwrap();
    assert!(owner.quote_into_data(0).is_err());
    assert_eq!(owner.retained_frame_data().unwrap().bytes, body);
    assert!(owner.bank.is_none());
    assert_censused(owner);

    let mut later = Some(received(b"true"));
    assert!(
        NativeImport18ImmutableRawCustodyData::take_into_data(&mut later, &mut output).is_err()
    );
    assert_eq!(later.as_ref().unwrap().bytes, b"true");
    assert_eq!(
        output
            .as_ref()
            .unwrap()
            .retained_frame_data()
            .unwrap()
            .bytes,
        body
    );
    assert!(
        output
            .as_mut()
            .unwrap()
            .quote_into_data(usize::MAX)
            .is_err()
    );
}

#[test]
fn checked_root_relative_children_refuse_equal_foreign_allocations() {
    let left = frozen(b"{\"k\":[1,2]}");
    let right = frozen(b"{\"k\":[1,2]}");
    let a = left.completed_bank_data().unwrap();
    let b = right.completed_bank_data().unwrap();
    let root = select(a.root_selection_row_data(usize::MAX).unwrap());
    let array = select(
        a.child_selection_row_data(&root, NativeImport18RawChildData::Field("k"), usize::MAX)
            .unwrap(),
    );
    let second = select(
        a.child_selection_row_data(&array, NativeImport18RawChildData::Element(1), usize::MAX)
            .unwrap(),
    );

    assert_eq!(second.value_data().unwrap(), &Value::from(2));
    assert!(b.borrow_selection_data(&root).is_err());
    assert!(
        b.child_selection_row_data(&root, NativeImport18RawChildData::Field("k"), usize::MAX)
            .is_err()
    );
    assert!(
        a.child_selection_row_data(
            &root,
            NativeImport18RawChildData::Field("missing"),
            usize::MAX
        )
        .is_err()
    );
    assert!(
        a.child_selection_row_data(&array, NativeImport18RawChildData::Element(2), usize::MAX)
            .is_err()
    );
    assert_eq!(a.frame_data().bytes, b.frame_data().bytes);
}

#[test]
fn each_one_short_selection_axis_refuses_before_copying_a_handle_and_keeps_its_root() {
    let owner = frozen(b"null");
    let bank = owner.completed_bank_data().unwrap();
    let baseline = Rc::strong_count(&bank.inner);
    for axis in 0..3 {
        let mut row = bank.root_selection_row_data(usize::MAX).unwrap();
        row.shorten_axis_data(axis);
        let mut output = None;
        assert!(NativeImport18RawSelectionData::read_into_data(&row, &mut output).is_err());
        let failed = output.as_ref().unwrap();
        assert!(failed.value_data().is_err());
        assert_eq!(Rc::strong_count(&bank.inner), baseline);
        assert!(matches!(
            failed.census_data(),
            NativeImport18ImmutableRawCensusData::Observed { .. }
        ));
    }
    let row = bank.root_selection_row_data(usize::MAX).unwrap();
    let mut output = None;
    NativeImport18RawSelectionData::read_into_data(&row, &mut output).unwrap();
    assert_eq!(Rc::strong_count(&bank.inner), baseline + 1);
    assert!(NativeImport18RawSelectionData::read_into_data(&row, &mut output).is_err());
    assert_eq!(Rc::strong_count(&bank.inner), baseline + 1);
    assert!(output.as_ref().unwrap().value_data().unwrap().is_null());
}

#[test]
fn raw64_receipt_uses_existing_observer_without_a_recursive_value_profile_shrink() {
    let body = format!("{}0{}", "[".repeat(64), "]".repeat(64));
    let owner = frozen(body.as_bytes());
    assert_eq!(owner.completed_bank_data().unwrap().population_data(), 65);
    assert_eq!(owner.retained_frame_data().unwrap().bytes, body.as_bytes());
    assert_censused(&owner);
}

#[test]
fn source_observer_refusal_happens_after_rooting_the_actual_received_frame() {
    let array = format!("{}null", "null,".repeat(65_535));
    let body = format!("[[{array}],[{array}]]");
    let mut source = Some(received(body.as_bytes()));
    let pointer = source.as_ref().unwrap().bytes.as_ptr();
    let mut output = None;

    assert!(
        NativeImport18ImmutableRawCustodyData::take_into_data(&mut source, &mut output).is_err()
    );
    assert!(source.is_none());
    let failed = output.as_ref().unwrap();
    assert_eq!(failed.stage, Stage::Failed);
    assert_eq!(failed.retained_frame_data().unwrap().bytes, body.as_bytes());
    assert_eq!(
        failed.retained_frame_data().unwrap().bytes.as_ptr(),
        pointer
    );
    assert_eq!(
        failed.census_data(),
        NativeImport18ImmutableRawCensusData::Refused
    );
    assert!(failed.bank.is_none());
}

#[test]
fn nested_checked_children_keep_actual_values_and_custody_after_the_search_scope_ends() {
    let body = br#"{ "outer" : [ { "inner" : [ { "leaf" : 7 } ] } ] }"#;
    let custody = frozen(body);
    let (leaf, ancestors) = {
        let bank = custody.completed_bank_data().unwrap();
        let mut parent = select(bank.root_selection_row_data(usize::MAX).unwrap());
        let mut ancestors = Vec::new();
        for child in [
            NativeImport18RawChildData::Field("outer"),
            NativeImport18RawChildData::Element(0),
            NativeImport18RawChildData::Field("inner"),
            NativeImport18RawChildData::Element(0),
            NativeImport18RawChildData::Field("leaf"),
        ] {
            let row = bank
                .child_selection_row_data(&parent, child, usize::MAX)
                .unwrap();
            let next = select(row);
            ancestors.push(parent);
            parent = next;
        }
        assert!(
            bank.child_selection_row_data(
                &parent,
                NativeImport18RawChildData::Field("missing"),
                usize::MAX
            )
            .is_err()
        );
        (parent, ancestors)
    };
    drop(custody);

    assert_eq!(leaf.value_data().unwrap(), &Value::from(7));
    assert_eq!(leaf.retained_frame_data().unwrap().bytes, body);
    assert_eq!(ancestors.len(), 5);
    assert!(ancestors[0].value_data().unwrap().is_object());
    assert!(ancestors[1].value_data().unwrap().is_array());
    assert!(ancestors[2].value_data().unwrap().is_object());
    for owner in ancestors.iter().chain(std::iter::once(&leaf)) {
        assert_eq!(owner.retained_frame_data().unwrap().bytes, body);
        assert_eq!(
            owner.census_data(),
            NativeImport18ImmutableRawCensusData::Observed {
                requested_bytes: owner.retained_requested_storage_data(usize::MAX).unwrap(),
                within_row: Some(true),
            }
        );
    }
}
