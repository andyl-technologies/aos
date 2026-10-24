//! Exercises actual FIRST allocation/custody with real framed receipts.

use super::*;
use crate::transport::FrameReader;
use std::io::Cursor;

fn unquoted_first(body: &[u8]) -> NativeImport18OwningFirstAttemptData {
    let mut wire = Vec::new();
    wire.extend_from_slice(&u32::try_from(body.len()).unwrap().to_be_bytes());
    wire.extend_from_slice(body);
    let mut received = FrameReader::new(Cursor::new(wire), body.len())
        .unwrap()
        .read_retained()
        .unwrap();
    let mut raw = None;
    NativeImport18ImmutableRawCustodyData::take_into_data(&mut received, &mut raw).unwrap();
    let raw = raw.as_mut().unwrap();
    raw.quote_into_data(usize::MAX).unwrap();
    raw.freeze_data().unwrap();
    let row = raw
        .completed_bank_data()
        .unwrap()
        .root_selection_row_data(usize::MAX)
        .unwrap();
    let mut selected = None;
    NativeImport18RawSelectionData::read_into_data(&row, &mut selected).unwrap();
    let mut owner = None;
    NativeImport18OwningFirstAttemptData::take_into_data(&mut selected, &mut owner).unwrap();
    owner.unwrap()
}

pub(in super::super) fn first(body: &[u8]) -> NativeImport18OwningFirstAttemptData {
    let mut owner = unquoted_first(body);
    owner.quote_into_data(usize::MAX).unwrap();
    owner.run_data().unwrap();
    owner
}

pub(in super::super) fn taken(body: &[u8]) -> NativeImport18FirstBankCustodyData {
    let mut first = Some(first(body));
    let mut custody = None;
    NativeImport18FirstBankCustodyData::take_into_data(&mut first, &mut custody).unwrap();
    assert!(first.is_none());
    custody.unwrap()
}

pub(in super::super) fn frozen(body: &[u8]) -> NativeImport18FirstBankCustodyData {
    let mut custody = taken(body);
    custody.quote_into_data(usize::MAX).unwrap();
    custody.freeze_data().unwrap();
    custody
}

fn assert_censused(custody: &NativeImport18FirstBankCustodyData) {
    let bytes = custody.retained_requested_storage_data(usize::MAX).unwrap();
    assert_eq!(
        custody.census_data(),
        NativeImport18FirstBankCensusData::Observed {
            requested_bytes: bytes,
            within_row: custody.row.as_ref().map(|row| bytes <= row.retained)
        }
    );
}

#[test]
fn actual_first_freeze_exact_row_and_every_one_short_axis_preserve_custody() {
    let mut exact = taken(b"null");
    exact.quote_into_data(usize::MAX).unwrap();
    let (r, _, _) = exact.requested_storage_data().unwrap();
    exact.freeze_data().unwrap();
    assert_eq!(
        exact.retained_requested_storage_data(usize::MAX).unwrap(),
        r
    );
    assert_censused(&exact);
    for axis in 0..3 {
        let mut short = taken(b"null");
        short.quote_into_data(usize::MAX).unwrap();
        short.row.as_mut().unwrap().shorten_axis_data(axis);
        assert!(short.freeze_data().is_err());
        assert!(short.received.is_some() && short.bank.is_none());
        assert!(
            short
                .retained_first_data()
                .unwrap()
                .completed_data()
                .is_ok()
        );
        assert!(short.completed_bank_data().is_err());
        assert_censused(&short);
    }
}

#[test]
fn actual_first_freeze_quote_exact_total_and_one_short_do_not_recover_mutability() {
    let mut measure = taken(b"null");
    measure.quote_into_data(usize::MAX).unwrap();
    let (r, t, s) = measure.requested_storage_data().unwrap();
    let total = r.checked_add(t).unwrap().checked_add(s).unwrap();
    let mut exact = taken(b"null");
    exact.quote_into_data(total).unwrap();
    exact.freeze_data().unwrap();
    assert!(exact.freeze_data().is_err());
    assert_censused(&exact);
    let mut short = taken(b"null");
    assert!(short.quote_into_data(total - 1).is_err());
    assert!(short.received.is_some() && short.bank.is_none());
    assert_censused(&short);
}

#[test]
fn failed_first_transfer_is_rooted_without_success_only_allocation_and_reuse_keeps_foreign() {
    let mut actual = unquoted_first(b"null");
    assert!(actual.quote_into_data(0).is_err());
    let mut first = Some(actual);
    let mut custody = None;
    assert!(NativeImport18FirstBankCustodyData::take_into_data(&mut first, &mut custody).is_err());
    assert!(first.is_none());
    let mut foreign = Some(self::first(b"true"));
    assert!(
        NativeImport18FirstBankCustodyData::take_into_data(&mut foreign, &mut custody).is_err()
    );
    assert!(foreign.is_some());
    let failed = custody.as_ref().unwrap();
    assert!(failed.received.is_some() && failed.bank.is_none());
    assert_eq!(
        failed
            .retained_first_data()
            .unwrap()
            .retained_selection_data()
            .unwrap()
            .retained_frame_data()
            .unwrap()
            .bytes,
        b"null"
    );
    assert_censused(failed);
}
