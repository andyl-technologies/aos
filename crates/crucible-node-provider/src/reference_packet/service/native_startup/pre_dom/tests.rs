//! Checks actual raw/parser ownership and original-reader refusal boundaries.

use super::*;
use crate::retained_metadata::{MetadataObserver, requested_metadata_backing_storage_data};
use crate::transport::{FrameReader, original_frames::OriginalFrameReservation};
use crucible_node_contract::{U64, canonical};
use std::{cell::RefCell, io::Cursor, rc::Rc};

type TestResult = Result<(), Box<dyn std::error::Error>>;

fn row(transient: usize) -> PacketNativeStartupAllocationRow {
    PacketNativeStartupAllocationRow {
        retained_requested_bytes: U64::new(1),
        maximum_simultaneous_transient_bytes: U64::new(transient as u64),
        declared_counter_scratch_bytes: U64::new(counter_scratch_data() as u64),
    }
}

fn wire(raw: &[u8]) -> Vec<u8> {
    let mut bytes = (raw.len() as u32).to_be_bytes().to_vec();
    bytes.extend_from_slice(raw);
    bytes
}

#[test]
fn actual_nested_and_escaped_values_fit_the_measured_raw_occurrence_extent() -> TestResult {
    for raw in [
        b"{}".as_slice(),
        b"[]",
        br#"{"a":{},"b":[{},[],"\uD834\uDD1E",1.5,-0],"c":"\n\t\""}"#,
    ] {
        let extent = raw_shape::extent(raw)?;
        let value = canonical::parse_json_with_depth(raw, raw.len(), 64)?;
        let mut observer = MetadataObserver::new();
        observer.observe(&value)?;
        let actual_backing = requested_metadata_backing_storage_data(&observer.finish())?;
        assert!(extent.value_dom_requested_bytes >= actual_backing);
        let encoded = canonical::canonical_json(&value)?;
        assert!(encoded.len() <= extent.maximum_canonical_encoded_bytes);
        assert!(extent.canonical_pass_requested_bytes()? >= extent.value_dom_requested_bytes);
    }
    Ok(())
}

#[test]
fn private_exact_and_one_short_charge_the_independent_typed_launch_carry() -> TestResult {
    let raw = br#"{"a":[{},"literal",1]}"#;
    let actual = raw_shape::extent(raw)?.canonical_pass_requested_bytes()?;
    let carry = 4096;
    let exact = row(actual + carry);
    OriginalNativeFramePreflight::private(&exact, carry).admit(raw)?;
    let short = row(actual + carry - 1);
    assert!(
        OriginalNativeFramePreflight::private(&short, carry)
            .admit(raw)
            .is_err()
    );
    // Omitting a simultaneous typed owner cannot borrow credit from another row.
    assert!(
        OriginalNativeFramePreflight::private(&row(actual), carry)
            .admit(raw)
            .is_err()
    );
    Ok(())
}

#[test]
fn original_reader_preserves_strict_errors_when_funded_and_stops_before_parse_when_short()
-> TestResult {
    let raw = br#"{"duplicate":0,"duplicate":1}"#;
    let maximum = row(raw_shape::extent(raw)?.canonical_pass_requested_bytes()?);
    let bank = Rc::new(RefCell::new(OriginalFrameReservation::reserve(
        raw.len() + 4,
        1,
    )?));
    let mut reader = FrameReader::new(Cursor::new(wire(raw)), raw.len())?;
    reader.install_originals(Rc::clone(&bank));
    let budget = OriginalNativeFramePreflight::private(&maximum, 0);
    assert!(matches!(
        reader.read_original_native_preflight(raw.len(), &budget),
        Err(ProviderError::Contract(_))
    ));
    assert_eq!(bank.borrow().frames().count(), 1);
    assert!(matches!(
        reader.read_original_native_preflight(raw.len(), &budget),
        Err(ProviderError::Frame("connection already failed"))
    ));

    let short = row(maximum.maximum_simultaneous_transient_bytes.get() as usize - 1);
    let second_bank = Rc::new(RefCell::new(OriginalFrameReservation::reserve(
        raw.len() + 4,
        1,
    )?));
    let mut second = FrameReader::new(Cursor::new(wire(raw)), raw.len())?;
    second.install_originals(Rc::clone(&second_bank));
    assert!(matches!(
        second.read_original_native_preflight(
            raw.len(),
            &OriginalNativeFramePreflight::private(&short, 0)
        ),
        Err(ProviderError::ResourceExhausted(
            "native original frame layout window"
        ))
    ));
    assert_eq!(second_bank.borrow().frames().count(), 1);
    assert!(matches!(
        second.read(),
        Err(ProviderError::Frame("connection already failed"))
    ));
    Ok(())
}

#[test]
fn selected_hello_reader_keeps_the_same_attempt_and_original_journal_on_layout_refusal()
-> TestResult {
    let raw = br#"{"duplicate":0,"duplicate":1}"#;
    let exact = raw_shape::extent(raw)?.canonical_pass_requested_bytes()?;
    let short = row(exact - 1);
    let journal = crate::native_hello::OriginalNativeHelloJournal::reserve(raw.len(), 64)?;
    let original = journal.original_test_identity();
    let mut exchange = journal.bind(Cursor::new(wire(raw)))?;
    assert!(matches!(
        exchange.receive_original_preflight(&OriginalNativeFramePreflight::private(&short, 0)),
        Err(ProviderError::ResourceExhausted(
            "native original frame layout window"
        ))
    ));
    let (_, journal) = exchange.into_parts();
    assert!(original(&journal));
    assert_eq!(journal.original_frames().frames().count(), 1);
    let failure = match journal.bind_owned(Cursor::new(wire(raw))) {
        Ok(_) => panic!("spent original Hello was rebound"),
        Err(failure) => failure,
    };
    let (_, journal) = failure.into_original();
    assert!(original(&journal));
    assert_eq!(journal.original_frames().frames().count(), 1);
    Ok(())
}
