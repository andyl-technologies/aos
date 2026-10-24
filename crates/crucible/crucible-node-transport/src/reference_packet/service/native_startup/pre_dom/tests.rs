//! Checks actual raw/parser ownership and original-reader refusal boundaries.

use super::*;
use crate::retained_metadata::{MetadataObserver, requested_metadata_backing_storage_data};
use crate::transport::{FrameReader, original_frames::OriginalFrameReservation};
use crucible_node_format::{U64, canonical};
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
    let actual = raw
        .len()
        .checked_add(super::super::storage::private_frame_work_data(
            raw_shape::extent(raw)?,
            0,
        )?)
        .ok_or_else(exhausted)?;
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
    let maximum = row(raw
        .len()
        .checked_add(super::super::storage::private_frame_work_data(
            raw_shape::extent(raw)?,
            0,
        )?)
        .ok_or_else(exhausted)?);
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
    let exact = raw
        .len()
        .checked_add(super::super::storage::private_frame_work_data(
            raw_shape::extent(raw)?,
            0,
        )?)
        .ok_or_else(exhausted)?;
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

#[test]
fn whitespace_heavy_reader_keeps_raw_body_and_dom_in_the_same_funded_phase() -> TestResult {
    // Keep the same whitespace/body-overlap oracle after adding the partial
    // native DTO phase: whitespace does not change its actual occurrence row.
    let fixed = super::super::storage::private_frame_work_data(raw_shape::extent(b"0")?, 0)?;
    let whitespace = fixed.checked_add(8192).ok_or_else(exhausted)?;
    assert!(whitespace < 1024 * 1024);
    let mut raw = vec![b' '; whitespace];
    raw.push(b'0');
    let layout = super::super::storage::private_frame_work_data(raw_shape::extent(&raw)?, 0)?;
    assert!(layout < raw.len());

    // The independent raw length check succeeds, but cannot fund the DOM that
    // is constructed while that same temporary raw Vec remains live.
    let only_body = row(raw.len());
    let budget = OriginalNativeFramePreflight::private(&only_body, 0);
    budget.admit_raw_bank(raw.len())?;
    let bank = Rc::new(RefCell::new(OriginalFrameReservation::reserve(
        raw.len() + 4,
        1,
    )?));
    let mut reader = FrameReader::new(Cursor::new(wire(&raw)), raw.len())?;
    reader.install_originals(Rc::clone(&bank));
    assert!(matches!(
        reader.read_original_native_preflight(raw.len(), &budget),
        Err(ProviderError::ResourceExhausted(
            "native original frame layout window"
        ))
    ));
    assert_eq!(bank.borrow().frames().count(), 1);

    let full = row(raw.len().checked_add(layout).ok_or_else(exhausted)?);
    let exact = OriginalNativeFramePreflight::private(&full, 0);
    let mut funded = FrameReader::new(Cursor::new(wire(&raw)), raw.len())?;
    funded.install_originals(Rc::new(RefCell::new(OriginalFrameReservation::reserve(
        raw.len() + 4,
        1,
    )?)));
    let value = funded
        .read_original_native_preflight(raw.len(), &exact)?
        .ok_or_else(exhausted)?
        .value;
    assert_eq!(value, serde_json::json!(0));
    Ok(())
}

#[test]
fn carried_launch_and_clone_are_checked_before_the_second_raw_allocation() -> TestResult {
    let carry = 4096 + 1024;
    let too_small = row(carry + 100 - 1);
    let gate = OriginalNativeFramePreflight::private(&too_small, carry);
    assert!(gate.admit_raw_bank(100).is_err());
    let exact = row(carry + 100);
    OriginalNativeFramePreflight::private(&exact, carry).admit_raw_bank(100)?;
    Ok(())
}

#[test]
fn selected_private_phase_keeps_two_dom_canonical_views_and_partial_native_slots() -> TestResult {
    let raw = br#"{"a":[{},"literal",1]}"#;
    let extent = raw_shape::extent(raw)?;
    let one_pass = extent.canonical_pass_requested_bytes()?;
    let phase = super::super::storage::private_frame_work_data(extent, 0)?;
    assert!(phase > one_pass.checked_mul(2).ok_or_else(exhausted)?);
    let first = canonical::parse_json_with_depth(raw, raw.len(), 64)?;
    let independent = first.clone();
    let mut owners = MetadataObserver::new();
    owners.observe(&first)?;
    owners.observe(&independent)?;
    let banks = canonical::canonical_json(&first)?
        .capacity()
        .checked_add(canonical::canonical_json(&independent)?.capacity())
        .ok_or_else(exhausted)?;
    let actual = requested_metadata_backing_storage_data(&owners.finish())?
        .checked_add(banks)
        .ok_or_else(exhausted)?;
    assert!(phase >= actual);
    let old = row(raw.len() + one_pass);
    assert!(
        OriginalNativeFramePreflight::private(&old, 0)
            .admit(raw)
            .is_err()
    );
    let funded = row(raw.len() + phase);
    OriginalNativeFramePreflight::private(&funded, 0).admit(raw)?;
    Ok(())
}

#[test]
fn legacy_byte_floor_refuses_the_same_smaller_budget_that_actual_shape_gate_enforces() -> TestResult
{
    let mut raw = vec![b' '; 64 * 1024];
    raw.extend_from_slice(br#"{"retained":[{},"literal"]}"#);
    let phase = super::super::storage::private_frame_work_data(raw_shape::extent(&raw)?, 0)?;
    let selected = row(raw.len().checked_add(phase).ok_or_else(exhausted)?);
    let broad =
        crate::retained_metadata::serialization_storage::original_json_value_storage_extent_data(
            raw.len(),
        )?;
    assert!(
        broad.canonical_pass_requested_bytes()? as u64
            > selected.maximum_simultaneous_transient_bytes.get()
    );

    // This is the old binary's defining pre-parser comparison, not a mode
    // inferred from a smaller row. Only the current actual gate accepts it.
    let budget = OriginalNativeFramePreflight::private(&selected, 0);
    let mut reader = FrameReader::new(Cursor::new(wire(&raw)), raw.len())?;
    let bank = Rc::new(RefCell::new(OriginalFrameReservation::reserve(
        raw.len() + 4,
        1,
    )?));
    reader.install_originals(Rc::clone(&bank));
    let actual = reader
        .read_original_native_preflight(raw.len(), &budget)?
        .ok_or_else(exhausted)?
        .value;
    assert_eq!(
        actual,
        canonical::parse_json_with_depth(&raw, raw.len(), 64)?
    );
    assert_eq!(bank.borrow().frames().count(), 1);
    Ok(())
}

#[test]
fn actual_borrowed_launch_partial_owners_fit_the_raw_preflight_before_deserialization() -> TestResult
{
    use super::super::super::PacketNative5SourceLaunch;
    use serde::Deserialize;
    let (_, _, selection, coordinator) =
        crate::reference_packet::coordinator::original_canonical_ack_controller_scope();
    // A real DTO decode is deliberately not an admitted native installation.
    // The raw census must cover it before any later semantic validation.
    let mut value = serde_json::json!({
        "schema_version":5,"selection":selection,
        "program":{"kind":"producer","program":{"schema":"source-owned.packet-program.v1","events":[]}},
        "controller_pid":"1","controller_uid":"0","controller_executable":coordinator.reference,
        "admission_token":crucible_node_format::Bytes::new(vec![7;32]),"initial_coordinator":coordinator,
        "limits":{"frame_bytes":"65536","nesting":"64","requests":"64","journal_entries":"256","blob_chunk_bytes":"1024"},
        "storage":{"snapshot_bytes":"16384","control_snapshot_bytes":"8192","protocol_snapshot_bytes":"65536","frame_bank_bytes":"65536","frames_per_direction":"256","hello_bytes":"131080","settlement_bytes":"65536"},
        "effects":"/not-opened-by-raw-preflight-control"
    });
    value["selection"]["provider"]["extensions"]["opaque"] =
        serde_json::json!({"a":[{},[],"literal"]});
    let raw = canonical::canonical_json(&value)?;
    let phase = super::super::storage::private_frame_work_data(raw_shape::extent(&raw)?, 0)?;
    let budget = row(raw.len().checked_add(phase).ok_or_else(exhausted)?);
    OriginalNativeFramePreflight::private(&budget, 0).admit(&raw)?;

    let actual = PacketNative5SourceLaunch::deserialize(&value)?;
    let facts = crate::retained_metadata::observe_retained_native_launch(&actual)?;
    let backing = requested_metadata_backing_storage_data(&facts)?;
    assert!(phase >= backing + std::mem::size_of::<PacketNative5SourceLaunch>());
    let short = row(raw.len() + phase - 1);
    assert!(
        OriginalNativeFramePreflight::private(&short, 0)
            .admit(&raw)
            .is_err()
    );
    Ok(())
}
