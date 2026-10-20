//! Compares the connected issuer layout supplier with the full old generic path.

use super::super::*;
use super::{counter_scratch_data, project};

type TestResult = Result<(), ProviderError>;

fn original_quote(bytes: &[u8], typed_slot: usize, maximum: usize) -> Result<usize, ProviderError> {
    let layouts = crate::reference_packet::control::packet_control_snapshot_validation_layouts();
    scan(
        bytes,
        maximum,
        typed_slot.max(layouts.maximum_typed_slot_bytes),
        map_node(
            layouts.maximum_tree_key_value_bytes,
            layouts.maximum_tree_entry_alignment,
        )?,
    )?
    .requested(&Phases {
        dom: 1,
        typed: 1,
        canonical: 1,
    })
}

fn original_counter() -> usize {
    size_of::<[u8; 64]>()
        + size_of::<Credit>()
        + size_of::<Phases>()
        + size_of::<crate::reference_packet::control::PacketControlSnapshotValidationLayouts>()
        // Includes the new helpers' named DOM root-node width.
        + 13 * size_of::<usize>()
        + 3 * size_of::<std::alloc::Layout>()
        + size_of::<[usize; 6]>()
        + size_of::<[usize; 4]>()
        + 2 * size_of::<&[usize]>()
        + 2 * size_of::<std::slice::Iter<'static, usize>>()
        + size_of::<&[u8]>()
}

fn outcome(result: Result<usize, ProviderError>) -> Result<usize, String> {
    result.map_err(|error| format!("{error:?}; {error}"))
}

#[test]
fn actual_issuer_layout_fields_and_generic_quote_match_the_original() -> TestResult {
    let expected = crate::reference_packet::control::packet_control_snapshot_validation_layouts();
    let actual = project();

    assert_eq!(
        actual.maximum_typed_slot_bytes,
        expected.maximum_typed_slot_bytes
    );
    assert_eq!(
        actual.maximum_tree_key_value_bytes,
        expected.maximum_tree_key_value_bytes
    );
    assert_eq!(
        actual.maximum_tree_entry_alignment,
        expected.maximum_tree_entry_alignment
    );
    assert_eq!(
        selected_issuer_decode_counter_scratch_data(),
        original_counter() + counter_scratch_data()
    );

    for input in [
        b"null".as_slice(),
        b"{}",
        b"[]",
        br#"{"key":[0,{},[],"quoted\n\"text"],"nested":{"child":true}}"#,
    ] {
        for typed_slot in [
            0,
            size_of::<Value>(),
            size_of::<crate::reference_packet::service::PacketNative5SourceLaunch>(),
        ] {
            let expected = original_quote(input, typed_slot, usize::MAX)?;
            assert_eq!(
                selected_issuer_decode_storage_data(input, typed_slot, usize::MAX)?,
                expected
            );
            // In this inherited generic helper, maximum bounds raw scanner input.
            // The enclosing issuer separately admits the returned requested sum.
            assert_eq!(
                selected_issuer_decode_storage_data(input, typed_slot, input.len())?,
                expected
            );
        }
    }
    Ok(())
}

#[test]
fn original_issuer_raw_boundary_framing_depth_and_overflow_refusals_are_preserved() {
    let input = br#"{"a":[0,{}]}"#;
    assert!(original_quote(input, 0, input.len() - 1).is_err());
    assert_eq!(
        outcome(selected_issuer_decode_storage_data(
            input,
            0,
            input.len() - 1
        )),
        outcome(original_quote(input, 0, input.len() - 1))
    );

    for malformed in [b"".as_slice(), b"{]", b"{", b"\"unterminated"] {
        assert!(original_quote(malformed, 0, usize::MAX).is_err());
        assert_eq!(
            outcome(selected_issuer_decode_storage_data(
                malformed,
                0,
                usize::MAX
            )),
            outcome(original_quote(malformed, 0, usize::MAX))
        );
    }
    let deep = format!("{}null{}", "[".repeat(65), "]".repeat(65));
    assert!(original_quote(deep.as_bytes(), 0, usize::MAX).is_err());
    assert_eq!(
        outcome(selected_issuer_decode_storage_data(
            deep.as_bytes(),
            0,
            usize::MAX
        )),
        outcome(original_quote(deep.as_bytes(), 0, usize::MAX))
    );
    assert!(original_quote(b"[]", usize::MAX, usize::MAX).is_err());
    assert_eq!(
        outcome(selected_issuer_decode_storage_data(
            b"[]",
            usize::MAX,
            usize::MAX
        )),
        outcome(original_quote(b"[]", usize::MAX, usize::MAX))
    );
}
