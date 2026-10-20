//! Compares the real fixed-owner supplier with the original three-call sequence.

use super::*;

type TestResult = Result<(), ProviderError>;

// This independent oracle retains the old real calls, rather than consulting
// the new report or reconstructing private layouts from copied constants.
fn original_components(maximum: usize) -> Result<[usize; 3], ProviderError> {
    let shared_headers = super::super::super::super::server::complete::birth::original_native_birth_shared_layout_bytes()?;
    let phase_headers = super::super::super::super::server::complete::birth::original_native_birth_phase_layout_bytes()?;
    let context_banks = super::super::sum(
        &super::super::super::super::ack_emitter::ORIGINAL_ACK_CONTEXT_BANK_BYTES,
        maximum,
    )?;
    Ok([shared_headers, phase_headers, context_banks])
}

#[test]
fn actual_fixed_owner_components_preserve_the_original_exact_context_boundary() -> TestResult {
    let expected = original_components(usize::MAX)?;
    let actual = project(usize::MAX)?;

    assert_eq!(actual.shared_headers_bytes, expected[0]);
    assert_eq!(actual.phase_headers_bytes, expected[1]);
    assert_eq!(actual.context_bank_bytes, expected[2]);
    assert!(expected.iter().all(|bytes| *bytes > 0));

    // Only the original context sum consumes this supplied ceiling. The outer
    // real birth quote separately bounds all retained components together.
    let exact = expected[2];
    assert_eq!(project(exact)?, actual);
    assert_eq!(original_components(exact)?, expected);
    assert!(matches!(
        project(exact - 1),
        Err(ProviderError::ResourceExhausted(
            "native baseline requested storage"
        ))
    ));
    assert!(matches!(
        original_components(exact - 1),
        Err(ProviderError::ResourceExhausted(
            "native baseline requested storage"
        ))
    ));
    Ok(())
}

#[test]
fn inherited_context_sum_refuses_overflow_and_short_bounds() {
    // Exercise the unchanged helper actually used for the context component;
    // this is not an overflow claim about the fixed real constant roster.
    assert!(matches!(
        super::super::sum(&[usize::MAX, 1], usize::MAX),
        Err(ProviderError::ResourceExhausted(
            "native baseline requested storage"
        ))
    ));
    assert_eq!(
        super::super::sum(&[usize::MAX], usize::MAX).ok(),
        Some(usize::MAX)
    );
    assert!(super::super::sum(&[usize::MAX], usize::MAX - 1).is_err());
}
