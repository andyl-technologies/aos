//! Checks the actual reserved association family used before genuine private birth.
//!
//! These controls allocate only the real bounded byte banks. They construct no
//! Hello, emitter, native read, archive ticket, private key or Child authority.

// crucible-lint: allow panic-shortcut -- Assertions report actual ownership/phase regressions.

use super::*;

type TestResult = Result<(), String>;

fn reserved() -> Result<OriginalAckPeerAssociation, String> {
    let mut slot = None;
    OriginalAckPeerAssociation::reserve_into(8192, &mut slot)
        .map_err(|failure| format!("{failure:?}"))?;
    let mut original = slot.ok_or("original association absent")?;
    original
        .reserve_complete_restore_banks(8192)
        .map_err(|failure| format!("{failure:?}"))?;
    original
        .reserve_restore_transfer_phase_banks(8192)
        .map_err(|failure| format!("{failure:?}"))?;
    Ok(original)
}

#[test]
fn actual_reserved_birth_banks_are_observed_before_any_association_attempt() -> TestResult {
    let mut original = reserved()?;
    original
        .authenticate_reserved_prebirth_data()
        .map_err(|failure| format!("{failure:?}"))?;
    let bytes = original
        .allocated_bank_bytes()
        .map_err(|failure| format!("{failure:?}"))?;
    let roots: [(usize, usize); 5] = std::array::from_fn(|index| {
        (
            original.banks[index].as_ptr() as usize,
            original.banks[index].capacity(),
        )
    });
    assert!(
        bytes
            > OriginalAckPeerAssociation::minimum_bank_bytes(8192)
                .map_err(|failure| format!("{failure:?}"))?
    );
    assert_eq!(
        original
            .retained_heap_storage_data(bytes)
            .map_err(|failure| format!("{failure:?}"))?,
        bytes
    );
    assert!(original.retained_heap_storage_data(bytes - 1).is_err());

    // A real entered association cannot masquerade as these prebirth banks.
    original.attempted = true;
    assert!(original.authenticate_reserved_prebirth_data().is_err());
    assert!(original.attempted);
    assert_eq!(
        original
            .allocated_bank_bytes()
            .map_err(|failure| format!("{failure:?}"))?,
        bytes
    );
    assert_eq!(
        std::array::from_fn::<_, 5, _>(|index| {
            (
                original.banks[index].as_ptr() as usize,
                original.banks[index].capacity(),
            )
        }),
        roots
    );
    Ok(())
}

#[test]
fn unattempted_flag_does_not_hide_a_retained_literal_or_normalized_owner() -> TestResult {
    let mut literal = reserved()?;
    literal.banks[4].extend_from_slice(b"retained-original-frame");
    let before = literal.banks[4].as_slice();
    assert!(!literal.attempted);
    assert!(literal.authenticate_reserved_prebirth_data().is_err());
    assert_eq!(literal.banks[4].as_slice(), before);

    let mut normalized = reserved()?;
    normalized.normalized[0] = Some(serde_json::json!({"retained": "original"}));
    assert!(!normalized.attempted);
    assert!(normalized.authenticate_reserved_prebirth_data().is_err());
    assert_eq!(
        normalized.normalized[0].as_ref(),
        Some(&serde_json::json!({"retained": "original"}))
    );
    Ok(())
}
