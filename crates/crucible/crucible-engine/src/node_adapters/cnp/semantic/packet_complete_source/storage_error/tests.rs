//! Exercises actual Source backing with typed refusals and legacy diagnostics.
//!
//! Constructors use the existing inert complete declaration fixture. No native
//! process, borrowed authority, report, key, socket or background worker exists.

// crucible-lint: allow panic-shortcut -- Assertions compare the same actual owners and refusal classes.

use super::super::*;
use crate::node_contract::RuntimeError;

type TestResult = Result<(), String>;

fn source() -> Result<PacketCompleteSemanticSource, String> {
    use super::super::tests::{coordinator, installation, producer, storage_selection};

    let coordinator = coordinator();
    let mut program = producer();
    program.events.reserve(31);
    PacketCompleteSemanticSource::new_producer_for_collecting_world(
        installation(&coordinator, 0),
        program,
        coordinator,
        storage_selection(),
    )
    .map_err(|failure| format!("{failure:?}"))
}

#[test]
fn actual_installation_typed_exact_and_one_short_preserve_legacy_owner_observation() -> TestResult {
    let source = source()?;
    let original = source
        .original_complete_installation_storage_data(usize::MAX)
        .map_err(|failure| format!("{failure:?}"))?;
    let typed = source
        .original_complete_installation_storage_data_with_error::<RuntimeError>(usize::MAX)
        .map_err(|failure| format!("{failure:?}"))?;
    assert_eq!(typed, original);
    assert!(typed > 0);
    assert_eq!(
        source.original_complete_installation_storage_data_with_error::<RuntimeError>(typed),
        Ok(typed)
    );

    assert_eq!(
        source.original_complete_installation_storage_data_with_error::<RuntimeError>(typed - 1),
        Err(RuntimeError::ResourceLimit)
    );
    assert!(
        source
            .original_complete_installation_storage_data(typed - 1)
            .is_err()
    );
    assert_eq!(
        source
            .original_complete_installation_storage_data(usize::MAX)
            .map_err(|failure| format!("{failure:?}"))?,
        original
    );
    // A supported component does not hide absent full Source/protocol owners.
    assert_eq!(
        source.original_complete_retained_nested_precredit_data(usize::MAX),
        Err(RuntimeError::UnsupportedFacet)
    );
    Ok(())
}

#[test]
fn typed_foreign_creator_refuses_before_walk_and_keeps_original_backing_and_diagnostic()
-> TestResult {
    let mut source = source()?;
    let original = source
        .original_complete_installation_storage_data(usize::MAX)
        .map_err(|failure| format!("{failure:?}"))?;
    let creator = source.process;
    source.process = creator.wrapping_add(1);

    assert_eq!(
        source.original_complete_installation_storage_data_with_error::<RuntimeError>(usize::MAX),
        Err(RuntimeError::ForeignAuthority)
    );
    let legacy = source
        .original_complete_installation_storage_data(usize::MAX)
        .err()
        .ok_or("legacy foreign creator was accepted")?;
    assert_eq!(legacy.effects, EffectKnowledge::None);
    assert_eq!(
        legacy.reason,
        "complete source belongs to another creator process"
    );

    source.process = creator;
    assert_eq!(
        source.original_complete_installation_storage_data_with_error::<RuntimeError>(usize::MAX),
        Ok(original)
    );
    assert!(source.capture_banks.borrow().is_none());
    assert!(source.ack_peer_birth.borrow().is_none());
    Ok(())
}
