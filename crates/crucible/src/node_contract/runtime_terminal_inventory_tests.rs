//! Classified terminal read failure retains original native owner custody.

use super::*;

#[test]
fn terminal_uncertain_native_read_contains_original_world_and_issues_no_barrier()
-> Result<(), crucible_node_contract::ContractError> {
    let (mut runtime, activation) =
        super::super::tests::terminal_read_failure_fixture(EffectKnowledge::Unknown);

    assert!(matches!(
        runtime.read_terminal_inventory(&activation, 65_536),
        Err(RuntimeError::InvalidReceipt)
    ));
    assert_eq!(
        runtime.owner_lifecycle(&Id::new("shared-owner")?),
        Some(Lifecycle::Quarantined)
    );
    assert!(runtime.terminal_checkpoint().is_none());
    Ok(())
}

#[test]
fn terminal_no_effect_unsupported_read_does_not_invent_quarantine_or_eof()
-> Result<(), crucible_node_contract::ContractError> {
    let (mut runtime, activation) =
        super::super::tests::terminal_read_failure_fixture(EffectKnowledge::None);

    assert!(matches!(
        runtime.read_terminal_inventory(&activation, 65_536),
        Err(RuntimeError::UnsupportedFacet)
    ));
    assert_eq!(
        runtime.owner_lifecycle(&Id::new("shared-owner")?),
        Some(Lifecycle::Stopped)
    );
    assert!(runtime.terminal_checkpoint().is_none());
    Ok(())
}
