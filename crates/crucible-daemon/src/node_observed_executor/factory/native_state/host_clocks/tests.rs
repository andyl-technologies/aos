//! Checks bounded independent Host Clock selection before native preparation.

#![cfg(test)]
// crucible-lint: allow panic-shortcut -- Source roster and default-byte assertions deliberately fail these data controls.
#![allow(clippy::unwrap_used)]

use super::*;
use crucible_node_contract::Id;

fn clock(node: &str, owner: &str) -> InstalledNodeSelection {
    InstalledNodeSelection {
        node: Id::new(node).unwrap(),
        owner: Id::new(owner).unwrap(),
        kind: InstalledNodeKind::HostClock,
    }
}

#[test]
fn empty_list_preserves_original_two_owner_selection() {
    assert!(validate(&[]).is_ok());
}

#[test]
fn independently_named_clock_list_is_bounded_and_ordered() {
    let selected = [clock("meter", "owner/meter"), clock("timer", "owner/timer")];
    assert!(validate(&selected).is_ok());

    let reversed = [selected[1].clone(), selected[0].clone()];
    assert!(validate(&reversed).is_err());
    let too_many: Vec<_> = (0..=MAXIMUM_ADDITIONAL_CLOCKS)
        .map(|index| clock(&format!("meter-{index}"), &format!("owner/meter-{index}")))
        .collect();
    assert!(validate(&too_many).is_err());
}

#[test]
fn original_and_duplicate_owner_aliases_refuse() {
    assert!(validate(&[clock("meter", "owner/cpu")]).is_err());
    assert!(validate(&[clock("meter", "owner/clock")]).is_err());
    assert!(
        validate(&[
            clock("meter", "owner/shared"),
            clock("timer", "owner/shared")
        ])
        .is_err()
    );
    assert!(validate(&[clock("meter", "owner/meter"), clock("meter", "owner/other")]).is_err());
}

#[test]
fn a_native_kind_cannot_masquerade_as_an_independent_clock() {
    let mut selected = clock("meter", "owner/meter");
    selected.kind = super::super::super::InstalledNodeKind::Gem5Closed {
        isa: super::super::super::InstalledGem5Isa::X86_64,
    };
    assert!(validate(&[selected]).is_err());
}
