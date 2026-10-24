//! Checks the actual constructor-peak accounting mechanism without Main issuance.
//!
//! The ordinary guard and paired allocator fixture cannot create a native Source
//! or reservation family. These controls qualify only peak retention/refusal.

// crucible-lint: allow panic-shortcut -- mechanism fixture admission must succeed before peak retention and refusal assertions; it cannot issue a Main or Source.
#![allow(clippy::unwrap_used)]

use super::*;
use crucible_host_resources::host_supervision::{
    HostOperationBudgets, HostOperationClass, HostOperationSupervisor,
};

fn fixture() -> (
    OriginalNativeAccountRoster,
    OriginalNativeAccountFactoryBinding,
    HostOperationSupervisor,
) {
    let supervisor = HostOperationSupervisor::new(HostOperationBudgets::default(), None).unwrap();
    let original = Arc::new(supervisor.begin(HostOperationClass::Preparation).unwrap());
    let (credit, _, _) = OriginalNativeAccountCredit::mechanism_credit(original).unwrap();
    let (roster, binding) =
        OriginalNativeAccountRoster::publish([Some(credit), None, None, None], 1).unwrap();
    (roster, binding, supervisor)
}

#[test]
fn same_slot_reuses_one_constructor_peak_across_account_generations() {
    let (_roster, factory, _supervisor) = fixture();
    let first = factory.claim(1, 512 << 20, 1 << 30).unwrap();
    let owner = first.roster.upgrade().unwrap();
    let extent = process_purpose::family_constructor_extent().unwrap();
    let first_generation = first.generation;
    {
        let mut state = owner.lock().unwrap();
        let slot = &mut state.slots[first.index];
        let before = slot.assigned_metadata_bytes().unwrap();
        slot.reserve_family_constructor().unwrap();
        slot.reserve_family_constructor().unwrap();
        assert_eq!(slot.family_constructor_bytes, extent);
        assert_eq!(slot.assigned_metadata_bytes().unwrap(), before + extent);
        assert!(slot.installed_process.is_none());
    }

    first.cleanup().unwrap();
    first.close_vector().unwrap();
    let second = factory.claim(1, 512 << 20, 1 << 30).unwrap();
    assert_ne!(second.generation, first_generation);
    let mut state = owner.lock().unwrap();
    let slot = &mut state.slots[second.index];
    let before = slot.assigned_metadata_bytes().unwrap();
    slot.reserve_family_constructor().unwrap();
    assert_eq!(slot.family_constructor_bytes, extent);
    assert_eq!(slot.assigned_metadata_bytes().unwrap(), before);
    assert!(slot.installed_process.is_none());
}

#[test]
fn exhausted_constructor_peak_refuses_before_publishing_family_or_control() {
    let (_roster, factory, _supervisor) = fixture();
    let attempt = factory.claim(1, 512 << 20, 1 << 30).unwrap();
    let owner = attempt.roster.upgrade().unwrap();
    let mut state = owner.lock().unwrap();
    let slot = &mut state.slots[attempt.index];
    let before = slot.assigned_metadata_bytes().unwrap();
    slot.credit.as_mut().unwrap().total_metadata_bytes = before;

    assert!(slot.reserve_family_constructor().is_err());
    assert_eq!(slot.family_constructor_bytes, 0);
    assert_eq!(slot.assigned_metadata_bytes().unwrap(), before);
    assert!(slot.installed_process.is_none());
}
