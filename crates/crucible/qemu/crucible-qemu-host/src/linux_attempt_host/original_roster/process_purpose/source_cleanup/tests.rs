//! Exercises nominal receiver identity without issuing a Native Source.

use super::*;
use crate::linux_attempt_host::original_roster::{
    OriginalNativeAccountCredit, OriginalNativeAccountRoster,
};
use crucible_host_resources::host_supervision::{
    HostOperationBudgets, HostOperationClass, HostOperationSupervisor,
};

#[test]
fn nominal_helper_receiver_cannot_promote_an_unissued_source() {
    let supervisor = HostOperationSupervisor::new(HostOperationBudgets::default(), None).unwrap();
    let original = Arc::new(supervisor.begin(HostOperationClass::Preparation).unwrap());
    let (credit, resident, metadata) =
        OriginalNativeAccountCredit::mechanism_credit(original).unwrap();
    let (roster, binding) =
        OriginalNativeAccountRoster::publish([Some(credit), None, None, None], 1).unwrap();
    let attempt = binding.claim(1, 512 << 20, 1 << 30).unwrap();
    let lender = attempt.helper_cleanup_lender();
    let receiver = crate::QemuIssuedHelperReceiver::from_lender(lender.clone());
    let clone = receiver.clone();
    let held = attempt.roster.upgrade().unwrap();
    let controller = held.lock().unwrap().slots[attempt.index]
        .source_controller
        .as_ref()
        .unwrap()
        .clone();
    drop(held);

    assert!(receiver.same_identity(&clone));
    assert!(receiver.upgrade().is_none());
    assert!(!receiver.matches_controller(&controller));
    assert!(lender.clone().retained_original().is_err());
    assert!(lender.current_incarnation().is_err());

    // Scalar edits only form negative observers; they cannot issue custody.
    for changed in [
        SourceCleanupLender {
            index: lender.index + 1,
            ..lender.clone()
        },
        SourceCleanupLender {
            generation: lender.generation + 1,
            ..lender.clone()
        },
        SourceCleanupLender {
            process_generation: Some(1),
            ..lender.clone()
        },
        SourceCleanupLender {
            roster: RosterWeak::new(),
            ..lender.clone()
        },
    ] {
        assert!(changed.current_incarnation().is_err());
        let foreign = crate::QemuIssuedHelperReceiver::from_lender(changed);
        assert!(!receiver.same_identity(&foreign));
        assert!(foreign.upgrade().is_none());
    }

    drop((controller, attempt, binding, roster));

    assert!(clone.upgrade().is_none());
    // Missing custody is not a physical-return receipt for either original.
    assert!(resident.reserve_resources(0, 0, 1).is_err());
    assert!(metadata.reserve_resources(0, 0, 1).is_err());
}
