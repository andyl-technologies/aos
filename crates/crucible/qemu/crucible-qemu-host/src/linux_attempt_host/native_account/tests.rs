//! Checks CPU subset observations without manufacturing native launch authority.
// SPDX-License-Identifier: Apache-2.0

// crucible-lint: allow panic-shortcut -- component controls panic on incorrect loan accounting or original refusal.
#![allow(clippy::unwrap_used)]

use super::*;
use crucible_host_resources::host_supervision::{HostOperationBudgets, HostOperationClass};

fn credit() -> (
    OriginalNativeAccountCredit,
    HostOperationSupervisor,
    HostServiceAllocator,
    HostServiceAllocator,
) {
    let supervisor = HostOperationSupervisor::new(HostOperationBudgets::default(), None).unwrap();
    let original = Arc::new(supervisor.begin(HostOperationClass::Preparation).unwrap());
    let (credit, resident, metadata) =
        OriginalNativeAccountCredit::mechanism_credit(original).unwrap();
    // The existing fixture owns real paired accounting loans. Its declared CPU
    // ceiling exercises only the subset mechanism, never a Main or native grant.
    (credit, supervisor, resident, metadata)
}

#[test]
fn cpu_subset_checks_keep_original_work_and_paired_accounting_unchanged() {
    let (credit, supervisor, resident, metadata) = credit();
    let cap = supervisor.cap_id();
    let before = supervisor.operation_statuses().unwrap();

    assert_eq!(credit.cpu_ceiling().unwrap(), 1);
    credit.require_vcpu_ceiling(1).unwrap();
    for request in [0, 2, u32::MAX] {
        assert!(matches!(
            credit.require_vcpu_ceiling(request),
            Err(OriginalActorAccountError::Unavailable)
        ));
    }

    let after = supervisor.operation_statuses().unwrap();
    assert_eq!(after.len(), before.len());
    assert_eq!(after[0].operation_id, before[0].operation_id);
    assert_eq!(supervisor.cap_id(), cap);
    assert!(resident.reserve_resources(0, 0, 1).is_err());
    assert!(metadata.reserve_resources(0, 0, 1).is_err());
}

#[test]
fn original_cancellation_precedes_cpu_request_validation() {
    let (credit, supervisor, resident, metadata) = credit();
    supervisor.cancel().unwrap();

    assert!(matches!(
        credit.cpu_ceiling(),
        Err(OriginalActorAccountError::Supervision(_))
    ));
    for request in [0, 1, 2] {
        assert!(matches!(
            credit.require_vcpu_ceiling(request),
            Err(OriginalActorAccountError::Supervision(_))
        ));
    }

    assert!(resident.reserve_resources(0, 0, 1).is_err());
    assert!(metadata.reserve_resources(0, 0, 1).is_err());
}

#[test]
fn copied_cpu_ceiling_without_original_custody_cannot_authorize_a_subset() {
    let (mut credit, _supervisor, resident, metadata) = credit();
    let retained = credit.original.take();

    assert!(matches!(
        credit.cpu_ceiling(),
        Err(OriginalActorAccountError::Unavailable)
    ));
    assert!(matches!(
        credit.require_vcpu_ceiling(1),
        Err(OriginalActorAccountError::Unavailable)
    ));
    assert!(resident.reserve_resources(0, 0, 1).is_err());
    assert!(metadata.reserve_resources(0, 0, 1).is_err());

    // Restore the same owner rather than releasing its actual pair or issuing
    // another credit. No native retirement was asserted by this component test.
    credit.original = retained;
    credit.require_vcpu_ceiling(1).unwrap();
}
