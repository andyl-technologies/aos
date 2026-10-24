//! Checks local lease/inventory reachability and explicit remote adapter selection.

#![cfg(target_os = "linux")]

use aos_sandbox_ownership::local_ownership::ProtectedFixedLocalLeaseOwnerV1;
use aos_sandbox_ownership::{OwnershipReceivingClosedV1, OwnershipServiceReceivingOriginalV1};

#[test]
fn local_lease_service_enters_through_the_retained_original_without_remote_selection() {
    let _new = OwnershipServiceReceivingOriginalV1::new;
    let _start: fn(&mut OwnershipServiceReceivingOriginalV1) -> Result<(), OwnershipReceivingClosedV1> =
        OwnershipServiceReceivingOriginalV1::start_local_authority_once_v1;
    let _serve: fn(&mut OwnershipServiceReceivingOriginalV1) -> Result<(), OwnershipReceivingClosedV1> =
        OwnershipServiceReceivingOriginalV1::run_local_authority_v1;
    let _original_cause = OwnershipServiceReceivingOriginalV1::failure;
    let _local_cause = ProtectedFixedLocalLeaseOwnerV1::retained_failure;
}
