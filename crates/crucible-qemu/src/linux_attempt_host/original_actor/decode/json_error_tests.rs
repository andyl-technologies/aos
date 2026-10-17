//! Actual original-bank JSON payload free and error-custody controls.
//!
//! Serial position repair frees two pinned 40-byte ErrorImpl allocations before
//! returning the third. The retained box and message are identified through
//! actual allocation capture and the allocation-free Display borrow. These
//! controls establish requested purposes and physical free order; they grant no allocator rounding, service birth or VM admission.

// crucible-lint: allow panic-shortcut -- fixture failures identify malformed-input acceptance, missing original credit, or premature physical payload/control close; no production panic or admission is added.
#![allow(clippy::unwrap_used)]

use super::*;
use crucible::owned_decode::json_profiles::policy::Projection;
use crucible::owned_decode::{
    ClosedJsonError, closed_json_diagnostic_extent_for_test, from_json_slice_closed,
};
use crucible_linux_resource::host_supervision::{
    HostOperationBudgets, HostOperationClass, HostOperationSupervisor,
};
use crucible_linux_resource::test_support::{AllocationIdentity, TestAllocationObserver};
use std::fmt;
use std::num::NonZeroUsize;

struct MessageIdentity {
    bytes: usize,
    identity: Option<AllocationIdentity>,
}

impl fmt::Write for MessageIdentity {
    fn write_str(&mut self, text: &str) -> fmt::Result {
        // ErrorCode::Message writes its entire Box<str> to Display. This captures
        // only its live base identity; no raw Serde error or ownership escapes.
        if text.len() == self.bytes {
            assert!(self.identity.is_none());
            self.identity = Some(AllocationIdentity::from_address(
                NonZeroUsize::new(text.as_ptr() as usize).unwrap(),
            ));
        }
        Ok(())
    }
}

fn paid_payload_closes_before_original_credit(unwind: bool) {
    let name = "unknown-field".repeat(512);
    let bytes = format!("{{\"{name}\":0}}").into_bytes();
    let message_bytes = {
        let error = match serde_json::from_slice::<Projection<'_>>(&bytes) {
            Ok(_) => panic!("expected actual unknown-field error"),
            Err(error) => error,
        };
        error.to_string().rsplit_once(" at line ").unwrap().0.len()
    };
    let diagnostic = closed_json_diagnostic_extent_for_test::<Projection<'_>>(&bytes).unwrap();
    let supervisor = HostOperationSupervisor::new(HostOperationBudgets::default(), None).unwrap();
    let original = Arc::new(supervisor.begin(HostOperationClass::Preparation).unwrap());
    let resident = HostServiceAllocator::new(1, 64, 1 << 20).unwrap();
    let metadata = HostServiceAllocator::new(1, 64, 1 << 20).unwrap();
    let owner =
        OriginalActorDecodeOwner::prepare(&original, &resident, &metadata, 1 << 20).unwrap();

    let ((result, identities), events) = TestAllocationObserver::capture_allocation_events(|| {
        TestAllocationObserver::capture_controls([40; 3], || {
            from_json_slice_closed::<Projection<'_>>(&bytes, owner.budget().unwrap())
        })
    })
    .unwrap();
    let Err(ClosedJsonError::Json(error)) = result else {
        panic!("healthy original did not return its actual paid diagnostic");
    };
    assert!(!events.overflow);
    assert_eq!(identities[0], None);
    assert_eq!(identities[1], None);
    assert!(identities[2].is_some());
    assert_eq!(
        events
            .entries()
            .filter(|event| event.allocated && event.bytes == 40)
            .count(),
        3
    );
    assert_eq!(
        events
            .entries()
            .filter(|event| !event.allocated && event.bytes == 40)
            .count(),
        2
    );

    let mut message = MessageIdentity {
        bytes: message_bytes,
        identity: None,
    };
    fmt::write(&mut message, format_args!("{error}")).unwrap();
    assert!(message.identity.is_some());
    let identities = [message.identity, identities[2], None];
    // crucible-lint: allow direct-diagnostic -- reports actual compiled control types, not payment or frame qualification.
    eprintln!(
        "JSON target geometry: PaidJsonError={} ClosedJsonError={} OriginalActorAccountError={}",
        std::mem::size_of::<crucible::owned_decode::PaidJsonError>(),
        std::mem::size_of::<ClosedJsonError>(),
        std::mem::size_of::<crate::OriginalActorAccountError>()
    );

    // Serial position repair has already closed its old boxes. The two live
    // payloads must retain both original credits and custody until physical free.
    let owner = match owner.try_close() {
        Ok(()) => panic!("paid error alias permitted premature original close"),
        Err(owner) => owner,
    };
    original.wait_slice().unwrap();

    let ((), observations) =
        TestAllocationObserver::observe_controls([&resident, &metadata], None, identities, || {
            if unwind {
                let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(move || {
                    let _error = error;
                    panic!("actual paid diagnostic unwind");
                }));
                assert!(outcome.is_err());
            } else {
                drop(error);
            }
        });

    assert!(observations[2].is_none());
    let message = observations[0].unwrap();
    let error_impl = observations[1].unwrap();
    assert_eq!(message.ordinal, 1);
    assert_eq!(error_impl.ordinal, 2);
    for sample in [message, error_impl] {
        assert_eq!(sample.before.original_bytes, sample.after.original_bytes);
        for counter in sample.before.original_bytes {
            assert!(
                counter.unwrap() >= diagnostic,
                "JSON payload freed after original diagnostic credit"
            );
        }
    }
    assert!(owner.try_close().is_ok());
    assert!(resident.reserve_resources(1, 64, 1 << 20).is_ok());
    assert!(metadata.reserve_resources(1, 64, 1 << 20).is_ok());
}

#[test]
fn actual_json_message_and_boxes_close_before_original_credit() {
    paid_payload_closes_before_original_credit(false);
}

#[test]
fn actual_json_unwind_closes_payload_before_original_credit() {
    paid_payload_closes_before_original_credit(true);
}
