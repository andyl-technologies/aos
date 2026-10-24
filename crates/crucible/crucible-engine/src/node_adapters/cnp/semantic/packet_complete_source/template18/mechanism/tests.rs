//! Exercises real code-source custody and rejects row DATA as mechanism authority.

use super::super::super::tests as fixture;
use super::*;

fn code_source(reactive: bool) -> Rc<PacketCompleteSemanticSource> {
    let coordinator = fixture::coordinator();
    Rc::new(if reactive {
        PacketCompleteSemanticSource::new_reactive_for_collecting_world(
            fixture::installation(&coordinator, 1),
            fixture::reactive(&coordinator, 1),
            coordinator,
            fixture::storage_selection(),
        )
        .unwrap()
    } else {
        PacketCompleteSemanticSource::new_producer_for_collecting_world(
            fixture::installation(&coordinator, 0),
            fixture::producer(),
            coordinator,
            fixture::storage_selection(),
        )
        .unwrap()
    })
}

#[test]
fn ordinary_entry_refuses_a_worker_bound_row_before_clone_and_spends_once() {
    for reactive in [false, true] {
        let code = code_source(reactive);
        let genuine = code
            .native_source_template18_construction_data(usize::MAX)
            .unwrap();
        let mut claimed = genuine;
        // Only the private test can tamper with this DATA row. This pointer is
        // never dereferenced and cannot construct an Rc or sealed mechanism.
        claimed.mechanism = Some(Rc::as_ptr(&code).cast());
        let original_owners = Rc::strong_count(&code);
        let mut attempt = OriginalNativeSourceTemplate18Attempt::default();

        assert_eq!(
            code.native_source_template18_into(&claimed, &mut attempt),
            Err(RuntimeError::ForeignAuthority)
        );
        assert!(attempt.started && attempt.failed);
        assert!(attempt.partial_data().is_none());
        assert_eq!(Rc::strong_count(&code), original_owners);
        assert!(code.native_import18_derivation_mechanism.is_none());
        assert_eq!(attempt.retained_requested_storage_data(0), Ok(0));
        assert_eq!(
            code.native_source_template18_into(&genuine, &mut attempt),
            Err(RuntimeError::DuplicateOperation)
        );
        assert!(attempt.partial_data().is_none());
    }
}

#[test]
fn real_ordinary_initializers_and_template_transfer_keep_mechanism_none() {
    for reactive in [false, true] {
        let code = code_source(reactive);
        assert!(code.native_import18_derivation_mechanism.is_none());
        let row = code
            .native_source_template18_construction_data(usize::MAX)
            .unwrap();
        assert!(row.mechanism.is_none());
        let (retained, transient, scratch) = row.requested_storage_data();
        let exact = retained
            .checked_add(transient)
            .unwrap()
            .checked_add(scratch)
            .unwrap();
        assert!(
            code.native_source_template18_construction_data(exact)
                .is_ok()
        );
        assert!(
            code.native_source_template18_construction_data(exact - 1)
                .is_err()
        );
        let mut attempt = OriginalNativeSourceTemplate18Attempt::default();
        code.native_source_template18_into(&row, &mut attempt)
            .unwrap();

        let observed = attempt.retained_requested_storage_data(usize::MAX).unwrap();
        assert!(observed > 0 && observed <= retained);
        let fresh = attempt.take_completed_data().unwrap();
        assert!(!Rc::ptr_eq(&code, &fresh));
        assert!(fresh.native_import18_derivation_mechanism.is_none());
        assert!(fresh.authenticate_template18_data().is_ok());
        assert_eq!(
            fresh.original_complete_code_retained_storage_precredit_data(observed),
            Ok(observed)
        );
        assert_eq!(
            fresh.original_complete_code_retained_storage_precredit_data(observed - 1),
            Err(RuntimeError::ResourceLimit)
        );
        assert!(fresh.native_import18_birth_construction.is_none());
        assert!(fresh.ack_peer_birth.borrow().is_none());
        assert!(fresh.ack_peer_association.borrow().is_none());
    }
}
