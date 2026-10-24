//! Sender construction retains the explicit original on admission refusal.
//!
//! A real seventeen-byte RAM root has independent storage funding. The finite
//! caller and foreign ambient account confer no whole-world execution authority.

use super::*;

enum AdmissionCut {
    Healthy,
    Entry,
    FrameCredit,
    FinalValidation,
    OfferFinalValidation,
}

fn construct_sender(cut: AdmissionCut) {
    let directory = tempfile::tempdir().unwrap();
    let backend_quota = ObservedQuota::with_limit(32 << 20);
    let store = directory_store(directory.path(), &backend_quota);
    let backend_original = fixture_original(&store);
    let root = store
        .capture(
            topology(17),
            Scope::Exact,
            &mut patterned,
            &Retention::default(),
            &backend_original,
            &mut || Ok(()),
        )
        .unwrap();
    let offer = archive_offer(&root, 64);
    // Sender offers admit both bounded root-decoder overlaps, independently
    // of this fixture's small stored image and retained caller prepayment.
    let quota = ObservedQuota::with_limit(128 << 20);
    let original = DecodeBudget::for_store(quota.clone()).unwrap();
    original.charge_bytes(8197).unwrap();
    let admitted = quota.used();
    let make_sender = || {
        RamTransferSender::new(
            store.clone(),
            root.clone(),
            [71; 32],
            ContentId::parse(&offer.whole_world_root).unwrap(),
            &offer.destination,
            offer.durable_placements,
            offer.limits,
            &original,
        )
    };

    match cut {
        AdmissionCut::Healthy | AdmissionCut::OfferFinalValidation => {}
        AdmissionCut::Entry => quota.revoked.store(true, Ordering::SeqCst),
        AdmissionCut::FrameCredit => {
            // Observe the actual entry and diagnostic-slot admission prefix.
            // Revoke at the following request for the first offer-frame credit.
            let before = quota.verifications.load(Ordering::SeqCst);
            original.verify_live().unwrap();
            let account = crate::ram::store_boundary::WorkAccount::new(&original).unwrap();
            let prefix = quota.verifications.load(Ordering::SeqCst) - before;
            drop(account);
            assert_eq!(quota.used(), admitted);
            quota
                .revoke_after_verifications
                .store(prefix + 1, Ordering::SeqCst);
        }
        AdmissionCut::FinalValidation => {
            // The genuine healthy constructor supplies the verification count;
            // closing it returns every temporary loan before the refusal run.
            let before = quota.verifications.load(Ordering::SeqCst);
            let sender = make_sender().unwrap();
            let complete = quota.verifications.load(Ordering::SeqCst) - before;
            drop(sender);
            assert_eq!(quota.used(), admitted);
            assert!(complete > 1);
            quota
                .revoke_after_verifications
                .store(complete, Ordering::SeqCst);
        }
    }

    let foreign_quota = ObservedQuota::new();
    let foreign = DecodeBudget::for_store(foreign_quota.clone()).unwrap();
    foreign.charge_bytes(239).unwrap();
    let foreign_requests = foreign_quota.reservations.load(Ordering::SeqCst);
    let foreign_scope = foreign.enter();
    let result = make_sender();

    if matches!(cut, AdmissionCut::Healthy) {
        let mut sender = result.ok().unwrap();
        // The initial response consumes its constructor credit; the repeated
        // offer must reserve and return its own real frame credit.
        for _ in 0..2 {
            let response = sender.offer().unwrap();
            assert_eq!(response.message().operation, [71; 32]);
            assert_eq!(
                response.message().control,
                crucible_qemu_protocol::ram_transfer::RamTransferControl::Offer(offer.clone())
            );
            drop(response);
        }
        drop(sender);
        assert_eq!(quota.used(), admitted);
    } else {
        let error = if matches!(cut, AdmissionCut::OfferFinalValidation) {
            let mut sender = result.ok().unwrap();
            drop(sender.offer().unwrap());
            let retained_sender = quota.used();
            let before = quota.verifications.load(Ordering::SeqCst);
            let response = sender.offer().unwrap();
            let complete = quota.verifications.load(Ordering::SeqCst) - before;
            drop(response);
            assert_eq!(quota.used(), retained_sender);
            assert!(complete > 1);

            quota
                .revoke_after_verifications
                .store(complete, Ordering::SeqCst);
            let error = sender.offer().err().unwrap();
            drop(sender);
            error
        } else {
            result.err().unwrap()
        };
        assert!(quota.revoked.load(Ordering::SeqCst));
        let mut cause = Some(&error as &(dyn Error + 'static));
        let mut actual_revocation = false;
        while let Some(current) = cause {
            if current.is::<RevokedOriginalAuthority>() {
                actual_revocation = true;
                break;
            }
            cause = current.source();
        }
        assert!(actual_revocation);
        assert_eq!(
            foreign_quota.reservations.load(Ordering::SeqCst),
            foreign_requests
        );

        drop(foreign_scope);
        drop(foreign);
        let retained_foreign = foreign_quota.used();
        drop(original);
        let retained_original = quota.used();
        drop(error);
        assert_eq!((quota.used(), foreign_quota.used()), (0, 0));
        assert_eq!((retained_original, retained_foreign), (admitted, 0));
        return;
    }

    assert_eq!(
        foreign_quota.reservations.load(Ordering::SeqCst),
        foreign_requests
    );
    drop(foreign_scope);
    drop(foreign);
    drop(original);
    assert_eq!((quota.used(), foreign_quota.used()), (0, 0));
}

#[test]
fn sender_constructor_preserves_its_actual_ram_offer_and_returns_temporary_credit() {
    construct_sender(AdmissionCut::Healthy);
}

#[test]
fn sender_constructor_entry_refusal_retains_explicit_original() {
    construct_sender(AdmissionCut::Entry);
}

#[test]
fn sender_constructor_frame_credit_refusal_retains_explicit_original() {
    construct_sender(AdmissionCut::FrameCredit);
}

#[test]
fn sender_constructor_final_validation_refusal_retains_explicit_original() {
    construct_sender(AdmissionCut::FinalValidation);
}

#[test]
fn sender_repeated_offer_final_refusal_retains_original_after_sender_close() {
    construct_sender(AdmissionCut::OfferFinalValidation);
}
