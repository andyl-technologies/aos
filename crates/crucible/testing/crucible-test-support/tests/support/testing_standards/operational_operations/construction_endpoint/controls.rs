//! Binds actual refusal, file identity and nested-history component observations.

use super::super::Companion;

// Each loop keeps repeated refusal and its actual observations in one scope.
// The successful move includes both probes and the final once-only refusal.
pub(super) const REFUSAL_ASSERTION: &str =
    "assert!(lifecycle.retry_retained_debug_construction().is_err());";
pub(super) const POISON_ASSERTION: &str = r#"assert!(matches!(
        lifecycle.retry_retained_debug_construction(),
        Err(ProductionVmConstructionCleanupError::Poisoned)
    ));"#;
pub(super) const BODY_OBSERVATIONS: &str = r#"for _ in 0..2 {
        assert!(lifecycle.retry_retained_debug_construction().is_err());
        let retained = lifecycle.retained_debug_construction.get_mut().unwrap();
        let Some(RetainedDebugConstruction::Unpublished(Some(failure))) = retained else {
            panic!("body-only success cannot consume the owning failure");
        };
        let FailureStorage::Preallocated(custody) = &failure.storage else {
            panic!("the original carrier must remain in its prepaid slot");
        };
        assert_eq!(std::ptr::from_ref(custody.as_ref()), address);
        probe.assert_first(failure.first_error().unwrap());
    }"#;

pub(super) const PAIR_OBSERVATIONS: &str = r#"for _ in 0..2 {
        assert!(lifecycle.retry_retained_debug_construction().is_err());
        let retained = lifecycle.retained_debug_construction.get_mut().unwrap();
        let Some(RetainedDebugConstruction::Unpublished(Some(failure))) = retained else {
            panic!("the actual refused pair cannot be discarded");
        };
        let FailureStorage::Rejected { first, returned } = &failure.storage else {
            panic!("the same canonical pair must remain owned");
        };
        let returned = returned.lock().unwrap();
        let (reservation, owner) = returned.as_ref().unwrap();
        assert_eq!(std::ptr::from_ref(reservation.as_ref()).cast::<()>(), token);
        assert_eq!(std::ptr::from_ref(owner.as_ref()).cast::<()>(), body);
        probe.assert_first(first);
        assert_eq!(cleanup_calls.load(Ordering::SeqCst), 0);
        assert_eq!(drops.load(Ordering::SeqCst), 0);
    }"#;

pub(super) const RECEIPT_OBSERVATIONS: &str = r#"for _ in 0..2 {
        assert!(SourceCleanupHistory::take_returned_constructor(&mut first, &mut receipt).is_err());
        probe.assert_first(first.as_ref().unwrap());
        assert_eq!(
            std::ptr::from_ref(receipt.as_ref().unwrap().as_ref()).cast::<()>(),
            address
        );
        assert!(receipt.as_ref().unwrap().retained_post_body().is_none());
    }"#;

pub(super) const OCCUPIED_SUCCESS: &str = r#"let occupied_body = destination.take().unwrap();
    retained.transfer_history(&mut destination).unwrap();
    incoming_probe.assert_history(destination.as_ref().unwrap());
    occupied_probe.assert_history(&occupied_body);
    assert!(!destination.as_ref().unwrap().has_terminal_custody());
    assert!(retained.transfer_history(&mut destination).is_err());
    drop(destination);
    drop(occupied_body);
    assert_eq!(incoming_probe.drops.load(Ordering::SeqCst), 1);
    assert_eq!(occupied_probe.drops.load(Ordering::SeqCst), 1);"#;

pub(super) const CASES: &[(&str, usize)] = &[
    (REFUSAL_ASSERTION, 4),
    (POISON_ASSERTION, 1),
    (BODY_OBSERVATIONS, 1),
    (PAIR_OBSERVATIONS, 1),
    (RECEIPT_OBSERVATIONS, 1),
    (OCCUPIED_SUCCESS, 1),
    (
        r#"assert!(found, "the original file-owning cause must remain reachable"); self.assert_open();"#,
        1,
    ),
    (
        r#"fn take_post_body(&mut self) -> Result<Option<Self::PostBody>, Self::Failure> { panic!("unavailable publication cannot extract native obligations"); }"#,
        1,
    ),
    (
        r#"fn body_only_cleanup_cannot_clear_the_original_failed_candidate()"#,
        1,
    ),
    (
        r#"fn refused_original_receiver_keeps_the_same_pair_and_typed_first()"#,
        1,
    ),
    (
        r#"fn missing_carrier_keeps_the_actual_incoming_file_owner()"#,
        1,
    ),
    (
        r#"fn additional_original_cause_and_poison_never_clear_the_existing_owner()"#,
        1,
    ),
    (
        r#"fn unavailable_canonical_receipt_preserves_both_original_history_inputs()"#,
        1,
    ),
    (
        r#"fn occupied_history_destination_restores_the_same_actual_diagnostic_owner()"#,
        1,
    ),
    (
        r#"let current = fs::metadata(format!("/proc/self/fd/{}", self.descriptor)).unwrap();
        assert_eq!((current.dev(), current.ino()), self.identity);
        assert_eq!(self.drops.load(Ordering::SeqCst), 0);"#,
        1,
    ),
    (
        r#"let actual = error.source().unwrap().downcast_ref::<FileCause>().unwrap();
        assert_eq!(std::ptr::from_ref(actual), self.cause);
        self.assert_open();"#,
        1,
    ),
    (
        r#"LifecycleHistoryRef::Failure(crate::LifecycleFailureRef::SourceCleanup(
                history,
            )) = record
            {
                history.visit_history(|_, record| {
                    if let LifecycleHistoryRef::Failure(crate::LifecycleFailureRef::Realization(
                        crucible_qemu_host::QemuVmRealizationError::ModelCopy { source },
                    )) = record"#,
        1,
    ),
    (
        r#"if std::ptr::from_ref(actual) == self.cause { found = true; }"#,
        1,
    ),
    (
        r#"assert_eq!(std::ptr::from_ref(custody.as_ref()), address);
        probe.assert_first(failure.first_error().unwrap());"#,
        1,
    ),
    (
        r#"crate::lifecycle_cleanup::LifecycleCleanupHandle::unavailable_reservation_for_test()"#,
        1,
    ),
    (
        r#"assert_eq!(std::ptr::from_ref(reservation.as_ref()).cast::<()>(), token);
        assert_eq!(std::ptr::from_ref(owner.as_ref()).cast::<()>(), body);
        probe.assert_first(first);
        assert_eq!(cleanup_calls.load(Ordering::SeqCst), 0);
        assert_eq!(drops.load(Ordering::SeqCst), 0);"#,
        1,
    ),
    (r#"FailureStorage::Missing(missing)"#, 2),
    (
        r#".retained_hot_fork_disk_files
            .len(),
        1"#,
        1,
    ),
    (
        r#"assert_eq!((current.dev(), current.ino()), identity);"#,
        1,
    ),
    (r#"failure.additional = Some(additional);"#, 1),
    (
        r#"first_probe.assert_first(failure.first_error().unwrap());
    additional_probe.assert_first(failure.additional.as_ref().unwrap());"#,
        1,
    ),
    (
        r#"let _same_slot = lifecycle.retained_debug_construction.lock().unwrap();"#,
        1,
    ),
    (r#"Err(poisoned) => poisoned.into_inner(),"#, 1),
    (
        r#"Some(crate::lifecycle_cleanup::LifecycleCleanupHandle::unavailable_handoff_for_test())"#,
        1,
    ),
    (
        r#"assert!(SourceCleanupHistory::take_returned_constructor(&mut first, &mut receipt).is_err());"#,
        3,
    ),
    (r#"assert!(first.is_none());"#, 1),
    (r#"assert!(receipt.is_none());"#, 1),
    (r#"probe.assert_first(first.as_ref().unwrap());"#, 2),
    (
        r#"assert!(receipt.as_ref().unwrap().retained_post_body().is_none());"#,
        1,
    ),
    (
        r#"assert!(!ProductionVmConstructionPostBody::history_only().has_terminal_custody());"#,
        1,
    ),
    (
        r#"assert!(retained.transfer_history(&mut destination).is_err());"#,
        2,
    ),
    (
        r#"occupied_probe.assert_history(destination.as_ref().unwrap());
    incoming_probe.assert_open();"#,
        1,
    ),
    (
        r#"assert_eq!(std::ptr::from_ref(actual), incoming_probe.cause);"#,
        1,
    ),
    (
        r#"incoming_probe.assert_history(destination.as_ref().unwrap());
    occupied_probe.assert_history(&occupied_body);"#,
        1,
    ),
    (
        r#"assert!(!destination.as_ref().unwrap().has_terminal_custody());"#,
        1,
    ),
    (
        r#"drop(destination);
    drop(occupied_body);
    assert_eq!(incoming_probe.drops.load(Ordering::SeqCst), 1);
    assert_eq!(occupied_probe.drops.load(Ordering::SeqCst), 1);"#,
        1,
    ),
    (r#"assert_eq!(probe.drops.load(Ordering::SeqCst), 1);"#, 3),
    (r#"assert_eq!(drops.load(Ordering::SeqCst), 1);"#, 1),
    (
        r#"assert_eq!(first_probe.drops.load(Ordering::SeqCst), 1);
    assert_eq!(additional_probe.drops.load(Ordering::SeqCst), 1);"#,
        1,
    ),
];

pub(super) const JOIN_CASES: &[(&str, usize)] = &[
    (
        r#"fn containing_first_refusal_keeps_the_already_moved_child_history()"#,
        1,
    ),
    (
        r#"crate::vm_lifecycle::runtime::tests::production_loop_without_backends(&source)"#,
        1,
    ),
    (
        r#"Some(crate::vm_lifecycle::construction::RetainedDebugConstruction::History(Some(history)))"#,
        1,
    ),
    (r#"custody.complete_with(|_| Ok(lifecycle)).unwrap();"#, 1),
    (
        r#"for message in ["first retained report", "second retained report"]"#,
        1,
    ),
    (r#"custody.post_body = Some(destination);"#, 1),
    (
        r#"let original_message = message.as_ptr();
    custody.first = Some(LifecycleApiError::LoopFactory { message });"#,
        1,
    ),
    (
        r#"assert!(ProductionVmCleanupOwner::take_post_body(&mut custody).is_err());"#,
        1,
    ),
    (
        r#"lifecycle.retained_debug_construction.get_mut().unwrap().is_none()"#,
        1,
    ),
    (r#"assert_eq!(message.as_ptr(), original_message);"#, 1),
    (
        r#"crate::LifecycleHistoryRef::Failure(crate::LifecycleFailureRef::SourceCleanup(
            history,
        )) = record
        {
            history.visit_history(|_, record| {
                if let crate::LifecycleHistoryRef::Failure(
                    crate::LifecycleFailureRef::Realization(
                        crucible_qemu_host::QemuVmRealizationError::ModelCopy { source },
                    ),
                ) = record"#,
        1,
    ),
    (
        r#"let actual = source.downcast_ref::<HistoryFile>().unwrap();
                    assert_eq!(std::ptr::from_ref(actual), address);
                    found = true;"#,
        1,
    ),
    (
        r#"assert!(found);
    assert!(!body.has_terminal_custody());
    assert!(!body.has_source_return());
    assert_eq!(drops.load(Ordering::SeqCst), 0);"#,
        1,
    ),
    (
        r#"assert_eq!((current.dev(), current.ino()), identity);

    drop(custody);
    assert_eq!(drops.load(Ordering::SeqCst), 1);"#,
        1,
    ),
];

pub(super) const CASE_EVIDENCE: Companion = Companion {
    path: "crates/crucible/control/crucible-daemon/src/vm_lifecycle/construction/retained_debug/tests.rs",
    required: CASES,
};
pub(super) const JOIN_EVIDENCE: Companion = Companion {
    path: "crates/crucible/control/crucible-daemon/src/vm_lifecycle/construction/custody/post_body/tests.rs",
    required: JOIN_CASES,
};
pub(super) const REFUSING_OWNER: &str = r#"fn retry_cleanup(&mut self) -> Result<(), Self::Failure> {
        self.cleanup_calls.fetch_add(1, Ordering::SeqCst);
        panic!("unavailable publication cannot run the original body");
    }"#;
