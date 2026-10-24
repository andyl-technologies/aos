//! Binds report and component-file calls to exact physical observations.

use super::super::Contract;

pub(super) const RETIREMENT: Contract = Contract {
    package: "crucible-daemon",
    target: "src/lifecycle_cleanup/prepared_retirement",
    required: &[
        (r#".begin("#, 0),
        (r#"HostOperationSupervisor::new("#, 0),
        (r#"Instant::now("#, 0),
        (r#".begin(HostOperationClass::"#, 0),
        (r#".begin_original_cleanup_control("#, 0),
        (
            r#"if slot.epoch.load(Ordering::Acquire) != self.key.epoch"#,
            3,
        ),
        (r#"self.request_retirement();"#, 2),
        (
            r#"if slot.is(CleanupPhase::TerminalReady) { return Ok(true); }"#,
            1,
        ),
        (r#"if slot.is(CleanupPhase::DestructionRefused)"#, 1),
        (
            r#"attempted.map_err(|_| PreparedSourceRefusal::Pending)?; Ok(false)"#,
            1,
        ),
        (
            r#"let attempted = retry_slot(slot, Some(self.key.epoch))"#,
            1,
        ),
    ],
    expressions: &[
        (r#"fn retry(&mut self)"#, 1),
        (r#"retry_slot(slot, Some(self.key.epoch))"#, 1),
    ],
    identifiers: &[("retry", 1), ("retry_slot", 1)],
    companions: &[super::DRIVER_OWNER],
};

pub(super) const RESERVATION: Contract = Contract {
    package: "crucible-daemon",
    target: "src/lifecycle_cleanup/reservation",
    required: &[
        (r#".begin("#, 0),
        (r#"HostOperationSupervisor::new("#, 0),
        (r#"Instant::now("#, 0),
        (r#".begin(HostOperationClass::"#, 0),
        (r#".begin_original_cleanup_control("#, 0),
        (
            r#"if self.terminal_history.is_some() { return Ok(ProductionVmCleanupStage::Complete); }"#,
            1,
        ),
        (
            r#"let observed = self.observe_slot(slot)?; if observed == ProductionVmCleanupStage::Complete { return Ok(observed); } attempted?; Ok(observed)"#,
            1,
        ),
        (
            r#"if self.observed == ProductionVmCleanupStage::Complete { return Ok(self.observed); }"#,
            2,
        ),
        (r#"let attempted = retry_slot(slot, Some(self.epoch))"#, 1),
        (
            r#"assert!(super::driver::retry_body_and_controls(&slot, 1)"#,
            1,
        ),
        (r#"super::driver::retry_body_and_controls(&slot, 1)"#, 2),
    ],
    expressions: &[
        (r#"fn retry(&mut self)"#, 1),
        (r#"retry_slot(slot, Some(self.epoch))"#, 1),
        (r#"super::driver::retry_body_and_controls(&slot, 1)"#, 2),
    ],
    identifiers: &[
        ("retry", 1),
        ("retry_slot", 1),
        ("retry_body_and_controls", 2),
    ],
    companions: &[super::DRIVER_OWNER],
};

pub(super) const FILE_CELL: Contract = Contract {
    package: "crucible-daemon",
    target: "src/lifecycle_cleanup/reservation/tests/file_cell",
    required: &[
        (r#".begin("#, 0),
        (r#"HostOperationSupervisor::new("#, 0),
        (r#"Instant::now("#, 0),
        (r#".begin(HostOperationClass::"#, 0),
        (r#".begin_original_cleanup_control("#, 0),
        (r#"require_file_only(slot)?;"#, 4),
        (
            r#"if expected.is_some_and(|expected| expected != epoch)"#,
            1,
        ),
        (
            r#"if slot.completed_epoch.load(Ordering::Acquire) >= epoch { return Ok(()); }"#,
            1,
        ),
        (
            r#"if slot.controls_closed_epoch.load(Ordering::Acquire) < epoch"#,
            1,
        ),
        (
            r#"service.role.is_some() || service.start.is_some() || service.return_body.is_some()"#,
            1,
        ),
        (
            r#"slot.worlds_returned_epoch.load(Ordering::Acquire) != 0"#,
            1,
        ),
        (
            r#"super::super::super::driver::retry_body_and_controls(slot, epoch)"#,
            1,
        ),
    ],
    expressions: &[(
        r#"super::super::super::driver::retry_body_and_controls(slot, epoch)"#,
        1,
    )],
    identifiers: &[("retry_file_cell", 1), ("retry_body_and_controls", 1)],
    companions: &[super::DRIVER_OWNER],
};

pub(super) const SHARED_FILE: Contract = Contract {
    package: "crucible-daemon",
    target: "src/lifecycle_cleanup/reservation/tests/shared_source_tests",
    required: &[
        (
            r#"assert!(matches!(cell.first_failure, Some(crate::ProductionVmConstructionCleanupError::Poisoned))); assert!(!cell.owner_cleanup_complete); assert!(!cell.owner_post_body_taken);"#,
            1,
        ),
        (
            r#"assert_eq!(selected.slot.worlds_returned_epoch.load(Ordering::Acquire), 0); assert_eq!(selected.slot.completed_epoch.load(Ordering::Acquire), 0);"#,
            1,
        ),
        (
            r#"assert_eq!(loop_failure_message(first).as_ptr(), raw_identity);"#,
            1,
        ),
        (
            r#"assert_eq!((retained.dev(), retained.ino()), identity);"#,
            1,
        ),
        (
            r#"assert_eq!(selected.slot.completed_epoch.load(Ordering::Acquire), 0);"#,
            2,
        ),
        (r#".begin("#, 0),
        (r#"HostOperationSupervisor::new("#, 0),
        (r#"Instant::now("#, 0),
        (r#".begin(HostOperationClass::"#, 0),
        (r#".begin_original_cleanup_control("#, 0),
        (
            r#"Arc::get_mut(shared).ok_or(Self::Failure::SharedAliasesPending)?"#,
            1,
        ),
        (
            r#"self.file = body.file.take(); drop(self.shared.take());"#,
            1,
        ),
        (
            r#"if let Some(first) = self.first.take() { return Err(first); } drop(self.file.take());"#,
            1,
        ),
        (
            r#"assert_eq!(&**retained as *const _ as *const (), owner_identity);"#,
            1,
        ),
        (
            r#"assert_eq!(cleanup_calls.load(Ordering::Acquire), 0);"#,
            2,
        ),
        (
            r#"assert_eq!(cleanup_calls.load(Ordering::Acquire), 1);"#,
            1,
        ),
        (r#"assert!(retry_slot(&selected.slot, Some(149))"#, 4),
        (r#"assert!(retry_slot(&selected.slot, Some(150))"#, 1),
    ],
    expressions: &[
        (r#"retry_slot(&selected.slot, Some(149))"#, 4),
        (r#"retry_slot(&selected.slot, Some(150))"#, 1),
    ],
    identifiers: &[("retry_cleanup", 2), ("retry_slot", 5)],
    companions: &[super::DRIVER_OWNER],
};

pub(super) const FILE_TESTS: Contract = Contract {
    package: "crucible-daemon",
    target: "src/lifecycle_cleanup/reservation/tests",
    required: &[
        (r#".begin("#, 6),
        (r#"HostOperationSupervisor::new("#, 6),
        (r#"Instant::now("#, 0),
        (r#".begin(HostOperationClass::"#, 6),
        (r#".begin_original_cleanup_control("#, 0),
        (r#"ProductionVmNodeLauncher::finish(self)"#, 1),
        (
            r#"assert!(fixture.slot.is(CleanupPhase::DestructionRefused));"#,
            4,
        ),
        (r#"assert_eq!(attempts.load(Ordering::Acquire), 1);"#, 1),
        (r#"assert_eq!(callbacks.load(Ordering::Acquire), 1);"#, 2),
        (
            r#"assert_eq!(slot.completed_epoch.load(Ordering::Acquire), epoch);"#,
            1,
        ),
        (r#"assert!(retry_file_cell(&selected.slot, Some(7))"#, 1),
        (r#"assert!(retry_slot(&selected.slot, Some(7))"#, 1),
        (r#"assert!(retry_slot(&selected.slot, Some(19))"#, 1),
        (r#"assert_eq!(handoff.retry()"#, 2),
        (r#"assert!(retry_file_cell(&slot, Some(epoch))"#, 1),
        (r#"let work = retry_file_cell(&selected.slot, Some(71))"#, 1),
        (r#"let first = retry_slot(&selected.slot, Some(91))"#, 1),
        (
            r#"let first = retry_file_cell(&selected.slot, Some(92))"#,
            1,
        ),
        (
            r#"let first = retry_file_cell(&selected.slot, Some(93))"#,
            1,
        ),
        (
            r#"assert!(prepared_driver::retry_body_in_place(&fixture.slot, &mut prepared)"#,
            2,
        ),
        (
            r#"assert!(prepared_driver::retry_prepared(&fixture.slot, 42)"#,
            2,
        ),
        (r#"assert!(retry_slot(&fixture.slot, Some(51))"#, 1),
        (r#"assert!(retry_slot(&fixture.slot, Some(52))"#, 2),
    ],
    expressions: &[
        (r#"retry_file_cell(&selected.slot, Some(7))"#, 3),
        (r#"retry_slot(&selected.slot, Some(7))"#, 1),
        (r#"retry_slot(&selected.slot, Some(19))"#, 1),
        (r#"retry()"#, 2),
        (r#"retry_file_cell(&slot, Some(epoch))"#, 2),
        (r#"retry_file_cell(&selected.slot, Some(71))"#, 1),
        (r#"retry_slot(&selected.slot, Some(91))"#, 1),
        (r#"retry_file_cell(&selected.slot, Some(92))"#, 2),
        (r#"retry_file_cell(&selected.slot, Some(93))"#, 2),
        (
            r#"prepared_driver::retry_body_in_place(&fixture.slot, &mut prepared)"#,
            2,
        ),
        (r#"prepared_driver::retry_prepared(&fixture.slot, 42)"#, 2),
        (r#"retry_slot(&fixture.slot, Some(51))"#, 1),
        (r#"retry_slot(&fixture.slot, Some(52))"#, 2),
    ],
    identifiers: &[
        ("retry_cleanup", 3),
        ("retry_file_cell", 11),
        (
            "exact_retry_preserves_siblings_and_history_until_receipt_observes_close",
            1,
        ),
        ("retry_slot", 6),
        ("retry", 2),
        ("retry_body_in_place", 2),
        ("retry_prepared", 2),
    ],
    companions: &[super::DRIVER_OWNER, super::FILE_ONLY],
};
