//! Binds the retained installation continuation to its actual physical owner.

use super::{Contract, facts};

pub(super) const CONTRACT: Contract = Contract {
    package: "crucible-daemon",
    target: "src/qemu_hot_fork_world/lifecycle/installation",
    required: &[
        (
            r#"let published = failure.retry_reserved_publication(); self.construction = Some(failure);"#,
            1,
        ),
        (
            r#"let attempt = handoff.retry(); let stage = handoff.stage().map_err(HotForkInstallationRetirementError::Cleanup)?; if stage == ProductionVmCleanupStage::BodyRetained { attempt.map_err(HotForkInstallationRetirementError::Cleanup)?; } Ok(stage)"#,
            1,
        ),
        (
            r#"check_original(original)?; if self.history.post_body.is_some() { return self.restore_terminal_source(original); }"#,
            1,
        ),
        (
            r#"if !self.handoff_confirmed { self.reconciliations.validate_operational_handoff().map_err(Error::Reconciliation)?; self.handoff_confirmed = true; }"#,
            1,
        ),
        (
            r#"self.resources.finish().map_err(Error::Aggregate)?; self.aggregate_released = true; self.auxiliary_resources = None;"#,
            1,
        ),
        (
            r#"if self.advance_cleanup()? != ProductionVmCleanupStage::Complete { return Ok(None); }"#,
            1,
        ),
        (
            r#"Err(handoff) => { self.cleanup_handoff = Some(handoff); return Ok(None); }"#,
            1,
        ),
        (
            r#"check_original(original)?; self.source_world.try_lock().map_err(|_| Error::SourceUnavailable)?.restore_retained_service_supervisor().map_err(Error::SourceRestoration)?; let source = self.source_lease.take().ok_or(Error::MissingSource)?;"#,
            1,
        ),
        (r#"Instant::now("#, 0),
        (r#"thread::sleep("#, 0),
        (r#"HostOperationSupervisor::new("#, 0),
    ],
    expressions: &[
        (r#"failure.retry_reserved_publication()"#, 1),
        (r#"handoff.retry()"#, 1),
        (r#"construction.retry_cleanup()"#, 1),
    ],
    identifiers: &[
        (r#"retry"#, 1),
        (r#"retry_cleanup"#, 1),
        (r#"retry_reserved_publication"#, 1),
    ],
    companions: &[
        facts::PUBLICATION_FACT,
        facts::MAIN_RETIREMENT,
        facts::TARGET_OWNER,
        facts::TARGET_BODIES,
        facts::RESERVATION,
        facts::QUEUE,
        facts::BODY_DRIVER,
        facts::REPORT_PINS,
        facts::RECEIPT,
    ],
};
