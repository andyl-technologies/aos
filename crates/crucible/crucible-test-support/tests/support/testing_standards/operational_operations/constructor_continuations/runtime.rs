//! Binds the retained runtime continuation to its actual physical owner.

use super::{Companion, Contract, facts};

pub(super) const CONTRACT: Contract = Contract {
    package: "crucible-daemon",
    target: "src/qemu_hot_fork_world_factory/runtime",
    required: &[
        (
            r#"observer: Option<PreparedSourceRetirement>, terminal: Option<crate::ProductionVmConstructionPostBody>, source: Option<QemuHotForkSourceWorldLease>,"#,
            1,
        ),
        (
            r#"if self.completed { return Ok(AttemptExecutionReconciliationStep::Complete); }"#,
            1,
        ),
        (
            r#"match observer.finish() { Ok(body) => self.terminal = Some(body), Err(observer) => { self.observer = Some(observer); return Ok(AttemptExecutionReconciliationStep::Progressed); } }"#,
            1,
        ),
        (
            r#"if self.source.is_none() { self.source = finalize_target_terminal::<F>(body); } if self.source.is_none() { return Ok(AttemptExecutionReconciliationStep::Progressed); }"#,
            1,
        ),
        (
            r#"source.restore_retained_service_supervisor()?; self.source_supervision_restored = true;"#,
            1,
        ),
        (r#"drop(self.terminal.take()); self.completed = true;"#, 1),
        (
            r#"if !self.shutdown_complete { return Err(crate::ProductionVmConstructionCleanupError::Retained("Target publication reconciliation preceded actual shutdown",)); }"#,
            1,
        ),
        (r#"body.return_to_main(); drop(self.body.take());"#, 1),
        (
            r#"if self.shutdown_events.is_none() { self.shutdown_events = Some(self.owner_mut()?.shutdown()?);"#,
            1,
        ),
        (r#"Instant::now("#, 0),
        (r#"thread::sleep("#, 0),
        (r#"HostOperationSupervisor::new("#, 0),
    ],
    expressions: &[(r#"observer.retry()"#, 1)],
    identifiers: &[(r#"retry"#, 1)],
    companions: &[
        facts::MAIN_RETIREMENT,
        facts::MAIN_AFTER_BODY,
        Companion {
            path: "crates/crucible/crucible-daemon/src/qemu_hot_fork_world_factory/target_construction.rs",
            required: &[
                (
                    r#"if !return_target_terminal_metadata::<F>(body) { return None; }"#,
                    1,
                ),
                (r#"target.take_terminal_checkout()"#, 1),
            ],
        },
    ],
};
