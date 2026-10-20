//! Binds existing Source owners, saved Cleanup and physical last-use order.

use super::{Companion, Contract};

pub(super) const PREPARATION: Contract = Contract {
    package: "crucible-daemon",
    target: "src/vm_lifecycle/hot_fork/preparation",
    required: &[
        (
            r#"pub(in crate::vm_lifecycle) fn retry_body(
    &mut self,
) -> Result<(), crate::ProductionVmConstructionCleanupError> {
    self.world.retry_source_retirement_body()
}"#,
            1,
        ),
        (
            r#"pub(in crate::vm_lifecycle) fn take_post_body(
    &mut self,
) -> Result<
    Option<crate::ProductionVmConstructionPostBody>,
    crate::ProductionVmConstructionCleanupError,
> {
    self.world.take_source_retirement_post_body()
}"#,
            1,
        ),
        (
            r#"fn run_once(&mut self, rollback_here: bool) -> Result<(), ()> {
    if self.attempted {
        return Err(());
    }
    self.attempted = true;
    if let Err(first) = self.prepare() {
        self.first = Some(first);
        if rollback_here {
            self.retain_current_disk();
            self.rollback_after_refusal();
        }
        return Err(());
    }
    self.complete = true;
    Ok(())
}"#,
            1,
        ),
        (
            r#"HostOperationSupervisor::new("#,
            0,
        ),
        (
            r#"begin_original_cleanup_control("#,
            0,
        ),
    ],
    expressions: &[
        (
            r#"self.world.retry_source_retirement_body()"#,
            1,
        ),
    ],
    identifiers: &[
        (
            r#"retry_body"#,
            1,
        ),
        (
            r#"retry_source_retirement_body"#,
            1,
        ),
    ],
    companions: &[
        Companion {
            path: "crates/crucible/control/crucible-daemon/src/vm_lifecycle/hot_fork/source_retirement.rs",
            required: super::source::REQUIRED,
        },
        Companion {
            path: "crates/crucible/control/crucible-daemon/src/vm_lifecycle/construction/custody.rs",
            required: &[
                (
                    r#"Phase::SharedSource(source) => source.retry_body()?,"#,
                    1,
                ),
                (
                    r#"Phase::SourceRearmFailure(source) => source.retry_body()?,"#,
                    1,
                ),
                (
                    r#"Phase::SourcePreparation(preparation) => preparation.retry_body()?,"#,
                    1,
                ),
                (
                    r#"self.physically_closed.store(true, Ordering::Release);"#,
                    1,
                ),
            ],
        },
    ],
};

pub(super) const REARM: Contract = Contract {
    package: "crucible-daemon",
    target: "src/vm_lifecycle/hot_fork/rearm_return",
    required: &[
        (
            r#"pub(in crate::vm_lifecycle) fn retry_body(&mut self) -> Result<(), CleanupError> {
    if self.source.is_none() {
        if self.failure.retained_source.is_some() {
            return Err(CleanupError::Retained(
                "rearm failure retains another Source",
            ));
        }
        let lifecycle = self.failure.lifecycle.take().ok_or(CleanupError::Retained(
            "failed Source rearm lifecycle is absent",
        ))?;
        let metadata = self.failure.metadata.get_or_insert_default();
        self.source = Some(ProductionVmHotForkSourceWorld {
            lifecycle: Some(lifecycle),
            continuation: metadata.continuation.take(),
            prepared: std::mem::take(&mut metadata.prepared),
            disk_custody: std::mem::take(&mut metadata.disk_custody),
            cleanup_observer: metadata.cleanup_observer.take(),
            retirement: None,
            target_backends_lent: false,
            #[cfg(feature = "private-measurement-domain")]
            managed_parent_park_history: metadata.managed_parent_park_history.take(),
        });
    }
    self.source
        .as_mut()
        .ok_or(CleanupError::Retained("failed Source rearm body is absent"))?
        .retry_source_retirement_body()
}"#,
            1,
        ),
        (
            r#"pub(in crate::vm_lifecycle) fn take_post_body(
    &mut self,
) -> Result<Option<crate::ProductionVmConstructionPostBody>, CleanupError> {
    let source = self.source.as_mut().ok_or(CleanupError::Retained(
        "failed Source rearm body was not retired",
    ))?;
    if !self.history_transferred {
        let history = source
            .retirement
            .as_mut()
            .filter(|state| state.body_closed)
            .and_then(|state| state.history.as_mut())
            .ok_or(CleanupError::Retained(
                "Source retirement history is unavailable",
            ))?;
        if history.rearm.is_some() {
            return Err(CleanupError::Retained(
                "Source rearm history is already occupied",
            ));
        }
        history.rearm = Some(SourceRearmHistory {
            first: self.failure.first.take(),
            message: std::mem::take(&mut self.failure.message),
            unreconciled_nodes: std::mem::take(&mut self.failure.unreconciled_nodes),
            rollback_diagnostics: std::mem::take(&mut self.failure.rollback_diagnostics),
        });
        self.history_transferred = true;
    }
    source.take_source_retirement_post_body()
}"#,
            1,
        ),
        (
            r#"HostOperationSupervisor::new("#,
            0,
        ),
        (
            r#"begin_original_cleanup_control("#,
            0,
        ),
        (
            r#"Box::new("#,
            0,
        ),
    ],
    expressions: &[
        (
            r#"retry_source_retirement_body()"#,
            1,
        ),
    ],
    identifiers: &[
        (
            r#"retry_body"#,
            1,
        ),
        (
            r#"retry_source_retirement_body"#,
            1,
        ),
    ],
    companions: &[
        Companion {
            path: "crates/crucible/control/crucible-daemon/src/vm_lifecycle/hot_fork/source_retirement.rs",
            required: super::source::REQUIRED,
        },
        Companion {
            path: "crates/crucible/control/crucible-daemon/src/vm_lifecycle/construction/custody.rs",
            required: &[
                (
                    r#"Phase::SharedSource(source) => source.retry_body()?,"#,
                    1,
                ),
                (
                    r#"Phase::SourceRearmFailure(source) => source.retry_body()?,"#,
                    1,
                ),
                (
                    r#"Phase::SourcePreparation(preparation) => preparation.retry_body()?,"#,
                    1,
                ),
                (
                    r#"self.physically_closed.store(true, Ordering::Release);"#,
                    1,
                ),
            ],
        },
    ],
};
