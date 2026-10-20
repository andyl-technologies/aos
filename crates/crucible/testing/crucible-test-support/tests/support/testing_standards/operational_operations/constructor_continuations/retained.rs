//! Binds the retained retained continuation to its actual physical owner.

use super::{Contract, facts};

pub(super) const CONTRACT: Contract = Contract {
    package: "crucible-daemon",
    target: "src/qemu_campaign_lifecycle/source_construction/retained",
    required: &[
        (
            r#"Self::Api { owner, handoff } => (handoff, owner.retry_reserved_publication()?),"#,
            1,
        ),
        (
            r#"let Some(receipt) = published else { return Err("same Source publication has no retained cleanup receipt"); }; *slot = Some(SourceCleanupHandoff::new(receipt));"#,
            1,
        ),
        (
            r#"if let Some(handoff) = self.handoff_mut() && !matches!(handoff.stage(), Ok(ProductionVmCleanupStage::Complete)) { return Err(self); }"#,
            1,
        ),
        (
            r#"if let Some(handoff) = self.handoff_mut() && !handoff.retain_post_body() { return Err(self); }"#,
            1,
        ),
        (
            r#"let history = match owner.into_history() { Ok(history) => history, Err(owner) => { self.retained_install = Some(owner);"#,
            1,
        ),
        (
            r#"let attempt = receipt.retry(); let stage = receipt.stage(); if !matches!(stage, Ok(ProductionVmCleanupStage::Complete))"#,
            1,
        ),
        (
            r#"if self.lifecycle_outstanding { return Err(QemuAttemptProductionVmLifecycleError::SourceInstallRetained { diagnostic: String::from("same factory still retains an outstanding lifecycle relation",), }, ); }"#,
            1,
        ),
        (r#"self.take_completed_install_history()"#, 1),
        (r#"Instant::now("#, 0),
        (r#"thread::sleep("#, 0),
        (r#"HostOperationSupervisor::new("#, 0),
    ],
    expressions: &[
        (r#"owner.retry_reserved_publication()"#, 1),
        (r#"self.retry_retained_source_installation()"#, 2),
        (r#"owner.retry_publication()"#, 1),
        (r#"receipt.retry()"#, 1),
    ],
    identifiers: &[
        (r#"retry"#, 1),
        (r#"retry_publication"#, 2),
        (r#"retry_reserved_publication"#, 1),
        (r#"retry_retained_source_installation"#, 3),
    ],
    companions: &[
        facts::PUBLICATION_FACT,
        facts::MAIN_RETIREMENT,
        facts::RESERVATION,
        facts::QUEUE,
        facts::BODY_DRIVER,
        facts::REPORT_PINS,
        facts::RECEIPT,
    ],
};
