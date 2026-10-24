//! Binds the retained Source continuation to its actual physical owner.

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
            r#"pub(crate) fn retry_retained_source_installation(&mut self,) -> Result<(), QemuAttemptProductionVmLifecycleError> { if self.lifecycle_outstanding { return Err(QemuAttemptProductionVmLifecycleError::SourceInstallRetained { diagnostic: "same factory still retains an outstanding lifecycle relation", source: None, }, ); }"#,
            1,
        ),
        (
            r#"pub(super) fn retained_cleanup_report(
    attempt: Result<ProductionVmCleanupStage, LifecycleApiError>,
    stage: Result<ProductionVmCleanupStage, LifecycleApiError>,
) -> QemuAttemptProductionVmLifecycleError {
    QemuAttemptProductionVmLifecycleError::SourceInstallRetained {
        diagnostic: "same Source cleanup body or containing charge remains retained",
        source: SourceInstallationCleanupRefusal::new(attempt.err(), stage.err()),
    }
}"#,
            1,
        ),
        (r#"return Err(retained_cleanup_report(attempt, stage));"#, 1),
        (r#"owner.to_string("#, 0),
        (r#"first.to_string("#, 0),
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
        super::Companion {
            path: "crates/crucible/crucible-daemon/src/qemu_campaign_lifecycle/source_construction/retained_status.rs",
            required: &[
                (
                    r###"#[derive(Debug)]
pub struct SourceInstallationCleanupRefusal {
    cleanup: Option<LifecycleApiError>,
    observation: Option<LifecycleApiError>,
}

impl SourceInstallationCleanupRefusal {
    pub(super) fn new(
        cleanup: Option<LifecycleApiError>,
        observation: Option<LifecycleApiError>,
    ) -> Option<Self> {
        if cleanup.is_none() && observation.is_none() {
            return None;
        }
        Some(Self {
            cleanup,
            observation,
        })
    }

    /// Borrows the refusal returned by the actual cleanup invocation.
    #[must_use]
    pub fn cleanup_error(&self) -> Option<&LifecycleApiError> {
        self.cleanup.as_ref()
    }

    /// Borrows the independent refusal returned by the stage observation.
    #[must_use]
    pub fn observation_error(&self) -> Option<&LifecycleApiError> {
        self.observation.as_ref()
    }
}

impl fmt::Display for SourceInstallationCleanupRefusal {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match (&self.cleanup, &self.observation) {
            (Some(cleanup), Some(observation)) => {
                write!(
                    formatter,
                    "{cleanup}; independent stage observation: {observation}"
                )
            }
            (Some(first), None) | (None, Some(first)) => fmt::Display::fmt(first, formatter),
            (None, None) => unreachable!("a retained cleanup refusal contains an actual error"),
        }
    }
}

impl Error for SourceInstallationCleanupRefusal {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        self.cleanup
            .as_ref()
            .or(self.observation.as_ref())
            .map(|first| first as &dyn Error)
    }
}"###,
                    1,
                ),
                ("assert_eq!(counts.allocations, 0);", 3),
                ("assert_eq!(counts.reallocations, 0);", 3),
                ("assert!(!counts.overflow);", 3),
                (
                    "assert_eq!(pointer(source.cleanup_error().unwrap()), cleanup_pointer);",
                    1,
                ),
                (
                    "assert_eq!(pointer(source.observation_error().unwrap()), observation_pointer);",
                    1,
                ),
                (
                    "assert_eq!(pointer(owner.first_error().unwrap()), original);",
                    1,
                ),
                (
                    "let LifecycleApiError::LoopFactory { message } = error else",
                    1,
                ),
                ("message.as_ptr()", 1),
            ],
        },
        facts::PUBLICATION_FACT,
        facts::MAIN_RETIREMENT,
        facts::RESERVATION,
        facts::QUEUE,
        facts::BODY_DRIVER,
        facts::REPORT_PINS,
        facts::RECEIPT,
    ],
};
