//! Binds immutable origin publication to its actual Main payer and consumers.
//!
//! These facts preserve descriptor admission beneath the same saved Preparation;
//! the ordinary constructor supplies no origin and no accepting Source grant.

use super::super::Companion;

pub(in super::super) const ORIGIN_BODY: Companion = Companion {
    path: "crates/crucible/crucible-daemon/src/qemu_resource_guard/shared_host.rs",
    required: &[
        (
            r#"pub(super) struct SharedHostBody<H> {
    /// Destroys the actual allocator before its final immutable pool alias.
    pub(super) host: Mutex<H>,
    origin: Option<LinuxQemuNativeWorldPreparationOrigin>,
}"#,
            1,
        ),
        (
            r#"pub(super) fn ordinary(host: H) -> Self {
        Self {
            host: Mutex::new(host),
            origin: None,
        }
    }"#,
            1,
        ),
        (
            r#"pub(super) fn with_origin(host: H, origin: LinuxQemuNativeWorldPreparationOrigin) -> Self {
        Self {
            host: Mutex::new(host),
            origin: Some(origin),
        }
    }"#,
            1,
        ),
        (
            r#"pub(super) fn world_origin(
        &self,
    ) -> Result<&LinuxQemuNativeWorldPreparationOrigin, QemuVmRealizationError> {
        if self.host.is_poisoned() {
            return Err(QemuVmRealizationError::ExecutorUnavailable {
                operation: "borrow actual Source World Preparation origin",
                message: String::from("host-resource allocator lock is poisoned"),
            });
        }
        self.origin
            .as_ref()
            .ok_or_else(|| QemuVmRealizationError::ExecutorUnavailable {
                operation: "borrow actual Source World Preparation origin",
                message: String::from("shared factory has no prepublished authentic normal pool"),
            })
    }"#,
            1,
        ),
        (
            r#"impl<H> Deref for SharedHostBody<H> {
    type Target = Mutex<H>;

    fn deref(&self) -> &Self::Target {
        &self.host
    }
}"#,
            1,
        ),
        (
            r#"pub(super) fn shared_body_extent<H>() -> Option<usize> {
    let (layout, _) = std::alloc::Layout::new::<(AtomicUsize, AtomicUsize)>()
        .extend(std::alloc::Layout::new::<SharedHostBody<H>>())
        .ok()?;
    Some(layout.pad_to_align().size())
}"#,
            1,
        ),
        (r#"self.host.lock("#, 0),
        (r#"self.host.try_lock("#, 0),
        (r#"Arc::new("#, 0),
        (r#"HostOperationSupervisor::new("#, 0),
        (r#".begin("#, 0),
        (r#"Instant::now("#, 0),
    ],
};

pub(in super::super) const ORIGIN_PUBLICATION: Companion = Companion {
    path: "crates/crucible/crucible-daemon/src/packaged_qemu_executor.rs",
    required: &[
        (
            r#"let factory_bytes = LinuxQemuAttemptHostResourceFactory::normal_pool_control_bytes(capacity)?;
let controls = factory_bytes.checked_add(queue_bytes).ok_or_else(|| {
    QemuVmRealizationError::ExecutorUnavailable {
        operation: "price actual Main pool controls",
        message: String::from("same-bank containing extent overflows"),
    }
})?;
let purpose = normal.claim_native_pool(request, controls,
    crucible_qemu_host::LinuxQemuAttemptHostFactory::normal_shared_descriptor_peak(),
    normal.original(),
).map_err(|source| PackagedQemuExecutorError::NormalNativeAccount(source.into()))?;"#,
            1,
        ),
        (
            r#"let mut concrete_host = opened?;
    let cleanup = if let Some((purpose, queue)) = normal_pool {
        if let Err(source) = concrete_host.bind_normal_pool(purpose) {
            // This freshly opened factory has entered no World constructor.
            // Close its actual namespace descriptors; ACTOR retains the same
            // pool/queue debit and any failed initial admission independently.
            drop(concrete_host);
            return Err(PackagedQemuExecutorError::NormalNativeAccount(source));
        }
        Some(queue.handle())
    } else {
        None
    };
    #[cfg(feature = "private-measurement-domain")]
    let concrete_host = {
        let mut host = concrete_host;
        if let Some(binding) = binding {
            let original = config
                .original_preparation
                .as_ref()
                .ok_or(PackagedQemuExecutorError::MissingOriginalFactoryPreparation)?;
            if let Err(source) = original.verify_factory_binding(&binding) {
                // Identity includes a live original check. Its refusal after
                // open cannot turn field Drop into certified retirement.
                std::mem::forget(host);
                return Err(PackagedQemuExecutorError::OriginalFactoryBinding(source));
            }
            let bound = host.bind_original_accounts(binding);
            let after = original.boundary();
            if let Err(source) = bound {
                std::mem::forget(host);
                return Err(PackagedQemuExecutorError::OriginalFactoryBind {
                    source,
                    original_after: after.err(),
                });
            }
            if let Err(source) = after {
                std::mem::forget(host);
                return Err(PackagedQemuExecutorError::OriginalPreparationBoundary(
                    source,
                ));
            }
        }
        host
    };
    Ok(match cleanup {
        Some(cleanup) => SharedQemuAttemptHostResourceFactory::try_with_world_origin(
            concrete_host,
            Some(cleanup),
        )?,
        None => SharedQemuAttemptHostResourceFactory::new(concrete_host),
    })
}"#,
            1,
        ),
        (
            r#"SharedQemuAttemptHostResourceFactory::try_with_world_origin("#,
            1,
        ),
    ],
};

pub(in super::super) const ORIGIN_RUNNERS: Companion = Companion {
    path: "crates/crucible/crucible-daemon/src/qemu_campaign_lifecycle/campaign_run.rs",
    required: &[
        (
            r#"pub fn run_guarded_default_campaign(
    request: GuardedDefaultCampaignRunRequest,
) -> Result<GuardedDefaultCampaignRun, GuardedDefaultCampaignRunError> {
    let host = request
        .execution
        .as_ref()
        .ok_or(GuardedDefaultCampaignRunError::ManagedExecution(
            crucible_control_api::host_operational::HostOperationalError::Unavailable,
        ))?
        .inner
        .host
        .clone();
    run_guarded_default_campaign_with_host(request, host)
}"#,
            1,
        ),
        (
            r#"pub(super) fn run_guarded_default_campaign_with_host<H>(
    request: GuardedDefaultCampaignRunRequest,
    host: SharedQemuAttemptHostResourceFactory<H>,
) -> Result<GuardedDefaultCampaignRun, GuardedDefaultCampaignRunError>
where
    H: QemuAttemptHostResourceFactory + QemuAttemptSelectedHostResourceFactory + Send + 'static,
    H::Owner: Send + 'static,
{"#,
            1,
        ),
        (
            r#"let (runner, execution_evidence) = production_campaign_runner(
    request.lifecycle.clone(), host, store, Arc::clone(&checkpoints),
    Arc::clone(&exact_retention), request.supplemental_finding_oracle.clone(),
    request.verify_determinism_findings,
);"#,
            1,
        ),
        (
            r#"fn production_campaign_runner<H>(
    lifecycle: impl Into<Arc<ProductionVmLifecycleConfig>>,
    host: SharedQemuAttemptHostResourceFactory<H>,
    store: CampaignExecutorStore,
    checkpoints: Arc<ExactCheckpointStore>,
    exact_retention: Arc<CampaignRunFindingExactRetentionSource>,
    supplemental_oracle: Option<Arc<dyn GuardedCampaignFindingOracle>>,
    verify_determinism_findings: bool,
) -> (
    impl CrucibleExecutionRunner<Error = GuardedDefaultCampaignProductionRunnerError>
    + crate::completed_reproduction::PrepareCompletedReproduction,
    QemuAttemptExecutionEvidence,
)
where
    H: QemuAttemptHostResourceFactory + QemuAttemptSelectedHostResourceFactory + Send + 'static,
    H::Owner: Send + 'static,
{"#,
            1,
        ),
        (
            r#"let lifecycle = lifecycle.into();
let production = QemuAttemptProductionVmLifecycleFactory::new(
    lifecycle.clone(), ComposedQemuAttemptResourceGuardFactory::new(host.clone()),
).with_terminal_checkpoints(Arc::clone(&checkpoints));"#,
            1,
        ),
        (
            r#"let replay_production = QemuAttemptProductionVmLifecycleFactory::new(
    lifecycle.clone(), ComposedQemuAttemptResourceGuardFactory::new(host),
).with_terminal_checkpoints(Arc::clone(&checkpoints));"#,
            1,
        ),
        (r#"(runner, execution_evidence)"#, 2),
        (r#"SharedQemuAttemptHostResourceFactory::new("#, 0),
        (
            r#"SharedQemuAttemptHostResourceFactory::try_with_world_origin("#,
            0,
        ),
    ],
};

pub(in super::super) const ORIGIN_FINDING: Companion = Companion {
    path: "crates/crucible/crucible-daemon/src/qemu_campaign_lifecycle/campaign_run/finding_branch.rs",
    required: &[
        (
            r#"let (runner, _) = production_campaign_runner(
    lifecycle, owner.inner.host.clone(), store.clone(), owner.inner.checkpoints.clone(),
    exact_retention.clone(), None, owner.inner.config.verifies_determinism_findings(),
);"#,
            1,
        ),
        (r#"SharedQemuAttemptHostResourceFactory::new("#, 0),
        (
            r#"SharedQemuAttemptHostResourceFactory::try_with_world_origin("#,
            0,
        ),
    ],
};

pub(in super::super) const ORIGIN_OWNER: Companion = Companion {
    path: "crates/crucible/crucible-daemon/src/packaged_qemu_executor/guarded.rs",
    required: &[(
        r#"pub(crate) struct GuardedOwnerInner {
    pub(crate) actor: CampaignActorPort<DirectoryAssignmentLedger, PackagedAttemptAdmission>,
    pub(crate) config: PackagedQemuExecutorConfig,
    pub(crate) repository: Arc<CampaignRepository>,
    pub(crate) planner: crucible_campaign::PlannerAuthorityKey,
    debugger: Option<crucible_campaign::DebuggerAuthorityKey>,
    pub(crate) checkpoints: Arc<ExactCheckpointStore>,
    pub(crate) host: SharedQemuAttemptHostResourceFactory<LinuxQemuAttemptHostResourceFactory>,
    pub(crate) lifecycle_cleanup: Option<Arc<crate::lifecycle_cleanup::LifecycleCleanupQueue>>,"#,
        1,
    )],
};
