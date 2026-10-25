//! Binds controller birth and typed/erased deallocation to the same Main loan.
//!
//! Every alias closes through the existing shared owner; nominal identity and
//! allocation closure never substitute for actual child or Source return.

use super::super::Companion;

pub(super) const MAIN: Companion = Companion {
    path: "crates/crucible/crucible-qemu-host/src/linux_attempt_host/native_account.rs",
    required: &[(
        r#"pub(super) fn prepare_launch_controller(
        &self,
    ) -> Result<RetainedNativeFreshLaunchError, OriginalActorAccountError> {
        let origin = self
            .original
            .as_ref()
            .ok_or(OriginalActorAccountError::Unavailable)?;
        let Some(normal) = origin.normal.as_ref() else {
            #[cfg(test)]
            return Ok(OriginalNativeFreshLaunchError::prepare_unissued(
                &origin.preparation,
            ));
            #[cfg(not(test))]
            return Err(OriginalActorAccountError::Unavailable);
        };
        let (_, peak, descriptors) =
            source_host_peak().map_err(|_| OriginalActorAccountError::Unavailable)?;
        let host = normal.reserve_source_host_purpose(peak, descriptors, &origin.preparation)?;
        let funding = LaunchControllerFunding::reserve(host, &origin.preparation)?;

        Ok(OriginalNativeFreshLaunchError::prepare(
            &origin.preparation,
            funding,
        ))
    }"#,
        1,
    )],
};

pub(super) const CONTROLLER: Companion = Companion {
    path: "crates/crucible/crucible-qemu-host/src/linux_attempt_host/original_node/retained_error.rs",
    required: &[
        (
            r#"pub(in crate::linux_attempt_host) struct LaunchControllerFunding {
    pub(in crate::linux_attempt_host) host: AuthenticatedSourceHostPurpose,
    _control: SourceHostControlLease,
    pub(super) helper_first: Option<crate::spawn::helper_first::HelperFirstJournal>,
}"#,
            1,
        ),
        (
            r#"impl LaunchControllerFunding {
    /// Reserves the controller's actual Main loan before its shared allocation.
    ///
    /// # Errors
    /// Refuses exhausted Main capacity or a different, expired Original.
    pub(in crate::linux_attempt_host) fn reserve(
        host: AuthenticatedSourceHostPurpose,
        original: &HostOperationGuard,
    ) -> Result<Self, OriginalActorAccountError> {
        let bytes = controller_peak_bytes()?;
        let control = host.reserve_controls(0, bytes)?;
        control.verify_original_capacity(original, 0, bytes)?;

        let first_bytes = crate::spawn::helper_first::control_peak_bytes()
            .ok_or(OriginalActorAccountError::Unavailable)?;
        let helper_first = host.reserve_controls(0, first_bytes)?;
        helper_first.verify_original_capacity(original, 0, first_bytes)?;

        Ok(Self {
            host,
            _control: control,
            helper_first: Some(crate::spawn::helper_first::HelperFirstJournal::new(
                helper_first,
            )),
        })
    }
}"#,
            1,
        ),
        (
            r#"pub(in crate::linux_attempt_host) fn controller_peak_bytes()
-> Result<u64, OriginalActorAccountError> {
    SharedOperationalCause::<OriginalNativeFreshLaunchError>::allocation_bytes()
        .ok()
        .and_then(|bytes| bytes.checked_add(std::mem::size_of::<OriginalNativeFreshLaunchError>()))
        .and_then(|bytes| u64::try_from(bytes).ok())
        .ok_or(OriginalActorAccountError::Unavailable)
}"#,
            1,
        ),
        (
            r#"pub struct RetainedNativeFreshLaunchError {
    source: SharedOperationalCause<OriginalNativeFreshLaunchError>,
}"#,
            1,
        ),
        (
            r#"impl RetainedNativeFreshLaunchError {
    pub(super) fn new(source: OriginalNativeFreshLaunchError) -> Self {
        Self {
            source: SharedOperationalCause::new(source),
        }
    }

    /// Saves the initiating refusal in its prebirth controller before a postcut.
    ///
    /// Sharing this same owner neither allocates another diagnostic body nor
    /// transfers any retained child or cleanup authority.
    pub(super) fn retain_primary(&self, primary: FreshLaunchCause) -> Self {
        self.record(primary, None);
        self.clone()
    }

    /// Shares the same concrete original through the portable backend boundary.
    ///
    /// This observer allocates no new body and retains the original error's
    /// downcast identity. It grants no operation, cleanup or return authority.
    #[must_use]
    pub fn backend_cause(&self) -> BackendOperationalCause {
        self.source.backend_cause()
    }

    /// Compares existing controller allocations without authorizing their use.
    #[must_use]
    pub fn same_owner(&self, other: &Self) -> bool {
        self.source == other.source
    }
}"#,
            1,
        ),
        (
            r#"impl Deref for RetainedNativeFreshLaunchError {
    type Target = OriginalNativeFreshLaunchError;

    fn deref(&self) -> &Self::Target {
        self.source.source_ref()
    }
}"#,
            1,
        ),
        (
            r#"impl AsRef<OriginalNativeFreshLaunchError> for RetainedNativeFreshLaunchError {
    fn as_ref(&self) -> &OriginalNativeFreshLaunchError {
        self.source.source_ref()
    }
}"#,
            1,
        ),
        (
            r#"impl Error for RetainedNativeFreshLaunchError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        Some(self.source.source_ref())
    }
}"#,
            1,
        ),
    ],
};
pub(super) const ORIGINAL: Companion = Companion {
    path: "crates/crucible/crucible-qemu-host/src/linux_attempt_host/original_node.rs",
    required: &[
        (
            r#"pub struct OriginalNativeFreshLaunchError {
    origin: Arc<HostOperationGuard>,
    cleanup: OnceLock<Result<Arc<HostOperationGuard>, HostSupervisionError>>,
    primary: OnceLock<FreshLaunchCause>,
    original_after: OnceLock<HostSupervisionError>,
    node: Mutex<RetainedLaunch>,
    child_borrowed: std::sync::atomic::AtomicBool,
    helper: Mutex<helper_receiver::HelperDebt>,
    source_host: Option<retained_error::LaunchControllerFunding>,
    helper_first: OnceLock<crate::QemuIssuedHelperFailure>,
    exact_launch: exact_artifacts::ExactArtifactCell<
        crate::supervision::exact_restore::QemuExactRestoreArtifacts,
    >,
    workspace: Mutex<Option<crate::spawn::OriginalDeviceDigestWorkspace>>,
}"#,
            1,
        ),
        (
            r#"pub(super) fn prepare(
        origin: &Arc<HostOperationGuard>,
        funding: retained_error::LaunchControllerFunding,
    ) -> RetainedNativeFreshLaunchError {
        Self::prepare_body(origin, Some(funding))
    }"#,
            1,
        ),
        (
            r#"fn prepare_body(
        origin: &Arc<HostOperationGuard>,
        mut funding: Option<retained_error::LaunchControllerFunding>,
    ) -> RetainedNativeFreshLaunchError {
        let helper = helper_receiver::HelperDebt::new(
            funding
                .as_mut()
                .and_then(|funding| funding.helper_first.take()),
        );

        RetainedNativeFreshLaunchError::new(Self {
            origin: Arc::clone(origin),
            cleanup: OnceLock::new(),
            primary: OnceLock::new(),
            original_after: OnceLock::new(),
            node: Mutex::new(RetainedLaunch::default()),
            child_borrowed: std::sync::atomic::AtomicBool::new(false),
            helper: Mutex::new(helper),
            source_host: funding,
            helper_first: OnceLock::new(),
            exact_launch: exact_artifacts::ExactArtifactCell::default(),
            workspace: Mutex::new(None),
        })
    }"#,
            1,
        ),
        (
            r#"pub(super) fn retained_source_host(
        &self,
    ) -> Result<
        &crucible_host_resources::host_services::process_birth::AuthenticatedSourceHostPurpose,
        OriginalAccountCheckError,
    > {
        self.source_host
            .as_ref()
            .map(|funding| &funding.host)
            .ok_or(OriginalAccountCheckError::Unavailable)
    }"#,
            1,
        ),
    ],
};

pub(super) const SHARED: Companion = Companion {
    path: "crates/crucible/crucible-engine/src/backend/shared_cause.rs",
    required: &[
        (
            r#"pub struct SharedOperationalCause<E: Error + Send + Sync + 'static> {
    shared: Option<Arc<E>>,
}"#,
            1,
        ),
        (
            r#"pub fn new(source: E) -> Self {
        Self {
            shared: Some(Arc::new(source)),
        }
    }"#,
            1,
        ),
        (
            r#"pub fn backend_cause(&self) -> BackendOperationalCause {
        BackendOperationalCause::from_shared(Arc::clone(self.shared()))
    }"#,
            1,
        ),
        (
            r#"impl<E: Error + Send + Sync + 'static> Clone for SharedOperationalCause<E> {
    fn clone(&self) -> Self {
        Self {
            shared: self.shared.clone(),
        }
    }
}"#,
            1,
        ),
        (
            r#"impl<E: Error + Send + Sync + 'static> Drop for SharedOperationalCause<E> {
    fn drop(&mut self) {
        if let Some(shared) = self.shared.take() {
            drop(Arc::into_inner(shared));
        }
    }
}"#,
            1,
        ),
        (
            r#"impl<E: Error + Send + Sync + 'static> ClosedOperationalCause for E {
    fn close(self: Arc<Self>) {
        drop(Arc::into_inner(self));
    }
}"#,
            1,
        ),
    ],
};
pub(super) const ERASED: Companion = Companion {
    path: "crates/crucible/crucible-engine/src/backend/error.rs",
    required: &[
        (
            r#"impl Clone for BackendOperationalCause {
    fn clone(&self) -> Self {
        Self(self.0.clone())
    }
}"#,
            1,
        ),
        (
            r#"impl Drop for BackendOperationalCause {
    fn drop(&mut self) {
        if let Some(shared) = self.0.take() {
            shared.close();
        }
    }
}"#,
            1,
        ),
        (
            r#"pub(super) fn from_shared<E: Error + Send + Sync + 'static>(source: Arc<E>) -> Self {
        Self(Some(source))
    }"#,
            1,
        ),
    ],
};
pub(super) const API: Companion = Companion {
    path: "crates/crucible/crucible-control-api/src/lifecycle/backend_error.rs",
    required: &[
        (
            r#"pub struct LifecycleBackendConstructionError {
    source: BackendOperationalCause,
}"#,
            1,
        ),
        (
            r#"pub fn from_operational(source: BackendOperationalCause) -> Self {
        Self { source }
    }"#,
            1,
        ),
        (
            r#"pub fn new(source: impl Error + Send + Sync + 'static) -> Self {
        Self {
            source: BackendOperationalCause::new(source),
        }
    }"#,
            1,
        ),
        (
            r#"impl Error for LifecycleBackendConstructionError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        self.source.source()
    }
}"#,
            1,
        ),
    ],
};

pub(super) const CLAIM: Companion = Companion {
    path: "crates/crucible/crucible-qemu-host/src/linux_attempt_host/original_roster.rs",
    required: &[(
        r#"let controller = slot
            .credit
            .as_ref()
            .ok_or(OriginalActorAccountError::Unavailable)?
            .prepare_launch_controller()?;
        slot.source_controller = Some(controller);
        slot.source_cleanup_assigned = false;
        state.next_generation = next_generation;
        state.slots[index].active = Some(generation);
        // Publish the funded controller before the independent Original post.
        // A refused post retains the same allocation and excludes slot reuse.
        if let Err(error) = state.slots[index]
            .credit
            .as_ref()
            .ok_or(OriginalActorAccountError::Unavailable)?
            .require_original()
        {
            state.slots[index].launch_abandoned = true;
            return Err(error.into());
        }"#,
        1,
    )],
};

pub(super) const FIRST: Companion = Companion {
    path: "crates/crucible/crucible-qemu-host/src/spawn/helper_first.rs",
    required: &[
        (
            r#"struct HelperCause<Funding> {
    source: OnceLock<QemuSpawnError>,
    _funding: Funding,
}"#,
            1,
        ),
        (
            r#"impl<Funding: fmt::Debug> Error for HelperCause<Funding> {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        self.source.get().map(|source| source as _)
    }
}"#,
            1,
        ),
        (
            r#"pub struct QemuIssuedHelperFailure {
    first: SharedOperationalCause<HelperCause<SourceHostControlLease>>,
}"#,
            1,
        ),
        (
            r#"pub(crate) struct HelperFirstJournal<
    Funding: fmt::Debug + Send + Sync + 'static = SourceHostControlLease,
> {
    first: SharedOperationalCause<HelperCause<Funding>>,
}

impl<Funding: fmt::Debug + Send + Sync + 'static> HelperFirstJournal<Funding> {
    pub(crate) fn new(funding: Funding) -> Self {
        Self {
            first: SharedOperationalCause::new(HelperCause {
                source: OnceLock::new(),
                _funding: funding,
            }),
        }
    }

    fn record_body(self, source: QemuSpawnError) -> SharedOperationalCause<HelperCause<Funding>> {
        // The linear journal is the only initializer, and no observer exists
        // until this consuming method publishes the completed first error.
        if self.first.source_ref().source.set(source).is_err() {
            unreachable!("a linear unpublished helper journal is recorded once");
        }
        self.first
    }
}

impl HelperFirstJournal {
    pub(crate) fn record(self, source: QemuSpawnError) -> QemuIssuedHelperFailure {
        QemuIssuedHelperFailure {
            first: self.record_body(source),
        }
    }
}"#,
            1,
        ),
        (
            r#"impl QemuIssuedHelperFailure {
    /// Borrows the same concrete first error without detaching its funding.
    #[must_use]
    pub fn source_ref(&self) -> &QemuSpawnError {
        match self.first.source_ref().source.get() {
            Some(source) => source,
            None => unreachable!("only a recorded helper journal can be published"),
        }
    }
}"#,
            1,
        ),
        (
            r#"pub(crate) fn control_peak_bytes() -> Option<u64> {
    SharedOperationalCause::<HelperCause<SourceHostControlLease>>::allocation_bytes()
        .ok()?
        .checked_add(std::mem::size_of::<HelperCause<SourceHostControlLease>>())
        .and_then(|bytes| u64::try_from(bytes).ok())
}"#,
            1,
        ),
    ],
};

pub(super) const JOURNAL: Companion = Companion {
    path: "crates/crucible/crucible-qemu-host/src/linux_attempt_host/original_node/helper_receiver.rs",
    required: &[
        (
            r#"pub(super) struct HelperDebt {
    pub(super) child: Option<crate::node::RetainedChild>,
    lender: Option<crate::linux_attempt_host::SourceCleanupLender>,
    first: Option<SharedFirst>,
    unshared_first: Option<crate::QemuSpawnError>,
    first_journal: Option<crate::spawn::helper_first::HelperFirstJournal>,
    before: Option<HostSupervisionError>,
    source_after: Option<HostSupervisionError>,
    after: Option<HostSupervisionError>,
    output: Option<RetainedHelperOutput>,
    panicked: bool,
    probe_prepared: bool,
    effect_original: Option<crate::QemuHotForkSourceOriginal>,
    // This borrower outlives both the actual child and its retained captures.
    controls: Option<crucible_host_resources::host_services::process_birth::SourceHostControlLease>,
    first_cleanup: Option<crate::QemuNodeError>,
    latest_cleanup: Option<crate::QemuNodeError>,
}"#,
            1,
        ),
        (
            r#"pub(super) fn new(
        first_journal: Option<crate::spawn::helper_first::HelperFirstJournal>,
    ) -> Self {
        let mut debt = Self::default();
        debt.first_journal = first_journal;
        debt
    }"#,
            1,
        ),
        (
            r#"fn first_cause(&self) -> Option<&crate::QemuSpawnError> {
        self.first
            .as_ref()
            .map(SharedFirst::source_ref)
            .or(self.unshared_first.as_ref())
    }"#,
            1,
        ),
        (
            r#"fn save_first(&mut self, first: crate::QemuSpawnError) {
        if self.first_cause().is_some() {
            return;
        }
        match self.first_journal.take() {
            Some(journal) => self.first = Some(journal.record(first)),
            // An unissued fixture can retain a local refusal in its existing
            // journal, but cannot publish a shared diagnostic without a payer.
            None => self.unshared_first = Some(first),
        }
    }"#,
            1,
        ),
    ],
};
