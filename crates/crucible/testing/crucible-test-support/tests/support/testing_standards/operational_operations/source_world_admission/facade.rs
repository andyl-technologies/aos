//! Binds the real facade lookup and once-issued acquisition Original.

use super::super::Companion;

pub(in super::super) const ADMISSION: Companion = Companion {
    path: "crates/crucible/control/crucible-daemon/src/qemu_resource_guard/world_admission.rs",
    required: &[
        (
            r#"pub(crate) struct SourceWorldAdmissionHistory { first: Option<AdmissionFirst>, post: Option<HostSupervisionError>, }"#,
            1,
        ),
        (
            r#"pub(crate) fn first_failure(&self) -> Option<crate::LifecycleFailureRef<'_>> {
        match &self.first {
            Some(AdmissionFirst::Original(first)) => {
                Some(crate::LifecycleFailureRef::Supervision(first))
            }
            // The existing native constructor report retains the typed mutex
            // custody refusal. Its independent Original post stays below.
            Some(AdmissionFirst::Custody) => None,
            None => self
                .post
                .as_ref()
                .map(crate::LifecycleFailureRef::Supervision),
        }
    }"#,
            1,
        ),
        (
            r#"pub(crate) fn post(&self) -> Option<&HostSupervisionError> {
        self.post.as_ref()
    }"#,
            1,
        ),
        (
            r#"pub(super) fn matches(&self, receiver: &NativeWorldBeforeEffects<'_>) -> bool {
    self.selection.same_role(receiver.source_selection()) }"#,
            1,
        ),
        (
            r#"pub(crate) fn take_history(&mut self) -> SourceWorldAdmissionHistory { std::mem::take(&mut self.history) }"#,
            1,
        ),
        (
            r#"pub(super) fn lock_host<'a, H>(
        &mut self,
        host: &'a Mutex<H>,
    ) -> Result<MutexGuard<'a, H>, QemuVmRealizationError> {
        let observed = acquire_host(host, self.preparation.operation());
        if let Some(first) = observed.first {
            self.history.first.get_or_insert(first);
        }
        if let Err(post) = observed.post {
            self.history.post.get_or_insert(post);
        }
        observed.host
    }"#,
            1,
        ),
        (
            r#"fn acquire_host<'a, H>(
    host: &'a Mutex<H>,
    original: &HostOperationGuard,
) -> HostAcquisition<'a, H> {
    acquire_host_with_wait(host, original, || original.wait_for_change())
}"#,
            1,
        ),
        (
            r#"fn acquire_host_with_wait<'a, H>(
    host: &'a Mutex<H>,
    original: &HostOperationGuard,
    mut wait: impl FnMut() -> Result<(), HostSupervisionError>,
) -> HostAcquisition<'a, H> {
    let mut first = None;
    let acquired = (|| {
        loop {
            if let Err(refusal) = original.wait_slice() {
                first = Some(AdmissionFirst::Original(refusal));
                return Err(QemuVmRealizationError::CleanupRetained {
                    operation: "admit shared World under its saved Preparation",
                });
            }
            match host.try_lock() {
                Ok(host) => return Ok(host),
                Err(TryLockError::Poisoned(_)) => {
                    first = Some(AdmissionFirst::Custody);
                    return Err(QemuVmRealizationError::ExecutorUnavailable {
                        operation: "install shared native node World",
                        message: String::from("host-resource allocator lock is poisoned"),
                    });
                }
                Err(TryLockError::WouldBlock) => {
                    if let Err(refusal) = wait() {
                        first = Some(AdmissionFirst::Original(refusal));
                        return Err(QemuVmRealizationError::CleanupRetained {
                            operation: "wait for shared World under its saved Preparation",
                        });
                    }
                }
            }
        }
    })();
    observe_acquisition(acquired, first, original)
}"#,
            1,
        ),
        (
            r#"fn observe_acquisition<'a, H>(
    acquired: Result<MutexGuard<'a, H>, QemuVmRealizationError>,
    first: Option<AdmissionFirst>,
    original: &HostOperationGuard,
) -> HostAcquisition<'a, H> {
    // This post belongs to acquisition, before the infallible constructor-entry
    // seam. Lower claim/window/setup effects retain their own original posts.
    // A successful lower constructor completes Preparation and is not waited again.
    let post = original.wait_slice().map(|_| ());
    let host = match (acquired, &post) {
        (Ok(host), Ok(())) => Ok(host),
        (Ok(host), Err(_)) => {
            drop(host);
            Err(QemuVmRealizationError::CleanupRetained {
                operation: "observe shared World admission post before entry",
            })
        }
        (Err(first), _) => Err(first),
    };
    HostAcquisition { host, first, post }
}"#,
            1,
        ),
        (r#"HostOperationSupervisor::new("#, 0),
        (r#".begin("#, 0),
        (r#".progress("#, 0),
        (r#"Instant::now("#, 0),
    ],
};

pub(in super::super) const FACADE: Companion = Companion {
    path: "crates/crucible/control/crucible-daemon/src/qemu_resource_guard.rs",
    required: &[
        (
            r#"fn world_preparation_origin(
        &self,
    ) -> Result<crucible_qemu_host::LinuxQemuNativeWorldPreparationOrigin, QemuVmRealizationError>
    {
        self.host.world_origin().cloned()
    }"#,
            1,
        ),
        (
            r#"fn begin_world(
        &mut self,
        admission: &mut SourceWorldAdmission,
        resources: AttemptResourceLimits,
        selected_checkpoint: Option<SelectedExactCheckpointRoot>,
        consumer_control_bytes: u64,
        registration: &dyn crate::vm_lifecycle::ProductionHostRamRegistrationFactory,
        before_effects: &mut NativeWorldBeforeEffects<'_>,
    ) -> Result<
        (Self::Owner, Option<SelectedExactCheckpointRoot>),
        QemuAttemptResourceGuardBeginFailure,
    > {
        if !admission.matches(before_effects) {
            return Err(
                QemuAttemptResourceGuardBeginFailure::before_checkpoint_claim(
                    QemuVmRealizationError::CleanupRetained {
                        operation: "match the same Source World admission receiver",
                    },
                    selected_checkpoint,
                ),
            );
        }
        let mut host = match admission.lock_host(&self.host) {
            Ok(host) => host,
            Err(first) => {
                return Err(
                    QemuAttemptResourceGuardBeginFailure::before_checkpoint_claim(
                        first,
                        selected_checkpoint,
                    ),
                );
            }
        };
        host.begin_world(
            admission,
            resources,
            selected_checkpoint,
            consumer_control_bytes,
            registration,
            before_effects,
        )
    }"#,
            1,
        ),
        (
            r#"fn prepare_world_admission(
        &self,
        selection: crate::PreparedSourceSelector,
        registration: &dyn crate::vm_lifecycle::ProductionHostRamRegistrationFactory,
    ) -> Result<SourceWorldAdmission, QemuVmRealizationError> {
        let identity = registration.native_world_identity().map_err(|source| {
            QemuVmRealizationError::ExecutorUnavailable {
                operation: "borrow selected World Preparation identity",
                message: source.to_string(),
            }
        })?;
        let origin = self.host.world_preparation_origin()?;
        let preparation = origin.prepare(
            crucible_host_resources::host_services::process_birth::NativeWorldIdentity {
                owner: identity.owner,
                selection: identity.selection,
            },
        )?;
        Ok(SourceWorldAdmission::new(preparation, selection))
    }"#,
            1,
        ),
        (
            r#"if !admission.matches(before_effects) {
            return Err(
                QemuAttemptResourceGuardBeginFailure::before_checkpoint_claim(
                    QemuVmRealizationError::CleanupRetained {
                        operation: "match the same Source World admission receiver",
                    },
                    selected_checkpoint,
                ),
            );
        }"#,
            2,
        ),
        (
            r#"let hosts = self.host.begin_native_world(
            &mut admission.preparation,
            identity,
            controls,
            checkpoint,
            before_effects,
            |accept| {
                registration
                    .visit_native_nodes(&mut |_name, row| {
                        accept(NativeNodeReservation {
                            node: row.node,
                            resources: row.resources,
                            source_host_descriptors: row.source_host_descriptors,
                            target_host_descriptors: row.target_host_descriptors,
                        })
                        .map_err(|source| {
                            crucible_control_api::host_operational::HostRamAdmissionError::contract(
                                source.to_string(),
                            )
                        })
                    })
                    .map_err(|source| ServiceBirthError::Policy(source.to_string()))
            },
        );"#,
            1,
        ),
        (
            r#"let (host, selected_checkpoint) = self.host.begin_world(
    admission, resources, selected_checkpoint, consumer_control_bytes, registration, before_effects,
)?; ComposedQemuAttemptResourceGuard::from_installed_host(host, resources, cancellation, selected_checkpoint,)"#,
            1,
        ),
        (
            r#"pub struct SharedQemuAttemptHostResourceFactory<H> {
    host: Arc<shared_host::SharedHostBody<H>>,
    cleanup: Option<crate::lifecycle_cleanup::LifecycleCleanupHandle>,
}"#,
            1,
        ),
        (
            r#"pub fn new(host: H) -> Self {
        Self {
            host: Arc::new(shared_host::SharedHostBody::ordinary(host)),
            cleanup: None,
        }
    }"#,
            1,
        ),
        (
            r#"pub(crate) fn try_with_world_origin(
        host: H,
        cleanup: Option<crate::lifecycle_cleanup::LifecycleCleanupHandle>,
    ) -> Result<Self, QemuVmRealizationError>
    where
        H: QemuAttemptSelectedHostResourceFactory,
    {
        let origin = host.world_preparation_origin()?;
        Ok(Self {
            host: Arc::new(shared_host::SharedHostBody::with_origin(host, origin)),
            cleanup,
        })
    }"#,
            1,
        ),
        (
            r#"pub(crate) fn exclusive_factory(
        &mut self,
    ) -> Result<&mut LinuxQemuAttemptHostResourceFactory, QemuVmRealizationError> {
        Arc::get_mut(&mut self.host)
            .ok_or_else(|| QemuVmRealizationError::ExecutorUnavailable {
                operation: "borrow actual Main factory for terminal retirement",
                message: String::from("actual factory borrowers remain"),
            })?
            .host
            .get_mut()
            .map_err(|_| QemuVmRealizationError::ExecutorUnavailable {
                operation: "borrow actual Main factory for terminal retirement",
                message: String::from("actual factory custody is poisoned"),
            })
    }"#,
            1,
        ),
        (
            r#"fn clone(&self) -> Self {
        Self {
            host: Arc::clone(&self.host),
            cleanup: self.cleanup.clone(),
        }
    }"#,
            1,
        ),
        (
            r#"pub(crate) fn normal_pool_control_bytes(
        capacity: usize,
    ) -> Result<u64, QemuVmRealizationError> {
        let shared = shared_host::shared_body_extent::<Self>().ok_or_else(|| {
            QemuVmRealizationError::ExecutorUnavailable {
                operation: "price normal factory shared body",
                message: String::from("actual shared body layout overflows"),
            }
        })?;
        let pool =
            LinuxQemuAttemptHostFactory::normal_pool_control_extent(capacity).ok_or_else(|| {
                QemuVmRealizationError::ExecutorUnavailable {
                    operation: "price normal pool fixed arrays",
                    message: String::from("actual fixed-array layout overflows"),
                }
            })?;
        u64::try_from(shared)
            .ok()
            .and_then(|bytes| bytes.checked_add(pool))
            .ok_or_else(|| QemuVmRealizationError::ExecutorUnavailable {
                operation: "price normal pool containing bodies",
                message: String::from("actual containing extent overflows"),
            })
    }"#,
            1,
        ),
    ],
};

pub(in super::super) const RECEIVER_API: Companion = Companion {
    path: "crates/crucible/control/crucible-daemon/src/crucible_qemu_session.rs",
    required: &[
        (
            r#"pub(crate) trait SourceWorldConstructor: crucible_qemu_host::LinuxQemuNativeWorldConstructor {
    fn source_selection(&self) -> &crate::PreparedSourceSelector; }"#,
            1,
        ),
        (
            r#"pub(crate) type NativeWorldBeforeEffects<'a> = dyn SourceWorldConstructor + 'a;"#,
            1,
        ),
        (
            r#"fn prepare_world_admission(
        &self,
        _selection: crate::PreparedSourceSelector,
        _registration: &dyn crate::vm_lifecycle::ProductionHostRamRegistrationFactory,
    ) -> Result<crate::qemu_resource_guard::SourceWorldAdmission, QemuVmRealizationError> {
        Err(QemuVmRealizationError::ExecutorUnavailable {
            operation: "prepare actual Source World admission",
            message: String::from("factory has no real World Preparation origin"),
        })
    }"#,
            1,
        ),
    ],
};
