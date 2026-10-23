//! Binds Source installation and its native World to the original Main body.
//!
//! Every transfer preserves the same input, factory, reservation and World.
//! Completed body custody alone cannot substitute for native return or the
//! original terminal receipt; these source checks grant no native authority.

use super::Companion;

/// Binds owning callback and postbody types across the control boundary.
pub(super) const CONTROL_API: Companion = Companion {
    path: "crates/crucible/control/crucible-control-api/src/cleanup_owner.rs",
    required: &[
        (super::super::cleanup_delegation::CLEANUP_BOX_ALIASES, 1),
        (
            r#"pub trait ProductionVmCleanupReservation: Send { type Failure: std::error::Error + Send + 'static;"#,
            1,
        ),
        (
            r#"fn retain(
        self: Box<Self>,
        owner: Box<
            dyn ProductionVmCleanupOwner<Failure = Self::Failure, PostBody = Self::PostBody>,
        >,
    ) -> ProductionVmCleanupRetainResult<Self::Failure, Self::PostBody, Self::ReturnDestination>;"#,
            1,
        ),
        (
            r#"fn prepare_return(
        self: Box<Self>,
    ) -> ProductionVmCleanupPrepareResult<Self::Failure, Self::PostBody, Self::ReturnDestination>;"#,
            1,
        ),
        (
            r#"fn retain_returned(
        self: Box<Self>,
        owner: Box<
            dyn ProductionVmCleanupOwner<Failure = Self::Failure, PostBody = Self::PostBody>,
        >,
    ) -> ProductionVmCleanupRetainResult<Self::Failure, Self::PostBody, Self::ReturnDestination>;"#,
            1,
        ),
    ],
};

/// Binds Source republication and transfer of the original completed receipt.
pub(super) const RETAINED_SOURCE: Companion = Companion {
    path: "crates/crucible/control/crucible-daemon/src/qemu_campaign_lifecycle/source_construction/retained.rs",
    required: &[
        (
            r#"Api { owner: crate::ProductionVmConstructionFailure, handoff: Option<SourceCleanupHandoff>, },"#,
            1,
        ),
        (
            r#"Self::Api { owner, handoff } => (handoff, owner.retry_reserved_publication()?),"#,
            1,
        ),
        (
            r#"let Some(receipt) = published else { return Err(""); };
*slot = Some(SourceCleanupHandoff::new(receipt)); Ok(())"#,
            1,
        ),
        (
            r#"if let Some(handoff) = self.handoff_mut()
    && !matches!(handoff.stage(), Ok(ProductionVmCleanupStage::Complete)) { return Err(self); }"#,
            1,
        ),
        (
            r#"if let Some(handoff) = self.handoff_mut() && !handoff.retain_post_body() { return Err(self); }"#,
            1,
        ),
        (
            r#"if let Some(owner) = self.retained_install.as_mut() {
    if owner.handoff_mut().is_none() {
        if owner.retry_publication().is_err() { return Err(owner.report()); }
    }
}"#,
            1,
        ),
        (
            r#"let Some(receipt) = owner.handoff_mut() else { return Err(owner.report()); };
let attempt = receipt.retry(); let stage = receipt.stage();
if !matches!(stage, Ok(ProductionVmCleanupStage::Complete)) {"#,
            1,
        ),
        (
            r#"Self::Api { owner, handoff: Some(handoff), } => match owner.into_published_error() {
    Ok(first) => SourceCleanupHistory {
        first: Some(SourceInstallationFirst::Api(first)),
        cleanup: None, cleanup_post: None, terminal_receipt: Some(handoff),
    },
    Err(owner) => { return Err(Self::Api { owner, handoff: Some(handoff), }); }
},"#,
            1,
        ),
        (
            r#"pub(super) fn require_install_vacancy(
        &mut self,
    ) -> Result<(), QemuAttemptProductionVmLifecycleError> {
        if self.lifecycle_outstanding {
            return Err(
                QemuAttemptProductionVmLifecycleError::SourceInstallRetained {
                    diagnostic: "same factory already lent its one live lifecycle",
                    source: None,
                },
            );
        }


        self.retry_retained_source_installation()
    }"#,
            1,
        ),
    ],
};

/// Binds construction and refused World-control retention.
pub(super) const PENDING_SOURCE: Companion = Companion {
    path: "crates/crucible/control/crucible-daemon/src/qemu_lifecycle_launcher/pending_construction.rs",
    required: &[
        (
            r#"factory: Some(factory), world: None, reservation: Some(reservation),"#,
            1,
        ),
        (
            r#"if let Err(controls) = reservation.attach_controls(controls) {
    self.controls = Some(controls);
    return Err(crate::ProductionVmConstructionCleanupError::Retained("",));
}"#,
            1,
        ),
        (
            r#"(Self::new_prepaid(factory, reservation), Some(start))"#,
            2,
        ),
    ],
};

/// Binds input and factory retention before prepared-body publication.
pub(super) const SOURCE_BIRTH: Companion = Companion {
    path: "crates/crucible/control/crucible-daemon/src/qemu_campaign_lifecycle/source_construction.rs",
    required: &[
        (
            r#"match self.prepare_source_with_input((), PendingSourceConstruction::<R>::new_prepared) {"#,
            1,
        ),
        (
            r#"if let Err(first) = self.refresh_prepared_source() {
            return Err(SourcePreparationFailure { input, first });
        }"#,
            1,
        ),
        (
            r#"if let Err(first) = self.require_install_vacancy() {
            return Err(SourcePreparationFailure { input, first });
        }"#,
            1,
        ),
        (
            r#"let Some(factory) = self.resources.retain_fork_target_factory() else {
            return Err(SourcePreparationFailure {
                input,
                first: QemuAttemptProductionVmLifecycleError::ResourceInstallation(
                    QemuVmRealizationError::CleanupRetained {
                        operation:                                                       ,
                    },
                ),
            });
        }"#,
            1,
        ),
        (
            r#"let Some(producer) = self.resources.source_main_producer() else {
            return Err(SourcePreparationFailure {
                input,
                first: QemuAttemptProductionVmLifecycleError::SourceMainPreparation(
                    SourceMainPreparationRefusal {
                        first: crate::lifecycle_cleanup::ServiceMainPreclaimError::Role(
                                                                         ,
                        ),
                    },
                ),
            });
        }"#,
            1,
        ),
        (
            r#"let installed = match producer.reserve_with_prepared(
            crate::lifecycle_cleanup::PreparedRole::Source,
            (factory, input),
            bytes,
            build,
            crate::lifecycle_cleanup::PreparedSourceProjections {
                first: PendingSourceConstruction::<R>::project_first_error,
                history: PendingSourceConstruction::<R>::project_history,
                terminal_metadata_return: None,
            },
        ) {
            Ok(installed) => installed,
            Err(((_, input), first)) => {
                return Err(SourcePreparationFailure {
                    input,
                    first: QemuAttemptProductionVmLifecycleError::SourceMainPreparation(
                        SourceMainPreparationRefusal { first },
                    ),
                });
            }
        };"#,
            1,
        ),
        (
            r#"let prepared = crate::qemu_lifecycle_launcher::PreparedSourceHandle::from_main(installed);
let service = prepared.service_main_handle(); self.prepared_source = Some(prepared); Ok(service)"#,
            1,
        ),
    ],
};

/// Binds the launched World to its original reservation and selector.
pub(super) const LAUNCHER: Companion = Companion {
    path: "crates/crucible/control/crucible-daemon/src/qemu_lifecycle_launcher.rs",
    required: &[
        (
            r#"pub(crate) fn with_cleanup_reservation(
        mut self,
        reservation: crate::WorldLifecycleCleanupReservation,
    ) -> Self {
        self.prepared_source_selector =
            Some(reservation.service_preclaim().handle().prepared_selector());
        self.cleanup_reservation = Some(reservation);
        self
    }"#,
            1,
        ),
        (
            r#"fn take_cleanup_reservation(
        &mut self,
    ) -> Option<
        Box<
            dyn crucible_control_api::ProductionVmCleanupReservation<
                    Failure = crate::ProductionVmConstructionCleanupError,
                    PostBody = crate::ProductionVmConstructionPostBody,
                    ReturnDestination = crate::lifecycle_cleanup::SourceBodyReturn,
                >,
        >,
    > { self.cleanup_reservation.take().map(crate::WorldLifecycleCleanupReservation::into_reservation) }"#,
            1,
        ),
        (
            r#"pub(crate) fn with_world_cleanup_loan(
        mut self,
        world: crucible_host_resources::host_services::process_birth::AuthenticatedNativeWorldCleanupLoan,
    ) -> Self { self._world_cleanup_loan = Some(world); self }"#,
            1,
        ),
    ],
};

/// Binds the real factory selector without a fallback Main issuer.
pub(super) const FACTORY: Companion = Companion {
    path: "crates/crucible/control/crucible-daemon/src/qemu_resource_guard.rs",
    required: &[
        (
            r#"fn source_main_producer(&self) -> Option<crate::SourceMainProducer> { None }"#,
            1,
        ),
        (
            r#"fn source_main_producer(&self) -> Option<crate::SourceMainProducer> {
    self.cleanup.as_ref().map(|cleanup| cleanup.source_main_producer())
}"#,
            1,
        ),
        (
            r#"fn source_main_producer(&self) -> Option<crate::SourceMainProducer> {
    self.host.source_main_producer()
}"#,
            1,
        ),
    ],
};

/// Binds authenticated native World delivery before preparation begins.
pub(super) const NATIVE_WORLD: Companion = super::super::source_world_admission::NATIVE_WORLD;

/// Binds custody and first-cause retention at native admission refusals.
pub(super) const NATIVE_REFUSAL: Companion = Companion {
    path: "crates/crucible/host/crucible-host-resources/src/host_services/process_birth/executor_purpose/native_pool/refusal.rs",
    required: &[
        (
            r#"#[derive(Debug)]
pub(super) struct RetainedClaim {
    owner: PreparedRefusal,
    delivery: Option<ServiceBirthError>,
    receiver: Option<&'static str>,
}

/// Keeps mutually exclusive clean/refused postcuts in their original storage.
///
/// Assignment refusal is factual only after a clean independent postcut. A
/// negative postcut retains its actual cause and cannot acquire that fact.
pub(super) enum RefusalPostcut {
    Clean,
    AssignmentRefused,
    Refused(ServiceBirthError),
}

impl RefusalPostcut {
    pub(super) fn world_attempt(
        after: Option<ServiceBirthError>,
        assignment_refused: bool,
    ) -> Self {
        match after {
            Some(after) => Self::Refused(after),
            None if assignment_refused => Self::AssignmentRefused,
            None => Self::Clean,
        }
    }

    pub(super) fn as_ref(&self) -> Option<&ServiceBirthError> {
        match self {
            Self::Refused(after) => Some(after),
            Self::Clean | Self::AssignmentRefused => None,
        }
    }

    #[cfg(test)]
    pub(super) fn is_none(&self) -> bool {
        self.as_ref().is_none()
    }
}

impl From<Option<ServiceBirthError>> for RefusalPostcut {
    fn from(after: Option<ServiceBirthError>) -> Self {
        Self::world_attempt(after, false)
    }
}

impl std::fmt::Debug for RefusalPostcut {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.as_ref().fmt(formatter)
    }
}

/// Owns the carrier allocated before an issuer can publish a child.
///
/// No Arc or Weak alias escapes. Final header destruction precedes the value's
/// owner and paired metadata destruction, including on a successful attempt.
#[derive(Debug)]
pub(in super::super) struct PreparedRefusal {
    allocation: Option<Arc<RefusalAllocation>>,
}

#[derive(Debug)]
struct RefusalAllocation {
    // The actual child closes before the same Main's carrier charge is refunded.
    owner: Option<RetainedOwner>,
    _metadata: super::super::HostServiceLeasePair,
}

#[derive(Debug)]
enum RetainedOwner {
    Pool {
        _pool: AuthenticatedNativePoolPurpose,
    },
    Source {
        _source: AuthenticatedSourceHostPurpose,
    },
    Dispatcher {
        _dispatcher: super::super::AuthenticatedTargetDispatcherPurpose,
    },
    World(Option<AuthenticatedNativeWorldClaim>),
    Window {
        _window: AuthenticatedNativeNodeHostWindow,
    },
}

impl PreparedRefusal {
    /// Prices both allocation construction overlap and its paired lease controls.
    fn metadata_bytes() -> Result<u64, ServiceBirthError> {
        let (allocation, _) = std::alloc::Layout::new::<(
            std::sync::atomic::AtomicUsize,
            std::sync::atomic::AtomicUsize,
        )>()
        .extend(std::alloc::Layout::new::<RefusalAllocation>())
        .map_err(|_| ServiceBirthError::policy("native refusal layout overflows"))?;

        u64::try_from(allocation.pad_to_align().size())
            .ok()
            .and_then(|bytes| bytes.checked_add(std::mem::size_of::<RefusalAllocation>() as u64))
            .and_then(|bytes| bytes.checked_add(std::mem::size_of::<Self>() as u64))
            .and_then(|bytes| bytes.checked_add(2 * HostServiceLease::metadata_bytes()))
            .ok_or_else(|| ServiceBirthError::policy("native refusal extent overflows"))
    }

    /// Admits the complete carrier before child publication or kernel effects.
    pub(in super::super) fn reserve(
        main: &super::super::AuthenticatedNativeSlotPurpose,
    ) -> Result<Self, ServiceBirthError> {
        let metadata = main.owner.reserve_metadata(Self::metadata_bytes()?)?;
        Ok(Self::from_metadata(metadata))
    }

    fn from_metadata(metadata: super::super::HostServiceLeasePair) -> Self {
        Self {
            allocation: Some(Arc::new(RefusalAllocation {
                owner: None,
                _metadata: metadata,
            })),
        }
    }

    fn allocation_mut(&mut self) -> &mut RefusalAllocation {
        match self.allocation.as_mut().and_then(Arc::get_mut) {
            Some(allocation) => allocation,
            None => unreachable!("the private refusal carrier has exactly one owner"),
        }
    }

    fn retain(mut self, owner: RetainedOwner) -> RetainedClaim {
        self.allocation_mut().owner = Some(owner);
        RetainedClaim {
            owner: self,
            delivery: None,
            receiver: None,
        }
    }
}

impl Drop for PreparedRefusal {
    fn drop(&mut self) {
        if let Some(allocation) = self.allocation.take() {
            // No weak or strong aliases can keep an uncharged header alive.
            drop(Arc::into_inner(allocation));
        }
    }
}

impl RetainedClaim {
    pub(super) const fn empty() -> Self {
        Self {
            owner: PreparedRefusal { allocation: None },
            delivery: None,
            receiver: None,
        }
    }

    pub(super) fn is_empty(&self) -> bool {
        self.owner.allocation.is_none() && self.delivery.is_none() && self.receiver.is_none()
    }

    pub(super) fn source(
        source: AuthenticatedSourceHostPurpose,
        prepared: PreparedRefusal,
    ) -> Self {
        prepared.retain(RetainedOwner::Source { _source: source })
    }

    pub(super) fn pool(pool: AuthenticatedNativePoolPurpose, prepared: PreparedRefusal) -> Self {
        prepared.retain(RetainedOwner::Pool { _pool: pool })
    }

    pub(super) fn dispatcher(
        dispatcher: super::super::AuthenticatedTargetDispatcherPurpose,
        prepared: PreparedRefusal,
    ) -> Self {
        prepared.retain(RetainedOwner::Dispatcher {
            _dispatcher: dispatcher,
        })
    }

    pub(super) fn world(world: AuthenticatedNativeWorldClaim, prepared: PreparedRefusal) -> Self {
        prepared.retain(RetainedOwner::World(Some(world)))
    }

    pub(super) fn window(
        window: AuthenticatedNativeNodeHostWindow,
        prepared: PreparedRefusal,
    ) -> Self {
        prepared.retain(RetainedOwner::Window { _window: window })
    }
}"#,
            1,
        ),
        (
            r#"pub fn take_retained_world(&mut self) -> Option<AuthenticatedNativeWorldClaim> {
        let allocation = self._retained.owner.allocation.as_mut()?;
        match Arc::get_mut(allocation)?.owner.as_mut()? {
            RetainedOwner::World(world) => world.take(),
            _ => None,
        }
    }"#,
            1,
        ),
        (r#"self._retained.delivery.get_or_insert(error);"#, 1),
        (r#"self._retained.receiver.get_or_insert(operation);"#, 1),
    ],
};

/// Binds all-or-restore World transfers and original no-entry proof consumption.
pub(super) const PREPARED_WORLD: Companion = super::super::source_world_admission::PREPARED_WORLD;
