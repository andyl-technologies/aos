//! Binds the original candidate, terminal receipt and existing size-derived payers.

use super::super::Companion;

// Owned functions use the scanner's code tokens: diagnostic strings and comments
// are absent. This also lets the unchanged generic duplicate-expression control
// append a complete expression and count it, including refusal/transfer methods
// whose own bodies have no retry identifier. These are matcher literals, not
// replacement Rust implementations.

pub(super) const ADVANCE: &str = r#"pub(in crate::vm_lifecycle) fn retry(&mut self) -> Result<(), CleanupError> {
        if let Self::History(history) = self {
            return if history.is_some() {
                Ok(())
            } else {
                Err(CleanupError::Retained(,))
            };
        }
        self.publish()?;
        let Self::Published(returned) = self else {
            return Err(CleanupError::Retained(,));
        };
        let history = returned.retry()?;
        *self = Self::History(Some(history));
        Ok(())
    }"#;

pub(super) const PUBLISH: &str = r#"fn publish(&mut self) -> Result<(), CleanupError> {
        let Self::Unpublished(slot) = self else {
            return Ok(());
        };
        let failure = slot.as_mut().ok_or(CleanupError::Retained(,))?;
        if failure.additional.is_some() {
            return Err(CleanupError::Retained(,));
        }
        if matches!(failure.storage, FailureStorage::Rejected { .. }) {
            let receipt = failure
                .retry_reserved_publication()
                .map_err(CleanupError::Retained)?
                .ok_or(CleanupError::Retained(,))?;

            *self = Self::Published(ConstructorReturn {
                shell: slot.take(),
                first: None,
                receipt: Some(receipt),
            });
            return Ok(());
        }

        let failure = slot.take().ok_or(CleanupError::Retained(,))?;
        match failure.retain_in_reserved_cleanup() {
            Ok((first, receipt)) => {
                *self = Self::Published(ConstructorReturn {
                    shell: None,
                    first: Some(first),
                    receipt: Some(receipt),
                });
                Ok(())
            }
            Err(failure) => {
                *slot = Some(failure);
                Err(CleanupError::Retained(,))
            }
        }
    }"#;

pub(super) const UNSUPPORTED: &str = r#"fn publish(&mut self) -> Result<(), CleanupError> {

        Err(CleanupError::Retained(,))
    }"#;

pub(super) const TRANSFER: &str = r#"pub(in crate::vm_lifecycle) fn transfer_history(
        &mut self,
        destination: &mut Option<ProductionVmConstructionPostBody>,
    ) -> Result<(), CleanupError> {
        let Self::History(slot) = self else {
            return Err(CleanupError::Retained(,));
        };
        let history = slot.take().ok_or(CleanupError::Retained(,))?;
        let body = destination.get_or_insert_with(ProductionVmConstructionPostBody::history_only);
        match body.retain_source_history(history) {
            Ok(()) => Ok(()),
            Err(history) => {
                *slot = Some(history);
                Err(CleanupError::Retained(,))
            }
        }
    }"#;

pub(super) const RETURN: &str = r#"fn retry(&mut self) -> Result<SourceCleanupHistory, CleanupError> {
        #[cfg(target_os =        )]
        if self.first.is_none() {
            let shell = self.shell.take().ok_or(CleanupError::Retained(,))?;
            match shell.into_published_error() {
                Ok(first) => self.first = Some(first),
                Err(shell) => {
                    self.shell = Some(shell);
                    return Err(CleanupError::Retained(,));
                }
            }
        }
        if self.shell.is_some() {
            return Err(CleanupError::Retained(,));
        }
        let receipt = self.receipt.as_mut().ok_or(CleanupError::Retained(,))?;

        let _attempt = receipt.retry();
        SourceCleanupHistory::take_returned_constructor(&mut self.first, &mut self.receipt)
            .map_err(CleanupError::Retained)
    }"#;

pub(super) const EFFECTS: &[(&str, usize)] = &[
    (ADVANCE, 1),
    (PUBLISH, 1),
    (UNSUPPORTED, 1),
    (TRANSFER, 1),
    (RETURN, 1),
];

pub(super) const ENDPOINT: Companion = Companion {
    path: "crates/crucible/control/crucible-daemon/src/vm_lifecycle/construction/retained_debug.rs",
    required: EFFECTS,
};

pub(super) const RUNTIME: Companion = Companion {
    path: "crates/crucible/control/crucible-daemon/src/vm_lifecycle/runtime.rs",
    required: &[
        (
            r#"pub(super) fn retry_retained_debug_construction(
        &mut self,
    ) -> Result<(), ProductionVmConstructionCleanupError> {
        let retained = self.retained_debug_construction.get_mut().map_err(|_| {
            SchedulerError::BoundaryViolation {
                message: String::from("debug construction custody is poisoned"),
            }
        })?;
        if let Some(construction) = retained.as_mut() {
            construction.retry()?;
        }
        Ok(())
    }"#,
            1,
        ),
        (
            r#"pub(super) fn transfer_retained_debug_construction(
        &mut self,
        destination: &mut Option<crate::ProductionVmConstructionPostBody>,
    ) -> Result<(), ProductionVmConstructionCleanupError> {
        let retained = self
            .retained_debug_construction
            .get_mut()
            .map_err(|_| ProductionVmConstructionCleanupError::Poisoned)?;
        if let Some(construction) = retained.as_mut() {
            construction.transfer_history(destination)?;
            *retained = None;
        }
        Ok(())
    }"#,
            1,
        ),
        (
            r#"let mut retained = self.retained_debug_construction.try_lock().map_err(|_| {"#,
            1,
        ),
        (r#"if retained.is_some() {"#, 1),
        (
            r#"Err(failure) => {
                *retained = Some(construction::RetainedDebugConstruction::new(failure));
                // Publish the actual owner before constructing a diagnostic.
                return Err(SchedulerError::BoundaryViolation {
                    message: format!(
                        "construct whole-world debug replay candidate: {}",
                        retained
                            .as_ref()
                            .map_or("missing retained failure".to_owned(), ToString::to_string)
                    ),
                });
            }"#,
            1,
        ),
    ],
};

pub(super) const CONTAINING_JOIN: Companion = Companion {
    path: "crates/crucible/control/crucible-daemon/src/vm_lifecycle/construction/custody/post_body.rs",
    required: &[
        (
            r#"fn take_post_body(&mut self) -> Result<Option<Self::PostBody>, Self::Failure> {
        if !self.physically_closed.load(Ordering::Acquire) {
            return Err(Self::Failure::Retained(
                "construction body cleanup is not complete",
            ));
        }
        #[cfg(target_os = "linux")]
        {
            if self.post_body.is_none() {
                let phase = self.phase.get_mut().map_err(|_| Self::Failure::Poisoned)?;
                let body = match phase {
                    Phase::Partial(partial) => match partial.node_launcher.as_mut() {
                        Some(launcher) => launcher.take_post_body()?,
                        None => None,
                    },
                    Phase::Complete(lifecycle) => {
                        let body = lifecycle.node_launcher.take_post_body()?;
                        body
                    }
                    #[cfg(target_os = "linux")]
                    Phase::Source(source) => source.take_source_retirement_post_body()?,
                    #[cfg(target_os = "linux")]
                    Phase::SharedSource(source) => source.take_post_body()?,
                    #[cfg(target_os = "linux")]
                    Phase::SourceRearmFailure(source) => source.take_post_body()?,
                    #[cfg(target_os = "linux")]
                    Phase::SourcePreparation(preparation) => preparation.take_post_body()?,
                    Phase::Empty => None,
                };
                self.post_body = body;
            }
            let phase = self.phase.get_mut().map_err(|_| Self::Failure::Poisoned)?;
            if let Phase::Complete(lifecycle) = phase {
                lifecycle.transfer_retained_debug_construction(&mut self.post_body)?;
            }
            if self.first.is_some() && self.post_body.is_none() {
                self.post_body = Some(crate::ProductionVmConstructionPostBody::history_only());
            }
            if let Some(first) = self.first.take() {
                if let Some(body) = self.post_body.as_mut() {
                    if let Err(first) = body.retain_constructor_first(first) {
                        self.first = Some(first);
                        return Err(Self::Failure::Retained(
                            "construction first still occupies its original body",
                        ));
                    }
                } else {
                    self.first = Some(first);
                    return Err(Self::Failure::Retained(
                        "construction history destination is absent",
                    ));
                }
            }
        }
        #[cfg(target_os = "linux")]
        if let Some(destination) = self.return_destination.take() {
            destination.cancel_for_owned_body();
        }
        Ok(self.post_body.take())
    }"#,
            1,
        ),
        (
            r#"fn retry_cleanup(&mut self) -> Result<(), crate::ProductionVmConstructionCleanupError> {
        ProductionVmConstructionCustody::retry_cleanup(self)
    }"#,
            1,
        ),
    ],
};

pub(super) const HISTORY: Companion = Companion {
    path: "crates/crucible/control/crucible-daemon/src/qemu_campaign_lifecycle.rs",
    required: &[
        (
            r#"pub(crate) fn take_returned_constructor(
        first: &mut Option<LifecycleApiError>,
        receipt: &mut Option<SourceCleanupReceipt>,
    ) -> Result<Self, &'static str> {
        if first.is_none() {
            return Err("construction return has no original first cause");
        }
        let Some(handoff) = receipt.as_mut() else {
            return Err("construction return has no original cleanup receipt");
        };
        if !matches!(
            handoff.stage(),
            Ok(crucible_control_api::ProductionVmCleanupStage::Complete)
        ) {
            return Err("construction return has not completed its original role");
        }
        if !handoff.retain_post_body()
            || !handoff
                .retained_post_body()
                .is_some_and(crate::ProductionVmConstructionPostBody::has_terminal_custody)
        {
            return Err("construction return retains its actual terminal obligations");
        }

        let Some(original_first) = first.take() else {
            return Err("construction return lost its original first cause");
        };
        let Some(original_receipt) = receipt.take() else {
            *first = Some(original_first);
            return Err("construction return lost its original cleanup receipt");
        };
        Ok(Self {
            first: Some(SourceInstallationFirst::Api(original_first)),
            cleanup: None,
            cleanup_post: None,
            terminal_receipt: Some(SourceCleanupHandoff::new(original_receipt)),
        })
    }"#,
            1,
        ),
        (
            r#"impl Drop for SourceCleanupHandoff {
    fn drop(&mut self) {
        let receipt = match self.receipt.get_mut() {
            Ok(receipt) => receipt,
            Err(poisoned) => poisoned.into_inner(),
        };
        if let Some(receipt) = receipt.take() {
            receipt.dispose();
        }
    }
}"#,
            1,
        ),
    ],
};

pub(super) const PAID_BODY: Companion = Companion {
    path: "crates/crucible/control/crucible-daemon/src/lifecycle_cleanup/post_body.rs",
    required: &[
        (
            r#"pub(crate) const fn history_only() -> Self {
        Self {
            terminal: None,
            returns: [None, None],
            not_started: None,
            constructor_first: [None, None],
            cleanup_first: None,
            source_history: None,
            source_retirement_history: None,
        }
    }"#,
            1,
        ),
        (
            r#"pub(crate) fn has_terminal_custody(&self) -> bool {
        self.terminal.is_some()
    }"#,
            1,
        ),
        (
            r#"pub(crate) fn retain_source_history(
        &mut self,
        history: SourceCleanupHistory,
    ) -> Result<(), SourceCleanupHistory> {
        if self.source_history.is_some() {
            return Err(history);
        }
        self.source_history = Some(history);
        Ok(())
    }"#,
            1,
        ),
        (
            r#"pub(crate) fn has_source_return(&self) -> bool {
        self.not_started.is_some()
            || self
                .returns
                .iter()
                .flatten()
                .any(|body| matches!(body, NativeReturn::World(_)))
    }"#,
            1,
        ),
        (
            r#"fn drop(&mut self) {
        if let Some(return_metadata) = self
            .terminal
            .as_ref()
            .and_then(|terminal| terminal.fields.metadata_return)
        {
            // The callback only returns this original Target's metadata. It
            // cannot extract the terminal or reenter native work. All history
            // destruction here runs outside the queue's metadata mutexes.
            match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| return_metadata(self))) {
                Ok(true) => {}
                Ok(false) => {
                    super::terminal::return_pending_terminal(self);
                    return;
                }
                Err(payload) => {
                    if let Some(terminal) = self.terminal.as_mut() {
                        terminal.fields.panic_payload = Some(payload);
                    }
                    super::terminal::return_pending_terminal(self);
                    return;
                }
            }
        }
        let Some(terminal) = self.terminal.take() else {
            return;
        };
        let key = terminal.key.copy_selection();
        let queue = Arc::clone(&terminal.queue);
        // The terminal reference is transferred, never duplicated. All nested
        // actual leaves and Main-paid shells die outside the role metadata lock.
        // Take every field before starting destruction. If any destructor
        // unwinds, no later automatic field drop can escape this observed cut.
        let payload = (
            std::mem::take(&mut self.returns),
            self.not_started.take(),
            std::mem::take(&mut self.constructor_first),
            self.cleanup_first.take(),
            self.source_history.take(),
            self.source_retirement_history.take(),
            terminal,
        );
        let slot = &queue.slots[key.index];
        if !super::terminal::destroy_payload(slot, payload) {
            return;
        }
        super::terminal::return_report_reference(&key, true);
    }"#,
            1,
        ),
    ],
};

pub(super) const ORIGINAL_RECEIPT: Companion = Companion {
    path: "crates/crucible/control/crucible-daemon/src/lifecycle_cleanup/reservation.rs",
    required: &[
        (
            r#"fn observe_slot(
        &mut self,
        slot: &CleanupSlot,
    ) -> Result<ProductionVmCleanupStage, LifecycleApiError> {
        if self.observed == ProductionVmCleanupStage::Complete {
            return Ok(self.observed);
        }
        if slot.completed_epoch.load(Ordering::Acquire) >= self.epoch {
            self.observed = ProductionVmCleanupStage::Complete;
            return Ok(self.observed);
        }
        if slot.body_destroyed_epoch.load(Ordering::Acquire) >= self.epoch {
            self.observed = ProductionVmCleanupStage::BodyDestroyed;
        }
        if slot.controls_closed_epoch.load(Ordering::Acquire) >= self.epoch {
            self.observed = ProductionVmCleanupStage::Complete;
            let mut cell = slot
                .cell
                .try_lock()
                .map_err(|_| refusal("completed handoff history is borrowed or poisoned"))?;
            if cell.epoch != self.epoch || cell.owner.is_some() || cell.controls.is_some() {
                return Err(refusal("completed handoff retains a different actual body"));
            }
            if self.first_failure.is_none() {
                self.first_failure = cell.first_failure.take();
            }
        }
        Ok(self.observed)
    }"#,
            1,
        ),
        (
            r#"fn retry(&mut self) -> Result<ProductionVmCleanupStage, LifecycleApiError> {
        if self.terminal_history.is_some() {
            return Ok(ProductionVmCleanupStage::Complete);
        }
        let queue = self
            .queue
            .upgrade()
            .ok_or_else(|| refusal("containing Main cleanup owner is absent"))?;
        let slot = queue
            .slots
            .get(self.index)
            .ok_or_else(|| refusal("cleanup handoff cell is absent"))?;
        let attempted = retry_slot(slot, Some(self.epoch));
        let observed = self.observe_slot(slot)?;
        if observed == ProductionVmCleanupStage::Complete {
            return Ok(observed);
        }
        attempted?;
        Ok(observed)
    }"#,
            1,
        ),
        (
            r#"fn stage(&mut self) -> Result<ProductionVmCleanupStage, LifecycleApiError> {
        if self.observed == ProductionVmCleanupStage::Complete {
            return Ok(self.observed);
        }
        let queue = self
            .queue
            .upgrade()
            .ok_or_else(|| refusal("containing Main cleanup owner is absent"))?;
        let slot = queue
            .slots
            .get(self.index)
            .ok_or_else(|| refusal("cleanup handoff cell is absent"))?;
        self.observe_slot(slot)
    }"#,
            1,
        ),
        (
            r#"fn retain_post_body(&mut self) -> bool {
        if self.terminal_history.is_some() {
            return true;
        }
        if !self.report_reference {
            return false;
        }
        let key = ServiceMainPreclaim {
            queue: Weak::clone(&self.queue),
            index: self.index,
            epoch: self.epoch,
        };
        match terminal::take_terminal_body(&key) {
            Ok(body) => {
                // The same one report reference moves into the actual terminal
                // body. No cache or strong queue edge remains in Main's cell.
                self.report_reference = false;
                self.observed = ProductionVmCleanupStage::Complete;
                self.terminal_history = Some(body);
                true
            }
            Err(_) => false,
        }
    }"#,
            1,
        ),
        (
            r#"fn retained_post_body(&self) -> Option<&Self::PostBody> {
        self.terminal_history.as_ref()
    }"#,
            1,
        ),
        (
            r#"fn dispose(mut self: Box<Self>) {
        let terminal = self.terminal_history.take();
        dispose_receipt_before_terminal(self, terminal);
    }"#,
            1,
        ),
        (
            r#"fn dispose_receipt_before_terminal<T, P>(receipt: Box<T>, terminal: Option<P>) {
    drop(receipt);
    drop(terminal);
}"#,
            1,
        ),
    ],
};

pub(super) const TERMINAL: Companion = Companion {
    path: "crates/crucible/control/crucible-daemon/src/lifecycle_cleanup/terminal.rs",
    required: &[
        (
            r#"fn take(
        prepared: &mut prepared_service::PreparedCell,
        service: &mut prepared_service::ServiceCell,
        cell: &mut CleanupCell,
    ) -> Self {
        Self {
            role: service.role.take(),
            metadata_return: prepared.terminal_metadata_return.take(),
            prepared: prepared.owner.take(),
            projection: prepared.projection.take(),
            history_projection: prepared.history_projection.take(),
            service: service.start.take(),
            cleanup_first: cell.first_failure.take(),
            prepared_cleanup_first: prepared.cleanup_failure.take(),
            control_failure: cell.control_failure.take(),
            access: prepared.terminal_access.take(),
            receiver: prepared.terminal_receiver.take(),
            panic_payload: prepared.panic_payload.take(),
        }
    }"#,
            1,
        ),
        (
            r#"pub(super) fn take_terminal_body(
    key: &ServiceMainPreclaim,
) -> Result<ProductionVmConstructionPostBody, PreparedSourceRefusal> {
    take_terminal_body_with_reports(key, &mut None, &mut None)
}"#,
            1,
        ),
        (
            r#"pub(super) fn take_terminal_body_with_reports(
    key: &ServiceMainPreclaim,
    access: &mut Option<ServiceMainPreclaimError>,
    receiver: &mut Option<prepared_service::ServiceMainReceiver>,
) -> Result<ProductionVmConstructionPostBody, PreparedSourceRefusal> {
    let queue = key
        .queue
        .upgrade()
        .ok_or(PreparedSourceRefusal::RoleUnavailable)?;
    let slot = queue
        .slots
        .get(key.index)
        .ok_or(PreparedSourceRefusal::RoleUnavailable)?;
    let mut prepared = slot
        .prepared
        .try_lock()
        .map_err(|_| PreparedSourceRefusal::Borrowed)?;
    let mut service = slot
        .service
        .try_lock()
        .map_err(|_| PreparedSourceRefusal::Borrowed)?;
    let mut cell = slot
        .cell
        .try_lock()
        .map_err(|_| PreparedSourceRefusal::Borrowed)?;
    if cell.epoch != key.epoch
        || prepared.epoch != key.epoch
        || service.epoch != key.epoch
        || slot.epoch.load(Ordering::Acquire) != key.epoch
        || !slot.is(CleanupPhase::TerminalReady)
    {
        return Err(PreparedSourceRefusal::Pending);
    }
    if (access.is_some() && prepared.terminal_access.is_some())
        || (receiver.is_some() && prepared.terminal_receiver.is_some())
        || service.role.is_none()
        || cell.retirement_input.is_some()
        || cell.retirement_input_reserved
        || cell.panic_payload.is_some()
        || prepared.panic_payload.is_some()
        || service.panic_payload.is_some()
        || service.queued_owner.is_some()
        || service.queued_owner_borrowed
        || cell.owner.is_some()
        || cell.controls.is_some()
        || prepared.pending_post_body.is_some()
        || !prepared.body_closed
        || !prepared.post_body_taken
        || slot.external_receivers.load(Ordering::Acquire) != 0
        || service.transport_receiver.is_some()
        || service.completed_transport_sequence != service.transport_sequence
        || service
            .start
            .as_ref()
            .is_some_and(|start| !start.is_released())
    {
        return Err(PreparedSourceRefusal::Pending);
    }
    if cell.post_body.is_some() {
        return Err(PreparedSourceRefusal::Pending);
    }
    let Some(body) = service.return_body.as_ref() else {
        return Err(PreparedSourceRefusal::Pending);
    };
    if !body.native_returns_observed() || body.terminal.is_some() {
        return Err(PreparedSourceRefusal::Pending);
    }
    if !slot.claim(CleanupPhase::TerminalReady, CleanupPhase::TerminalOwned) {
        return Err(PreparedSourceRefusal::Pending);
    }

    if slot.report_references.load(Ordering::Acquire) != 1 {
        let _restored = slot.claim(CleanupPhase::TerminalOwned, CleanupPhase::TerminalReady);
        return Err(PreparedSourceRefusal::Pending);
    }

    // Every validation precedes these infallible moves. This transfer consumes
    // the caller's already counted report reference; it creates no second one.
    let Some(mut body) = service.return_body.take() else {
        slot.publish(CleanupPhase::DestructionRefused);
        return Err(PreparedSourceRefusal::DestructionUncertain);
    };
    cell.handoff = false;
    cell.controls_bound = false;
    cell.owner_cleanup_complete = false;
    cell.owner_post_body_taken = false;
    let mut fields = TerminalFields::take(&mut prepared, &mut service, &mut cell);
    if fields.access.is_none() {
        fields.access = access.take();
    }
    if fields.receiver.is_none() {
        fields.receiver = receiver.take();
    }
    body.terminal = Some(TerminalCustody {
        key: key.copy_selection(),
        queue: Arc::clone(&queue),
        fields,
    });
    Ok(body)
}"#,
            1,
        ),
    ],
};

pub(super) const SHUTDOWN: Companion = Companion {
    path: "crates/crucible/control/crucible-daemon/src/vm_lifecycle/quantum_loop.rs",
    required: &[(
        r#"let construction_shutdown = self.retry_retained_debug_construction();
        let prior_node_lease_cleanup_failure = self.node_lease_cleanup_failed;
        let lease_binding = self.prepare_whole_node_shutdown();
        let staged_shutdown = self.retire_terminal_replacement_transaction();
        let shutdown = self.inner.shutdown();
        let lease_shutdown = match lease_binding {
            Ok(binding) => self.finish_whole_node_leases(binding),
            Err(first) => Err(first),
        };
        let launcher_shutdown = if shutdown.is_ok()
            && lease_shutdown.is_ok()
            && construction_shutdown.is_ok()
            && staged_shutdown.is_ok()
            && self.terminal_replacement_values.is_empty()
            && self.terminal_replacement_leases.is_empty()
            && !self.node_lease_cleanup_failed"#,
        1,
    )],
};

pub(super) const PAYER_0: Companion = Companion {
    path: "crates/crucible/control/crucible-daemon/src/vm_lifecycle.rs",
    required: &[(
        r#"retained_debug_construction: std::sync::Mutex<Option<construction::RetainedDebugConstruction>>"#,
        1,
    )],
};

pub(super) const PAYER_1: Companion = Companion {
    path: "crates/crucible/control/crucible-daemon/src/qemu_lifecycle_launcher.rs",
    required: &[
        (
            r#"let source_loop = u64::try_from(std::mem::size_of::<crate::ProductionVmLifecycleLoop>())"#,
            1,
        ),
        (r#".and_then(|bytes| bytes.checked_add(source_loop))"#, 1),
    ],
};

pub(super) const PAYER_2: Companion = Companion {
    path: "crates/crucible/control/crucible-daemon/src/qemu_lifecycle_launcher/pending_construction.rs",
    required: &[
        (r#"let bytes = std::mem::size_of::<Self>()"#, 1),
        (
            r#"bytes.checked_add(std::mem::size_of::<crate::ProductionVmConstructionCustody>())"#,
            1,
        ),
    ],
};

pub(super) const PAYER_3: Companion = Companion {
    path: "crates/crucible/control/crucible-daemon/src/qemu_hot_fork_world_factory/target_construction.rs",
    required: &[(
        r#"std::mem::size_of::<Self>()
            .checked_add(std::mem::size_of::<crate::ProductionVmConstructionCustody>())"#,
        1,
    )],
};

pub(super) const NATIVE_OBSERVATION: Companion = Companion {
    path: "crates/crucible/control/crucible-daemon/src/lifecycle_cleanup/post_body.rs",
    required: &[
        (
            r#"pub(super) fn native_returns_observed(&self) -> bool {
        if self.world_never_entered() {
            return true;
        }
        self.returns.iter().any(Option::is_some)
            && self.returns.iter().flatten().all(|body| match body {
                NativeReturn::World(world) => world.returned && world.observer_returned,
                NativeReturn::Target(target) => target.is_physically_returned(),
            })
    }"#,
            1,
        ),
        (
            r#"pub(super) fn worlds_physically_returned(&self) -> bool {
        self.has_world_return()
            && self.returns.iter().flatten().all(|body| match body {
                NativeReturn::World(world) => world.returned,
                NativeReturn::Target(_) => false,
            })
    }"#,
            1,
        ),
        (
            r#"pub(crate) fn world_never_entered(&self) -> bool {
        self.not_started.is_some() && self.returns.iter().all(Option::is_none)
    }"#,
            1,
        ),
    ],
};

/// Reuses the current canonical driver, rather than creating an endpoint driver.
pub(super) const ROLE_DRIVER: Companion = Companion {
    path: "crates/crucible/control/crucible-daemon/src/lifecycle_cleanup/driver.rs",
    required: super::super::lifecycle_retirement::SERVICE_DRIVER.required,
};

pub(super) const NEGATIVE_TOKENS: Companion = Companion {
    path: "crates/crucible/control/crucible-daemon/src/lifecycle_cleanup/reservation.rs",
    required: &[
        (
            r#"pub(crate) fn unavailable_reservation_for_test() -> Box<
        dyn ProductionVmCleanupReservation<
            Failure = <crate::ProductionVmConstructionCustody as ProductionVmCleanupOwner>::Failure,
            PostBody = <crate::ProductionVmConstructionCustody as ProductionVmCleanupOwner>::PostBody, ReturnDestination = crate::lifecycle_cleanup::SourceBodyReturn>,
    >{
        Box::new(CleanupReservation {
            queue: Weak::new(),
            index: usize::MAX,
            epoch: 0,
            observed: ProductionVmCleanupStage::BodyRetained,
            first_failure: None,
            terminal_history: None,
            report_reference: false,
        })
    }"#,
            1,
        ),
        (
            r#"pub(crate) fn unavailable_handoff_for_test() -> Box<
        dyn ProductionVmCleanupHandoff<
                Failure = crate::ProductionVmConstructionCleanupError,
                PostBody = crate::ProductionVmConstructionPostBody,
            >,
    > {
        Box::new(CleanupReservation {
            queue: Weak::new(),
            index: usize::MAX,
            epoch: 0,
            observed: ProductionVmCleanupStage::BodyRetained,
            first_failure: None,
            terminal_history: None,
            report_reference: false,
        })
    }"#,
            1,
        ),
    ],
};

pub(super) const COMPONENT_LAUNCHER: Companion = Companion {
    path: "crates/crucible/control/crucible-daemon/src/vm_lifecycle/node_launcher.rs",
    required: &[
        (
            r#"impl crucible_control_api::ProductionVmCleanupOwner for PackagedProductionVmNodeLauncher {
    type Failure = crate::ProductionVmConstructionCleanupError;
    type PostBody = crate::ProductionVmConstructionPostBody;

    fn take_post_body(&mut self) -> Result<Option<Self::PostBody>, Self::Failure> {
        // This component launcher owns no native World or Service return.
        Ok(None)
    }

    fn retry_cleanup(&mut self) -> Result<(), crate::ProductionVmConstructionCleanupError> {
        ProductionVmNodeLauncher::finish(self)
    }
}"#,
            1,
        ),
        (
            r#"impl ProductionVmNodeLauncher for PackagedProductionVmNodeLauncher {
    fn begin_execution_quantum(&mut self) -> Result<(), LifecycleApiError> {
        Ok(())
    }

    fn check_operational_boundary(&mut self) -> Result<(), LifecycleApiError> {
        Ok(())
    }

    fn launch_fresh(
        &mut self,
        _request: ProductionVmNodeLaunchRequest<'_>,
        _qemu_executable: &Path,
        _root_image: &Path,
    ) -> Result<ProductionVmNodeLaunch, LifecycleApiError> {
        Err(loop_factory_error(
            "test lifecycle has no production process authority",
        ))
    }

    fn launch_restored(
        &mut self,
        _request: ProductionVmNodeLaunchRequest<'_>,
        _admission: ProductionVmExactNodeRestoreAdmission,
    ) -> Result<ProductionVmNodeLaunch, LifecycleApiError> {
        Err(loop_factory_error(
            "test lifecycle has no production process authority",
        ))
    }

    fn replay_candidate(&self) -> Result<Box<dyn ProductionVmNodeLauncher>, LifecycleApiError> {
        Err(loop_factory_error(
            "test lifecycle has no production replay authority",
        ))
    }

    fn finish(&mut self) -> Result<(), crate::ProductionVmConstructionCleanupError> {
        Ok(())
    }
}"#,
            1,
        ),
    ],
};

pub(super) const COMPONENT_LOOP: Companion = Companion {
    path: "crates/crucible/control/crucible-daemon/src/vm_lifecycle/runtime/tests.rs",
    required: &[
        (
            r#"construction_custody: LifecycleConstructionCustody::Unissued(None),"#,
            1,
        ),
        (
            r#"node_launcher: Box::new(PackagedProductionVmNodeLauncher),"#,
            1,
        ),
        (
            r#"retained_debug_construction: std::sync::Mutex::new(None),"#,
            1,
        ),
        (
            r#"inner: BackendQuantumLoop::with_network_output_interceptor(scheduler, nodes, interceptor),"#,
            1,
        ),
        (r#"let nodes = QemuNodeSet::new();"#, 1),
    ],
};
