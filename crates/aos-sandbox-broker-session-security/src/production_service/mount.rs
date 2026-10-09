//! Complete resident Mount request, response and release cycles.

use std::time::Duration;

use crate::DormantAuthenticatedBrokerSessionV1;

/// Borrows the complete Mount-owned production composition for one request.
pub struct ProductionMountBrokerOwnersV1<'owners> {
    /// The sealed Mount effect and inventory callsite.
    pub mount: &'owners mut dyn aos_sandbox_mount::DormantMountBrokerCallsiteV1,
    /// The optional Host-sealed catalog scope for catalog preparation.
    pub catalog_scope: Option<aos_sandbox_mount::host_scope::ObservedMountScope>,
}

/// Retains the closed selected Mount original cycle through local Root1 send.
///
/// A genuine authenticated Mount session enters this owner before receiving.
/// The same fixed Root opening and delivered catalog originals remain resident
/// through independent domain admission and the existing native runtime. This
/// route sends no public success and proves neither Ready nor terminal drain.
/// After real native terminal readback, the named continuation may commit only
/// fixed Conflict and the two current inventory responses on the same Session.
/// The selected installed caller supplies the genuine
/// exclusive table/PID1-image owner, which is bookended at protected crossings.
/// Source's independent initial entry chain, lower unreturned prefixes and
/// allocation funding remain separate functional bounds.
pub struct ProductionOriginalMountCycleV1 {
    startup: Option<aos_sandbox::mount_manager_startup::SelectedMountStartupV2>,
    receipt: crate::ProductionOriginalMountReceiptV1,
    root: crate::ProductionSelectedRootMountSourceProviderV1,
    publication: Option<Vec<u8>>,
    catalog: Option<Vec<u8>>,
    selection: Option<Vec<u8>>,
    mount_result: Option<Result<bool, aos_sandbox_mount::MountError>>,
    response_result: Option<Result<aos_sandbox_mount::broker::OriginalMountResponseProgressV5, aos_sandbox_mount::MountError>>,
    response_postcheck_failed: bool,
    deadline_result: Option<Result<u64, crate::ProductionBrokerSessionActivationErrorV1>>,
    deadline: u64,
    attempted: bool,
    ended: bool,
    locally_sent: bool,
    first_stage: Option<OriginalMountCycleStageV1>,
}

#[derive(Clone, Copy)]
enum OriginalMountCycleStageV1 {
    Startup,
    Root,
    Receipt,
    Mount,
    Deadline,
}

impl std::fmt::Debug for ProductionOriginalMountCycleV1 {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("ProductionOriginalMountCycleV1([resident original cycle])")
    }
}

/// Lends an original cycle's genuine first returned cause without recovery.
pub enum ProductionOriginalMountCycleFailureV1<'owner> {
    /// The same admitted startup owner retains the genuine kernel/image cause.
    Startup(aos_sandbox::mount_manager_startup::SelectedMountStartupFailureRefV2<'owner>),
    /// The fixed Root opening, Session or delivered catalog failed.
    Root(crate::ProductionSelectedRootMountSourceProviderFailureV1<'owner>),
    /// The original Mount receipt or signed-domain admission failed.
    Receipt(crate::ProductionOriginalMountReceiptFailureV1<'owner>),
    /// The same broker/native runtime retained this returned failure.
    Mount(&'owner aos_sandbox_mount::MountError),
    /// The original absolute deadline expired or could not be sampled.
    Deadline(&'owner crate::ProductionBrokerSessionActivationErrorV1),
    /// A closed association failed or the original unwound without a cause.
    Ended,
}

impl std::fmt::Debug for ProductionOriginalMountCycleFailureV1<'_> {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(match self {
            Self::Startup(_) => "ProductionOriginalMountCycleFailureV1::Startup",
            Self::Root(_) => "ProductionOriginalMountCycleFailureV1::Root",
            Self::Receipt(_) => "ProductionOriginalMountCycleFailureV1::Receipt",
            Self::Mount(_) => "ProductionOriginalMountCycleFailureV1::Mount",
            Self::Deadline(_) => "ProductionOriginalMountCycleFailureV1::Deadline",
            Self::Ended => "ProductionOriginalMountCycleFailureV1::Ended",
        })
    }
}

struct OriginalMountCycleBoundaryV1<'owner> {
    owner: &'owner mut ProductionOriginalMountCycleV1,
    completed: bool,
}

impl Drop for OriginalMountCycleBoundaryV1<'_> {
    fn drop(&mut self) {
        if !self.completed {
            self.owner.end();
        }
    }
}

impl ProductionOriginalMountCycleV1 {
    /// Parks the completed selected startup beside the same original request.
    ///
    /// This accepts only the actual move-only Core owner. It does not complete
    /// an initial table from DATA, duplicate an image flight or grant Acquire.
    #[must_use]
    pub fn with_selected_startup(
        session: DormantAuthenticatedBrokerSessionV1,
        deadline: u64,
        startup: aos_sandbox::mount_manager_startup::SelectedMountStartupV2,
    ) -> Self {
        Self {
            startup: Some(startup),
            receipt: session.retain_original_mount_receipt(deadline),
            root: crate::ProductionSelectedRootMountSourceProviderV1::new(deadline),
            publication: None,
            catalog: None,
            selection: None,
            mount_result: None,
            response_result: None,
            response_postcheck_failed: false,
            deadline_result: None,
            deadline,
            attempted: false,
            ended: false,
            locally_sent: false,
            first_stage: None,
        }
    }

    /// Runs once through the existing original native stage engine.
    ///
    /// Successful local send keeps this whole owner and the broker's runtime;
    /// it cannot be converted into a generic response, success or retry permit.
    /// The caller must retain both until an independently implemented terminal
    /// continuation or intentional failed invocation. Ordinary dispatch is not
    /// changed or opened by this method.
    ///
    /// # Errors
    ///
    /// Lends a resident cause after ending both original queues. No subsequent
    /// call observes, reconnects, renews, re-admits or reconstructs the request.
    pub fn run_once<W: aos_sandbox_mount::worker::MountWorker>(
        &mut self,
        broker: &mut aos_sandbox_mount::broker::MountBroker<W>,
    ) -> Result<(), ProductionOriginalMountCycleFailureV1<'_>> {
        if self.attempted || self.ended {
            self.end();
            return Err(self.failure_or_ended());
        }
        self.attempted = true;
        let succeeded = {
            let mut boundary = OriginalMountCycleBoundaryV1 {
                owner: self,
                completed: false,
            };
            let succeeded = boundary.owner.run_inner(broker);
            boundary.completed = succeeded;
            succeeded
        };
        if succeeded {
            Ok(())
        } else {
            Err(self.failure_or_ended())
        }
    }

    /// Advances a response only after this SAME selected cycle sent Root1.
    ///
    /// The original deadline, receipt, Root Session, signed-domain owner,
    /// broker writer/runtime and selected kernel/image owner stay resident.
    /// Successful local Root4 selects the same Source7/Root13 continuation;
    /// neither local send is retried or implies peer receipt or settlement.
    ///
    /// # Errors
    ///
    /// Ends the original queues before lending a resident failure on missing
    /// association, expired deadline, stale catalog/startup or native refusal.
    pub fn advance_selected_response_once<W: aos_sandbox_mount::worker::MountWorker>(
        &mut self,
        broker: &mut aos_sandbox_mount::broker::MountBroker<W>,
    ) -> Result<aos_sandbox_mount::broker::OriginalMountResponseProgressV5, ProductionOriginalMountCycleFailureV1<'_>> {
        if self.ended || self.first_stage.is_some() || !self.attempted
            || !self.locally_sent || self.startup.is_none()
        {
            self.end();
            return Err(self.failure_or_ended());
        }
        let progress = {
            let mut boundary = OriginalMountCycleBoundaryV1 {
                owner: self,
                completed: false,
            };
            let progress = boundary.owner.advance_response_inner(broker);
            boundary.completed = progress.is_some();
            progress
        };
        match progress {
            Some(progress) => Ok(progress),
            None => Err(self.failure_or_ended()),
        }
    }

    fn advance_response_inner<W: aos_sandbox_mount::worker::MountWorker>(
        &mut self,
        broker: &mut aos_sandbox_mount::broker::MountBroker<W>,
    ) -> Option<aos_sandbox_mount::broker::OriginalMountResponseProgressV5> {
        if !self.bookend(broker) {
            return None;
        }
        if !self.advance_native_response(broker) {
            return None;
        }

        // The action is resident before the slower outer catalog/kernel/image
        // checks. Native failure is not replaced by their separately held debt.
        if !self.bookend(broker) {
            self.response_postcheck_failed = true;
            return None;
        }
        self.response_result.as_ref().and_then(|result| result.as_ref().ok()).copied()
    }

    fn advance_native_response<W: aos_sandbox_mount::worker::MountWorker>(
        &mut self,
        broker: &mut aos_sandbox_mount::broker::MountBroker<W>,
    ) -> bool {
        let (Some(authority), Some(session)) = (
            self.receipt.authority_mut(), self.root.borrow_current_session(),
        ) else {
            self.note_failure(OriginalMountCycleStageV1::Root);
            return false;
        };
        self.response_result = Some(broker.advance_signed_original_response_v5(authority, session));
        if !matches!(self.response_result, Some(Ok(_))) {
            self.note_failure(OriginalMountCycleStageV1::Mount);
        }

        true
    }

    /// Advances the fixed nonadmitting terminal on the original transport.
    ///
    /// The actual stored Root terminal is reobserved through its already-sent
    /// branch. Conflict does not assert an absent effect or physical Release.
    /// The original Acquire, writers and both same queues remain owned here.
    ///
    /// # Errors
    /// Ends both queues on a stale owner, failed original cutoff, signing,
    /// commit ambiguity or native send refusal. No signature or send is retried.
    pub fn advance_selected_nonadmitting_terminal<W: aos_sandbox_mount::worker::MountWorker>(
        &mut self,
        broker: &mut aos_sandbox_mount::broker::MountBroker<W>,
    ) -> Result<bool, ProductionOriginalMountCycleFailureV1<'_>> {
        if self.ended || self.first_stage.is_some() || self.startup.is_none()
            || !self.locally_sent || !self.attempted
        {
            self.end();
            return Err(self.failure_or_ended());
        }
        let succeeded = {
            let mut boundary = OriginalMountCycleBoundaryV1 { owner: self, completed: false };
            let succeeded = boundary.owner.advance_nonadmitting_inner(broker);
            boundary.completed = succeeded;
            succeeded
        };
        if succeeded {
            Ok(self.receipt.terminal_stage() == crate::production_response::OriginalMountTerminalStageV1::Sent)
        } else {
            Err(self.failure_or_ended())
        }
    }

    fn advance_nonadmitting_inner<W: aos_sandbox_mount::worker::MountWorker>(
        &mut self,
        broker: &mut aos_sandbox_mount::broker::MountBroker<W>,
    ) -> bool {
        if !self.nonadmitting_bookend(broker) {
            return false;
        }
        // A historical DATA flag is insufficient: this is the genuine native
        // phase7 readback and retained same-Session already-sent observation.
        let native = self.advance_native_response(broker);
        if !native || !matches!(self.response_result, Some(Ok(aos_sandbox_mount::broker::OriginalMountResponseProgressV5::RootTerminalRecordedSent))) {
            self.note_failure(OriginalMountCycleStageV1::Mount);
            // A returned native refusal remains first; it does not suppress
            // the independent owner and original-clock negative observations.
            if !self.nonadmitting_bookend(broker) {
                self.response_postcheck_failed = true;
            }
            return false;
        }
        if !self.nonadmitting_bookend(broker) {
            return false;
        }
        let action = if self.receipt.terminal_stage() == crate::production_response::OriginalMountTerminalStageV1::Sent {
            self.receipt.advance_original_inventory(broker, &mut self.root)
        } else {
            self.receipt.advance_nonadmitting_terminal()
        };
        if !action { self.note_failure(OriginalMountCycleStageV1::Receipt); }
        // These posts are independently attempted even after the actual action
        // failed; first cause stays resident before any negative disposition.
        let post = self.nonadmitting_bookend(broker);
        if !post { self.response_postcheck_failed = true; }
        action && post
    }

    fn nonadmitting_bookend<W: aos_sandbox_mount::worker::MountWorker>(
        &mut self,
        broker: &mut aos_sandbox_mount::broker::MountBroker<W>,
    ) -> bool {
        let root = self.root.recheck_catalog();
        if !root { self.note_failure(OriginalMountCycleStageV1::Root); }
        let startup = match self.startup.as_mut() {
            Some(startup) => broker.recheck_selected_mount_startup(startup).is_ok(),
            None => false,
        };
        if !startup { self.note_failure(OriginalMountCycleStageV1::Startup); }
        let receipt = self.receipt.recheck_nonadmitting_terminal();
        if !receipt { self.note_failure(OriginalMountCycleStageV1::Receipt); }
        let clock = self.check_deadline();
        receipt && root && startup && clock
    }

    /// Reports only the completed channel prefix for private routing.
    #[must_use]
    pub fn original_release_channel_settled(&self) -> bool {
        !self.ended && self.receipt.original_release_channel_settled()
    }

    /// Advances independently authorized Release on the SAME retained owners.
    ///
    /// The fixed intake cut starts only after all three authentic exchanges.
    /// Once the actual Release is admitted, its genuine reopened effect and
    /// original paired clock replace the historical Acquire crossing. Local
    /// send is DATA only: it permits neither cleanup nor descriptor release.
    ///
    /// # Errors
    /// Ends both queues before diagnostic/drop on receive, admission, native
    /// reservation, signing, send or independent owner/clock refusal.
    pub fn advance_selected_original_release<W: aos_sandbox_mount::worker::MountWorker>(
        &mut self,
        broker: &mut aos_sandbox_mount::broker::MountBroker<W>,
    ) -> Result<aos_sandbox_mount::broker::OriginalMountReleaseProgressV1, ProductionOriginalMountCycleFailureV1<'_>> {
        if self.ended || self.first_stage.is_some() || self.startup.is_none()
            || !self.attempted || !self.locally_sent
            || !self.receipt.original_release_channel_settled()
        {
            self.end();
            return Err(self.failure_or_ended());
        }
        let progress = {
            let mut boundary = OriginalMountCycleBoundaryV1 { owner: self, completed: false };
            let owner = &mut *boundary.owner;
            // Before a receive can block, retain the one new intake cut and
            // observe the genuine startup/catalog owners. The Root bookend's
            // final clock is that fixed cut, never the historical Acquire D.
            let intake_current = if owner.receipt.original_release_admitted() {
                true
            } else if !owner.receipt.prepare_original_release_intake() {
                owner.note_failure(OriginalMountCycleStageV1::Receipt);
                false
            } else {
                let startup = match owner.startup.as_mut() {
                    Some(startup) => broker.recheck_selected_mount_startup(startup).is_ok(),
                    None => false,
                };
                if !startup {
                    owner.note_failure(OriginalMountCycleStageV1::Startup);
                }
                let root = owner.receipt.original_release_intake_cut()
                    .is_some_and(|cut| owner.root.recheck_catalog_for_original_release_intake(cut));
                if !root {
                    owner.note_failure(OriginalMountCycleStageV1::Root);
                }
                startup && root
            };
            let progress = if intake_current {
                owner.receipt.advance_original_release(broker, &mut owner.root)
            } else {
                None
            };
            if progress.is_none() {
                owner.note_failure(if owner.receipt.original_release_root_loan_pending() {
                    OriginalMountCycleStageV1::Root
                } else {
                    OriginalMountCycleStageV1::Receipt
                });
            }
            // These independent posts also run after an actual action Err.
            // The receipt's selected crossing was armed before dispatch, so
            // caught unwind still lends its already resident cause on end.
            let root_receipt = owner.receipt.recheck_original_release(broker, &mut owner.root);
            if !root_receipt {
                if owner.root.failure().is_some() {
                    owner.note_failure(OriginalMountCycleStageV1::Root);
                } else {
                    owner.note_failure(OriginalMountCycleStageV1::Receipt);
                }
            }
            let startup = match owner.startup.as_mut() {
                Some(startup) => broker.recheck_selected_mount_startup(startup).is_ok(),
                None => false,
            };
            if !startup {
                owner.note_failure(OriginalMountCycleStageV1::Startup);
            }
            boundary.completed = progress.is_some() && root_receipt && startup;
            if boundary.completed { progress } else { None }
        };
        progress.ok_or_else(|| self.failure_or_ended())
    }

    /// Lends the actual native Release cause without copying or rechecking it.
    #[must_use]
    pub fn release_failure<'owner, W: aos_sandbox_mount::worker::MountWorker>(
        &self,
        broker: &'owner aos_sandbox_mount::broker::MountBroker<W>,
    ) -> Option<&'owner (dyn std::error::Error + 'static)> {
        broker.original_release_failure_v1()
    }

    /// Lends independent native Release posts without replacing its first cause.
    #[must_use]
    pub fn release_postcheck_debt<'owner, W: aos_sandbox_mount::worker::MountWorker>(
        &self,
        broker: &'owner aos_sandbox_mount::broker::MountBroker<W>,
    ) -> Option<&'owner (dyn std::error::Error + 'static)> {
        broker.original_release_postcheck_debt_v1()
    }

    /// Borrows the actual response cause from its SAME broker runtime owner.
    ///
    /// This performs no observation, retry, extraction or cause cloning. The
    /// cycle's status error and later outer bookend debt remain separate.
    #[must_use]
    pub fn response_failure<'owner, W: aos_sandbox_mount::worker::MountWorker>(
        &self,
        broker: &'owner aos_sandbox_mount::broker::MountBroker<W>,
    ) -> Option<aos_sandbox_mount::broker::OriginalMountResponseFailureV5<'owner>> {
        broker.original_response_failure_v5()
    }

    /// Lends an actual later outer bookend refusal without another observation.
    #[must_use]
    pub fn response_postcheck_debt(&self) -> Option<ProductionOriginalMountCycleFailureV1<'_>> {
        if !self.response_postcheck_failed {
            return None;
        }
        // This is the shared bookend's literal check order, not a second probe.
        if let Some(cause) = self.deadline_result.as_ref().and_then(|result| result.as_ref().err()) {
            return Some(ProductionOriginalMountCycleFailureV1::Deadline(cause));
        }
        if let Some(cause) = self.receipt.failure() {
            return Some(ProductionOriginalMountCycleFailureV1::Receipt(cause));
        }
        if let Some(cause) = self.root.failure() {
            return Some(ProductionOriginalMountCycleFailureV1::Root(cause));
        }
        self.startup.as_ref().and_then(|startup| startup.failure())
            .map(ProductionOriginalMountCycleFailureV1::Startup)
    }

    fn check_deadline(&mut self) -> bool {
        self.deadline_result = Some(crate::production_activation::remaining_duration(self.deadline));
        if matches!(self.deadline_result, Some(Ok(_))) {
            return true;
        }
        self.note_failure(OriginalMountCycleStageV1::Deadline);
        false
    }

    fn note_failure(&mut self, stage: OriginalMountCycleStageV1) {
        if self.first_stage.is_none() {
            self.first_stage = Some(stage);
        }
    }

    fn startup_bookend<W: aos_sandbox_mount::worker::MountWorker>(
        &mut self,
        broker: &mut aos_sandbox_mount::broker::MountBroker<W>,
    ) -> bool {
        if !self.check_deadline() {
            return false;
        }
        let Some(startup) = self.startup.as_mut() else {
            return false;
        };
        if broker.recheck_selected_mount_startup(startup).is_err() {
            self.note_failure(OriginalMountCycleStageV1::Startup);
            return false;
        }
        // Charge the slow fixed five-second observation to the SAME original D.
        self.check_deadline()
    }

    fn bookend<W: aos_sandbox_mount::worker::MountWorker>(
        &mut self,
        broker: &mut aos_sandbox_mount::broker::MountBroker<W>,
    ) -> bool {
        if !self.check_deadline() {
            return false;
        }
        if !self.receipt.recheck_original_request() {
            self.note_failure(OriginalMountCycleStageV1::Receipt);
            return false;
        }
        if !self.root.recheck_catalog() {
            self.note_failure(OriginalMountCycleStageV1::Root);
            return false;
        }
        self.startup_bookend(broker)
    }

    fn run_inner<W: aos_sandbox_mount::worker::MountWorker>(
        &mut self,
        broker: &mut aos_sandbox_mount::broker::MountBroker<W>,
    ) -> bool {
        if !self.startup_bookend(broker) {
            return false;
        }
        if !self.receipt.arm_original_fence() {
            self.note_failure(OriginalMountCycleStageV1::Receipt);
            return false;
        }
        if !self.startup_bookend(broker) {
            return false;
        }
        if !self.check_deadline() {
            return false;
        }
        if !self.startup_bookend(broker) || !self.check_deadline() {
            return false;
        }
        if !self.startup_bookend(broker) {
            return false;
        }
        if self.root.connect_once().is_err() {
            self.note_failure(OriginalMountCycleStageV1::Root);
            return false;
        }
        if !self.startup_bookend(broker) {
            return false;
        }
        if !self.root.read_catalog_once() {
            self.note_failure(OriginalMountCycleStageV1::Root);
            return false;
        }
        if !self.startup_bookend(broker) {
            return false;
        }
        if self.receipt.receive_once().is_err() {
            self.note_failure(OriginalMountCycleStageV1::Receipt);
            return false;
        }
        if !self.startup_bookend(broker) {
            return false;
        }
        if self.receipt.admit_original_acquire(broker).is_err() {
            self.note_failure(OriginalMountCycleStageV1::Receipt);
            return false;
        }
        if !self.bookend(broker) {
            return false;
        }
        let Some((publication, catalog)) = self.root.catalog_pair() else {
            return false;
        };
        // These are bounded comparison DATA copies; the original delivered
        // files and bytes remain in root.catalog. Allocation funding is not
        // upgraded into original custody or a hard-memory reservation here.
        self.publication = Some(publication.to_vec());
        self.catalog = Some(catalog.to_vec());
        if !self.bookend(broker) {
            return false;
        }

        let (Some(authority), Some(session)) = (self.receipt.authority_mut(), self.root.borrow_current_session()) else {
            self.first_stage.get_or_insert(OriginalMountCycleStageV1::Root);
            return false;
        };
        self.mount_result = Some(broker.begin_signed_original_acquire(
            authority, session, &mut self.publication, &mut self.catalog, &mut self.selection,
        ).map(|()| false));
        if !matches!(self.mount_result, Some(Ok(_))) {
            self.note_failure(OriginalMountCycleStageV1::Mount);
            return false;
        }
        if !self.bookend(broker) {
            return false;
        }

        loop {
            if !self.bookend(broker) {
                return false;
            }
            let (Some(authority), Some(session)) = (self.receipt.authority_mut(), self.root.borrow_current_session()) else {
                self.first_stage.get_or_insert(OriginalMountCycleStageV1::Root);
                return false;
            };
            self.mount_result = Some(broker.advance_signed_original_acquire(authority, session));
            if !matches!(self.mount_result, Some(Ok(_))) {
                self.note_failure(OriginalMountCycleStageV1::Mount);
                return false;
            }
            if !self.bookend(broker) {
                return false;
            }
            if matches!(self.mount_result, Some(Ok(true))) {
                self.locally_sent = true;
                return true;
            }
            // Existing nonblocking Query/send backpressure, using the same
            // original absolute deadline rather than a renewed timer.
            std::thread::sleep(Duration::from_nanos(2_000_000));
        }
    }

    /// Reports local sends only; it is not a terminal or public success witness.
    #[must_use]
    pub fn locally_sent(&self) -> bool {
        self.locally_sent && !self.ended
    }

    /// Lends the actual retained failure without any new observation.
    #[must_use]
    pub fn failure(&self) -> Option<ProductionOriginalMountCycleFailureV1<'_>> {
        let failure = match self.first_stage {
            Some(OriginalMountCycleStageV1::Startup) => self.startup.as_ref()
                .and_then(|startup| startup.failure()).map(ProductionOriginalMountCycleFailureV1::Startup),
            Some(OriginalMountCycleStageV1::Root) => self.root.failure().map(ProductionOriginalMountCycleFailureV1::Root),
            Some(OriginalMountCycleStageV1::Receipt) => self.receipt.failure().map(ProductionOriginalMountCycleFailureV1::Receipt),
            Some(OriginalMountCycleStageV1::Mount) => {
                // The broker's status error intentionally carries no copied
                // cause. Prefer the actual admission/runtime cause kept with
                // the receipt's same original domain owner.
                match self.receipt.failure() {
                    Some(crate::ProductionOriginalMountReceiptFailureV1::Authority(cause)) => {
                        Some(ProductionOriginalMountCycleFailureV1::Receipt(
                            crate::ProductionOriginalMountReceiptFailureV1::Authority(cause),
                        ))
                    }
                    _ => self.mount_result.as_ref()
                        .and_then(|result| result.as_ref().err())
                        .or_else(|| self.response_result.as_ref().and_then(|result| result.as_ref().err()))
                        .map(ProductionOriginalMountCycleFailureV1::Mount),
                }
            }
            Some(OriginalMountCycleStageV1::Deadline) => self.deadline_result.as_ref().and_then(|result| result.as_ref().err()).map(ProductionOriginalMountCycleFailureV1::Deadline),
            None if self.receipt.original_release_root_loan_pending() => self.root.failure()
                .map(ProductionOriginalMountCycleFailureV1::Root),
            None => self.receipt.selected_failure_for_cycle()
                .map(ProductionOriginalMountCycleFailureV1::Receipt),
        };
        failure.or_else(|| self.ended.then_some(ProductionOriginalMountCycleFailureV1::Ended))
    }

    fn failure_or_ended(&self) -> ProductionOriginalMountCycleFailureV1<'_> {
        self.failure().unwrap_or(ProductionOriginalMountCycleFailureV1::Ended)
    }

    /// Ends both same-original queues before any descendant prefix drops.
    pub fn end(&mut self) {
        self.ended = true;
        if let Some(startup) = self.startup.as_mut() {
            startup.end();
        }
        self.root.end();
        self.receipt.end();
    }
}

impl Drop for ProductionOriginalMountCycleV1 {
    fn drop(&mut self) {
        self.end();
    }
}

