//! Closed receiving stages and a same-original protected Session replay loan.
//!
//! Upper schema/body values are representation DATA charged under the genuine
//! receiver. Only actual original borrow paths create a loan; staged replay is
//! inseparable from the actual prepared Native opener through both debits.

use super::*;

/// Retains one actual rooted/name pass and its independent original post.
///
/// This private DATA destination is funded only by the genuine fixed Session
/// entry. Positive native disposal and a positive independent post are both
/// required before its resident peak can hold a later fresh sample.
pub(super) struct SessionJournalObservationV1 {
    demand: Option<Result<ResourceVector, crate::JournalError>>,
    paid: bool,
    originals: crate::journal::ProtectedJournalCurrentnessOriginalsV1,
    result: Option<Result<(), crate::JournalError>>,
    post: Option<NativeResult>,
    settled: bool,
}

impl SessionJournalObservationV1 {
    pub(super) const fn new() -> Self {
        Self {
            demand: None,
            paid: false,
            originals: crate::journal::ProtectedJournalCurrentnessOriginalsV1::new(),
            result: None,
            post: None,
            settled: false,
        }
    }

    pub(super) fn observe(&mut self, journal: &crate::Journal) -> bool {
        if !self.paid || self.result.is_some() && !self.settled {
            return false;
        }
        if self.settled {
            // The previous local interval actually completed both posts and
            // disposed its files and Vec backing before this peak is reused.
            self.originals = crate::journal::ProtectedJournalCurrentnessOriginalsV1::new();
            self.result = None;
            self.post = None;
            self.settled = false;
        }
        self.result = Some(journal.validate_held_owned_at_for_uid_retaining(
            std::path::Path::new("/var/lib/aos/sandbox-storage/broker-session"),
            "session.journal",
            0,
            &mut self.originals,
        ));
        matches!(self.result, Some(Ok(())))
    }

    pub(super) fn settle_positive(&mut self) {
        if matches!(self.result, Some(Ok(())))
            && matches!(self.post, Some(Ok(())))
            && self.originals.is_complete()
        {
            self.originals.settle_positive_once_v1();
            self.settled = true;
        }
    }

    pub(super) fn failure(&self) -> Option<&(dyn Error + 'static)> {
        self.demand.as_ref().and_then(|result| result.as_ref().err())
            .map(|cause| cause as &dyn Error)
            .or_else(|| self.originals.failure())
            .or_else(|| self.result.as_ref().and_then(|result| result.as_ref().err())
                .map(|cause| cause as &dyn Error))
            .or_else(|| native_failure(&self.post))
    }
}

/// Retains the real arithmetic reservation and independent original post.
pub(super) struct OutcomeReservationV1 {
    reservation: Option<Result<(), aos_sandbox_core::AccountingError>>,
    current: Option<NativeResult>,
}

impl OutcomeReservationV1 {
    pub(super) const fn new() -> Self {
        Self { reservation: None, current: None }
    }

    pub(super) fn is_entered(&self) -> bool {
        self.reservation.is_some() || self.current.is_some()
    }

    pub(super) fn is_positive(&self) -> bool {
        matches!(self.reservation, Some(Ok(())))
            && matches!(self.current, Some(Ok(())))
    }
}

#[derive(Clone, Copy)]
enum OutcomeTurnV1 {
    Inventory,
    Prepare,
}

impl<'original> StoragePrepareReceivingLoanV1<'original> {
    /// Checks the SAME retained Session Journal before a warm continuation.
    ///
    /// The existing authority-instance Arc was captured only during the first
    /// continuously borrowed paid fixed Session replay, after independent posts.
    /// No identity, descriptor, namespace or numeric budget from the caller can
    /// replace that actual writer. This check grants no handshake/method/effect
    /// authority and does not reset once-per-boot replay/initialization stages.
    ///
    /// # Errors
    ///
    /// Refuses a different authority epoch, an active undisposed opener,
    /// unhealthy/substituted fixed root-owned names, original currentness debt
    /// or prior failure. The whole Native named Result and independent original
    /// post stay retained; the earlier named failure wins over later post debt.
    pub fn require_retained_session_journal_v1(
        &mut self,
        journal: &crate::Journal,
    ) -> Result<(), StorageReceivingClosedV1> {
        self.require_session_fixed_current_v1()?;
        let receiving = self.receiving()?;
        if !receiving.session_replayed || !receiving.session_initialization
            || receiving.native_opening_peak.active.is_some()
            || !receiving.session_identity.as_ref().is_some_and(|owner| owner.same_journal(journal))
        {
            receiving.first.get_or_insert(Failure::Closed);
            return Err(StorageReceivingClosedV1);
        }
        let names_failed = !receiving.session_journal.observe(journal);
        // Do not project names into first until the independently paid original
        // post has run; this exclusive borrow cannot fund another entry meanwhile.
        let post = self.original.recheck();
        let post_failed = post.is_err();
        if let Some(StorageResourceRecipientCustodyV1::Receiving { receiving, .. }) =
            self.original.recipient.as_mut()
        {
            receiving.session_journal.post = Some(post);
            if names_failed {
                receiving.first = Some(Failure::SessionJournal);
            }
        }
        if names_failed || post_failed {
            Err(StorageReceivingClosedV1)
        } else {
            if let Some(StorageResourceRecipientCustodyV1::Receiving { receiving, .. }) =
                self.original.recipient.as_mut()
            {
                receiving.session_journal.settle_positive();
            }
            Ok(())
        }
    }

    /// Pays fixed Session manifest/key/mode and Native preparation before entry.
    ///
    /// `demand` describes the upper Security objects; it supplies no authority.
    /// The fixed actual Native opener demand is added independently here.
    ///
    /// # Errors
    /// Refuses repeat payment, missing current originals or the immutable ceiling.
    pub fn reserve_session_fixed_once_v1(&mut self, demand: ResourceVector)
        -> Result<(), StorageReceivingClosedV1>
    {
        let receiving = self.receiving()?;
        if !receiving.startup.complete() || receiving.session_fixed {
            receiving.first.get_or_insert(Failure::Closed);
            return Err(StorageReceivingClosedV1);
        }
        receiving.session_journal.demand = Some(
            crate::journal::ProtectedJournalCurrentnessOriginalsV1::fixed_demand_v1(
                std::path::Path::new("/var/lib/aos/sandbox-storage/broker-session"),
                "session.journal",
            ),
        );
        let Some(Ok(currentness)) = receiving.session_journal.demand.as_ref() else {
            receiving.first.get_or_insert(Failure::SessionJournal);
            return Err(StorageReceivingClosedV1);
        };
        // This local rooted/name peak remains paid independently of the
        // temporary Native opening peak which is disposed after cold startup.
        receiving.reserve(*currentness)?;
        receiving.session_journal.paid = true;
        let native = match StorageBrokerCapturedJournalOpenV1::fixed_preparation_demand() {
            Ok(demand) => demand,
            Err(error) => {
                receiving.arithmetic = Some(error);
                receiving.first.get_or_insert(Failure::Arithmetic);
                return Err(StorageReceivingClosedV1);
            }
        };
        let demand = match demand.checked_add(native) {
            Ok(demand) => demand,
            Err(error) => {
                receiving.arithmetic = Some(error);
                receiving.first.get_or_insert(Failure::Arithmetic);
                return Err(StorageReceivingClosedV1);
            }
        };
        receiving.reserve_native_opening_v1(NativeOpeningKindV1::Session,
            demand, native.get(D::OpenFiles))?;
        receiving.session_fixed = true;
        self.require_session_fixed_current_v1()
    }

    /// Requires the same paid fixed interval and a fresh original observation.
    ///
    /// # Errors
    /// Refuses missing fixed payment or any retained accounting/startup debt.
    /// All later calls remain closed after the first actual observation failure.
    pub fn require_session_fixed_current_v1(&mut self) -> Result<(), StorageReceivingClosedV1> {
        let receiving = self.receiving()?;
        if !receiving.session_fixed {
            receiving.first = Some(Failure::Closed);
            return Err(StorageReceivingClosedV1);
        }
        self.original.recheck().map_err(|_| StorageReceivingClosedV1)
    }

    pub(super) fn post_session_journal_observation_v1(&mut self) -> Result<(), StorageReceivingClosedV1> {
        // The actual Cold owner armed this independently paid flight while the
        // same original was still admissible, before joint native work. Earlier
        // health/financial refusal cannot suppress its genuine observation.
        let post = self.finish_initial_observation_native_post_v1();
        let failed = post.is_err();
        if let Some(StorageResourceRecipientCustodyV1::Receiving { receiving, .. }) =
            self.original.recipient.as_mut()
        {
            receiving.session_journal.post = Some(post);
        }
        if failed {
            Err(StorageReceivingClosedV1)
        } else {
            Ok(())
        }
    }

    /// Pays the actual upper Session schema and initialization capacities once.
    ///
    /// Security derives this nonauthorizing DATA demand from its own retained
    /// types, canonical decoders and the same captured Native prefix. It must
    /// reserve before schema decode, initial append or checkpoint growth.
    ///
    /// # Errors
    /// Refuses missing fixed payment, repeated schema payment or an exceeded
    /// original service budget; the first actual refusal stays retained.
    pub fn reserve_session_schema_once_v1<'cut>(
        &'cut mut self,
        staged: &'cut mut StorageBrokerCapturedJournalOpenV1,
        demand: ResourceVector,
    ) -> Result<StoragePrepareSessionReplayLoanV1<'cut, 'original>, StorageReceivingClosedV1> {
        self.require_session_fixed_current_v1()?;
        let receiving = self.receiving()?;
        if receiving.session_schema || staged.captured_extent().is_none() {
            receiving.first = Some(Failure::Closed);
            return Err(StorageReceivingClosedV1);
        }
        receiving.reserve(demand)?;
        receiving.session_schema = true;
        Ok(StoragePrepareSessionReplayLoanV1 {
            receiving: self, staged, prefix_paid: false, entered: false,
        })
    }

    /// Pays postopening Session initialization and checkpoint/history growth.
    ///
    /// Security derives this DATA demand from the same captured original and
    /// reserves it before that staged Journal is taken or initialization grows.
    ///
    /// # Errors
    /// Refuses absent replay success, repeat entry or exceeded service budget.
    pub fn reserve_session_initialization_once_v1(&mut self, demand: ResourceVector)
        -> Result<(), StorageReceivingClosedV1>
    {
        let receiving = self.receiving()?;
        if !receiving.session_replayed || receiving.session_initialization {
            receiving.first = Some(Failure::Closed);
            return Err(StorageReceivingClosedV1);
        }
        receiving.reserve(demand)?;
        receiving.session_initialization = true;
        Ok(())
    }

    /// Pays both retained Inventory and Prepare wire turns before first receive.
    ///
    /// Security derives this DATA demand from its actual raw/canonical objects,
    /// selected method schemas and existing decoder limits. It is not funding
    /// or permission to receive without that protected Session's own custody.
    ///
    /// # Errors
    /// Refuses missing original stages, repeat entry or exceeded service budget.
    pub fn reserve_prepare_wire_once_v1(&mut self, demand: ResourceVector)
        -> Result<(), StorageReceivingClosedV1>
    {
        let receiving = self.receiving()?;
        if !receiving.session_initialization || receiving.prepare_wire {
            receiving.first = Some(Failure::Closed);
            return Err(StorageReceivingClosedV1);
        }
        receiving.reserve(demand)?;
        receiving.prepare_wire = true;
        self.require_prepare_retention_v1()
    }

    /// Requires original receiving and both paid retained request-turn shapes.
    ///
    /// # Errors
    /// Refuses absent paid stages, retained failure or changed actual startup.
    pub fn require_prepare_retention_v1(&mut self) -> Result<(), StorageReceivingClosedV1> {
        let receiving = self.receiving()?;
        if !receiving.prepare_wire || !receiving.session_initialization {
            receiving.first = Some(Failure::Closed);
            return Err(StorageReceivingClosedV1);
        }
        self.original.recheck().map_err(|_| StorageReceivingClosedV1)
    }

    /// Pays additional catalog/workspace-backed Inventory models and body.
    ///
    /// Storage derives this DATA from its independently held State/workspace
    /// owners and fixed observation protocol before any inventory construction.
    /// It cannot be inferred from Session history or its packet ceiling. The
    /// actual fixed observer peak must already be paid by this same original;
    /// its successful settled reuse is not another retained domain model.
    ///
    /// # Errors
    /// Refuses missing paid request stages, repeat entry or an exceeded envelope.
    pub fn reserve_inventory_retention_once_v1(&mut self, demand: ResourceVector)
        -> Result<(), StorageReceivingClosedV1>
    {
        let receiving = self.receiving()?;
        if !receiving.prepare_wire || !receiving.catalog_observer_peak_paid
            || receiving.inventory_paid
        {
            receiving.first = Some(Failure::Closed);
            return Err(StorageReceivingClosedV1);
        }
        receiving.reserve(demand)?;
        receiving.inventory_paid = true;
        Ok(())
    }

    /// Pays later copies, signing and history growth for the actual Inventory body.
    ///
    /// The upper Session owner derives this DATA only after parking its real
    /// domain response. Storage's earlier domain debit pays construction of
    /// that original response; this distinct debit precedes its later copies.
    ///
    /// # Errors
    /// Refuses absent domain payment, repeat entry or original custody/budget
    /// failure. The whole arithmetic result and currentness post stay retained.
    pub fn reserve_inventory_outcome_once_v1(&mut self, demand: ResourceVector)
        -> Result<(), StorageReceivingClosedV1>
    {
        self.reserve_outcome_once_v1(OutcomeTurnV1::Inventory, demand)
    }

    /// Pays later copies, signing and history growth for the actual Prepared body.
    ///
    /// This is the second closed outcome slot on the same receiving original.
    /// The actual protected Session method selects it; no index, length or
    /// DATA vector can create another receiving interval or authorize a reply.
    ///
    /// # Errors
    /// Refuses a partially entered or failed Inventory outcome, absent catalog
    /// payment, repeated entry or an original custody/budget failure. Inventory
    /// may be absent on the existing supported direct-Prepare route.
    pub fn reserve_prepare_outcome_once_v1(&mut self, demand: ResourceVector)
        -> Result<(), StorageReceivingClosedV1>
    {
        self.reserve_outcome_once_v1(OutcomeTurnV1::Prepare, demand)
    }

    fn reserve_outcome_once_v1(&mut self, turn: OutcomeTurnV1, demand: ResourceVector)
        -> Result<(), StorageReceivingClosedV1>
    {
        self.require_prepare_retention_v1()?;
        let receiving = self.receiving()?;
        let eligible = match turn {
            OutcomeTurnV1::Inventory => receiving.inventory_paid
                && receiving.inventory_outcome.reservation.is_none()
                && receiving.prepare_outcome.reservation.is_none(),
            OutcomeTurnV1::Prepare => receiving.catalog_paid
                && ((!receiving.inventory_paid
                    && receiving.inventory_outcome.reservation.is_none())
                    || receiving.inventory_outcome.is_positive())
                && receiving.prepare_outcome.reservation.is_none(),
        };
        if !eligible {
            receiving.first.get_or_insert(Failure::Closed);
            return Err(StorageReceivingClosedV1);
        }

        // The ledger retains the actual first arithmetic error. The closed
        // turn also keeps its complete returned reservation, before any post.
        let reservation = receiving.ledger.reserve(demand).map_err(|cause| *cause);
        let slot = match turn {
            OutcomeTurnV1::Inventory => &mut receiving.inventory_outcome,
            OutcomeTurnV1::Prepare => &mut receiving.prepare_outcome,
        };
        slot.reservation = Some(reservation);
        if matches!(slot.reservation, Some(Err(_))) {
            receiving.first.get_or_insert(Failure::Accounting);
            return Err(StorageReceivingClosedV1);
        }

        let current = self.original.recheck();
        let positive = current.is_ok();
        // Access the retained original directly even after a failed recheck:
        // the positive-only accessor would hide precisely this failed post.
        if let Some(StorageResourceRecipientCustodyV1::Receiving { receiving, .. }) =
            self.original.recipient.as_mut()
        {
            let slot = match turn {
                OutcomeTurnV1::Inventory => &mut receiving.inventory_outcome,
                OutcomeTurnV1::Prepare => &mut receiving.prepare_outcome,
            };
            slot.current = Some(current);
        }
        if positive { Ok(()) } else { Err(StorageReceivingClosedV1) }
    }

    /// Pays a separate reusable exact-terminal-replay transport lane once.
    ///
    /// Security keeps its actual Prepared/current outcome owner independently.
    /// This DATA debit grants no resend or effect permission. Reuse requires
    /// complete exact resend/posts and actual positive carrier disposal there.
    ///
    /// # Errors
    /// Refuses missing original stages, repeat payment or an exceeded envelope.
    pub fn reserve_prepare_replay_lane_once_v1(&mut self, demand: ResourceVector)
        -> Result<(), StorageReceivingClosedV1>
    {
        let receiving = self.receiving()?;
        if !receiving.prepare_wire || !receiving.catalog_paid || receiving.replay_lane_paid {
            receiving.first = Some(Failure::Closed);
            return Err(StorageReceivingClosedV1);
        }
        receiving.reserve(demand)?;
        receiving.replay_lane_paid = true;
        Ok(())
    }

    /// Requires current original custody and the separate paid replay carrier.
    ///
    /// # Errors
    /// Refuses missing lane payment, retained native debt or changed originals.
    pub fn require_prepare_replay_lane_current_v1(&mut self)
        -> Result<(), StorageReceivingClosedV1>
    {
        let receiving = self.receiving()?;
        if !receiving.replay_lane_paid || !receiving.catalog_paid {
            receiving.first = Some(Failure::Closed);
            return Err(StorageReceivingClosedV1);
        }
        self.require_prepare_retention_v1()
    }

    /// Pays the concrete Storage catalog/body retention before allocation.
    ///
    /// This describes upper Storage objects under the genuine same service
    /// envelope. It supplies no grant, writer or signing capability.
    ///
    /// # Errors
    /// Refuses an absent Session stage, repeated entry or exceeded service budget.
    pub fn reserve_catalog_retention_once_v1(&mut self, demand: ResourceVector)
        -> Result<(), StorageReceivingClosedV1>
    {
        let receiving = self.receiving()?;
        if !receiving.prepare_wire || !receiving.session_replayed || receiving.catalog_paid {
            receiving.first = Some(Failure::Closed);
            return Err(StorageReceivingClosedV1);
        }
        receiving.reserve(demand)?;
        receiving.catalog_paid = true;
        Ok(())
    }

    /// Retains the exact ordinary Native bootstrap append in its paid startup stage.
    ///
    /// This adds no journal authority or semantic exception. The fixed Storage
    /// constructor supplies its protected snapshot; Native ordinary commit
    /// performs every existing namespace/currentness/ordering guard unchanged.
    ///
    /// # Errors
    /// Refuses missing initialization payment, wrong phase, reentry or any
    /// actual Native/readback/name failure. The whole result remains resident.
    pub fn commit_state_bootstrap_once_v1(
        &mut self, journal: &mut crate::Journal, transaction: &crate::JournalTransaction,
    ) -> Result<(), StorageReceivingClosedV1> {
        self.original.recheck().map_err(|_| StorageReceivingClosedV1)?;
        let receiving = self.receiving()?;
        if !receiving.startup.state_ready_for_initialization() {
            receiving.first.get_or_insert(Failure::Closed);
            return Err(StorageReceivingClosedV1);
        }
        let result = receiving.startup_bootstrap.append_ordinary_once(journal, transaction);
        if result.is_err() { receiving.first.get_or_insert(Failure::StartupBootstrap); }
        result
    }

    /// Retains the fixed resolver-floor append before workspace startup begins.
    ///
    /// The exact policy binding comes from the actual protected Storage reader.
    /// This funding restriction cannot create a policy, HMAC, grant or writer.
    ///
    /// # Errors
    /// Refuses missing initialization payment, wrong phase, reentry or an
    /// actual Native/readback/name failure, preserving the original first cause.
    pub fn commit_startup_resolver_floor_once_v1(
        &mut self, journal: &mut crate::Journal, transaction: &crate::JournalTransaction,
    ) -> Result<(), StorageReceivingClosedV1> {
        self.original.recheck().map_err(|_| StorageReceivingClosedV1)?;
        let receiving = self.receiving()?;
        if !receiving.startup.state_ready_for_initialization() {
            receiving.first.get_or_insert(Failure::Closed);
            return Err(StorageReceivingClosedV1);
        }
        let result = receiving.startup_resolver_floor.append_ordinary_once(journal, transaction);
        if result.is_err() { receiving.first.get_or_insert(Failure::StartupResolverFloor); }
        result
    }

    /// Reports actual startup Native/readback/name uncertainty requiring reopen.
    pub fn state_startup_requires_reopen_v1(&self) -> bool {
        match self.original.recipient.as_ref() {
            Some(StorageResourceRecipientCustodyV1::Receiving { receiving, .. }) =>
                receiving.startup_bootstrap.requires_reopen()
                    || receiving.startup_resolver_floor.requires_reopen(),
            _ => true,
        }
    }

    /// Retains a fresh protected resolver-floor prefix during selected Prepare.
    ///
    /// This is the server's independently trusted policy publication, not a
    /// replacement for the later request-bound preparation clock. Native's
    /// ordinary semantic guards remain unchanged at this prefix as well.
    ///
    /// # Errors
    /// Refuses absent catalog payment/current originals, reentry or an actual
    /// Native/readback/name error. All original Results remain resident.
    pub fn commit_prepare_resolver_floor_once_v1(
        &mut self, journal: &mut crate::Journal, transaction: &crate::JournalTransaction,
    ) -> Result<(), StorageReceivingClosedV1> {
        self.require_prepare_retention_v1()?;
        let receiving = self.receiving()?;
        if !receiving.prepare_policy_append_paid || !receiving.catalog_paid {
            receiving.first.get_or_insert(Failure::Closed);
            return Err(StorageReceivingClosedV1);
        }
        let result = receiving.prepare_resolver_floor.append_ordinary_once(journal, transaction);
        if result.is_err() { receiving.first.get_or_insert(Failure::PrepareResolverFloor); }
        result
    }

    /// Pays the actual four-member append shape before Record/key/frame growth.
    ///
    /// # Errors
    /// Refuses missing domain payment, reentry or the original immutable ceiling.
    pub fn reserve_catalog_append_once_v1(
        &mut self,
        demand: ResourceVector,
    ) -> Result<(), StorageReceivingClosedV1> {
        self.require_prepare_retention_v1()?;
        let receiving = self.receiving()?;
        if !receiving.catalog_paid || receiving.catalog_append_paid
            || (receiving.prepare_policy_append_paid && !receiving.prepare_resolver_floor.is_positive())
        {
            receiving.first.get_or_insert(Failure::Closed);
            return Err(StorageReceivingClosedV1);
        }
        receiving.reserve_preparation_append_bound_v1(demand)?;
        receiving.catalog_append_paid = true;
        Ok(())
    }

    /// Pays the actual fixed policy-floor append before its encoder enters.
    ///
    /// # Errors
    /// Refuses missing domain payment, repeated entry or an exceeded envelope.
    pub fn reserve_prepare_policy_append_once_v1(
        &mut self,
        demand: ResourceVector,
    ) -> Result<(), StorageReceivingClosedV1> {
        self.require_prepare_retention_v1()?;
        let receiving = self.receiving()?;
        if !receiving.catalog_paid || receiving.prepare_policy_append_paid {
            receiving.first.get_or_insert(Failure::Closed);
            return Err(StorageReceivingClosedV1);
        }
        receiving.reserve_preparation_append_bound_v1(demand)?;
        receiving.prepare_policy_append_paid = true;
        Ok(())
    }

    /// Retains one actual ordinary catalog append and independent Native posts.
    ///
    /// The exact Broker loan adds its authenticated final effect deadline at
    /// Native's actual append frontier. All ordinary semantic guards still run.
    ///
    /// # Errors
    /// Refuses missing paid stages/current originals, exact transaction mismatch,
    /// Native/clock/readback/name errors or reentry. The original whole results
    /// remain resident through all later catalog/Session/response projections.
    pub fn commit_catalog_preparation_once_v1(
        &mut self,
        journal: &mut crate::Journal,
        transaction: &crate::JournalTransaction,
        clock: Result<aos_sandbox_broker::StoragePrepareNativeClockLoanV1<'_>,
                      aos_sandbox_broker::BrokerAdmissionError>,
    ) -> Result<(), StorageReceivingClosedV1> {
        self.require_prepare_retention_v1()?;
        let receiving = self.receiving()?;
        if !receiving.catalog_paid || !receiving.catalog_append_paid
            || !receiving.session_schema || !receiving.session_prefix {
            receiving.first = Some(Failure::Closed);
            return Err(StorageReceivingClosedV1);
        }
        let result = receiving.catalog.append_once(journal, transaction, clock);
        if result.is_err() { receiving.first = Some(Failure::Catalog); }
        result
    }

    /// Borrows the whole first native catalog result on this original receiver.
    pub fn catalog_native_result_v1(&self) -> Option<&Result<crate::CommitResult, crate::JournalError>> {
        match self.original.recipient.as_ref() {
            Some(StorageResourceRecipientCustodyV1::Receiving { receiving, .. }) => receiving.catalog.native_result(),
            _ => None,
        }
    }

    /// Reports actual Native uncertainty requiring protected reopen, as DATA.
    pub fn catalog_requires_reopen_v1(&self) -> bool {
        match self.original.recipient.as_ref() {
            Some(StorageResourceRecipientCustodyV1::Receiving { receiving, .. }) => receiving.catalog.requires_reopen()
                || receiving.prepare_resolver_floor.requires_reopen(),
            _ => true,
        }
    }

    /// Borrows the actual first receiving cause retained by the original owner.
    pub fn failure(&self) -> Option<&(dyn Error + 'static)> {
        match self.original.recipient.as_ref() {
            Some(StorageResourceRecipientCustodyV1::Receiving { receiving, .. }) => receiving.failure(),
            _ => Some(&StorageReceivingClosedV1),
        }
    }
}

/// Keeps one admitted actual Session opener joined to its original payer.
#[must_use]
pub struct StoragePrepareSessionReplayLoanV1<'cut, 'original> {
    receiving: &'cut mut StoragePrepareReceivingLoanV1<'original>,
    staged: &'cut mut StorageBrokerCapturedJournalOpenV1,
    prefix_paid: bool,
    entered: bool,
}

impl StoragePrepareSessionReplayLoanV1<'_, '_> {
    /// Pays Native and semantic replay from this same captured physical owner.
    ///
    /// # Errors
    /// Refuses repeated entry, missing actual extent, arithmetic/shape refusal or
    /// dominant capacities beyond the immutable original receiving envelope.
    pub fn reserve_session_prefix_once_v1(&mut self) -> Result<(), StorageReceivingClosedV1> {
        self.receiving.require_session_fixed_current_v1()?;
        let receiving = self.receiving.receiving()?;
        if self.prefix_paid || receiving.session_prefix {
            receiving.first = Some(Failure::Closed);
            return Err(StorageReceivingClosedV1);
        }
        receiving.session_prefix = true;
        let Some(extent) = self.staged.captured_extent() else {
            receiving.first.get_or_insert(Failure::Closed);
            return Err(StorageReceivingClosedV1);
        };
        let native = extent.dominant_native_receiving_demand_v1();
        let semantic = extent.dominant_semantic_receiving_demand_v1();
        let (native, semantic) = match (native, semantic) {
            (Ok(native), Ok(semantic)) => (native, semantic),
            (Err(error), _) | (_, Err(error)) => {
                receiving.shape = Some(error);
                receiving.first.get_or_insert(Failure::Shape);
                return Err(StorageReceivingClosedV1);
            }
        };
        let demand = match native.checked_add(semantic) {
            Ok(demand) => demand,
            Err(error) => {
                receiving.arithmetic = Some(error);
                receiving.first.get_or_insert(Failure::Arithmetic);
                return Err(StorageReceivingClosedV1);
            }
        };
        receiving.reserve(demand)?;
        self.prefix_paid = true;
        Ok(())
    }

    /// Replays the same held opener once and keeps its complete Native Results.
    ///
    /// # Errors
    /// Refuses reentry, changed original custody or an actual retained replay,
    /// metadata, name, repair or currentness refusal. There is no retry opener.
    pub fn replay_session_once_v1(&mut self) -> Result<(), StorageReceivingClosedV1> {
        if self.entered || !self.prefix_paid {
            if let Ok(receiving) = self.receiving.receiving() {
                receiving.first.get_or_insert(Failure::Closed);
            }
            return Err(StorageReceivingClosedV1);
        }
        self.entered = true;
        self.receiving.require_session_fixed_current_v1()?;
        self.staged.replay_once();
        let replay_ready = self.staged.replay_ready();
        let post = self.receiving.require_session_fixed_current_v1();
        if !replay_ready {
            if let Ok(receiving) = self.receiving.receiving() {
                receiving.first.get_or_insert(Failure::Closed);
            }
            return Err(StorageReceivingClosedV1);
        }
        post?;
        let Some(owner) = self.staged.opening_owner_link_v1() else {
            if let Ok(receiving) = self.receiving.receiving() {
                receiving.first.get_or_insert(Failure::Closed);
            }
            return Err(StorageReceivingClosedV1);
        };
        self.receiving.receiving()?.bind_native_opening_owner_v1(
            NativeOpeningKindV1::Session, owner,
        )?;
        self.receiving.receiving()?.session_replayed = true;
        Ok(())
    }
}

impl StorageReceivingOriginalV1 {
    fn reserve_preparation_append_bound_v1(
        &mut self,
        demand: ResourceVector,
    ) -> Result<(), StorageReceivingClosedV1> {
        use crate::controller_resource_reservation::component_receiving::complete_bound_delta_v1;

        let (high_water, delta) = match complete_bound_delta_v1(
            self.preparation_append_high_water,
            demand,
        ) {
            Ok(bound) => bound,
            Err(cause) => {
                self.arithmetic = Some(cause);
                self.first.get_or_insert(Failure::Arithmetic);
                return Err(StorageReceivingClosedV1);
            }
        };
        self.reserve(delta)?;
        self.preparation_append_high_water = high_water;
        Ok(())
    }
}
