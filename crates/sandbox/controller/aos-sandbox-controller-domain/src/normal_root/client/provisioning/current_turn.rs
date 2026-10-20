//! Bounds one actual publication phase by original Root and paired bookends.
//!
//! The actual immutable Action contract selects the turn. The peer anchors,
//! paid refusal destination and same C23 original stay owned throughout the
//! native body. None of these observations completes its semantic Action.

use super::*;
use crate::cold_launch_publication::{OriginalPublicationActionV1,
    action::PublicationActionContractV1};
use crate::CreateProvisioningOriginalsV1;
use aos_sandbox_model::ResourceDimension as D;

#[derive(Default)]
pub(super) struct PublicationTurnStateV1 {
    entered: bool,
    association: Option<Result<(), ApplyRootDataErrorV1>>,
    current: Option<Result<(), ResourceReservationErrorV1>>,
    admission: Option<Result<(), ResourceReservationErrorV1>>,
    funding_original: bool,
    original: Option<Box<TurnOriginalV1>>,
    refusal: Option<Box<RefusalOriginalV1>>,
    first: Option<EntryFailureV1>,
    reentry: Option<Closed>,
}

#[derive(Clone, Copy)]
enum EntryFailureV1 { Association, Current, Funding, Clock, Time, Peer, SigningEntry, SigningClock, SigningTime, Reentry }

enum TurnBindingV1 {
    Construction,
    Publication(Arc<PublicationActionContractV1>),
}

struct TurnOriginalV1 {
    binding: TurnBindingV1,
    signing_entry: Option<Result<(), ResourceReservationErrorV1>>,
    signing_clock: RetainedKernelPairedClockAttemptV1,
    signing_sample: Option<Result<RawPairedClockSample, SourceGenesisErrorV1>>,
    signing_time: Option<Result<(), ApplyRootDataErrorV1>>,
    before_clock: RetainedKernelPairedClockAttemptV1,
    before_sample: Option<Result<RawPairedClockSample, SourceGenesisErrorV1>>,
    before_time: Option<Result<(), ApplyRootDataErrorV1>>,
    before_peer: PeerSampleV1,
    before: Option<Result<(), NormalRootStartupErrorV1>>,
    after_peer: PeerSampleV1,
    after: Option<Result<(), NormalRootStartupErrorV1>>,
    after_clock: RetainedKernelPairedClockAttemptV1,
    after_sample: Option<Result<RawPairedClockSample, SourceGenesisErrorV1>>,
    after_time: Option<Result<(), ApplyRootDataErrorV1>>,
    returned_original: Option<Result<(), ResourceReservationErrorV1>>,
    settlement: Option<Result<(), NormalRootStartupErrorV1>>,
    after_entered: bool,
    complete: bool,
}

pub(super) use super::super::peer_receiving::refusal::RootPeerRefusalOriginalV1 as RefusalOriginalV1;

impl TurnOriginalV1 {
    fn new(binding: TurnBindingV1) -> Self {
        Self { binding, signing_entry: None, signing_clock: Default::default(),
            signing_sample: None, signing_time: None, before_clock: Default::default(), before_sample: None,
            before_time: None, before_peer: PeerSampleV1::new(), before: None,
            after_peer: PeerSampleV1::new(), after: None,
            after_clock: Default::default(), after_sample: None, after_time: None,
            returned_original: None, settlement: None, after_entered: false, complete: false }
    }
}

impl PublicationTurnStateV1 {
    pub(super) fn property_failure_view_v1(&self)
        -> Option<aos_systemd_client::FixedPid1PropertyFailureViewV1<'_>> {
        let marker = self.failure()?.downcast_ref::<aos_systemd_client::FixedPid1PropertyErrorV1>()?;
        let original = self.original.as_deref()?;
        for sample in [&original.before_peer, &original.after_peer] {
            if super::diagnostics::same_property_marker_v1(marker, sample.failure()) {
                return sample.property_failure_view_v1();
            }
        }
        None
    }

    pub(super) fn failure(&self) -> Option<&(dyn Error + 'static)> {
        let original = self.original.as_deref();
        let primary = match self.first {
            Some(EntryFailureV1::Association) => cause(&self.association),
            Some(EntryFailureV1::Current) => cause(&self.current),
            Some(EntryFailureV1::Funding) => cause(&self.admission),
            Some(EntryFailureV1::Clock) => original.and_then(|value|
                value.before_clock.failure().or_else(|| cause(&value.before_sample))),
            Some(EntryFailureV1::Time) => original.and_then(|value| cause(&value.before_time)),
            Some(EntryFailureV1::Peer) => original.and_then(|value|
                value.before_peer.failure().or_else(|| cause(&value.before))),
            Some(EntryFailureV1::SigningEntry) => original.and_then(|value| cause(&value.signing_entry)),
            Some(EntryFailureV1::SigningClock) => original.and_then(|value|
                value.signing_clock.failure().or_else(|| cause(&value.signing_sample))),
            Some(EntryFailureV1::SigningTime) => original.and_then(|value| cause(&value.signing_time)),
            Some(EntryFailureV1::Reentry) => self.reentry.as_ref().map(|cause| cause as _),
            None => None,
        };
        primary.or_else(|| original.and_then(|value| {
            value.after_peer.failure().or_else(|| cause(&value.after))
                .or_else(|| value.after_clock.failure()).or_else(|| cause(&value.after_sample))
                .or_else(|| cause(&value.after_time)).or_else(|| cause(&value.returned_original))
                .or_else(|| cause(&value.settlement))
        })).or_else(|| self.refusal.as_deref().and_then(RefusalOriginalV1::failure))
    }
}

impl RootStorageApplyClientOriginalV1 {
    /// Prices the retained completed Root client without future peer traffic.
    ///
    /// The completed turn still owns its native samplers until actual positive
    /// retirement. Settling the property archives alone supplies no FD credit.
    ///
    /// # Errors
    /// Refuses an active or failed prior turn and checked native geometry overflow.
    #[doc(hidden)]
    pub fn resident_receiving_demand_v1(&self)
        -> Result<ResourceVector, ResourceReservationErrorV1> {
        self.resident_demand_v1()?.checked_add(self.completed_turn_resident_demand_v1()?)
            .map_err(ResourceReservationErrorV1::from)
    }

    pub(super) fn completed_turn_resident_demand_v1(&self)
        -> Result<ResourceVector, ResourceReservationErrorV1> {
        if self.publication.failure().is_some() {
            return Err(ResourceReservationErrorV1::Conflict);
        }
        match self.publication.original.as_ref() {
            Some(turn) if turn.complete => Self::publication_turn_demand_v1(&self.profile),
            Some(_) => Err(ResourceReservationErrorV1::Conflict),
            None => {
                let bytes = std::mem::size_of::<RefusalOriginalV1>().checked_mul(2)
                    .and_then(|bytes| u64::try_from(bytes).ok())
                    .ok_or(ResourceReservationErrorV1::Conflict)?;
                Ok(ResourceVector::ZERO.with(D::MemoryBytes, bytes))
            }
        }
    }

    // The genuine pre-ACK caller checks the actual Action/Source association
    // before this positive-only handoff. Retire the whole completed native
    // leaf, not just its property archives, before lending its capacity to the
    // distinct final exchange. Failed native prefixes remain resident.
    pub(super) fn retire_completed_turn_for_final_once_v1(&mut self)
        -> Result<(), ResourceReservationErrorV1> {
        let turn = self.publication.original.as_ref()
            .ok_or(ResourceReservationErrorV1::Conflict)?;
        if self.first.is_some() || self.publication.failure().is_some()
            || self.publication.reentry.is_some() || !turn.complete
            || !turn.after_entered
            || !matches!(turn.returned_original, Some(Ok(())))
            || !matches!(turn.settlement, Some(Ok(()))) {
            return Err(ResourceReservationErrorV1::Conflict);
        }
        self.publication = PublicationTurnStateV1::default();
        Ok(())
    }

    /// Arms actual Root and clock before/after for one private Action phase.
    ///
    /// A refused admission consumes the spare paid by the preceding positive
    /// purpose. The Core caller still finishes the independently owned C23 post
    /// and calls this client's unconditional after on every entered result.
    ///
    /// # Errors
    /// Retains a changed contract, financial refusal, native/clock error or
    /// expired original horizon. Reentry never replaces a failed destination.
    #[doc(hidden)]
    pub fn begin_publication_turn_once_v1(&mut self,
        loan: &mut OriginalCreateProvisioningRootLoanV1<'_, '_>,
        controller: &Journal, action: &OriginalPublicationActionV1,
        co_resident: ResourceVector,
    ) -> Result<(), Closed> {
        self.begin_turn_once(loan, controller, action.parent_operation_v1(),
            Ok(action.root_admission_commitment_v1()),
            TurnBindingV1::Publication(Arc::clone(action.contract_v1())), co_resident)
    }

    /// Arms the real pre-Action signing and construction window.
    ///
    /// The same intrinsic Root owner selects this one fixed purpose. No Action,
    /// caller-built phase, copied clock or success boolean constructs it.
    ///
    /// # Errors
    /// Retains association, financial, native and original temporal refusals.
    #[doc(hidden)]
    pub fn begin_construction_turn_once_v1(&mut self,
        loan: &mut OriginalCreateProvisioningRootLoanV1<'_, '_>,
        controller: &Journal, co_resident: ResourceVector,
    ) -> Result<(), Closed> {
        if self.construction_entered {
            self.publication.reentry.get_or_insert(self.closed);
            self.publication.first.get_or_insert(EntryFailureV1::Reentry);
            return Err(self.closed);
        }
        self.construction_entered = true;
        let digest = StorageApplyReplyDataV1::decode_v1(self.state.received.bytes())
            .and_then(|reply| reply.digest_v1());
        self.begin_turn_once(loan, controller, self.parent, digest,
            TurnBindingV1::Construction, co_resident)
    }

    fn begin_turn_once(&mut self,
        loan: &mut OriginalCreateProvisioningRootLoanV1<'_, '_>, controller: &Journal,
        parent: OperationId, admission: Result<[u8; 32], ApplyRootDataErrorV1>,
        binding: TurnBindingV1, co_resident: ResourceVector,
    ) -> Result<(), Closed> {
        if self.final_exchange.started_v1() {
            self.publication.reentry.get_or_insert(self.closed);
            self.publication.first.get_or_insert(EntryFailureV1::Reentry);
            return Err(self.closed);
        }
        if self.publication.entered {
            let completed = self.publication.original.as_ref().is_some_and(|turn| turn.complete);
            if !completed {
                self.publication.reentry.get_or_insert(self.closed);
                self.publication.first.get_or_insert(EntryFailureV1::Reentry);
                return Err(self.closed);
            }
            // The actual previous after joined the returned completed C23 and
            // positively settled both native samples. The fresh real Root loan
            // can exist only after that same lower original's next native turn.
            // Retire the completed native leaf; spent traffic never decreases.
            self.publication = PublicationTurnStateV1::default();
        }
        self.publication.entered = true;
        self.publication.association = Some((|| {
            if !self.admitted || self.first.is_some() || self.stable.is_none()
                || parent != self.parent
                || loan.parent_operation_v1() != self.parent
                || !std::ptr::eq(loan.profile_v1(), self.profile.as_ref())
                || loan.native_turn_v1() <= self.native_turn
                || admission? != StorageApplyReplyDataV1::decode_v1(self.state.received.bytes())?.digest_v1()?
            { return Err(ApplyRootDataErrorV1::Malformed); }
            Ok(())
        })());
        if !matches!(self.publication.association, Some(Ok(()))) {
            self.publication.first = Some(EntryFailureV1::Association);
            return Err(self.closed);
        }

        self.native_turn = loan.native_turn_v1();
        self.publication.current = Some(loan.require_current_v1(controller));
        if !matches!(self.publication.current, Some(Ok(()))) {
            self.publication.first = Some(EntryFailureV1::Current);
            return Err(self.closed);
        }

        self.publication.admission = Some((|| {
            let complete = co_resident.checked_add(self.active_turn_receiving_demand_v1()?)?;
            let debit = loan.require_complete_v1(controller, complete);
            if debit.is_err() && loan.failure_v1().is_some() {
                self.publication.funding_original = true;
            }
            debit
        })());
        if !matches!(self.publication.admission, Some(Ok(()))) {
            self.publication.first = Some(EntryFailureV1::Funding);
            return Err(self.closed);
        }

        // The existing old refusal is no longer needed once both new native
        // destinations and the next refusal's own traffic are actually paid.
        // No spent traffic or highwater is returned to the financial original.
        self.publication.original = Some(Box::new(TurnOriginalV1::new(binding)));
        self.next_refusal = Some(Box::new(RefusalOriginalV1::new()));
        let authority_expiry = retained_authority_expiry_v1(&self.state.reply);
        let original = self.publication.original.as_mut().ok_or(self.closed)?;
        original.before_sample = Some(original.before_clock.observe_once(Some(self.origin)));
        let before = match original.before_sample.as_ref() {
            Some(Ok(sample)) => *sample,
            _ => { self.publication.first = Some(EntryFailureV1::Clock); return Err(self.closed); }
        };
        original.before_time = Some((|| {
            let expiry = binding_expiry_v1(&original.binding, authority_expiry?)?;
            require_phase_sample(self.origin, self.cutoff, expiry, before)
        })());
        if !matches!(original.before_time, Some(Ok(()))) {
            self.publication.first = Some(EntryFailureV1::Time);
            return Err(self.closed);
        }
        original.before = Some(original.before_peer.observe_with_cutoff_once_v1(
            &self.profile, self.state.connection.stream().map_err(|_| self.closed)?,
            self.stable.as_ref(), None, false, self.cutoff));
        if matches!(original.before, Some(Ok(()))) { Ok(()) }
        else { self.publication.first = Some(EntryFailureV1::Peer); Err(self.closed) }
    }

    /// Runs the prepaid negative Root post after actual next-C entry refusal.
    ///
    /// This is available without minting a healthy Root loan after its original
    /// failed. It validates the same actual opaque C23 and Action identities;
    /// it can only close the flight and never issue a current-turn token.
    ///
    /// # Errors
    /// Always refuses after retaining its already paid independent native post.
    #[doc(hidden)]
    pub fn observe_publication_entry_refusal_once_v1(&mut self,
        action: &OriginalPublicationActionV1, receiving: &CreateProvisioningOriginalsV1,
        controller: &Journal,
    ) -> Result<(), Closed> {
        if self.publication.entered {
            if !self.publication.original.as_ref().is_some_and(|turn| turn.complete) {
                return Err(self.closed);
            }
            self.publication = PublicationTurnStateV1::default();
        }
        self.publication.entered = true;
        self.publication.association = Some(if action.parent_operation_v1() == self.parent
            && receiving.belongs_to_operation_v1(self.parent)
            && receiving.has_same_profile_v1(&self.profile) {
            Ok(())
        } else { Err(ApplyRootDataErrorV1::Malformed) });
        self.publication.reentry = Some(self.closed);
        self.publication.first = Some(EntryFailureV1::Reentry);
        // A real earlier original admission error remains selected. A later
        // Root native-post refusal cannot replace that same retained cause.
        self.publication.funding_original = receiving.failure().is_some();
        self.finish_turn_once(Some(action), Some(receiving), controller, false)
    }

    /// Runs the prepaid Root post when the first construction C turn refuses.
    ///
    /// # Errors
    /// Always refuses after retaining the same actual negative-only post.
    #[doc(hidden)]
    pub fn observe_construction_entry_refusal_once_v1(&mut self,
        receiving: &CreateProvisioningOriginalsV1, controller: &Journal,
    ) -> Result<(), Closed> {
        if self.construction_entered || self.publication.entered {
            return Err(self.closed);
        }
        self.construction_entered = true;
        self.publication.entered = true;
        self.publication.association = Some(if receiving.belongs_to_operation_v1(self.parent)
            && receiving.has_same_profile_v1(&self.profile) {
            Ok(())
        } else { Err(ApplyRootDataErrorV1::Malformed) });
        self.publication.reentry = Some(self.closed);
        self.publication.first = Some(EntryFailureV1::Reentry);
        self.publication.funding_original = receiving.failure().is_some();
        self.finish_turn_once(None, Some(receiving), controller, true)
    }

    /// Runs the already paid independent Root and paired after for this phase.
    ///
    /// This runs before asking whether the returned original is healthy or
    /// finished. It cannot publish semantic completion or restore failed C23.
    ///
    /// # Errors
    /// Retains every native, time, association and original completion failure.
    #[doc(hidden)]
    pub fn finish_publication_turn_once_v1(&mut self,
        action: &OriginalPublicationActionV1,
        receiving: Option<&CreateProvisioningOriginalsV1>, controller: &Journal,
    ) -> Result<(), Closed> {
        self.finish_turn_once(Some(action), receiving, controller, false)
    }

    /// Runs the owed signing/construction posts after returning the same C23.
    ///
    /// Missing/failed Action construction still runs every paid native post.
    /// Only the actual matching Action can permit positive native retirement.
    ///
    /// # Errors
    /// Retains failed construction, missing original, native and time refusals.
    #[doc(hidden)]
    pub fn finish_construction_turn_once_v1(&mut self,
        action: Option<&OriginalPublicationActionV1>,
        receiving: Option<&CreateProvisioningOriginalsV1>, controller: &Journal,
    ) -> Result<(), Closed> {
        self.finish_turn_once(action, receiving, controller, true)
    }

    fn finish_turn_once(&mut self, action: Option<&OriginalPublicationActionV1>,
        receiving: Option<&CreateProvisioningOriginalsV1>, controller: &Journal,
        construction: bool,
    ) -> Result<(), Closed> {
        if !self.publication.entered { return Err(self.closed); }
        let authority_expiry = retained_authority_expiry_v1(&self.state.reply);
        let Some(original) = self.publication.original.as_mut() else {
            if self.publication.refusal.is_some() { return Err(self.closed); }
            self.publication.refusal = self.next_refusal.take();
            if let (Some(refusal), Ok(stream)) = (
                self.publication.refusal.as_mut(), self.state.connection.stream()) {
                refusal.observe_once(&self.profile, stream, self.stable.as_ref(), self.origin, self.cutoff);
            }
            return Err(self.closed);
        };
        if original.after_entered { return Err(self.closed); }
        original.after_entered = true;
        original.after = Some(match self.state.connection.stream() {
            Ok(stream) => original.after_peer.observe_with_cutoff_once_v1(
                &self.profile, stream, self.stable.as_ref(), None, true, self.cutoff),
            Err(_) => Err(NormalRootStartupErrorV1::Service),
        });
        original.after_sample = Some(original.after_clock.observe_once(Some(self.origin)));
        original.after_time = Some((|| {
            let before = original.before_sample.as_ref().and_then(|r| r.as_ref().ok())
                .ok_or(ApplyRootDataErrorV1::Malformed)?;
            let after = *original.after_sample.as_ref().and_then(|r| r.as_ref().ok())
                .ok_or(ApplyRootDataErrorV1::Malformed)?;
            before.validate_later_sample(after).map_err(|_| ApplyRootDataErrorV1::Malformed)?;
            if let Some(Ok(signing)) = original.signing_sample.as_ref() {
                signing.validate_later_sample(after)
                    .map_err(|_| ApplyRootDataErrorV1::Malformed)?;
            }
            let mut expiry = binding_expiry_v1(&original.binding, authority_expiry?)?;
            if let Some(action) = action {
                expiry = expiry.min(action.storage_apply_plan_expires_seconds_v1()
                    .map_err(|_| ApplyRootDataErrorV1::Malformed)?);
            }
            require_phase_sample(self.origin, self.cutoff, expiry, after)
        })());
        original.returned_original = Some((|| {
            let receiving = receiving.ok_or(ResourceReservationErrorV1::Conflict)?;
            let action = action.ok_or(ResourceReservationErrorV1::Conflict)?;
            let binding_matches = match &original.binding {
                TurnBindingV1::Construction => construction
                    && matches!(original.signing_time, Some(Ok(())))
                    && action.parent_operation_v1() == self.parent
                    && action.root_admission_commitment_v1()
                        == StorageApplyReplyDataV1::decode_v1(self.state.received.bytes())
                            .and_then(|reply| reply.digest_v1())
                            .map_err(|_| ResourceReservationErrorV1::Conflict)?,
                TurnBindingV1::Publication(contract) => !construction
                    && Arc::ptr_eq(contract, action.contract_v1()),
            };
            if !binding_matches || action.failure().is_some()
                || !receiving.belongs_to_operation_v1(self.parent)
                || !receiving.has_same_profile_v1(&self.profile)
                || receiving.native_turn_v1() != self.native_turn {
                return Err(ResourceReservationErrorV1::Conflict);
            }
            receiving.require_completed_original_v1(controller)
        })());
        if self.publication.first.is_some()
            || !matches!(original.after, Some(Ok(())))
            || !matches!(original.after_time, Some(Ok(())))
            || !matches!(original.returned_original, Some(Ok(()))) {
            return Err(self.closed);
        }
        original.settlement = Some(original.before_peer.settle_positive_once()
            .and_then(|_| original.after_peer.settle_positive_once()));
        if !matches!(original.settlement, Some(Ok(()))) { return Err(self.closed); }
        original.complete = true;
        Ok(())
    }

    /// Captures the final actual clock after preparing the real signing key/message.
    ///
    /// # Errors
    /// Retains reentry, original closure, native clock and expired horizon errors.
    #[doc(hidden)]
    pub fn final_signing_clock_once_v1(&mut self,
        loan: &OriginalCreateProvisioningRootLoanV1<'_, '_>, controller: &Journal,
    ) -> Result<RawPairedClockSample, Closed> {
        let authority_expiry = retained_authority_expiry_v1(&self.state.reply);
        let original = self.publication.original.as_mut().ok_or(self.closed)?;
        if self.publication.first.is_some() || original.after_entered
            || !matches!(original.binding, TurnBindingV1::Construction)
            || !matches!(original.before, Some(Ok(())))
            || original.signing_entry.is_some() {
            self.publication.reentry.get_or_insert(self.closed);
            self.publication.first.get_or_insert(EntryFailureV1::Reentry);
            return Err(self.closed);
        }
        original.signing_entry = Some(loan.require_current_v1(controller));
        if !matches!(original.signing_entry, Some(Ok(()))) {
            self.publication.first = Some(EntryFailureV1::SigningEntry);
            return Err(self.closed);
        }
        original.signing_sample = Some(original.signing_clock.observe_once(Some(self.origin)));
        let sample = match original.signing_sample.as_ref() {
            Some(Ok(sample)) => *sample,
            _ => { self.publication.first = Some(EntryFailureV1::SigningClock); return Err(self.closed); }
        };
        original.signing_time = Some((|| {
            let before = original.before_sample.as_ref().and_then(|r| r.as_ref().ok())
                .ok_or(ApplyRootDataErrorV1::Malformed)?;
            before.validate_later_sample(sample).map_err(|_| ApplyRootDataErrorV1::Malformed)?;
            let expiry = binding_expiry_v1(&original.binding, authority_expiry?)?;
            require_phase_sample(self.origin, self.cutoff, expiry, sample)
        })());
        if matches!(original.signing_time, Some(Ok(()))) { Ok(sample) }
        else { self.publication.first = Some(EntryFailureV1::SigningTime); Err(self.closed) }
    }

    /// Borrows the real construction window without adopting a passed clock.
    ///
    /// # Errors
    /// Refuses another phase, failed before or a changed original C23 join.
    #[doc(hidden)]
    pub fn borrow_construction_turn_v1<'flight>(&'flight self,
        loan: &OriginalCreateProvisioningRootLoanV1<'_, '_>, controller: &Journal,
    ) -> Result<RootStorageApplyConstructionTurnV1<'flight>, ResourceReservationErrorV1> {
        let original = self.publication.original.as_deref().ok_or(ResourceReservationErrorV1::Conflict)?;
        if self.publication.first.is_some() || original.after_entered
            || !matches!(original.binding, TurnBindingV1::Construction)
            || !matches!(original.before, Some(Ok(())))
            || !matches!(original.before_time, Some(Ok(())))
            || loan.parent_operation_v1() != self.parent
            || !std::ptr::eq(loan.profile_v1(), self.profile.as_ref()) {
            return Err(ResourceReservationErrorV1::Conflict);
        }
        loan.require_current_v1(controller)?;
        Ok(RootStorageApplyConstructionTurnV1 { client: self })
    }

    /// Borrows a live Root window only for the actual private Action contract.
    ///
    /// # Errors
    /// Refuses incomplete before, expired entry, another contract or closed C23.
    #[doc(hidden)]
    pub fn borrow_publication_turn_v1<'flight>(&'flight self,
        action: &OriginalPublicationActionV1, receiving: &CreateProvisioningOriginalsV1,
        controller: &Journal,
    ) -> Result<RootStorageApplyCurrentTurnV1<'flight>, ResourceReservationErrorV1> {
        let token = RootStorageApplyCurrentTurnV1 { client: self };
        token.require_action_v1(action, receiving, controller)?;
        Ok(token)
    }

    /// Rejoins this exact positively settled Action turn and native original.
    ///
    /// This performs no IO or new admission. An older positive Root turn cannot
    /// cover a later native C23 interval, even on the same parent and profile.
    ///
    /// # Errors
    /// Refuses unfinished or failed Root posts, another Action contract, a
    /// changed parent/admission/native ordinal or an unfinished C23 handback.
    #[doc(hidden)]
    pub fn require_completed_publication_turn_v1(&self,
        action: &OriginalPublicationActionV1, receiving: &CreateProvisioningOriginalsV1,
        controller: &Journal,
    ) -> Result<(), ResourceReservationErrorV1> {
        let original = self.publication.original.as_deref()
            .ok_or(ResourceReservationErrorV1::Conflict)?;
        if self.first.is_some() || self.publication.first.is_some()
            || self.publication.reentry.is_some() || !original.complete
            || !original.after_entered
            || !matches!(&original.binding, TurnBindingV1::Publication(contract)
                if Arc::ptr_eq(contract, action.contract_v1()))
            || action.failure().is_some()
            || action.parent_operation_v1() != self.parent
            || action.root_admission_commitment_v1()
                != StorageApplyReplyDataV1::decode_v1(self.state.received.bytes())
                    .and_then(|reply| reply.digest_v1())
                    .map_err(|_| ResourceReservationErrorV1::Conflict)?
            || !receiving.belongs_to_operation_v1(self.parent)
            || !receiving.has_same_profile_v1(&self.profile)
            || receiving.native_turn_v1() != self.native_turn {
            return Err(ResourceReservationErrorV1::Conflict);
        }
        receiving.require_completed_original_v1(controller)
    }

    /// Rejoins the actual completed construction interval and same C23.
    ///
    /// This read performs no new admission or IO. A historical opening or a
    /// previous positive native ordinal cannot complete this action's issuance.
    ///
    /// # Errors
    /// Refuses failed/missing construction posts, a changed parent/admission,
    /// another native ordinal or an unfinished original.
    #[doc(hidden)]
    pub fn require_completed_construction_turn_v1(&self,
        action: &OriginalPublicationActionV1, receiving: &CreateProvisioningOriginalsV1,
        controller: &Journal,
    ) -> Result<(), ResourceReservationErrorV1> {
        let original = self.publication.original.as_deref()
            .ok_or(ResourceReservationErrorV1::Conflict)?;
        if self.first.is_some() || self.publication.first.is_some()
            || self.publication.reentry.is_some() || !original.complete
            || !original.after_entered
            || !matches!(original.binding, TurnBindingV1::Construction)
            || !matches!(original.signing_time, Some(Ok(())))
            || !matches!(original.returned_original, Some(Ok(())))
            || action.failure().is_some()
            || action.parent_operation_v1() != self.parent
            || action.root_admission_commitment_v1()
                != StorageApplyReplyDataV1::decode_v1(self.state.received.bytes())
                    .and_then(|reply| reply.digest_v1())
                    .map_err(|_| ResourceReservationErrorV1::Conflict)?
            || !receiving.belongs_to_operation_v1(self.parent)
            || !receiving.has_same_profile_v1(&self.profile)
            || receiving.native_turn_v1() != self.native_turn {
            return Err(ResourceReservationErrorV1::Conflict);
        }
        receiving.require_completed_original_v1(controller)
    }

    /// Borrows this turn's selected Root cause alongside the same real C23.
    #[must_use]
    pub fn publication_failure_with_original_v1<'cause>(&'cause self,
        receiving: &'cause CreateProvisioningOriginalsV1,
    ) -> Option<&'cause (dyn Error + 'static)> {
        if matches!(self.publication.first, Some(EntryFailureV1::Funding | EntryFailureV1::Reentry))
            && self.publication.funding_original
            && receiving.belongs_to_operation_v1(self.parent)
            && receiving.has_same_profile_v1(&self.profile) {
            receiving.failure().or_else(|| self.publication.failure())
        } else { self.publication.failure() }
    }

    /// Supplies every retained Root owner and this phase's actual traffic.
    ///
    /// This passive cost is joined to the reached Action/Core graph before its
    /// next debit. A prior highwater does not fund simultaneous new residents.
    ///
    /// # Errors
    /// Refuses checked compiled/native geometry overflow.
    #[doc(hidden)]
    pub fn active_turn_receiving_demand_v1(&self)
        -> Result<ResourceVector, ResourceReservationErrorV1> {
        Ok(self.resident_demand_v1()?
            .checked_add(Self::publication_turn_demand_v1(&self.profile)?)?
            .checked_add(Self::peer_traffic_v1(3)?)?)
    }

    fn publication_turn_demand_v1(profile: &ProductionControllerNormalRootProfileV1)
        -> Result<ResourceVector, ResourceReservationErrorV1> {
        let native = CreateStorageRootPeerReceivingOriginalsV1::provisioning_turn_native_peak_v1(profile)
            .ok_or(ResourceReservationErrorV1::Conflict)?;
        let clocks = RetainedKernelPairedClockAttemptV1::dominant_requested_bytes_v1()
            .and_then(|n| n.checked_mul(4)).ok_or(ResourceReservationErrorV1::Conflict)?;
        let bytes = std::mem::size_of::<TurnOriginalV1>().checked_mul(2)
            .and_then(|n| n.checked_add(std::mem::size_of::<RefusalOriginalV1>().checked_mul(3)?))
            .and_then(|n| n.checked_add(clocks))
            .and_then(|n| n.checked_add(std::mem::size_of::<RootStorageApplyCurrentTurnV1<'static>>().checked_mul(2)?))
            .and_then(|n| n.checked_add(std::mem::size_of::<RootStorageApplyConstructionTurnV1<'static>>().checked_mul(2)?))
            .and_then(|n| u64::try_from(n).ok())
            .ok_or(ResourceReservationErrorV1::Conflict)?;
        Ok(native.checked_add(ResourceVector::ZERO.with(D::MemoryBytes, bytes)
            .with(D::OpenFiles, 4 * RetainedKernelPairedClockAttemptV1::MAXIMUM_RETAINED_FILES_V1 as u64)
            .with(D::Pids, u64::try_from(CreateStorageRootPeerReceivingOriginalsV1::worker_threads_v1())
                .map_err(|_| ResourceReservationErrorV1::Conflict)?))?)
    }
}

/// Borrows one currently open native Root/paired window without owning the Action.
#[doc(hidden)]
pub struct RootStorageApplyCurrentTurnV1<'flight> { client: &'flight RootStorageApplyClientOriginalV1 }

impl RootStorageApplyCurrentTurnV1<'_> {
    pub(crate) fn receiving_demand_v1(&self) -> Result<ResourceVector, ResourceReservationErrorV1> {
        self.client.active_turn_receiving_demand_v1()
    }

    /// Borrows the actual admitted before clock under the same action/native gate.
    pub(crate) fn actual_before_clock_v1(&self, action: &OriginalPublicationActionV1,
        receiving: &CreateProvisioningOriginalsV1, controller: &Journal,
    ) -> Result<RawPairedClockSample, ResourceReservationErrorV1> {
        self.require_action_v1(action, receiving, controller)?;
        self.client.publication.original.as_deref()
            .and_then(|original| original.before_sample.as_ref())
            .and_then(|result| result.as_ref().ok()).copied()
            .ok_or(ResourceReservationErrorV1::Conflict)
    }

    /// Borrows the same actual Root-admitted plan after the exact current join.
    pub(crate) fn admitted_canonical_plan_v1(&self, action: &OriginalPublicationActionV1,
        receiving: &CreateProvisioningOriginalsV1, controller: &Journal,
    ) -> Result<&[u8], ResourceReservationErrorV1> {
        self.require_action_v1(action, receiving, controller)?;
        Ok(StorageApplyReplyDataV1::decode_v1(self.client.state.received.bytes())
            .map_err(|_| ResourceReservationErrorV1::Conflict)?.canonical_plan)
    }

    pub(crate) fn require_action_v1(&self, action: &OriginalPublicationActionV1,
        receiving: &CreateProvisioningOriginalsV1, controller: &Journal,
    ) -> Result<(), ResourceReservationErrorV1> {
        let current = &self.client.publication;
        let original = current.original.as_deref().ok_or(ResourceReservationErrorV1::Conflict)?;
        if current.first.is_some() || !current.entered || original.after_entered
            || !matches!(original.before, Some(Ok(())))
            || !matches!(original.before_time, Some(Ok(())))
            || !matches!(&original.binding, TurnBindingV1::Publication(contract)
                if Arc::ptr_eq(contract, action.contract_v1()))
            || !receiving.belongs_to_operation_v1(self.client.parent)
            || !receiving.has_same_profile_v1(&self.client.profile)
            || receiving.native_turn_v1() != self.client.native_turn {
            return Err(ResourceReservationErrorV1::Conflict);
        }
        receiving.require_current_v1(controller)
    }
}

/// Borrows the actual current signing/construction interval of the same Root owner.
#[doc(hidden)]
pub struct RootStorageApplyConstructionTurnV1<'flight> {
    client: &'flight RootStorageApplyClientOriginalV1,
}

impl RootStorageApplyConstructionTurnV1<'_> {
    /// Requires the actual native window before unsigned/key preparation.
    ///
    /// # Errors
    /// Refuses another owner, an incomplete before or a closed actual C23 turn.
    #[doc(hidden)]
    pub fn require_preparation_admission_v1(&self,
        admission: &RootStorageApplyAdmissionOriginalV1<'_>,
    ) -> Result<(), Closed> {
        let original = self.client.publication.original.as_deref().ok_or(self.client.closed)?;
        if !std::ptr::eq(self.client, admission.client)
            || admission.receiving.native_turn_v1() != self.client.native_turn
            || self.client.publication.first.is_some() || original.after_entered
            || !matches!(original.binding, TurnBindingV1::Construction)
            || !matches!(original.before, Some(Ok(())))
            || !matches!(original.before_time, Some(Ok(()))) {
            return Err(self.client.closed);
        }
        admission.require_current_v1().map_err(|_| self.client.closed)
    }

    /// Requires this same client's actual final signing admission.
    ///
    /// # Errors
    /// Refuses a changed native window, missing final clock or closed C23.
    #[doc(hidden)]
    pub fn require_admission_v1(&self, admission: &RootStorageApplyAdmissionOriginalV1<'_>)
        -> Result<(), Closed> {
        self.require_preparation_admission_v1(admission)?;
        let original = self.client.publication.original.as_deref().ok_or(self.client.closed)?;
        if !matches!(original.signing_time, Some(Ok(()))) {
            return Err(self.client.closed);
        }
        Ok(())
    }

    /// Returns the retained native final-signing clock when reached, else before.
    ///
    /// # Errors
    /// Refuses a failed or closed actual interval.
    pub fn actual_before_clock_v1(&self) -> Result<RawPairedClockSample, Closed> {
        let original = self.client.publication.original.as_deref().ok_or(self.client.closed)?;
        if self.client.publication.first.is_some() || original.after_entered {
            return Err(self.client.closed);
        }
        original.signing_sample.as_ref().or(original.before_sample.as_ref())
            .and_then(|result| result.as_ref().ok()).copied().ok_or(self.client.closed)
    }

    /// Returns the unchanged minimum actual original authority cutoff.
    #[must_use]
    pub fn cutoff_v1(&self) -> u64 { self.client.cutoff }
}

fn retained_authority_expiry_v1(
    admission: &Option<Result<StorageApplyAdmissionDataV1, ApplyRootDataErrorV1>>,
) -> Result<i64, ApplyRootDataErrorV1> {
    let admission = positive(admission)?;
    Ok(admission.policy_expires_seconds.min(admission.lease_expires_seconds))
}

fn binding_expiry_v1(binding: &TurnBindingV1, authority_expiry: i64)
    -> Result<i64, ApplyRootDataErrorV1> {
    match binding {
        TurnBindingV1::Construction => Ok(authority_expiry),
        TurnBindingV1::Publication(contract) => Ok(authority_expiry.min(
            contract.storage_apply_plan_expires_seconds_v1()
                .map_err(|_| ApplyRootDataErrorV1::Malformed)?)),
    }
}

fn require_phase_sample(origin: RawPairedClockSample, cutoff: u64, expires: i64,
    sample: RawPairedClockSample,
) -> Result<(), ApplyRootDataErrorV1> {
    origin.validate_later_sample(sample).map_err(|_| ApplyRootDataErrorV1::Malformed)?;
    if sample.boottime_nanoseconds() >= cutoff || sample.wall_seconds() >= expires {
        return Err(ApplyRootDataErrorV1::Malformed);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use aos_sandbox_model::RawClockProvenance;

    fn sample(wall: i64, boot_seconds: u64) -> RawPairedClockSample {
        RawPairedClockSample::new_untrusted(
            RawClockProvenance::new_untrusted([1; 16]).unwrap(),
            [2; 16], wall, boot_seconds * 1_000_000_000,
        ).unwrap()
    }

    #[test]
    fn live_phase_refuses_boundary_expiry_and_realtime_reversal() {
        let original = sample(100, 10);
        let cutoff = 30_000_000_000;

        assert!(require_phase_sample(original, cutoff, i64::MAX, sample(119, 29)).is_ok());
        assert!(require_phase_sample(original, cutoff, i64::MAX, sample(120, 30)).is_err());
        assert!(require_phase_sample(original, cutoff, i64::MAX, sample(99, 11)).is_err());
    }

    #[test]
    fn live_phase_never_adopts_another_kernel_boot_or_provenance() {
        let original = sample(100, 10);
        let foreign_boot = RawPairedClockSample::new_untrusted(
            original.provenance(), [3; 16], 101, 11_000_000_000,
        ).unwrap();
        let foreign_origin = RawPairedClockSample::new_untrusted(
            RawClockProvenance::new_untrusted([4; 16]).unwrap(),
            original.host_boot_id(), 101, 11_000_000_000,
        ).unwrap();

        assert!(require_phase_sample(original, 30_000_000_000, i64::MAX, foreign_boot).is_err());
        assert!(require_phase_sample(original, 30_000_000_000, i64::MAX, foreign_origin).is_err());
    }
    #[test]
    fn paired_clock_tolerance_does_not_extend_wall_authority() {
        let original = sample(100, 10);
        let expired = sample(120, 28);

        assert!(original.validate_later_sample(expired).is_ok());
        assert!(require_phase_sample(original, 29_000_000_000, 120, expired).is_err());
        assert!(require_phase_sample(original, 29_000_000_000, 121, expired).is_ok());
    }

    #[test]
    fn retained_lease_and_policy_each_narrow_the_selected_wall_expiry() {
        let mut admission = StorageApplyAdmissionDataV1 {
            controller_nonce: [1; 16], root_nonce: [2; 16], query_digest: [3; 32],
            original_boot: [4; 16], original_boottime_ns: 10_000_000_000,
            original_cutoff_ns: 30_000_000_000, observed_wall_seconds: 101,
            observed_boottime_ns: 11_000_000_000, cutoff_ns: 29_000_000_000,
            policy_expires_seconds: 120, lease_expires_seconds: 130,
            preparation_expires_boottime_ns: 30_000_000_000,
        };

        assert_eq!(retained_authority_expiry_v1(&Some(Ok(admission))).unwrap(), 120);
        admission.lease_expires_seconds = 110;
        assert_eq!(retained_authority_expiry_v1(&Some(Ok(admission))).unwrap(), 110);
    }

}
