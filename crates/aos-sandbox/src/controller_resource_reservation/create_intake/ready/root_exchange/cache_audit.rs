//! Funds and retains the fresh Cache purpose under the actual original Root turn.
//!
//! The private borrower splits the same Ready's originals beside its mutable
//! Cache. It has no amount, account, nonce or success constructor. Its actual
//! shape and every funding refusal remain in the Root turn through the five
//! fresh readers, contacted signer and independently owed Cache/J/Root posts.

use aos_sandbox_core::RawPairedClockSample;
use aos_sandbox_protocol::domain_ledger::create_storage_history::{
    HistoryErrorV1,
    cache_held::{CacheHeldReceiptDataV1, CACHE_HELD_RECEIPT_BYTES_V1,
        current_proof::CacheCurrentProofBodyDataV1},
    ready::ReadyBundleDataV1,
    root_open::RootHelloDataV1,
};

use crate::cache_residency::{CacheCurrentAuditOriginalsV1, CacheCurrentAuditShapeV1,
    CacheHeldClosedV1, CacheHeldErrorV1, CacheHeldIdentityDataV1,
    CacheHeldNativeSemanticShapeV1};
use super::super::cache_current_proof::{CacheCurrentProofRootStageV1,
    CacheCurrentSignerInputsV1, OriginalCreateStorageCacheCurrentProofV1,
    CacheCurrentProofPurposeV1};
use super::*;

#[derive(Default)]
pub(super) struct CacheCurrentAdmissionOriginalsV1 {
    entered: bool,
    shape: Option<Result<CacheCurrentAuditShapeV1, CacheHeldErrorV1>>,
    owner_geometry: Option<Result<ResourceVector, ResourceReservationErrorV1>>,
    base: Option<ResourceVector>,
    geometry: Option<Result<ResourceVector, ResourceReservationErrorV1>>,
    funding: Option<Result<(), ResourceReservationErrorV1>>,
    arm: Option<Result<(), CacheHeldClosedV1>>,
    semantic_geometry: Option<Result<ResourceVector, ResourceReservationErrorV1>>,
    semantic_funding: Option<Result<(), ResourceReservationErrorV1>>,
    semantic_delta: Option<Result<(ResourceVector, ResourceVector), ResourceReservationErrorV1>>,
    semantic_base: Option<ResourceVector>,
    before_entered: bool,
    before: CacheCurrentnessOriginalV1,
    before_result: Option<Result<(), ResourceReservationErrorV1>>,
    before_peer: Option<Result<(), CreateStorageRootExchangeClosedV1>>,
    after_entered: bool,
    after: CacheCurrentnessOriginalV1,
    after_result: Option<Result<(), ResourceReservationErrorV1>>,
    after_peer: Option<Result<(), CreateStorageRootExchangeClosedV1>>,
    after_clock: Option<Result<(), ResourceReservationErrorV1>>,
    clock: Option<RawPairedClockSample>,
    clock_failure: Option<ResourceReservationErrorV1>,
    signed_clock: Option<RawPairedClockSample>,
    named_failure: Option<ResourceReservationErrorV1>,
    complete: bool,
    property_reservation: Option<usize>,
}

impl CacheCurrentAdmissionOriginalsV1 {
    pub(super) fn use_semantic_funding_failed_v1(&self) -> bool {
        matches!(self.semantic_delta, Some(Ok(_)))
            && matches!(self.semantic_funding, Some(Err(_)))
    }

    pub(super) fn base_without_traffic_v1(&self) -> Option<ResourceVector> {
        self.semantic_base.or(self.base)
    }

    pub(super) fn root_before_is_owed_v1(&self) -> bool {
        self.before_entered && self.before_result.is_some() && self.before_peer.is_none()
            && matches!(self.funding, Some(Ok(()))) && matches!(self.arm, Some(Ok(())))
    }

    pub(super) fn root_after_is_owed_v1(&self) -> bool {
        self.after_entered && self.after_result.is_some() && self.after_peer.is_none()
            && self.before_entered && matches!(self.funding, Some(Ok(())))
            && matches!(self.arm, Some(Ok(())))
    }

    fn admission_failure(&self) -> Option<&(dyn Error + 'static)> {
        cause(&self.shape).or_else(|| cause(&self.owner_geometry))
            .or_else(|| cause(&self.geometry)).or_else(|| cause(&self.funding))
            .or_else(|| cause(&self.arm))
    }

    fn funding_failure(&self) -> Option<&(dyn Error + 'static)> {
        self.named_failure.as_ref().map(|error| error as _)
            .or_else(|| cause(&self.semantic_geometry))
            .or_else(|| cause(&self.semantic_delta))
            .or_else(|| cause(&self.semantic_funding))
    }

    fn semantic_failure(&self) -> Option<&(dyn Error + 'static)> {
        self.funding_failure()
            .or_else(|| self.clock_failure.as_ref().map(|error| error as _))
    }

    pub(super) fn failure<'cause>(&'cause self,
        owner: &'cause OriginalCreateStorageCacheCurrentProofV1,
        peer: &'cause CreateStorageRootPeerReceivingOriginalsV1,
    ) -> Option<&'cause (dyn Error + 'static)> {
        match owner.root_failure_stage_v1() {
            Some(CacheCurrentProofRootStageV1::Admission) => self.admission_failure(),
            Some(CacheCurrentProofRootStageV1::Before) => self.before.failure()
                .or_else(|| cause(&self.before_result)).or_else(|| peer.failure())
                .or_else(|| cause(&self.before_peer)),
            Some(CacheCurrentProofRootStageV1::After) => self.after.failure()
                .or_else(|| cause(&self.after_result)).or_else(|| peer.failure())
                .or_else(|| cause(&self.after_peer)).or_else(|| cause(&self.after_clock)),
            // Only actual funding refusal precedes its coarse native stop.
            // The independent post-clock happens after active replay and must
            // keep the audit owner's actual active/native/clock cause order.
            None if owner.audit_failure_is_selected_v1() =>
                self.funding_failure().or_else(|| owner.failure()),
            None => owner.failure(),
        }.or_else(|| owner.failure())
    }

    // Actual construction bytes and independently owed native backing.
    fn fixed_demand_v1() -> Result<ResourceVector, ResourceReservationErrorV1> {
        let bytes = std::mem::size_of::<Self>().checked_mul(2)
            .and_then(|bytes| bytes.checked_add(std::mem::size_of::<CacheCurrentAuditReceivingLoanV1<'_>>().checked_mul(2)?))
            .and_then(|bytes| bytes.checked_add(2 * std::mem::size_of::<CacheCurrentSignerInputsV1<'_>>()))
            .and_then(|bytes| bytes.checked_add(2 * std::mem::size_of::<RawPairedClockSample>()))
            .and_then(|bytes| bytes.checked_add(std::mem::size_of::<(u32, u32, u32)>()))
            .and_then(|bytes| bytes.checked_add(2 * std::mem::size_of::<cache_receiving::OriginalCacheAssociationV1>()))
            .and_then(|bytes| bytes.checked_add(2 * std::mem::size_of::<CreateStorageWriterPositionV1>()))
            .and_then(|bytes| bytes.checked_add(12 * std::mem::size_of::<ResourceVector>()))
            .ok_or(ResourceReservationErrorV1::Conflict)?;
        let names = crate::journal::create_storage_name_peak_demand_v1()?;
        let fixed = ResourceVector::ZERO
            .with(D::MemoryBytes, u64::try_from(bytes).map_err(|_| ResourceReservationErrorV1::Conflict)?)
            // These two independent outer J destinations coexist with a
            // failed/owed Root pair. No credit is taken from earlier names.
            .with(D::OpenFiles, names.get(D::OpenFiles));
        Ok(fixed.checked_add(CacheCurrentnessOriginalV1::receiving_backing_demand_v1(2)?
            .with(D::MetadataEntries, 0))?)
    }
}

/// Borrows only the actual already-admitted Cache purpose's original payer.
///
/// Cache itself remains a disjoint mutable borrow in the shared native audit.
/// This type has no public constructor or raw budget/identity input.
pub(crate) struct CacheCurrentAuditReceivingLoanV1<'borrow> {
    parent: &'borrow ProjectPreparationReservationAttemptV1,
    intake: &'borrow mut Q04OriginalIntakeAttemptV1,
    controller: &'borrow Journal,
    source: &'borrow ProtectedSourceDomainJournalOwnerV1,
    profile: &'borrow ProductionControllerNormalRootProfileV1,
    state: &'borrow mut RootTurnStateV1,
    cache_base: ResourceVector,
    use_receiving: Option<&'borrow mut super::super::UseReceivingOriginalsV1>,
}

impl CacheCurrentAuditReceivingLoanV1<'_> {
    pub(crate) fn cache_native_base_v1(&self) -> ResourceVector { self.cache_base }

    pub(crate) fn cache_current_semantic_peak_v1(&self)
        -> Result<ResourceVector, ResourceReservationErrorV1>
    {
        self.state.cache_current.shape.as_ref()
            .and_then(|result| result.as_ref().ok())
            .map(CacheCurrentAuditShapeV1::semantic_peak_v1)
            .ok_or(ResourceReservationErrorV1::Conflict)
    }


    pub(crate) fn require_cache_named_preparation(&mut self, identity: CacheHeldIdentityDataV1)
        -> Result<(), ResourceReservationErrorV1>
    {
        let result = (|| {
            if let Some(receiving) = self.use_receiving.as_deref() {
                receiving.require_reserved_v1()?;
            }
            self.intake.require_retained_capture()?;
            self.parent.require_create_storage_association(self.controller, self.source, self.profile)?;
            self.state.expected_cache.as_ref().ok_or(ResourceReservationErrorV1::Conflict)?
                .require_identity_v1(identity)?;
            let current = &self.state.cache_current;
            if !current.entered || !matches!(current.funding, Some(Ok(())))
                || current.semantic_failure().is_some()
                || !self.state.invitation_complete {
                return Err(ResourceReservationErrorV1::Conflict);
            }
            Ok(())
        })();
        if let Err(error) = result {
            self.state.cache_current.named_failure.get_or_insert(error);
            return Err(ResourceReservationErrorV1::Conflict);
        }
        Ok(())
    }

    pub(crate) fn admit_cache_semantic_shape(&mut self, shape: &CacheHeldNativeSemanticShapeV1)
        -> Result<(), ResourceReservationErrorV1>
    {
        self.require_cache_named_preparation(shape.original_identity_v1())?;
        if self.use_receiving.is_some() {
            return self.admit_use_cache_semantic_shape_v1(shape);
        }
        let result = (|| {
            let base = self.state.geometry.as_ref().and_then(|result| result.as_ref().ok())
                .copied().ok_or(ResourceReservationErrorV1::Conflict)?;
            let non_cache = self.state.cache_current.owner_geometry.as_ref()
                .and_then(|result| result.as_ref().ok()).copied()
                .ok_or(ResourceReservationErrorV1::Conflict)?;
            Ok(base.checked_add(non_cache)?
                .checked_add(shape.dominant_receiving_demand_v1().map_err(|_| ResourceReservationErrorV1::Conflict)?)?)
        })();
        self.state.cache_current.semantic_geometry = Some(result);
        if let Some(Ok(base)) = self.state.cache_current.semantic_geometry.as_ref() {
            self.state.cache_current.semantic_base = Some(*base);
        }
        let complete = self.state.cache_current.semantic_geometry.as_ref()
            .and_then(|result| result.as_ref().ok()).copied()
            .ok_or(ResourceReservationErrorV1::Conflict)
            .and_then(|base| with_property_traffic(base, self.state.property_paid));
        self.state.cache_current.semantic_funding = Some(match complete {
            Ok(complete) => self.intake.reserve_create_capture_complete(
                CreateContinuationCaptureOwnerV1::RootExchange, complete),
            Err(error) => Err(error),
        });
        if matches!(self.state.cache_current.semantic_funding, Some(Ok(()))) { Ok(()) }
        else { Err(ResourceReservationErrorV1::Conflict) }
    }

    pub(crate) fn require_current_clock_v1(&mut self, sample: RawPairedClockSample)
        -> Result<(), ResourceReservationErrorV1>
    {
        if self.state.cache_current.clock_failure.is_some() {
            return Err(ResourceReservationErrorV1::Conflict);
        }
        let result = (|| {
            self.state.expected_cache.as_ref().ok_or(ResourceReservationErrorV1::Conflict)?
                .require_clock_v1(sample)?;
            let hello = self.state.transport.hello_body().map_err(|_| ResourceReservationErrorV1::Conflict)?;
            if sample.host_boot_id() != hello.boot || sample.boottime_nanoseconds() < hello.started
                || sample.boottime_nanoseconds() >= hello.cutoff {
                return Err(ResourceReservationErrorV1::Conflict);
            }
            let previous = self.state.cache_current.clock.or(self.state.last_native_clock)
                .ok_or(ResourceReservationErrorV1::Conflict)?;
            previous.validate_later_sample(sample).map_err(|_| ResourceReservationErrorV1::Conflict)?;
            Ok(())
        })();
        match result {
            Ok(()) => { self.state.cache_current.clock = Some(sample); Ok(()) }
            Err(error) => {
                self.state.cache_current.clock_failure = Some(error);
                Err(ResourceReservationErrorV1::Conflict)
            }
        }
    }
}

fn with_property_traffic(base: ResourceVector, observations: usize)
    -> Result<ResourceVector, ResourceReservationErrorV1>
{
    let (wire, logs) = CreateStorageRootPeerReceivingOriginalsV1::query_traffic_v1(observations)
        .ok_or(ResourceReservationErrorV1::Conflict)?;
    Ok(base.checked_add(ResourceVector::ZERO.with(D::NetworkBytes, wire).with(D::LogBytes, logs))?)
}

impl OriginalCreateStorageRootExchangeV1<'_, '_, '_> {
    pub(in crate::controller_resource_reservation::create_intake::ready) fn admit_cache_current_once_v1(&mut self,
        owner: &mut OriginalCreateStorageCacheCurrentProofV1,
    ) -> Result<(), ResourceReservationErrorV1> {
        if owner.purpose_v1()? != self.cache_current_purpose_v1()? {
            return Err(ResourceReservationErrorV1::Conflict);
        }
        if self.use_receiving.is_some() {
            return self.admit_use_cache_current_once_v1(owner);
        }
        if self.state.cache_current.entered || !owner.has_entered_v1()
            || !self.state.ready_complete || !self.state.invitation_complete
            || self.state.first.is_some() || self.require_fixed().is_err() {
            return Err(ResourceReservationErrorV1::Conflict);
        }
        self.state.cache_current.entered = true;
        self.state.cache_current.shape = Some(self.cache.current_proof_audit_shape_v1());
        self.state.cache_current.owner_geometry = Some(
            current_outer_fixed_receiving_demand_v1());
        self.state.cache_current.geometry = Some((|| {
            let shape = self.state.cache_current.shape.as_ref().and_then(|result| result.as_ref().ok())
                .ok_or(ResourceReservationErrorV1::Conflict)?;
            self.state.expected_cache.as_ref().ok_or(ResourceReservationErrorV1::Conflict)?
                .require_identity_v1(shape.original_identity_v1())?;
            let root = *self.state.geometry.as_ref().and_then(|result| result.as_ref().ok())
                .ok_or(ResourceReservationErrorV1::Conflict)?;
            let owner = *self.state.cache_current.owner_geometry.as_ref()
                .and_then(|result| result.as_ref().ok()).ok_or(ResourceReservationErrorV1::Conflict)?;
            let base = root.checked_add(owner)?
                .checked_add(shape.dominant_receiving_demand_v1())?;
            self.state.cache_current.base = Some(base);
            let required = self.state.property_used.checked_add(2)
                .ok_or(ResourceReservationErrorV1::Conflict)?;
            self.state.cache_current.property_reservation = Some(required);
            with_property_traffic(base, required)
        })());
        self.state.cache_current.funding = Some(match &self.state.cache_current.geometry {
            Some(Ok(demand)) => self.intake.reserve_create_capture_complete(
                CreateContinuationCaptureOwnerV1::RootExchange, *demand),
            _ => Err(ResourceReservationErrorV1::Conflict),
        });
        if !matches!(self.state.cache_current.funding, Some(Ok(()))) {
            return Err(ResourceReservationErrorV1::Conflict);
        }
        self.state.property_paid = self.state.cache_current.property_reservation
            .ok_or(ResourceReservationErrorV1::Conflict)?;
        let cache_base = self.state.cache_current.shape.as_ref().and_then(|result| result.as_ref().ok())
            .map(CacheCurrentAuditShapeV1::dominant_receiving_demand_v1)
            .ok_or(ResourceReservationErrorV1::Conflict)?;
        let mut receiving = CacheCurrentAuditReceivingLoanV1 {
            parent: self.parent, intake: self.intake, controller: self.controller,
            source: self.source, profile: self.profile, state: self.state, cache_base,
            use_receiving: self.use_receiving.as_deref_mut(),
        };
        let arm = self.cache.arm_current_proof_audit_once(owner.audit_originals_v1(), &mut receiving);
        receiving.state.cache_current.arm = Some(arm);
        if matches!(receiving.state.cache_current.arm, Some(Ok(()))) { Ok(()) }
        else { Err(ResourceReservationErrorV1::Conflict) }
    }

    pub(in crate::controller_resource_reservation::create_intake::ready) fn audit_cache_current_once_v1(&mut self, audit: &mut CacheCurrentAuditOriginalsV1)
        -> Result<(), CacheHeldClosedV1>
    {
        let cache_base = self.state.cache_current.shape.as_ref().and_then(|result| result.as_ref().ok())
            .map(CacheCurrentAuditShapeV1::dominant_receiving_demand_v1).ok_or(CacheHeldClosedV1)?;
        let mut receiving = CacheCurrentAuditReceivingLoanV1 {
            parent: self.parent, intake: self.intake, controller: self.controller,
            source: self.source, profile: self.profile, state: self.state, cache_base,
            use_receiving: self.use_receiving.as_deref_mut(),
        };
        self.cache.audit_current_proof_once(audit, &mut receiving)
    }

    pub(in crate::controller_resource_reservation::create_intake::ready) fn finish_cache_current_audit_once_v1(&mut self, audit: &mut CacheCurrentAuditOriginalsV1)
        -> Result<(), CacheHeldClosedV1>
    {
        // The real same Cache post is already armed. Sticky J or signer debt
        // cannot suppress this independently owed native observation.
        self.cache.finish_current_proof_audit_once(audit)
    }

    pub(in crate::controller_resource_reservation::create_intake::ready) fn observe_cache_current_before_v1(&mut self,
        peer: &mut CreateStorageRootPeerReceivingOriginalsV1,
        owner: &OriginalCreateStorageCacheCurrentProofV1,
    ) -> Result<(), CreateStorageRootExchangeClosedV1> {
        if !owner.admission_succeeded_v1() || !owner.root_before_entered_v1()
            || self.state.cache_current.before_entered || !matches!(self.state.cache_current.arm, Some(Ok(()))) {
            return Err(CreateStorageRootExchangeClosedV1);
        }
        self.state.cache_current.before_entered = true;
        // Both the entered primary and its independently owed Root post are
        // paid before the first new native query. A later J refusal cannot
        // erase the already admitted second query.
        self.prepay_root_peer_observations_v1(2)?;
        let expected = self.state.expected_cache.ok_or(CreateStorageRootExchangeClosedV1)?;
        let position = self.state.expected_controller.ok_or(CreateStorageRootExchangeClosedV1)?;
        self.state.cache_current.before_result = Some(self.state.cache_current.before.observe_operation_once(
            CacheControlOriginalsV1 { parent: self.parent, intake: self.intake,
                controller: self.controller, source: self.source, profile: self.profile },
            self.cache, expected, Ok(position)));
        if !matches!(self.state.cache_current.before_result, Some(Ok(()))) {
            return Err(CreateStorageRootExchangeClosedV1);
        }
        self.state.owed_post = Some(RootPostFrontierV1::CacheCurrentBefore);
        let before_peer = peer.recheck_once(self);
        self.state.cache_current.before_peer = Some(before_peer);
        if matches!(self.state.cache_current.before_peer, Some(Ok(()))) { Ok(()) }
        else { Err(CreateStorageRootExchangeClosedV1) }
    }

    pub(in crate::controller_resource_reservation::create_intake::ready) fn observe_cache_current_after_v1(&mut self,
        peer: &mut CreateStorageRootPeerReceivingOriginalsV1,
        owner: &OriginalCreateStorageCacheCurrentProofV1,
    ) -> Result<(), CreateStorageRootExchangeClosedV1> {
        if !owner.admission_succeeded_v1() || !owner.root_after_entered_v1()
            || !self.state.cache_current.before_entered || self.state.cache_current.after_entered {
            return Err(CreateStorageRootExchangeClosedV1);
        }
        self.state.cache_current.after_entered = true;
        let expected = self.state.expected_cache.ok_or(CreateStorageRootExchangeClosedV1)?;
        let position = self.state.expected_controller.ok_or(CreateStorageRootExchangeClosedV1)?;
        self.state.cache_current.after_result = Some(self.state.cache_current.after.observe_operation_once(
            CacheControlOriginalsV1 { parent: self.parent, intake: self.intake,
                controller: self.controller, source: self.source, profile: self.profile },
            self.cache, expected, Ok(position)));
        self.state.owed_post = Some(RootPostFrontierV1::CacheCurrentAfter);
        let after_peer = peer.recheck_once(self);
        self.state.cache_current.after_peer = Some(after_peer);
        self.state.cache_current.after_clock = Some((|| {
            let clock = self.state.cache_current.after.completed_clock_data_v1()?;
            expected.require_clock_v1(clock)?;
            if clock.boottime_nanoseconds() >= self.state.transport.hello_body()
                .map_err(|_| ResourceReservationErrorV1::Conflict)?.cutoff {
                return Err(ResourceReservationErrorV1::Conflict);
            }
            if let Some(signed) = self.state.cache_current.signed_clock {
                // The signed current-proof clock intentionally has another
                // purpose provenance. Compare its actual same-boot native
                // position; never retag it to satisfy a local-clock policy.
                require_native_clock_order(signed, clock)
                    .map_err(|_| ResourceReservationErrorV1::Conflict)?;
            }
            Ok(())
        })());
        self.state.cache_current.complete = matches!(self.state.cache_current.before_result, Some(Ok(())))
            && matches!(self.state.cache_current.before_peer, Some(Ok(())))
            && matches!(self.state.cache_current.after_result, Some(Ok(())))
            && matches!(self.state.cache_current.after_peer, Some(Ok(())))
            && matches!(self.state.cache_current.after_clock, Some(Ok(())))
            && self.state.cache_current.semantic_failure().is_none();
        if self.state.cache_current.complete { Ok(()) }
        else { Err(CreateStorageRootExchangeClosedV1) }
    }

    pub(in crate::controller_resource_reservation::create_intake::ready) fn cache_current_signer_inputs_v1<'actual>(&'actual mut self, bytes: &'actual [u8])
        -> Result<CacheCurrentSignerInputsV1<'actual>, ResourceReservationErrorV1>
    {
        if !self.state.invitation_complete || !matches!(self.state.cache_current.before_peer, Some(Ok(())))
            || self.state.cache_current.semantic_failure().is_some() {
            return Err(ResourceReservationErrorV1::Conflict);
        }
        let bundle = ReadyBundleDataV1::decode(bytes).map_err(|_| ResourceReservationErrorV1::Conflict)?;
        let held: &[u8; CACHE_HELD_RECEIPT_BYTES_V1] = bundle.cache_held.try_into()
            .map_err(|_| ResourceReservationErrorV1::Conflict)?;
        let hello = self.state.transport.hello_frame();
        self.state.invitation.as_ref().and_then(|result| result.as_ref().ok())
            .ok_or(ResourceReservationErrorV1::Conflict)?.require_challenge_bytes(hello, held)
            .map_err(|_| ResourceReservationErrorV1::Conflict)?;
        let receipt = CacheHeldReceiptDataV1::decode(held, bundle.lane)
            .map_err(|_| ResourceReservationErrorV1::Conflict)?;
        let live = self.cache.borrow_pre_root_cut_v1().map_err(|_| ResourceReservationErrorV1::Conflict)?;
        if live.held_receipt_data_v1().map_err(|_| ResourceReservationErrorV1::Conflict)? != receipt {
            return Err(ResourceReservationErrorV1::Conflict);
        }
        let (signer_uid, signer_gid, socket_gid) = self.profile.cache_current_signer_identities_v1();
        Ok(CacheCurrentSignerInputsV1 { hello, held, signer_uid, signer_gid, socket_gid,
            cutoff: self.state.transport.hello_body().map_err(|_| ResourceReservationErrorV1::Conflict)?
                .cutoff.min(receipt.body(bundle.lane).map_err(|_| ResourceReservationErrorV1::Conflict)?.association.cutoff) })
    }

    pub(in crate::controller_resource_reservation::create_intake::ready) fn compare_cache_current_body_v1(&mut self, body: &CacheCurrentProofBodyDataV1, bytes: &[u8])
        -> Result<(), HistoryErrorV1>
    {
        let bundle = ReadyBundleDataV1::decode(bytes)?;
        let held = CacheHeldReceiptDataV1::decode(bundle.cache_held, bundle.lane)?;
        let root = self.state.transport.hello_body()?;
        let hello = RootHelloDataV1::decode(self.state.transport.hello_frame(), root.open)?;
        body.compare_held_data(held)?;
        body.compare_root_hello_data(hello)?;
        let previous = self.state.cache_current.clock.ok_or(HistoryErrorV1::Correlation)?;
        // Body decoding fixes the current-proof clock provenance. These
        // independently observed local and signed samples have distinct
        // purpose tags; freshness is the actual same-boot BOOTTIME bracket.
        require_native_clock_order(previous, body.sample)?;
        self.state.cache_current.signed_clock = Some(body.sample);
        Ok(())
    }
}

impl OriginalCreateStorageReadyV1<'_, '_> {
    /// Produces the fresh Cache proof from this same Ready's authenticated Root invitation.
    ///
    /// The retained native signer flight and body checks do not verify a Cache
    /// public key or grant Use. Root independently verifies its separately
    /// pinned direct signer response and exact forwarded bytes before issuing U.
    ///
    /// # Errors
    /// Retains fixed or reached funding, new audit, actual signer transport,
    /// correlation and every independently owed Cache/J/Root post failure.
    #[doc(hidden)]
    pub fn produce_original_cache_current_once(&mut self, bytes: &[u8])
        -> Result<(), CreateStorageRootExchangeClosedV1>
    {
        if self.failure().is_some() || self.original.owner.root_exchange.cache_current_proof.has_entered_v1() {
            return Err(CreateStorageRootExchangeClosedV1);
        }
        self.original.owner.bundle.require_completed_bytes_v1(bytes)
            .map_err(|_| CreateStorageRootExchangeClosedV1)?;
        let owner = &mut *self.original.owner;
        let root = &mut owner.root_exchange;
        let mut loan = OriginalCreateStorageRootExchangeV1 {
            use_receiving: None,
            parent: &owner.parent, intake: &mut owner.intake, controller: self.original.controller,
            source: self.original.source, profile: self.original.profile, cache: &mut self.cache,
            state: &mut root.turn,
        };
        root.cache_current_proof.produce_once(&mut loan, &mut root.peer, bytes)
    }
}

// This compares already-owned samples with purpose-specific provenance. Each
// producer's codec fixes its own tag; freshness must not manufacture a shared
// tag or treat this nonauthorizing DATA comparison as a native observation.
fn require_native_clock_order(before: RawPairedClockSample, after: RawPairedClockSample)
    -> Result<(), HistoryErrorV1>
{
    if before.host_boot_id() != after.host_boot_id()
        || before.boottime_nanoseconds() > after.boottime_nanoseconds() {
        return Err(HistoryErrorV1::Correlation);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use aos_sandbox_core::RawClockProvenance;

    fn sample(tag: u8, boot: u8, boottime: u64) -> RawPairedClockSample {
        RawPairedClockSample::new_untrusted(
            RawClockProvenance::new_untrusted([tag; 16]).unwrap(), [boot; 16], 7, boottime,
        ).unwrap()
    }

    #[test]
    fn signed_current_purpose_uses_the_actual_native_bracket_without_retagging() {
        let native_before = sample(1, 3, 10);
        let signed = sample(2, 3, 11);
        let native_after = sample(1, 3, 12);

        assert!(native_before.validate_later_sample(signed).is_err());
        assert!(require_native_clock_order(native_before, signed).is_ok());
        assert!(require_native_clock_order(signed, native_after).is_ok());
        assert_eq!(signed.provenance().as_bytes(), [2; 16]);
    }

    #[test]
    fn a_changed_boot_or_sample_outside_the_actual_native_bracket_refuses() {
        let native_before = sample(1, 3, 10);
        let native_after = sample(1, 3, 12);

        assert!(require_native_clock_order(native_before, sample(2, 4, 11)).is_err());
        assert!(require_native_clock_order(native_before, sample(2, 3, 9)).is_err());
        assert!(require_native_clock_order(sample(2, 3, 13), native_after).is_err());
    }
}


fn current_outer_fixed_receiving_demand_v1()
    -> Result<ResourceVector, ResourceReservationErrorV1>
{
    let (wire, logs) = ProductionControllerNormalRootProfileV1::
        create_storage_producer_traffic_bound_v1(2)
        .ok_or(ResourceReservationErrorV1::Conflict)?;
    Ok(OriginalCreateStorageCacheCurrentProofV1::fixed_non_cache_receiving_demand_v1()?
        .checked_add(CacheCurrentAdmissionOriginalsV1::fixed_demand_v1()?)?
        .checked_add(ResourceVector::ZERO.with(D::NetworkBytes, wire).with(D::LogBytes, logs))?)
}

/// Prices the compiled Controller-side fixed Cache current-proof flight.
///
/// Includes the five-audit fixed backing, contacted signer transport and two
/// outer J destinations. Dynamic five-prefix replay demand is separate. The
/// caller adds its cumulative Root query traffic once through its Root recipe;
/// signer service F and earlier Root/Session originals are outside this term.
/// Rust control destinations create no resident namespace metadata entries.
///
/// # Errors
/// Rejects checked byte, descriptor or traffic arithmetic overflow.
#[doc(hidden)]
pub fn create_storage_cache_current_fixed_receiving_demand_v1()
    -> Result<ResourceVector, ResourceReservationErrorV1>
{
    Ok(current_outer_fixed_receiving_demand_v1()?
        .checked_add(crate::cache_residency::current_cache_fixed_receiving_demand_v1()?)?)
}

impl OriginalCreateStorageReadyV1<'_, '_> {
    /// Returns extent DATA from this completed first proof's same held Cache.
    ///
    /// # Errors
    /// Refuses an incomplete or failed first proof, failed Ready, or changed
    /// original pre-Root cut. It performs no reopen and grants no new purpose.
    #[doc(hidden)]
    pub fn completed_cache_current_extents_v1(&self)
        -> Result<crate::cache_residency::CreateStorageCacheCurrentExtentsDataV1, CreateStorageReadyClosedV1>
    {
        if self.failure().is_some() {
            return Err(CreateStorageReadyClosedV1);
        }
        self.original.owner.root_exchange.cache_current_proof.completed_packet_v1()
            .map_err(|_| CreateStorageReadyClosedV1)?;
        self.cache.current_proof_extents_v1().map_err(|_| CreateStorageReadyClosedV1)
    }
}


#[cfg(test)]
mod shared_receiving_tests {
    use super::*;

    #[test]
    fn fixed_current_receiving_prices_native_files_without_rust_field_metadata() {
        let demand = create_storage_cache_current_fixed_receiving_demand_v1().unwrap();

        assert_eq!(demand.get(D::MetadataEntries), 0);
        assert!(demand.get(D::MemoryBytes) > 0);
        assert!(demand.get(D::OpenFiles) > 0);
        assert!(demand.get(D::NetworkBytes) > 0);
    }
}


impl OriginalCreateStorageRootExchangeV1<'_, '_, '_> {
    pub(in crate::controller_resource_reservation::create_intake::ready)
    fn cache_current_purpose_v1(&self)
        -> Result<CacheCurrentProofPurposeV1, ResourceReservationErrorV1>
    {
        match self.use_receiving.as_deref() {
            Some(_) if self.state.use_tail.second_invitation_complete_v1()
                && self.state.initial_cache_current.is_some() => {
                Ok(CacheCurrentProofPurposeV1::ReservedU)
            }
            None if self.state.initial_cache_current.is_none() => {
                Ok(CacheCurrentProofPurposeV1::InitialJ)
            }
            _ => Err(ResourceReservationErrorV1::Conflict),
        }
    }

    fn admit_use_cache_current_once_v1(&mut self,
        owner: &mut OriginalCreateStorageCacheCurrentProofV1,
    ) -> Result<(), ResourceReservationErrorV1> {
        if self.cache_current_purpose_v1()? != CacheCurrentProofPurposeV1::ReservedU
            || self.state.cache_current.entered || !owner.has_entered_v1()
            || self.require_fixed().is_err() {
            return Err(ResourceReservationErrorV1::Conflict);
        }
        self.use_receiving.as_deref().ok_or(ResourceReservationErrorV1::Conflict)?
            .require_reserved_v1()?;
        self.state.cache_current.entered = true;
        self.state.cache_current.shape = Some(self.cache.current_proof_audit_shape_v1());
        self.state.cache_current.owner_geometry = Some(current_outer_fixed_receiving_demand_v1());
        self.state.cache_current.geometry = Some((|| {
            let shape = self.state.cache_current.shape.as_ref()
                .and_then(|result| result.as_ref().ok())
                .ok_or(ResourceReservationErrorV1::Conflict)?;
            self.state.expected_cache.as_ref().ok_or(ResourceReservationErrorV1::Conflict)?
                .require_identity_v1(shape.original_identity_v1())?;
            let owner = self.state.cache_current.owner_geometry.as_ref()
                .and_then(|result| result.as_ref().ok()).copied()
                .ok_or(ResourceReservationErrorV1::Conflict)?;
            // Earlier Root originals stay under their existing reservation.
            // This U pays this distinct flight's complete fixed/native/model peak.
            owner.checked_add(shape.dominant_receiving_demand_v1())
                .map_err(ResourceReservationErrorV1::Accounting)
        })());
        self.state.cache_current.funding = Some(match self.state.cache_current.geometry.as_ref() {
            Some(Ok(demand)) => self.use_receiving.as_deref_mut()
                .ok_or(ResourceReservationErrorV1::Conflict)?.reserve_once(*demand),
            _ => Err(ResourceReservationErrorV1::Conflict),
        });
        if !matches!(self.state.cache_current.funding, Some(Ok(()))) {
            if matches!(self.state.cache_current.geometry, Some(Ok(_))) {
                self.state.use_tail.mark_use_funding_failure_v1();
            }
            return Err(ResourceReservationErrorV1::Conflict);
        }
        self.state.cache_current.base = self.state.cache_current.geometry.as_ref()
            .and_then(|result| result.as_ref().ok()).copied();
        self.prepay_root_peer_observations_v1(2)
            .map_err(|_| ResourceReservationErrorV1::Conflict)?;
        let cache_base = self.state.cache_current.shape.as_ref()
            .and_then(|result| result.as_ref().ok())
            .map(CacheCurrentAuditShapeV1::dominant_receiving_demand_v1)
            .ok_or(ResourceReservationErrorV1::Conflict)?;
        let mut receiving = CacheCurrentAuditReceivingLoanV1 {
            parent: self.parent, intake: self.intake, controller: self.controller,
            source: self.source, profile: self.profile, state: self.state, cache_base,
            use_receiving: self.use_receiving.as_deref_mut(),
        };
        let arm = self.cache.arm_current_proof_audit_once(owner.audit_originals_v1(), &mut receiving);
        receiving.state.cache_current.arm = Some(arm);
        if matches!(receiving.state.cache_current.arm, Some(Ok(()))) { Ok(()) }
        else { Err(ResourceReservationErrorV1::Conflict) }
    }
}

impl CacheCurrentAuditReceivingLoanV1<'_> {
    fn admit_use_cache_semantic_shape_v1(&mut self, shape: &CacheHeldNativeSemanticShapeV1)
        -> Result<(), ResourceReservationErrorV1>
    {
        self.state.cache_current.semantic_geometry = Some((|| {
            let owner = self.state.cache_current.owner_geometry.as_ref()
                .and_then(|result| result.as_ref().ok()).copied()
                .ok_or(ResourceReservationErrorV1::Conflict)?;
            owner.checked_add(shape.dominant_receiving_demand_v1()
                .map_err(|_| ResourceReservationErrorV1::Conflict)?)
                .map_err(ResourceReservationErrorV1::Accounting)
        })());
        self.state.cache_current.semantic_delta = Some((|| {
            let paid = self.state.cache_current.semantic_base.or(self.state.cache_current.base)
                .ok_or(ResourceReservationErrorV1::Conflict)?;
            let reached = self.state.cache_current.semantic_geometry.as_ref()
                .and_then(|result| result.as_ref().ok()).copied()
                .ok_or(ResourceReservationErrorV1::Conflict)?;
            aos_sandbox_core::component_receiving::complete_bound_delta_v1(paid, reached)
                .map_err(ResourceReservationErrorV1::Accounting)
        })());
        self.state.cache_current.semantic_funding = Some(match self.state.cache_current.semantic_delta.as_ref() {
            Some(Ok((_, additional))) => self.use_receiving.as_deref_mut()
                .ok_or(ResourceReservationErrorV1::Conflict)?.reserve_once(*additional),
            _ => Err(ResourceReservationErrorV1::Conflict),
        });
        if matches!(self.state.cache_current.semantic_funding, Some(Ok(()))) {
            self.state.cache_current.semantic_base = self.state.cache_current.semantic_delta.as_ref()
                .and_then(|result| result.as_ref().ok()).map(|(complete, _)| *complete);
            Ok(())
        } else {
            Err(ResourceReservationErrorV1::Conflict)
        }
    }
}

impl OriginalCreateStorageReadyV1<'_, '_> {
    /// Produces the distinct second Cache proof after the actual U reservation.
    ///
    /// The first native flight and admission remain resident. This purpose
    /// borrows the actual returned U beside the same Cache and authenticated
    /// second Root invitation. It cannot reuse J or a terminal audit.
    ///
    /// # Errors
    /// Retains reentry, wrong original, actual U funding, audit, signer,
    /// correlation, cutoff and independently owed Cache/Root post failures.
    #[doc(hidden)]
    pub fn produce_use_cache_current_once(&mut self, bytes: &[u8])
        -> Result<(), CreateStorageRootExchangeClosedV1>
    {
        if self.failure().is_some() { return Err(CreateStorageRootExchangeClosedV1); }
        self.original.owner.bundle.require_completed_bytes_v1(bytes)
            .map_err(|_| CreateStorageRootExchangeClosedV1)?;
        let owner = &mut *self.original.owner;
        let root = &mut owner.root_exchange;
        if !root.turn.use_tail.second_invitation_complete_v1() || root.turn.initial_cache_current.is_some()
            || root.use_cache_current_proof.has_entered_v1() || !root.turn.cache_current.complete {
            return Err(CreateStorageRootExchangeClosedV1);
        }
        root.cache_current_proof.completed_packet_v1()?;
        let mut original = owner.storage_use.borrow_root_receiving_once_v1()
            .map_err(|_| CreateStorageRootExchangeClosedV1)?;
        let (reserved, receiving) = original.split_original_and_receiving_v1()
            .map_err(|_| CreateStorageRootExchangeClosedV1)?;
        let position = reserved.position_v1().map_err(|_| CreateStorageRootExchangeClosedV1)?;
        let clock = reserved.completed_clock_v1().map_err(|_| CreateStorageRootExchangeClosedV1)?;
        if root.turn.expected_controller != Some(position) {
            return Err(CreateStorageRootExchangeClosedV1);
        }
        // Move the completed first capsule into its own permanent slot. Only
        // this actual U transition creates the distinct second empty capsule.
        root.turn.initial_cache_current = Some(std::mem::take(&mut root.turn.cache_current));
        root.turn.cache_current.clock = Some(clock);
        let mut loan = OriginalCreateStorageRootExchangeV1 {
            parent: &owner.parent, intake: &mut owner.intake,
            controller: self.original.controller, source: self.original.source,
            profile: self.original.profile, cache: &mut self.cache,
            state: &mut root.turn, use_receiving: Some(receiving),
        };
        let result = root.use_cache_current_proof.produce_once(&mut loan, &mut root.peer, bytes);
        if result.is_ok() {
            root.use_cache_current_proof.completed_packet_v1()?;
            root.turn.use_cache_complete = true;
        }
        result
    }
}
