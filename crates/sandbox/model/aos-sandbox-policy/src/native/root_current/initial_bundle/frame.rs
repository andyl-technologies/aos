//! Keeps the same parsed Ready borrow across genuine typed Ownership admission.
//!
//! This scoped borrower stores no self-reference and owns no substitute phase.
//! Its parsed fields point into the original immutable Ready bytes retained by
//! the surrounding native programme. Only the private actual-owner factory can
//! construct it; every decoder result stays on that same actual owner.

use std::error::Error;

use aos_sandbox_broker::receiving::{
    RootInitialReceivingOriginalV1, RootObservationErrorV1,
    RootSelectedStartupBorrowV1, RootUpperMutationGuardV1,
};
use aos_sandbox_model::DecodeLimits;
use aos_sandbox_model::format::assignment_capture::CanonicalAssignmentDecodeCaptureV1;
use aos_sandbox_ownership_protocol::response_verification::{
    OwnershipClaimDecodeCaptureV1, OwnershipResponseVerifyCaptureV1,
};
use aos_sandbox_protocol::domain_ledger::create_storage_history::{
    assignment_planned::AssignmentPlannedBodyDataV1, ready::ReadyBundleDataV1,
};

use super::{
    E, Mechanical, NativeError, RootInitialBundleOwnershipOriginalV1,
    RootInitialOpenPreparedOriginalV1, RootInitialReadyOriginalV1,
    RootInitialSourceExchangeOriginalV1, RootInitialTrustOriginalV1,
    RootCurrentAcceptedOriginalsV1, RootCurrentWritersOriginalV1, positive, require_clock,
};

/// Borrows genuine Ready framing and actual Ownership custody through typed admission.
///
/// No public constructor, raw parts, supplied geometry or successful result can
/// create this loan. Its lifetime keeps the same native programme's Ready bytes,
/// writers, original Open, independent Source and captured trust resident.
pub struct RootInitialBundleOwnershipFrameBorrowV1<'cut, 'startup> {
    state: &'cut mut RootInitialBundleOwnershipOriginalV1,
    bundle: ReadyBundleDataV1<'cut>,
    planned: AssignmentPlannedBodyDataV1<'cut>,
    writers: &'cut RootCurrentWritersOriginalV1,
    open: &'cut RootInitialOpenPreparedOriginalV1,
    source: &'cut RootInitialSourceExchangeOriginalV1,
    trust: &'cut RootInitialTrustOriginalV1,
    originals: &'cut RootCurrentAcceptedOriginalsV1<'startup>,
}

impl<'cut, 'startup> RootInitialBundleOwnershipFrameBorrowV1<'cut, 'startup> {
    pub(super) fn prepare_once_v1(
        state: &'cut mut RootInitialBundleOwnershipOriginalV1,
        writers: &'cut RootCurrentWritersOriginalV1,
        open: &'cut RootInitialOpenPreparedOriginalV1,
        ready: &'cut RootInitialReadyOriginalV1,
        source: &'cut RootInitialSourceExchangeOriginalV1,
        trust: &'cut RootInitialTrustOriginalV1,
        originals: &'cut RootCurrentAcceptedOriginalsV1<'startup>,
    ) -> Result<Self, E> {
        if state.body_entered || state.closed {
            state.closed = true;
            return Err(E::Incomplete);
        }
        state.body_entered = true;
        state.fixed.require_complete_v1()?;
        let raw = ready.raw_ready_bytes_v1()?;
        source.require_complete_v1()?;

        let bundle = match ReadyBundleDataV1::borrow_field_framing_data_v1(raw) {
            Ok(bundle) => {
                state.framing = Some(Ok(()));
                bundle
            }
            Err(error) => {
                state.framing = Some(Err(error));
                state.primary = Some(Err(E::Incomplete));
                return Err(E::Incomplete);
            }
        };
        let planned = match crate::bundle_ownership_data::planned_assignment_v1(bundle) {
            Ok(planned) => {
                state.assignment_framing = Some(Ok(()));
                planned
            }
            Err(error) => {
                state.assignment_framing = Some(Err(error));
                state.primary = Some(Err(E::Incomplete));
                return Err(E::Incomplete);
            }
        };
        state.geometry = Some((|| {
            let verifier = trust.verifier_v1().map_err(|_| NativeError::boundary())?;
            crate::bundle_ownership_data::ownership_bundle_typed_demand_v1(
                bundle, planned.manifest.len(), verifier,
            ).map_err(|_| NativeError::Mechanical(Mechanical::JournalTooLarge))
        })());
        if !matches!(state.geometry, Some(Ok(_))) {
            state.primary = Some(Err(E::Incomplete));
            return Err(E::Incomplete);
        }

        Ok(Self { state, bundle, planned, writers, open, source, trust, originals })
    }

    /// Pays typed decoding from this same privately derived Ready geometry.
    ///
    /// # Errors
    /// Retains repeated entry, real Initial/financial mismatch, missing geometry,
    /// actual debit or selected service refusal. No decoder or native IO runs here.
    pub fn begin_typed_once_v1(
        &mut self,
        initial: &mut RootInitialReceivingOriginalV1,
        startup: &RootSelectedStartupBorrowV1<'_>,
        exclusion: &RootUpperMutationGuardV1<'_>,
    ) -> Result<(), RootObservationErrorV1> {
        if self.state.closed || self.state.typed.entered || self.state.primary.is_some() {
            self.state.closed = true;
            initial.latch_root_refusal_v1();
            return Err(RootObservationErrorV1::Service);
        }

        let mut predecessor = match self.originals.peer.borrow_current_writers_predecessor_v1(initial) {
            Ok(predecessor) => predecessor,
            Err(error) => {
                self.state.park_predecessor_refusal_v1(error);
                return Err(RootObservationErrorV1::Service);
            }
        };
        let (initial, financial) = predecessor.split_initial_v1();
        if initial.failure().is_some() {
            self.state.closed = true;
            initial.latch_root_refusal_v1();
            return Err(RootObservationErrorV1::Service);
        }
        self.state.typed.entered = true;
        self.state.typed.financial = Some(financial.clone());

        self.state.typed.permit = Some((|| {
            let body = self.open.body_v1().map_err(|_| NativeError::boundary())?;
            let enrollment = initial.enrollment_v1().ok_or_else(NativeError::boundary)?;
            let base = self.state.fixed.require_complete_v1().map_err(|_| NativeError::boundary())?;
            if !matches!(initial.recipient_binding_result_v1(), Some(Ok(())))
                || (body.root_recipient, body.root_producer)
                    != (enrollment.recipient_invocation, enrollment.identity.native_fields().invocation)
                || self.state.fixed.financial.as_ref()
                    .is_none_or(|original| !original.same_original_data_v1(financial))
                || !startup.same_financial_original_data_v1(financial)
            {
                return Err(NativeError::boundary());
            }
            let additional = self.state.geometry.as_ref()
                .and_then(|geometry| geometry.as_ref().ok()).copied()
                .ok_or_else(NativeError::boundary)?;
            let demand = base.checked_add(additional).map_err(|_| NativeError::boundary())?;
            if financial.require_receiving_demand_under_upper_exclusion_v1(exclusion, demand).is_err() {
                return Err(NativeError::Financial(financial.clone()));
            }
            Ok(demand)
        })());
        self.state.typed.finish_v1(initial, startup, exclusion)
    }

    /// Allocates the admitted captures and verifies the same manifest and response.
    ///
    /// # Errors
    /// Retains actual typed-admission, native writer/readback/clock, assignment,
    /// claim, association or trusted Ownership response verification refusal.
    pub fn verify_once_v1(&mut self) -> Result<(), E> {
        if self.state.primary.is_some() || self.state.closed {
            self.state.closed = true;
            return Err(E::Incomplete);
        }
        self.state.primary = Some(self.verify_inner_v1());
        positive(&self.state.primary).map(|_| ())
    }

    fn verify_inner_v1(&mut self) -> Result<(), E> {
        self.state.typed.require_complete_v1()?;
        self.state.assignment = Some(Box::new(CanonicalAssignmentDecodeCaptureV1::new()));
        self.state.claim = Some(Box::new(OwnershipClaimDecodeCaptureV1::new()));
        self.state.response = Some(Box::new(OwnershipResponseVerifyCaptureV1::new()));

        let (authority, policy) = match self.writers.opened_pair_view_v1() {
            Ok(pair) => pair,
            Err(error) => {
                self.state.before_readback = Some(Err(super::RootInitialOpenErrorV1::Root(error)));
                return Err(E::Incomplete);
            }
        };
        self.state.before.observe_once_v1(authority, policy);
        self.state.before_readback = Some(self.open.readback_current_v1(authority, policy));
        self.state.before.require_complete_v1()?;
        positive(&self.state.before_readback)?;
        self.state.before_sample = Some(self.state.before_clock.observe_once(None));
        self.state.before_cutoff = Some(require_clock(self.open, self.source, &self.state.before_sample));
        positive(&self.state.before_cutoff)?;

        self.state.assignment_decode = Some(self.state.assignment.as_mut().ok_or(E::Incomplete)?
            .decode_once_v1(self.planned.manifest, DecodeLimits::default()));
        positive(&self.state.assignment_decode)?;
        self.state.claim_decode = Some(self.state.claim.as_mut().ok_or(E::Incomplete)?
            .decode_once_v1(self.bundle.ownership_claim));
        positive(&self.state.claim_decode)?;
        let claim = self.state.claim.as_ref().and_then(|capture| capture.value()).ok_or(E::Incomplete)?;
        let manifest = self.state.assignment.as_ref().and_then(|capture| capture.value())
            .ok_or(E::Incomplete)?;

        // The same-frame canonical recipe keeps intent/head parse errors ahead
        // of the actual Source and original Open completion getter slots.
        self.state.association = Some(self.require_association_v1(manifest, claim));
        positive(&self.state.association)?;
        let verifier = self.trust.verifier_v1()?;
        let clock = positive(&self.state.before_sample)?;
        self.state.verification = Some(verifier.verify_response_bytes_retaining_v1(
            claim, self.bundle.ownership_lease, self.bundle.ownership_signature,
            self.bundle.ownership_receipt, self.bundle.ownership_receipt_signature, clock,
            self.state.response.as_mut().ok_or(E::Incomplete)?,
        ));
        positive(&self.state.verification).map(|_| ())
    }

    fn require_association_v1(
        &self,
        manifest: &aos_sandbox_model::CanonicalAssignmentManifestV1,
        claim: &aos_sandbox_ownership_protocol::OwnershipClaimV1,
    ) -> Result<(), aos_sandbox_protocol::domain_ledger::create_storage_history::HistoryErrorV1> {
        let bundle = self.bundle;
        let planned = self.planned;
        crate::require_root_bundle_ownership_association_data_v1!(
            bundle, planned, manifest, claim,
            source = self.source.fields_v1(), root = self.open.body_v1()
        )
    }

    /// Borrows the real retained diagnostic while this scoped frame is active.
    ///
    /// This performs no observation and supplies no new loan or transition.
    pub fn failure_v1(&self) -> Option<&(dyn Error + 'static)> {
        self.state.failure_v1()
    }
}
