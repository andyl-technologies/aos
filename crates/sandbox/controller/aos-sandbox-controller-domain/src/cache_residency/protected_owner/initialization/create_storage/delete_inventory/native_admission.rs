//! Lends one actual C17 turn to the shared Cache native reader.
//!
//! Only this private Delete query constructs the admission after paying the
//! five-owner fixed/captured/full-prefix bound on the same Source/C17 scope.
//! The original turn owns its intrinsic financial/profile association; this
//! reader view neither creates an account nor accepts an external capacity.

use super::*;
use aos_sandbox_broker::controller_receiving::bank_launch::ControllerDeletePreacceptTurnOriginalV1;

pub(in super::super) struct CacheDeleteReadAdmissionV1<'profile> {
    pub(super) turn: ControllerDeletePreacceptTurnOriginalV1<'profile>,
    identity: CacheHeldIdentityDataV1,
    paid: Option<ResourceVector>,
    semantic: Option<ResourceVector>,
    failure: Option<ResourceReservationErrorV1>,
    native_marker: bool,
}

impl<'profile> CacheDeleteReadAdmissionV1<'profile> {
    // This constructor is confined to the concrete genuine query factory.
    // The real Source debit completes before install_paid_shape is reachable.
    pub(super) fn new(
        turn: ControllerDeletePreacceptTurnOriginalV1<'profile>,
        identity: CacheHeldIdentityDataV1,
    ) -> Self {
        Self { turn, identity, paid: None, semantic: None, failure: None, native_marker: false }
    }

    pub(super) fn install_paid_shape(
        &mut self,
        complete: ResourceVector,
        semantic: ResourceVector,
    ) -> Result<(), ResourceReservationErrorV1> {
        if self.paid.is_some() || !semantic.is_within(complete) || self.failure.is_some() {
            return self.refuse();
        }
        if self.turn.require_prepaid_cache_read_frontier_v1().is_err() {
            self.native_marker = true;
            return self.refuse();
        }
        self.paid = Some(complete);
        self.semantic = Some(semantic);
        Ok(())
    }

    pub(in super::super) fn semantic_peak_v1(&self) -> Result<ResourceVector, JournalError> {
        self.semantic.filter(|_| self.failure.is_none()).ok_or(JournalError::ProtectedBoundary)
    }

    pub(in super::super) fn require_identity_v1(&mut self, identity: CacheHeldIdentityDataV1)
        -> Result<(), ResourceReservationErrorV1>
    {
        if self.identity != identity || self.paid.is_none() || self.failure.is_some() {
            return self.refuse();
        }
        if self.turn.require_prepaid_cache_read_frontier_v1().is_err() {
            self.native_marker = true;
            return self.refuse();
        }
        Ok(())
    }

    pub(in super::super) fn require_semantic_shape_v1(&mut self, shape: &CacheHeldNativeSemanticShapeV1)
        -> Result<(), ResourceReservationErrorV1>
    {
        self.require_identity_v1(shape.original_identity_v1())?;
        let complete = match shape.dominant_receiving_demand_v1() {
            Ok(complete) => complete,
            Err(_) => return self.refuse(),
        };
        if !self.paid.is_some_and(|paid| complete.is_within(paid)) {
            return self.refuse();
        }
        Ok(())
    }

    pub(super) fn local_failure_v1(&self) -> Option<&(dyn Error + 'static)> {
        self.failure.as_ref().map(|cause| cause as _)
    }

    pub(super) fn has_native_marker_v1(&self) -> bool { self.native_marker }

    fn refuse<T>(&mut self) -> Result<T, ResourceReservationErrorV1> {
        self.failure.get_or_insert(ResourceReservationErrorV1::Conflict);
        self.turn.refuse_primary_v1();
        Err(ResourceReservationErrorV1::Conflict)
    }
}
