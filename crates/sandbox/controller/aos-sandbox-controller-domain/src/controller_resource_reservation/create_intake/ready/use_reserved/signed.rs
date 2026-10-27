//! Borrows the actual U-funded C6 Signed owner for the same Root transport.
//!
//! The canonical bundle is produced from the actual verified signed plan and
//! protected B proposal. Only the native pair's complete readback/post permits
//! lending these bytes beside that same reservation's mutable receiving ledger.

use super::*;
use aos_sandbox_protocol::authorization_artifact::SignedBrokerPlan;
use aos_sandbox_protocol::semantics::ProtectedStorageCreatePreparationV1;
use aos_sandbox_protocol::domain_ledger::create_storage_history::{
    controller_use::ControllerSignedBodyDataV1, KeyV1, OwnerV1, PhaseV1,
    RecordEnvelopeV1, HEAD_BYTES,
};
use crate::controller_resource_reservation::create_intake::history::signed::SignedOriginalsV1;

impl OriginalCreateStorageReadyV1<'_, '_> {
    /// Records the actual signed preparation on this original Controller lane.
    ///
    /// The same completed Root8/native signing phase and returned U remain
    /// held. The actual typed signed plan is compared to those original bytes;
    /// the shared request builder derives the exact Prepare body and identity.
    /// No caller receipt, raw signature bytes or declared amount issues C6.
    ///
    /// # Errors
    /// Retains reentry, incomplete signing/U, changed original plan/statement,
    /// protected proposal, native writer/prefix, quota, cutoff or independent
    /// post failure. It neither dispatches Prepare nor completes Create.
    #[doc(hidden)]
    pub fn produce_original_storage_signed_once(&mut self,
        signed: &SignedBrokerPlan,
        protected: &ProtectedStorageCreatePreparationV1,
    ) -> Result<(), CreateStorageReadyClosedV1> {
        if self.failure().is_some() || self.original.owner.storage_use.signed.started() {
            self.original.owner.storage_use.closed.get_or_insert(ResourceReservationErrorV1::Conflict);
            return Err(CreateStorageReadyClosedV1);
        }
        self.original.require_operation_currentness_peak_v1(&self.cache)
            .map_err(|_| CreateStorageReadyClosedV1)?;
        self.require_original_storage_signing_complete_v1().map_err(|_| CreateStorageReadyClosedV1)?;
        let owner = &mut *self.original.owner;
        let actual = &mut owner.storage_use;
        actual.signed.produce_once(&owner.parent, &mut owner.intake,
            &owner.histories, &owner.assignment, &actual.validated, &actual.reserved,
            &mut actual.reservation, &owner.root_exchange, signed, protected,
            self.original.controller, self.original.source, self.original.profile)
            .map_err(|_| CreateStorageReadyClosedV1)
    }
}

// This lender contains actual original references only. No decoded record,
// resource vector or borrowed raw packet can construct a completed instance.
pub(in crate::controller_resource_reservation::create_intake)
struct OriginalCreateStorageSignedV1<'held> {
    reserved: OriginalCreateStorageUseReservedV1<'held>,
    signed: &'held SignedOriginalsV1,
}

impl CreateStorageUseOriginalsV1 {
    pub(in crate::controller_resource_reservation::create_intake)
    fn split_signed_receiving_v1(&mut self)
        -> Result<(OriginalCreateStorageSignedV1<'_>, &mut receiving::UseReceivingOriginalsV1), ResourceReservationErrorV1>
    {
        if self.failure().is_some() { return Err(ResourceReservationErrorV1::Conflict); }
        self.signed.position()?;
        self.reserved.position()?;
        self.reservation.position()?;
        let request_shape_bytes = self.reservation.request_shape_bytes_v1()?;
        let (append, receiving) = self.reservation.split_root_receiving_v1()?;
        let reserved = OriginalCreateStorageUseReservedV1 {
            append, request_shape_bytes, record: &self.reserved,
        };
        receiving.require_reserved_v1()?;
        if receiving.claim_data_v1()? != reserved.claim_v1()? {
            return Err(ResourceReservationErrorV1::Conflict);
        }
        Ok((OriginalCreateStorageSignedV1::from_original_reserved_v1(reserved, &self.signed)?, receiving))
    }
}

impl<'held> OriginalCreateStorageSignedV1<'held> {
    pub(in crate::controller_resource_reservation::create_intake)
    fn from_original_reserved_v1(reserved: OriginalCreateStorageUseReservedV1<'held>,
        signed: &'held SignedOriginalsV1,
    ) -> Result<Self, ResourceReservationErrorV1> {
        reserved.position_v1()?;
        signed.position()?;
        Ok(Self { reserved, signed })
    }

    pub(in crate::controller_resource_reservation::create_intake)
    fn position_v1(&self) -> Result<CreateStorageWriterPositionV1, ResourceReservationErrorV1> {
        self.reserved.claim_v1()?;
        self.signed.position()
    }

    pub(in crate::controller_resource_reservation::create_intake)
    fn reserved_v1(&self) -> &OriginalCreateStorageUseReservedV1<'held> { &self.reserved }

    pub(in crate::controller_resource_reservation::create_intake)
    fn request_shape_bytes_v1(&self) -> Result<usize, ResourceReservationErrorV1> {
        self.position_v1()?;
        self.reserved.request_shape_bytes_v1()
    }

    pub(in crate::controller_resource_reservation::create_intake)
    fn request_id_v1(&self) -> Result<[u8; 16], ResourceReservationErrorV1> { self.signed.request_id_v1() }

    pub(in crate::controller_resource_reservation::create_intake)
    fn bundle_v1(&self) -> Result<&'held [u8], ResourceReservationErrorV1> {
        self.position_v1()?;
        self.signed.bundle_v1()
    }

    pub(in crate::controller_resource_reservation::create_intake)
    fn record_v1(&self) -> Result<&'held [u8], ResourceReservationErrorV1> { self.signed.record_v1() }

    pub(in crate::controller_resource_reservation::create_intake)
    fn head_v1(&self) -> Result<&'held [u8; HEAD_BYTES], ResourceReservationErrorV1> { self.signed.head_v1() }

    pub(in crate::controller_resource_reservation::create_intake)
    fn body_v1(&self, lane: [u8; 16]) -> Result<ControllerSignedBodyDataV1<'held>, ResourceReservationErrorV1> {
        let record = RecordEnvelopeV1::decode(self.record_v1()?,
            KeyV1::new(lane, OwnerV1::Controller, 6).map_err(|_| ResourceReservationErrorV1::Conflict)?,
            PhaseV1::new(OwnerV1::Controller, 5).map_err(|_| ResourceReservationErrorV1::Conflict)?)
            .map_err(|_| ResourceReservationErrorV1::Conflict)?;
        ControllerSignedBodyDataV1::decode(record.body(), lane, self.request_shape_bytes_v1()?)
            .map_err(|_| ResourceReservationErrorV1::Conflict)
    }
}

// Only the same completed C5/U and C6 owner can form this immutable view.
pub(in crate::controller_resource_reservation::create_intake)
fn completed_signed_view_v1<'held>(
    reservation: &'held reservation::UseReservationOriginalsV1,
    reserved: &'held super::super::super::history::use_reserved::UseReservedOriginalsV1,
    signed: &'held SignedOriginalsV1,
) -> Result<OriginalCreateStorageSignedV1<'held>, ResourceReservationErrorV1> {
    signed.position()?;
    let reserved = completed_reserved_view_v1(reservation, reserved)?;
    OriginalCreateStorageSignedV1::from_original_reserved_v1(reserved, signed)
}
