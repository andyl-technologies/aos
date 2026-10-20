//! Enters the actual C7 pair through the same Ready and returned U.

use super::*;

impl OriginalCreateStorageReadyV1<'_, '_> {
    /// Records dispatch binding from this original's completed C6 and Root4.
    ///
    /// All signed bytes and the unchanged actual U remain resident. This does
    /// not send a Broker request or replace the original Storage Session.
    ///
    /// # Errors
    /// Retains reentry, incomplete signed transport/U, changed Controller/native
    /// prefix, accounting, cutoff or independently owed post failure.
    #[doc(hidden)]
    pub fn produce_original_storage_dispatch_bound_once(&mut self) -> Result<(), CreateStorageReadyClosedV1> {
        if self.failure().is_some() || self.original.owner.storage_use.dispatch.started() {
            self.original.owner.storage_use.closed.get_or_insert(ResourceReservationErrorV1::Conflict);
            return Err(CreateStorageReadyClosedV1);
        }
        self.original.require_operation_currentness_peak_v1(&self.cache).map_err(|_| CreateStorageReadyClosedV1)?;
        let owner = &mut *self.original.owner;
        let actual = &mut owner.storage_use;
        actual.dispatch.produce_once(&owner.parent, &mut owner.intake, &owner.histories,
            &owner.assignment, &actual.validated, &actual.reserved, &actual.signed,
            &mut actual.reservation, &owner.root_exchange,
            self.original.controller, self.original.source, self.original.profile)
            .map_err(|_| CreateStorageReadyClosedV1)
    }
}
