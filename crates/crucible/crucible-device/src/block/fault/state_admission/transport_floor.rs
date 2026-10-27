//! The frontend's oldest live transport epoch and pruning below it.
//!
//! Every block request carries `oldest_live_epoch`: the oldest epoch any request
//! the frontend may still submit can carry, including the request itself. It
//! covers in-flight requests and identities the frontend will resubmit after a
//! `RetryPreserveId` disposition, so no later request names an older epoch
//! ([IO-35]). The retired reset policy and preserve-ID authorizations of older
//! epochs can therefore never be consulted again and are dropped when the
//! acknowledged floor advances.

use super::*;

impl BlockFaultState {
    /// Records the oldest live epoch carried by an admitted request.
    ///
    /// The floor must not exceed the request's own epoch or the authenticated
    /// transport epoch, and must not regress below a floor already
    /// acknowledged: the frontend computes it over every identity it may still
    /// submit, so a decrease means that set was misreported. All three cases
    /// fail closed. Advancing the floor drops retired epochs and preserve-ID
    /// authorizations strictly below it.
    ///
    /// # Errors
    ///
    /// Returns [`DeviceError::InvalidBlockFaultDirective`] when the floor
    /// follows the request epoch, follows the transport epoch, or regresses.
    pub(in crate::block::fault) fn acknowledge_oldest_live_epoch(
        &mut self,
        request: &BlockRequest,
    ) -> Result<(), DeviceError> {
        let floor = request.oldest_live_epoch;
        if floor > request.epoch {
            return Err(DeviceError::InvalidBlockFaultDirective {
                reason: "block request oldest live epoch follows its own epoch",
            });
        }
        if self.transport_epoch.is_some_and(|epoch| floor > epoch) {
            return Err(DeviceError::InvalidBlockFaultDirective {
                reason: "block request oldest live epoch follows the transport epoch",
            });
        }
        if floor < self.oldest_live_transport_epoch {
            return Err(DeviceError::InvalidBlockFaultDirective {
                reason: "block request oldest live epoch regressed",
            });
        }
        if floor == self.oldest_live_transport_epoch {
            return Ok(());
        }

        observed_set!(self, oldest_live_transport_epoch, floor);

        // `split_off` keeps the pruning cost proportional to what is dropped.
        // Authorizations below the floor are unusable: the frontend no longer
        // holds those identities, for example because a later reset rewrote the
        // disposition that granted them.
        let kept_epochs = self.retired_transport_epochs.split_off(&floor);
        let dropped_epochs = std::mem::replace(&mut self.retired_transport_epochs, kept_epochs);
        let kept_authorizations = self
            .retry_preserve_authorizations
            .split_off(&BlockRequestIdentity::new(floor, 0));
        let dropped_authorizations =
            std::mem::replace(&mut self.retry_preserve_authorizations, kept_authorizations);
        self.observation_changed |=
            !dropped_epochs.is_empty() || !dropped_authorizations.is_empty();
        Ok(())
    }
}
