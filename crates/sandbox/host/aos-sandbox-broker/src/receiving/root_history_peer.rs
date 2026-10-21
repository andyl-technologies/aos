//! Retains actual Root/Controller/Root native post custody across upper stages.
//!
//! Root receiving still acquires its actual L then U at each independent worker
//! and Root-service slot. This owner moves only the native originals; it does
//! not acquire Domain locks, invoke an upper callback or authorize append.

use std::error::Error;

use aos_sandbox_model::{ResourceDimension as D, ResourceVector};
use aos_linux_descriptors::unix_stream::RetainedUnixStream;

use super::{
    ObservationLifetimeV1, RootObservationErrorV1 as E, RootPrearmedHistoryServicePostV1,
    RootSelectedControllerCurrentSampleV1, RootSelectedControllerPeerOriginalV1,
};

mod open;
mod programme;
pub use programme::RootHistoryObservationOriginalV1;
pub use open::{RootAcceptedHistoryBorrowerV1, RootOpenPhysicalBorrowerV1};

/// Retains the same two prearmed Root originals and Controller current sample.
///
/// The actual receiving stage pays before construction and retains its typed
/// traffic/worker/return obligations. Native settlement and sampler disposal
/// remain after all independently owed upper stages have returned.
pub struct RootHistoryPeerPostNativeOriginalV1 {
    before: RootPrearmedHistoryServicePostV1,
    after: RootPrearmedHistoryServicePostV1,
    peer: Option<RootSelectedControllerCurrentSampleV1>,
}

impl RootHistoryPeerPostNativeOriginalV1 {
    /// Moves the actual prearmed service originals and existing observer lifetime.
    ///
    /// This observes nothing and grants no peer, currentness or receiving phase.
    #[must_use]
    pub fn from_originals_v1(
        before: RootPrearmedHistoryServicePostV1,
        after: RootPrearmedHistoryServicePostV1,
        lifetime: ObservationLifetimeV1,
    ) -> Self {
        Self {
            before,
            after,
            peer: Some(RootSelectedControllerCurrentSampleV1::new(lifetime)),
        }
    }

    /// Quotes the actual native samplers, owner moves and finite helper controls.
    ///
    /// # Errors
    /// Refuses checked overflow or an unavailable native sampler supplier.
    pub fn demand_v1() -> Result<ResourceVector, E> {
        let service = RootPrearmedHistoryServicePostV1::demand_v1().ok_or(E::Service)?;
        let peer = RootSelectedControllerCurrentSampleV1::demand_v1()?;
        let controls = Self::additional_control_bytes_v1()
            .and_then(|bytes| u64::try_from(bytes).ok())
            .ok_or(E::Service)?;
        service
            .checked_add(service)
            .and_then(|value| value.checked_add(peer))
            .and_then(|value| {
                value.checked_add(ResourceVector::ZERO.with(D::MemoryBytes, controls))
            })
            .map_err(|_| E::Service)
    }

    fn additional_control_bytes_v1() -> Option<usize> {
        std::mem::size_of::<Self>()
            .checked_mul(3)?
            .checked_add(
                std::mem::size_of::<(
                    RootPrearmedHistoryServicePostV1,
                    RootPrearmedHistoryServicePostV1,
                    ObservationLifetimeV1,
                )>()
                .checked_mul(3)?,
            )?
            .checked_add(
                std::mem::size_of::<(
                    &mut Self,
                    Option<&RetainedUnixStream>,
                    Option<&RootSelectedControllerPeerOriginalV1<'_>>,
                )>()
                .checked_mul(3)?,
            )?
            .checked_add(std::mem::size_of::<Result<(), E>>().checked_mul(6)?)?
            .checked_add(
                std::mem::size_of::<&mut RootPrearmedHistoryServicePostV1>().checked_mul(6)?,
            )?
            .checked_add(std::mem::size_of::<&mut Self>().checked_mul(12)?)?
            .checked_add(std::mem::size_of::<&Self>().checked_mul(12)?)?
            .checked_add(std::mem::size_of::<Option<&(dyn Error + 'static)>>().checked_mul(9)?)?
            .checked_add(
                std::mem::size_of::<Option<aos_systemd_client::FixedPid1PropertyFailureViewV1<'_>>>()
                    .checked_mul(3)?,
            )?
            .checked_add(
                std::mem::size_of::<&RootSelectedControllerCurrentSampleV1>().checked_mul(3)?,
            )?
            .checked_add(std::mem::size_of::<bool>().checked_mul(3)?)?
            .checked_add(open::additional_control_bytes_v1()?)
    }

    /// Borrows the actual independently prearmed Root-before destination.
    pub fn before_original_mut_v1(&mut self) -> &mut RootPrearmedHistoryServicePostV1 {
        &mut self.before
    }

    /// Borrows the actual independently prearmed Root-after destination.
    pub fn after_original_mut_v1(&mut self) -> &mut RootPrearmedHistoryServicePostV1 {
        &mut self.after
    }

    /// Runs the same Controller observation after the reached Root-before slot.
    ///
    /// # Errors
    /// Refuses absent originals or any actual same-peer sample failure.
    pub fn observe_controller_once_v1(
        &mut self,
        native: Option<&RetainedUnixStream>,
        peer: Option<&RootSelectedControllerPeerOriginalV1<'_>>,
    ) -> Result<(), E> {
        match (native, peer, self.peer.as_mut()) {
            (Some(native), Some(peer), Some(sample)) => {
                peer.observe_prearmed_current_into_v1(native, sample)
            }
            _ => Err(E::Service),
        }
    }

    /// Settles the actual Controller sample after the independent Root-after slot.
    ///
    /// # Errors
    /// Refuses an absent, incomplete, refused or repeated native settlement.
    pub fn settle_after_root_post_once_v1(&mut self) -> Result<(), E> {
        match self.peer.as_mut() {
            Some(peer) => peer.settle_after_root_post_once_v1(),
            None => Err(E::Service),
        }
    }

    /// Disposes positive samplers after the caller's whole original settlement.
    ///
    /// The fixed driver calls this only after its worker, traffic and returned
    /// result obligations are positive; failed originals remain physically held.
    pub fn retire_positive_once_v1(&mut self) {
        if self.before.is_positive_v1()
            && self.after.is_positive_v1()
            && self
                .peer
                .as_ref()
                .is_some_and(|peer| peer.is_settled_positive_v1())
        {
            drop(self.peer.take());
            self.before.retire_positive_once_v1();
            self.after.retire_positive_once_v1();
        }
    }

    /// Borrows the actual Root-before native first cause.
    #[must_use]
    pub fn before_failure_v1(&self) -> Option<&(dyn Error + 'static)> {
        self.before.failure()
    }

    /// Borrows the actual Controller native first cause.
    #[must_use]
    pub fn peer_failure_v1(&self) -> Option<&(dyn Error + 'static)> {
        self.peer.as_ref().and_then(|peer| peer.failure())
    }

    /// Borrows the actual Root-after native first cause.
    #[must_use]
    pub fn after_failure_v1(&self) -> Option<&(dyn Error + 'static)> {
        self.after.failure()
    }

    /// Borrows the same Controller archive failure selected by its native cause.
    #[must_use]
    pub fn peer_property_failure_view_v1(
        &self,
    ) -> Option<aos_systemd_client::FixedPid1PropertyFailureViewV1<'_>> {
        self.peer
            .as_ref()
            .and_then(|peer| peer.property_failure_view_v1())
    }
}
