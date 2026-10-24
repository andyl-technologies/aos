//! Borrows actual RootOpen peer, stream and first-clock owners for named stages.
//!
//! The closed append context owns stage order and typed semantic purpose. Each
//! Root/worker stage rejoins its actual prearmed permanent original under the
//! same separate L interval; no Domain callback or earlier-success token exists.

use std::os::fd::BorrowedFd;

use aos_sandbox_model::RawPairedClockSample;
use aos_linux_descriptors::unix_stream::RetainedUnixStream;

use super::super::{RootOpenClockClosedV1, RootOpenClockOriginalV1};
use super::{
    E, RootHistoryPeerPostNativeOriginalV1, RootPrearmedHistoryServicePostV1,
    RootSelectedControllerPeerOriginalV1,
};

/// Borrows the real same-Root post, accepted peer/stream and immutable clock.
///
/// Only the actual prearmed native post can construct it. Comparison DATA or an
/// independently constructed clock cannot replace the held completed peer and
/// actual Root originals. This borrower does not authorize journal append.
pub struct RootAcceptedHistoryBorrowerV1<'cut, 'startup> {
    post: &'cut mut RootHistoryPeerPostNativeOriginalV1,
    peer: &'cut RootSelectedControllerPeerOriginalV1<'startup>,
    stream: &'cut RetainedUnixStream,
    observation: Option<&'cut mut super::programme::ObservationStateV1>,
}

impl RootHistoryPeerPostNativeOriginalV1 {
    /// Borrows the actual completed peer, accepted stream and prearmed originals.
    ///
    /// # Errors
    /// Refuses a different Root original or an incomplete actual native peer.
    pub fn borrow_accepted_history_v1<'cut, 'startup>(
        &'cut mut self,
        peer: &'cut RootSelectedControllerPeerOriginalV1<'startup>,
        stream: &'cut RetainedUnixStream,
    ) -> Result<RootAcceptedHistoryBorrowerV1<'cut, 'startup>, E> {
        peer.require_completed()?;
        let startup = peer.startup_original_v1();
        if !self.before.matches_startup_original_v1(startup)
            || !self.after.matches_startup_original_v1(startup)
        {
            return Err(E::Service);
        }
        Ok(RootAcceptedHistoryBorrowerV1 {
            post: self,
            peer,
            stream,
            observation: None,
        })
    }

    /// Borrows the actual accepted originals and this same saved RootOpen clock.
    ///
    /// # Errors
    /// Refuses a foreign or incomplete peer/startup, or an unstarted clock.
    pub fn borrow_root_open_physical_v1<'cut, 'startup>(
        &'cut mut self,
        peer: &'cut RootSelectedControllerPeerOriginalV1<'startup>,
        stream: &'cut RetainedUnixStream,
        clock: &'cut RootOpenClockOriginalV1,
    ) -> Result<RootOpenPhysicalBorrowerV1<'cut, 'startup>, E> {
        clock.initial_data_v1().map_err(|_| E::Service)?;
        let accepted = self.borrow_accepted_history_v1(peer, stream)?;
        Ok(RootOpenPhysicalBorrowerV1 { accepted, clock })
    }
}

impl<'cut, 'startup> RootAcceptedHistoryBorrowerV1<'cut, 'startup> {
    /// Binds this actual accepted borrower to the same saved RootOpen clock.
    ///
    /// The native Initial RootOpen producer supplies its own original by
    /// reference; no clock DATA, timestamp, interval, or renewed origin is adopted.
    ///
    /// # Errors
    /// Refuses an unstarted or failed actual first-clock owner.
    pub fn with_root_open_clock_v1(
        self,
        clock: &'cut RootOpenClockOriginalV1,
    ) -> Result<RootOpenPhysicalBorrowerV1<'cut, 'startup>, E> {
        match clock.initial_data_v1() {
            Ok(_) => {}
            Err(_) => return Err(E::Service),
        }
        Ok(RootOpenPhysicalBorrowerV1 { accepted: self, clock })
    }

    /// Quotes this finite binding's actual argument and return controls.
    ///
    /// The genuine Initial Open pre-entry supplier consumes this before the
    /// binding is constructed. This amount grants no clock or append permission.
    #[must_use]
    pub fn root_open_clock_binding_control_bytes_v1() -> Option<usize> {
        use std::mem::size_of;
        size_of::<(Self, &RootOpenClockOriginalV1)>().checked_mul(3)?
            .checked_add(size_of::<Result<RootOpenPhysicalBorrowerV1<'cut, 'startup>, E>>().checked_mul(3)?)?
            .checked_add(size_of::<Result<(RawPairedClockSample, std::time::Instant), RootOpenClockClosedV1>>().checked_mul(3)?)?
            .checked_add(size_of::<RootOpenPhysicalBorrowerV1<'cut, 'startup>>().checked_mul(3)?)?
            .checked_add(size_of::<&RootOpenClockOriginalV1>().checked_mul(3)?)?
            .checked_add(size_of::<E>().checked_mul(3)?)
    }
}

impl<'cut, 'startup> RootAcceptedHistoryBorrowerV1<'cut, 'startup> {
    pub(super) fn with_observation_state_v1(mut self,
        state: &'cut mut super::programme::ObservationStateV1) -> Self {
        self.observation = Some(state);
        self
    }


    /// Borrows the same actual selected service owner for recurring typed entry.
    ///
    /// Its recheck owns the original financial L/N interval, one canonical
    /// traffic debit and the same native sampler. Upper L/U must be released
    /// before recheck; no additional service debit or sampler is introduced.
    ///
    /// # Errors
    /// Refuses failed, incomplete, ordinary or ended original selected custody.
    pub fn borrow_selected_startup_v1(
        &self,
    ) -> Result<super::super::RootSelectedStartupBorrowV1<'_>, E> {
        self.peer.startup_original_v1().borrow_selected_startup_v1()
    }

    /// Copies identity DATA from the same actual startup and accepted peer.
    ///
    /// The actual RootOpen owner separately performs its second service recheck
    /// at the original preclock frontier before invoking this passive read.
    ///
    /// # Errors
    /// Refuses a missing, failed or ended actual original enrollment association.
    pub fn root_open_identity_data_v1(&self) -> Result<aos_sandbox_protocol::domain_ledger::create_storage_history::root_open::RootCurrentOpenIdentityDataV1, E>{
        let startup = self.peer.startup_original_v1();
        let original = startup.selected_permanent.get().ok_or(E::Service)?;
        let _exclusion = original.enter_history_post_exclusion_v1();
        let _native = original.enter_native()?;
        let enrollment = original.enrollment().enrollment_v1().ok_or(E::Service)?;
        let credentials = self.stream.peer().credentials();
        Ok(aos_sandbox_protocol::domain_ledger::create_storage_history::root_open::RootCurrentOpenIdentityDataV1 {
            profile: startup.fields().profile_file.measured_digest_v1(),
            recipient: enrollment.recipient_invocation,
            producer: enrollment.identity.native_fields().invocation,
            root_pid: std::process::id(),
            controller_pid: credentials.pid().get(),
            controller_uid: startup.fields().profile.identities[0],
            controller_gid: startup.fields().profile.identities[1],
        })
    }

    /// Copies only the actual Controller credentials on the held accepted stream.
    #[must_use]
    pub fn accepted_controller_credentials_data_v1(
        &self,
    ) -> aos_linux_descriptors::unix_stream::UnixStreamPeerCredentials {
        self.stream.peer().credentials()
    }

    /// Compares the held accepted stream with the handler's same endpoint.
    ///
    /// # Errors
    /// Preserves the actual native endpoint mismatch or kernel failure.
    pub fn require_same_endpoint_v1(
        &self,
        original: BorrowedFd<'_>,
    ) -> Result<(), aos_linux_descriptors::Error> {
        self.stream.require_same_endpoint_v1(original)
    }

    /// Observes the same actual worker and independent Root/Controller/Root originals.
    ///
    /// The real Policy lender retains its Stage/traffic obligation. This method
    /// runs no semantic verifier and grants no append or continuation purpose.
    ///
    /// # Errors
    /// Retains the actual worker, native post or settlement refusal on this post.
    pub fn observe_shared_once_v1(&mut self) -> Result<(), E> {
        let state = self.observation.as_deref_mut().ok_or(E::Service)?;
        super::programme::observe_borrowed_once_v1(self.post, state, self.peer, self.stream)
    }

    /// Enters the actual paid shared worker on this same prearmed original.
    ///
    /// The real completed peer and sealed prearmed originals preserve the
    /// immutable admission prefix; actual healthy N and worker-idle are rejoined
    /// at this reached frontier under its own same-original L interval.
    ///
    /// # Errors
    /// Refuses a foreign, unhealthy or nonidle original worker.
    pub fn enter_shared_worker_once_v1(&mut self) -> Result<(), E> {
        self.post.before.enter_original_history_worker_once_v1()
    }

    /// Observes the independently prearmed Root-before on its actual retained original.
    ///
    /// # Errors
    /// Retains a foreign, ended, repeated or failed native Root observation.
    pub fn observe_root_before_once_v1(&mut self) -> Result<(), E> {
        self.post
            .before
            .observe_owned_with_exclusion_once_v1(self.peer.startup_original_v1())
    }

    /// Observes the actual Controller without retaining an upper receiving lock.
    ///
    /// # Errors
    /// Retains the same peer/stream native, image, cgroup or PID1 failure.
    pub fn observe_controller_once_v1(&mut self) -> Result<(), E> {
        self.post
            .observe_controller_once_v1(Some(self.stream), Some(self.peer))
    }

    /// Observes the independently owed Root-after despite earlier refusal.
    ///
    /// # Errors
    /// Retains a foreign, ended, repeated or failed native Root observation.
    pub fn observe_root_after_once_v1(&mut self) -> Result<(), E> {
        self.post
            .after
            .observe_owned_with_exclusion_once_v1(self.peer.startup_original_v1())
    }

    /// Releases the same entered shared worker through its same original owed path.
    ///
    /// # Errors
    /// Refuses a foreign, ended or already idle worker without restoring health.
    pub fn finish_shared_worker_once_v1(&mut self) -> Result<(), E> {
        self.post.before.finish_original_history_worker_once_v1()
    }

    /// Settles the same Controller sample after the complete independent posts.
    ///
    /// # Errors
    /// Refuses an absent, failed, incomplete or repeated original settlement.
    pub fn settle_after_posts_once_v1(&mut self) -> Result<(), E> {
        self.post.settle_after_root_post_once_v1()
    }

    /// Retires positive samplers at the original whole-completion frontier.
    pub fn retire_positive_once_v1(&mut self) {
        self.post.retire_positive_once_v1();
    }
}

/// Borrows the actual accepted native originals and saved RootOpen clock.
///
/// The common accepted borrower remains the sole physical worker/post engine.
/// This wrapper adds only the genuine saved first-clock reference; it grants
/// neither a semantic continuation nor a paid worker purpose by itself.
pub struct RootOpenPhysicalBorrowerV1<'cut, 'startup> {
    accepted: RootAcceptedHistoryBorrowerV1<'cut, 'startup>,
    clock: &'cut RootOpenClockOriginalV1,
}

impl RootOpenPhysicalBorrowerV1<'_, '_> {
    /// Borrows the actual selected service owner for its existing fixed entry.
    ///
    /// # Errors
    /// Refuses failed, incomplete, ordinary or ended selected original custody.
    pub fn borrow_selected_startup_v1(
        &self,
    ) -> Result<super::super::RootSelectedStartupBorrowV1<'_>, E> {
        self.accepted.borrow_selected_startup_v1()
    }

    /// Copies only the Controller credentials retained on this same stream.
    #[must_use]
    pub fn accepted_controller_credentials_data_v1(
        &self,
    ) -> aos_linux_descriptors::unix_stream::UnixStreamPeerCredentials {
        self.accepted.accepted_controller_credentials_data_v1()
    }

    /// Compares the actual accepted stream with the handler's same endpoint.
    ///
    /// # Errors
    /// Preserves the actual native endpoint mismatch or kernel failure.
    pub fn require_same_endpoint_v1(
        &self,
        original: BorrowedFd<'_>,
    ) -> Result<(), aos_linux_descriptors::Error> {
        self.accepted.require_same_endpoint_v1(original)
    }

    /// Observes this same accepted programme without renewing its saved clock.
    ///
    /// # Errors
    /// Retains the actual worker, native post or settlement refusal.
    pub fn observe_shared_once_v1(&mut self) -> Result<(), E> {
        self.accepted.observe_shared_once_v1()
    }

    /// Enters the same actual named worker for the proven initial purpose.
    ///
    /// # Errors
    /// Preserves the actual same-original native stage refusal.
    pub fn enter_shared_worker_once_v1(&mut self) -> Result<(), E> {
        self.accepted.enter_shared_worker_once_v1()
    }

    /// Runs the independently prearmed native Root-before stage.
    ///
    /// # Errors
    /// Preserves the actual same-original native stage refusal.
    pub fn observe_root_before_once_v1(&mut self) -> Result<(), E> {
        self.accepted.observe_root_before_once_v1()
    }

    /// Runs the same original Controller sample with upper locks released.
    ///
    /// # Errors
    /// Preserves the actual same-original native stage refusal.
    pub fn observe_controller_once_v1(&mut self) -> Result<(), E> {
        self.accepted.observe_controller_once_v1()
    }

    /// Runs the independently owed native Root-after stage.
    ///
    /// # Errors
    /// Preserves the actual same-original native stage refusal.
    pub fn observe_root_after_once_v1(&mut self) -> Result<(), E> {
        self.accepted.observe_root_after_once_v1()
    }

    /// Finishes the same actual named worker through its owed path.
    ///
    /// # Errors
    /// Preserves the actual same-original native stage refusal.
    pub fn finish_shared_worker_once_v1(&mut self) -> Result<(), E> {
        self.accepted.finish_shared_worker_once_v1()
    }

    /// Settles the actual Controller sample after the independent posts.
    ///
    /// # Errors
    /// Preserves the actual same-original native stage refusal.
    pub fn settle_after_posts_once_v1(&mut self) -> Result<(), E> {
        self.accepted.settle_after_posts_once_v1()
    }

    /// Retires only the same actually positive native samples.
    pub fn retire_positive_once_v1(&mut self) {
        self.accepted.retire_positive_once_v1();
    }

    /// Compares the actual native peer with another genuine producer borrow.
    ///
    /// Reference identity preserves the original qualifier association. Matching
    /// credentials, clock DATA or a shared financial account cannot replace it.
    ///
    /// # Errors
    /// Refuses a different native peer without observing either peer again.
    pub fn require_same_controller_peer_original_v1(
        &self,
        original: &RootSelectedControllerPeerOriginalV1<'_>,
    ) -> Result<(), E> {
        if std::ptr::eq(self.accepted.peer, original) {
            Ok(())
        } else {
            Err(E::Service)
        }
    }

    /// Bounds only the actual comparison argument, reference and result planes.
    #[must_use]
    pub fn peer_association_control_bytes_v1() -> Option<usize> {
        use std::mem::size_of;

        size_of::<(&Self, &RootSelectedControllerPeerOriginalV1<'_>)>()
            .checked_mul(3)?
            .checked_add(size_of::<(&RootSelectedControllerPeerOriginalV1<'_>,
                &RootSelectedControllerPeerOriginalV1<'_>)>().checked_mul(3)?)?
            .checked_add(size_of::<bool>().checked_mul(3)?)?
            .checked_add(size_of::<Result<(), E>>().checked_mul(3)?)
    }

    /// Borrows the actual immutable first-clock owner used by this same cut.
    #[must_use]
    pub fn clock_original_v1(&self) -> &RootOpenClockOriginalV1 {
        self.clock
    }

    /// Compares the actual final sample against this same original interval.
    ///
    /// # Errors
    /// Refuses a changed boot, foreign cutoff or expired original interval.
    pub fn require_current_clock_v1(
        &self,
        current: RawPairedClockSample,
        cutoff: u64,
    ) -> Result<(), RootOpenClockClosedV1> {
        self.clock.require_current_v1(current, cutoff)
    }
}

pub(super) fn additional_control_bytes_v1() -> Option<usize> {
    let common = std::mem::size_of::<RootAcceptedHistoryBorrowerV1<'_, '_>>()
        .checked_mul(3)?
        .checked_add(
            std::mem::size_of::<Result<RootAcceptedHistoryBorrowerV1<'_, '_>, E>>()
                .checked_mul(3)?,
        )?
        .checked_add(
            std::mem::size_of::<(
                &mut RootHistoryPeerPostNativeOriginalV1,
                &RootSelectedControllerPeerOriginalV1<'_>,
                &RetainedUnixStream,
            )>()
            .checked_mul(3)?,
        )?
        .checked_add(std::mem::size_of::<&RootAcceptedHistoryBorrowerV1<'_, '_>>().checked_mul(9)?)?
        .checked_add(
            std::mem::size_of::<&mut RootAcceptedHistoryBorrowerV1<'_, '_>>().checked_mul(21)?,
        )?
        .checked_add(
            std::mem::size_of::<aos_linux_descriptors::unix_stream::UnixStreamPeerCredentials>()
                .checked_mul(6)?,
        )?
        .checked_add(std::mem::size_of::<Result<(), E>>().checked_mul(18)?)?
        .checked_add(std::mem::size_of::<Result<(), aos_linux_descriptors::Error>>().checked_mul(3)?)?;

    let root_open = std::mem::size_of::<RootOpenPhysicalBorrowerV1<'_, '_>>()
        .checked_mul(3)?
        .checked_add(
            std::mem::size_of::<Result<RootOpenPhysicalBorrowerV1<'_, '_>, E>>().checked_mul(3)?,
        )?
        .checked_add(
            std::mem::size_of::<(
                &mut RootHistoryPeerPostNativeOriginalV1,
                &RootSelectedControllerPeerOriginalV1<'_>,
                &RetainedUnixStream,
                &RootOpenClockOriginalV1,
            )>()
            .checked_mul(3)?,
        )?
        .checked_add(
            std::mem::size_of::<&mut RootOpenPhysicalBorrowerV1<'_, '_>>().checked_mul(21)?,
        )?
        .checked_add(
            std::mem::size_of::<(&RootOpenPhysicalBorrowerV1<'_, '_>, BorrowedFd<'_>)>()
                .checked_mul(3)?,
        )?
        .checked_add(
            std::mem::size_of::<(
                &RootOpenPhysicalBorrowerV1<'_, '_>,
                RawPairedClockSample,
                u64,
            )>()
            .checked_mul(3)?,
        )?
        .checked_add(std::mem::size_of::<&RootOpenClockOriginalV1>().checked_mul(3)?)?
        .checked_add(
            std::mem::size_of::<&super::super::RootStartupNativeOriginalV1>().checked_mul(6)?,
        )?
        .checked_add(std::mem::size_of::<Result<(), E>>().checked_mul(21)?)?
        .checked_add(std::mem::size_of::<Result<(), aos_linux_descriptors::Error>>().checked_mul(3)?)?
        .checked_add(std::mem::size_of::<Result<(), RootOpenClockClosedV1>>().checked_mul(3)?)?
        .checked_add(
            std::mem::size_of::<Result<super::super::RootSelectedStartupBorrowV1<'_>, E>>()
                .checked_mul(3)?,
        )?
        .checked_add(
            std::mem::size_of::<(
                &RootPrearmedHistoryServicePostV1,
                &super::super::RootStartupNativeOriginalV1,
            )>()
            .checked_mul(6)?,
        )?
        .checked_add(std::mem::size_of::<bool>().checked_mul(6)?);

    common.checked_add(root_open?)?
        .checked_add(std::mem::size_of::<Result<aos_sandbox_protocol::domain_ledger::create_storage_history::root_open::RootCurrentOpenIdentityDataV1, E>>().checked_mul(3)?)?
        .checked_add(std::mem::size_of::<aos_sandbox_protocol::domain_ledger::create_storage_history::root_open::RootCurrentOpenIdentityDataV1>().checked_mul(3)?)?
        .checked_add(std::mem::size_of::<&RootAcceptedHistoryBorrowerV1<'_, '_>>().checked_mul(3)?)?
        .checked_add(std::mem::size_of::<Option<&super::super::OriginalEnrollment>>().checked_mul(3)?)?
        .checked_add(std::mem::size_of::<Result<&super::super::OriginalEnrollment, E>>().checked_mul(3)?)?
        .checked_add(std::mem::size_of::<aos_linux_descriptors::unix_stream::UnixStreamPeerCredentials>().checked_mul(3)?)?
        .checked_add(std::mem::size_of::<&super::super::RootStartupNativeOriginalV1>().checked_mul(3)?)?
        .checked_add(std::mem::size_of::<&super::super::root_permanent::RootPermanentNativeOriginalV1>().checked_mul(3)?)?
        .checked_add(std::mem::size_of::<super::super::root_invocation::RootNativeInvocationGuardV1<'_>>().checked_mul(3)?)?
        .checked_add(std::mem::size_of::<Result<super::super::root_invocation::RootNativeInvocationGuardV1<'_>, E>>().checked_mul(3)?)
}

pub(super) fn programme_forwarding_control_bytes_v1() -> Option<usize> {
    use std::mem::size_of;
    size_of::<&mut RootAcceptedHistoryBorrowerV1<'_, '_>>().checked_mul(3)?
        .checked_add(size_of::<&mut RootOpenPhysicalBorrowerV1<'_, '_>>().checked_mul(3)?)?
        .checked_add(size_of::<Result<(), E>>().checked_mul(6)?)?
        .checked_add(size_of::<Option<&mut super::programme::ObservationStateV1>>().checked_mul(6)?)?
        .checked_add(size_of::<Result<&mut super::programme::ObservationStateV1, E>>().checked_mul(3)?)?
        .checked_add(size_of::<Option<usize>>().checked_mul(3)?)
}
