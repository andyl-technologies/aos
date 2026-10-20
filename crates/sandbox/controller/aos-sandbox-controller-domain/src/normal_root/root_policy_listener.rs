//! Retains the fixed Root listener and one actual accepted policy flight.
//!
//! The exclusive listener borrow makes accepted-flight receiving sequential.
//! Upper dispatch Results are custody DATA: even a fabricated successful Result
//! grants no phase or signer authority. Native settlement independently checks
//! the original selected Root and ends the same accepted socket before reuse.

mod connection_escrow;
mod permanent_completion;
pub(crate) use permanent_completion::RootPolicyPositiveCompletionPlanV2;
mod purpose_peer;
mod serving;

use purpose_peer::RootAcceptedPurposePeerV1;
mod delete_exchange;

use std::error::Error;
use std::fs::Metadata;
use std::io;
use std::os::unix::{fs::FileTypeExt as _, net::{UnixListener, UnixStream}};
use std::path::Path;

use aos_sandbox_model::{ResourceDimension as D, ResourceVector};
use aos_sandbox_linux::unix_stream::RetainedUnixStream;

use super::{NormalRootStartupErrorV1, ProductionNormalRootStartupV1};

const SOCKET: &str = crate::policy_compiler::POLICY_AUTHORITY_FIXED_SOCKET_PATH_V2;

pub(crate) struct RootCurrentOpenIdentityDataV1 {
    pub(crate) profile: [u8; 32],
    pub(crate) recipient: [u8; 16],
    pub(crate) producer: [u8; 16],
    pub(crate) root_pid: u32,
    pub(crate) controller_pid: u32,
    pub(crate) controller_uid: u32,
    pub(crate) controller_gid: u32,
}

/// Retains fixed socket preparation and one installed Root listener.
///
/// Only actual selected startup constructs this owner. Its genuine RootR, when
/// installed, pays fixed listener and accepted-flight reservoirs before bind.
/// Ordinary selected startup establishes no receiving claim.
pub struct RootPolicyListenerReceivingV1<'startup> {
    startup: &'startup ProductionNormalRootStartupV1,
    permit: Option<Result<(), NormalRootStartupErrorV1>>,
    metadata: Option<io::Result<Metadata>>,
    removal: Option<io::Result<()>>,
    listener: Option<io::Result<UnixListener>>,
    entered: bool,
    resource_receiving: bool,
    failed: bool,
    flight_permit: Option<Result<(), NormalRootStartupErrorV1>>,
    serving: Option<serving::RootPolicyServingCustodyV1>,
    connection_escrow: Option<connection_escrow::RootPolicyConnectionEscrowV1>,
}

impl<'startup> RootPolicyListenerReceivingV1<'startup> {
    pub(crate) fn permanent_completion_tail_demand_v2() -> Option<ResourceVector> {
        permanent_completion::RootPermanentCompletionOriginalV2::receiving_demand_v2()
    }

    pub(super) fn new(startup: &'startup ProductionNormalRootStartupV1) -> Self {
        Self { startup, permit: None, metadata: None, removal: None,
               listener: None, entered: false,
               resource_receiving: startup.receiving.is_some(), failed: false, flight_permit: None,
               serving: None, connection_escrow: None }
    }

    pub(crate) fn fixed_demand() -> ResourceVector {
        // Fixed listener/flight owners, at most one accepted address and socket
        // duplicate/pidfd family, literal socket path, bounded native error/path
        // work and a 112-byte prelude's per-byte subject-evidence owner slots.
        let memory = std::mem::size_of::<Self>() + std::mem::size_of::<RootPolicyAcceptedFlightV1<'_, '_>>()
            + 112 * (std::mem::size_of::<aos_sandbox_linux::unix_stream::UnixStreamSubjectChunk>() + 4096)
            + 3 * std::mem::size_of::<crate::policy_compiler::RootPolicyPreludeOriginalV1<'_, '_, '_>>()
            + (3 * std::mem::size_of::<crate::policy_compiler::OriginalRootCreateStorageCurrentAttemptV1<'_, '_, '_>>())
                .max(3 * std::mem::size_of::<crate::policy_compiler::delete_root::RootDeletePendingReceivingV1<'_, '_, '_>>())
                .max(3 * std::mem::size_of::<crate::policy_compiler::delete_root::RootDeletePlanningReceivingV1<'_, '_, '_>>())
                .max(3 * std::mem::size_of::<crate::policy_compiler::RootStorageApplyReceivingV1<'_, '_, '_>>())
                .max(3 * std::mem::size_of::<crate::policy_compiler::RootStartResourceReceivingV2<'_, '_, '_>>())
                .max(3 * std::mem::size_of::<crate::policy_compiler::RootMaintenanceStorageReceivingV3<'_, '_, '_>>())
                .max(3 * std::mem::size_of::<crate::policy_compiler::RootFinalityRecoverReceivingV1<'_, '_, '_>>())
                .max(3 * std::mem::size_of::<crate::policy_compiler::execution_no_apply_root::transport::RootExecutionNoApplyReceivingV2<'_, '_, '_>>())
                .max(3 * std::mem::size_of::<crate::policy_compiler::stop_cleanup_root::transport::RootStopCleanupReceivingV1<'_, '_, '_>>())
                .max(3 * std::mem::size_of::<crate::policy_compiler::RootEnvironmentPolicyAttemptV1<'_, '_, '_>>())
            + 3 * std::mem::size_of::<serving::RootPolicyServingCustodyV1>()
            + serving::disposition_construction_bytes_v1()
            + 64 * 1024;
        let base = ResourceVector::ZERO.with(D::MemoryBytes, memory as u64)
            .with(D::OpenFiles, 6).with(D::MetadataEntries, 128)
            .with(D::NetworkBytes, 112).with(D::OutputBytes, memory as u64);
        let opening_clock = crate::policy_compiler::RootPolicyPreludeOriginalV1::opening_clock_demand_v1();
        match base.checked_add(opening_clock) {
            Ok(complete) => complete,
            // An unrepresentable fixed shape cannot produce a smaller debit.
            Err(_) => base.with(D::MemoryBytes, u64::MAX).with(D::OpenFiles, u64::MAX),
        }
    }

    /// Admits and binds the unchanged fixed policy-authority socket once.
    ///
    /// # Errors
    /// Retains insufficient original provision, unsafe prior names, failed
    /// removal/bind, or changed selected Root. Reentry performs no observation.
    pub fn bind_once(&mut self) -> Result<(), NormalRootStartupErrorV1> {
        if self.entered { self.failed = true; return Err(NormalRootStartupErrorV1::Service); }
        self.entered = true;
        self.permit = Some(if self.startup.receiving.is_some() {
            let mut receiving = self.startup.lock_receiving_v1()?;
            let returned = receiving.original_mut_v1().prepay_policy_listener_once(self.startup);
            receiving.finish_returned_v1(returned)
        } else { Err(NormalRootStartupErrorV1::Service) });
        if !matches!(self.permit, Some(Ok(()))) {
            self.failed = true;
            return Err(NormalRootStartupErrorV1::Service);
        }
        let path = Path::new(SOCKET);
        self.metadata = Some(path.symlink_metadata());
        match self.metadata.as_ref() {
            Some(Ok(metadata)) if metadata.file_type().is_socket() => {
                self.removal = Some(std::fs::remove_file(path));
                if !matches!(self.removal, Some(Ok(()))) {
                    self.failed = true;
                    return Err(NormalRootStartupErrorV1::Service);
                }
            }
            Some(Err(cause)) if cause.kind() == io::ErrorKind::NotFound => {}
            _ => { self.failed = true; return Err(NormalRootStartupErrorV1::Service); }
        }
        self.listener = Some(UnixListener::bind(path));
        if !matches!(self.listener, Some(Ok(_))) {
            self.failed = true;
            return Err(NormalRootStartupErrorV1::Service);
        }
        Ok(())
    }

    /// Borrows one prearmed accepted flight before the native accept operation.
    ///
    /// # Errors
    /// Rejects missing binding or earlier debt. The returned exclusive borrow
    /// prevents a second accepted receiver until this actual flight is disposed.
    pub fn next_flight(
        &mut self,
    ) -> Result<RootPolicyAcceptedFlightV1<'_, 'startup>, NormalRootStartupErrorV1> {
        if self.failed || !matches!(self.listener, Some(Ok(_))) {
            return Err(NormalRootStartupErrorV1::Service);
        }
        if self.flight_permit.is_some() || self.connection_escrow.is_some() {
            self.failed = true;
            return Err(NormalRootStartupErrorV1::Service);
        }
        self.flight_permit = Some(match &self.startup.receiving {
            Some(_) => match self.startup.lock_receiving_v1() {
                Ok(mut original) => {
                    let returned = original.original_mut_v1().begin_policy_flight_once_v1(self.startup);
                    original.finish_returned_v1(returned)
                }
                Err(_) => Err(NormalRootStartupErrorV1::Service),
            },
            None => Err(NormalRootStartupErrorV1::Service),
        });
        if !matches!(self.flight_permit, Some(Ok(()))) {
            self.failed = true;
            return Err(NormalRootStartupErrorV1::Service);
        }
        Ok(RootPolicyAcceptedFlightV1 {
            listener: self, accepted: None, duplicate: None, original: None,
            native: None, controller_peer: None, controller_admission: None,
            purpose_peer: None, purpose_admission: None,
            controller_current_return: None, controller_current_original: None,
            before: None, after: None, dispatch: None, rejected_dispatch: None, finish_order: None,
            shutdown: None, closed: None, attempted: false, transferred: false, finished: false,
            environment_work: None,
            planning_work: None,
            delete_completion_work: None,
            execution_no_apply_work: None,
            stop_cleanup_work: None,
            apply_work: None,
            start_resource_work: None,
            maintenance_storage_work: None,
            finality_recover_work: None,
            start_assignment_inputs_work: None,
        })
    }

    /// Borrows the original first listener failure without observing again.
    #[must_use]
    pub fn failure(&self) -> Option<&(dyn Error + 'static)> {
        if let Some(Err(cause)) = &self.permit { return Some(cause); }
        if let Some(Err(cause)) = &self.metadata {
            if cause.kind() != io::ErrorKind::NotFound { return Some(cause); }
        }
        if let Some(Err(cause)) = &self.removal { return Some(cause); }
        if let Some(Err(cause)) = &self.listener { return Some(cause); }
        if let Some(Err(cause)) = &self.flight_permit { return Some(cause); }
        None
    }
}

/// Retains one same-listener accepted original and independent final debt.
///
/// The actual handler receives only the accepted original. Its same-OFD native
/// duplicate remains here until original shutdown and Root currentness complete.
#[must_use = "retain and finish the whole accepted flight before accepting another"]
pub struct RootPolicyAcceptedFlightV1<'listener, 'startup> {
    listener: &'listener mut RootPolicyListenerReceivingV1<'startup>,
    accepted: Option<io::Result<(UnixStream, std::os::unix::net::SocketAddr)>>,
    duplicate: Option<Result<std::os::fd::OwnedFd, rustix::io::Errno>>,
    original: Option<UnixStream>,
    native: Option<Result<RetainedUnixStream, aos_sandbox_linux::Error>>,
    controller_peer: Option<super::RootControllerPeerReceivingV1<'startup>>,
    controller_admission: Option<Result<(), NormalRootStartupErrorV1>>,
    purpose_peer: Option<RootAcceptedPurposePeerV1<'startup>>,
    purpose_admission: Option<Result<(), NormalRootStartupErrorV1>>,
    environment_work: Option<Box<crate::policy_compiler::environment_root::RootEnvironmentDispatchOriginalV1>>,
    planning_work: Option<Box<crate::policy_compiler::delete_root::RootDeletePlanningDispatchOriginalV1>>,
    delete_completion_work: Option<Box<crate::policy_compiler::delete_root::RootDeleteDispatchOriginalV4>>,
    execution_no_apply_work: Option<Box<crate::policy_compiler::execution_no_apply_root::transport::RootExecutionNoApplyDispatchOriginalV2>>,
    stop_cleanup_work: Option<Box<crate::policy_compiler::stop_cleanup_root::transport::RootStopCleanupDispatchOriginalV1>>,
    apply_work: Option<Box<crate::policy_compiler::storage_apply_root::RootStorageApplyDispatchOriginalV1>>,
    start_resource_work: Option<Box<crate::policy_compiler::host_launch_root::RootStartResourceDispatchOriginalV2>>,
    maintenance_storage_work: Option<Box<crate::policy_compiler::host_launch_root::RootMaintenanceStorageDispatchOriginalV3>>,
    finality_recover_work: Option<Box<crate::policy_compiler::finality_recover_root::RootFinalityRecoverDispatchOriginalV1>>,
    start_assignment_inputs_work: Option<Box<crate::policy_compiler::start_assignment_inputs_root::RootStartAssignmentInputsDispatchOriginalV2>>,
    controller_current_return: Option<Result<(), NormalRootStartupErrorV1>>,
    controller_current_original: Option<Result<super::RootHistoryPeerPostV1, NormalRootStartupErrorV1>>,
    before: Option<Result<(), NormalRootStartupErrorV1>>,
    after: Option<Result<(), NormalRootStartupErrorV1>>,
    dispatch: Option<Result<(), Box<dyn Error>>>,
    rejected_dispatch: Option<Result<(), Box<dyn Error>>>,
    finish_order: Option<Result<(), NormalRootStartupErrorV1>>,
    shutdown: Option<Result<(), rustix::io::Errno>>,
    closed: Option<NormalRootStartupErrorV1>,
    attempted: bool,
    transferred: bool,
    finished: bool,
}

impl<'listener, 'startup> RootPolicyAcceptedFlightV1<'listener, 'startup> {
    /// Accepts and retains the original before any protocol discriminator read.
    ///
    /// # Errors
    /// Retains failed accept, duplicate/adoption and selected currentness. No
    /// second connection, reconnect or second accept is attempted on failure.
    pub fn accept_once(&mut self) -> Result<(), NormalRootStartupErrorV1> {
        let returned = self.accept_inner_once();
        if returned.is_err() && self.after.is_none() {
            // No handler exists on this branch. Keep every acquired owner and
            // complete the same prepaid post before projecting accept failure.
            self.end_original_socket_once();
            self.finish_native_post_once();
            self.listener.failed = true;
        }
        returned
    }

    fn accept_inner_once(&mut self) -> Result<(), NormalRootStartupErrorV1> {
        if self.attempted {
            self.closed.get_or_insert(NormalRootStartupErrorV1::Service);
            self.listener.failed = true;
            self.finished = false;
            return Err(NormalRootStartupErrorV1::Service);
        }
        self.attempted = true;
        let listener = self.listener.listener.as_ref().and_then(|result| result.as_ref().ok())
            .ok_or(NormalRootStartupErrorV1::Service)?;
        self.accepted = Some(listener.accept());
        let accepted = self.accepted.take();
        match accepted {
            Some(Ok((stream, _address))) => { self.original = Some(stream); }
            returned => { self.accepted = returned; return Err(NormalRootStartupErrorV1::Service); }
        }
        self.before = Some(match &self.listener.startup.receiving {
            Some(_) => match self.listener.startup.lock_receiving_v1() {
                Ok(mut original) => {
                    let returned = original.original_mut_v1().observe_policy_flight_before_once_v1(self.listener.startup);
                    original.finish_returned_v1(returned)
                }
                Err(_) => Err(NormalRootStartupErrorV1::Service),
            },
            None => Err(NormalRootStartupErrorV1::Service),
        });
        if !matches!(self.before, Some(Ok(()))) { return Err(NormalRootStartupErrorV1::Service); }
        let original = self.original.as_ref().ok_or(NormalRootStartupErrorV1::Service)?;
        self.duplicate = Some(rustix::io::fcntl_dupfd_cloexec(original, 0));
        let duplicate = self.duplicate.take();
        match duplicate {
            Some(Ok(fd)) => { self.native = Some(RetainedUnixStream::from_owned(fd)); }
            returned => { self.duplicate = returned; return Err(NormalRootStartupErrorV1::Service); }
        }
        if !matches!(self.native, Some(Ok(_))) {
            return Err(NormalRootStartupErrorV1::Service);
        }
        self.listener.connection_escrow = Some(
            connection_escrow::RootPolicyConnectionEscrowV1::claim_before_body_v1(
                self.listener.startup,
            )?,
        );
        self.listener
            .connection_escrow
            .as_mut()
            .ok_or(NormalRootStartupErrorV1::Service)?
            .arm_before_body_once_v2(self.listener.startup)?;
        Ok(())
    }

    /// Moves the same accepted stream into the fixed policy handler once.
    #[must_use]
    pub fn take_dispatch_original_once(&mut self) -> Option<UnixStream> {
        if self.closed.is_some() || self.transferred || !matches!(self.native, Some(Ok(_)))
            || !matches!(self.before, Some(Ok(()))) { return None; }
        self.transferred = true;
        self.original.take()
    }

    pub(crate) fn admit_current_controller_peer_once(&mut self) -> Result<(), NormalRootStartupErrorV1> {
        if self.purpose_peer.is_some() || self.controller_admission.is_some() || self.purpose_admission.is_some()
            || self.closed.is_some() || !self.transferred {
            self.closed.get_or_insert(NormalRootStartupErrorV1::Service);
            return Err(NormalRootStartupErrorV1::Service);
        }
        self.controller_admission = Some(self.admit_current_controller_peer_inner());
        if matches!(self.controller_admission, Some(Ok(()))) { Ok(()) }
        else { Err(NormalRootStartupErrorV1::Service) }
    }

    fn admit_current_controller_peer_inner(&mut self) -> Result<(), NormalRootStartupErrorV1> {
        let startup = self.listener.startup;
        let lifetime = {
            let mut receiving = startup.lock_receiving_v1()?;
            let returned = receiving.original_mut_v1().prepay_current_controller_peer_once(startup);
            receiving.finish_returned_v1(returned)?
        };
        self.controller_peer = Some(super::RootControllerPeerReceivingV1::new(startup, lifetime));
        let peer = self.controller_peer.as_mut().ok_or(NormalRootStartupErrorV1::Service)?;
        let native = self.native.as_ref().and_then(|result| result.as_ref().ok())
            .ok_or(NormalRootStartupErrorV1::Service)?;
        let capture = peer.capture_once(native);
        // The actual Root post runs even after peer capture/decoder failure.
        {
            let mut receiving = startup.lock_receiving_v1()?;
            let returned = receiving.original_mut_v1().post_current_controller_peer_once(startup, capture);
            receiving.finish_returned_v1(returned)?;
        }
        let settlement = peer.settle_positive_once();
        {
            let mut receiving = startup.lock_receiving_v1()?;
            let returned = receiving.original_mut_v1().finish_current_controller_peer_once(settlement);
            receiving.finish_returned_v1(returned)?;
        }
        peer.require_completed()
    }

    pub(crate) fn current_outcome_failure_view_v1(&self,
        stage: crate::policy_compiler::create_storage_current::outcome::OutcomeFinancialStageV1,
    ) -> Option<crate::policy_compiler::RootCurrentFailureViewV1<'_>> {
        let guard = self.listener.startup.lock_receiving_v1().ok()?;
        guard.original_v1().current_outcome_failure_v1(stage)?;
        Some(crate::policy_compiler::RootCurrentFailureViewV1::outcome(guard, stage))
    }

    pub(crate) fn current_signed_controller_failure_view_v1(&self,
        stage: crate::policy_compiler::create_storage_current::signed_bound::SignedControllerFinancialStageV1,
    ) -> Option<crate::policy_compiler::RootCurrentFailureViewV1<'_>> {
        let guard = self.listener.startup.lock_receiving_v1().ok()?;
        guard.original_v1().current_signed_controller_failure_v1(stage)?;
        Some(crate::policy_compiler::RootCurrentFailureViewV1::signed_controller(guard, stage))
    }

    pub(crate) fn current_closed_failure_view_v1(&self,
        stage: crate::policy_compiler::create_storage_current::closed::ClosedFinancialStageV1)
        -> Option<crate::policy_compiler::RootCurrentFailureViewV1<'_>> {
        let guard = self.listener.startup.lock_receiving_v1().ok()?;
        guard.original_v1().current_closed_failure_v1(stage)?;
        Some(crate::policy_compiler::RootCurrentFailureViewV1::closed(guard, stage))
    }

    pub(crate) fn current_signed_failure_view_v1(&self, bytes: bool)
        -> Option<crate::policy_compiler::RootCurrentFailureViewV1<'_>> {
        let guard = self.listener.startup.lock_receiving_v1().ok()?;
        guard.original_v1().current_signed_failure_v1(bytes)?;
        Some(crate::policy_compiler::RootCurrentFailureViewV1::signed(guard, bytes))
    }

    pub(crate) fn arm_history_peer_post_v1(&self) -> Result<super::RootHistoryPeerPostV1, NormalRootStartupErrorV1> {
        let startup = self.current_cut_startup()?;
        let mut receiving = startup.lock_receiving_v1()?;
        let returned = receiving.original_mut_v1().arm_history_peer_post_v1(startup);
        receiving.finish_returned_v1(returned)
    }

    pub(crate) fn observe_history_peer_post_once_v1(&self, post: &mut super::RootHistoryPeerPostV1)
        -> Result<(), NormalRootStartupErrorV1> {
        post.observe_once(self.listener.startup, self.native.as_ref().and_then(|result| result.as_ref().ok()),
            self.controller_peer.as_ref())
    }

    pub(crate) fn recheck_current_controller_peer_once(&mut self) -> Result<(), NormalRootStartupErrorV1> {
        if matches!(self.controller_current_return, Some(Err(_))) || self.closed.is_some() {
            return Err(NormalRootStartupErrorV1::Service);
        }
        self.controller_current_return = Some(self.recheck_current_controller_peer_inner());
        if matches!(self.controller_current_return, Some(Ok(()))) { Ok(()) }
        else { Err(NormalRootStartupErrorV1::Service) }
    }

    fn recheck_current_controller_peer_inner(&mut self) -> Result<(), NormalRootStartupErrorV1> {
        if self.controller_current_original.is_some() { return Err(NormalRootStartupErrorV1::Service); }
        self.controller_current_original = Some(self.arm_history_peer_post_v1());
        let post = self.controller_current_original.as_mut().and_then(|result| result.as_mut().ok())
            .ok_or(NormalRootStartupErrorV1::Service)?;
        post.require_armed_v1()?;
        let result = post.observe_once(self.listener.startup,
            self.native.as_ref().and_then(|result| result.as_ref().ok()), self.controller_peer.as_ref());
        if result.is_ok() && post.is_positive_v1() {
            // The actual whole independent post and native/Ended settlement
            // preceded this disposal. Its monotone traffic debt remains on R.
            drop(self.controller_current_original.take());
        }
        result
    }

    pub(crate) fn enable_current_subject_reporting_once(
        &mut self,
    ) -> Result<(), aos_sandbox_linux::seqpacket::SeqpacketError> {
        self.current_cut_startup().map_err(|_| aos_sandbox_linux::seqpacket::SeqpacketError::Closed)?;
        self.native.as_mut().and_then(|result| result.as_mut().ok())
            .ok_or(aos_sandbox_linux::seqpacket::SeqpacketError::Closed)?
            .enable_subject_reporting()
    }

    pub(crate) fn receive_current_subject_chunk_into(
        &mut self,
        buffer: &mut aos_sandbox_linux::unix_stream::RetainedSubjectStreamReadV1,
        geometry: &aos_sandbox_linux::unix_stream::SubjectStreamReceiveGeometryV1,
    ) -> Result<(), aos_sandbox_linux::unix_stream::SubjectStreamReadErrorV1> {
        use aos_sandbox_linux::unix_stream::SubjectStreamReadErrorV1 as Error;
        self.current_cut_startup().map_err(|_| Error::Order)?;
        let native = self.native.as_mut().and_then(|result| result.as_mut().ok())
            .ok_or(Error::Order)?;
        buffer.receive_next_with_geometry_once(native, geometry)
    }

    pub(crate) fn observe_current_chunk_subject_into(
        &self,
        buffer: &aos_sandbox_linux::unix_stream::RetainedSubjectStreamReadV1,
        sample: &mut super::RootControllerChunkSubjectSampleV1,
    ) -> Result<(), NormalRootStartupErrorV1> {
        let peer = self.controller_peer.as_ref().ok_or(NormalRootStartupErrorV1::Service)?;
        let native = self.current_cut_native()?;
        let chunk = buffer.pending_chunk().map_err(|_| NormalRootStartupErrorV1::Service)?;
        sample.capture_once(peer.native_original_v1(), native, chunk).map_err(Into::into)
    }

    pub(crate) fn current_root_open_identity(&self) -> Result<RootCurrentOpenIdentityDataV1, NormalRootStartupErrorV1> {
        let startup = self.current_cut_startup()?;
        startup.recheck()?;
        let (recipient, producer) = {
            let receiving = startup.lock_receiving_v1()?;
            let returned = receiving.original_v1().current_root_open_original_pair();
            receiving.finish_returned_v1(returned)?
        };
        let peer = self.current_cut_native()?.peer().credentials();
        Ok(RootCurrentOpenIdentityDataV1 {
            profile: startup.native.fields().profile_file.measured_digest_v1(),
            recipient,
            producer,
            root_pid: std::process::id(),
            controller_pid: peer.pid().get(),
            controller_uid: startup.native.fields().profile.identities[0],
            controller_gid: startup.native.fields().profile.identities[1],
        })
    }

    pub(crate) fn current_cut_native(&self) -> Result<&RetainedUnixStream, NormalRootStartupErrorV1> {
        if self.closed.is_some() || !self.transferred { return Err(NormalRootStartupErrorV1::Service); }
        self.native.as_ref().and_then(|result| result.as_ref().ok())
            .ok_or(NormalRootStartupErrorV1::Service)
    }

    pub(crate) fn current_cut_startup(&self) -> Result<&'startup ProductionNormalRootStartupV1, NormalRootStartupErrorV1> {
        self.controller_peer.as_ref().ok_or(NormalRootStartupErrorV1::Service)?.require_completed()?;
        if !matches!(self.controller_admission, Some(Ok(()))) { return Err(NormalRootStartupErrorV1::Service); }
        Ok(self.listener.startup)
    }

    /// Parks the whole handler return, ends its same socket and posts Root.
    ///
    /// Positive disposition also requires the actual Root6 token and same held
    /// writer pair parked by the consuming terminal producer. Only after socket
    /// End, the independent Root post and real upper disposal does the shared
    /// transient operation complete. The permanent pair and debt remain held;
    /// a handler Result alone supplies no authority, disposal or lifetime refund.
    ///
    /// # Errors
    /// Retains any original handler, native shutdown or selected Root failure.
    pub fn finish_dispatch_once(&mut self, returned: Result<(), Box<dyn Error>>) -> Result<(), NormalRootStartupErrorV1> {
        self.finish_dispatch_inner_v1(returned, serving::ServingDispatchV1::Initial)
    }

    pub(crate) fn finish_environment_dispatch_once_v1(&mut self,
        work: crate::policy_compiler::environment_root::RootEnvironmentDispatchOriginalV1,
    ) -> Result<(), NormalRootStartupErrorV1> {
        if self.environment_work.is_some() { std::process::abort(); }
        // Park the whole native offer before any fallible projection. A failed
        // last Root post cannot unwind successful-looking earlier IO owners.
        self.environment_work = Some(Box::new(work));
        let returned = (|| {
            let native = self.native.as_ref().and_then(|result| result.as_ref().ok())
                .ok_or(NormalRootStartupErrorV1::Service)?;
            self.environment_work.as_ref().ok_or(NormalRootStartupErrorV1::Service)?
                .require_same_complete_v1(native)
        })().map_err(|cause| Box::new(cause) as Box<dyn Error>);
        self.finish_dispatch_inner_v1(returned, serving::ServingDispatchV1::Environment)
    }

    /// Borrows the parked Planning flight's first failure, including guarded native causes.
    ///
    /// The rendered view keeps each worker archive locked while formatting;
    /// no borrowed native error escapes its guard.
    pub fn delete_planning_failure_view_v1(&self) -> Option<impl std::fmt::Display + '_> {
        self.planning_work.as_ref()?;
        Some(RootDeletePlanningFailureViewV1(self))
    }

    pub(crate) fn finish_delete_planning_dispatch_once_v1(&mut self,
        work: crate::policy_compiler::delete_root::RootDeletePlanningDispatchOriginalV1,
    ) -> Result<(), NormalRootStartupErrorV1> {
        if self.planning_work.is_some() { std::process::abort(); }
        // Keep the whole offered owner through every fallible projection and
        // independent final post, including an unsuccessful offered owner.
        self.planning_work = Some(Box::new(work));
        let returned = (|| {
            let native = self.native.as_ref().and_then(|result| result.as_ref().ok())
                .ok_or(NormalRootStartupErrorV1::Service)?;
            self.planning_work.as_ref().ok_or(NormalRootStartupErrorV1::Service)?
                .require_same_complete_v1(native)
        })().map_err(|cause| Box::new(cause) as Box<dyn Error>);
        self.finish_dispatch_inner_v1(returned, serving::ServingDispatchV1::DeletePlanning)
    }

    pub(crate) fn finish_delete_completion_dispatch_once_v4(
        &mut self,
        work: crate::policy_compiler::delete_root::RootDeleteDispatchOriginalV4,
    ) -> Result<(), NormalRootStartupErrorV1> {
        if self.delete_completion_work.is_some() {
            std::process::abort();
        }
        self.delete_completion_work = Some(Box::new(work));
        let returned = (|| {
            let native = self
                .native
                .as_ref()
                .and_then(|result| result.as_ref().ok())
                .ok_or(NormalRootStartupErrorV1::Service)?;
            self.delete_completion_work
                .as_ref()
                .ok_or(NormalRootStartupErrorV1::Service)?
                .require_same_complete_v4(native)
        })()
        .map_err(|cause| Box::new(cause) as Box<dyn Error>);
        self.finish_dispatch_inner_v1(returned, serving::ServingDispatchV1::DeleteCompletion)
    }

    pub(crate) fn finish_execution_no_apply_dispatch_once_v2(
        &mut self,
        work: crate::policy_compiler::execution_no_apply_root::transport::RootExecutionNoApplyDispatchOriginalV2,
    ) -> Result<(), NormalRootStartupErrorV1> {
        if self.execution_no_apply_work.is_some() { std::process::abort(); }
        self.execution_no_apply_work = Some(Box::new(work));
        let returned = (|| {
            let native = self.native.as_ref().and_then(|result| result.as_ref().ok())
                .ok_or(NormalRootStartupErrorV1::Service)?;
            self.execution_no_apply_work.as_ref().ok_or(NormalRootStartupErrorV1::Service)?
                .require_same_complete_v2(native)
        })().map_err(|cause| Box::new(cause) as Box<dyn Error>);
        self.finish_dispatch_inner_v1(returned, serving::ServingDispatchV1::ExecutionNoApply)
    }

    pub(crate) fn finish_stop_cleanup_dispatch_once_v1(
        &mut self,
        work: crate::policy_compiler::stop_cleanup_root::transport::RootStopCleanupDispatchOriginalV1,
    ) -> Result<(), NormalRootStartupErrorV1> {
        if self.stop_cleanup_work.is_some() { std::process::abort(); }
        self.stop_cleanup_work = Some(Box::new(work));
        let returned = (|| {
            let native = self.native.as_ref().and_then(|result| result.as_ref().ok())
                .ok_or(NormalRootStartupErrorV1::Service)?;
            self.stop_cleanup_work.as_ref().ok_or(NormalRootStartupErrorV1::Service)?
                .require_same_complete_v1(native)
        })().map_err(|cause| Box::new(cause) as Box<dyn Error>);
        self.finish_dispatch_inner_v1(returned, serving::ServingDispatchV1::StopCleanup)
    }

    pub(crate) fn finish_storage_apply_dispatch_once_v1(&mut self,
        work: crate::policy_compiler::storage_apply_root::RootStorageApplyDispatchOriginalV1,
    ) -> Result<(), NormalRootStartupErrorV1> {
        if self.apply_work.is_some() { std::process::abort(); }
        // Keep the whole offered owner through every fallible projection and
        // independent final post, including an unsuccessful offered owner.
        self.apply_work = Some(Box::new(work));
        let returned = (|| {
            let native = self.native.as_ref().and_then(|result| result.as_ref().ok())
                .ok_or(NormalRootStartupErrorV1::Service)?;
            self.apply_work.as_ref().ok_or(NormalRootStartupErrorV1::Service)?
                .require_same_complete_v1(native)
        })().map_err(|cause| Box::new(cause) as Box<dyn Error>);
        self.finish_dispatch_inner_v1(returned, serving::ServingDispatchV1::StorageApply)
    }

    pub(crate) fn finish_start_resource_dispatch_once_v2(&mut self,
        work: crate::policy_compiler::host_launch_root::RootStartResourceDispatchOriginalV2,
    ) -> Result<(), NormalRootStartupErrorV1> {
        if self.start_resource_work.is_some() { std::process::abort(); }
        // Keep the whole offered owner through every fallible projection and
        // independent final post, including an unsuccessful offered owner.
        self.start_resource_work = Some(Box::new(work));
        let returned = (|| {
            let native = self.native.as_ref().and_then(|result| result.as_ref().ok())
                .ok_or(NormalRootStartupErrorV1::Service)?;
            self.start_resource_work.as_ref().ok_or(NormalRootStartupErrorV1::Service)?
                .require_same_complete_v2(native)
        })().map_err(|cause| Box::new(cause) as Box<dyn Error>);
        self.finish_dispatch_inner_v1(returned, serving::ServingDispatchV1::StartResource)
    }

    pub(crate) fn finish_maintenance_storage_dispatch_once_v3(&mut self,
        work: crate::policy_compiler::host_launch_root::RootMaintenanceStorageDispatchOriginalV3,
    ) -> Result<(), NormalRootStartupErrorV1> {
        if self.maintenance_storage_work.is_some() { std::process::abort(); }
        // Keep the whole offered owner through every fallible projection and
        // independent final post, including an unsuccessful offered owner.
        self.maintenance_storage_work = Some(Box::new(work));
        let returned = (|| {
            let native = self.native.as_ref().and_then(|result| result.as_ref().ok())
                .ok_or(NormalRootStartupErrorV1::Service)?;
            self.maintenance_storage_work.as_ref().ok_or(NormalRootStartupErrorV1::Service)?
                .require_same_complete_v3(native)
        })().map_err(|cause| Box::new(cause) as Box<dyn Error>);
        self.finish_dispatch_inner_v1(returned, serving::ServingDispatchV1::MaintenanceStorage)
    }

    pub(crate) fn finish_finality_recover_dispatch_once_v1(&mut self,
        work: crate::policy_compiler::finality_recover_root::RootFinalityRecoverDispatchOriginalV1,
    ) -> Result<(), NormalRootStartupErrorV1> {
        if self.finality_recover_work.is_some() { std::process::abort(); }
        // Park the complete native offer before any fallible final projection.
        self.finality_recover_work = Some(Box::new(work));
        let returned = (|| {
            let native = self.native.as_ref().and_then(|result| result.as_ref().ok())
                .ok_or(NormalRootStartupErrorV1::Service)?;
            self.finality_recover_work.as_ref().ok_or(NormalRootStartupErrorV1::Service)?
                .require_same_complete_v1(native)
        })().map_err(|cause| Box::new(cause) as Box<dyn Error>);
        self.finish_dispatch_inner_v1(returned, serving::ServingDispatchV1::FinalityRecover)
    }

    pub(crate) fn finish_start_assignment_inputs_dispatch_once_v2(&mut self,
        work: crate::policy_compiler::start_assignment_inputs_root::RootStartAssignmentInputsDispatchOriginalV2,
    ) -> Result<(), NormalRootStartupErrorV1> {
        if self.start_assignment_inputs_work.is_some() { std::process::abort(); }
        // Park the complete native offer before any fallible final projection.
        self.start_assignment_inputs_work = Some(Box::new(work));
        let returned = (|| {
            let native = self.native.as_ref().and_then(|result| result.as_ref().ok())
                .ok_or(NormalRootStartupErrorV1::Service)?;
            self.start_assignment_inputs_work.as_ref().ok_or(NormalRootStartupErrorV1::Service)?
                .require_same_complete_v1(native)
        })().map_err(|cause| Box::new(cause) as Box<dyn Error>);
        self.finish_dispatch_inner_v1(returned, serving::ServingDispatchV1::StartAssignmentInputs)
    }

    fn finish_dispatch_inner_v1(
        &mut self,
        returned: Result<(), Box<dyn Error>>,
        kind: serving::ServingDispatchV1,
    ) -> Result<(), NormalRootStartupErrorV1> {
        let invalid = self.closed.is_some() || self.dispatch.is_some() || !self.transferred;
        if self.finish_order.is_none() {
            self.finish_order = Some(if invalid { Err(NormalRootStartupErrorV1::Service) } else { Ok(()) });
        }
        if self.dispatch.is_none() {
            self.dispatch = Some(returned);
        } else if self.rejected_dispatch.is_none() {
            self.rejected_dispatch = Some(returned);
        } else {
            // No unbounded rejected-offer list or implicit dropping of a new
            // whole error. The offered owner remains on this stack at death.
            std::process::abort();
        }
        if invalid {
            self.closed.get_or_insert(NormalRootStartupErrorV1::Service);
        }
        // An invalid handler disposition cannot cancel the already armed post.
        // Keep its offered result and every native owner through that post.
        if !matches!(kind, serving::ServingDispatchV1::DeleteCompletion | serving::ServingDispatchV1::ExecutionNoApply | serving::ServingDispatchV1::StopCleanup) {
            self.end_original_socket_once();
        }
        self.finish_native_post_once();
        self.finished = !invalid
            && matches!(self.dispatch, Some(Ok(())))
            && self.socket_disposition_matches_v1(kind)
            && matches!(self.after, Some(Ok(())));
        if self.finished {
            self.complete_serving_dispatch_v1(kind)
        } else {
            self.listener.failed = true;
            Err(NormalRootStartupErrorV1::Service)
        }
    }

    fn socket_disposition_matches_v1(&self, kind: serving::ServingDispatchV1) -> bool {
        match kind {
            serving::ServingDispatchV1::DeleteCompletion | serving::ServingDispatchV1::ExecutionNoApply | serving::ServingDispatchV1::StopCleanup => self.shutdown.is_none(),
            _ => matches!(self.shutdown, Some(Ok(()))),
        }
    }

    fn end_original_socket_once(&mut self) {
        if self.shutdown.is_some() { return; }
        if let Some(Ok(native)) = &self.native {
            self.shutdown = Some(rustix::net::shutdown(native.as_fd(), rustix::net::Shutdown::Both));
        } else if let Some(original) = &self.original {
            self.shutdown = Some(rustix::net::shutdown(original, rustix::net::Shutdown::Both));
        }
    }

    fn finish_native_post_once(&mut self) {
        if self.after.is_some() { return; }
        self.after = Some(match &self.listener.startup.receiving {
            Some(_) => match self.listener.startup.lock_receiving_v1() {
                Ok(mut original) => {
                    let returned = original.original_mut_v1().finish_policy_flight_native_once_v1(self.listener.startup);
                    original.finish_returned_v1(returned)
                }
                Err(_) => Err(NormalRootStartupErrorV1::Service),
            },
            None => Err(NormalRootStartupErrorV1::Service),
        });
    }

    /// Borrows the original first returned failure without another operation.
    #[must_use]
    pub fn failure(&self) -> Option<&(dyn Error + 'static)> {
        if let Some(Err(cause)) = &self.accepted { return Some(cause); }
        if let Some(Err(cause)) = &self.before { return Some(cause); }
        if let Some(Err(cause)) = &self.duplicate { return Some(cause); }
        if let Some(Err(cause)) = &self.native { return Some(cause); }
        if let Some(peer) = &self.controller_peer {
            if let Some(cause) = peer.failure() { return Some(cause); }
        }
        if let Some(Err(cause)) = &self.controller_admission { return Some(cause); }
        if let Some(peer) = &self.purpose_peer {
            if let Some(cause) = peer.primary_failure_v1() { return Some(cause); }
        }
        if let Some(Err(cause)) = &self.purpose_admission { return Some(cause); }
        // The concrete body latches its cause before it enters independent
        // final peer posts. Those later originals remain inspectable below.
        if let Some(work) = &self.environment_work {
            if let Some(cause) = work.failure() { return Some(cause); }
        }
        if let Some(work) = &self.apply_work {
            if let Some(cause) = work.failure() { return Some(cause); }
        }
        if let Some(work) = &self.start_resource_work {
            if let Some(cause) = work.failure() { return Some(cause); }
        }
        if let Some(work) = &self.maintenance_storage_work {
            if let Some(cause) = work.failure() { return Some(cause); }
        }
        if let Some(work) = &self.finality_recover_work {
            if let Some(cause) = work.failure() { return Some(cause); }
        }
        if let Some(work) = &self.start_assignment_inputs_work {
            if let Some(cause) = work.failure() { return Some(cause); }
        }
        if let Some(work) = &self.planning_work {
            if let Some(cause) = work.failure() { return Some(cause); }
        }
        if let Some(work) = &self.execution_no_apply_work {
            if let Some(cause) = work.failure() { return Some(cause); }
        }

        if let Some(work) = &self.stop_cleanup_work {
            if let Some(cause) = work.failure() { return Some(cause); }
        }
        if let Some(work) = &self.delete_completion_work {
            if let Some(cause) = work.failure() {
                return Some(cause);
            }
        }
        if let Some(peer) = &self.purpose_peer {
            if let Some(cause) = peer.failure() { return Some(cause); }
        }
        if let Some(original) = &self.controller_current_original {
            match original {
                Ok(original) => if let Some(cause) = original.failure() { return Some(cause); },
                Err(cause) => return Some(cause),
            }
        }
        if let Some(Err(cause)) = &self.controller_current_return { return Some(cause); }
        if let Some(Err(cause)) = &self.finish_order { return Some(cause); }
        if let Some(Err(cause)) = &self.dispatch { return Some(cause.as_ref()); }
        if let Some(Err(cause)) = &self.shutdown { return Some(cause); }
        if let Some(Err(cause)) = &self.after { return Some(cause); }
        if let Some(cause) = self
            .listener
            .connection_escrow
            .as_ref()
            .and_then(|escrow| escrow.failure())
        {
            return Some(cause);
        }
        if let Some(cause) = &self.closed { return Some(cause); }
        if let Some(Err(cause)) = &self.rejected_dispatch { return Some(cause.as_ref()); }
        None
    }
}

impl Drop for RootPolicyAcceptedFlightV1<'_, '_> {
    fn drop(&mut self) {
        if self.listener.resource_receiving && self.attempted && !self.finished {
            // A failed or unwinding R flight cannot release custody then admit
            // another request. The original listener remains borrowed at death.
            std::process::abort();
        }
    }
}

struct RootDeletePlanningFailureViewV1<'owner, 'listener, 'startup>(
    &'owner RootPolicyAcceptedFlightV1<'listener, 'startup>,
);

impl std::fmt::Display for RootDeletePlanningFailureViewV1<'_, '_, '_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self.0.planning_work.as_ref() {
            Some(work) if work.failure().is_some() => work.format_failure_v1(self.0, f),
            _ => match self.0.failure() {
                Some(cause) => std::fmt::Display::fmt(cause, f),
                None => f.write_str("Delete planning flight failure is unavailable"),
            },
        }
    }
}
