//! Retains one authenticated Host root-export ingress and all owed bookends.
//!
//! The fixed original is constructed only after the same Storage F pays its
//! header, native preview and saved catalog representation. Preview bytes choose
//! a decoder bound; they never establish Host or canary authority. The complete
//! original authenticated launch and fresh physical catalog remain mandatory.

use super::*;

mod receiving;
pub(super) use receiving::RootExportRepresentationV2;
use std::error::Error;
use aos_sandbox_broker::{
    BrokerAdmissionError, StorageHostLaunchExportInspectionErrorV2,
    VerifiedStorageHostLaunchExportV2,
};
use aos_sandbox_broker::kernel_clock::{
    KernelPairedClockErrorV1, RetainedKernelPairedClockAttemptV1,
};
use aos_sandbox_linux::cgroup::{CgroupV2Root, ControllerStartupHostCgroupReadbackV1};
use aos_sandbox_linux::inventory::MountId;
use aos_sandbox_linux::pidfd::PidFdInfo;
use aos_sandbox_linux::seqpacket::{
    RecordBindingError, RecordSubjectListener, RetainedSeqpacketAdmissionErrorV1,
    RetainedSeqpacketReceiveErrorV1, SeqpacketError,
};
use aos_sandbox_linux::seqpacket::descriptor_subject::{DescriptorSubjectSocket, ReceivedDescriptorRecord};
use aos_sandbox_protocol::storage_root_export::{
    StorageRootExportProtocolErrorV1, StorageRootExportResponseV1,
};
use aos_sandbox_protocol::storage_root_export::launch::StorageRootLaunchExportRequestV2;
use crate::peer::{
    HostRootExportPeerVerifier, RootServiceConnectionOriginalV2,
    RootServicePeerError, RootServiceRecordOriginalV2,
};

#[derive(Debug, thiserror::Error)]
enum RootExportClockErrorV2 {
    #[error("original root-export clock changed or expired")]
    Stale,
    #[error(transparent)]
    Linux(aos_sandbox_linux::Error),
}

impl KernelPairedClockErrorV1 for RootExportClockErrorV2 {
    fn stale() -> Self { Self::Stale }
    fn kernel(cause: aos_sandbox_linux::Error) -> Self { Self::Linux(cause) }
}

type Pair = RetainedKernelPairedClockAttemptV1<RootExportClockErrorV2>;
type Receiving<'a, 'b> = aos_sandbox_controller_domain::StorageRootLaunchExportReceivingLoanV2<'a, 'b>;

#[derive(Clone, Copy)]
enum Failure {
    Host, Listener, Accept, AcceptedPeer, Clock(usize), Wait,
    Model, Receive, Binding, RecordPeer, Frame, Trust, Original,
    BeforePeer, Body, MountStat, MountId, Response, BeforeSendPeer,
    Current(usize), Send, Gate,
}

/// Owns the same native ingress, original frame, returned mount and first cause.
///
/// An unsuccessful instance must remain on the actual Runtime through process
/// exit. A successful instance disposes only after the same native/profile posts
/// and successful descriptor transfer. No method returns a caller-adoptable FD.
pub(super) struct RootExportOriginalV2 {
    host: ControllerStartupHostCgroupReadbackV1,
    host_result: Option<aos_sandbox_linux::Result<()>>,
    host_pair: Option<(CgroupV2Root, HostRootExportPeerVerifier)>,
    host_pair_error: Option<crate::service::StorageServiceError>,
    listener: Option<Result<(), SeqpacketError>>,
    socket: Option<Result<DescriptorSubjectSocket, RetainedSeqpacketAdmissionErrorV1>>,
    accepted_peer: RootServiceConnectionOriginalV2,
    accepted: Option<Result<PidFdInfo, RootServicePeerError>>,
    clocks: [Pair; 4],
    clock_values: [Option<Result<RawPairedClockSample, RootExportClockErrorV2>>; 4],
    wait: Option<Result<(), aos_sandbox_linux::seqpacket::bounded::BoundedRecordError>>,
    model: Option<Result<(), aos_sandbox_controller_domain::StorageReceivingClosedV1>>,
    record: Option<Result<ReceivedDescriptorRecord, RetainedSeqpacketReceiveErrorV1>>,
    binding: Option<Result<(), RecordBindingError>>,
    record_peer: RootServiceRecordOriginalV2,
    record_result: Option<Result<(), RootServicePeerError>>,
    frame_result: Option<Result<(), StorageRootExportProtocolErrorV1>>,
    verified: Option<Result<VerifiedStorageHostLaunchExportV2, StorageHostLaunchExportInspectionErrorV2>>,
    original: Option<Result<(), aos_sandbox_controller_domain::StorageReceivingClosedV1>>,
    peers: [RootServiceConnectionOriginalV2; 3],
    peer_results: [Option<Result<PidFdInfo, RootServicePeerError>>; 3],
    current: [Option<Result<(), BrokerAdmissionError>>; 3],
    body: root_mount_export::RootMountExportOriginalV2,
    body_result: Option<Result<(), StorageRuntimeError>>,
    mount_stat: Option<rustix::io::Result<rustix::fs::Stat>>,
    mount_id: Option<aos_sandbox_linux::Result<MountId>>,
    response: Option<Result<[u8; aos_sandbox_protocol::storage_root_export::STORAGE_ROOT_EXPORT_RESPONSE_BYTES_V1], StorageRootExportProtocolErrorV1>>,
    send: Option<Result<(), SeqpacketError>>,
    socket_post: Option<Result<(), SeqpacketError>>,
    subject_post: crate::peer::RootServiceSubjectPostOriginalV2,
    subject_post_result: Option<Result<(), RootServicePeerError>>,
    listener_post: Option<Result<(), SeqpacketError>>,
    mount_stat_post: Option<rustix::io::Result<rustix::fs::Stat>>,
    mount_id_post: Option<aos_sandbox_linux::Result<MountId>>,
    mount_comparison_post: Option<Result<(), StorageRuntimeError>>,
    native_post: Option<Result<(), aos_sandbox_controller_domain::StorageReceivingClosedV1>>,
    posts: Option<Result<(), StorageRuntimeError>>,
    gate: Option<StorageRuntimeError>,
    first: Option<Failure>,
    entered: bool,
    completed: bool,
}

impl RootExportOriginalV2 {
    pub(super) fn new() -> Self {
        Self {
            host: ControllerStartupHostCgroupReadbackV1::new(), host_result: None,
            host_pair: None, host_pair_error: None, listener: None, socket: None,
            accepted_peer: RootServiceConnectionOriginalV2::new(), accepted: None,
            clocks: std::array::from_fn(|_| Pair::default()),
            clock_values: std::array::from_fn(|_| None), wait: None, model: None,
            record: None, binding: None, record_peer: RootServiceRecordOriginalV2::new(),
            record_result: None, frame_result: None, verified: None, original: None,
            peers: std::array::from_fn(|_| RootServiceConnectionOriginalV2::new()),
            peer_results: std::array::from_fn(|_| None),
            current: std::array::from_fn(|_| None),
            body: root_mount_export::RootMountExportOriginalV2::default(), body_result: None,
            mount_stat: None, mount_id: None, response: None, send: None,
            socket_post: None, subject_post: crate::peer::RootServiceSubjectPostOriginalV2::new(),
            subject_post_result: None, listener_post: None, mount_stat_post: None,
            mount_id_post: None, mount_comparison_post: None, native_post: None, posts: None,
            gate: None, first: None, entered: false, completed: false,
        }
    }

    fn fail<T>(&mut self, site: Failure) -> Result<T, StorageRuntimeError> {
        self.first.get_or_insert(site);
        if matches!(site, Failure::Gate) {
            self.gate.get_or_insert(StorageRuntimeError::Recovery);
        }
        Err(StorageRuntimeError::Receiving)
    }

    fn clock_once(&mut self, index: usize) -> Result<RawPairedClockSample, StorageRuntimeError> {
        let original = self.clock_values[0].as_ref().and_then(|result| result.as_ref().ok()).copied();
        self.clock_values[index] = Some(self.clocks[index].observe_once(original));
        match self.clock_values[index].as_ref() {
            Some(Ok(sample)) => Ok(*sample),
            _ => self.fail(Failure::Clock(index)),
        }
    }

    // This selected-only adapter starts after the actual Storage lender prepays
    // the complete fixed/native header. Shared canary ingress will drive this
    // same prefix; its separate public/job/history stages cannot use launch's
    // parsed-body bound or infer a grant from eight preview bytes.
    pub(super) fn observe_launch_once(
        &mut self,
        runtime: &mut StorageBrokerRuntime,
        listener: &mut RecordSubjectListener,
        template: &ProtectedGuestRootTemplateV1,
        receiving: &mut Receiving<'_, '_>,
    ) -> Result<(), StorageRuntimeError> {
        if self.entered { return self.fail(Failure::Gate); }
        self.entered = true;
        let primary = self.launch_body(runtime, listener, template, receiving);
        // Do not interpret the body until all independently owed observations
        // have run, including after native transport/profile uncertainty.
        self.finish_posts(listener, receiving);
        primary?;
        if !matches!(self.posts, Some(Ok(()))) {
            return Err(StorageRuntimeError::Receiving);
        }
        Ok(())
    }

    fn launch_body(
        &mut self,
        runtime: &mut StorageBrokerRuntime,
        listener: &mut RecordSubjectListener,
        template: &ProtectedGuestRootTemplateV1,
        receiving: &mut Receiving<'_, '_>,
    ) -> Result<(), StorageRuntimeError> {
        self.host_result = Some(self.host.capture_once());
        if !matches!(self.host_result, Some(Ok(()))) { return self.fail(Failure::Host); }
        self.host_pair = Some(match HostRootExportPeerVerifier::take_fixed_capture_v2(&mut self.host) {
            Ok(pair) => pair,
            Err(cause) => {
                self.host_pair_error = Some(cause);
                return self.fail(Failure::Host);
            }
        });
        self.listener = Some(listener.validate_current());
        if !matches!(self.listener, Some(Ok(()))) { return self.fail(Failure::Listener); }
        self.socket = Some(listener.accept_storage_root_export_retaining_v2());
        if !matches!(self.socket, Some(Ok(_))) { return self.fail(Failure::Accept); }
        {
            let Some((_, verifier)) = self.host_pair.as_ref() else { return self.fail(Failure::Gate); };
            let Some(Ok(socket)) = self.socket.as_ref() else { return self.fail(Failure::Gate); };
            self.accepted = Some(verifier.verify_connection_retaining_v2(socket.peer(), &mut self.accepted_peer));
        }
        let execution = match &self.accepted {
            Some(Ok(execution)) => *execution,
            _ => return self.fail(Failure::AcceptedPeer),
        };
        let sample = self.clock_once(0)?;
        let Some(deadline) = sample.boottime_nanoseconds().checked_add(5_000_000_000)
        else { return self.fail(Failure::Gate); };
        // This polls through the same bounded native wait engine. A successful
        // primitive poll carries no remaining external obligation; a refusal
        // remains in its actual typed slot and stops this original attempt.
        let socket = self.socket.as_mut().and_then(|result| result.as_mut().ok())
            .ok_or(StorageRuntimeError::Receiving)?;
        self.wait = Some(aos_sandbox_linux::seqpacket::bounded::wait_storage_root_export_request_v2(socket, deadline));
        if !matches!(self.wait, Some(Ok(()))) { return self.fail(Failure::Wait); }
        let preview = match socket.preview_storage_root_export_request_retaining_v2(
            aos_sandbox_protocol::storage_root_export::launch::STORAGE_ROOT_LAUNCH_EXPORT_MAXIMUM_BYTES_V2,
        ) {
            Ok(preview) => preview,
            Err(cause) => {
                self.record = Some(Err(cause));
                // The preview result still borrows the socket here. Record the
                // same first failure through its disjoint destination.
                self.first.get_or_insert(Failure::Receive);
                return Err(StorageRuntimeError::Receiving);
            }
        };
        if preview.previewed_prefix_v2() != b"AOSRME02" {
            self.record = Some(Err(preview.refuse_preparation_once_v2()));
            return self.fail(Failure::Gate);
        }
        self.model = Some(receiving.require_launch_model_receiving_v2(
            runtime.coordinator.root_export_authority_v2(), preview.previewed_extent_v2(),
        ));
        if !matches!(self.model, Some(Ok(()))) {
            self.record = Some(Err(preview.refuse_preparation_once_v2()));
            return self.fail(Failure::Model);
        }
        self.record = Some(preview.consume_once_v2());
        if !matches!(self.record, Some(Ok(_))) { return self.fail(Failure::Receive); }
        let Some(Ok(record)) = self.record.as_ref() else { return self.fail(Failure::Gate); };
        let socket = self.socket.as_mut().and_then(|result| result.as_mut().ok())
            .ok_or(StorageRuntimeError::Receiving)?;
        self.binding = Some(socket.validate_received_origin_retaining(record));
        if !matches!(self.binding, Some(Ok(()))) { return self.fail(Failure::Binding); }
        let Some((_, verifier)) = self.host_pair.as_ref() else { return self.fail(Failure::Gate); };
        self.record_result = Some(verifier.verify_record_retaining_v2(
            execution, socket.peer(), record.subject(), &mut self.record_peer,
        ));
        if !matches!(self.record_result, Some(Ok(()))) { return self.fail(Failure::RecordPeer); }
        if !record.descriptors().is_empty() { return self.fail(Failure::Gate); }
        let (request, digest) = match StorageRootLaunchExportRequestV2::decode(record.payload()) {
            Ok(frame) => {
                self.frame_result = Some(Ok(()));
                self.verified = Some(runtime.coordinator.root_export_authority_v2()
                    .inspect_storage_host_launch_export_v2(&frame, &sample));
                (*frame.request(), frame.digest())
            }
            Err(cause) => {
                self.frame_result = Some(Err(cause));
                return self.fail(Failure::Frame);
            }
        };
        let Some(Ok(verified)) = self.verified.as_ref() else { return self.fail(Failure::Trust); };
        self.original = Some(receiving.bind_verified_original_once_v2(verified));
        if !matches!(self.original, Some(Ok(()))) { return self.fail(Failure::Original); }
        let proof = request.proof;
        let cutoff = verified.original_cutoff_v2();
        let current_publication = verified.current_guest_root_publication_v2().copied();
        self.peer_once(0)?;
        let before = self.clock_once(1)?;
        self.require_current(0, &before)?;
        self.body_result = Some(self.body.observe_receiving_v2(runtime, proof, template, cutoff, receiving, current_publication));
        if !matches!(self.body_result, Some(Ok(()))) { return self.fail(Failure::Body); }
        let Some(mount) = self.body.mount_v2() else { return self.fail(Failure::Gate); };
        self.mount_stat = Some(rustix::fs::fstat(mount));
        self.mount_id = Some(MountId::from_fd(mount.as_fd()));
        let (Some(Ok(stat)), Some(Ok(mount_id))) = (&self.mount_stat, &self.mount_id) else {
            return self.fail(if self.mount_stat.as_ref().is_some_and(Result::is_err) {
                Failure::MountStat
            } else { Failure::MountId });
        };
        let response = StorageRootExportResponseV1 {
            nonce: request.nonce, request_digest: digest,
            root_device: stat.st_dev, root_inode: stat.st_ino, detached_mount_id: mount_id.get(),
        };
        self.response = Some(response.encode());
        if !matches!(self.response, Some(Ok(_))) { return self.fail(Failure::Response); }
        self.peer_once(1)?;
        let before_send = self.clock_once(2)?;
        self.require_current(1, &before_send)?;
        let Some(mount) = self.body.mount_v2() else { return self.fail(Failure::Gate); };
        let socket = self.socket.as_mut().and_then(|result| result.as_mut().ok())
            .ok_or(StorageRuntimeError::Receiving)?;
        let Some(Ok(bytes)) = self.response.as_ref() else { return self.fail(Failure::Gate); };
        self.send = Some(socket.send_with_descriptors_retaining(bytes, &[mount.as_fd()]));
        if !matches!(self.send, Some(Ok(()))) { return self.fail(Failure::Send); }
        Ok(())
    }

    fn peer_once(&mut self, index: usize) -> Result<(), StorageRuntimeError> {
        let Some((_, verifier)) = self.host_pair.as_ref() else { return self.fail(Failure::Gate); };
        let Some(Ok(socket)) = self.socket.as_ref() else { return self.fail(Failure::Gate); };
        self.peer_results[index] = Some(verifier.verify_connection_retaining_v2(socket.peer(), &mut self.peers[index]));
        let expected = self.accepted.as_ref().and_then(|result| result.as_ref().ok());
        match (&self.peer_results[index], expected) {
            (Some(Ok(current)), Some(expected)) if current == expected => Ok(()),
            _ => self.fail(if index == 0 { Failure::BeforePeer } else { Failure::BeforeSendPeer }),
        }
    }

    fn require_current(&mut self, index: usize, sample: &RawPairedClockSample)
        -> Result<(), StorageRuntimeError>
    {
        let Some(Ok(verified)) = self.verified.as_ref() else { return self.fail(Failure::Gate); };
        self.current[index] = Some(verified.require_current_sample_v2(sample));
        if matches!(self.current[index], Some(Ok(()))) { Ok(()) }
        else { self.fail(Failure::Current(index)) }
    }

    fn finish_posts(&mut self, listener: &RecordSubjectListener, receiving: &mut Receiving<'_, '_>) {
        self.listener_post = Some(listener.validate_current());
        if let Some(Ok(socket)) = self.socket.as_ref() {
            self.socket_post = Some(socket.observe_owed_local_filesystem_path_v2(
                std::path::Path::new("/run/aos/sandbox-storage/root-export.sock"),
            ));
            if let Some((_, verifier)) = self.host_pair.as_ref() {
                self.peer_results[2] = Some(verifier.verify_connection_retaining_v2(socket.peer(), &mut self.peers[2]));
                if let (Some(Ok(record)), Some(Ok(execution))) = (&self.record, &self.accepted) {
                    self.subject_post_result = Some(verifier.observe_record_subject_owed_v2(
                        *execution, record.subject(), &mut self.subject_post,
                    ));
                }
            }
        }
        if let Some(mount) = self.body.retained_mount_for_owed_post_v2() {
            self.mount_stat_post = Some(rustix::fs::fstat(mount));
            self.mount_id_post = Some(MountId::from_fd(mount));
            self.mount_comparison_post = Some((|| {
                let (Some(Ok(stat)), Some(Ok(mount_id))) = (&self.mount_stat_post, &self.mount_id_post)
                else { return Err(StorageRuntimeError::Receiving); };
                if let Some(Ok(before)) = &self.mount_stat {
                    if (before.st_dev, before.st_ino) != (stat.st_dev, stat.st_ino) {
                        return Err(StorageRuntimeError::Recovery);
                    }
                }
                if let Some(Ok(before)) = &self.mount_id {
                    if before != mount_id { return Err(StorageRuntimeError::Recovery); }
                }
                Ok(())
            })());
        }
        // A failed initial native pair cannot suppress this independently paid
        // final pair or the same original/profile post below.
        let initial = self.clock_values[0].as_ref().and_then(|result| result.as_ref().ok()).copied();
        self.clock_values[3] = Some(self.clocks[3].observe_once(initial));
        if let (Some(Ok(verified)), Some(Ok(sample))) = (&self.verified, &self.clock_values[3]) {
            self.current[2] = Some(verified.require_current_sample_v2(sample));
        }
        self.native_post = Some(receiving.finish_native_once_v2());
        self.posts = Some((|| {
            if !matches!(self.listener_post, Some(Ok(()))) { return Err(StorageRuntimeError::Receiving); }
            if matches!(self.socket, Some(Ok(_))) {
                if !matches!(self.socket_post, Some(Ok(())))
                    || !matches!(self.peer_results[2], Some(Ok(_)))
                    || self.peer_results[2].as_ref().and_then(|result| result.as_ref().ok())
                        != self.accepted.as_ref().and_then(|result| result.as_ref().ok())
                { return Err(StorageRuntimeError::Receiving); }
            }
            if matches!(self.record, Some(Ok(_))) && matches!(self.accepted, Some(Ok(_)))
                && !matches!(self.subject_post_result, Some(Ok(())))
            { return Err(StorageRuntimeError::Receiving); }
            if self.mount_comparison_post.is_some() && !matches!(self.mount_comparison_post, Some(Ok(()))) {
                return Err(StorageRuntimeError::Receiving);
            }
            if !matches!(self.clock_values[3], Some(Ok(_)))
                || (matches!(self.verified, Some(Ok(_))) && !matches!(self.current[2], Some(Ok(()))))
                || !matches!(self.native_post, Some(Ok(())))
            { return Err(StorageRuntimeError::Receiving); }
            Ok(())
        })());
    }

    pub(super) fn failure<'owner>(&'owner self, original: &'owner aos_sandbox_controller_domain::StoragePrepareReceivingLoanV1<'_>)
        -> Option<&'owner (dyn Error + 'static)>
    {
        fn cause<T, E: Error + 'static>(slot: &Option<Result<T, E>>) -> Option<&(dyn Error + 'static)> {
            slot.as_ref()?.as_ref().err().map(|cause| cause as _)
        }
        let primary = match self.first {
            Some(Failure::Host) => self.host.failure().or_else(|| cause(&self.host_result))
                .or_else(|| self.host_pair_error.as_ref().map(|cause| cause as _)),
            Some(Failure::Listener) => cause(&self.listener),
            Some(Failure::Accept) => self.socket.as_ref()?.as_ref().err().map(|cause| cause.cause() as _),
            Some(Failure::AcceptedPeer) => self.accepted_peer.failure().or_else(|| cause(&self.accepted)),
            Some(Failure::Clock(index)) => self.clocks[index].failure().or_else(|| cause(&self.clock_values[index])),
            Some(Failure::Wait) => cause(&self.wait),
            Some(Failure::Model | Failure::Original) => original.root_export_receiving_failure_v2(),
            Some(Failure::Receive) => cause(&self.record),
            Some(Failure::Binding) => cause(&self.binding),
            Some(Failure::RecordPeer) => self.record_peer.failure().or_else(|| cause(&self.record_result)),
            Some(Failure::Frame) => cause(&self.frame_result),
            Some(Failure::Trust) => cause(&self.verified),
            Some(Failure::BeforePeer) => self.peers[0].failure().or_else(|| cause(&self.peer_results[0])),
            Some(Failure::BeforeSendPeer) => self.peers[1].failure().or_else(|| cause(&self.peer_results[1])),
            Some(Failure::Body) => self.body.failure_with_original_v2(original).or_else(|| cause(&self.body_result)),
            Some(Failure::MountStat) => cause(&self.mount_stat),
            Some(Failure::MountId) => cause(&self.mount_id),
            Some(Failure::Response) => cause(&self.response),
            Some(Failure::Current(index)) => cause(&self.current[index]),
            Some(Failure::Send) => cause(&self.send),
            Some(Failure::Gate) => self.gate.as_ref().map(|cause| cause as _),
            None => None,
        };
        primary.or_else(|| cause(&self.listener_post)).or_else(|| cause(&self.socket_post))
            .or_else(|| self.peers[2].failure()).or_else(|| cause(&self.peer_results[2]))
            .or_else(|| self.subject_post.failure()).or_else(|| cause(&self.subject_post_result))
            .or_else(|| cause(&self.mount_stat_post)).or_else(|| cause(&self.mount_id_post))
            .or_else(|| cause(&self.mount_comparison_post))
            .or_else(|| self.clocks[3].failure()).or_else(|| cause(&self.current[2]))
            .or_else(|| original.root_export_receiving_failure_v2()).or_else(|| cause(&self.posts))
    }

    // The caller consumes the actual F positive-disposition token before
    // invoking this infallible local disposal, then completes arithmetic only.
    pub(super) fn dispose_after_positive_posts_v2(&mut self) {
        if self.first.is_some() || !matches!(self.send, Some(Ok(())))
            || !matches!(self.posts, Some(Ok(())))
        { std::process::abort(); }
        self.body.dispose_positive_after_posts_v2();
        drop(self.record.take());
        drop(self.socket.take());
        drop(self.host_pair.take());
        self.completed = true;
    }
}

impl Drop for RootExportOriginalV2 {
    fn drop(&mut self) {
        if self.entered && !self.completed { std::process::abort(); }
    }
}

impl StorageBrokerRuntime {
    /// Serves an original HostLaunch export on the same occupied Storage F.
    ///
    /// The parent service first moves its actual startup into the existing
    /// original slot. This method joins the SAME State writer before any upper
    /// allocation, Host cgroup capture, accept or receive. It admits no local
    /// effect and cannot turn a parsed row, catalog or mount into Host authority.
    /// The launch frame, independently signed artifacts, actual peer and fresh
    /// physical catalog are checked separately under the original cutoff.
    ///
    /// # Errors
    /// Retains the original arithmetic, admission, native, protocol or crypto
    /// cause and every reached failed prefix. The caller must borrow that cause
    /// and exit while the actual startup slot and this Runtime remain resident;
    /// no failed disposal or handback is possible.
    pub fn serve_host_launch_root_export_receiving_v2(
        &mut self,
        listener: &mut RecordSubjectListener,
        template: &ProtectedGuestRootTemplateV1,
        original: &mut aos_sandbox_controller_domain::StoragePrepareReceivingLoanV1<'_>,
    ) -> Result<crate::root_export::RootExportOutcome, StorageRuntimeError> {
        if !self.original_service_lent || self.original_worker_startup.is_some()
            || self.root_export_original.is_some() || self.root_export_geometry.is_some()
            || self.requires_reopen()
        { return Err(StorageRuntimeError::Receiving); }
        self.root_export_geometry = Some(RootExportRepresentationV2::from_runtime_v2(self));
        let Some(Ok(geometry)) = self.root_export_geometry.as_ref() else {
            return Err(StorageRuntimeError::Receiving);
        };
        let mut flight = original.borrow_root_launch_export_receiving_v2(
            self.coordinator.recovery_encoding_journal_v1(), geometry.upper_bytes,
            geometry.saved_catalog_bytes, geometry.catalog_entries, geometry.catalog_native_files,
        ).map_err(|_| StorageRuntimeError::Receiving)?;
        // This box is allocated only after its exact compiled constructor,
        // result and allocator-header bound has been admitted on that original.
        // An unwind aborts in its own Drop before any inner native field drops.
        let mut owner = Box::new(RootExportOriginalV2::new());
        let observed = owner.observe_launch_once(self, listener, template, &mut flight);
        if observed.is_err() {
            self.root_export_original = Some(owner);
            return Err(StorageRuntimeError::Receiving);
        }
        let disposal = match flight.prepare_positive_disposal_v2() {
            Ok(disposal) => disposal,
            Err(_) => {
                self.root_export_original = Some(owner);
                return Err(StorageRuntimeError::Receiving);
            }
        };
        // Every fallible observation, send and independently owed post already
        // succeeded. The same physical mount and upper native originals dispose
        // before the lower owner completes infallible financial arithmetic.
        owner.dispose_after_positive_posts_v2();
        drop(owner);
        disposal.complete_after_disposal_v2();
        self.root_export_geometry = None;
        Ok(crate::root_export::RootExportOutcome::Exported)
    }

    /// Borrows the actual earliest failed root-export owner without reentry.
    ///
    /// This negative-only diagnostic accepts the same original slot's borrower.
    /// It supplies no retry, descriptor, successful outcome or fresh authority.
    #[must_use]
    pub fn host_launch_root_export_failure_v2<'owner>(
        &'owner self,
        original: &'owner aos_sandbox_controller_domain::StoragePrepareReceivingLoanV1<'_>,
    ) -> Option<&'owner (dyn Error + 'static)> {
        self.root_export_geometry.as_ref().and_then(|result| result.as_ref().err())
            .map(|cause| cause as _)
            .or_else(|| self.root_export_original.as_ref()?.failure(original))
            .or_else(|| original.root_export_receiving_failure_v2())
    }
}
