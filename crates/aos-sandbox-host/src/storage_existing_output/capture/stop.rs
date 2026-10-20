//! Sends fresh Stop cancellation from the actual failed physical Capture owner.
//!
//! The old channel, source, aliases and every earlier error remain resident.
//! Only actual fresh Stop containment and its paid control loan may enter this
//! once-only connection. A verified residual receipt releases no output debt.

use super::*;
use aos_sandbox_linux::seqpacket::capture_stop::CaptureWriterAliasCloseOriginalV4;
use aos_sandbox_protocol::authenticated_session::all_methods::AuthenticatedBrokerMethodRequestV1;
use aos_sandbox_protocol::storage_capture_session::stop_cleanup::{
    CAPTURE_STOP_RECEIPT_BYTES_V4, CaptureQuiescentIncompleteReceiptDataV4,
    CaptureStopCleanupProtocolErrorV4, CaptureStopCleanupRequestDataV4,
    MAXIMUM_CAPTURE_STOP_REQUEST_BYTES_V4,
};

#[derive(Clone, Copy)]
enum First {
    Admission,
    Aliases,
    Shutdown,
    Opening,
    Wire,
    Encoding,
    Send,
    Receive,
    Decode,
    Verification,
    Post(usize),
}

pub(super) struct CaptureStopOriginalV4 {
    aliases: CaptureWriterAliasCloseOriginalV4,
    alias_result: Option<Result<()>>,
    alias_gate: Option<HostError>,
    shutdown: Option<Result<()>>,
    shutdown_gate: Option<HostError>,
    open: OpenOriginalV2,
    opening: Option<Result<()>>,
    socket: Option<DescriptorSubjectSocket>,
    route: Option<SocketRouteIdentity>,
    manager: Option<PidFdInfo>,
    wire: Option<std::result::Result<(), CaptureStopCleanupProtocolErrorV4>>,
    encoding: Option<std::result::Result<Vec<u8>, std::collections::TryReserveError>>,
    send_native: NativeOriginalV2,
    sent: Option<Result<()>>,
    reply: ReplyOriginalV2,
    received: Option<Result<()>>,
    receipt: Option<std::result::Result<CaptureQuiescentIncompleteReceiptDataV4, CaptureStopCleanupProtocolErrorV4>>,
    verification: Option<std::result::Result<(), CaptureStopCleanupProtocolErrorV4>>,
    post_native: [NativeOriginalV2; 3],
    posts: [Option<Result<()>>; 3],
    result: Option<Result<()>>,
    first: Option<First>,
}

impl CaptureStopOriginalV4 {
    fn new() -> Self {
        Self {
            aliases: CaptureWriterAliasCloseOriginalV4::new(),
            alias_result: None,
            alias_gate: None,
            shutdown: None,
            shutdown_gate: None,
            open: OpenOriginalV2::new(),
            opening: None,
            socket: None,
            route: None,
            manager: None,
            wire: None,
            encoding: None,
            send_native: NativeOriginalV2::new(),
            sent: None,
            reply: ReplyOriginalV2::new(),
            received: None,
            receipt: None,
            verification: None,
            post_native: std::array::from_fn(|_| NativeOriginalV2::new()),
            posts: std::array::from_fn(|_| None),
            result: None,
            first: None,
        }
    }

    pub(super) fn receiving_demand_v4() -> Option<ResourceVector> {
        // Reuse the canonical client's complete native/vector recipe. Its ten
        // native reservoirs, sixteen membership probes and four receives cover
        // this one connection's six reservoirs and finite native roster. The
        // extra after probes are SUM because failed primary inputs stay held.
        let base = StorageExistingOutputOriginalV2::preparation_demand_v2()?;
        let (post_bytes, post_files, post_names) =
            aos_sandbox_linux::cgroup::RuntimeScopeMembershipOriginalV1::exact_receiving_demand_v1()?;
        let (reply_bytes, reply_files) = DescriptorSubjectSocket::storage_zero_rights_reply_obligations_v6(
            CAPTURE_STOP_RECEIPT_BYTES_V4,
        )?;
        let memory = size_of::<Self>().checked_mul(2)?
            .checked_add(MAXIMUM_CAPTURE_STOP_REQUEST_BYTES_V4.checked_mul(2)?)?
            .checked_add(reply_bytes)?
            .checked_add(post_bytes.checked_mul(3)?)?
            .checked_add(CaptureWriterAliasCloseOriginalV4::receiving_bytes_v4()?)?;
        let traffic = MAXIMUM_CAPTURE_STOP_REQUEST_BYTES_V4.checked_add(CAPTURE_STOP_RECEIPT_BYTES_V4)?;
        base.checked_add(ResourceVector::ZERO
            .with(D::MemoryBytes, u64::try_from(memory).ok()?)
            .with(D::OpenFiles, u64::try_from(reply_files.checked_add(post_files.checked_mul(3)?)?).ok()?)
            .with(D::MetadataEntries, u64::try_from(post_names.checked_mul(3)?).ok()?)
            .with(D::OutputBytes, u64::try_from(traffic).ok()?)
            .with(D::NetworkBytes, u64::try_from(traffic).ok()?)).ok()
    }

    fn posts_once(&mut self, client: &StorageExistingOutputClientV1, held: &HeldCaptureV2) {
        for index in 0..3 {
            let mut native = Some(&mut self.post_native[index]);
            // Each result owns a separate native destination. A failed route
            // or manager observation cannot suppress the later subject check.
            self.posts[index] = Some(match index {
                0 => validate_socket_route_observed(&mut native).and_then(|route| {
                    if Some(route) == self.route { Ok(()) } else { Err(refused()) }
                }),
                1 => self.socket.as_ref().ok_or_else(refused).and_then(|socket| {
                    let manager = client.verify_activation_peer_observed(socket, &mut native)?;
                    if Some(manager) == self.manager { Ok(()) } else { Err(refused()) }
                }),
                _ => {
                    let subject = membership_observed(&client.storage_cgroup, held.subject.pidfd(), &mut native);
                    subject.and_then(|observed| {
                        if observed != held.storage || !alive_observed(&held.subject, &mut native, false)? {
                            return Err(refused());
                        }
                        Ok(())
                    })
                }
            });
            if !matches!(self.posts[index], Some(Ok(()))) {
                self.first.get_or_insert(First::Post(index));
            }
        }
    }

    fn run_once(
        &mut self,
        client: &StorageExistingOutputClientV1,
        held: &mut HeldCaptureV2,
        pipes_transferred: bool,
        request: &AuthenticatedBrokerMethodRequestV1,
        effect: &aos_sandbox_broker::BrokerEffectIntentV1,
        runtime: ObjectDigest,
        current: &mut dyn FnMut() -> Result<()>,
    ) -> Result<()> {
        self.result = Some((|| {
            if pipes_transferred {
                self.alias_result = Some(if held.pipes.is_empty() { Ok(()) } else { Err(refused()) });
            } else {
                let (returned, gate) = self.aliases.close_once_with_current_cut_v4(&mut held.pipes, current);
                self.alias_result = Some(returned.map_err(|_| refused()));
                self.alias_gate = gate;
            }
            if !matches!(self.alias_result, Some(Ok(()))) {
                self.first.get_or_insert(First::Aliases);
            }
            // This shutdown interrupts any old Storage terminal wait. Its FD
            // and separate shutdown error remain on the exact old owner.
            self.shutdown = Some(match current() {
                Ok(()) => {
                    held.socket.begin_original_retention_v1();
                    held.socket.close();
                    if held.socket.original_retention_failed_v1()
                        && held.socket.original_shutdown_failure_v1().is_none() {
                        Ok(())
                    } else { Err(refused()) }
                }
                Err(cause) => {
                    self.shutdown_gate = Some(cause);
                    Err(refused())
                }
            });
            if !matches!(self.shutdown, Some(Ok(()))) {
                self.first.get_or_insert(First::Shutdown);
            }

            self.opening = Some((|| {
                current()?;
                let (socket, route, manager) = client.open_checked_socket_with_disposition(Some(&mut self.open))?;
                self.route = Some(route);
                self.manager = Some(manager);
                self.socket = Some(socket.take()?);
                if route != held.route || manager != held.manager { return Err(refused()); }
                Ok(())
            })());
            if !matches!(self.opening, Some(Ok(()))) {
                self.first.get_or_insert(First::Opening);
                return Err(refused());
            }
            let artifacts = request.authorization().ok_or_else(refused)?;
            let begin = held.begin.digest().map_err(|_| refused())?;
            let wire = CaptureStopCleanupRequestDataV4::new(
                effect.effect_deadline_boottime_nanoseconds(), held.begin.nonce,
                begin, *held.begin.source.source_digest_v2().as_bytes(), held.begin.attempt,
                request.exact_body(), aos_sandbox_protocol::session::AuthorizationArtifactBytes {
                    broker_plan: artifacts.broker_plan(),
                    broker_plan_signature: artifacts.broker_plan_signature(),
                    ownership_lease: artifacts.ownership_lease(),
                    ownership_lease_signature: artifacts.ownership_lease_signature(),
                },
            );
            let wire = match wire {
                Ok(wire) => { self.wire = Some(Ok(())); wire }
                Err(cause) => {
                    self.wire = Some(Err(cause));
                    self.first.get_or_insert(First::Wire);
                    return Err(refused());
                }
            };
            self.encoding = Some(wire.encode_v4());
            let Some(Ok(bytes)) = self.encoding.as_ref() else {
                self.first.get_or_insert(First::Encoding);
                return Err(refused());
            };
            let socket = self.socket.as_mut().ok_or_else(refused)?;
            self.sent = Some((|| {
                current()?;
                send_observed(socket, bytes, effect.effect_deadline_boottime_nanoseconds(),
                    &mut Some(&mut self.send_native))
            })());
            if !matches!(self.sent, Some(Ok(()))) { self.first.get_or_insert(First::Send); }
            // An entered send owes its distinct receive even on native refusal.
            // A failed channel cannot become healthy; the shared receive engine
            // records that refusal on its original destination.
            self.received = Some((|| {
                let reply = client.receive_storage_record_observed(socket,
                    self.manager.ok_or_else(refused)?, self.route.ok_or_else(refused)?,
                    effect.effect_deadline_boottime_nanoseconds(), CAPTURE_STOP_RECEIPT_BYTES_V4,
                    Some((held.storage, &held.subject)), Some(&mut self.reply))?;
                self.receipt = Some(CaptureQuiescentIncompleteReceiptDataV4::decode_v4(reply.bytes()?));
                let receipt = self.receipt.as_ref().and_then(|result| result.as_ref().ok()).ok_or_else(refused)?;
                self.verification = Some(receipt.verify_request_v4(&wire, request.request_id(), runtime,
                    held.begin.durable_attempt_digest, held.proof.physical_row_digest,
                    effect.plan_digest(), effect.lease_digest()));
                if matches!(self.verification, Some(Ok(()))) { Ok(()) } else { Err(refused()) }
            })());
            if !matches!(self.received, Some(Ok(()))) {
                self.first.get_or_insert(if matches!(self.receipt, Some(Err(_))) {
                    First::Decode
                } else if matches!(self.verification, Some(Err(_))) {
                    First::Verification
                } else { First::Receive });
            }
            Ok(())
        })());
        self.posts_once(client, held);
        if !matches!(self.result, Some(Ok(()))) {
            self.first.get_or_insert(First::Admission);
        }
        if self.first.is_none() { Ok(()) } else { Err(refused()) }
    }

    pub(super) fn failure<'a>(&'a self, held: &'a HeldCaptureV2) -> Option<&'a (dyn Error + 'static)> {
        let selected: Option<&(dyn Error + 'static)> = match self.first? {
            First::Admission => error(&self.result),
            First::Aliases => self.alias_gate.as_ref().map(|cause| cause as _).or_else(|| self.aliases.failure())
                .or_else(|| error(&self.alias_result)),
            First::Shutdown => self.shutdown_gate.as_ref().map(|cause| cause as _)
                .or_else(|| held.socket.original_shutdown_failure_v1().map(|cause| cause as _))
                .or_else(|| error(&self.shutdown)),
            First::Opening => self.open.failure().or_else(|| error(&self.opening)),
            First::Wire => self.wire.as_ref()?.as_ref().err().map(|cause| cause as _),
            First::Encoding => self.encoding.as_ref()?.as_ref().err().map(|cause| cause as _),
            First::Send => self.send_native.failure().or_else(|| error(&self.sent)),
            First::Receive => self.reply.failure().or_else(|| error(&self.received)),
            First::Decode => self.receipt.as_ref()?.as_ref().err().map(|cause| cause as _),
            First::Verification => self.verification.as_ref()?.as_ref().err().map(|cause| cause as _),
            First::Post(index) => self.post_native[index].failure().or_else(|| error(&self.posts[index])),
        };
        selected.or_else(|| error(&self.result))
    }
}

impl StorageCaptureOriginalV2 {
    pub(crate) fn stop_receiving_demand_v4() -> Option<ResourceVector> {
        CaptureStopOriginalV4::receiving_demand_v4()
    }

    /// Attempts fresh cancellation without ending any old Capture obligation.
    ///
    /// # Errors
    /// Refuses another Stage, uncontained runtime, unmatched authenticated Stop,
    /// a repeated attempt, or any alias/channel/native/protocol uncertainty.
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn stop_contained_once_v4(
        &mut self,
        failed: &crate::broker::HostCaptureFailedStageV4,
        native: &crate::broker::HostResidentStopNativeCompletedV4,
        worker: &std::sync::Arc<tokio::sync::Mutex<crate::worker::launch::HostLaunchWorkerOriginalV2>>,
        receiving: &crate::plan::HostExecutionReceivingLoanV2<'_>,
        request: &AuthenticatedBrokerMethodRequestV1,
        effect: &aos_sandbox_broker::BrokerEffectIntentV1,
        runtime: ObjectDigest,
        current: &mut dyn FnMut() -> Result<()>,
    ) -> Result<()> {
        if self.stop.is_some() { return Err(refused()); }
        self.stop_parent_v4()?;
        failed.require_failed_resident_v4()?;
        receiving.require_capture_stop_request_v4(request)?;
        use sha2::{Digest as _, Sha256};
        if effect.verb() != aos_sandbox_core::BrokerVerb::HostStop
            || effect.request_id() != &request.request_id()
            || effect.transport_request_digest().as_bytes() != &<[u8; 32]>::from(Sha256::digest(request.exact_body()))
            || !native.matches_worker_v4(worker,
                (request.request_id(), request.session_binding(), request.signed_request_digest()))
        {
            return Err(refused());
        }
        self.stop = Some(Box::new(CaptureStopOriginalV4::new()));
        let stop = self.stop.as_mut().ok_or_else(refused)?;
        let held = self.held.as_mut().ok_or_else(refused)?;
        stop.run_once(self.client.as_ref().ok_or_else(refused)?, held,
            self.pipes_transferred, request, effect, runtime, current)
    }

    pub(crate) fn stop_failure_v4(&self) -> Option<&(dyn Error + 'static)> {
        self.stop.as_ref()?.failure(self.held.as_ref()?)
    }

    pub(crate) fn stop_clock_failure_selected_v4(&self) -> bool {
        let Some(stop) = self.stop.as_ref() else { return false; };
        match stop.first {
            Some(First::Aliases) => stop.alias_gate.is_some(),
            Some(First::Shutdown) => stop.shutdown_gate.is_some(),
            Some(First::Opening) => stop.open.failure().is_none() && matches!(stop.opening, Some(Err(_))),
            Some(First::Send) => stop.send_native.failure().is_none() && matches!(stop.sent, Some(Err(_))),
            _ => false,
        }
    }

    pub(crate) fn stopped_with_residual_v4(&self) -> Result<&CaptureQuiescentIncompleteReceiptDataV4> {
        let stop = self.stop.as_ref().ok_or_else(refused)?;
        if stop.first.is_some() || !matches!(stop.result, Some(Ok(())))
            || !stop.posts.iter().all(|post| matches!(post, Some(Ok(()))))
            || !matches!(stop.sent, Some(Ok(()))) || !matches!(stop.received, Some(Ok(())))
        {
            return Err(refused());
        }
        stop.receipt.as_ref().and_then(|result| result.as_ref().ok()).ok_or_else(refused)
    }
}

fn error<T, E: std::error::Error + 'static>(
    value: &Option<std::result::Result<T, E>>,
) -> Option<&(dyn std::error::Error + 'static)> {
    value.as_ref()?.as_ref().err().map(|cause| cause as _)
}
