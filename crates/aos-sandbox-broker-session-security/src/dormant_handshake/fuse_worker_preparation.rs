//! Original received-flight entry for one-shot lower Mount worker preparation.
//!
//! This entry drives the existing protected same-socket challenge, genuine
//! Host scope readback, Mount signature/current slot admission, original
//! reservation ACK, durable object-start marker and actual kernel-object
//! producer. It registers no listener and changes no production advertisement.
//! The separate Host entry admits purpose 56 and retains launch escrow before
//! PID1. Controller issuance, complete descriptor-copy closure, fresh HELLO,
//! kernel INIT/idmap and Root resource-read joins remain separate.

use aos_sandbox_linux::cgroup::CgroupV2Root;
use aos_sandbox_mount::broker::{MountBroker, PreparedMountFuseWorkerHandoffV1};
use aos_sandbox_mount::worker::MountWorker;

use crate::handshake::fixed_mount_peer_verifier;

use super::{
    DormantAuthenticatedBrokerSessionV1, DormantBrokerDescriptorRequestReceiveProgressV1,
    DormantBrokerSessionHandshakeErrorV1, DormantReceivedBrokerDescriptorRequestV1,
    DormantReceivedBrokerRequestV1, DormantUnconfirmedBrokerDescriptorRequestV1,
};

impl DormantAuthenticatedBrokerSessionV1 {
    /// Chooses exact closed Host coordinates beneath the actual owner deadline.
    pub(crate) fn original_worker_request_coordinates(
        &mut self,
        original_deadline: u64,
    ) -> Result<super::DormantBrokerRequestCoordinatesV1, DormantBrokerSessionHandshakeErrorV1>
    {
        let method = aos_proto::aos::sandbox::local::v1::BrokerMethod::BROKER_METHOD_HOST_PREPARE_FUSE_WORKER_SESSION_V1;
        self.0.require_negotiated_client_method(method)?;
        let (request_id, deadline, maximum_response_bytes, protocol_version, audience) =
            self.0.client_request_coordinates()?;
        if audience != aos_proto::aos::sandbox::local::v1::Audience::AUDIENCE_ROOT_MOUNT
            || protocol_version != aos_sandbox_core::ProtocolVersion::new(1, 0)
        {
            return Err(DormantBrokerSessionHandshakeErrorV1::RemoteInvalid);
        }
        let deadline_boottime_nanoseconds = deadline.min(original_deadline);
        super::check_production_deadline(deadline_boottime_nanoseconds)?;
        Ok(super::DormantBrokerRequestCoordinatesV1 {
            request_id,
            deadline_boottime_nanoseconds,
            maximum_response_bytes,
            protocol_version,
            audience,
        })
    }

    /// Prepares and sends four roles only from the actual original Mount owner.
    pub(crate) fn prepare_and_send_original_worker<W: MountWorker>(
        &mut self,
        handoff: &mut PreparedMountFuseWorkerHandoffV1<'_, '_, W>,
        envelope: aos_proto::aos::sandbox::local::v1::BrokerRequestEnvelope,
        coordinates: super::DormantBrokerRequestCoordinatesV1,
    ) -> Result<
        crate::handshake::fuse_intent_continuation::OriginalMountHostWorkerDispatchV1,
        DormantBrokerSessionHandshakeErrorV1,
    > {
        use super::{
            DormantBrokerDescriptorRequestPreparationV1 as Preparation,
            DormantPreparedBrokerDescriptorRequestV1 as Prepared,
        };
        use crate::handshake::fuse_intent_continuation::OriginalMountHostWorkerDispatchV1;
        let method = aos_proto::aos::sandbox::local::v1::BrokerMethod::BROKER_METHOD_HOST_PREPARE_FUSE_WORKER_SESSION_V1;
        self.0.require_negotiated_client_method(method)?;
        handoff
            .recheck()
            .map_err(|_| DormantBrokerSessionHandshakeErrorV1::RemoteInvalid)?;
        let roles = handoff
            .take_launch_roles()
            .map_err(|_| DormantBrokerSessionHandshakeErrorV1::RemoteInvalid)?;
        let (request, initialize) = self.0.prepare_client_request(
            envelope,
            method,
            4,
            coordinates.request_id(),
            coordinates.deadline_boottime_nanoseconds(),
            coordinates.maximum_response_bytes(),
        )?;
        let prepared = if initialize {
            match self.0.initialize_authenticated_request(&request)? {
                crate::ProtectedBrokerSessionInitializationResultV1::Initialized => Prepared {
                    request,
                    descriptors: Vec::from(roles),
                },
                crate::ProtectedBrokerSessionInitializationResultV1::RecoveryRequired {
                    error,
                    recovery,
                } => {
                    return Ok(OriginalMountHostWorkerDispatchV1::Durability(
                        Preparation::InitializationRecoveryRequired {
                            error,
                            recovery,
                            request: DormantUnconfirmedBrokerDescriptorRequestV1 {
                                request,
                                descriptors: Vec::from(roles),
                            },
                        },
                    ));
                }
            }
        } else {
            match self.0.append_authenticated_request(&request)? {
                crate::ProtectedBrokerRequestCommitResultV1::Committed => Prepared {
                    request,
                    descriptors: Vec::from(roles),
                },
                crate::ProtectedBrokerRequestCommitResultV1::RecoveryRequired {
                    error,
                    recovery,
                } => {
                    return Ok(OriginalMountHostWorkerDispatchV1::Durability(
                        Preparation::SuccessorRecoveryRequired {
                            error,
                            recovery,
                            request: DormantUnconfirmedBrokerDescriptorRequestV1 {
                                request,
                                descriptors: Vec::from(roles),
                            },
                        },
                    ));
                }
            }
        };
        handoff
            .recheck()
            .map_err(|_| DormantBrokerSessionHandshakeErrorV1::RemoteInvalid)?;
        // Sent drops the local outgoing table. It does not prove receiver,
        // queued transport or PID1 copies have closed before a fresh HELLO.
        let progress = self.send_authenticated_descriptor_request(prepared);
        handoff
            .recheck()
            .map_err(|_| DormantBrokerSessionHandshakeErrorV1::RemoteInvalid)?;
        Ok(OriginalMountHostWorkerDispatchV1::Transport(progress))
    }

    /// Drives original Mount object production and its actual four-role Host send.
    ///
    /// This closed entry keeps the same pending Controller/Mount flight, real
    /// Mount writer and original kernel objects held throughout the distinct
    /// sealed-plan exchange and durable Host-session preparation/send. It does
    /// not register a service, widen any ordinary one-FD sender or complete an
    /// outcome. The callback retains durability/transport uncertainty under
    /// the actual Mount owner; returning still leaves all escrows occupied.
    ///
    /// Complete reply/queued-copy closure and a fresh worker challenge remain
    /// mandatory before HELLO/INIT/idmap. No metadata/backing dispatch or Root
    /// read guard is created by this preparation-only transport result.
    pub(crate) fn with_original_mount_worker_host_dispatch<W, F, R>(
        &mut self,
        request: &DormantReceivedBrokerRequestV1,
        mount: &mut MountBroker<W>,
        host_cgroup_root: &CgroupV2Root,
        host: &mut DormantAuthenticatedBrokerSessionV1,
        action: F,
    ) -> Result<R, DormantBrokerSessionHandshakeErrorV1>
    where
        W: MountWorker,
        F: FnOnce(
            &mut PreparedMountFuseWorkerHandoffV1<'_, '_, W>,
            crate::handshake::fuse_intent_continuation::OriginalMountHostWorkerDispatchV1,
        ) -> Result<R, DormantBrokerSessionHandshakeErrorV1>,
    {
        let mut transport = self.0.hold_fuse_intent_transport(&request.0)?;
        transport.with_original_worker_handoff_transport(
            mount,
            host_cgroup_root,
            |transport, handoff| {
                let progress = transport.dispatch_original_host_worker(handoff, host)?;
                action(handoff, progress)
            },
        )
    }

    /// Receives only the exact four-role original worker preparation profile.
    ///
    /// This separate receiver does not widen the ordinary Host zero/one-FD
    /// receiver or any production hello. The original packet's full per-record
    /// subject is joined to the retained fixed Mount peer before protected
    /// signed-request admission. Initial and successor uncertainty retain the
    /// exact four owners beside the existing durable recovery token.
    ///
    /// # Errors
    ///
    /// Rejects a foreign method, descriptor geometry, subject, session or
    /// protected currentness. Replays are reconciliation, never fresh launch
    /// eligibility. A fatal receive consumes and closes its received copies.
    pub fn receive_original_host_worker_preparation(
        &mut self,
    ) -> Result<DormantBrokerDescriptorRequestReceiveProgressV1, DormantBrokerSessionHandshakeErrorV1>
    {
        let verifier = fixed_mount_peer_verifier()?;
        self.0.require_original_mount_worker_peer(&verifier)?;
        let (admission, descriptors) = match self.0.receive_authenticated_descriptor_request(4) {
            Ok(value) => value,
            Err(crate::handshake::DormantBrokerSessionHandshakeErrorV1::Transport) => {
                return Ok(DormantBrokerDescriptorRequestReceiveProgressV1::Pending);
            }
            Err(error) => return Err(error.into()),
        };
        self.0.require_original_mount_worker_peer(&verifier)?;
        let (request, initialize) = match admission {
            crate::recovery::ProtectedBrokerReceivedRequestAdmissionV1::New {
                request,
                requires_initialization,
            } => (request, requires_initialization),
            crate::recovery::ProtectedBrokerReceivedRequestAdmissionV1::InFlightReplay {
                request,
            } => {
                return Ok(
                    DormantBrokerDescriptorRequestReceiveProgressV1::InFlightReplay(
                        super::DormantBrokerDescriptorInFlightReplayV1 {
                            custody: super::DormantBrokerOutcomeUnknownV1 {
                                request: DormantReceivedBrokerRequestV1(request),
                                observation: None,
                            },
                            descriptors,
                        },
                    ),
                );
            }
            crate::recovery::ProtectedBrokerReceivedRequestAdmissionV1::TerminalReplay {
                ..
            } => {
                // This profile has no terminal worker outcome. Never adopt
                // incoming owners from a historical successful response.
                return Err(DormantBrokerSessionHandshakeErrorV1::RemoteInvalid);
            }
        };
        if request.method() != aos_proto::aos::sandbox::local::v1::BrokerMethod::BROKER_METHOD_HOST_PREPARE_FUSE_WORKER_SESSION_V1 {
            return Err(DormantBrokerSessionHandshakeErrorV1::RemoteInvalid);
        }
        let retained = DormantUnconfirmedBrokerDescriptorRequestV1 {
            request: request.clone(),
            descriptors,
        };
        if initialize {
            return Ok(match self.0.initialize_authenticated_request(&request)? {
                crate::ProtectedBrokerSessionInitializationResultV1::Initialized => {
                    DormantBrokerDescriptorRequestReceiveProgressV1::Received(DormantReceivedBrokerDescriptorRequestV1 { request, descriptors: retained.descriptors })
                }
                crate::ProtectedBrokerSessionInitializationResultV1::RecoveryRequired { error, recovery } => {
                    DormantBrokerDescriptorRequestReceiveProgressV1::InitializationRecoveryRequired { error, recovery, request: retained }
                }
            });
        }
        Ok(match self.0.append_authenticated_request(&request)? {
            crate::ProtectedBrokerRequestCommitResultV1::Committed => {
                DormantBrokerDescriptorRequestReceiveProgressV1::Received(
                    DormantReceivedBrokerDescriptorRequestV1 {
                        request,
                        descriptors: retained.descriptors,
                    },
                )
            }
            crate::ProtectedBrokerRequestCommitResultV1::RecoveryRequired { error, recovery } => {
                DormantBrokerDescriptorRequestReceiveProgressV1::SuccessorRecoveryRequired {
                    error,
                    recovery,
                    request: retained,
                }
            }
        })
    }

    /// Consumes the original received four-role packet under its pending writer.
    ///
    /// The descriptor-bearing request has already passed this session's real
    /// per-record peer and durable RequestPrepared installation. Moving its
    /// owners out of the received packet drops that packet's descriptor table
    /// before the sealed Host adapter can enter PID1. Host independently admits
    /// purpose 56 against the installed assignment and complete local lease,
    /// commits permanent launch escrow, and retains the actual process owner.
    ///
    /// `action` runs while the original pending writer is still borrowed. The
    /// reply lends comparison bytes and descriptor copies, not connected Mount
    /// or read authority. This entry performs no terminal settlement or reply
    /// send; outgoing queued copies and Mount's endpoint copies remain separate
    /// barriers before a fresh HELLO challenge. Returning cannot rearm a worker
    /// locator: Host's durable escrow remains occupied even on lost replies.
    ///
    /// # Errors
    ///
    /// Rejects another method, inexact roles, foreign/stale pending state or
    /// failed Host admission/launch/readback. Errors preserve RequestPrepared
    /// and any Host/Mount escrow; none proves that a process was not launched.
    pub async fn with_original_host_worker_preparation<H, F, R>(
        &mut self,
        received: DormantReceivedBrokerDescriptorRequestV1,
        host: &mut H,
        action: F,
    ) -> Result<R, DormantBrokerSessionHandshakeErrorV1>
    where
        H: aos_sandbox_host::DormantHostBrokerCallsiteV1,
        F: FnOnce(
            &aos_sandbox_host::DormantOriginalHostFuseWorkerPreparationV1,
        ) -> Result<R, DormantBrokerSessionHandshakeErrorV1>,
    {
        let DormantReceivedBrokerDescriptorRequestV1 {
            request,
            descriptors,
        } = received;
        if request.method()
            != aos_proto::aos::sandbox::local::v1::BrokerMethod::BROKER_METHOD_HOST_PREPARE_FUSE_WORKER_SESSION_V1
            || request.authorization().is_none()
        {
            return Err(DormantBrokerSessionHandshakeErrorV1::RemoteInvalid);
        }
        let roles: [std::os::fd::OwnedFd; 4] = descriptors
            .try_into()
            .map_err(|_| DormantBrokerSessionHandshakeErrorV1::RemoteInvalid)?;
        let verifier = fixed_mount_peer_verifier()?;
        self.0.require_original_mount_worker_peer(&verifier)?;
        let mut pending = self.0.hold_pending_request(&request)?;
        pending.recheck_mount_worker_peer(&verifier)?;
        let mut guard = || {
            pending.recheck_mount_worker_peer(&verifier).map_err(|_| {
                aos_sandbox_host::HostError::Fence("original worker session custody changed")
            })
        };
        let reply = host
            .prepare_original_fuse_worker(&request, roles, &mut guard)
            .await
            .map_err(|_| DormantBrokerSessionHandshakeErrorV1::RemoteInvalid)?;
        drop(guard);
        pending.recheck_mount_worker_peer(&verifier)?;
        let result = action(&reply);
        // Even a failed callback must not bypass the final currentness check.
        // Neither failure retires the durable launch or pending request.
        pending.recheck_mount_worker_peer(&verifier)?;
        result
    }

    /// Drives original Mount preparation while retaining actual session custody.
    ///
    /// `request` must be the original request received and durably prepared on
    /// this same authenticated session. The protected owner reopens its exact
    /// nonterminal head and original peer around every control packet. The
    /// lower Mount owner independently verifies the signed purpose, installed
    /// assignment/lease, original Host scope and physical destination slot.
    /// Only then does it commit the one-shot start marker and create the four
    /// original roles lent to `action` alongside the held Mount writer.
    ///
    /// The callback is a custody continuation, not an authority factory. No
    /// reply bytes, clone of an old request, returned pidfd or decoded plan
    /// substitutes for actual Host acceptance, per-record worker proof or a
    /// live Root read grant. The handoff cannot escape this borrow; outgoing
    /// FD copies still require explicit receiver/transport/PID1 barriers before
    /// a fresh worker challenge. This entry does not enable that challenge.
    ///
    /// # Errors
    ///
    /// Rejects another session/head/method/peer, expired preparation, invalid
    /// Host/Mount custody, wrong ACK, changed rows/slot, occupied start marker
    /// or object/handoff failure. Returning, callback failure or lost replies
    /// preserve RequestPrepared and every Mount escrow row; none permits
    /// reissue, terminal settlement or reservation retirement.
    pub fn with_original_mount_worker_handoff<W, F, R>(
        &mut self,
        request: &DormantReceivedBrokerRequestV1,
        mount: &mut MountBroker<W>,
        host_cgroup_root: &CgroupV2Root,
        action: F,
    ) -> Result<R, DormantBrokerSessionHandshakeErrorV1>
    where
        W: MountWorker,
        F: FnOnce(
            &mut PreparedMountFuseWorkerHandoffV1<'_, '_, W>,
        ) -> Result<R, DormantBrokerSessionHandshakeErrorV1>,
    {
        let mut transport = self.0.hold_fuse_intent_transport(&request.0)?;
        transport.with_original_worker_handoff(mount, host_cgroup_root, action)
    }
}
