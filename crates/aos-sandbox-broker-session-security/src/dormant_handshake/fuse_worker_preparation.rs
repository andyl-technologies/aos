//! Original received-flight entry for one-shot lower Mount worker preparation.
//!
//! This entry drives the existing protected same-socket challenge, genuine
//! Host scope readback, Mount signature/current slot admission, original
//! reservation ACK, durable object-start marker and actual kernel-object
//! producer. It registers no listener and changes no production advertisement.
//! Host purpose-56 issuance/admission and the subsequent descriptor-copy,
//! fresh HELLO, kernel INIT/idmap and Root resource-read joins remain separate.

use aos_sandbox_linux::cgroup::CgroupV2Root;
use aos_sandbox_mount::broker::{MountBroker, PreparedMountFuseWorkerHandoffV1};
use aos_sandbox_mount::worker::MountWorker;

use super::{
    DormantAuthenticatedBrokerSessionV1, DormantBrokerDescriptorRequestReceiveProgressV1,
    DormantBrokerSessionHandshakeErrorV1, DormantReceivedBrokerDescriptorRequestV1,
    DormantReceivedBrokerRequestV1, DormantUnconfirmedBrokerDescriptorRequestV1,
};

impl DormantAuthenticatedBrokerSessionV1 {
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
        let (admission, descriptors) = match self.0.receive_authenticated_descriptor_request(4) {
            Ok(value) => value,
            Err(crate::handshake::DormantBrokerSessionHandshakeErrorV1::Transport) => {
                return Ok(DormantBrokerDescriptorRequestReceiveProgressV1::Pending);
            }
            Err(error) => return Err(error.into()),
        };
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
        let mut pending = self.0.hold_pending_request(&request)?;
        pending.recheck()?;
        let mut guard = || {
            pending.recheck().map_err(|_| {
                aos_sandbox_host::HostError::Fence("original worker session custody changed")
            })
        };
        let reply = host
            .prepare_original_fuse_worker(&request, roles, &mut guard)
            .await
            .map_err(|_| DormantBrokerSessionHandshakeErrorV1::RemoteInvalid)?;
        drop(guard);
        pending.recheck()?;
        let result = action(&reply);
        // Even a failed callback must not bypass the final currentness check.
        // Neither failure retires the durable launch or pending request.
        pending.recheck()?;
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
