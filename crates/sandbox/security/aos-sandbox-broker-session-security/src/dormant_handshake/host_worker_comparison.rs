//! Called original nonterminal Host comparison transport under both owners.
//!
//! The Host side consumes the actual four-role packet and sends only inside
//! the sealed Host's physical-state/live-launch sandwich. Mount enters this
//! continuation only after its genuine held producer and actual four-role
//! sender, retaining that same Mount writer and original objects throughout
//! receive and the fresh original-channel rendezvous. The Host stays inside
//! that same sealed callback throughout the fresh preparation exchange; no
//! scalar acknowledgment establishes copy absence. No terminal outcome, INIT
//! or read gate is opened.

use std::os::fd::{BorrowedFd, OwnedFd};

use aos_sandbox_host::{
    DormantHostBrokerCallsiteV1, HostError, OriginalHostFuseWorkerTransportActionV1 as Action,
    OriginalHostFuseWorkerTransportProgressV1 as Progress,
};
use aos_sandbox_linux::cgroup::CgroupV2Root;
use aos_sandbox_mount::broker::{MountBroker, PreparedMountFuseWorkerHandoffV1};
use aos_sandbox_mount::worker::MountWorker;

use super::{
    DormantAuthenticatedBrokerSessionV1, DormantBrokerDescriptorRequestSendProgressV1,
    DormantBrokerSessionHandshakeErrorV1, DormantReceivedBrokerDescriptorRequestV1,
    DormantReceivedBrokerRequestV1,
};
use crate::handshake::fuse_intent_continuation::OriginalMountHostWorkerDispatchV1;
use crate::handshake::host_worker_comparison::{
    HeldOriginalHostWorkerComparisonV1, OriginalHostWorkerComparisonV1,
};

/// Retains received comparison objects, never a live-worker or read guard.
pub(crate) struct DormantOriginalHostWorkerComparisonV1(OriginalHostWorkerComparisonV1);

impl DormantOriginalHostWorkerComparisonV1 {
    /// Borrows the exact original response for comparisons only.
    pub(crate) fn body(&self) -> &[u8] {
        self.0.body()
    }

    /// Borrows actual received pidfd/cgroup copies without adopting authority.
    pub(crate) fn descriptors(&self) -> [BorrowedFd<'_>; 2] {
        self.0.descriptors()
    }
}

/// Preserves actual outgoing ownership uncertainty without a terminal result.
pub(crate) enum OriginalMountHostWorkerComparisonProgressV1<R> {
    /// The original received comparison was lent under the held Mount owner.
    Compared(R),
    /// The original durable/send recovery still owns the outgoing descriptors.
    Deferred(OriginalMountHostWorkerDispatchV1),
}

/// Retains the original request on every uncertain launch/comparison delivery.
pub(crate) enum OriginalHostWorkerComparisonSendProgressV1 {
    /// The actual comparison send and final owner sandwiches completed.
    Sent,
    /// Delivery or launch cannot be treated as absence or retried from a row.
    ReconciliationRequired {
        /// Retains the same original authenticated pending request, not a grant.
        request: DormantReceivedBrokerRequestV1,
        /// Records the conservative failure without clearing either escrow.
        error: DormantBrokerSessionHandshakeErrorV1,
    },
}

impl DormantAuthenticatedBrokerSessionV1 {
    /// Launches and sends only on the original nonterminal Host/Mount flight.
    ///
    /// The actual packet table moves before PID1; original RequestPrepared,
    /// fixed Mount peer and Host's physical/live launch remain independently
    /// checked around send. Returning does not acknowledge copy closure or
    /// retire any launch/reservation. Post-send errors are ambiguous.
    ///
    /// # Errors
    ///
    /// Rejects foreign packets, stale pending/service custody, Host admission,
    /// launch/readback, physical drift, malformed comparison or transport loss.
    pub(crate) async fn send_original_host_worker_comparison<H: DormantHostBrokerCallsiteV1>(
        &mut self,
        received: DormantReceivedBrokerDescriptorRequestV1,
        host: &mut H,
    ) -> Result<OriginalHostWorkerComparisonSendProgressV1, DormantBrokerSessionHandshakeErrorV1>
    {
        let DormantReceivedBrokerDescriptorRequestV1 {
            request,
            descriptors,
        } = received;
        if request.authorization().is_none() {
            return Err(DormantBrokerSessionHandshakeErrorV1::RemoteInvalid);
        }
        let roles: [OwnedFd; 4] = descriptors
            .try_into()
            .map_err(|_| DormantBrokerSessionHandshakeErrorV1::RemoteInvalid)?;
        let mut held = HeldOriginalHostWorkerComparisonV1::capture(&mut self.0, &request)?;
        let mut transport = |action: Action<'_>| match action {
            Action::CheckCurrentness => {
                held.recheck()
                    .map_err(|_| HostError::Fence("original pending worker transport changed"))?;
                Ok(Progress::Checked)
            }
            Action::SendComparison { body, descriptors } => held
                .send(body, descriptors)
                .map_err(|_| HostError::Fence("original comparison send is uncertain")),
            Action::SendRendezvousReady { challenge } => held
                .send_rendezvous_ready(challenge)
                .map_err(|_| HostError::Fence("original rendezvous ready is uncertain")),
            Action::ReceiveRendezvousJoined { challenge } => held
                .receive_rendezvous_joined(challenge)
                .map_err(|_| HostError::Fence("original rendezvous join is uncertain")),
            Action::SendRendezvousConfirmed { challenge } => held
                .send_rendezvous_confirmed(challenge)
                .map_err(|_| HostError::Fence("original rendezvous confirmation is uncertain")),
            Action::SendKernelInitStart { challenge } => held
                .send_kernel_init_start(challenge)
                .map_err(|_| HostError::Fence("original kernel INIT scheduling is uncertain")),
            Action::ReceiveKernelIdmapApplied { challenge } => held
                .receive_kernel_idmap_applied(challenge)
                .map_err(|_| HostError::Fence("original kernel preparation is uncertain")),
            Action::SendKernelPreparationConfirmed { challenge } => held
                .send_kernel_preparation_confirmed(challenge)
                .map_err(|_| {
                    HostError::Fence("original kernel preparation confirmation is uncertain")
                }),
        };
        let sent = host
            .send_original_fuse_worker_comparison(&request, roles, &mut transport)
            .await
            .map_err(|_| DormantBrokerSessionHandshakeErrorV1::RemoteInvalid);
        drop(transport);
        // Host still retains its real launch on every error. Keep the pending
        // journal and occupied escrows; no terminal outcome is manufactured.
        let checked = held
            .recheck()
            .map_err(DormantBrokerSessionHandshakeErrorV1::from);
        drop(held);
        match sent.and(checked) {
            Ok(()) => Ok(OriginalHostWorkerComparisonSendProgressV1::Sent),
            Err(error) => Ok(
                OriginalHostWorkerComparisonSendProgressV1::ReconciliationRequired {
                    request: DormantReceivedBrokerRequestV1(request),
                    error,
                },
            ),
        }
    }

    /// Drives original role delivery, rendezvous and kernel-only preparation.
    ///
    /// The same outer Controller/Mount flight, actual Mount writer and original
    /// kernel-object bundle remain borrowed throughout. Deferred send returns
    /// real recovery ownership, never an eligible received comparison. A reply
    /// is only lent to the callback: no received data reconstructs Host or
    /// Mount authority. Kernel INIT and original idmap remain inside the same
    /// Host callback; neither completes readiness or a Root read grant. This
    /// entry selects no service/default advertisement.
    ///
    /// # Errors
    ///
    /// Rejects original preparation/signing/send failures, stale Mount/Host
    /// custody, substituted reply/roles, deadline or transport failure. Failed
    /// or lost replies preserve every durable obligation for reconciliation.
    pub(crate) fn with_original_mount_worker_host_comparison<W, F, R>(
        &mut self,
        request: &DormantReceivedBrokerRequestV1,
        mount: &mut MountBroker<W>,
        host_cgroup_root: &CgroupV2Root,
        host: &mut DormantAuthenticatedBrokerSessionV1,
        action: F,
    ) -> Result<OriginalMountHostWorkerComparisonProgressV1<R>, DormantBrokerSessionHandshakeErrorV1>
    where
        W: MountWorker,
        F: FnOnce(
            &mut PreparedMountFuseWorkerHandoffV1<'_, '_, W>,
            &DormantOriginalHostWorkerComparisonV1,
        ) -> Result<R, DormantBrokerSessionHandshakeErrorV1>,
    {
        let mut original = self.0.hold_fuse_intent_transport(&request.0)?;
        original.with_original_worker_handoff_transport(
            mount,
            host_cgroup_root,
            |original, handoff| {
                let progress = original.dispatch_original_host_worker(handoff, host)?;
                let outstanding = match progress {
                    OriginalMountHostWorkerDispatchV1::Transport(
                        DormantBrokerDescriptorRequestSendProgressV1::Sent(outstanding),
                    ) => outstanding,
                    deferred => {
                        return Ok(OriginalMountHostWorkerComparisonProgressV1::Deferred(
                            deferred,
                        ));
                    }
                };
                let mut held =
                    HeldOriginalHostWorkerComparisonV1::capture(&mut host.0, &outstanding.0)?;
                let reply = DormantOriginalHostWorkerComparisonV1(held.receive(handoff, original)?);
                // Consume the actual fresh record while both processes remain
                // in this same original nonterminal continuation. Returning
                // comparison bytes or pidfd copies alone never enters it.
                held.complete_mount_rendezvous(handoff, original, &reply.0)?;
                handoff
                    .recheck()
                    .map_err(|_| DormantBrokerSessionHandshakeErrorV1::RemoteInvalid)?;
                original.recheck()?;
                let result = action(handoff, &reply);
                held.recheck()?;
                handoff
                    .recheck()
                    .map_err(|_| DormantBrokerSessionHandshakeErrorV1::RemoteInvalid)?;
                original.recheck()?;
                result.map(OriginalMountHostWorkerComparisonProgressV1::Compared)
            },
        )
    }
}
