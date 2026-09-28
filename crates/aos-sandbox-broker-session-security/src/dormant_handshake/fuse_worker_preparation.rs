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
    DormantAuthenticatedBrokerSessionV1, DormantBrokerSessionHandshakeErrorV1,
    DormantReceivedBrokerRequestV1,
};

impl DormantAuthenticatedBrokerSessionV1 {
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
