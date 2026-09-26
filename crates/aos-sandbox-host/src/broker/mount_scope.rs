//! Exact retained-scope admission before RootMount namespace/root export.
//!
//! The signed query cannot install a lease, renew a fence, or substitute a new
//! payload after reboot. All descriptor duplicates remain borrowed by the
//! prepared reply's live authority and kernel checks until the bounded send.

use std::os::fd::{AsFd as _, BorrowedFd, OwnedFd};

use aos_sandbox_broker::BrokerAdmissionError;
use aos_sandbox_core::RawPairedClockSample;
use aos_sandbox_linux::pidfd::{NamespaceFd, NamespaceKind};
use aos_sandbox_protocol::ProtocolValidationError;
use aos_sandbox_protocol::mount_scope::{ValidatedMountScopeRequest, encode_mount_scope_response};
use aos_sandbox_protocol::mount_scope_identity::{
    HostNamespaceIdentityV1, decode_mount_scope_identity_response_v1,
    encode_mount_scope_identity_response_v1,
};
use aos_sandbox_protocol::session::ValidatedUntrustedAuthorizationArtifacts;

use super::{HostBroker, ensure_response_bound, payload_scope::PreparedPayloadScopeReply};
use crate::plan::HostCatalog;
use crate::state::HostStateStore;
use crate::worker::HostWorker;
use crate::{HostError, Result};

impl<C: HostCatalog, S: HostStateStore, W: HostWorker + Sync> HostBroker<C, S, W> {
    /// Prepares method-45 readback without making it reachable from the live service.
    ///
    /// The response identities and the five duplicate descriptors come from
    /// one retained, type-checked payload pin. The signed query uses its own
    /// purpose; a method-13 grant cannot authorize this readback.
    pub(crate) async fn prepare_mount_scope_identity<T>(
        &mut self,
        artifacts: &ValidatedUntrustedAuthorizationArtifacts,
        request: &ValidatedMountScopeRequest,
        request_body: &[u8],
        clock: &mut T,
    ) -> Result<PreparedPayloadScopeReply<'_, 5>>
    where
        T: FnMut() -> Result<RawPairedClockSample> + Send,
    {
        let fence = request.fence();
        let identity = self.checked_scope_runtime(fence)?;
        let (prior, current) = self.open_scope_fence(fence)?;
        let observed = clock()?;
        let admitted = self.authority.admit_mount_scope_identity(
            artifacts,
            request,
            request_body,
            &observed,
            &prior,
        )?;
        if admitted.fence != current {
            return Err(HostError::Fence(
                "mount scope identity query does not match installed authority",
            ));
        }
        self.authority
            .check_before_effect(&admitted.effect, &mut || {
                clock().map_err(|_| BrokerAdmissionError::FenceRejected)
            })?;

        self.recover_completed_runtime_scope(identity).await?;
        self.refresh_payload_scope(identity).await?;
        self.retain_durable_scope_handle(identity)?;
        let pins = self
            .payload_pin(&identity)
            .ok_or(HostError::UnknownHandle)?;
        require_exact_scope_handle(request.payload_scope_handle(), &pins.scope_handle)?;
        pins.recheck_kernel()?;

        let mount = pins.payload.mount().identity();
        let user = pins.payload.user().identity();
        let body = encode_mount_scope_identity_response_v1(
            request,
            pins.payload.relative_cgroup_hint().as_bytes(),
            &observed.host_boot_id(),
            &pins.invocation_id,
            HostNamespaceIdentityV1::new(mount.device, mount.inode)?,
            HostNamespaceIdentityV1::new(user.device, user.inode)?,
        )?;
        ensure_response_bound(&body, request.header().maximum_response_bytes())?;

        let descriptors = [
            duplicate(pins.payload.pidfd().as_fd())?,
            duplicate(pins.payload.cgroup())?,
            duplicate(pins.payload.root())?,
            duplicate(pins.payload.mount().as_fd())?,
            duplicate(pins.payload.user().as_fd())?,
        ];
        verify_identity_readback(
            request,
            &body,
            &observed.host_boot_id(),
            &pins.invocation_id,
            &pins.scope_handle,
            descriptors[3].as_fd(),
            descriptors[4].as_fd(),
        )?;
        let reply = PreparedPayloadScopeReply {
            body,
            descriptors,
            pins,
            authority: &self.authority,
            effect: admitted.effect,
        };
        reply.check_before_send(clock)?;

        Ok(reply)
    }

    pub(crate) async fn prepare_mount_scope<T>(
        &mut self,
        artifacts: &ValidatedUntrustedAuthorizationArtifacts,
        request: &ValidatedMountScopeRequest,
        request_body: &[u8],
        clock: &mut T,
    ) -> Result<PreparedPayloadScopeReply<'_, 5>>
    where
        T: FnMut() -> Result<RawPairedClockSample> + Send,
    {
        let fence = request.fence();
        let identity = self.checked_scope_runtime(fence)?;
        let (prior, current) = self.open_scope_fence(fence)?;
        let admitted = self.authority.admit_mount_scope(
            artifacts,
            request,
            request_body,
            &clock()?,
            &prior,
        )?;
        if admitted.fence != current {
            return Err(HostError::Fence(
                "mount scope query does not match installed authority",
            ));
        }

        self.authority
            .check_before_effect(&admitted.effect, &mut || {
                clock().map_err(|_| BrokerAdmissionError::FenceRejected)
            })?;

        self.refresh_payload_scope(identity).await?;
        let pins = self
            .payload_pin(&identity)
            .ok_or(HostError::UnknownHandle)?;

        // Refresh may discover a replacement after reboot. It must never make
        // an old signed exact-scope query authorize that new payload.
        require_exact_scope_handle(request.payload_scope_handle(), &pins.scope_handle)?;
        pins.recheck_kernel()?;

        let body =
            encode_mount_scope_response(request, pins.payload.relative_cgroup_hint().as_bytes())?;
        ensure_response_bound(&body, request.header().maximum_response_bytes())?;

        let descriptors = [
            duplicate(pins.payload.pidfd().as_fd())?,
            duplicate(pins.payload.cgroup())?,
            duplicate(pins.payload.root())?,
            duplicate(pins.payload.mount().as_fd())?,
            duplicate(pins.payload.user().as_fd())?,
        ];

        let reply = PreparedPayloadScopeReply {
            body,
            descriptors,
            pins,
            authority: &self.authority,
            effect: admitted.effect,
        };
        reply.check_before_send(clock)?;

        Ok(reply)
    }

    /// Reopens RootMount descriptors for an exact protected terminal replay.
    ///
    /// No new effect admission or deadline renewal occurs. The protected
    /// assignment fence, retained payload scope, live kernel identities, and
    /// monotone boot clock are rechecked around physical readback.
    pub(crate) async fn reopen_mount_scope_for_terminal_replay<T>(
        &mut self,
        request: &ValidatedMountScopeRequest,
        clock: &mut T,
    ) -> Result<(Vec<u8>, Vec<OwnedFd>)>
    where
        T: FnMut() -> Result<RawPairedClockSample> + Send,
    {
        self.reopen_mount_scope_terminal(request, clock, false)
            .await
    }

    /// Reopens the exact method-45 body and FDs without minting a new grant.
    ///
    /// Cold recovery can remint the volatile scope handle. An old terminal
    /// replay then fails closed; durable same-handle lineage is a separate
    /// prerequisite for replay across a Host process restart.
    pub(crate) async fn reopen_mount_scope_identity_for_terminal_replay<T>(
        &mut self,
        request: &ValidatedMountScopeRequest,
        clock: &mut T,
    ) -> Result<(Vec<u8>, Vec<OwnedFd>)>
    where
        T: FnMut() -> Result<RawPairedClockSample> + Send,
    {
        self.reopen_mount_scope_terminal(request, clock, true).await
    }

    async fn reopen_mount_scope_terminal<T>(
        &mut self,
        request: &ValidatedMountScopeRequest,
        clock: &mut T,
        include_identity: bool,
    ) -> Result<(Vec<u8>, Vec<OwnedFd>)>
    where
        T: FnMut() -> Result<RawPairedClockSample> + Send,
    {
        let fence = request.fence();
        let identity = self.checked_scope_runtime(fence)?;
        let expected_assignment = fence
            .broker_assignment()
            .map_err(|_| HostError::UnknownHandle)?;
        let (prior, current) = self.open_scope_fence(fence)?;
        self.authority.check_current_fence(&current)?;
        if current.assignment() != expected_assignment {
            return Err(HostError::Fence(
                "mount scope replay does not match installed authority",
            ));
        }
        let observed = clock()?;

        if include_identity {
            self.recover_completed_runtime_scope(identity).await?;
        }
        self.refresh_payload_scope(identity).await?;
        let pins = self
            .payload_pin(&identity)
            .ok_or(HostError::UnknownHandle)?;
        require_exact_scope_handle(request.payload_scope_handle(), &pins.scope_handle)?;
        pins.recheck_kernel()?;
        let body = if include_identity {
            let mount = pins.payload.mount().identity();
            let user = pins.payload.user().identity();
            encode_mount_scope_identity_response_v1(
                request,
                pins.payload.relative_cgroup_hint().as_bytes(),
                &observed.host_boot_id(),
                &pins.invocation_id,
                HostNamespaceIdentityV1::new(mount.device, mount.inode)?,
                HostNamespaceIdentityV1::new(user.device, user.inode)?,
            )?
        } else {
            encode_mount_scope_response(request, pins.payload.relative_cgroup_hint().as_bytes())?
        };
        ensure_response_bound(&body, request.header().maximum_response_bytes())?;
        let descriptors = [
            duplicate(pins.payload.pidfd().as_fd())?,
            duplicate(pins.payload.cgroup())?,
            duplicate(pins.payload.root())?,
            duplicate(pins.payload.mount().as_fd())?,
            duplicate(pins.payload.user().as_fd())?,
        ];
        if include_identity {
            verify_identity_readback(
                request,
                &body,
                &observed.host_boot_id(),
                &pins.invocation_id,
                &pins.scope_handle,
                descriptors[3].as_fd(),
                descriptors[4].as_fd(),
            )?;
        }
        pins.recheck_kernel()?;
        let _after_readback = clock()?;
        let current_after = self.authority.open_fence(fence.sandbox_id(), &prior)?;
        self.authority.check_current_fence(&current_after)?;
        if current_after != current {
            return Err(HostError::Fence(
                "mount scope authority changed during replay readback",
            ));
        }

        Ok((body, Vec::from(descriptors)))
    }
}

fn duplicate(descriptor: BorrowedFd<'_>) -> Result<OwnedFd> {
    descriptor
        .try_clone_to_owned()
        .map_err(|source| HostError::Descriptor {
            operation: "clone retained mount-scope descriptor",
            source,
        })
}

fn require_exact_scope_handle(requested: &[u8; 32], retained: &[u8; 32]) -> Result<()> {
    // A cold recovery may remint a volatile scope handle. It must not turn an
    // old signed request or terminal replay into authority for those new pins.
    if requested != retained {
        return Err(HostError::UnknownHandle);
    }
    Ok(())
}

fn verify_identity_readback(
    request: &ValidatedMountScopeRequest,
    body: &[u8],
    host_boot_id: &[u8; 16],
    runtime_invocation_id: &[u8; 16],
    payload_scope_handle: &[u8; 32],
    mount_descriptor: BorrowedFd<'_>,
    user_descriptor: BorrowedFd<'_>,
) -> Result<()> {
    let response = decode_mount_scope_identity_response_v1(body, request)?;
    let mount = NamespaceFd::from_owned(duplicate(mount_descriptor)?, NamespaceKind::Mount)
        .map_err(|_| {
            HostError::Protocol(ProtocolValidationError::InvalidField(
                "retained mount namespace descriptor",
            ))
        })?;
    let user = NamespaceFd::from_owned(duplicate(user_descriptor)?, NamespaceKind::User).map_err(
        |_| {
            HostError::Protocol(ProtocolValidationError::InvalidField(
                "retained user namespace descriptor",
            ))
        },
    )?;
    let mount_identity = mount.identity();
    let user_identity = user.identity();

    if response.host_boot_id() != host_boot_id
        || response.runtime_invocation_id() != runtime_invocation_id
        || response.scope().payload_scope_handle() != payload_scope_handle
        || response.mount_namespace()
            != HostNamespaceIdentityV1::new(mount_identity.device, mount_identity.inode)?
        || response.user_namespace()
            != HostNamespaceIdentityV1::new(user_identity.device, user_identity.inode)?
    {
        return Err(HostError::Protocol(ProtocolValidationError::InvalidField(
            "retained mount-scope identity readback",
        )));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::fs::File;

    use aos_proto::aos::sandbox::local::v1::{
        AssignmentFence, Audience, ObserveMountScopeIdentityResponseV1, ObserveMountScopeRequest,
        RequestHeader,
    };
    use aos_sandbox_protocol::mount_scope::decode_mount_scope_request;
    use aos_sandbox_protocol::semantics::host::runtime_handle_v1;
    use aos_sandbox_protocol::{PeerCredentials, PeerPolicy};
    use buffa::Message as _;

    use super::*;

    #[test]
    fn identity_readback_rejects_altered_epochs_scope_and_received_namespace_fds() {
        let raw = ObserveMountScopeRequest {
            header: Some(RequestHeader {
                protocol_major: 1,
                protocol_minor: 0,
                request_id: vec![1; 16],
                audience: Audience::AUDIENCE_ROOT_MOUNT.into(),
                deadline_boottime_nanoseconds: 101,
                maximum_response_bytes: 8192,
                ..Default::default()
            })
            .into(),
            fence: Some(AssignmentFence {
                sandbox_id: vec![2; 16],
                incarnation_id: vec![3; 16],
                assignment_epoch: 1,
                desired_generation: 2,
                assignment_digest: vec![4; 32],
                ..Default::default()
            })
            .into(),
            runtime_handle: runtime_handle_v1(&[3; 16], 1, &[4; 32]).to_vec(),
            payload_scope_handle: vec![5; 32],
            ..Default::default()
        };
        let request = decode_mount_scope_request(
            &raw.encode_to_vec(),
            PeerCredentials {
                uid: 0,
                gid: 0,
                pid: Some(7),
            },
            PeerPolicy {
                uid: 0,
                gid: Some(0),
                audience: Audience::AUDIENCE_ROOT_MOUNT,
            },
            1,
        )
        .unwrap();
        let mount = NamespaceFd::from_owned(
            File::open("/proc/self/ns/mnt").unwrap().into(),
            NamespaceKind::Mount,
        )
        .unwrap();
        let user = NamespaceFd::from_owned(
            File::open("/proc/self/ns/user").unwrap().into(),
            NamespaceKind::User,
        )
        .unwrap();
        let mount_identity = mount.identity();
        let user_identity = user.identity();
        let boot_id = [8; 16];
        let invocation_id = [9; 16];
        let scope_handle = [5; 32];
        let body = encode_mount_scope_identity_response_v1(
            &request,
            b"payload.scope",
            &boot_id,
            &invocation_id,
            HostNamespaceIdentityV1::new(mount_identity.device, mount_identity.inode).unwrap(),
            HostNamespaceIdentityV1::new(user_identity.device, user_identity.inode).unwrap(),
        )
        .unwrap();
        let check = |body: &[u8], mount_fd, user_fd| {
            verify_identity_readback(
                &request,
                body,
                &boot_id,
                &invocation_id,
                &scope_handle,
                mount_fd,
                user_fd,
            )
        };

        assert!(check(&body, mount.as_fd(), user.as_fd()).is_ok());
        assert!(check(&body, user.as_fd(), mount.as_fd()).is_err());
        assert!(
            verify_identity_readback(
                &request,
                &body,
                &[7; 16],
                &invocation_id,
                &scope_handle,
                mount.as_fd(),
                user.as_fd(),
            )
            .is_err()
        );
        assert!(
            verify_identity_readback(
                &request,
                &body,
                &boot_id,
                &[7; 16],
                &[6; 32],
                mount.as_fd(),
                user.as_fd(),
            )
            .is_err()
        );

        let original = ObserveMountScopeIdentityResponseV1::decode_from_slice(&body).unwrap();
        let mutations: [fn(&mut ObserveMountScopeIdentityResponseV1); 7] = [
            |response| response.host_boot_id[0] ^= 1,
            |response| response.runtime_invocation_id[0] ^= 1,
            |response| response.payload_scope_handle[0] ^= 1,
            |response| response.mount_namespace_device += 1,
            |response| response.mount_namespace_inode += 1,
            |response| response.user_namespace_device += 1,
            |response| response.user_namespace_inode += 1,
        ];
        for mutate in mutations {
            let mut changed = original.clone();
            mutate(&mut changed);
            assert!(check(&changed.encode_to_vec(), mount.as_fd(), user.as_fd()).is_err());
        }
    }

    #[test]
    fn reminted_scope_handle_cannot_reopen_an_old_signed_query() {
        let old_signed_handle = [5; 32];
        let recovered_new_handle = [6; 32];

        assert!(require_exact_scope_handle(&old_signed_handle, &old_signed_handle).is_ok());
        assert!(matches!(
            require_exact_scope_handle(&old_signed_handle, &recovered_new_handle),
            Err(HostError::UnknownHandle)
        ));
    }
}
