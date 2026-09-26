//! Closed Storage client for an independently authenticated Host cgroup readback.
//!
//! This owner connects only through the fixed Storage-to-Host signed session.
//! The retained Storage plan was separately checked against both signers and
//! the current export catalog and an initial physical workspace observation.
//! Method 34 remains absent from the
//! production hello, so this type has no request-send or FD-egress operation.

use std::fs::File;
use std::path::Path;

use aos_proto::aos::sandbox::local::v1::{Audience, BrokerMethod};
use aos_sandbox_broker_session_protocol::{
    BrokerSessionProtocolV1, authenticated_broker_methods_for_role_v1,
};
use aos_sandbox_linux::boot::KernelBootId;
use aos_sandbox_linux::cgroup::{CgroupV2Root, RetainedCgroupAnchor};
use aos_sandbox_linux::pidfd::{PidFd, PidFdInfo};
use aos_sandbox_protocol::host_consumer_cgroup::ValidatedConsumerCgroupRequestV1;
use aos_sandbox_storage::StorageLiveExportReadbackV1;
use rustix::time::{ClockId, clock_gettime};

use crate::{
    BrokerSessionSecurityError, DormantAuthenticatedBrokerSessionV1,
    DormantBrokerSessionHandshakeErrorV1, ProtectedBrokerSessionFixedCustodyV1,
    ProtectedBrokerSessionFixedEndpointV1, ProtectedHostConsumerCgroupTransferV1,
    ProtectedHostStorageConsumerJoinErrorV1, ProtectedHostStorageConsumerJoinV1,
};

const HOST_SERVICE_CGROUP: &str = "aos.slice/aos-control.slice/aos-sandbox-hostd.service";

/// Reports failure of the closed signed Storage-to-Host client preflight.
#[derive(Debug, thiserror::Error)]
pub enum StorageHostConsumerClientErrorV1 {
    /// The method has become advertised before the grant protocol was completed.
    #[error("Host consumer-cgroup method is not closed in the production profile")]
    ProfileOpen,
    /// The fixed Host/Storage role has no admissible signed method yet.
    #[error("Host/Storage signed-session profile has no admissible methods")]
    ProfileClosed,
    /// The independently signed Storage plan or catalog row became stale.
    #[error("Storage live-export signer or catalog is no longer current")]
    StorageCurrentness,
    /// Fixed signed-session custody could not be loaded.
    #[error("Storage-to-Host protected custody failed: {0}")]
    Custody(#[from] BrokerSessionSecurityError),
    /// The fixed signed Host handshake did not complete.
    #[error("Storage-to-Host signed handshake failed: {0}")]
    Handshake(#[from] DormantBrokerSessionHandshakeErrorV1),
    /// The authenticated Host process left its exact service identity.
    #[error("authenticated Host service process is not current")]
    HostPeer,
    /// The candidate Host query does not match Storage's signed consumer.
    #[error("Host query differs from Storage's signed consumer claim")]
    Query,
    /// The signed terminal, Host kernel pins, or Storage claim did not join.
    #[error("Host and Storage consumer join failed: {0}")]
    Join(#[from] ProtectedHostStorageConsumerJoinErrorV1),
}

/// Retains fixed signed Host-session custody beside Storage's signed catalog pins.
///
/// No public socket, session, request-send, or descriptor accessor exists.
/// This owner cannot produce a LocalLive grant or kernel handoff.
#[must_use = "retain the signed Host session and Storage catalog pins together"]
pub struct StorageHostConsumerClientV1 {
    session: DormantAuthenticatedBrokerSessionV1,
    readback: Option<StorageLiveExportReadbackV1>,
    host_process: PidFd,
    host_service: RetainedCgroupAnchor,
    host_info: PidFdInfo,
    boot_id: KernelBootId,
}

impl StorageHostConsumerClientV1 {
    /// Connects the fixed Storage audience to Host under signed BSA custody.
    ///
    /// The method profile is checked before connecting and after the handshake.
    /// No method-34 request can be sent while the grant path remains incomplete.
    /// Today the Storage role has no other advertised method, so this returns
    /// `ProfileClosed` before opening a socket. No empty-method handshake is
    /// substituted for the existing signed BSA profile.
    ///
    /// # Errors
    ///
    /// Rejects premature method advertisement, stale signed Storage inputs,
    /// invalid fixed custody or handshake, or a substituted Host service peer.
    pub fn connect_closed(
        readback: StorageLiveExportReadbackV1,
        deadline_boottime_nanoseconds: u64,
    ) -> Result<Self, StorageHostConsumerClientErrorV1> {
        require_closed_profile()?;
        readback
            .revalidate_signer_catalog_currentness()
            .map_err(|_| StorageHostConsumerClientErrorV1::StorageCurrentness)?;

        let custody = ProtectedBrokerSessionFixedCustodyV1::open_fixed_protected(
            ProtectedBrokerSessionFixedEndpointV1::StorageHostClient,
        )?;
        let mut session =
            custody.connect_production_client_session(deadline_boottime_nanoseconds)?;
        let (host_process, host_service, host_info) = open_host_peer(&mut session)?;
        let boot_id =
            KernelBootId::current().map_err(|_| StorageHostConsumerClientErrorV1::HostPeer)?;

        readback
            .revalidate_signer_catalog_currentness()
            .map_err(|_| StorageHostConsumerClientErrorV1::StorageCurrentness)?;
        require_closed_profile()?;
        Ok(Self {
            session,
            readback: Some(readback),
            host_process,
            host_service,
            host_info,
            boot_id,
        })
    }

    /// Rechecks signed Storage publication and the exact authenticated Host peer.
    ///
    /// # Errors
    ///
    /// Rejects profile exposure, replaced broker-session peer, reboot, retired
    /// Host service process, or stale signer/catalog custody.
    pub fn recheck(&mut self) -> Result<(), StorageHostConsumerClientErrorV1> {
        require_closed_profile()?;
        self.readback
            .as_ref()
            .ok_or(StorageHostConsumerClientErrorV1::StorageCurrentness)?
            .revalidate_signer_catalog_currentness()
            .map_err(|_| StorageHostConsumerClientErrorV1::StorageCurrentness)?;
        if KernelBootId::current().map_err(|_| StorageHostConsumerClientErrorV1::HostPeer)?
            != self.boot_id
        {
            return Err(StorageHostConsumerClientErrorV1::HostPeer);
        }
        let current = self
            .host_service
            .verify_exact_membership(&self.host_process)
            .map_err(|_| StorageHostConsumerClientErrorV1::HostPeer)?;
        if current != self.host_info {
            return Err(StorageHostConsumerClientErrorV1::HostPeer);
        }
        let (peer, _, info) = open_host_peer(&mut self.session)?;
        if info != self.host_info
            || self.host_service.verify_exact_membership(&peer).ok() != Some(self.host_info)
        {
            return Err(StorageHostConsumerClientErrorV1::HostPeer);
        }
        self.readback
            .as_ref()
            .ok_or(StorageHostConsumerClientErrorV1::StorageCurrentness)?
            .revalidate_signer_catalog_currentness()
            .map_err(|_| StorageHostConsumerClientErrorV1::StorageCurrentness)
    }

    /// Checks a candidate method-34 query against the independently signed name.
    ///
    /// This comparison does not sign or send the query. Host must still prove
    /// the exact current retained scope and physical cgroup, and Controller
    /// must separately prove the current Attachment before any grant.
    ///
    /// # Errors
    ///
    /// Rejects stale signed or kernel pins, a changed assignment/boot, or a
    /// query whose deadline has already expired in Host's decoder.
    pub fn preflight_query(
        &mut self,
        query: &ValidatedConsumerCgroupRequestV1,
    ) -> Result<(), StorageHostConsumerClientErrorV1> {
        self.recheck()?;
        let now = clock_gettime(ClockId::Boottime);
        let seconds =
            u64::try_from(now.tv_sec).map_err(|_| StorageHostConsumerClientErrorV1::Query)?;
        let nanoseconds =
            u64::try_from(now.tv_nsec).map_err(|_| StorageHostConsumerClientErrorV1::Query)?;
        let now = seconds
            .checked_mul(1_000_000_000)
            .and_then(|value| value.checked_add(nanoseconds))
            .ok_or(StorageHostConsumerClientErrorV1::Query)?;
        if now >= query.header().deadline_boottime_nanoseconds() {
            return Err(StorageHostConsumerClientErrorV1::Query);
        }
        if !self
            .readback
            .as_ref()
            .ok_or(StorageHostConsumerClientErrorV1::StorageCurrentness)?
            .matches_unexpired_host_assignment(*query.fence(), self.boot_id)
        {
            return Err(StorageHostConsumerClientErrorV1::Query);
        }
        self.recheck()
    }

    /// Joins a same-session signed Host receipt to the retained Storage plan.
    ///
    /// This remains unreachable through the production profile. The receipt
    /// itself contains the exact signed terminal and inseparable FD pair; a
    /// response from another session fails its protected journal-head check.
    ///
    /// # Errors
    ///
    /// Rejects stale signed, peer, physical, or named-consumer currentness.
    pub fn join_receipt(
        &mut self,
        transfer: ProtectedHostConsumerCgroupTransferV1,
    ) -> Result<ProtectedHostStorageConsumerJoinV1<'_>, StorageHostConsumerClientErrorV1> {
        self.recheck()?;
        let readback = self
            .readback
            .take()
            .ok_or(StorageHostConsumerClientErrorV1::StorageCurrentness)?;
        transfer
            .join_storage(&mut self.session, readback)
            .map_err(Into::into)
    }
}

fn require_closed_profile() -> Result<(), StorageHostConsumerClientErrorV1> {
    let methods = authenticated_broker_methods_for_role_v1(
        BrokerSessionProtocolV1::Host,
        Audience::AUDIENCE_STORAGE_BROKER,
    );
    if methods.contains(&BrokerMethod::BROKER_METHOD_HOST_OBSERVE_CONSUMER_CGROUP) {
        return Err(StorageHostConsumerClientErrorV1::ProfileOpen);
    }
    if methods.is_empty() {
        return Err(StorageHostConsumerClientErrorV1::ProfileClosed);
    }
    Ok(())
}

fn open_host_peer(
    session: &mut DormantAuthenticatedBrokerSessionV1,
) -> Result<(PidFd, RetainedCgroupAnchor, PidFdInfo), StorageHostConsumerClientErrorV1> {
    let descriptor = session.retain_authenticated_peer_pidfd()?;
    let peer =
        PidFd::from_owned(descriptor).map_err(|_| StorageHostConsumerClientErrorV1::HostPeer)?;
    let root = CgroupV2Root::from_owned(
        File::open("/sys/fs/cgroup")
            .map_err(|_| StorageHostConsumerClientErrorV1::HostPeer)?
            .into(),
    )
    .map_err(|_| StorageHostConsumerClientErrorV1::HostPeer)?;
    let service = root
        .resolve(Path::new(HOST_SERVICE_CGROUP))
        .map_err(|_| StorageHostConsumerClientErrorV1::HostPeer)?;
    let info = service
        .verify_exact_membership(&peer)
        .map_err(|_| StorageHostConsumerClientErrorV1::HostPeer)?;
    let credentials = info
        .credentials()
        .ok_or(StorageHostConsumerClientErrorV1::HostPeer)?;
    if info.pid() != info.thread_group_id()
        || credentials.real_user_id() != 0
        || credentials.real_group_id() != 0
        || credentials.effective_user_id() != 0
        || credentials.effective_group_id() != 0
        || credentials.saved_user_id() != 0
        || credentials.saved_group_id() != 0
        || credentials.filesystem_user_id() != 0
        || credentials.filesystem_group_id() != 0
    {
        return Err(StorageHostConsumerClientErrorV1::HostPeer);
    }
    Ok((peer, service, info))
}

#[cfg(test)]
mod tests {
    use super::*;
    use aos_sandbox_broker_session_protocol::{
        BrokerSessionNegotiationError, production_broker_client_hello_v1,
    };

    #[test]
    fn storage_host_consumer_client_stays_closed_in_production_profile() {
        assert!(matches!(
            require_closed_profile(),
            Err(StorageHostConsumerClientErrorV1::ProfileClosed)
        ));
        assert!(
            !authenticated_broker_methods_for_role_v1(
                BrokerSessionProtocolV1::Host,
                Audience::AUDIENCE_STORAGE_BROKER,
            )
            .contains(&BrokerMethod::BROKER_METHOD_HOST_OBSERVE_CONSUMER_CGROUP)
        );
        assert!(matches!(
            production_broker_client_hello_v1(
                BrokerSessionProtocolV1::Host,
                Audience::AUDIENCE_STORAGE_BROKER,
                8192,
            ),
            Err(BrokerSessionNegotiationError::Methods)
        ));
    }
}
