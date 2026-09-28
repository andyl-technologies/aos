//! Authenticated native Provider-to-Storage inspection and original-root delivery.
//!
//! The live Provider process submits one AOSZHQ01 or signed AOSZNQ02 per connection.
//! V1 drops its measured mount before descriptor-free AOSZHU01. Signed V2
//! independently pins Provider/RootMount authority, durably retains consumer
//! interest, and transfers exactly one original SourceRoot from live escrow.
//! Neither branch spends a Provider challenge or opens public Acquire.

use std::path::Path;

use aos_sandbox_linux::seqpacket::RecordSubjectListener;
use aos_sandbox_linux::seqpacket::SeqpacketError;
use aos_sandbox_source_provider_protocol::{
    MAXIMUM_SIGNED_STORAGE_NATIVE_ACQUIRE_REQUEST_BYTES_V2, SignedStorageNativeAcquireRequestV2,
    StorageZfsHoldTransportRequestV1, StorageZfsHoldUnavailableV1,
};

use crate::live_export_request_trust::StorageLiveExportRequestTrustV1;
use crate::peer::ProviderLiveExportPeerVerifier;
use crate::root_export::receive_request;
use crate::runtime::{StorageBrokerRuntime, StorageNativeDeliveryOutcomeV2, StorageRuntimeError};
use crate::service::StorageServiceError;
use crate::storage_zfs_hold_key::StorageZfsHoldKeyV1;
use crate::transport::boottime;

const REQUEST_RECEIVE_NANOSECONDS: u64 = 10_000_000_000;
const READBACK_NANOSECONDS: u64 = 180_000_000_000;

/// Reports whether one closed native request was authenticated and inspected.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum StorageZfsHoldTransportOutcomeV1 {
    /// Storage inspected the exact claim but granted no SourceRoot authority.
    Unavailable,
    /// Storage transferred the exact accepted original root and stable signed reply.
    Exported,
    /// The accepted interest and original root remain retained after uncertain send.
    SendAmbiguous,
    /// The connection, packet, protected cut, or physical mount failed closed.
    Rejected,
}

/// Inspects V1 or durably accepts one signed V2 original-root delivery.
///
/// # Errors
///
/// Returns a fatal error for a retired listener/cgroup, invalid clock, or a
/// Storage runtime requiring process reopen. Ordinary rejection closes only
/// the accepted child.
pub fn serve_zfs_hold_request_once(
    listener: &mut RecordSubjectListener,
    runtime: &mut StorageBrokerRuntime,
    verifier: &ProviderLiveExportPeerVerifier,
    authority_directory: &Path,
    key: Option<&StorageZfsHoldKeyV1>,
) -> Result<StorageZfsHoldTransportOutcomeV1, StorageServiceError> {
    if runtime.requires_reopen() {
        return Err(StorageRuntimeError::ReopenRequired.into());
    }
    verifier.validate_current()?;
    listener.validate_current()?;
    let mut connection = match listener.accept_descriptor_subject() {
        Ok(connection) => connection,
        Err(SeqpacketError::WouldBlock | SeqpacketError::Interrupted) => {
            return Ok(StorageZfsHoldTransportOutcomeV1::Rejected);
        }
        Err(_) => return Ok(StorageZfsHoldTransportOutcomeV1::Rejected),
    };
    let execution = match verifier.verify_connection(connection.peer()) {
        Ok(execution) => execution,
        Err(()) => return Ok(StorageZfsHoldTransportOutcomeV1::Rejected),
    };
    let receive_deadline = boottime()?
        .checked_add(REQUEST_RECEIVE_NANOSECONDS)
        .ok_or(StorageServiceError::Clock)?;
    let record = match receive_request(
        &mut connection,
        receive_deadline,
        MAXIMUM_SIGNED_STORAGE_NATIVE_ACQUIRE_REQUEST_BYTES_V2,
    ) {
        Ok(record) => record,
        Err(_) => return Ok(StorageZfsHoldTransportOutcomeV1::Rejected),
    };
    let record = match connection.bind_received(record) {
        Ok(record) => record,
        Err(_) => return Ok(StorageZfsHoldTransportOutcomeV1::Rejected),
    };
    if !record.descriptors().is_empty()
        || verifier
            .verify_record(execution, record.peer(), record.subject())
            .is_err()
    {
        return Ok(StorageZfsHoldTransportOutcomeV1::Rejected);
    }
    let request = match NativeRequestPacket::decode(record.payload()) {
        Ok(request) => request,
        Err(()) => return Ok(StorageZfsHoldTransportOutcomeV1::Rejected),
    };
    drop(record);
    let readback_deadline = boottime()?
        .checked_add(READBACK_NANOSECONDS)
        .ok_or(StorageServiceError::Clock)?;

    if let NativeRequestPacket::Signed(request) = &request {
        let trust = match StorageLiveExportRequestTrustV1::open_root_owned(authority_directory) {
            Ok(trust) => trust,
            Err(_) => return Ok(StorageZfsHoldTransportOutcomeV1::Rejected),
        };
        let authenticated = match trust.verify_native(request) {
            Ok(authenticated) => authenticated,
            Err(_) => return Ok(StorageZfsHoldTransportOutcomeV1::Rejected),
        };
        if let Some(key) = key {
            let outcome = runtime.with_native_acquire_delivery_v2(
                &authenticated,
                key,
                |bytes, mount, original_deadline| {
                    if verifier.verify_connection(connection.peer()) != Ok(execution)
                        || boottime().map_err(|_| ())? >= readback_deadline.min(original_deadline)
                    {
                        return Err(());
                    }
                    connection
                        .send_with_descriptors(bytes, &[mount])
                        .map_err(|_| ())
                },
            );
            match outcome {
                Ok(StorageNativeDeliveryOutcomeV2::Delivered) => {
                    return Ok(StorageZfsHoldTransportOutcomeV1::Exported);
                }
                Ok(StorageNativeDeliveryOutcomeV2::SendAmbiguous) => {
                    return Ok(StorageZfsHoldTransportOutcomeV1::SendAmbiguous);
                }
                Ok(StorageNativeDeliveryOutcomeV2::Unavailable) => {}
                Err(StorageRuntimeError::ReopenRequired) => {
                    return Err(StorageRuntimeError::ReopenRequired.into());
                }
                Err(_) => return Ok(StorageZfsHoldTransportOutcomeV1::Rejected),
            }
        }
        // Local escrow absence is NOT total custody loss. The Provider may
        // still hold the original; do not stamp absence or retire its interest.
        let response = StorageZfsHoldUnavailableV1::for_request(request.request().claims())
            .to_canonical_bytes();
        if verifier.verify_connection(connection.peer()) != Ok(execution)
            || boottime()? >= readback_deadline
            || connection.send(&response).is_err()
        {
            return Ok(StorageZfsHoldTransportOutcomeV1::Rejected);
        }
        return Ok(StorageZfsHoldTransportOutcomeV1::Unavailable);
    }
    let NativeRequestPacket::Legacy(request) = request else {
        return Ok(StorageZfsHoldTransportOutcomeV1::Rejected);
    };

    // Provider's catalog is a selection claim, not Storage authority. Only
    // the independently recovered Snapshot/hold cut can authorize the read.
    let (binding, _) = request.selection();
    let catalog = request.catalog();
    let (_, snapshot) = match catalog.select_under_head(
        catalog.generation(),
        catalog.digest(),
        catalog.namespace_digest(),
        binding,
    ) {
        Ok(selected) => selected,
        Err(_) => return Ok(StorageZfsHoldTransportOutcomeV1::Rejected),
    };
    let held = match runtime.observe_native_held_snapshot_claim_with_mount(&snapshot) {
        Ok(held) => held,
        Err(StorageRuntimeError::ReopenRequired) => {
            return Err(StorageRuntimeError::ReopenRequired.into());
        }
        Err(_) => return Ok(StorageZfsHoldTransportOutcomeV1::Rejected),
    };
    if held.verify_mount().is_err() {
        return Ok(StorageZfsHoldTransportOutcomeV1::Rejected);
    }
    // No descriptor, receipt, or retained authority escapes this inspection.
    drop(held);

    if verifier.verify_connection(connection.peer()) != Ok(execution)
        || boottime()? >= readback_deadline
    {
        return Ok(StorageZfsHoldTransportOutcomeV1::Rejected);
    }
    let response = StorageZfsHoldUnavailableV1::for_request(&request).to_canonical_bytes();
    if connection.send(&response).is_err() {
        return Ok(StorageZfsHoldTransportOutcomeV1::Rejected);
    }
    Ok(StorageZfsHoldTransportOutcomeV1::Unavailable)
}

enum NativeRequestPacket {
    Legacy(StorageZfsHoldTransportRequestV1),
    Signed(SignedStorageNativeAcquireRequestV2),
}

impl NativeRequestPacket {
    fn decode(bytes: &[u8]) -> Result<Self, ()> {
        match bytes.get(..8) {
            Some(b"AOSZHQ01") => StorageZfsHoldTransportRequestV1::from_canonical_bytes(bytes)
                .ok()
                .filter(|request| request.sequence() == 1)
                .map(Self::Legacy)
                .ok_or(()),
            Some(b"AOSZNQ02") => SignedStorageNativeAcquireRequestV2::from_canonical_bytes(bytes)
                .map(Self::Signed)
                .map_err(|_| ()),
            _ => Err(()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn native_v2_and_legacy_packets_keep_distinct_canonical_dispatch() {
        let request = crate::native_issuance::native_request_fixture_for_test().0;
        let native = request.to_canonical_bytes();
        assert!(matches!(
            NativeRequestPacket::decode(&native),
            Ok(NativeRequestPacket::Signed(_))
        ));
        let legacy = request.request().claims().to_canonical_bytes();
        assert!(matches!(
            NativeRequestPacket::decode(&legacy),
            Ok(NativeRequestPacket::Legacy(_))
        ));
        for invalid in [
            &native[..native.len() - 1],
            &legacy[..legacy.len() - 1],
            b"AOSZNQ01",
        ] {
            assert!(NativeRequestPacket::decode(invalid).is_err());
        }
    }

    #[test]
    fn native_carrier_sequence_is_exact_signed_identity_not_legacy_first_sequence() {
        let request = crate::native_issuance::native_request_fixture_for_test().0;
        let mut native = request.to_canonical_bytes();
        // The structural decoder accepts any canonical nonzero native carrier
        // sequence; protected trust still must reject this changed signature.
        native[36..44].copy_from_slice(&30_u64.to_be_bytes());
        assert!(matches!(
            NativeRequestPacket::decode(&native),
            Ok(NativeRequestPacket::Signed(_))
        ));
        let mut legacy = request.request().claims().to_canonical_bytes();
        legacy[16..24].copy_from_slice(&30_u64.to_be_bytes());
        assert!(NativeRequestPacket::decode(&legacy).is_err());
    }

    #[test]
    fn legacy_and_cold_unavailable_are_real_zero_fd_subject_records() {
        use aos_sandbox_linux::seqpacket::descriptor_subject::DescriptorSubjectSocket;
        let (left, right) = rustix::net::socketpair(
            rustix::net::AddressFamily::UNIX,
            rustix::net::SocketType::SEQPACKET,
            rustix::net::SocketFlags::CLOEXEC,
            None,
        )
        .unwrap();
        let mut sender = DescriptorSubjectSocket::from_owned(left).unwrap();
        let mut receiver = DescriptorSubjectSocket::from_owned(right).unwrap();
        let request = crate::native_issuance::native_request_fixture_for_test().0;
        let response = StorageZfsHoldUnavailableV1::for_request(request.request().claims())
            .to_canonical_bytes();
        for _ in 0..2 {
            sender.send(&response).unwrap();
            let record = receiver.receive(response.len(), 0).unwrap();
            assert_eq!(record.payload(), &response);
            assert!(record.descriptors().is_empty());
        }
        assert!(sender.send_with_descriptors(&response, &[]).is_err());
    }
}
