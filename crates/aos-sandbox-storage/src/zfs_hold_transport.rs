//! Authenticated native Provider-to-Storage inspection and original-root delivery.
//!
//! The live Provider process submits one native request per connection.
//! V1 drops its measured mount before descriptor-free AOSZHU01. Signed V2
//! independently pins Provider/RootMount authority, durably retains consumer
//! interest, and transfers exactly one original SourceRoot from live escrow.
//! Neither branch spends a Provider challenge or opens public Acquire.
//! AOSZNR01 instead reads historical unsigned acceptance metadata and always
//! replies without descriptors. Its sequence/nonce correlate the outstanding
//! query; no readback grants latest-state, custody, or retirement authority.

use std::path::Path;

use aos_sandbox_linux::seqpacket::RecordSubjectListener;
use aos_sandbox_linux::seqpacket::SeqpacketError;
use aos_sandbox_source_provider_protocol::{
    MAXIMUM_SIGNED_STORAGE_NATIVE_ACQUIRE_REQUEST_BYTES_V2,
    SignedStorageNativeAcceptanceReadbackQueryV1, SignedStorageNativeAcquireRequestV2,
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

/// Receives Root1 and its exact request into the selected original carrier.
///
/// This is separate from the unchanged V1/V2/metadata dispatcher. A returned
/// child, record, subject and parsed body enter the carrier before the next
/// fallible gate. The one original receive deadline is never renewed.
///
/// # Errors
///
/// Returns reopen-required after retaining the actual first cause and all
/// returned carrier custody in the selected runtime. Lower consuming failure
/// prefixes remain lower-layer functional obligations.
pub(crate) fn serve_original_held_offer_once(
    listener: &mut RecordSubjectListener,
    runtime: &mut StorageBrokerRuntime,
    verifier: &ProviderLiveExportPeerVerifier,
    trust: &crate::runtime::StorageOriginalNativeTrustLoanV1<'_>,
    key: &StorageZfsHoldKeyV1,
) -> Result<StorageZfsHoldTransportOutcomeV1, StorageServiceError> {
    use crate::runtime::original_held_measurement::{
        OriginalHeldMeasurementErrorV3 as Error, OriginalHeldRecordV1,
    };
    use aos_sandbox_source_provider_protocol::native_held_completion::{
        MAXIMUM_NATIVE_HELD_CONTROL_BYTES_V1,
        frame::SignedNativeHeldControlV1,
    };

    let mut carrier = runtime.begin_original_held_carrier()?;
    let _crossing = carrier.unwind_fence();
    let received = (|| {
        verifier.validate_current()?;
        listener.validate_current()?;
        carrier.child = Some(listener.accept_retaining()
            .map_err(|cause| Error::HeldAdmission(Box::new(cause)))?);
        let child = carrier.child.as_ref().ok_or(Error::Closed)?;
        carrier.execution = Some(verifier.verify_connection_typed(child.peer())?);
        let deadline = boottime()?.checked_add(REQUEST_RECEIVE_NANOSECONDS)
            .ok_or(StorageServiceError::Clock)?;

        for (index, maximum) in [
            MAXIMUM_NATIVE_HELD_CONTROL_BYTES_V1,
            MAXIMUM_SIGNED_STORAGE_NATIVE_ACQUIRE_REQUEST_BYTES_V2,
        ].into_iter().enumerate() {
            let child = carrier.child.as_mut().ok_or(Error::Closed)?;
            wait_original_record(child.as_fd()?, deadline)?;
            carrier.pending_record = Some(child.receive_retaining(maximum)
                .map_err(|cause| Error::HeldReceive(Box::new(cause)))?);
            let record = carrier.pending_record.take().ok_or(Error::Closed)?;
            let bound = match child.bind_received_retaining(record) {
                Ok(bound) => bound,
                Err((cause, record)) => {
                    carrier.pending_record = Some(record);
                    return Err(Error::HeldBinding(cause));
                }
            };
            let (bytes, subject, _) = bound.into_parts();
            carrier.records[index] = Some(OriginalHeldRecordV1 { bytes, subject });
            let record = carrier.records[index].as_ref().ok_or(Error::Closed)?;
            verifier.verify_record_typed(
                carrier.execution.ok_or(Error::Closed)?, child.peer(), &record.subject,
            )?;
            if index == 0 {
                carrier.root = Some(SignedNativeHeldControlV1::from_canonical_bytes(&record.bytes)?);
            } else {
                carrier.request = Some(SignedStorageNativeAcquireRequestV2::from_canonical_bytes(&record.bytes)?);
            }
            if boottime()? >= deadline {
                return Err(Error::Closed);
            }
        }
        trust.owner.require_original_root_prepared(
            carrier.root.as_ref().ok_or(Error::Closed)?,
            carrier.request.as_ref().ok_or(Error::Closed)?, key.verifier(),
        )?;
        Ok::<_, Error>(())
    })();
    if let Err(cause) = received {
        runtime.retain_original_held_carrier_failure(carrier, cause);
        return Err(StorageRuntimeError::ReopenRequired.into());
    }
    runtime.offer_original_held_native(carrier, trust.owner, verifier, key)
        .map(|outcome| match outcome {
            StorageNativeDeliveryOutcomeV2::Delivered => StorageZfsHoldTransportOutcomeV1::Exported,
            StorageNativeDeliveryOutcomeV2::SendAmbiguous => StorageZfsHoldTransportOutcomeV1::SendAmbiguous,
            StorageNativeDeliveryOutcomeV2::Unavailable => StorageZfsHoldTransportOutcomeV1::Unavailable,
        }).map_err(Into::into)
}

// Polling borrows the same child. It neither consumes a record nor retries a
// retaining receive whose actual lower cause already owns ambiguous custody.
fn wait_original_record(
    fd: std::os::fd::BorrowedFd<'_>, deadline: u64,
) -> Result<(), crate::runtime::original_held_measurement::OriginalHeldMeasurementErrorV3> {
    use crate::runtime::original_held_measurement::OriginalHeldMeasurementErrorV3 as Error;
    use rustix::event::{PollFd, PollFlags, Timespec, poll};

    loop {
        let remaining = deadline.checked_sub(boottime()?).filter(|value| *value > 0)
            .ok_or(Error::Closed)?;
        let timeout = Timespec::try_from(std::time::Duration::from_nanos(remaining))
            .map_err(|_| Error::Closed)?;
        let mut ready = [PollFd::from_borrowed_fd(fd, PollFlags::IN)];
        match poll(&mut ready, Some(&timeout)) {
            Err(rustix::io::Errno::INTR) => continue,
            Err(cause) => return Err(StorageServiceError::from(cause).into()),
            Ok(_) if ready[0].revents().contains(PollFlags::IN) => return Ok(()),
            Ok(_) => return Err(Error::Closed),
        }
    }
}

/// Reports whether one closed native request was authenticated and inspected.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum StorageZfsHoldTransportOutcomeV1 {
    /// Storage inspected the exact claim but granted no SourceRoot authority.
    Unavailable,
    /// Storage transferred the exact accepted original root and stable signed reply.
    Exported,
    /// The accepted interest and original root remain retained after uncertain send.
    SendAmbiguous,
    /// Storage returned historical unsigned acceptance metadata with zero FDs.
    MetadataReadback,
    /// The connection, packet, protected cut, or physical mount failed closed.
    Rejected,
}

/// Inspects native claims, delivers an original root, or reads historical metadata.
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

    if let NativeRequestPacket::Readback(query) = &request {
        let trust = match StorageLiveExportRequestTrustV1::open_root_owned(authority_directory) {
            Ok(trust) => trust,
            Err(_) => return Ok(StorageZfsHoldTransportOutcomeV1::Rejected),
        };
        let authenticated = match trust.verify_native_readback(query) {
            Ok(authenticated) => authenticated,
            Err(_) => return Ok(StorageZfsHoldTransportOutcomeV1::Rejected),
        };
        let Some(key) = key else {
            return Ok(StorageZfsHoldTransportOutcomeV1::Rejected);
        };
        let outcome = runtime.with_native_acceptance_readback_v1(&authenticated, key, |bytes| {
            if verifier.verify_connection(connection.peer()) != Ok(execution)
                || boottime().map_err(|_| ())? >= readback_deadline
            {
                return Err(());
            }
            // `.send` emits a descriptor-free subject record; the descriptor
            // API must never be used to manufacture an empty SCM_RIGHTS list.
            connection.send(bytes).map_err(|_| ())
        });
        return match outcome {
            Ok(()) => Ok(StorageZfsHoldTransportOutcomeV1::MetadataReadback),
            Err(StorageRuntimeError::ReopenRequired) => {
                Err(StorageRuntimeError::ReopenRequired.into())
            }
            Err(_) => Ok(StorageZfsHoldTransportOutcomeV1::Rejected),
        };
    }

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
    Readback(SignedStorageNativeAcceptanceReadbackQueryV1),
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
            Some(b"AOSZNR01") => {
                SignedStorageNativeAcceptanceReadbackQueryV1::from_canonical_bytes(bytes)
                    .map(Self::Readback)
                    .map_err(|_| ())
            }
            _ => Err(()),
        }
    }
}

#[cfg(test)]
mod tests {
    use aos_sandbox_linux::seqpacket::descriptor_subject::DescriptorSubjectSocket;
    use aos_sandbox_source_provider_protocol::{
        SourceProviderKeyUsageV1, SourceProviderSigningKeyV1,
        StorageNativeAcceptanceReadbackQueryV1,
    };
    use ed25519_dalek::SigningKey;

    use super::*;

    fn metadata_query() -> SignedStorageNativeAcceptanceReadbackQueryV1 {
        let request = crate::native_issuance::native_metadata_request_fixture_for_test();
        let key = SigningKey::from_bytes(&[32; 32]);
        let signer = SourceProviderSigningKeyV1::for_signing_key(
            [30; 16],
            1,
            aos_sandbox_core::ObjectDigest::from_bytes([33; 32]),
            [34; 16],
            1,
            SourceProviderKeyUsageV1::ProviderOutcome,
            &key,
        )
        .unwrap();
        let query = StorageNativeAcceptanceReadbackQueryV1::new(
            30,
            aos_sandbox_core::ObjectDigest::from_bytes([90; 32]),
            [91; 32],
            &request,
        )
        .unwrap();
        SignedStorageNativeAcceptanceReadbackQueryV1::sign(query, signer, &key).unwrap()
    }

    fn subject_pair() -> (DescriptorSubjectSocket, DescriptorSubjectSocket) {
        let (left, right) = rustix::net::socketpair(
            rustix::net::AddressFamily::UNIX,
            rustix::net::SocketType::SEQPACKET,
            rustix::net::SocketFlags::CLOEXEC,
            None,
        )
        .unwrap();
        (
            DescriptorSubjectSocket::from_owned(left).unwrap(),
            DescriptorSubjectSocket::from_owned(right).unwrap(),
        )
    }

    #[test]
    fn native_metadata_transport_keeps_exact_canonical_dispatch_separate_from_acquire() {
        let bytes = metadata_query().to_canonical_bytes();
        assert!(matches!(
            NativeRequestPacket::decode(&bytes),
            Ok(NativeRequestPacket::Readback(_))
        ));
        assert!(NativeRequestPacket::decode(&bytes[..bytes.len() - 1]).is_err());
        let mut extra = bytes.to_vec();
        extra.push(0);
        assert!(NativeRequestPacket::decode(&extra).is_err());
        for offset in [8, 10] {
            let mut malformed = bytes.clone();
            malformed[offset] ^= 1;
            assert!(NativeRequestPacket::decode(&malformed).is_err());
        }
    }

    #[test]
    fn native_metadata_transport_receives_a_real_zero_fd_subject_record() {
        let query = metadata_query().to_canonical_bytes();
        let (mut sender, mut receiver) = subject_pair();
        sender.send(&query).unwrap();
        let record = receive_request(
            &mut receiver,
            boottime().unwrap() + REQUEST_RECEIVE_NANOSECONDS,
            MAXIMUM_SIGNED_STORAGE_NATIVE_ACQUIRE_REQUEST_BYTES_V2,
        )
        .unwrap();
        let record = receiver.bind_received(record).unwrap();
        assert_eq!(record.payload(), query);
        assert!(record.descriptors().is_empty());
        assert!(matches!(
            NativeRequestPacket::decode(record.payload()),
            Ok(NativeRequestPacket::Readback(_))
        ));
    }

    #[test]
    fn native_metadata_transport_rejects_one_or_extra_inbound_scm_rights() {
        use std::os::fd::AsFd as _;

        let directory = tempfile::tempdir().unwrap();
        let first = std::fs::File::create(directory.path().join("first")).unwrap();
        let second = std::fs::File::create(directory.path().join("second")).unwrap();
        let query = metadata_query().to_canonical_bytes();
        let descriptors = [first.as_fd(), second.as_fd()];
        for count in [1, 2] {
            let (mut sender, mut receiver) = subject_pair();
            sender
                .send_with_descriptors(&query, &descriptors[..count])
                .unwrap();
            assert!(
                receive_request(
                    &mut receiver,
                    boottime().unwrap() + REQUEST_RECEIVE_NANOSECONDS,
                    MAXIMUM_SIGNED_STORAGE_NATIVE_ACQUIRE_REQUEST_BYTES_V2,
                )
                .is_err()
            );
        }
    }

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
