//! Canonical primitives for the lifecycle-worker wire format.

use aos_sandbox_core::BrokerVerb;

use crate::namespace_catalog::{
    NetworkNamespaceCatalogError, NetworkNamespaceLifecycleActionV1,
    NetworkNamespaceObservedStateKindV1, NetworkNamespaceObservedStateV1,
};
use crate::worker_protocol::NetworkWorkerProtocolError;

use super::{NetworkLifecycleDescriptorRoleV1, NetworkLifecycleWorkerRoleV1};

pub(super) const REQUEST_MAGIC: &[u8; 8] = b"AOSNLW01";
pub(super) const REQUEST_VERSION: u16 = 1;
pub(super) const REQUEST_HEADER_BYTES: usize = 100;
pub(super) const REQUEST_FIELD_COUNT: usize = 9;
pub(super) const CONTEXT_MAGIC: &[u8; 8] = b"AOSNLCX1";
pub(super) const CONTEXT_VERSION: u16 = 1;
pub(super) const CONTEXT_BYTES: usize = 398;

pub(super) const MAXIMUM_KERNEL_PLAN_BYTES: usize = 512 * 1024;
pub(super) const MAXIMUM_CATALOG_BYTES: usize = 16 * 1024;
pub(super) const MAXIMUM_AUTHORITY_RECORD_BYTES: usize = 1028 * 1024;
pub(super) const MAXIMUM_DISPATCH_RECORD_BYTES: usize = 64 * 1024;

/// Maximum encoded existing-resource request accepted by a future fixed worker.
pub const MAXIMUM_NETWORK_LIFECYCLE_WORKER_REQUEST_BYTES: usize = 5 * 1024 * 1024;

pub(super) fn encode_state(bytes: &mut Vec<u8>, state: NetworkNamespaceObservedStateV1) {
    bytes.push(state_code(state.kind()));
    if let Some((digest, generation, deadline)) = state.lease() {
        bytes.extend_from_slice(digest.as_bytes());
        bytes.extend_from_slice(&generation.to_be_bytes());
        bytes.extend_from_slice(&deadline.to_be_bytes());
    } else {
        bytes.extend_from_slice(&[0; 32]);
        bytes.extend_from_slice(&0_u64.to_be_bytes());
        bytes.extend_from_slice(&0_u64.to_be_bytes());
    }
}

pub(super) fn decode_state(
    decoder: &mut Decoder<'_>,
) -> Result<NetworkNamespaceObservedStateV1, NetworkWorkerProtocolError> {
    let kind = decoder.byte()?;
    let digest = aos_sandbox_core::ObjectDigest::from_bytes(decoder.take()?);
    let generation = decoder.u64()?;
    let deadline = decoder.u64()?;
    match kind {
        1 if digest.as_bytes() == &[0; 32] && generation == 0 && deadline == 0 => {
            Ok(NetworkNamespaceObservedStateV1::default_drop())
        }
        2 => NetworkNamespaceObservedStateV1::armed(digest, generation, deadline)
            .map_err(map_catalog_error),
        3 => NetworkNamespaceObservedStateV1::fenced(digest, generation, deadline)
            .map_err(map_catalog_error),
        4 if digest.as_bytes() == &[0; 32] && generation == 0 && deadline == 0 => {
            Ok(NetworkNamespaceObservedStateV1::absent())
        }
        _ => invalid("invalid lifecycle state"),
    }
}

fn map_catalog_error(_: NetworkNamespaceCatalogError) -> NetworkWorkerProtocolError {
    NetworkWorkerProtocolError::InvalidWire("invalid lifecycle state")
}

pub(super) const fn worker_role_code(role: NetworkLifecycleWorkerRoleV1) -> u8 {
    match role {
        NetworkLifecycleWorkerRoleV1::Mutation => 1,
    }
}

pub(super) fn decode_worker_role(
    value: u8,
) -> Result<NetworkLifecycleWorkerRoleV1, NetworkWorkerProtocolError> {
    match value {
        1 => Ok(NetworkLifecycleWorkerRoleV1::Mutation),
        _ => invalid("unknown lifecycle worker role"),
    }
}

pub(super) const fn descriptor_role_code(role: NetworkLifecycleDescriptorRoleV1) -> u8 {
    match role {
        NetworkLifecycleDescriptorRoleV1::TargetNamespace => 1,
    }
}

pub(super) fn decode_descriptor_role(
    value: u8,
) -> Result<NetworkLifecycleDescriptorRoleV1, NetworkWorkerProtocolError> {
    match value {
        1 => Ok(NetworkLifecycleDescriptorRoleV1::TargetNamespace),
        _ => invalid("unknown lifecycle descriptor role"),
    }
}

pub(super) const fn action_code(action: NetworkNamespaceLifecycleActionV1) -> u8 {
    match action {
        NetworkNamespaceLifecycleActionV1::Arm => 1,
        NetworkNamespaceLifecycleActionV1::Renew => 2,
        NetworkNamespaceLifecycleActionV1::Disarm => 3,
        NetworkNamespaceLifecycleActionV1::Fence => 4,
        NetworkNamespaceLifecycleActionV1::Destroy => 5,
    }
}

pub(super) fn decode_action(
    value: u8,
) -> Result<NetworkNamespaceLifecycleActionV1, NetworkWorkerProtocolError> {
    match value {
        1 => Ok(NetworkNamespaceLifecycleActionV1::Arm),
        2 => Ok(NetworkNamespaceLifecycleActionV1::Renew),
        3 => Ok(NetworkNamespaceLifecycleActionV1::Disarm),
        4 => Ok(NetworkNamespaceLifecycleActionV1::Fence),
        5 => Ok(NetworkNamespaceLifecycleActionV1::Destroy),
        _ => invalid("unknown lifecycle action"),
    }
}

pub(super) fn verb_code(verb: BrokerVerb) -> Result<u8, NetworkWorkerProtocolError> {
    match verb {
        BrokerVerb::NetworkArmLease => Ok(1),
        BrokerVerb::NetworkRenewLease => Ok(2),
        BrokerVerb::NetworkDisarm => Ok(3),
        BrokerVerb::NetworkDestroy => Ok(4),
        _ => invalid("invalid lifecycle verb"),
    }
}

pub(super) fn decode_verb(value: u8) -> Result<BrokerVerb, NetworkWorkerProtocolError> {
    match value {
        1 => Ok(BrokerVerb::NetworkArmLease),
        2 => Ok(BrokerVerb::NetworkRenewLease),
        3 => Ok(BrokerVerb::NetworkDisarm),
        4 => Ok(BrokerVerb::NetworkDestroy),
        _ => invalid("unknown lifecycle verb"),
    }
}

pub(super) const fn action_matches_verb(
    action: NetworkNamespaceLifecycleActionV1,
    verb: BrokerVerb,
) -> bool {
    matches!(
        (action, verb),
        (
            NetworkNamespaceLifecycleActionV1::Arm,
            BrokerVerb::NetworkArmLease
        ) | (
            NetworkNamespaceLifecycleActionV1::Renew,
            BrokerVerb::NetworkRenewLease
        ) | (
            NetworkNamespaceLifecycleActionV1::Disarm,
            BrokerVerb::NetworkDisarm
        ) | (
            NetworkNamespaceLifecycleActionV1::Destroy,
            BrokerVerb::NetworkDestroy
        )
    )
}

const fn state_code(state: NetworkNamespaceObservedStateKindV1) -> u8 {
    match state {
        NetworkNamespaceObservedStateKindV1::DefaultDrop => 1,
        NetworkNamespaceObservedStateKindV1::Armed => 2,
        NetworkNamespaceObservedStateKindV1::Fenced => 3,
        NetworkNamespaceObservedStateKindV1::Absent => 4,
    }
}

pub(super) fn validate_lengths(
    lengths: [usize; REQUEST_FIELD_COUNT],
    total: usize,
) -> Result<(), NetworkWorkerProtocolError> {
    let limits = [
        aos_sandbox_protocol::MAXIMUM_REQUEST_BYTES,
        MAXIMUM_KERNEL_PLAN_BYTES,
        MAXIMUM_CATALOG_BYTES,
        MAXIMUM_AUTHORITY_RECORD_BYTES,
        CONTEXT_BYTES,
        MAXIMUM_AUTHORITY_RECORD_BYTES,
        MAXIMUM_AUTHORITY_RECORD_BYTES,
        MAXIMUM_AUTHORITY_RECORD_BYTES,
        MAXIMUM_DISPATCH_RECORD_BYTES,
    ];
    if lengths
        .iter()
        .zip(limits)
        .any(|(length, limit)| *length == 0 || *length > limit)
        || lengths[4] != CONTEXT_BYTES
    {
        return Err(NetworkWorkerProtocolError::TooLarge);
    }
    let expected = lengths
        .iter()
        .try_fold(REQUEST_HEADER_BYTES, |sum, length| {
            sum.checked_add(*length)
                .ok_or(NetworkWorkerProtocolError::TooLarge)
        })?;
    if expected != total || total > MAXIMUM_NETWORK_LIFECYCLE_WORKER_REQUEST_BYTES {
        return Err(NetworkWorkerProtocolError::TooLarge);
    }
    Ok(())
}

pub(super) fn push_length(
    bytes: &mut Vec<u8>,
    length: usize,
) -> Result<(), NetworkWorkerProtocolError> {
    bytes.extend_from_slice(
        &u32::try_from(length)
            .map_err(|_| NetworkWorkerProtocolError::TooLarge)?
            .to_be_bytes(),
    );
    Ok(())
}

pub(super) fn invalid<T>(message: &'static str) -> Result<T, NetworkWorkerProtocolError> {
    Err(NetworkWorkerProtocolError::InvalidWire(message))
}

pub(super) struct Decoder<'a> {
    bytes: &'a [u8],
    offset: usize,
}

impl<'a> Decoder<'a> {
    pub(super) const fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, offset: 0 }
    }

    pub(super) fn take<const N: usize>(&mut self) -> Result<[u8; N], NetworkWorkerProtocolError> {
        self.bytes(N)?
            .try_into()
            .map_err(|_| NetworkWorkerProtocolError::InvalidWire("invalid fixed lifecycle field"))
    }

    pub(super) fn byte(&mut self) -> Result<u8, NetworkWorkerProtocolError> {
        Ok(self.take::<1>()?[0])
    }

    pub(super) fn u16(&mut self) -> Result<u16, NetworkWorkerProtocolError> {
        Ok(u16::from_be_bytes(self.take()?))
    }

    pub(super) fn u64(&mut self) -> Result<u64, NetworkWorkerProtocolError> {
        Ok(u64::from_be_bytes(self.take()?))
    }

    pub(super) fn usize_u32(&mut self) -> Result<usize, NetworkWorkerProtocolError> {
        Ok(u32::from_be_bytes(self.take()?) as usize)
    }

    pub(super) fn bytes(&mut self, length: usize) -> Result<&'a [u8], NetworkWorkerProtocolError> {
        let end = self
            .offset
            .checked_add(length)
            .ok_or(NetworkWorkerProtocolError::TooLarge)?;
        let value =
            self.bytes
                .get(self.offset..end)
                .ok_or(NetworkWorkerProtocolError::InvalidWire(
                    "truncated lifecycle payload",
                ))?;
        self.offset = end;
        Ok(value)
    }

    pub(super) fn finish(self) -> Result<(), NetworkWorkerProtocolError> {
        if self.offset == self.bytes.len() {
            Ok(())
        } else {
            invalid("trailing lifecycle payload")
        }
    }
}
