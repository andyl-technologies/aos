//! Canonical portable authority semantics for network effects.
//!
//! Network V1 encodes tagged, length-delimited fields in ascending tag order:
//!
//! ```text
//! field := tag:u8 || length:u32be || value:length
//! fields := magic, version, action, assignment fence, optional network handle,
//!           ordered endpoint IDs
//! ```
//!
//! Interface names, ifindexes, namespaces, nftables expressions, host paths,
//! request IDs, response ceilings, ownership-lease digests and generations,
//! and absolute `CLOCK_BOOTTIME` values never enter portable signed semantics.
//! The complete validated lease tuple remains an attempt-local request fact
//! which a future broker must compare with the separately verified lease and
//! durable monotonic fence immediately before each effect.

use aos_proto::aos::sandbox::local::v1::{ApplyNetworkRequest, NetworkAction};
use aos_sandbox_core::{
    BrokerArgumentCommitment, BrokerGrantTarget, BrokerResourceHandle, BrokerVerb, ProtocolId,
};
use buffa::Message as _;

use crate::{
    MAXIMUM_REQUEST_BYTES, PeerCredentials, PeerPolicy, ProtocolValidationError,
    ValidatedAssignmentFence, ValidatedHeader, exact_nonzero, validate_fence,
    validate_request_header,
};

const FORMAT_MAGIC: &[u8; 8] = b"AOSNSEM1";
const FORMAT_VERSION: u16 = 1;
const MAXIMUM_CANONICAL_BYTES: usize = 16 * 1024;
/// Maximum logical endpoint resources accepted by one network preparation.
pub const MAXIMUM_NETWORK_ENDPOINTS: usize = 256;

/// Reports a network request which has no single closed portable meaning.
#[derive(Clone, Debug, Eq, PartialEq, thiserror::Error)]
pub enum NetworkSemanticsError {
    /// The common protocol envelope, header, fence, or fixed-width field is invalid.
    #[error("invalid local network request: {0}")]
    Protocol(#[from] ProtocolValidationError),
    /// The action's optional fields do not have the required presence and absence.
    #[error("network action fields do not match the selected operation")]
    InvalidActionShape,
    /// An arm or renewal carries an already-expired local fail-stop deadline.
    #[error("network fail-stop deadline is absent or expired")]
    InvalidFailStopDeadline,
    /// The canonical semantic representation exceeded its fixed invariant.
    #[error("canonical network semantics exceed the V1 byte ceiling")]
    CanonicalEncodingTooLarge,
}

/// Describes one fully validated closed network operation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum NetworkOperation {
    /// Prepares default-drop assignment networking and mints a handle.
    Prepare {
        /// Canonically ordered logical endpoint-policy identifiers.
        endpoint_ids: Vec<[u8; 16]>,
    },
    /// Arms an existing network with current ownership authority.
    ArmLease {
        /// Opaque broker-minted network handle.
        network_handle: [u8; 32],
        /// Digest of the verified portable ownership lease.
        ownership_lease_digest: [u8; 32],
        /// Monotone ownership-lease generation.
        lease_generation: u64,
        /// Node/boot-local deadline, excluded from portable commitment bytes.
        fail_stop_boottime_nanoseconds: u64,
    },
    /// Renews the fail-stop gate without changing network policy.
    RenewLease {
        /// Opaque broker-minted network handle.
        network_handle: [u8; 32],
        /// Digest of the verified portable ownership lease.
        ownership_lease_digest: [u8; 32],
        /// Monotone ownership-lease generation.
        lease_generation: u64,
        /// Node/boot-local deadline, excluded from portable commitment bytes.
        fail_stop_boottime_nanoseconds: u64,
    },
    /// Applies local default-drop and disarms an existing network.
    Disarm {
        /// Opaque broker-minted network handle.
        network_handle: [u8; 32],
    },
    /// Destroys one existing broker-owned network.
    Destroy {
        /// Opaque broker-minted network handle.
        network_handle: [u8; 32],
    },
}

impl NetworkOperation {
    /// Returns the closed semantic verb selected by this operation.
    #[must_use]
    pub const fn broker_verb(&self) -> BrokerVerb {
        match self {
            Self::Prepare { .. } => BrokerVerb::NetworkPrepare,
            Self::ArmLease { .. } => BrokerVerb::NetworkArmLease,
            Self::RenewLease { .. } => BrokerVerb::NetworkRenewLease,
            Self::Disarm { .. } => BrokerVerb::NetworkDisarm,
            Self::Destroy { .. } => BrokerVerb::NetworkDestroy,
        }
    }

    /// Returns the network handle for existing-resource operations.
    #[must_use]
    pub const fn network_handle(&self) -> Option<&[u8; 32]> {
        match self {
            Self::Prepare { .. } => None,
            Self::ArmLease { network_handle, .. }
            | Self::RenewLease { network_handle, .. }
            | Self::Disarm { network_handle }
            | Self::Destroy { network_handle } => Some(network_handle),
        }
    }

    /// Returns the endpoint IDs supplied only during preparation.
    #[must_use]
    pub fn endpoint_ids(&self) -> &[[u8; 16]] {
        match self {
            Self::Prepare { endpoint_ids } => endpoint_ids,
            _ => &[],
        }
    }

    /// Returns the ownership-lease digest and generation for gate operations.
    #[must_use]
    pub const fn ownership_lease(&self) -> Option<(&[u8; 32], u64)> {
        match self {
            Self::ArmLease {
                ownership_lease_digest,
                lease_generation,
                ..
            }
            | Self::RenewLease {
                ownership_lease_digest,
                lease_generation,
                ..
            } => Some((ownership_lease_digest, *lease_generation)),
            _ => None,
        }
    }

    /// Returns the node-local fail-stop deadline for gate operations.
    #[must_use]
    pub const fn fail_stop_boottime_nanoseconds(&self) -> Option<u64> {
        match self {
            Self::ArmLease {
                fail_stop_boottime_nanoseconds,
                ..
            }
            | Self::RenewLease {
                fail_stop_boottime_nanoseconds,
                ..
            } => Some(*fail_stop_boottime_nanoseconds),
            _ => None,
        }
    }
}

/// Carries the validated request and its sole portable authorization meaning.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CanonicalNetworkSemanticsV1 {
    header: ValidatedHeader,
    fence: ValidatedAssignmentFence,
    operation: NetworkOperation,
    bytes: Vec<u8>,
    commitment: BrokerArgumentCommitment,
    target: BrokerGrantTarget,
}

impl CanonicalNetworkSemanticsV1 {
    /// Decodes hostile bytes and constructs their closed Network V1 meaning.
    ///
    /// # Errors
    ///
    /// Returns [`NetworkSemanticsError`] for oversized or malformed protobuf,
    /// unknown fields/actions, peer/header/fence failure, malformed handles or
    /// endpoint sets, invalid action shape, expired local fail-stop state, or a
    /// canonical byte-bound violation.
    pub fn decode(
        bytes: &[u8],
        peer: PeerCredentials,
        policy: PeerPolicy,
        now_boottime_nanoseconds: u64,
    ) -> Result<Self, NetworkSemanticsError> {
        if bytes.len() > MAXIMUM_REQUEST_BYTES {
            return Err(ProtocolValidationError::RequestTooLarge.into());
        }
        let request = ApplyNetworkRequest::decode_from_slice(bytes)
            .map_err(|error| ProtocolValidationError::MalformedWire(error.to_string()))?;
        if !request.__buffa_unknown_fields.is_empty() {
            return Err(ProtocolValidationError::UnknownFields.into());
        }
        let header = validate_request_header(
            request
                .header
                .as_option()
                .ok_or(ProtocolValidationError::MissingField("header"))?,
            peer,
            policy,
            ProtocolId::NetworkBroker,
            now_boottime_nanoseconds,
        )?;
        let fence = validate_fence(
            request
                .fence
                .as_option()
                .ok_or(ProtocolValidationError::MissingField("fence"))?,
        )?;
        let action = request
            .action
            .as_known()
            .filter(|value| *value != NetworkAction::NETWORK_ACTION_UNSPECIFIED)
            .ok_or(ProtocolValidationError::UnknownAction)?;
        let network_handle = optional_nonzero::<32>(&request.network_handle, "network_handle")?;
        let endpoint_ids = validate_endpoint_ids(&request.endpoint_ids)?;
        let ownership_lease_digest =
            optional_nonzero::<32>(&request.ownership_lease_digest, "ownership_lease_digest")?;
        let operation = operation_for(
            action,
            network_handle,
            endpoint_ids,
            ownership_lease_digest,
            request.lease_generation,
            request.fail_stop_boottime_nanoseconds,
            now_boottime_nanoseconds,
        )?;
        let target = match operation.network_handle() {
            None => BrokerGrantTarget::Assignment,
            Some(handle) => BrokerGrantTarget::Resource(
                BrokerResourceHandle::from_bytes(*handle)
                    .map_err(|_| NetworkSemanticsError::InvalidActionShape)?,
            ),
        };

        let mut encoder = Encoder::new();
        encoder.field(1, FORMAT_MAGIC)?;
        encoder.field(2, &FORMAT_VERSION.to_be_bytes())?;
        encoder.field(3, &[action_code(&operation)])?;
        encoder.field(4, fence.sandbox_id())?;
        encoder.field(5, fence.incarnation_id())?;
        encoder.field(6, &fence.assignment_epoch().to_be_bytes())?;
        encoder.field(7, &fence.desired_generation().to_be_bytes())?;
        encoder.field(8, fence.assignment_digest())?;
        encoder.optional_fixed(9, operation.network_handle())?;
        encoder.endpoint_ids(10, operation.endpoint_ids())?;
        let bytes = encoder.finish();
        let commitment = BrokerArgumentCommitment::for_canonical_bytes(&bytes);
        Ok(Self {
            header,
            fence,
            operation,
            bytes,
            commitment,
            target,
        })
    }

    /// Returns the fully validated transport header.
    #[must_use]
    pub const fn header(&self) -> &ValidatedHeader {
        &self.header
    }

    /// Returns the exact validated assignment fence.
    #[must_use]
    pub const fn fence(&self) -> &ValidatedAssignmentFence {
        &self.fence
    }

    /// Returns the closed network operation, including local deadline facts.
    #[must_use]
    pub const fn operation(&self) -> &NetworkOperation {
        &self.operation
    }

    /// Returns exact versioned portable commitment bytes.
    #[must_use]
    pub fn canonical_bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// Returns the portable argument commitment used by a broker grant.
    #[must_use]
    pub const fn argument_commitment(&self) -> BrokerArgumentCommitment {
        self.commitment
    }

    /// Returns the assignment or existing-network grant target.
    #[must_use]
    pub const fn grant_target(&self) -> BrokerGrantTarget {
        self.target
    }

    /// Returns the exact network broker verb.
    #[must_use]
    pub const fn broker_verb(&self) -> BrokerVerb {
        self.operation.broker_verb()
    }
}

fn operation_for(
    action: NetworkAction,
    network: Option<[u8; 32]>,
    endpoints: Vec<[u8; 16]>,
    lease: Option<[u8; 32]>,
    lease_generation: u64,
    fail_stop: u64,
    now: u64,
) -> Result<NetworkOperation, NetworkSemanticsError> {
    match (
        action,
        network,
        endpoints,
        lease,
        lease_generation,
        fail_stop,
    ) {
        (NetworkAction::NETWORK_ACTION_PREPARE, None, endpoints, None, 0, 0) => {
            Ok(NetworkOperation::Prepare {
                endpoint_ids: endpoints,
            })
        }
        (
            NetworkAction::NETWORK_ACTION_ARM_LEASE,
            Some(network_handle),
            endpoints,
            Some(ownership_lease_digest),
            lease_generation @ 1..,
            fail_stop_boottime_nanoseconds,
        ) if endpoints.is_empty() => gate_operation(
            false,
            network_handle,
            ownership_lease_digest,
            lease_generation,
            fail_stop_boottime_nanoseconds,
            now,
        ),
        (
            NetworkAction::NETWORK_ACTION_RENEW_LEASE,
            Some(network_handle),
            endpoints,
            Some(ownership_lease_digest),
            lease_generation @ 1..,
            fail_stop_boottime_nanoseconds,
        ) if endpoints.is_empty() => gate_operation(
            true,
            network_handle,
            ownership_lease_digest,
            lease_generation,
            fail_stop_boottime_nanoseconds,
            now,
        ),
        (NetworkAction::NETWORK_ACTION_DISARM, Some(network_handle), endpoints, None, 0, 0)
            if endpoints.is_empty() =>
        {
            Ok(NetworkOperation::Disarm { network_handle })
        }
        (NetworkAction::NETWORK_ACTION_DESTROY, Some(network_handle), endpoints, None, 0, 0)
            if endpoints.is_empty() =>
        {
            Ok(NetworkOperation::Destroy { network_handle })
        }
        _ => Err(NetworkSemanticsError::InvalidActionShape),
    }
}

fn gate_operation(
    renew: bool,
    network_handle: [u8; 32],
    ownership_lease_digest: [u8; 32],
    lease_generation: u64,
    fail_stop_boottime_nanoseconds: u64,
    now: u64,
) -> Result<NetworkOperation, NetworkSemanticsError> {
    if fail_stop_boottime_nanoseconds <= now {
        return Err(NetworkSemanticsError::InvalidFailStopDeadline);
    }
    if renew {
        Ok(NetworkOperation::RenewLease {
            network_handle,
            ownership_lease_digest,
            lease_generation,
            fail_stop_boottime_nanoseconds,
        })
    } else {
        Ok(NetworkOperation::ArmLease {
            network_handle,
            ownership_lease_digest,
            lease_generation,
            fail_stop_boottime_nanoseconds,
        })
    }
}

const fn action_code(operation: &NetworkOperation) -> u8 {
    match operation {
        NetworkOperation::Prepare { .. } => 1,
        NetworkOperation::ArmLease { .. } => 2,
        NetworkOperation::RenewLease { .. } => 3,
        NetworkOperation::Disarm { .. } => 4,
        NetworkOperation::Destroy { .. } => 5,
    }
}

fn validate_endpoint_ids(source: &[Vec<u8>]) -> Result<Vec<[u8; 16]>, ProtocolValidationError> {
    if source.len() > MAXIMUM_NETWORK_ENDPOINTS {
        return Err(ProtocolValidationError::TooManyEntries {
            field: "endpoint_ids",
            maximum: MAXIMUM_NETWORK_ENDPOINTS,
        });
    }
    let mut endpoints = Vec::with_capacity(source.len());
    for value in source {
        let endpoint = exact_nonzero::<16>(value, "endpoint_ids")?;
        if endpoints
            .last()
            .is_some_and(|previous| previous >= &endpoint)
        {
            return Err(ProtocolValidationError::InvalidField("endpoint_ids"));
        }
        endpoints.push(endpoint);
    }
    Ok(endpoints)
}

fn optional_nonzero<const N: usize>(
    bytes: &[u8],
    field: &'static str,
) -> Result<Option<[u8; N]>, ProtocolValidationError> {
    if bytes.is_empty() {
        Ok(None)
    } else {
        exact_nonzero(bytes, field).map(Some)
    }
}

struct Encoder {
    bytes: Vec<u8>,
}

impl Encoder {
    fn new() -> Self {
        Self {
            bytes: Vec::with_capacity(512),
        }
    }

    fn field(&mut self, tag: u8, value: &[u8]) -> Result<(), NetworkSemanticsError> {
        let length = u32::try_from(value.len())
            .map_err(|_| NetworkSemanticsError::CanonicalEncodingTooLarge)?;
        let next = self
            .bytes
            .len()
            .checked_add(5)
            .and_then(|size| size.checked_add(value.len()))
            .filter(|size| *size <= MAXIMUM_CANONICAL_BYTES)
            .ok_or(NetworkSemanticsError::CanonicalEncodingTooLarge)?;
        self.bytes.reserve(next - self.bytes.len());
        self.bytes.push(tag);
        self.bytes.extend_from_slice(&length.to_be_bytes());
        self.bytes.extend_from_slice(value);
        Ok(())
    }

    fn optional_fixed<const N: usize>(
        &mut self,
        tag: u8,
        value: Option<&[u8; N]>,
    ) -> Result<(), NetworkSemanticsError> {
        self.field(tag, value.map(<[u8; N]>::as_slice).unwrap_or_default())
    }

    fn endpoint_ids(&mut self, tag: u8, values: &[[u8; 16]]) -> Result<(), NetworkSemanticsError> {
        let mut bytes = Vec::with_capacity(2 + values.len() * 16);
        bytes.extend_from_slice(
            &u16::try_from(values.len())
                .map_err(|_| NetworkSemanticsError::CanonicalEncodingTooLarge)?
                .to_be_bytes(),
        );
        for value in values {
            bytes.extend_from_slice(value);
        }
        self.field(tag, &bytes)
    }

    fn finish(self) -> Vec<u8> {
        self.bytes
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use aos_proto::aos::sandbox::local::v1::Audience;

    use super::*;

    fn peer() -> PeerCredentials {
        PeerCredentials {
            uid: 100,
            gid: 200,
            pid: Some(300),
        }
    }

    fn policy() -> PeerPolicy {
        PeerPolicy {
            uid: 100,
            gid: Some(200),
            audience: Audience::AUDIENCE_NODE_CONTROLLER,
        }
    }

    fn request(action: NetworkAction) -> ApplyNetworkRequest {
        let mut request = ApplyNetworkRequest::default();
        let header = request.header.get_or_insert_default();
        header.protocol_major = 1;
        header.request_id = vec![1; 16];
        header.audience = Audience::AUDIENCE_NODE_CONTROLLER.into();
        header.deadline_boottime_nanoseconds = 200;
        header.maximum_response_bytes = 4096;
        let fence = request.fence.get_or_insert_default();
        fence.sandbox_id = vec![2; 16];
        fence.incarnation_id = vec![3; 16];
        fence.assignment_epoch = 4;
        fence.desired_generation = 5;
        fence.assignment_digest = vec![6; 32];
        request.action = action.into();
        request
    }

    fn prepare() -> ApplyNetworkRequest {
        let mut request = request(NetworkAction::NETWORK_ACTION_PREPARE);
        request.endpoint_ids = vec![vec![7; 16], vec![8; 16]];
        request
    }

    fn gate(action: NetworkAction) -> ApplyNetworkRequest {
        let mut request = request(action);
        request.network_handle = vec![7; 32];
        request.ownership_lease_digest = vec![8; 32];
        request.lease_generation = 9;
        request.fail_stop_boottime_nanoseconds = 300;
        request
    }

    fn decode(
        request: &ApplyNetworkRequest,
    ) -> Result<CanonicalNetworkSemanticsV1, NetworkSemanticsError> {
        CanonicalNetworkSemanticsV1::decode(&request.encode_to_vec(), peer(), policy(), 100)
    }

    #[test]
    fn portable_network_commitment_has_a_fixed_golden_digest() {
        let semantics = decode(&prepare()).unwrap();
        assert_eq!(semantics.broker_verb(), BrokerVerb::NetworkPrepare);
        assert_eq!(semantics.grant_target(), BrokerGrantTarget::Assignment);
        assert_eq!(
            semantics.argument_commitment().digest().as_bytes(),
            &[
                254, 21, 228, 83, 186, 179, 103, 42, 218, 163, 93, 42, 64, 125, 137, 239, 26, 223,
                74, 104, 62, 185, 166, 61, 150, 67, 110, 67, 178, 89, 198, 248,
            ]
        );
    }

    #[test]
    fn all_action_shapes_are_closed() {
        for (action, verb) in [
            (
                NetworkAction::NETWORK_ACTION_ARM_LEASE,
                BrokerVerb::NetworkArmLease,
            ),
            (
                NetworkAction::NETWORK_ACTION_RENEW_LEASE,
                BrokerVerb::NetworkRenewLease,
            ),
        ] {
            assert_eq!(decode(&gate(action)).unwrap().broker_verb(), verb);
        }
        for (action, verb) in [
            (
                NetworkAction::NETWORK_ACTION_DISARM,
                BrokerVerb::NetworkDisarm,
            ),
            (
                NetworkAction::NETWORK_ACTION_DESTROY,
                BrokerVerb::NetworkDestroy,
            ),
        ] {
            let mut request = request(action);
            request.network_handle = vec![9; 32];
            assert_eq!(decode(&request).unwrap().broker_verb(), verb);
        }
    }

    #[test]
    fn action_field_smuggling_and_expired_fail_stop_are_rejected() {
        let mut prepared = prepare();
        prepared.network_handle = vec![9; 32];
        assert_eq!(
            decode(&prepared),
            Err(NetworkSemanticsError::InvalidActionShape)
        );

        let mut armed = gate(NetworkAction::NETWORK_ACTION_ARM_LEASE);
        armed.endpoint_ids.push(vec![9; 16]);
        assert_eq!(
            decode(&armed),
            Err(NetworkSemanticsError::InvalidActionShape)
        );
        armed.endpoint_ids.clear();
        armed.fail_stop_boottime_nanoseconds = 100;
        assert_eq!(
            decode(&armed),
            Err(NetworkSemanticsError::InvalidFailStopDeadline)
        );

        let mut destroy = request(NetworkAction::NETWORK_ACTION_DESTROY);
        destroy.network_handle = vec![9; 32];
        destroy.lease_generation = 1;
        assert_eq!(
            decode(&destroy),
            Err(NetworkSemanticsError::InvalidActionShape)
        );

        let mut unspecified = request(NetworkAction::NETWORK_ACTION_UNSPECIFIED);
        unspecified.action = 99.into();
        assert!(matches!(
            decode(&unspecified),
            Err(NetworkSemanticsError::Protocol(
                ProtocolValidationError::UnknownAction
            ))
        ));
    }

    #[test]
    fn lease_actions_require_the_complete_exact_lease_tuple() {
        for action in [
            NetworkAction::NETWORK_ACTION_ARM_LEASE,
            NetworkAction::NETWORK_ACTION_RENEW_LEASE,
        ] {
            let valid = gate(action);
            let mut missing = valid.clone();
            missing.network_handle.clear();
            assert_eq!(
                decode(&missing),
                Err(NetworkSemanticsError::InvalidActionShape)
            );
            let mut missing = valid.clone();
            missing.ownership_lease_digest.clear();
            assert_eq!(
                decode(&missing),
                Err(NetworkSemanticsError::InvalidActionShape)
            );
            let mut missing = valid.clone();
            missing.lease_generation = 0;
            assert_eq!(
                decode(&missing),
                Err(NetworkSemanticsError::InvalidActionShape)
            );
            let mut expired = valid;
            expired.fail_stop_boottime_nanoseconds = 0;
            assert_eq!(
                decode(&expired),
                Err(NetworkSemanticsError::InvalidFailStopDeadline)
            );
        }
    }

    #[test]
    fn endpoints_require_exact_strict_canonical_order_and_bounds() {
        let mut request = prepare();
        request.endpoint_ids.swap(0, 1);
        assert!(matches!(
            decode(&request),
            Err(NetworkSemanticsError::Protocol(
                ProtocolValidationError::InvalidField("endpoint_ids")
            ))
        ));
        request.endpoint_ids = vec![vec![7; 16], vec![7; 16]];
        assert!(decode(&request).is_err());
        request.endpoint_ids = vec![vec![7; 15]];
        assert!(decode(&request).is_err());
        request.endpoint_ids = (0..=MAXIMUM_NETWORK_ENDPOINTS)
            .map(|index| {
                let mut id = [0; 16];
                id[8..].copy_from_slice(&(index as u64 + 1).to_be_bytes());
                id.to_vec()
            })
            .collect();
        assert!(matches!(
            decode(&request),
            Err(NetworkSemanticsError::Protocol(
                ProtocolValidationError::TooManyEntries { .. }
            ))
        ));
    }

    #[test]
    fn attempt_authority_and_transport_facts_do_not_change_portable_commitment() {
        let first = gate(NetworkAction::NETWORK_ACTION_ARM_LEASE);
        let mut second = first.clone();
        second.ownership_lease_digest = vec![11; 32];
        second.lease_generation = 12;
        second.fail_stop_boottime_nanoseconds = 400;
        let header = second.header.get_or_insert_default();
        header.request_id = vec![10; 16];
        header.deadline_boottime_nanoseconds = 500;
        header.maximum_response_bytes = 8192;
        let first = decode(&first).unwrap();
        let second = decode(&second).unwrap();
        assert_eq!(first.argument_commitment(), second.argument_commitment());
        assert_ne!(
            first.operation().fail_stop_boottime_nanoseconds(),
            second.operation().fail_stop_boottime_nanoseconds()
        );
        assert_ne!(
            first.operation().ownership_lease(),
            second.operation().ownership_lease()
        );
    }

    #[test]
    fn stable_effect_fields_each_change_the_portable_commitment() {
        let armed = gate(NetworkAction::NETWORK_ACTION_ARM_LEASE);
        let baseline = decode(&armed).unwrap().argument_commitment();

        let renewed = gate(NetworkAction::NETWORK_ACTION_RENEW_LEASE);
        assert_ne!(baseline, decode(&renewed).unwrap().argument_commitment());

        let mut changed = armed.clone();
        changed.network_handle = vec![12; 32];
        assert_ne!(baseline, decode(&changed).unwrap().argument_commitment());

        let mut changed = armed;
        changed.fence.get_or_insert_default().assignment_digest = vec![13; 32];
        assert_ne!(baseline, decode(&changed).unwrap().argument_commitment());

        let first = decode(&prepare()).unwrap().argument_commitment();
        let mut changed = prepare();
        changed.endpoint_ids.push(vec![9; 16]);
        assert_ne!(first, decode(&changed).unwrap().argument_commitment());
    }

    #[test]
    fn unknown_wire_fields_fail_closed() {
        let mut encoded = prepare().encode_to_vec();
        encoded.extend_from_slice(&[0x98, 0x06, 0x01]);
        assert!(matches!(
            CanonicalNetworkSemanticsV1::decode(&encoded, peer(), policy(), 100),
            Err(NetworkSemanticsError::Protocol(
                ProtocolValidationError::UnknownFields
            ))
        ));
    }
}
