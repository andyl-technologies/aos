//! Fixed Broker Session Authentication 1.0 semantic subjects.
//!
//! These types validate wire shape only. In particular, constructing a signer
//! reference, subject, or context does not establish protected provenance,
//! currentness, process identity, nonce freshness, or authority.

use aos_proto::aos::sandbox::local::v1::{Audience, BrokerMethod};
use aos_sandbox_core::ProtocolId;
use ed25519_dalek::SigningKey;
use sha2::{Digest as _, Sha256};

/// Feature major version for Broker Session Authentication 1.0.
pub const BROKER_SESSION_AUTHENTICATION_FEATURE_MAJOR: u32 = 1;
/// Feature minor version for Broker Session Authentication 1.0.
pub const BROKER_SESSION_AUTHENTICATION_FEATURE_MINOR: u32 = 0;
/// Exact encoded signer-reference width.
pub const BROKER_SESSION_SIGNER_REFERENCE_BYTES: usize = 120;
/// Signed-envelope bytes outside the exact subject.
pub const BROKER_SESSION_SIGNED_OVERHEAD_BYTES: usize = 204;
/// Exact ClientHello subject width.
pub const CLIENT_HELLO_SUBJECT_BYTES: usize = 150;
/// Exact BrokerHello subject width.
pub const BROKER_HELLO_SUBJECT_BYTES: usize = 182;
/// Exact ClientRecord subject width.
pub const BROKER_REQUEST_SUBJECT_BYTES: usize = 104;
/// Exact BrokerOutcome subject width.
pub const BROKER_OUTCOME_SUBJECT_BYTES: usize = 136;
/// Exact complete signed ClientHello artifact width.
pub const SIGNED_CLIENT_HELLO_BYTES: usize = 354;
/// Exact complete signed BrokerHello artifact width.
pub const SIGNED_BROKER_HELLO_BYTES: usize = 386;
/// Exact complete signed ClientRecord artifact width.
pub const SIGNED_BROKER_REQUEST_BYTES: usize = 308;
/// Exact complete signed BrokerOutcome artifact width.
pub const SIGNED_BROKER_OUTCOME_BYTES: usize = 340;

const _: [(); SIGNED_CLIENT_HELLO_BYTES] =
    [(); BROKER_SESSION_SIGNED_OVERHEAD_BYTES + CLIENT_HELLO_SUBJECT_BYTES];
const _: [(); SIGNED_BROKER_HELLO_BYTES] =
    [(); BROKER_SESSION_SIGNED_OVERHEAD_BYTES + BROKER_HELLO_SUBJECT_BYTES];
const _: [(); SIGNED_BROKER_REQUEST_BYTES] =
    [(); BROKER_SESSION_SIGNED_OVERHEAD_BYTES + BROKER_REQUEST_SUBJECT_BYTES];
const _: [(); SIGNED_BROKER_OUTCOME_BYTES] =
    [(); BROKER_SESSION_SIGNED_OVERHEAD_BYTES + BROKER_OUTCOME_SUBJECT_BYTES];

/// Reports a noncanonical Broker Session Authentication value.
#[derive(Clone, Debug, Eq, PartialEq, thiserror::Error)]
pub enum BrokerSessionValidationError {
    /// A fixed identifier, digest, nonce, or raw key uses its zero sentinel.
    #[error("{0} must not use the all-zero sentinel")]
    Zero(&'static str),
    /// A generation or direction-local sequence uses zero.
    #[error("{0} must be nonzero")]
    ZeroScalar(&'static str),
    /// A broker-only protocol, known audience, method, or key use is invalid.
    #[error("invalid closed Broker Session Authentication value: {0}")]
    InvalidClosedValue(&'static str),
    /// Signers, stable key IDs, or physical public keys are not pairwise distinct.
    #[error("the four Broker Session Authentication signing roles must be pairwise distinct")]
    SignersNotDistinct,
    /// The caller-supplied raw public key does not match its signer reference.
    #[error("Broker Session Authentication public-key fingerprint mismatch")]
    PublicKeyMismatch,
    /// An Ed25519 public key is malformed or weak.
    #[error("invalid or weak Broker Session Authentication Ed25519 public key")]
    InvalidPublicKey,
    /// A fixed-width subject or signer reference is malformed.
    #[error("invalid Broker Session Authentication fixed-width encoding")]
    InvalidEncoding,
}

/// Identifies one broker protocol with a distinct signed one-byte code.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum BrokerSessionProtocolV1 {
    /// Host broker protocol.
    Host = 1,
    /// Storage broker protocol.
    Storage = 2,
    /// Mount broker protocol.
    Mount = 3,
    /// Network broker protocol.
    Network = 4,
    /// Closed, separately versioned Mount FUSE protocol.
    MountFuse = 5,
}

impl BrokerSessionProtocolV1 {
    pub(crate) const fn code(self) -> u8 {
        match self {
            Self::Host => 1,
            Self::Storage => 2,
            Self::Mount => 3,
            Self::Network => 4,
            Self::MountFuse => 5,
        }
    }

    /// Resolves an existing broker protocol into its signed one-byte code.
    ///
    /// # Errors
    ///
    /// Returns [`BrokerSessionValidationError`] for every non-broker protocol.
    pub fn from_protocol_id(protocol: ProtocolId) -> Result<Self, BrokerSessionValidationError> {
        match protocol {
            ProtocolId::HostBroker => Ok(Self::Host),
            ProtocolId::StorageBroker => Ok(Self::Storage),
            ProtocolId::MountBroker => Ok(Self::Mount),
            ProtocolId::MountFuseBroker => Ok(Self::MountFuse),
            ProtocolId::NetworkBroker => Ok(Self::Network),
            _ => Err(BrokerSessionValidationError::InvalidClosedValue("protocol")),
        }
    }

    pub(crate) const fn from_code(code: u8) -> Result<Self, BrokerSessionValidationError> {
        match code {
            1 => Ok(Self::Host),
            2 => Ok(Self::Storage),
            3 => Ok(Self::Mount),
            4 => Ok(Self::Network),
            5 => Ok(Self::MountFuse),
            _ => Err(BrokerSessionValidationError::InvalidClosedValue("protocol")),
        }
    }
}

/// Identifies the four non-interchangeable signing roles.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum BrokerSessionKeyUsageV1 {
    /// Signs the client's hello.
    ClientHello = 1,
    /// Signs the broker's hello.
    BrokerHello = 2,
    /// Signs client-to-broker request records.
    ClientRecord = 3,
    /// Signs broker-to-client outcome records.
    BrokerOutcome = 4,
}

impl BrokerSessionKeyUsageV1 {
    pub(crate) const fn code(self) -> u8 {
        match self {
            Self::ClientHello => 1,
            Self::BrokerHello => 2,
            Self::ClientRecord => 3,
            Self::BrokerOutcome => 4,
        }
    }

    pub(crate) const fn index(self) -> usize {
        match self {
            Self::ClientHello => 0,
            Self::BrokerHello => 1,
            Self::ClientRecord => 2,
            Self::BrokerOutcome => 3,
        }
    }

    pub(crate) const fn from_code(code: u8) -> Result<Self, BrokerSessionValidationError> {
        match code {
            1 => Ok(Self::ClientHello),
            2 => Ok(Self::BrokerHello),
            3 => Ok(Self::ClientRecord),
            4 => Ok(Self::BrokerOutcome),
            _ => Err(BrokerSessionValidationError::InvalidClosedValue(
                "key usage",
            )),
        }
    }
}

/// Binds one stable authority and key generation to one exact signing role.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BrokerSessionSignerReferenceV1 {
    pub(crate) authority_id: [u8; 16],
    pub(crate) authority_generation: u64,
    pub(crate) authority_digest: [u8; 32],
    pub(crate) key_id: [u8; 16],
    pub(crate) key_generation: u64,
    pub(crate) public_key_digest: [u8; 32],
    pub(crate) usage: BrokerSessionKeyUsageV1,
}

impl BrokerSessionSignerReferenceV1 {
    /// Constructs one shape-checked signer reference without granting authority.
    ///
    /// # Errors
    ///
    /// Returns [`BrokerSessionValidationError`] for sentinel fields.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        authority_id: [u8; 16],
        authority_generation: u64,
        authority_digest: [u8; 32],
        key_id: [u8; 16],
        key_generation: u64,
        public_key_digest: [u8; 32],
        usage: BrokerSessionKeyUsageV1,
    ) -> Result<Self, BrokerSessionValidationError> {
        require_nonzero("authority ID", &authority_id)?;
        require_nonzero_scalar("authority generation", authority_generation)?;
        require_nonzero("authority digest", &authority_digest)?;
        require_nonzero("key ID", &key_id)?;
        require_nonzero_scalar("key generation", key_generation)?;
        require_nonzero("public-key digest", &public_key_digest)?;
        Ok(Self {
            authority_id,
            authority_generation,
            authority_digest,
            key_id,
            key_generation,
            public_key_digest,
            usage,
        })
    }

    /// Constructs a shape-only reference fingerprinted to a signing key.
    ///
    /// # Errors
    ///
    /// Returns [`BrokerSessionValidationError`] for sentinel metadata.
    pub fn for_signing_key(
        authority_id: [u8; 16],
        authority_generation: u64,
        authority_digest: [u8; 32],
        key_id: [u8; 16],
        key_generation: u64,
        usage: BrokerSessionKeyUsageV1,
        signing_key: &SigningKey,
    ) -> Result<Self, BrokerSessionValidationError> {
        let public_key_digest = Sha256::digest(signing_key.verifying_key().as_bytes()).into();
        Self::new(
            authority_id,
            authority_generation,
            authority_digest,
            key_id,
            key_generation,
            public_key_digest,
            usage,
        )
    }

    /// Returns the signer authority ID.
    #[must_use]
    pub const fn authority_id(&self) -> [u8; 16] {
        self.authority_id
    }

    /// Returns the signer authority generation.
    #[must_use]
    pub const fn authority_generation(&self) -> u64 {
        self.authority_generation
    }

    /// Returns the authority-state digest.
    #[must_use]
    pub const fn authority_digest(&self) -> [u8; 32] {
        self.authority_digest
    }

    /// Returns the stable key ID.
    #[must_use]
    pub const fn key_id(&self) -> [u8; 16] {
        self.key_id
    }

    /// Returns the immutable key generation.
    #[must_use]
    pub const fn key_generation(&self) -> u64 {
        self.key_generation
    }

    /// Returns SHA-256 over the raw Ed25519 public key.
    #[must_use]
    pub const fn public_key_digest(&self) -> [u8; 32] {
        self.public_key_digest
    }

    /// Returns the sole permitted signing use.
    #[must_use]
    pub const fn usage(&self) -> BrokerSessionKeyUsageV1 {
        self.usage
    }

    pub(crate) fn encode_into(&self, bytes: &mut Vec<u8>) {
        bytes.extend_from_slice(&self.authority_id);
        bytes.extend_from_slice(&self.authority_generation.to_be_bytes());
        bytes.extend_from_slice(&self.authority_digest);
        bytes.extend_from_slice(&self.key_id);
        bytes.extend_from_slice(&self.key_generation.to_be_bytes());
        bytes.extend_from_slice(&self.public_key_digest);
        bytes.push(self.usage.code());
        bytes.extend_from_slice(&[0; 7]);
    }

    pub(crate) fn decode(bytes: &[u8]) -> Result<Self, BrokerSessionValidationError> {
        if bytes.len() != BROKER_SESSION_SIGNER_REFERENCE_BYTES
            || bytes[113..120].iter().any(|byte| *byte != 0)
        {
            return Err(BrokerSessionValidationError::InvalidEncoding);
        }
        Self::new(
            take_array(bytes, 0)?,
            u64::from_be_bytes(take_array(bytes, 16)?),
            take_array(bytes, 24)?,
            take_array(bytes, 56)?,
            u64::from_be_bytes(take_array(bytes, 72)?),
            take_array(bytes, 80)?,
            BrokerSessionKeyUsageV1::from_code(bytes[112])?,
        )
    }
}

/// Exact ClientHello signature subject.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BrokerClientHelloSubjectV1 {
    pub(crate) node_id: [u8; 16],
    pub(crate) boot_id: [u8; 16],
    pub(crate) protocol: BrokerSessionProtocolV1,
    pub(crate) major: u16,
    pub(crate) minor: u16,
    pub(crate) audience: Audience,
    pub(crate) client_process: [u8; 16],
    pub(crate) nonce: [u8; 32],
    pub(crate) protected_context_digest: [u8; 32],
    pub(crate) cleared_fields_digest: [u8; 32],
}

/// Exact BrokerHello signature subject.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BrokerHelloSubjectV1 {
    pub(crate) node_id: [u8; 16],
    pub(crate) boot_id: [u8; 16],
    pub(crate) protocol: BrokerSessionProtocolV1,
    pub(crate) major: u16,
    pub(crate) minor: u16,
    pub(crate) audience: Audience,
    pub(crate) broker_process: [u8; 16],
    pub(crate) nonce: [u8; 32],
    pub(crate) protected_context_digest: [u8; 32],
    pub(crate) signed_client_hello_digest: [u8; 32],
    pub(crate) cleared_fields_digest: [u8; 32],
}

/// Exact ClientRecord signature subject.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BrokerRequestSubjectV1 {
    pub(crate) session_binding: [u8; 32],
    pub(crate) client_process: [u8; 16],
    pub(crate) sequence: u64,
    pub(crate) request_id: [u8; 16],
    pub(crate) cleared_fields_digest: [u8; 32],
}

/// Exact BrokerOutcome signature subject.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BrokerOutcomeSubjectV1 {
    pub(crate) session_binding: [u8; 32],
    pub(crate) broker_process: [u8; 16],
    pub(crate) sequence: u64,
    pub(crate) request_id: [u8; 16],
    pub(crate) signed_request_digest: [u8; 32],
    pub(crate) cleared_fields_digest: [u8; 32],
}

macro_rules! subject_accessors {
    ($type:ty, $process:ident) => {
        impl $type {
            /// Returns the session-binding digest.
            #[must_use]
            pub const fn session_binding(&self) -> [u8; 32] {
                self.session_binding
            }
            /// Returns the signed process-execution identifier.
            #[must_use]
            pub const fn $process(&self) -> [u8; 16] {
                self.$process
            }
            /// Returns the direction-local nonzero sequence.
            #[must_use]
            pub const fn sequence(&self) -> u64 {
                self.sequence
            }
            /// Returns the request identifier.
            #[must_use]
            pub const fn request_id(&self) -> [u8; 16] {
                self.request_id
            }
            /// Returns the cleared protobuf projection digest.
            #[must_use]
            pub const fn cleared_fields_digest(&self) -> [u8; 32] {
                self.cleared_fields_digest
            }
        }
    };
}

subject_accessors!(BrokerRequestSubjectV1, client_process);
subject_accessors!(BrokerOutcomeSubjectV1, broker_process);

impl BrokerOutcomeSubjectV1 {
    /// Returns the digest of the complete signed request artifact.
    #[must_use]
    pub const fn signed_request_digest(&self) -> [u8; 32] {
        self.signed_request_digest
    }
}

impl BrokerClientHelloSubjectV1 {
    /// Constructs one shape-checked ClientHello subject.
    ///
    /// # Errors
    ///
    /// Returns [`BrokerSessionValidationError`] for sentinels or an unknown audience.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        node_id: [u8; 16],
        boot_id: [u8; 16],
        protocol: BrokerSessionProtocolV1,
        major: u16,
        minor: u16,
        audience: Audience,
        client_process: [u8; 16],
        nonce: [u8; 32],
        protected_context_digest: [u8; 32],
        cleared_fields_digest: [u8; 32],
    ) -> Result<Self, BrokerSessionValidationError> {
        require_common(
            node_id,
            boot_id,
            major,
            audience,
            client_process,
            nonce,
            protected_context_digest,
            cleared_fields_digest,
        )?;
        Ok(Self {
            node_id,
            boot_id,
            protocol,
            major,
            minor,
            audience,
            client_process,
            nonce,
            protected_context_digest,
            cleared_fields_digest,
        })
    }

    /// Returns the client nonce.
    #[must_use]
    pub const fn nonce(&self) -> [u8; 32] {
        self.nonce
    }
    /// Returns the client process-execution ID.
    #[must_use]
    pub const fn client_process(&self) -> [u8; 16] {
        self.client_process
    }
    /// Returns the digest of the complete locally selected protected context.
    #[must_use]
    pub const fn protected_context_digest(&self) -> [u8; 32] {
        self.protected_context_digest
    }
    /// Returns the cleared hello projection digest.
    #[must_use]
    pub const fn cleared_fields_digest(&self) -> [u8; 32] {
        self.cleared_fields_digest
    }
}

impl BrokerHelloSubjectV1 {
    /// Constructs one shape-checked BrokerHello subject.
    ///
    /// # Errors
    ///
    /// Returns [`BrokerSessionValidationError`] for sentinels or an unknown audience.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        node_id: [u8; 16],
        boot_id: [u8; 16],
        protocol: BrokerSessionProtocolV1,
        major: u16,
        minor: u16,
        audience: Audience,
        broker_process: [u8; 16],
        nonce: [u8; 32],
        protected_context_digest: [u8; 32],
        signed_client_hello_digest: [u8; 32],
        cleared_fields_digest: [u8; 32],
    ) -> Result<Self, BrokerSessionValidationError> {
        require_common(
            node_id,
            boot_id,
            major,
            audience,
            broker_process,
            nonce,
            protected_context_digest,
            cleared_fields_digest,
        )?;
        require_nonzero("signed ClientHello digest", &signed_client_hello_digest)?;
        Ok(Self {
            node_id,
            boot_id,
            protocol,
            major,
            minor,
            audience,
            broker_process,
            nonce,
            protected_context_digest,
            signed_client_hello_digest,
            cleared_fields_digest,
        })
    }

    /// Returns the broker nonce.
    #[must_use]
    pub const fn nonce(&self) -> [u8; 32] {
        self.nonce
    }
    /// Returns the broker process-execution ID.
    #[must_use]
    pub const fn broker_process(&self) -> [u8; 16] {
        self.broker_process
    }
    /// Returns the digest of the complete locally selected protected context.
    #[must_use]
    pub const fn protected_context_digest(&self) -> [u8; 32] {
        self.protected_context_digest
    }
    /// Returns the complete signed ClientHello digest.
    #[must_use]
    pub const fn signed_client_hello_digest(&self) -> [u8; 32] {
        self.signed_client_hello_digest
    }
    /// Returns the cleared hello projection digest.
    #[must_use]
    pub const fn cleared_fields_digest(&self) -> [u8; 32] {
        self.cleared_fields_digest
    }
}

impl BrokerRequestSubjectV1 {
    /// Constructs one shape-checked ClientRecord subject.
    ///
    /// # Errors
    ///
    /// Returns [`BrokerSessionValidationError`] for sentinels or sequence zero.
    pub fn new(
        session_binding: [u8; 32],
        client_process: [u8; 16],
        sequence: u64,
        request_id: [u8; 16],
        cleared_fields_digest: [u8; 32],
    ) -> Result<Self, BrokerSessionValidationError> {
        require_traffic(
            session_binding,
            client_process,
            sequence,
            request_id,
            cleared_fields_digest,
        )?;
        Ok(Self {
            session_binding,
            client_process,
            sequence,
            request_id,
            cleared_fields_digest,
        })
    }
}

impl BrokerOutcomeSubjectV1 {
    /// Constructs one shape-checked BrokerOutcome subject.
    ///
    /// # Errors
    ///
    /// Returns [`BrokerSessionValidationError`] for sentinels or sequence zero.
    pub fn new(
        session_binding: [u8; 32],
        broker_process: [u8; 16],
        sequence: u64,
        request_id: [u8; 16],
        signed_request_digest: [u8; 32],
        cleared_fields_digest: [u8; 32],
    ) -> Result<Self, BrokerSessionValidationError> {
        require_traffic(
            session_binding,
            broker_process,
            sequence,
            request_id,
            cleared_fields_digest,
        )?;
        require_nonzero("signed request digest", &signed_request_digest)?;
        Ok(Self {
            session_binding,
            broker_process,
            sequence,
            request_id,
            signed_request_digest,
            cleared_fields_digest,
        })
    }
}

pub(crate) fn audience_code(audience: Audience) -> Result<u8, BrokerSessionValidationError> {
    match audience {
        Audience::AUDIENCE_NODE_CONTROLLER => Ok(1),
        Audience::AUDIENCE_ASSIGNMENT_GUARDIAN => Ok(2),
        Audience::AUDIENCE_MOUNT_WORKER => Ok(3),
        Audience::AUDIENCE_GUEST_AGENT => Ok(4),
        Audience::AUDIENCE_ROOT_MOUNT => Ok(5),
        Audience::AUDIENCE_STORAGE_BROKER => Ok(6),
        Audience::AUDIENCE_UNSPECIFIED => {
            Err(BrokerSessionValidationError::InvalidClosedValue("audience"))
        }
    }
}

pub(crate) fn audience_from_code(code: u8) -> Result<Audience, BrokerSessionValidationError> {
    match code {
        1 => Ok(Audience::AUDIENCE_NODE_CONTROLLER),
        2 => Ok(Audience::AUDIENCE_ASSIGNMENT_GUARDIAN),
        3 => Ok(Audience::AUDIENCE_MOUNT_WORKER),
        4 => Ok(Audience::AUDIENCE_GUEST_AGENT),
        5 => Ok(Audience::AUDIENCE_ROOT_MOUNT),
        6 => Ok(Audience::AUDIENCE_STORAGE_BROKER),
        _ => Err(BrokerSessionValidationError::InvalidClosedValue("audience")),
    }
}

pub(crate) fn method_code(method: BrokerMethod) -> Result<u8, BrokerSessionValidationError> {
    let code = method as i32;
    if code <= 0 || code > i32::from(u8::MAX) {
        Err(BrokerSessionValidationError::InvalidClosedValue("method"))
    } else {
        u8::try_from(code).map_err(|_| BrokerSessionValidationError::InvalidClosedValue("method"))
    }
}

pub(crate) fn require_nonzero<const N: usize>(
    field: &'static str,
    bytes: &[u8; N],
) -> Result<(), BrokerSessionValidationError> {
    if bytes.iter().all(|byte| *byte == 0) {
        Err(BrokerSessionValidationError::Zero(field))
    } else {
        Ok(())
    }
}

fn require_nonzero_scalar(
    field: &'static str,
    value: u64,
) -> Result<(), BrokerSessionValidationError> {
    if value == 0 {
        Err(BrokerSessionValidationError::ZeroScalar(field))
    } else {
        Ok(())
    }
}

#[allow(clippy::too_many_arguments)]
fn require_common(
    node_id: [u8; 16],
    boot_id: [u8; 16],
    major: u16,
    audience: Audience,
    process: [u8; 16],
    nonce: [u8; 32],
    protected_context: [u8; 32],
    cleared: [u8; 32],
) -> Result<(), BrokerSessionValidationError> {
    require_nonzero("node ID", &node_id)?;
    require_nonzero("boot ID", &boot_id)?;
    require_nonzero_scalar("protocol major", u64::from(major))?;
    audience_code(audience)?;
    require_nonzero("process ID", &process)?;
    require_nonzero("nonce", &nonce)?;
    require_nonzero("protected-context digest", &protected_context)?;
    require_nonzero("cleared-fields digest", &cleared)
}

fn require_traffic(
    binding: [u8; 32],
    process: [u8; 16],
    sequence: u64,
    request_id: [u8; 16],
    cleared: [u8; 32],
) -> Result<(), BrokerSessionValidationError> {
    require_nonzero("session binding", &binding)?;
    require_nonzero("process ID", &process)?;
    require_nonzero_scalar("sequence", sequence)?;
    require_nonzero("request ID", &request_id)?;
    require_nonzero("cleared-fields digest", &cleared)
}

pub(crate) fn take_array<const N: usize>(
    bytes: &[u8],
    offset: usize,
) -> Result<[u8; N], BrokerSessionValidationError> {
    bytes
        .get(offset..offset + N)
        .ok_or(BrokerSessionValidationError::InvalidEncoding)?
        .try_into()
        .map_err(|_| BrokerSessionValidationError::InvalidEncoding)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mount_fuse_has_a_distinct_signed_protocol_code() {
        let legacy = BrokerSessionProtocolV1::from_protocol_id(ProtocolId::MountBroker).unwrap();
        let fuse = BrokerSessionProtocolV1::from_protocol_id(ProtocolId::MountFuseBroker).unwrap();

        assert_eq!(legacy, BrokerSessionProtocolV1::Mount);
        assert_eq!(fuse, BrokerSessionProtocolV1::MountFuse);
        assert_ne!(legacy.code(), fuse.code());
        assert_eq!(BrokerSessionProtocolV1::from_code(fuse.code()), Ok(fuse));
        assert!(BrokerSessionProtocolV1::from_code(6).is_err());
    }
}
