//! Durable, method-neutral authenticated request and outcome records.
//!
//! This module preserves the complete signed packets required to recover any
//! method in the closed Broker Session Authentication profile. The format is
//! deliberately independent of a journal implementation: callers perform the
//! compare-and-swap and only then advance the returned snapshot.
//!
//! ```text
//! AOSBSD01 | version:u16be=1 | kind:u8 | protocol:u8 | method:u8 |
//! endpoint:u8 | revision:u64be | session-binding[32] | peer-binding[32] |
//! protected-context[32] | protected-endpoint[32] | protected-catalog[32] |
//! request-id[16] | client-sequence:u64be | broker-sequence:u64be |
//! maximum-response:u32be | predecessor[32] | profile-binding[32] |
//! request-semantics[32] | outcome-semantics[32] | request-length:u32be |
//! outcome-length:u32be | request-companion[336] | request-packet |
//! outcome-companion[416]? | outcome-packet?
//! ```
//!
//! A request record has no outcome fields and sets `broker-sequence` to zero.
//! A terminal record contains both companions and both byte-exact packets.

use aos_proto::aos::sandbox::local::v1::BrokerMethod;
use buffa::Enumeration as _;
use sha2::{Digest as _, Sha256};

use crate::{
    AUTHENTICATED_MOUNT_PREPARE_CATALOG_MAXIMUM_BYTES, AUTHENTICATED_RESPONSE_MAXIMUM_BYTES,
    BROKER_SESSION_OUTCOME_COMPANION_BYTES, BROKER_SESSION_REQUEST_COMPANION_BYTES,
    BrokerSessionCheckpointError, BrokerSessionOutcomeCompanionV1, BrokerSessionProtocolV1,
    BrokerSessionRequestCompanionV1, authenticated_broker_method_profile_v1,
    decode_canonical_request_v1, decode_canonical_response_v1,
};

pub mod history;

const MAGIC: &[u8; 8] = b"AOSBSD01";
const VERSION: u16 = 1;
const REQUEST_KIND: u8 = 1;
const TERMINAL_KIND: u8 = 2;
const HEADER_BYTES: usize = 354;
const REQUEST_PACKET_MAXIMUM_BYTES: usize = AUTHENTICATED_MOUNT_PREPARE_CATALOG_MAXIMUM_BYTES;
const OUTCOME_PACKET_MAXIMUM_BYTES: usize = AUTHENTICATED_RESPONSE_MAXIMUM_BYTES;

/// Maximum encoded durable authenticated exchange value.
pub const BROKER_SESSION_DURABLE_RECORD_MAXIMUM_BYTES: usize = HEADER_BYTES
    + BROKER_SESSION_REQUEST_COMPANION_BYTES
    + REQUEST_PACKET_MAXIMUM_BYTES
    + BROKER_SESSION_OUTCOME_COMPANION_BYTES
    + OUTCOME_PACKET_MAXIMUM_BYTES;

/// Reports a malformed record or an invalid recovery transition.
#[derive(Clone, Debug, Eq, PartialEq, thiserror::Error)]
pub enum BrokerSessionDurableError {
    /// The record has a wrong fixed prefix or unsupported version.
    #[error("invalid durable broker-session format")]
    InvalidFormat,
    /// The record exceeds a fixed allocation ceiling or has inconsistent lengths.
    #[error("invalid durable broker-session record length")]
    InvalidLength,
    /// A required identity, binding, commitment, or revision is zero.
    #[error("durable broker-session record contains a zero required field")]
    ZeroRequiredField,
    /// The protocol, method, or terminal shape is outside the closed profile.
    #[error("invalid durable broker-session closed value")]
    InvalidClosedValue,
    /// The fixed request or outcome companion is malformed.
    #[error("invalid durable broker-session companion: {0}")]
    Companion(#[from] BrokerSessionCheckpointError),
    /// A retained packet is malformed, noncanonical, or not cross-linked.
    #[error("durable broker-session packet does not match its companion")]
    PacketMismatch,
    /// The caller's expected revision or predecessor differs from current state.
    #[error("durable broker-session compare-and-swap failed")]
    CompareAndSwap,
    /// A sequence, request, method, peer, or session binding is discontinuous.
    #[error("durable broker-session transition is not continuous")]
    Continuity,
    /// The retained final sequence cannot advance without wrapping.
    #[error("durable broker-session sequence exhausted")]
    SequenceExhausted,
}

/// Identifies the durable phase of one authenticated exchange.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BrokerSessionDurablePhaseV1 {
    /// The signed request is retained and awaits one terminal outcome.
    RequestPrepared,
    /// The signed request and its signed terminal outcome are retained.
    Terminal,
}

/// Identifies which protected endpoint owns the durable history.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum BrokerSessionDurableEndpointV1 {
    /// The history advances client-send and client-receive state.
    Client = 1,
    /// The history advances broker-receive and broker-send state.
    Broker = 2,
}

/// Binds authenticated traffic to the exact locally verified peer execution.
///
/// The digest is minted by the protected transport owner from its peer policy,
/// kernel credentials, and process-execution observation. It is data here and
/// does not itself prove that those observations were protected or current.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BrokerSessionPeerBindingV1([u8; 32]);

impl BrokerSessionPeerBindingV1 {
    /// Constructs a nonzero exact peer binding.
    ///
    /// # Errors
    ///
    /// Returns [`BrokerSessionDurableError::ZeroRequiredField`] for the zero digest.
    pub fn new(digest: [u8; 32]) -> Result<Self, BrokerSessionDurableError> {
        require_nonzero(&digest)?;
        Ok(Self(digest))
    }

    /// Returns the exact protected-owner commitment.
    #[must_use]
    pub const fn digest(self) -> [u8; 32] {
        self.0
    }
}

/// Persists the protected state observed on both sides of a journal operation.
///
/// These digests are nonauthorizing data. Only the security owner may establish
/// that they name the still-current context, endpoint publication, and catalog.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BrokerSessionProtectedBindingsV1 {
    protected_context: [u8; 32],
    endpoint_publication: [u8; 32],
    current_catalog: [u8; 32],
}

impl BrokerSessionProtectedBindingsV1 {
    /// Constructs a complete set of nonzero protected-state commitments.
    ///
    /// # Errors
    ///
    /// Returns [`BrokerSessionDurableError::ZeroRequiredField`] when any
    /// protected-state commitment is the reserved zero value.
    pub fn new(
        protected_context: [u8; 32],
        endpoint_publication: [u8; 32],
        current_catalog: [u8; 32],
    ) -> Result<Self, BrokerSessionDurableError> {
        require_nonzero(&protected_context)?;
        require_nonzero(&endpoint_publication)?;
        require_nonzero(&current_catalog)?;
        Ok(Self {
            protected_context,
            endpoint_publication,
            current_catalog,
        })
    }

    /// Returns the exact protected verification-context digest.
    #[must_use]
    pub const fn protected_context(self) -> [u8; 32] {
        self.protected_context
    }

    /// Returns the exact protected endpoint-publication digest.
    #[must_use]
    pub const fn endpoint_publication(self) -> [u8; 32] {
        self.endpoint_publication
    }

    /// Returns the exact protected current-catalog digest.
    #[must_use]
    pub const fn current_catalog(self) -> [u8; 32] {
        self.current_catalog
    }
}

/// Retains one fully cross-linked authenticated exchange without authority.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BrokerSessionDurableRecordV1 {
    revision: u64,
    protocol: BrokerSessionProtocolV1,
    endpoint: BrokerSessionDurableEndpointV1,
    method: BrokerMethod,
    session_binding: [u8; 32],
    peer_binding: BrokerSessionPeerBindingV1,
    protected_bindings: BrokerSessionProtectedBindingsV1,
    request_id: [u8; 16],
    client_sequence: u64,
    broker_sequence: u64,
    maximum_response_bytes: u32,
    predecessor: [u8; 32],
    profile_binding: [u8; 32],
    request_semantic_binding: [u8; 32],
    outcome_semantic_binding: [u8; 32],
    request_companion: BrokerSessionRequestCompanionV1,
    request_packet: Vec<u8>,
    outcome_companion: Option<BrokerSessionOutcomeCompanionV1>,
    outcome_packet: Option<Vec<u8>>,
}

impl BrokerSessionDurableRecordV1 {
    /// Creates the first durable request state for one exact signed packet.
    ///
    /// # Errors
    ///
    /// Returns [`BrokerSessionDurableError`] when a binding is zero, the
    /// companion does not match the canonical packet, or its closed profile,
    /// request ID, session, sequence, and response ceiling are inconsistent.
    #[allow(clippy::too_many_arguments)]
    pub fn new_request(
        revision: u64,
        predecessor: [u8; 32],
        endpoint: BrokerSessionDurableEndpointV1,
        session_binding: [u8; 32],
        peer_binding: BrokerSessionPeerBindingV1,
        protected_bindings: BrokerSessionProtectedBindingsV1,
        request_semantic_binding: [u8; 32],
        request_id: [u8; 16],
        request_companion: BrokerSessionRequestCompanionV1,
        request_packet: Vec<u8>,
    ) -> Result<Self, BrokerSessionDurableError> {
        if revision != 1 || predecessor.iter().any(|byte| *byte != 0) {
            return Err(BrokerSessionDurableError::ZeroRequiredField);
        }
        require_nonzero(&session_binding)?;
        require_nonzero(&request_id)?;
        require_nonzero(&request_semantic_binding)?;
        validate_request_packet(
            &request_companion,
            &request_packet,
            session_binding,
            request_id,
        )?;

        let method = request_companion.method();
        let protocol = request_companion.protocol();
        let client_sequence = request_companion.signed_request().subject().sequence();
        if client_sequence != 1 {
            return Err(BrokerSessionDurableError::Continuity);
        }
        let maximum_response_bytes = request_companion.maximum_response_bytes();

        Ok(Self {
            revision,
            protocol,
            endpoint,
            method,
            session_binding,
            peer_binding,
            protected_bindings,
            request_id,
            client_sequence,
            broker_sequence: 0,
            maximum_response_bytes,
            predecessor,
            profile_binding: profile_binding(method)?,
            request_semantic_binding,
            outcome_semantic_binding: [0; 32],
            request_companion,
            request_packet,
            outcome_companion: None,
            outcome_packet: None,
        })
    }

    /// Advances a completed exchange to the next exact pending request.
    ///
    /// # Errors
    ///
    /// Returns [`BrokerSessionDurableError`] unless the current record is
    /// terminal and the successor preserves protocol, session, protected peer,
    /// response profile, exact predecessor, revision, and next client sequence.
    pub fn with_next_request(
        &self,
        protected_bindings: BrokerSessionProtectedBindingsV1,
        request_semantic_binding: [u8; 32],
        request_id: [u8; 16],
        request_companion: BrokerSessionRequestCompanionV1,
        request_packet: Vec<u8>,
    ) -> Result<Self, BrokerSessionDurableError> {
        if self.phase() != BrokerSessionDurablePhaseV1::Terminal
            || request_id == self.request_id
            || request_companion.protocol() != self.protocol
            || protected_bindings.protected_context() != self.protected_bindings.protected_context()
            || protected_bindings.endpoint_publication()
                != self.protected_bindings.endpoint_publication()
            || request_companion.signed_request().subject().sequence()
                != self
                    .client_sequence
                    .checked_add(1)
                    .ok_or(BrokerSessionDurableError::SequenceExhausted)?
        {
            return Err(BrokerSessionDurableError::Continuity);
        }
        let revision = self
            .revision
            .checked_add(1)
            .ok_or(BrokerSessionDurableError::SequenceExhausted)?;
        let predecessor = self.commitment()?;
        require_nonzero(&request_semantic_binding)?;
        validate_request_packet(
            &request_companion,
            &request_packet,
            self.session_binding,
            request_id,
        )?;
        let method = request_companion.method();
        let client_sequence = request_companion.signed_request().subject().sequence();
        let maximum_response_bytes = request_companion.maximum_response_bytes();

        Ok(Self {
            revision,
            protocol: self.protocol,
            endpoint: self.endpoint,
            method,
            session_binding: self.session_binding,
            peer_binding: self.peer_binding,
            protected_bindings,
            request_id,
            client_sequence,
            broker_sequence: 0,
            maximum_response_bytes,
            predecessor,
            profile_binding: profile_binding(method)?,
            request_semantic_binding,
            outcome_semantic_binding: [0; 32],
            request_companion,
            request_packet,
            outcome_companion: None,
            outcome_packet: None,
        })
    }

    /// Adds the exact signed terminal outcome to a retained request.
    ///
    /// # Errors
    ///
    /// Returns [`BrokerSessionDurableError`] if the outcome does not preserve
    /// the request, method, session, sequence, response ceiling, and signed
    /// request digest cross-links.
    pub fn with_terminal_outcome(
        &self,
        revision: u64,
        predecessor: [u8; 32],
        protected_bindings: BrokerSessionProtectedBindingsV1,
        outcome_semantic_binding: [u8; 32],
        outcome_companion: BrokerSessionOutcomeCompanionV1,
        outcome_packet: Vec<u8>,
    ) -> Result<Self, BrokerSessionDurableError> {
        if self.phase() != BrokerSessionDurablePhaseV1::RequestPrepared
            || revision
                != self
                    .revision
                    .checked_add(1)
                    .ok_or(BrokerSessionDurableError::SequenceExhausted)?
            || predecessor != self.commitment()?
            || protected_bindings.protected_context() != self.protected_bindings.protected_context()
            || protected_bindings.endpoint_publication()
                != self.protected_bindings.endpoint_publication()
        {
            return Err(BrokerSessionDurableError::Continuity);
        }
        require_nonzero(&outcome_semantic_binding)?;
        validate_outcome_packet(
            &outcome_companion,
            &outcome_packet,
            self.session_binding,
            self.request_id,
            self.client_sequence,
            self.maximum_response_bytes,
            self.method,
            self.protocol,
        )?;

        let broker_sequence = outcome_companion.signed_outcome().subject().sequence();
        if broker_sequence != self.client_sequence {
            return Err(BrokerSessionDurableError::Continuity);
        }
        Ok(Self {
            revision,
            protocol: self.protocol,
            endpoint: self.endpoint,
            method: self.method,
            session_binding: self.session_binding,
            peer_binding: self.peer_binding,
            protected_bindings,
            request_id: self.request_id,
            client_sequence: self.client_sequence,
            broker_sequence,
            maximum_response_bytes: self.maximum_response_bytes,
            predecessor,
            profile_binding: self.profile_binding,
            request_semantic_binding: self.request_semantic_binding,
            outcome_semantic_binding,
            request_companion: self.request_companion.clone(),
            request_packet: self.request_packet.clone(),
            outcome_companion: Some(outcome_companion),
            outcome_packet: Some(outcome_packet),
        })
    }

    /// Decodes and completely cross-links one bounded canonical record.
    ///
    /// # Errors
    ///
    /// Returns [`BrokerSessionDurableError`] for every malformed, oversized,
    /// noncanonical, unknown, zero, or internally inconsistent field.
    pub fn decode(bytes: &[u8]) -> Result<Self, BrokerSessionDurableError> {
        if bytes.len() < HEADER_BYTES + BROKER_SESSION_REQUEST_COMPANION_BYTES
            || bytes.len() > BROKER_SESSION_DURABLE_RECORD_MAXIMUM_BYTES
        {
            return Err(BrokerSessionDurableError::InvalidLength);
        }
        if bytes.get(..8) != Some(MAGIC.as_slice()) || read_u16(bytes, 8)? != VERSION {
            return Err(BrokerSessionDurableError::InvalidFormat);
        }

        let kind = bytes
            .get(10)
            .copied()
            .ok_or(BrokerSessionDurableError::InvalidLength)?;
        let protocol = decode_protocol(bytes.get(11).copied())?;
        let method = decode_method(bytes.get(12).copied())?;
        let endpoint = decode_endpoint(bytes.get(13).copied())?;
        let revision = read_u64(bytes, 14)?;
        let session_binding = read_array(bytes, 22)?;
        let peer_binding = BrokerSessionPeerBindingV1::new(read_array(bytes, 54)?)?;
        let protected_bindings = BrokerSessionProtectedBindingsV1::new(
            read_array(bytes, 86)?,
            read_array(bytes, 118)?,
            read_array(bytes, 150)?,
        )?;
        let request_id = read_array(bytes, 182)?;
        let client_sequence = read_u64(bytes, 198)?;
        let broker_sequence = read_u64(bytes, 206)?;
        let maximum_response_bytes = read_u32(bytes, 214)?;
        let predecessor = read_array(bytes, 218)?;
        let profile_binding = read_array(bytes, 250)?;
        let request_semantic_binding = read_array(bytes, 282)?;
        let outcome_semantic_binding = read_array(bytes, 314)?;
        let request_length = usize::try_from(read_u32(bytes, 346)?)
            .map_err(|_| BrokerSessionDurableError::InvalidLength)?;
        let outcome_length = usize::try_from(read_u32(bytes, 350)?)
            .map_err(|_| BrokerSessionDurableError::InvalidLength)?;

        let mut cursor = HEADER_BYTES;
        let request_companion_bytes =
            take(bytes, &mut cursor, BROKER_SESSION_REQUEST_COMPANION_BYTES)?;
        let request_companion = BrokerSessionRequestCompanionV1::decode(request_companion_bytes)?;
        let request_packet = take(bytes, &mut cursor, request_length)?.to_vec();

        let (outcome_companion, outcome_packet) = match kind {
            REQUEST_KIND if outcome_length == 0 && broker_sequence == 0 => (None, None),
            TERMINAL_KIND if outcome_length != 0 && broker_sequence != 0 => {
                let companion_bytes =
                    take(bytes, &mut cursor, BROKER_SESSION_OUTCOME_COMPANION_BYTES)?;
                let companion = BrokerSessionOutcomeCompanionV1::decode(companion_bytes)?;
                let packet = take(bytes, &mut cursor, outcome_length)?.to_vec();
                (Some(companion), Some(packet))
            }
            _ => return Err(BrokerSessionDurableError::InvalidClosedValue),
        };
        if cursor != bytes.len() || revision == 0 || client_sequence == 0 {
            return Err(BrokerSessionDurableError::InvalidLength);
        }

        let record = Self {
            revision,
            protocol,
            endpoint,
            method,
            session_binding,
            peer_binding,
            protected_bindings,
            request_id,
            client_sequence,
            broker_sequence,
            maximum_response_bytes,
            predecessor,
            profile_binding,
            request_semantic_binding,
            outcome_semantic_binding,
            request_companion,
            request_packet,
            outcome_companion,
            outcome_packet,
        };
        record.validate_cross_links()?;
        if record.encode()?.as_slice() != bytes {
            return Err(BrokerSessionDurableError::InvalidFormat);
        }
        Ok(record)
    }

    /// Encodes the sole bounded canonical record.
    ///
    /// # Errors
    ///
    /// Returns [`BrokerSessionDurableError`] if retained packet lengths exceed
    /// their fixed allocation ceilings or the record is inconsistent.
    pub fn encode(&self) -> Result<Vec<u8>, BrokerSessionDurableError> {
        self.validate_cross_links()?;
        if self.request_packet.len() > REQUEST_PACKET_MAXIMUM_BYTES
            || self
                .outcome_packet
                .as_ref()
                .is_some_and(|packet| packet.len() > OUTCOME_PACKET_MAXIMUM_BYTES)
        {
            return Err(BrokerSessionDurableError::InvalidLength);
        }
        let outcome_length = self.outcome_packet.as_ref().map_or(0, Vec::len);
        let capacity = HEADER_BYTES
            + BROKER_SESSION_REQUEST_COMPANION_BYTES
            + self.request_packet.len()
            + self
                .outcome_companion
                .as_ref()
                .map_or(0, |_| BROKER_SESSION_OUTCOME_COMPANION_BYTES)
            + outcome_length;
        if capacity > BROKER_SESSION_DURABLE_RECORD_MAXIMUM_BYTES {
            return Err(BrokerSessionDurableError::InvalidLength);
        }

        let request_length = u32::try_from(self.request_packet.len())
            .map_err(|_| BrokerSessionDurableError::InvalidLength)?;
        let outcome_length_u32 =
            u32::try_from(outcome_length).map_err(|_| BrokerSessionDurableError::InvalidLength)?;
        let mut bytes = Vec::with_capacity(capacity);
        bytes.extend_from_slice(MAGIC);
        bytes.extend_from_slice(&VERSION.to_be_bytes());
        bytes.push(match self.phase() {
            BrokerSessionDurablePhaseV1::RequestPrepared => REQUEST_KIND,
            BrokerSessionDurablePhaseV1::Terminal => TERMINAL_KIND,
        });
        bytes.push(self.protocol as u8);
        bytes.push(self.method as u8);
        bytes.push(self.endpoint as u8);
        bytes.extend_from_slice(&self.revision.to_be_bytes());
        bytes.extend_from_slice(&self.session_binding);
        bytes.extend_from_slice(&self.peer_binding.digest());
        bytes.extend_from_slice(&self.protected_bindings.protected_context());
        bytes.extend_from_slice(&self.protected_bindings.endpoint_publication());
        bytes.extend_from_slice(&self.protected_bindings.current_catalog());
        bytes.extend_from_slice(&self.request_id);
        bytes.extend_from_slice(&self.client_sequence.to_be_bytes());
        bytes.extend_from_slice(&self.broker_sequence.to_be_bytes());
        bytes.extend_from_slice(&self.maximum_response_bytes.to_be_bytes());
        bytes.extend_from_slice(&self.predecessor);
        bytes.extend_from_slice(&self.profile_binding);
        bytes.extend_from_slice(&self.request_semantic_binding);
        bytes.extend_from_slice(&self.outcome_semantic_binding);
        bytes.extend_from_slice(&request_length.to_be_bytes());
        bytes.extend_from_slice(&outcome_length_u32.to_be_bytes());
        bytes.extend_from_slice(&self.request_companion.encode());
        bytes.extend_from_slice(&self.request_packet);
        if let (Some(companion), Some(packet)) = (&self.outcome_companion, &self.outcome_packet) {
            bytes.extend_from_slice(&companion.encode());
            bytes.extend_from_slice(packet);
        }
        Ok(bytes)
    }

    /// Returns the domain-separated digest of the complete canonical record.
    ///
    /// # Errors
    ///
    /// Returns [`BrokerSessionDurableError`] if retained packet lengths or
    /// cross-links no longer satisfy the canonical record contract.
    pub fn commitment(&self) -> Result<[u8; 32], BrokerSessionDurableError> {
        let encoded = self.encode()?;
        Ok(digest(
            b"aos-sandbox-broker-session-durable-record-v1\0",
            &encoded,
        ))
    }

    /// Returns the durable record revision.
    #[must_use]
    pub const fn revision(&self) -> u64 {
        self.revision
    }

    /// Returns the exact closed method.
    #[must_use]
    pub const fn method(&self) -> BrokerMethod {
        self.method
    }

    /// Returns the exact broker protocol.
    #[must_use]
    pub const fn protocol(&self) -> BrokerSessionProtocolV1 {
        self.protocol
    }

    /// Returns the protected endpoint that owns this durable history.
    #[must_use]
    pub const fn endpoint(&self) -> BrokerSessionDurableEndpointV1 {
        self.endpoint
    }

    /// Returns the exact session binding.
    #[must_use]
    pub const fn session_binding(&self) -> [u8; 32] {
        self.session_binding
    }

    /// Returns the protected-owner peer commitment.
    #[must_use]
    pub const fn peer_binding(&self) -> BrokerSessionPeerBindingV1 {
        self.peer_binding
    }

    /// Returns the protected context, endpoint, and catalog commitments.
    #[must_use]
    pub const fn protected_bindings(&self) -> BrokerSessionProtectedBindingsV1 {
        self.protected_bindings
    }

    /// Returns the persisted exact method-profile commitment.
    #[must_use]
    pub const fn profile_binding(&self) -> [u8; 32] {
        self.profile_binding
    }

    /// Returns the method-specific canonical request-semantics commitment.
    #[must_use]
    pub const fn request_semantic_binding(&self) -> [u8; 32] {
        self.request_semantic_binding
    }

    /// Returns the outcome-semantics commitment, or zero while pending.
    #[must_use]
    pub const fn outcome_semantic_binding(&self) -> [u8; 32] {
        self.outcome_semantic_binding
    }

    /// Returns the exact request ID.
    #[must_use]
    pub const fn request_id(&self) -> [u8; 16] {
        self.request_id
    }

    /// Returns the admitted client sequence.
    #[must_use]
    pub const fn client_sequence(&self) -> u64 {
        self.client_sequence
    }

    /// Returns the terminal broker sequence, or zero while pending.
    #[must_use]
    pub const fn broker_sequence(&self) -> u64 {
        self.broker_sequence
    }

    /// Returns the request-bound maximum complete response size.
    #[must_use]
    pub const fn maximum_response_bytes(&self) -> u32 {
        self.maximum_response_bytes
    }

    /// Returns the current durable phase.
    #[must_use]
    pub const fn phase(&self) -> BrokerSessionDurablePhaseV1 {
        if self.outcome_companion.is_some() {
            BrokerSessionDurablePhaseV1::Terminal
        } else {
            BrokerSessionDurablePhaseV1::RequestPrepared
        }
    }

    /// Returns the exact signed request packet for recovery or resend.
    #[must_use]
    pub fn request_packet(&self) -> &[u8] {
        &self.request_packet
    }

    /// Returns the exact fixed request companion retained with the packet.
    #[must_use]
    pub const fn request_companion(&self) -> &BrokerSessionRequestCompanionV1 {
        &self.request_companion
    }

    /// Returns the exact signed terminal packet when complete.
    #[must_use]
    pub fn outcome_packet(&self) -> Option<&[u8]> {
        self.outcome_packet.as_deref()
    }

    /// Returns the exact fixed outcome companion when the exchange is terminal.
    #[must_use]
    pub const fn outcome_companion(&self) -> Option<&BrokerSessionOutcomeCompanionV1> {
        self.outcome_companion.as_ref()
    }

    /// Returns the predecessor commitment retained by this record.
    #[must_use]
    pub const fn predecessor(&self) -> [u8; 32] {
        self.predecessor
    }

    fn validate_cross_links(&self) -> Result<(), BrokerSessionDurableError> {
        if self.revision == 0 || self.client_sequence == 0 {
            return Err(BrokerSessionDurableError::ZeroRequiredField);
        }
        let terminal_offset = match self.phase() {
            BrokerSessionDurablePhaseV1::RequestPrepared => 1,
            BrokerSessionDurablePhaseV1::Terminal => 0,
        };
        let expected_revision = self
            .client_sequence
            .checked_mul(2)
            .and_then(|revision| revision.checked_sub(terminal_offset))
            .ok_or(BrokerSessionDurableError::SequenceExhausted)?;
        if self.revision != expected_revision
            || (self.revision == 1 && self.predecessor.iter().any(|byte| *byte != 0))
            || (self.revision != 1 && self.predecessor.iter().all(|byte| *byte == 0))
        {
            return Err(BrokerSessionDurableError::Continuity);
        }
        require_nonzero(&self.session_binding)?;
        require_nonzero(&self.request_id)?;
        require_nonzero(&self.request_semantic_binding)?;
        match self.phase() {
            BrokerSessionDurablePhaseV1::RequestPrepared
                if self.outcome_semantic_binding != [0; 32] =>
            {
                return Err(BrokerSessionDurableError::Continuity);
            }
            BrokerSessionDurablePhaseV1::Terminal => {
                require_nonzero(&self.outcome_semantic_binding)?;
            }
            BrokerSessionDurablePhaseV1::RequestPrepared => {}
        }
        if self.profile_binding != profile_binding(self.method)? {
            return Err(BrokerSessionDurableError::Continuity);
        }
        if self.request_companion.protocol() != self.protocol
            || self.request_companion.method() != self.method
            || self.request_companion.maximum_response_bytes() != self.maximum_response_bytes
            || self.request_companion.signed_request().subject().sequence() != self.client_sequence
        {
            return Err(BrokerSessionDurableError::Continuity);
        }
        validate_request_packet(
            &self.request_companion,
            &self.request_packet,
            self.session_binding,
            self.request_id,
        )?;
        match (&self.outcome_companion, &self.outcome_packet) {
            (None, None) if self.broker_sequence == 0 => Ok(()),
            (Some(companion), Some(packet)) if self.broker_sequence != 0 => {
                validate_outcome_packet(
                    companion,
                    packet,
                    self.session_binding,
                    self.request_id,
                    self.client_sequence,
                    self.maximum_response_bytes,
                    self.method,
                    self.protocol,
                )?;
                if companion.signed_outcome().subject().sequence() != self.broker_sequence
                    || self.broker_sequence != self.client_sequence
                {
                    return Err(BrokerSessionDurableError::Continuity);
                }
                Ok(())
            }
            _ => Err(BrokerSessionDurableError::InvalidClosedValue),
        }
    }
}

/// Describes the exact durable value expected by one compare-and-swap.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BrokerSessionDurableCasV1 {
    expected_revision: u64,
    expected_commitment: [u8; 32],
}

/// Projects durable direction-local sequence state without recreating keys.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BrokerSessionRecoveredSequenceV1 {
    session_binding: [u8; 32],
    peer_binding: BrokerSessionPeerBindingV1,
    revision: u64,
    record_commitment: [u8; 32],
    next_client_sequence: u64,
    next_broker_sequence: u64,
    outstanding_request: bool,
}

impl BrokerSessionRecoveredSequenceV1 {
    /// Recovers exact sequence and compare-and-swap facts from a full history.
    ///
    /// # Errors
    ///
    /// Returns [`BrokerSessionDurableError`] if the history has no valid head
    /// or its terminal sequence cannot advance.
    pub fn from_history(
        history: &history::BrokerSessionDurableHistoryV1,
    ) -> Result<Self, BrokerSessionDurableError> {
        Self::from_record(history.head()?)
    }

    /// Recovers exact sequence and compare-and-swap facts from one record.
    ///
    /// This projection does not recreate a transcript, verification key,
    /// signing key, dispatch permit, or journal ownership.
    ///
    /// # Errors
    ///
    /// Returns [`BrokerSessionDurableError`] if the record cannot advance or
    /// no longer has a canonical commitment.
    pub fn from_record(
        record: &BrokerSessionDurableRecordV1,
    ) -> Result<Self, BrokerSessionDurableError> {
        let completed_increment = match record.phase() {
            BrokerSessionDurablePhaseV1::RequestPrepared => 0,
            BrokerSessionDurablePhaseV1::Terminal => 1,
        };
        let next_client_sequence = record
            .client_sequence()
            .checked_add(completed_increment)
            .ok_or(BrokerSessionDurableError::SequenceExhausted)?;
        let next_broker_sequence = if record.phase() == BrokerSessionDurablePhaseV1::RequestPrepared
        {
            record.client_sequence()
        } else {
            record
                .broker_sequence()
                .checked_add(1)
                .ok_or(BrokerSessionDurableError::SequenceExhausted)?
        };
        Ok(Self {
            session_binding: record.session_binding(),
            peer_binding: record.peer_binding(),
            revision: record.revision(),
            record_commitment: record.commitment()?,
            next_client_sequence,
            next_broker_sequence,
            outstanding_request: record.phase() == BrokerSessionDurablePhaseV1::RequestPrepared,
        })
    }

    /// Returns the exact recovered session binding.
    #[must_use]
    pub const fn session_binding(&self) -> [u8; 32] {
        self.session_binding
    }

    /// Returns the exact recovered protected-peer binding.
    #[must_use]
    pub const fn peer_binding(&self) -> BrokerSessionPeerBindingV1 {
        self.peer_binding
    }

    /// Returns the next new client-to-broker sequence.
    #[must_use]
    pub const fn next_client_sequence(&self) -> u64 {
        self.next_client_sequence
    }

    /// Returns the next new broker-to-client sequence.
    #[must_use]
    pub const fn next_broker_sequence(&self) -> u64 {
        self.next_broker_sequence
    }

    /// Reports whether an exact request remains outstanding.
    #[must_use]
    pub const fn has_outstanding_request(&self) -> bool {
        self.outstanding_request
    }

    /// Returns the exact compare-and-swap target for the next write.
    ///
    /// # Errors
    ///
    /// Returns [`BrokerSessionDurableError::ZeroRequiredField`] only if an
    /// internally retained comparison target is invalid.
    pub fn cas(&self) -> Result<BrokerSessionDurableCasV1, BrokerSessionDurableError> {
        BrokerSessionDurableCasV1::new(self.revision, self.record_commitment)
    }
}

impl BrokerSessionDurableCasV1 {
    /// Creates a nonzero exact comparison target.
    ///
    /// # Errors
    ///
    /// Returns [`BrokerSessionDurableError::ZeroRequiredField`] for a zero field.
    pub fn new(
        expected_revision: u64,
        expected_commitment: [u8; 32],
    ) -> Result<Self, BrokerSessionDurableError> {
        if expected_revision == 0 {
            return Err(BrokerSessionDurableError::ZeroRequiredField);
        }
        require_nonzero(&expected_commitment)?;
        Ok(Self {
            expected_revision,
            expected_commitment,
        })
    }

    /// Verifies this comparison against the recovered current record.
    ///
    /// # Errors
    ///
    /// Returns [`BrokerSessionDurableError::CompareAndSwap`] after replacement.
    pub fn verify(
        &self,
        current: &BrokerSessionDurableRecordV1,
    ) -> Result<(), BrokerSessionDurableError> {
        if self.expected_revision != current.revision()
            || self.expected_commitment != current.commitment()?
        {
            return Err(BrokerSessionDurableError::CompareAndSwap);
        }
        Ok(())
    }

    /// Verifies this comparison against the validated full-history head.
    ///
    /// # Errors
    ///
    /// Returns [`BrokerSessionDurableError::CompareAndSwap`] when the expected
    /// revision or commitment differs from the authoritative history head.
    pub fn verify_history(
        &self,
        history: &history::BrokerSessionDurableHistoryV1,
    ) -> Result<(), BrokerSessionDurableError> {
        self.verify(history.head()?)
    }
}

fn validate_request_packet(
    companion: &BrokerSessionRequestCompanionV1,
    packet: &[u8],
    session_binding: [u8; 32],
    request_id: [u8; 16],
) -> Result<(), BrokerSessionDurableError> {
    if packet.is_empty() || packet.len() > REQUEST_PACKET_MAXIMUM_BYTES {
        return Err(BrokerSessionDurableError::InvalidLength);
    }
    let canonical = decode_canonical_request_v1(packet)
        .map_err(|_| BrokerSessionDurableError::PacketMismatch)?;
    let signed = canonical.signed_artifact();
    if canonical.message().method.as_known() != Some(companion.method())
        || signed != companion.signed_request()
        || signed.subject().session_binding() != session_binding
        || signed.subject().request_id() != request_id
        || authenticated_broker_method_profile_v1(companion.method())
            .is_none_or(|profile| profile.protocol() != companion.protocol())
    {
        return Err(BrokerSessionDurableError::PacketMismatch);
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn validate_outcome_packet(
    companion: &BrokerSessionOutcomeCompanionV1,
    packet: &[u8],
    session_binding: [u8; 32],
    request_id: [u8; 16],
    client_sequence: u64,
    maximum_response_bytes: u32,
    method: BrokerMethod,
    protocol: BrokerSessionProtocolV1,
) -> Result<(), BrokerSessionDurableError> {
    if packet.is_empty()
        || packet.len() > OUTCOME_PACKET_MAXIMUM_BYTES
        || packet.len() > maximum_response_bytes as usize
    {
        return Err(BrokerSessionDurableError::InvalidLength);
    }
    let canonical = decode_canonical_response_v1(packet)
        .map_err(|_| BrokerSessionDurableError::PacketMismatch)?;
    let signed = canonical.signed_artifact();
    if companion.protocol() != protocol
        || companion.method() != method
        || companion.request_id() != request_id
        || companion.client_sequence() != client_sequence
        || companion.maximum_response_bytes() != maximum_response_bytes
        || canonical.message().method.as_known() != Some(method)
        || signed != companion.signed_outcome()
        || signed.subject().session_binding() != session_binding
        || signed.subject().request_id() != request_id
    {
        return Err(BrokerSessionDurableError::PacketMismatch);
    }
    Ok(())
}

fn decode_protocol(
    value: Option<u8>,
) -> Result<BrokerSessionProtocolV1, BrokerSessionDurableError> {
    match value {
        Some(1) => Ok(BrokerSessionProtocolV1::Host),
        Some(2) => Ok(BrokerSessionProtocolV1::Storage),
        Some(3) => Ok(BrokerSessionProtocolV1::Mount),
        Some(4) => Ok(BrokerSessionProtocolV1::Network),
        _ => Err(BrokerSessionDurableError::InvalidClosedValue),
    }
}

fn decode_method(value: Option<u8>) -> Result<BrokerMethod, BrokerSessionDurableError> {
    let value = i32::from(value.ok_or(BrokerSessionDurableError::InvalidLength)?);
    BrokerMethod::from_i32(value)
        .filter(|method| authenticated_broker_method_profile_v1(*method).is_some())
        .ok_or(BrokerSessionDurableError::InvalidClosedValue)
}

fn decode_endpoint(
    value: Option<u8>,
) -> Result<BrokerSessionDurableEndpointV1, BrokerSessionDurableError> {
    match value {
        Some(1) => Ok(BrokerSessionDurableEndpointV1::Client),
        Some(2) => Ok(BrokerSessionDurableEndpointV1::Broker),
        _ => Err(BrokerSessionDurableError::InvalidClosedValue),
    }
}

fn take<'a>(
    bytes: &'a [u8],
    cursor: &mut usize,
    length: usize,
) -> Result<&'a [u8], BrokerSessionDurableError> {
    let end = cursor
        .checked_add(length)
        .ok_or(BrokerSessionDurableError::InvalidLength)?;
    let value = bytes
        .get(*cursor..end)
        .ok_or(BrokerSessionDurableError::InvalidLength)?;
    *cursor = end;
    Ok(value)
}

fn read_u16(bytes: &[u8], offset: usize) -> Result<u16, BrokerSessionDurableError> {
    Ok(u16::from_be_bytes(read_array(bytes, offset)?))
}

fn read_u32(bytes: &[u8], offset: usize) -> Result<u32, BrokerSessionDurableError> {
    Ok(u32::from_be_bytes(read_array(bytes, offset)?))
}

fn read_u64(bytes: &[u8], offset: usize) -> Result<u64, BrokerSessionDurableError> {
    Ok(u64::from_be_bytes(read_array(bytes, offset)?))
}

fn read_array<const N: usize>(
    bytes: &[u8],
    offset: usize,
) -> Result<[u8; N], BrokerSessionDurableError> {
    bytes
        .get(offset..offset.saturating_add(N))
        .ok_or(BrokerSessionDurableError::InvalidLength)?
        .try_into()
        .map_err(|_| BrokerSessionDurableError::InvalidLength)
}

fn require_nonzero<const N: usize>(bytes: &[u8; N]) -> Result<(), BrokerSessionDurableError> {
    if bytes.iter().all(|byte| *byte == 0) {
        return Err(BrokerSessionDurableError::ZeroRequiredField);
    }
    Ok(())
}

fn digest(domain: &[u8], bytes: &[u8]) -> [u8; 32] {
    let mut digest = Sha256::new();
    digest.update(domain);
    digest.update(bytes);
    digest.finalize().into()
}

fn profile_binding(method: BrokerMethod) -> Result<[u8; 32], BrokerSessionDurableError> {
    let profile = authenticated_broker_method_profile_v1(method)
        .ok_or(BrokerSessionDurableError::InvalidClosedValue)?;
    let mut digest = Sha256::new();
    digest.update(b"aos-sandbox-broker-session-method-profile-v1\0");
    digest.update((method as i32).to_be_bytes());
    digest.update([profile.protocol() as u8]);
    let (major, minor) = profile.version();
    digest.update(major.to_be_bytes());
    digest.update(minor.to_be_bytes());
    digest.update((profile.audience() as i32).to_be_bytes());
    digest.update([match profile.authorization() {
        crate::BrokerSessionAuthorizationPresenceV1::Required => 1,
        crate::BrokerSessionAuthorizationPresenceV1::Forbidden => 2,
    }]);
    digest.update(
        u64::try_from(profile.total_request_maximum_bytes())
            .map_err(|_| BrokerSessionDurableError::InvalidLength)?
            .to_be_bytes(),
    );
    digest.update(
        u64::try_from(profile.cleared_request_maximum_bytes())
            .map_err(|_| BrokerSessionDurableError::InvalidLength)?
            .to_be_bytes(),
    );
    digest.update([match profile.success_body() {
        crate::BrokerSessionSuccessBodyPresenceV1::Required => 1,
        crate::BrokerSessionSuccessBodyPresenceV1::Optional => 2,
    }]);
    digest.update(
        u32::try_from(profile.required_features().len())
            .map_err(|_| BrokerSessionDurableError::InvalidLength)?
            .to_be_bytes(),
    );
    for feature in profile.required_features() {
        let namespace = feature.namespace().as_bytes();
        let (major, minor) = feature.version();
        digest.update(
            u32::try_from(namespace.len())
                .map_err(|_| BrokerSessionDurableError::InvalidLength)?
                .to_be_bytes(),
        );
        digest.update(namespace);
        digest.update(major.to_be_bytes());
        digest.update(minor.to_be_bytes());
    }
    for roles in [
        profile.request_descriptor_roles(),
        profile.success_response_descriptor_roles(),
    ] {
        digest.update(
            u32::try_from(roles.len())
                .map_err(|_| BrokerSessionDurableError::InvalidLength)?
                .to_be_bytes(),
        );
        for role in roles {
            digest.update((*role as i32).to_be_bytes());
        }
    }
    let dispositions = profile.request_descriptor_dispositions();
    digest.update(
        u32::try_from(dispositions.len())
            .map_err(|_| BrokerSessionDurableError::InvalidLength)?
            .to_be_bytes(),
    );
    for disposition in dispositions {
        digest.update((*disposition as i32).to_be_bytes());
    }
    Ok(digest.finalize().into())
}
