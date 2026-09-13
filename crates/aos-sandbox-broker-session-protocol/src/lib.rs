//! Broker Session Authentication 1.0 cryptographic and wire foundation.
//!
//! This crate defines a production-inert authentication profile for the four
//! node-local broker protocols. It owns fixed signed artifacts, canonical
//! protobuf projections, protected-context shape checks, transcript binding,
//! and a pure stop-and-wait sequence model. It does not advertise the feature,
//! load protected configuration, generate nonces, dispatch effects, persist a
//! journal, inspect kernel objects, or confer authority.
//!
//! Every signed artifact uses this exact outer envelope:
//!
//! ```text
//! AOSBSA01 || version:u16be=1 || purpose:u8 || method:u8 || reserved[4]=0 ||
//! signer-reference[120] || subject-length:u32be || exact-subject ||
//! strict-ed25519-signature[64]
//! ```
//!
//! [`artifact`] owns the four typed signed records. [`projection`] commits
//! canonical protobuf with only its containing authentication field cleared.
//! [`endpoint_publication`] owns the untrusted broker bootstrap record,
//! [`context`] models caller-supplied protected configuration, and
//! [`transcript`] and [`traffic`] perform pure cryptographic checks. None of
//! those types proves that configuration came from a protected source.

pub mod artifact;
pub mod context;
pub mod endpoint_publication;
pub mod model;
pub mod profile;
pub mod projection;
pub mod traffic;
pub mod transcript;

/// Re-exports only the existing protobuf hello vocabulary needed by sealed integration.
pub mod hello_message {
    pub use aos_proto::aos::sandbox::local::v1::{
        Audience, BrokerClientHello, BrokerMethod, BrokerServerHello, Feature,
    };
}

pub use artifact::{
    BrokerSessionArtifactError, BrokerSessionSignature, SignedBrokerClientHelloV1,
    SignedBrokerHelloV1, SignedBrokerOutcomeV1, SignedBrokerRequestV1,
    complete_signed_client_hello_digest_v1, complete_signed_request_digest_v1,
    sign_broker_hello_v1, sign_client_hello_v1, sign_outcome_v1, sign_request_v1,
    signer_set_digest_v1,
};
pub use context::{ProtectedBrokerSessionKeyV1, ProtectedBrokerSessionVerificationContextV1};
pub use endpoint_publication::{
    BROKER_SESSION_ENDPOINT_PUBLICATION_BYTES, BrokerSessionEndpointPublicationError,
    UntrustedBrokerSessionEndpointPublicationV1,
};
pub use model::{
    BROKER_HELLO_SUBJECT_BYTES, BROKER_OUTCOME_SUBJECT_BYTES, BROKER_REQUEST_SUBJECT_BYTES,
    BROKER_SESSION_AUTHENTICATION_FEATURE_MAJOR, BROKER_SESSION_AUTHENTICATION_FEATURE_MINOR,
    BROKER_SESSION_SIGNED_OVERHEAD_BYTES, BROKER_SESSION_SIGNER_REFERENCE_BYTES,
    BrokerClientHelloSubjectV1, BrokerHelloSubjectV1, BrokerOutcomeSubjectV1,
    BrokerRequestSubjectV1, BrokerSessionKeyUsageV1, BrokerSessionProtocolV1,
    BrokerSessionSignerReferenceV1, BrokerSessionValidationError, CLIENT_HELLO_SUBJECT_BYTES,
    SIGNED_BROKER_HELLO_BYTES, SIGNED_BROKER_OUTCOME_BYTES, SIGNED_BROKER_REQUEST_BYTES,
    SIGNED_CLIENT_HELLO_BYTES,
};
pub use profile::{
    BrokerSessionNegotiationError, maximum_broker_session_request_bytes_v1,
    supported_broker_session_version_v1,
};
pub use projection::{
    AUTHENTICATED_HOST_QUERY_CLEARED_MAXIMUM_BYTES, AUTHENTICATED_HOST_QUERY_MAXIMUM_BYTES,
    AUTHENTICATED_MOUNT_PREPARE_CATALOG_CLEARED_MAXIMUM_BYTES,
    AUTHENTICATED_MOUNT_PREPARE_CATALOG_MAXIMUM_BYTES,
    AUTHENTICATED_ORDINARY_REQUEST_CLEARED_MAXIMUM_BYTES,
    AUTHENTICATED_ORDINARY_REQUEST_MAXIMUM_BYTES, AUTHENTICATED_RESPONSE_CLEARED_MAXIMUM_BYTES,
    AUTHENTICATED_RESPONSE_MAXIMUM_BYTES, AUTHENTICATED_RESPONSE_MINIMUM_BYTES,
    BrokerSessionProjectionError, CLIENT_HELLO_CLEARED_MAXIMUM_BYTES, CLIENT_HELLO_MAXIMUM_BYTES,
    CanonicalBrokerClientHelloV1, CanonicalBrokerRequestEnvelopeV1,
    CanonicalBrokerResponseEnvelopeV1, CanonicalBrokerServerHelloV1,
    SERVER_HELLO_CLEARED_MAXIMUM_BYTES, SERVER_HELLO_MAXIMUM_BYTES, client_hello_fields_digest_v1,
    decode_canonical_client_hello_v1, decode_canonical_request_v1, decode_canonical_response_v1,
    decode_canonical_server_hello_v1, encode_signed_client_hello_packet_v1,
    encode_signed_server_hello_packet_v1, outcome_fields_digest_v1, request_fields_digest_v1,
    server_hello_fields_digest_v1,
};
pub use traffic::{
    BrokerOutcomeAdmissionV1, BrokerRequestAdmissionV1, BrokerSessionReplayEvidenceV1,
    BrokerSessionSequenceError, BrokerSessionTrafficStateV1,
    CryptographicallyVerifiedBrokerOutcomeV1, CryptographicallyVerifiedBrokerRequestV1,
};
pub use transcript::{
    BrokerSessionTranscriptError, BrokerSessionTranscriptPhaseV1, ContextVerifiedClientHelloV1,
    StrictlyVerifiedClientHelloV1, VerifiedBrokerSessionTranscriptV1,
    verify_broker_session_transcript_after_client_v1, verify_broker_session_transcript_v1,
    verify_client_hello_context_v1, verify_client_hello_signature_v1,
};
