//! Canonical authentication for dormant backing-operation completions.
//!
//! The record is fixed width and signed with the protected session's broker
//! outcome key. Verification binds the protected peer and session, the exact
//! worker connection, all broker currentness inputs, the durable registration
//! operation, the complete backing identity commitment, the broker selector,
//! and the descriptor identity. This module performs no I/O and does not load
//! keys or establish their protected provenance.
//!
//! ```text
//! magic[8]="AOSFBC01" || version:u16be=1 || kind:u8=(OPEN=1,CLOSE=2) ||
//! reserved[5]=0 || request-id[16] || method:u8 || signed-request-digest[32] ||
//! canonical-outcome-packet-commitment[32] || peer-binding[32] || session-binding[32] ||
//! connection-authority[32] || worker-brand:u64be || callback-reducer-commitment[32] ||
//! callback-request-identity[32] || raw-handle:u64be || broker-execution[32] ||
//! broker-authority-generation:u64be || broker-outcome-sequence:u64be ||
//! publication-generation:u64be ||
//! protected-currentness[32] || registration-operation:u64be ||
//! backing-identity-commitment[32] || backing-id:u64be ||
//! descriptor-identity-commitment[32] || Ed25519-signature[64]
//! ```
//!
//! The signature covers the domain string
//! `aos-filesystem-backing-completion-v1\0` followed by every byte before the
//! signature.

use aos_filesystem_view::{
    BackingDisposition, BackingIdentity, MetadataConnection, RegistrationOperation, WorkerError,
};
use aos_sandbox_broker_session_protocol::{
    BrokerSessionKeyUsageV1, BrokerSessionProtocolV1, CanonicalBrokerResponseEnvelopeV1,
    ProtectedBrokerSessionVerificationContextV1, hello_message::BrokerMethod,
};
use aos_sandbox_broker_session_security::{
    ProtectedBrokerOutcomeAdmissionGateV1, ProtectedBrokerOutcomeAdmissionV1,
    ProtectedBrokerOutcomeCommittedAdvancementV1, ProtectedBrokerOutcomePendingAdvancementV1,
    ProtectedBrokerOutcomeReplayV1,
};
use ed25519_dalek::{Signature, VerifyingKey};
use sha2::{Digest as _, Sha256};

use super::{CompletedBackingClose, CompletedBackingOpen, DormantBackingReceiptFactory};
use crate::file_callbacks::{
    BackingCloseReceipt, BackingOpenReceipt, FileCallbackError, PendingCallbackOpen, ReleasePlan,
};

const COMPLETION_MAGIC: [u8; 8] = *b"AOSFBC01";
const COMPLETION_VERSION: u16 = 1;
const COMPLETION_RESERVED_BYTES: usize = 5;
const COMPLETION_BODY_BYTES: usize = 8
    + 2
    + 1
    + COMPLETION_RESERVED_BYTES
    + 16
    + 1
    + 32
    + 32
    + 32
    + 32
    + 32
    + 8
    + 32
    + 32
    + 8
    + 32
    + 8
    + 8
    + 8
    + 32
    + 8
    + 32
    + 8
    + 32;
const COMPLETION_SIGNATURE_BYTES: usize = 64;
/// Exact byte length of one canonical signed backing completion.
pub(crate) const SIGNED_BACKING_COMPLETION_BYTES: usize =
    COMPLETION_BODY_BYTES + COMPLETION_SIGNATURE_BYTES;
const COMPLETION_SIGNATURE_DOMAIN: &[u8] = b"aos-filesystem-backing-completion-v1\0";
const COMPLETION_SIGNING_MESSAGE_BYTES: usize =
    COMPLETION_SIGNATURE_DOMAIN.len() + COMPLETION_BODY_BYTES;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum CompletionKind {
    Open,
    Close,
}

impl CompletionKind {
    fn decode(value: u8) -> Result<Self, FileCallbackError> {
        match value {
            1 => Ok(Self::Open),
            2 => Ok(Self::Close),
            _ => Err(integrity_error()),
        }
    }
}

/// Holds protected authority for one broker-completion verification.
///
/// Construction consumes security-owned proof of an exact protected current
/// head. The protocol context supplies only the public key after its protected
/// context digest has been matched to that proof.
pub(crate) struct ProtectedBrokerCompletionAuthority {
    gate: ProtectedBrokerOutcomeAdmissionGateV1,
    backing: BackingIdentity,
    peer_binding: [u8; 32],
    session_binding: [u8; 32],
    request_id: [u8; 16],
    method: BrokerMethod,
    signed_request_digest: [u8; 32],
    broker_execution: [u8; 32],
    broker_generation: u64,
    broker_sequence: u64,
    publication_generation: u64,
    currentness_commitment: [u8; 32],
    durable_revision: u64,
    durable_commitment: [u8; 32],
    verifying_key: VerifyingKey,
}

impl ProtectedBrokerCompletionAuthority {
    /// Derives authority from a protected current-head outcome gate.
    ///
    /// # Errors
    ///
    /// Returns an integrity error unless the gate and shape-only context agree
    /// on the exact protected Mount currentness and active broker-outcome key.
    pub(crate) fn from_protected_gate(
        gate: ProtectedBrokerOutcomeAdmissionGateV1,
        context: &ProtectedBrokerSessionVerificationContextV1,
        backing: BackingIdentity,
    ) -> Result<Self, FileCallbackError> {
        let protected_context = context.protected_context_digest();
        if context.protocol() != BrokerSessionProtocolV1::Mount
            || gate.protected_bindings().protected_context() != protected_context
            || gate.session_binding() == [0; 32]
            || gate.request_id() == [0; 16]
            || gate.signed_request_digest() == [0; 32]
            || gate.client_sequence() == 0
            || gate.client_sequence() == u64::MAX
            || gate.protected_generation() == 0
            || gate.protected_head() == [0; 32]
            || context.keys().iter().any(|key| !key.is_active())
        {
            return Err(integrity_error());
        }
        let broker_outcome_key = context
            .keys()
            .iter()
            .find(|key| key.signer().usage() == BrokerSessionKeyUsageV1::BrokerOutcome)
            .ok_or_else(integrity_error)?;
        let verifying_key = VerifyingKey::from_bytes(broker_outcome_key.public_key())
            .map_err(|_| integrity_error())?;
        if verifying_key.is_weak() {
            return Err(integrity_error());
        }
        let mut broker_execution = [0; 32];
        broker_execution[..16].copy_from_slice(&context.client_process());
        broker_execution[16..].copy_from_slice(&context.broker_process());
        Ok(Self {
            backing,
            peer_binding: gate.peer_binding().digest(),
            session_binding: gate.session_binding(),
            request_id: gate.request_id(),
            method: gate.method(),
            signed_request_digest: gate.signed_request_digest(),
            broker_execution,
            broker_generation: gate.protected_generation(),
            broker_sequence: gate.client_sequence(),
            publication_generation: backing.publication_generation(),
            currentness_commitment: gate.protected_head(),
            durable_revision: gate.durable_revision(),
            durable_commitment: gate.durable_commitment(),
            verifying_key,
            gate,
        })
    }
}

/// Retains one bounded canonical signed broker completion packet.
///
/// It has no scalar constructor or public projections. Parsing authenticates
/// neither the signer nor currentness; only [`DormantBrokerCompletionVerifier`]
/// can convert it into callback success evidence.
pub(crate) struct SignedBackingCompletion {
    canonical_body: [u8; COMPLETION_BODY_BYTES],
    signature: [u8; COMPLETION_SIGNATURE_BYTES],
    kind: CompletionKind,
    request_id: [u8; 16],
    method: u8,
    signed_request_digest: [u8; 32],
    outcome_packet_commitment: [u8; 32],
    peer_binding: [u8; 32],
    session_binding: [u8; 32],
    authority_binding: [u8; 32],
    worker_brand: u64,
    reducer_identity: [u8; 32],
    callback_request_identity: [u8; 32],
    raw_handle: u64,
    broker_execution: [u8; 32],
    broker_generation: u64,
    broker_sequence: u64,
    publication_generation: u64,
    currentness_commitment: [u8; 32],
    operation: u64,
    backing_commitment: [u8; 32],
    backing_id: u64,
    descriptor_commitment: [u8; 32],
}

impl SignedBackingCompletion {
    /// Decodes the exact fixed-width canonical broker completion record.
    ///
    /// # Errors
    ///
    /// Returns an integrity error for wrong length, magic, version, reserved
    /// bytes, completion kind, trailing data, or any zero required field.
    pub(crate) fn from_canonical_bytes(bytes: &[u8]) -> Result<Self, FileCallbackError> {
        if bytes.len() != SIGNED_BACKING_COMPLETION_BYTES {
            return Err(integrity_error());
        }
        let mut cursor = CompletionCursor::new(bytes);
        if cursor.array::<8>()? != COMPLETION_MAGIC || cursor.u16()? != COMPLETION_VERSION {
            return Err(integrity_error());
        }
        let kind = CompletionKind::decode(cursor.u8()?)?;
        if cursor.array::<COMPLETION_RESERVED_BYTES>()? != [0; COMPLETION_RESERVED_BYTES] {
            return Err(integrity_error());
        }
        let request_id = cursor.nonzero_array()?;
        let method = cursor.u8()?;
        if method == 0 {
            return Err(integrity_error());
        }
        let signed_request_digest = cursor.nonzero_array()?;
        let outcome_packet_commitment = cursor.nonzero_array()?;
        let peer_binding = cursor.nonzero_array()?;
        let session_binding = cursor.nonzero_array()?;
        let authority_binding = cursor.nonzero_array()?;
        let worker_brand = cursor.nonzero_u64()?;
        let reducer_identity = cursor.nonzero_array()?;
        let callback_request_identity = cursor.nonzero_array()?;
        let raw_handle = cursor.nonzero_u64()?;
        let broker_execution = cursor.nonzero_array()?;
        let broker_generation = cursor.nonzero_u64()?;
        let broker_sequence = cursor.nonzero_u64()?;
        let publication_generation = cursor.nonzero_u64()?;
        let currentness_commitment = cursor.nonzero_array()?;
        let operation = cursor.nonzero_u64()?;
        let backing_commitment = cursor.nonzero_array()?;
        let backing_id = cursor.nonzero_u64()?;
        let descriptor_commitment = cursor.nonzero_array()?;
        let signature = cursor.nonzero_array()?;
        cursor.finish()?;

        let mut canonical_body = [0; COMPLETION_BODY_BYTES];
        canonical_body.copy_from_slice(&bytes[..COMPLETION_BODY_BYTES]);
        Ok(Self {
            canonical_body,
            signature,
            kind,
            request_id,
            method,
            signed_request_digest,
            outcome_packet_commitment,
            peer_binding,
            session_binding,
            authority_binding,
            worker_brand,
            reducer_identity,
            callback_request_identity,
            raw_handle,
            broker_execution,
            broker_generation,
            broker_sequence,
            publication_generation,
            currentness_commitment,
            operation,
            backing_commitment,
            backing_id,
            descriptor_commitment,
        })
    }
}

/// Verifies and consumes one signed completion under one protected snapshot.
///
/// This type is deliberately non-`Clone`. Each method consumes it and its
/// signed packet before the sealed completion enters the receipt factory.
pub(crate) struct DormantBrokerCompletionVerifier {
    factory: DormantBackingReceiptFactory,
    gate: ProtectedBrokerOutcomeAdmissionGateV1,
    effect: CompletionEffectBinding,
    peer_binding: [u8; 32],
    session_binding: [u8; 32],
    request_id: [u8; 16],
    method: BrokerMethod,
    signed_request_digest: [u8; 32],
    verifying_key: VerifyingKey,
}

#[derive(Clone, Copy)]
enum CompletionEffectBinding {
    Open {
        operation: RegistrationOperation,
        backing: BackingIdentity,
    },
    Close {
        operation: RegistrationOperation,
        backing: BackingIdentity,
        backing_id: u64,
        descriptor_commitment: [u8; 32],
    },
}

/// Returns either a pending completion with durable advancement or replay evidence.
#[must_use = "commit new advancement before minting or honor replay without a receipt"]
pub(crate) enum BrokerCompletionAdmission<T> {
    /// The outcome was new but cannot mint a receipt before durable confirmation.
    New {
        /// Move-only authenticated completion awaiting committed currentness.
        pending: T,
        /// Exact uncommitted session advancement and durable CAS ownership.
        advancement: ProtectedBrokerOutcomePendingAdvancementV1,
    },
    /// The signed outcome was an exact replay and minted no callback receipt.
    ExactReplay {
        /// Move-only protected replay/no-write evidence.
        replay: ProtectedBrokerOutcomeReplayV1,
    },
}

/// Retains authenticated OPEN evidence until protected CAS confirmation.
#[must_use = "only confirmed durable advancement may unlock the OPEN receipt"]
pub(crate) struct PendingBackingOpenReceipt {
    factory: DormantBackingReceiptFactory,
    completion: VerifiedBackingOpenCompletion,
    binding: CompletionCommitBinding,
}

/// Retains authenticated CLOSE evidence until protected CAS confirmation.
#[must_use = "only confirmed durable advancement may unlock the CLOSE receipt"]
pub(crate) struct PendingBackingCloseReceipt {
    factory: DormantBackingReceiptFactory,
    completion: VerifiedBackingCloseCompletion,
    binding: CompletionCommitBinding,
}

/// Couples a post-CAS receipt with the only usable advanced traffic state.
#[must_use = "retain both the callback receipt and committed session advancement"]
pub(crate) struct CommittedBrokerReceipt<T> {
    /// Callback receipt unlocked by confirmed protected persistence.
    pub(crate) receipt: T,
    /// Move-only committed advancement carrying usable next traffic.
    pub(crate) advancement: ProtectedBrokerOutcomeCommittedAdvancementV1,
}

struct CompletionCommitBinding {
    method: BrokerMethod,
    request_id: [u8; 16],
    signed_request_digest: [u8; 32],
    client_sequence: u64,
    broker_sequence: u64,
    session_binding: [u8; 32],
    peer_binding: [u8; 32],
    protected_generation: u64,
    protected_head: [u8; 32],
    durable_revision: u64,
    durable_commitment: [u8; 32],
    replacement_head: [u8; 32],
    admission_commitment: [u8; 32],
}

impl PendingBackingOpenReceipt {
    /// Mints OPEN success only after exact protected CAS and readback.
    ///
    /// # Errors
    ///
    /// Returns a stale or integrity error together with the still-owned
    /// committed advancement unless every binding remains exact.
    pub(crate) fn mint_after_commit(
        self,
        connection: &MetadataConnection<'_, '_, '_, '_>,
        advancement: ProtectedBrokerOutcomeCommittedAdvancementV1,
    ) -> Result<
        CommittedBrokerReceipt<BackingOpenReceipt>,
        (
            FileCallbackError,
            ProtectedBrokerOutcomeCommittedAdvancementV1,
        ),
    > {
        if let Err(error) = validate_committed_advancement(&self.binding, &advancement) {
            return Err((error, advancement));
        }
        let operation = self.completion.operation;
        let backing = self.completion.backing;
        let receipt = match self
            .factory
            .mint_open(connection, operation, backing, self.completion)
        {
            Ok(receipt) => receipt,
            Err(error) => return Err((error, advancement)),
        };
        Ok(CommittedBrokerReceipt {
            receipt,
            advancement,
        })
    }
}

impl PendingBackingCloseReceipt {
    /// Mints CLOSE success only after exact protected CAS and readback.
    ///
    /// # Errors
    ///
    /// Returns a stale or integrity error together with the still-owned
    /// committed advancement unless every binding remains exact.
    pub(crate) fn mint_after_commit(
        self,
        connection: &MetadataConnection<'_, '_, '_, '_>,
        advancement: ProtectedBrokerOutcomeCommittedAdvancementV1,
    ) -> Result<
        CommittedBrokerReceipt<BackingCloseReceipt>,
        (
            FileCallbackError,
            ProtectedBrokerOutcomeCommittedAdvancementV1,
        ),
    > {
        if let Err(error) = validate_committed_advancement(&self.binding, &advancement) {
            return Err((error, advancement));
        }
        let operation = self.completion.operation;
        let backing = self.completion.backing;
        let backing_id = self.completion.backing_id;
        let descriptor_commitment = self.completion.descriptor_commitment;
        let receipt = match self.factory.mint_close(
            connection,
            operation,
            backing,
            backing_id,
            descriptor_commitment,
            self.completion,
        ) {
            Ok(receipt) => receipt,
            Err(error) => return Err((error, advancement)),
        };
        Ok(CommittedBrokerReceipt {
            receipt,
            advancement,
        })
    }
}

impl DormantBrokerCompletionVerifier {
    /// Binds a verifier to one exact pending OPEN and protected outcome gate.
    ///
    /// # Errors
    ///
    /// Returns a stale error for mismatched pending state, or an integrity
    /// error when the connection or protected gate fails currentness.
    pub(crate) fn for_pending_open(
        connection: &MetadataConnection<'_, '_, '_, '_>,
        authority: ProtectedBrokerCompletionAuthority,
        pending: &PendingCallbackOpen<'_>,
    ) -> Result<Self, FileCallbackError> {
        let operation = pending.registration.ok_or(FileCallbackError::Stale)?;
        let BackingDisposition::Passthrough(backing) = pending.data.disposition() else {
            return Err(FileCallbackError::Stale);
        };
        if backing != authority.backing
            || pending.backing_id.is_some()
            || pending.descriptor_commitment.is_some()
        {
            return Err(FileCallbackError::Stale);
        }
        Self::for_binding(
            connection,
            authority,
            pending.reducer_identity,
            pending.callback_request_identity,
            pending.worker.raw_handle(),
            CompletionEffectBinding::Open { operation, backing },
        )
    }

    /// Binds a verifier to one exact close plan and protected outcome gate.
    ///
    /// # Errors
    ///
    /// Returns a stale error unless `plan` requires one exactly bound close,
    /// or an integrity error when the connection or gate fails currentness.
    pub(crate) fn for_close_plan(
        connection: &MetadataConnection<'_, '_, '_, '_>,
        authority: ProtectedBrokerCompletionAuthority,
        plan: ReleasePlan,
    ) -> Result<Self, FileCallbackError> {
        let ReleasePlan::CloseBacking {
            operation,
            backing,
            backing_id,
            reducer_commitment,
            callback_request_identity,
            raw_handle,
            descriptor_commitment,
        } = plan
        else {
            return Err(FileCallbackError::Stale);
        };
        if backing != authority.backing {
            return Err(FileCallbackError::Stale);
        }
        Self::for_binding(
            connection,
            authority,
            reducer_commitment,
            callback_request_identity,
            raw_handle,
            CompletionEffectBinding::Close {
                operation,
                backing,
                backing_id,
                descriptor_commitment,
            },
        )
    }

    fn for_binding(
        connection: &MetadataConnection<'_, '_, '_, '_>,
        authority: ProtectedBrokerCompletionAuthority,
        reducer_identity: [u8; 32],
        callback_request_identity: [u8; 32],
        raw_handle: u64,
        effect: CompletionEffectBinding,
    ) -> Result<Self, FileCallbackError> {
        let factory = DormantBackingReceiptFactory::for_connection(
            connection,
            reducer_identity,
            callback_request_identity,
            raw_handle,
            authority.broker_execution,
            authority.broker_generation,
            authority.broker_sequence,
            authority.publication_generation,
            authority.currentness_commitment,
            authority.durable_revision,
            authority.durable_commitment,
        )?;
        Ok(Self {
            factory,
            gate: authority.gate,
            effect,
            peer_binding: authority.peer_binding,
            session_binding: authority.session_binding,
            request_id: authority.request_id,
            method: authority.method,
            signed_request_digest: authority.signed_request_digest,
            verifying_key: authority.verifying_key,
        })
    }

    /// Verifies a signed OPEN completion without minting a callback receipt.
    ///
    /// # Errors
    ///
    /// Returns an integrity error for failed Ed25519 verification, or a stale
    /// error unless every protected, connection, operation, backing, selector,
    /// currentness, and descriptor binding is exact.
    pub(crate) fn verify_open(
        self,
        connection: &MetadataConnection<'_, '_, '_, '_>,
        signed: SignedBackingCompletion,
        outcome: &CanonicalBrokerResponseEnvelopeV1,
    ) -> Result<BrokerCompletionAdmission<PendingBackingOpenReceipt>, FileCallbackError> {
        let CompletionEffectBinding::Open { operation, backing } = self.effect else {
            return Err(FileCallbackError::Stale);
        };
        let backing_id = signed.backing_id;
        let descriptor_commitment = signed.descriptor_commitment;
        let (factory, admission) = self.admit(
            connection,
            CompletionKind::Open,
            operation,
            backing,
            backing_id,
            &signed,
            outcome,
        )?;
        match admission {
            ProtectedBrokerOutcomeAdmissionV1::New { advancement } => {
                validate_pending_advancement(&factory, &advancement)?;
                let completion = VerifiedBackingOpenCompletion::from_authenticated(
                    &factory,
                    operation,
                    backing,
                    backing_id,
                    descriptor_commitment,
                );
                let binding = CompletionCommitBinding::from_pending(
                    &factory,
                    &signed,
                    CompletionKind::Open,
                    &advancement,
                );
                Ok(BrokerCompletionAdmission::New {
                    pending: PendingBackingOpenReceipt {
                        factory,
                        completion,
                        binding,
                    },
                    advancement,
                })
            }
            ProtectedBrokerOutcomeAdmissionV1::ExactReplay { replay } => {
                validate_replay(&factory, &signed, outcome, &replay)?;
                Ok(BrokerCompletionAdmission::ExactReplay { replay })
            }
        }
    }

    /// Verifies a signed CLOSE completion without minting a callback receipt.
    ///
    /// # Errors
    ///
    /// Returns an integrity error for failed Ed25519 verification, or a stale
    /// error unless every protected, connection, operation, backing, selector,
    /// currentness, and descriptor binding is exact.
    pub(crate) fn verify_close(
        self,
        connection: &MetadataConnection<'_, '_, '_, '_>,
        signed: SignedBackingCompletion,
        outcome: &CanonicalBrokerResponseEnvelopeV1,
    ) -> Result<BrokerCompletionAdmission<PendingBackingCloseReceipt>, FileCallbackError> {
        let CompletionEffectBinding::Close {
            operation,
            backing,
            backing_id,
            descriptor_commitment,
        } = self.effect
        else {
            return Err(FileCallbackError::Stale);
        };
        if backing_id == 0
            || descriptor_commitment == [0; 32]
            || signed.descriptor_commitment != descriptor_commitment
        {
            return Err(FileCallbackError::Stale);
        }
        let (factory, admission) = self.admit(
            connection,
            CompletionKind::Close,
            operation,
            backing,
            backing_id,
            &signed,
            outcome,
        )?;
        match admission {
            ProtectedBrokerOutcomeAdmissionV1::New { advancement } => {
                validate_pending_advancement(&factory, &advancement)?;
                let completion = VerifiedBackingCloseCompletion::from_authenticated(
                    &factory,
                    operation,
                    backing,
                    backing_id,
                    descriptor_commitment,
                );
                let binding = CompletionCommitBinding::from_pending(
                    &factory,
                    &signed,
                    CompletionKind::Close,
                    &advancement,
                );
                Ok(BrokerCompletionAdmission::New {
                    pending: PendingBackingCloseReceipt {
                        factory,
                        completion,
                        binding,
                    },
                    advancement,
                })
            }
            ProtectedBrokerOutcomeAdmissionV1::ExactReplay { replay } => {
                validate_replay(&factory, &signed, outcome, &replay)?;
                Ok(BrokerCompletionAdmission::ExactReplay { replay })
            }
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn admit(
        self,
        connection: &MetadataConnection<'_, '_, '_, '_>,
        expected_kind: CompletionKind,
        expected_operation: RegistrationOperation,
        expected_backing: BackingIdentity,
        expected_backing_id: u64,
        signed: &SignedBackingCompletion,
        outcome: &CanonicalBrokerResponseEnvelopeV1,
    ) -> Result<
        (
            DormantBackingReceiptFactory,
            ProtectedBrokerOutcomeAdmissionV1,
        ),
        FileCallbackError,
    > {
        self.verify_signature(signed)?;
        self.verify_bindings(
            connection,
            expected_kind,
            expected_operation,
            expected_backing,
            expected_backing_id,
            signed,
            outcome,
        )?;
        let admission = self
            .gate
            .admit_outcome(outcome)
            .map_err(|_| integrity_error())?;
        Ok((self.factory, admission))
    }

    fn verify_signature(&self, signed: &SignedBackingCompletion) -> Result<(), FileCallbackError> {
        let mut message = [0; COMPLETION_SIGNING_MESSAGE_BYTES];
        let body_offset = COMPLETION_SIGNATURE_DOMAIN.len();
        message[..body_offset].copy_from_slice(COMPLETION_SIGNATURE_DOMAIN);
        message[body_offset..].copy_from_slice(&signed.canonical_body);
        self.verifying_key
            .verify_strict(&message, &Signature::from_bytes(&signed.signature))
            .map_err(|_| integrity_error())
    }

    #[allow(clippy::too_many_arguments)]
    fn verify_bindings(
        &self,
        connection: &MetadataConnection<'_, '_, '_, '_>,
        expected_kind: CompletionKind,
        expected_operation: RegistrationOperation,
        expected_backing: BackingIdentity,
        expected_backing_id: u64,
        signed: &SignedBackingCompletion,
        outcome: &CanonicalBrokerResponseEnvelopeV1,
    ) -> Result<(), FileCallbackError> {
        if connection.is_faulted() {
            return Err(integrity_error());
        }
        let outcome_subject = outcome.signed_artifact().subject();
        if signed.kind != expected_kind
            || self.method != method_for_kind(expected_kind)
            || signed.method != self.method as u8
            || signed.request_id != self.request_id
            || signed.signed_request_digest != self.signed_request_digest
            || signed.request_id != outcome_subject.request_id()
            || signed.signed_request_digest != outcome_subject.signed_request_digest()
            || self.method != outcome.signed_artifact().method()
            || signed.session_binding != outcome_subject.session_binding()
            || signed.broker_sequence != outcome_subject.sequence()
            || signed.broker_execution[16..] != outcome_subject.broker_process()
            || signed.outcome_packet_commitment
                != outcome_packet_commitment(outcome.encoded_bytes())
            || signed.peer_binding != self.peer_binding
            || signed.session_binding != self.session_binding
            || signed.authority_binding != self.factory.authority_binding
            || signed.worker_brand != self.factory.worker_brand
            || signed.reducer_identity != self.factory.reducer_identity
            || signed.callback_request_identity != self.factory.callback_request_identity
            || signed.raw_handle != self.factory.raw_handle
            || signed.broker_execution != self.factory.broker_execution
            || signed.broker_generation != self.factory.broker_generation
            || signed.broker_sequence != self.factory.broker_sequence
            || signed.publication_generation != self.factory.publication_generation
            || signed.currentness_commitment != self.factory.currentness_commitment
            || signed.operation != expected_operation.get()
            || signed.backing_commitment != expected_backing.evidence_commitment()
            || signed.backing_id != expected_backing_id
        {
            return Err(FileCallbackError::Stale);
        }
        Ok(())
    }
}

fn validate_pending_advancement(
    factory: &DormantBackingReceiptFactory,
    advancement: &ProtectedBrokerOutcomePendingAdvancementV1,
) -> Result<(), FileCallbackError> {
    if advancement.durable_cas().expected_generation() != factory.broker_generation
        || advancement.durable_cas().expected_head() != factory.currentness_commitment
        || advancement.durable_cas().expected_revision() != factory.durable_revision
        || advancement.durable_cas().expected_commitment() != factory.durable_commitment
        || advancement.durable_cas().replacement_head() == [0; 32]
        || advancement.replacement_history().is_empty()
        || advancement.admission_commitment() == [0; 32]
    {
        return Err(integrity_error());
    }
    Ok(())
}

fn validate_replay(
    factory: &DormantBackingReceiptFactory,
    signed: &SignedBackingCompletion,
    outcome: &CanonicalBrokerResponseEnvelopeV1,
    replay: &ProtectedBrokerOutcomeReplayV1,
) -> Result<(), FileCallbackError> {
    if replay.method() as u8 != signed.method
        || replay.request_id() != signed.request_id
        || replay.signed_request_digest() != signed.signed_request_digest
        || replay.client_sequence() != factory.broker_sequence
        || replay.broker_sequence() != factory.broker_sequence
        || replay.session_binding() != signed.session_binding
        || replay.peer_binding().digest() != signed.peer_binding
        || replay.protected_generation() != factory.broker_generation
        || replay.protected_head() != factory.currentness_commitment
        || replay.exact_packet() != outcome.encoded_bytes()
    {
        return Err(integrity_error());
    }
    Ok(())
}

impl CompletionCommitBinding {
    fn from_pending(
        factory: &DormantBackingReceiptFactory,
        signed: &SignedBackingCompletion,
        kind: CompletionKind,
        advancement: &ProtectedBrokerOutcomePendingAdvancementV1,
    ) -> Self {
        Self {
            method: method_for_kind(kind),
            request_id: signed.request_id,
            signed_request_digest: signed.signed_request_digest,
            client_sequence: factory.broker_sequence,
            broker_sequence: signed.broker_sequence,
            session_binding: signed.session_binding,
            peer_binding: signed.peer_binding,
            protected_generation: factory.broker_generation,
            protected_head: factory.currentness_commitment,
            durable_revision: factory.durable_revision,
            durable_commitment: factory.durable_commitment,
            replacement_head: advancement.durable_cas().replacement_head(),
            admission_commitment: advancement.admission_commitment(),
        }
    }
}

fn validate_committed_advancement(
    expected: &CompletionCommitBinding,
    advancement: &ProtectedBrokerOutcomeCommittedAdvancementV1,
) -> Result<(), FileCallbackError> {
    let next_sequence = expected
        .broker_sequence
        .checked_add(1)
        .ok_or_else(integrity_error)?;
    if advancement.method() != expected.method
        || advancement.request_id() != expected.request_id
        || advancement.signed_request_digest() != expected.signed_request_digest
        || advancement.client_sequence() != expected.client_sequence
        || advancement.broker_sequence() != expected.broker_sequence
        || advancement.session_binding() != expected.session_binding
        || advancement.peer_binding().digest() != expected.peer_binding
        || advancement.expected_generation() != expected.protected_generation
        || advancement.expected_head() != expected.protected_head
        || advancement.expected_revision() != expected.durable_revision
        || advancement.expected_commitment() != expected.durable_commitment
        || advancement.replacement_head() != expected.replacement_head
        || advancement.admission_commitment() != expected.admission_commitment
        || advancement.next_traffic().has_outstanding_request()
        || advancement.next_traffic().next_client_sequence() != next_sequence
        || advancement.next_traffic().next_broker_sequence() != next_sequence
    {
        return Err(integrity_error());
    }
    Ok(())
}

const fn method_for_kind(kind: CompletionKind) -> BrokerMethod {
    match kind {
        CompletionKind::Open => BrokerMethod::BROKER_METHOD_MOUNT_ACQUIRE_SOURCE,
        CompletionKind::Close => BrokerMethod::BROKER_METHOD_MOUNT_RELEASE_SOURCE_ACQUISITION,
    }
}

fn outcome_packet_commitment(packet: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(b"aos-filesystem-backing-outcome-packet-v1\0");
    hasher.update((packet.len() as u64).to_be_bytes());
    hasher.update(packet);
    hasher.finalize().into()
}

struct VerifiedBackingOpenCompletion {
    authority_binding: [u8; 32],
    worker_brand: u64,
    reducer_identity: [u8; 32],
    callback_request_identity: [u8; 32],
    raw_handle: u64,
    broker_execution: [u8; 32],
    broker_generation: u64,
    broker_sequence: u64,
    publication_generation: u64,
    currentness_commitment: [u8; 32],
    operation: RegistrationOperation,
    backing: BackingIdentity,
    backing_id: u64,
    descriptor_commitment: [u8; 32],
}

impl VerifiedBackingOpenCompletion {
    fn from_authenticated(
        factory: &DormantBackingReceiptFactory,
        operation: RegistrationOperation,
        backing: BackingIdentity,
        backing_id: u64,
        descriptor_commitment: [u8; 32],
    ) -> Self {
        Self {
            authority_binding: factory.authority_binding,
            worker_brand: factory.worker_brand,
            reducer_identity: factory.reducer_identity,
            callback_request_identity: factory.callback_request_identity,
            raw_handle: factory.raw_handle,
            broker_execution: factory.broker_execution,
            broker_generation: factory.broker_generation,
            broker_sequence: factory.broker_sequence,
            publication_generation: factory.publication_generation,
            currentness_commitment: factory.currentness_commitment,
            operation,
            backing,
            backing_id,
            descriptor_commitment,
        }
    }
}

impl super::sealed::Sealed for VerifiedBackingOpenCompletion {}

impl CompletedBackingOpen for VerifiedBackingOpenCompletion {
    fn authority_binding(&self) -> [u8; 32] {
        self.authority_binding
    }

    fn worker_brand(&self) -> u64 {
        self.worker_brand
    }

    fn reducer_identity(&self) -> [u8; 32] {
        self.reducer_identity
    }

    fn callback_request_identity(&self) -> [u8; 32] {
        self.callback_request_identity
    }

    fn raw_handle(&self) -> u64 {
        self.raw_handle
    }

    fn broker_execution(&self) -> [u8; 32] {
        self.broker_execution
    }

    fn broker_generation(&self) -> u64 {
        self.broker_generation
    }

    fn broker_sequence(&self) -> u64 {
        self.broker_sequence
    }

    fn publication_generation(&self) -> u64 {
        self.publication_generation
    }

    fn currentness_commitment(&self) -> [u8; 32] {
        self.currentness_commitment
    }

    fn operation(&self) -> RegistrationOperation {
        self.operation
    }

    fn backing(&self) -> BackingIdentity {
        self.backing
    }

    fn backing_id(&self) -> u64 {
        self.backing_id
    }

    fn descriptor_commitment(&self) -> [u8; 32] {
        self.descriptor_commitment
    }
}

struct VerifiedBackingCloseCompletion {
    authority_binding: [u8; 32],
    worker_brand: u64,
    reducer_identity: [u8; 32],
    callback_request_identity: [u8; 32],
    raw_handle: u64,
    broker_execution: [u8; 32],
    broker_generation: u64,
    broker_sequence: u64,
    publication_generation: u64,
    currentness_commitment: [u8; 32],
    operation: RegistrationOperation,
    backing: BackingIdentity,
    backing_id: u64,
    descriptor_commitment: [u8; 32],
}

impl VerifiedBackingCloseCompletion {
    fn from_authenticated(
        factory: &DormantBackingReceiptFactory,
        operation: RegistrationOperation,
        backing: BackingIdentity,
        backing_id: u64,
        descriptor_commitment: [u8; 32],
    ) -> Self {
        Self {
            authority_binding: factory.authority_binding,
            worker_brand: factory.worker_brand,
            reducer_identity: factory.reducer_identity,
            callback_request_identity: factory.callback_request_identity,
            raw_handle: factory.raw_handle,
            broker_execution: factory.broker_execution,
            broker_generation: factory.broker_generation,
            broker_sequence: factory.broker_sequence,
            publication_generation: factory.publication_generation,
            currentness_commitment: factory.currentness_commitment,
            operation,
            backing,
            backing_id,
            descriptor_commitment,
        }
    }
}

impl super::sealed::Sealed for VerifiedBackingCloseCompletion {}

impl CompletedBackingClose for VerifiedBackingCloseCompletion {
    fn authority_binding(&self) -> [u8; 32] {
        self.authority_binding
    }

    fn worker_brand(&self) -> u64 {
        self.worker_brand
    }

    fn reducer_identity(&self) -> [u8; 32] {
        self.reducer_identity
    }

    fn callback_request_identity(&self) -> [u8; 32] {
        self.callback_request_identity
    }

    fn raw_handle(&self) -> u64 {
        self.raw_handle
    }

    fn broker_execution(&self) -> [u8; 32] {
        self.broker_execution
    }

    fn broker_generation(&self) -> u64 {
        self.broker_generation
    }

    fn broker_sequence(&self) -> u64 {
        self.broker_sequence
    }

    fn publication_generation(&self) -> u64 {
        self.publication_generation
    }

    fn currentness_commitment(&self) -> [u8; 32] {
        self.currentness_commitment
    }

    fn operation(&self) -> RegistrationOperation {
        self.operation
    }

    fn backing(&self) -> BackingIdentity {
        self.backing
    }

    fn backing_id(&self) -> u64 {
        self.backing_id
    }

    fn descriptor_commitment(&self) -> [u8; 32] {
        self.descriptor_commitment
    }
}

struct CompletionCursor<'a> {
    bytes: &'a [u8],
    offset: usize,
}

impl<'a> CompletionCursor<'a> {
    const fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, offset: 0 }
    }

    fn array<const N: usize>(&mut self) -> Result<[u8; N], FileCallbackError> {
        let end = self.offset.checked_add(N).ok_or_else(integrity_error)?;
        let source = self
            .bytes
            .get(self.offset..end)
            .ok_or_else(integrity_error)?;
        let mut value = [0; N];
        value.copy_from_slice(source);
        self.offset = end;
        Ok(value)
    }

    fn nonzero_array<const N: usize>(&mut self) -> Result<[u8; N], FileCallbackError> {
        let value = self.array()?;
        if value.iter().all(|byte| *byte == 0) {
            return Err(integrity_error());
        }
        Ok(value)
    }

    fn u8(&mut self) -> Result<u8, FileCallbackError> {
        Ok(self.array::<1>()?[0])
    }

    fn u16(&mut self) -> Result<u16, FileCallbackError> {
        Ok(u16::from_be_bytes(self.array()?))
    }

    fn nonzero_u64(&mut self) -> Result<u64, FileCallbackError> {
        let value = u64::from_be_bytes(self.array()?);
        if value == 0 {
            return Err(integrity_error());
        }
        Ok(value)
    }

    fn finish(self) -> Result<(), FileCallbackError> {
        if self.offset == self.bytes.len() {
            Ok(())
        } else {
            Err(integrity_error())
        }
    }
}

fn integrity_error() -> FileCallbackError {
    FileCallbackError::Worker(WorkerError::IntegrityFailure)
}
