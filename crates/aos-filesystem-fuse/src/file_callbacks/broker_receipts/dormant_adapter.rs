//! Dormant bridge from protected broker outcomes to callback receipts.
//!
//! These functions are compiled for the future descriptor-owning transport but
//! are not installed in the active metadata operations table. They consume the
//! move-only protected outcome gate, verify a canonical signed completion, and
//! retain success behind the protected journal's post-CAS advancement token.

use aos_filesystem_view::{BackingDisposition, MetadataConnection};
use aos_sandbox_broker_session_protocol::{
    CanonicalBrokerResponseEnvelopeV1, ProtectedBrokerSessionVerificationContextV1,
};
use aos_sandbox_broker_session_security::{
    ProtectedBrokerOutcomeAdmissionGateV1, ProtectedBrokerOutcomeCommittedAdvancementV1,
};

use super::{
    BackingCloseReceipt, BackingOpenReceipt, BrokerCompletionAdmission, CommittedBrokerReceipt,
    DormantBrokerCompletionVerifier, PendingBackingCloseReceipt, PendingBackingOpenReceipt,
    ProtectedBrokerCompletionAuthority, SignedBackingCompletion,
};
use crate::file_callbacks::{FileCallbackError, PendingCallbackOpen, ReleasePlan};

/// Verifies one protected pending-OPEN completion without unlocking its receipt.
///
/// The returned pending receipt still requires the protected journal owner to
/// persist the supplied advancement and return its exact confirmed readback.
/// This function performs no broker effect, journal write, or callback reply.
///
/// # Errors
///
/// Returns [`FileCallbackError`] when the canonical completion, protected gate,
/// session context, pending callback, or exact backing binding disagrees.
pub(crate) fn verify_pending_open_completion(
    connection: &MetadataConnection<'_, '_, '_, '_>,
    pending: &PendingCallbackOpen<'_>,
    gate: ProtectedBrokerOutcomeAdmissionGateV1,
    context: &ProtectedBrokerSessionVerificationContextV1,
    canonical_completion: &[u8],
    outcome: &CanonicalBrokerResponseEnvelopeV1,
) -> Result<BrokerCompletionAdmission<PendingBackingOpenReceipt>, FileCallbackError> {
    let BackingDisposition::Passthrough(backing) = pending.data.disposition() else {
        return Err(FileCallbackError::Stale);
    };
    let signed = SignedBackingCompletion::from_canonical_bytes(canonical_completion)?;
    let authority =
        ProtectedBrokerCompletionAuthority::from_protected_gate(gate, context, backing)?;
    let verifier =
        DormantBrokerCompletionVerifier::for_pending_open(connection, authority, pending)?;

    verifier.verify_open(connection, signed, outcome)
}

/// Verifies one protected pending-CLOSE completion without unlocking its receipt.
///
/// The backing identity is derived from the reducer-produced release plan; no
/// caller-selected selector or backing can be substituted. This function
/// performs no broker effect, journal write, descriptor close, or callback reply.
///
/// # Errors
///
/// Returns [`FileCallbackError`] when the release plan does not require close,
/// or the canonical completion, protected gate, session context, and plan do
/// not bind the same exact effect.
pub(crate) fn verify_pending_close_completion(
    connection: &MetadataConnection<'_, '_, '_, '_>,
    plan: ReleasePlan,
    gate: ProtectedBrokerOutcomeAdmissionGateV1,
    context: &ProtectedBrokerSessionVerificationContextV1,
    canonical_completion: &[u8],
    outcome: &CanonicalBrokerResponseEnvelopeV1,
) -> Result<BrokerCompletionAdmission<PendingBackingCloseReceipt>, FileCallbackError> {
    let ReleasePlan::CloseBacking { backing, .. } = plan else {
        return Err(FileCallbackError::Stale);
    };
    let signed = SignedBackingCompletion::from_canonical_bytes(canonical_completion)?;
    let authority =
        ProtectedBrokerCompletionAuthority::from_protected_gate(gate, context, backing)?;
    let verifier = DormantBrokerCompletionVerifier::for_close_plan(connection, authority, plan)?;

    verifier.verify_close(connection, signed, outcome)
}

/// Unlocks one OPEN receipt after the protected journal CAS was confirmed.
///
/// # Errors
///
/// Returns [`FileCallbackError`] together with the committed advancement unless
/// it is the exact post-CAS readback paired with the pending completion.
pub(crate) fn finish_pending_open_completion(
    connection: &MetadataConnection<'_, '_, '_, '_>,
    pending: PendingBackingOpenReceipt,
    advancement: ProtectedBrokerOutcomeCommittedAdvancementV1,
) -> Result<
    CommittedBrokerReceipt<BackingOpenReceipt>,
    (
        FileCallbackError,
        ProtectedBrokerOutcomeCommittedAdvancementV1,
    ),
> {
    pending.mint_after_commit(connection, advancement)
}

/// Unlocks one CLOSE receipt after the protected journal CAS was confirmed.
///
/// # Errors
///
/// Returns [`FileCallbackError`] together with the committed advancement unless
/// it is the exact post-CAS readback paired with the pending completion.
pub(crate) fn finish_pending_close_completion(
    connection: &MetadataConnection<'_, '_, '_, '_>,
    pending: PendingBackingCloseReceipt,
    advancement: ProtectedBrokerOutcomeCommittedAdvancementV1,
) -> Result<
    CommittedBrokerReceipt<BackingCloseReceipt>,
    (
        FileCallbackError,
        ProtectedBrokerOutcomeCommittedAdvancementV1,
    ),
> {
    pending.mint_after_commit(connection, advancement)
}
