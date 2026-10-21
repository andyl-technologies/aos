//! Closed generation-one Create policy-admission continuation.
//!
//! The records below are historical comparison DATA. Only the same original
//! Controller, Source, Cache and Root owners can drive a live continuation;
//! decoding a record cannot supply that custody. The policy subgate never
//! makes the public Create or its generic Effect complete.
//!
//! ```text
//! AOSQ4I01 | version=1 | original cut and fixed identities | checksum
//! AOSQ4C01/AOSQ4R01 | version=1 | purpose phase | observed predecessor | checksum
//! AOSQ4S01/AOSQ4K01 | version=1 | held/released-pending | original cut | checksum
//! AOSQ4G01 | version=1 | Applying-only policy subgate | checksum
//! ```

use aos_sandbox_protocol::domain_ledger::JournalTransactionDataError;
use aos_sandbox_protocol::domain_ledger::ProtectedHistoryDataErrorV1;
pub(crate) use aos_sandbox_protocol::domain_ledger::create_q04_history::{
    CLAIM_CHUNK_BYTES, DECISION_BYTES, GATE_BYTES, IDENTITY_BYTES, MAXIMUM_CLAIM_BYTES,
    PENDING_BYTES, PHASE_BYTES, PREHOLD_RESPONSE_BYTES, Q04CutIdentityV1, Q04EffectSubgateV1,
    Q04HistoryDataErrorV1, Q04PendingOwnerV1, Q04PendingRecordV1, Q04PhaseOwnerV1,
    Q04PhaseRecordV1, Q04PreholdPublicationDataV1, Q04RootDecisionV1, Q04TransactionOwnerV1,
    chunk_count, claim_chunk_count,
};
#[cfg(test)]
const GATE_IDENTITY_DOMAIN: &[u8] = b"aos.sandbox.create-q04.effect-gate-identity.v1\0";

use aos_sandbox_model::bounded_codec::BoundedReader;
use aos_sandbox_model::{ObjectDigest, OperationId, ProjectId, SandboxId};
use ed25519_dalek::{Signature, Signer as _, SigningKey};
use sha2::{Digest as _, Sha256};

use crate::journal::JournalError;

mod authority_error;
mod owned_error;

pub(crate) use owned_error::{
    project_root_native_journal_error_v1, project_root_policy_error_v1,
};

fn project_q04_wire_error_v1(
    error: aos_sandbox_protocol::source_genesis_wire::Q04TransferWireErrorV1,
) -> CreateQ04ErrorV1 {
    use aos_sandbox_protocol::source_genesis_wire::Q04TransferWireErrorV1;

    match error {
        Q04TransferWireErrorV1::ChangedCut => CreateQ04ErrorV1::ChangedCut,
        Q04TransferWireErrorV1::Allocation(cause) => CreateQ04ErrorV1::Allocation(cause),
    }
}

mod client;
mod input_origin;
pub(super) mod root;

pub(crate) use client::{
    OriginalCreateQ04InvocationV1, OriginalQ04CompletedPreparationLoanV1,
    OriginalQ04FinalRootObservationV1, OriginalQ04ProjectPreparationLoanV1,
    OriginalQ04RootCacheLoanV1, Q04ControllerPreparationV1, RetainedCreatePolicySourcesDataV1,
};
pub(crate) use input_origin::{
    Q04OriginalInputDemandV1, Q04PreparedInputOriginV1, cache_replay_cell_bytes,
    original_input_demand,
};
pub(crate) use root::capacity_shape_digest as q04_capacity_shape_digest_v1;
pub(crate) use root::root_consumed_gate_record as root_consumed_gate_v1;


pub(crate) use aos_sandbox_policy::q04_data::{
    CLAIM_CHUNK_PREFIX_BYTES, CLAIM_FIELDS, CLAIM_INDEX_BYTES, CLAIM_PREFIX_BYTES,
    MAXIMUM_PREHOLD_BYTES, MAXIMUM_PREVIEW_BYTES, PREHOLD_FIELDS, PREHOLD_METADATA_BYTES,
    PREHOLD_PREFIX_BYTES, PREVIEW_FIELDS, PREVIEW_INDEX_BYTES, PREVIEW_PREFIX_BYTES,
};
pub(crate) const CONTROLLER_IDENTITY_KEY: &[u8] = b"\0aos-controller-q04-cut-v1\0";
pub(crate) const CONTROLLER_PHASE_PREFIX: &[u8] = b"\0aos-controller-q04-phase-v1\0";
pub(crate) use aos_sandbox_ledger_replay::source_policy_hold::SOURCE_PENDING_KEY;
pub(crate) const CACHE_PENDING_KEY: &[u8] = b"\0aos-cache-q04-pending-v1\0";

// Both original owners compare the same canonical DATA. The recipe contains
// no live loan, signature brand, future phase or caller-created authority.
/// Reports the original typed failure of a selected Q04 continuation.
///
/// This error is not a retry, clearance, receipt or public Create result.
/// Its caller retains the actual failed invocation and independent owners.
#[derive(Debug, thiserror::Error)]
pub enum CreateQ04ErrorV1 {
    /// The genuine native Cache owner retained the exact owning failure.
    #[error(transparent)]
    NativeCache(Box<aos_sandbox_cache::CacheQ04ErrorV1>),
    /// A protected native journal or exact phase transition failed.
    #[error(transparent)]
    Journal(#[from] JournalError),
    /// The same enrolled bank refused an original preparation or child CAS.
    #[error(transparent)]
    ResourceReservation(Box<crate::controller_resource_reservation::ResourceReservationErrorV1>),
    /// The sole native parser or a later original-name bookend failed.
    #[error("Q04 original native history failed: {first}")]
    NativeHistory {
        /// The unchanged first parser, exact-membership or custody failure.
        #[source]
        first: JournalError,
        /// A subsequent physical-name check, never a replacement first cause.
        final_bookend: Option<JournalError>,
    },
    /// The existing canonical compiler/publication engine rejected the cut.
    #[error(transparent)]
    PolicyCompiler(#[from] aos_sandbox_policy::native::PolicyCompilerJournalErrorV1),
    /// The Controller-side publication join retained its own native cause.
    #[error(transparent)]
    ControllerPolicyCompiler(#[from] super::PolicyCompilerJournalErrorV1),
    /// The native Policy owner retains its exact append, readback or post failure.
    #[error(transparent)]
    PolicyNativeJournal(aos_sandbox_policy::native::PolicyNativeJournalErrorV1),
    /// The original generation-one owner or signed readback failed.
    #[error(transparent)]
    SourceGenesis(#[from] crate::hierarchy::genesis_profile::SourceGenesisErrorV1),
    /// The exact applying Create ledger failed its existing validation.
    #[error(transparent)]
    Reconciler(#[from] crate::reconciler::ReconcilerError),
    /// The original bounded stream or fixed credential operation failed.
    #[error(transparent)]
    Io(#[from] std::io::Error),
    /// Strict native stream adoption or original-identity checking failed.
    #[error(transparent)]
    Kernel(#[from] aos_linux_descriptors::Error),
    /// A bounded continuation buffer could not reserve its actual storage.
    #[error(transparent)]
    Allocation(#[from] std::collections::TryReserveError),
    /// A signed Q04 acknowledgement failed the independently pinned role key.
    #[error(transparent)]
    AcknowledgementSignature(#[from] ed25519_dalek::SignatureError),
    /// The complete original Claim failed the independently pinned Controller key.
    #[error(transparent)]
    ClaimSignature(ed25519_dalek::SignatureError),
    /// The original-row DATA request failed the independent Controller pin.
    #[error(transparent)]
    PreholdSignature(ed25519_dalek::SignatureError),
    /// The independent signed deployment/project source failed its existing codec.
    #[error(transparent)]
    Deployment(#[from] super::PolicyDeploymentHeadErrorV1),
    /// The original current Controller/Publisher observation failed its existing codec.
    #[error(transparent)]
    ControllerCurrent(#[from] super::ControllerProjectAdmissionReadbackErrorV1),
    /// The fresh Controller hold observation failed its existing codec.
    #[error(transparent)]
    ControllerHeld(#[from] super::ControllerHoldReadbackErrorV1),
    /// The independently pinned Cache-purpose observation failed its old codec.
    #[error(transparent)]
    CachePacket(#[from] aos_sandbox_cache::CacheOwnerReadbackErrorV1),
    /// The actual fixed read-only Cache journal view failed its old engine.
    #[error(transparent)]
    CacheJournal(#[from] aos_sandbox_cache::CacheResidencyProtectedJournalErrorV1),
    /// The same retained physical Cache owner failed an original bookend.
    #[error(transparent)]
    CachePhysical(#[from] aos_sandbox_cache::CacheOwnerErrorV1),
    /// The original fixed Cache bootstrap source failed its existing engine.
    #[error(transparent)]
    CacheBootstrap(#[from] aos_sandbox_cache::CacheReplayControllerBootstrapErrorV1),
    /// The actual independently admitted normal-Root or original peer changed.
    #[error(transparent)]
    NormalRoot(#[from] crate::normal_root::NormalRootStartupErrorV1),
    /// Original stream adoption or strict kernel-subject observation failed.
    #[error(transparent)]
    Stream(#[from] aos_sandbox_linux::seqpacket::SeqpacketError),
    /// A strict receive retained its real partial subjects/descriptors and debt.
    #[error(transparent)]
    RetainedReceive(#[from] aos_sandbox_linux::seqpacket::RetainedSeqpacketReceiveErrorV1),
    /// The same parentless model/constructor sequence rejected the input.
    #[error(transparent)]
    Input(#[from] super::CurrentCreateCompilerInputErrorV1),
    /// The same real Controller/Publisher Create source failed its old engine.
    #[error(transparent)]
    ControllerSource(#[from] super::CurrentCreatePolicySourceErrorV1),
    /// The canonical original Desired/public projection failed its sole decoder.
    #[error(transparent)]
    Projection(#[from] aos_sandbox_protocol::public_api::projection::PublicProjectionError),
    /// The sole deterministic compiler rejected the retained original input.
    #[error(transparent)]
    Compilation(#[from] aos_sandbox_policy::PolicyCompilationError),
    /// The existing full original-input archive failed its sole codec.
    #[error(transparent)]
    InputOrigin(#[from] crate::publisher_admin::policy::PublisherPolicyError),
    /// A purpose, identity, phase or original owner join changed.
    #[error("the original Q04 continuation cut changed")]
    ChangedCut,
    /// The unchanged original flight cutoff was reached.
    #[error("the original Q04 flight deadline expired")]
    Expired,
    /// The same retained original transport was already mutably borrowed.
    #[error(transparent)]
    OriginBorrowMut(std::cell::BorrowMutError),
    /// A bounded original input or canonical suffix exceeded its limit.
    #[error("the original Q04 input or suffix exceeds its bound")]
    Bounds,
    /// A selected owner scope unwound before its final clearance.
    #[error("the original Q04 continuation unwound")]
    Unwind,
}

impl From<aos_sandbox_policy::controller_project_readback::ControllerProjectAdmissionDataErrorV1>
    for CreateQ04ErrorV1
{
    fn from(
        error: aos_sandbox_policy::controller_project_readback::ControllerProjectAdmissionDataErrorV1,
    ) -> Self {
        Self::ControllerCurrent(error.into())
    }
}

// Preserve the existing upper flattened packet-error lane after the pure codec move.
impl From<aos_sandbox_protocol::cache_owner_readback::CacheOwnerReadbackDataErrorV1>
    for CreateQ04ErrorV1
{
    fn from(cause: aos_sandbox_protocol::cache_owner_readback::CacheOwnerReadbackDataErrorV1) -> Self {
        Self::CachePacket(aos_sandbox_cache::CacheOwnerReadbackErrorV1::from(cause))
    }
}

impl From<JournalTransactionDataError> for CreateQ04ErrorV1 {
    fn from(error: JournalTransactionDataError) -> Self {
        <Self as From<JournalError>>::from(JournalError::from(error))
    }
}

impl From<aos_sandbox_protocol::policy_data::binding_v2::BindingDataErrorV1>
    for CreateQ04ErrorV1
{
    fn from(error: aos_sandbox_protocol::policy_data::binding_v2::BindingDataErrorV1) -> Self {
        Self::PolicyCompiler(aos_sandbox_policy::native::PolicyCompilerJournalErrorV1::from(error))
    }
}

impl From<aos_sandbox_ledger_replay::data::SourceSuccessorDataErrorV2> for CreateQ04ErrorV1 {
    fn from(error: aos_sandbox_ledger_replay::data::SourceSuccessorDataErrorV2) -> Self {
        Self::SourceGenesis(crate::hierarchy::genesis_profile::SourceGenesisErrorV1::from(error))
    }
}

impl From<ProtectedHistoryDataErrorV1> for CreateQ04ErrorV1 {
    fn from(error: ProtectedHistoryDataErrorV1) -> Self {
        Self::Journal(JournalError::from(error))
    }
}

impl From<Q04HistoryDataErrorV1> for CreateQ04ErrorV1 {
    fn from(error: Q04HistoryDataErrorV1) -> Self {
        match error {
            Q04HistoryDataErrorV1::Malformed => Self::Journal(JournalError::ProtectedBoundary),
            Q04HistoryDataErrorV1::ChangedCut => Self::ChangedCut,
            Q04HistoryDataErrorV1::Bounds => Self::Bounds,
        }
    }
}

impl From<aos_sandbox_policy::q04_data::PolicyQ04DataErrorV1> for CreateQ04ErrorV1 {
    fn from(error: aos_sandbox_policy::q04_data::PolicyQ04DataErrorV1) -> Self {
        use aos_sandbox_policy::q04_data::PolicyQ04DataErrorV1 as Data;
        match error {
            Data::UnauthenticatedCandidate => {
                Self::PolicyCompiler(aos_sandbox_policy::native::PolicyCompilerJournalErrorV1::UnauthenticatedCandidate)
            }
            Data::ChangedCut => Self::ChangedCut,
            Data::Bounds => Self::Bounds,
            Data::ProtectedBoundary => Self::Journal(JournalError::ProtectedBoundary),
            Data::Allocation(error) => Self::Allocation(error),
            Data::AcknowledgementSignature(error) => Self::AcknowledgementSignature(error),
            Data::ClaimSignature(error) => Self::ClaimSignature(error),
            Data::PreholdSignature(error) => Self::PreholdSignature(error),
            Data::History(error) => Self::from(error),
            Data::ProtectedHistory(error) => Self::from(error),
            Data::Transaction(error) => Self::from(error),
        }
    }
}

// A signing failure remains the first typed cause. A later whole-owner
// readback failure is separate debt; it never overwrites that cause or drops
// an already returned packet. This helper owns no resources or authority.
pub(crate) fn finish_controller_q04_signing_v1(
    result: Result<(), CreateQ04ErrorV1>,
    first_cause: &mut Option<CreateQ04ErrorV1>,
    postcheck_debt: &mut Option<CreateQ04ErrorV1>,
) -> Result<(), ()> {
    if let Err(error) = result {
        if first_cause.is_none() {
            *first_cause = Some(error);
        } else if postcheck_debt.is_none() {
            *postcheck_debt = Some(error);
        }
    }
    if first_cause.is_some() || postcheck_debt.is_some() {
        Err(())
    } else {
        Ok(())
    }
}

// Comparison DATA only. Each input is the exact canonical retained encoding;
// authority/currentness comes from the original loans, never this digest.
// Cclear = SHA256(domain || six (BEu32 length || complete value) pairs).
pub(crate) fn lower_clearance_recipe_digest_v1(
    identity: &Q04CutIdentityV1,
    root_settlement: &Q04PhaseRecordV1,
    cache_clear: ObjectDigest,
    source_clear: ObjectDigest,
    controller_settlement: &Q04PhaseRecordV1,
    status_three_effect: &[u8],
) -> Result<ObjectDigest, CreateQ04ErrorV1> {
    if root_settlement.owner() != Q04PhaseOwnerV1::Root
        || root_settlement.phase() != 6
        || controller_settlement.owner() != Q04PhaseOwnerV1::Controller
        || controller_settlement.phase() != 6
        || cache_clear.as_bytes() == &[0; 32]
        || source_clear.as_bytes() == &[0; 32]
        || status_three_effect.is_empty()
    {
        return Err(CreateQ04ErrorV1::ChangedCut);
    }
    let mut digest = Sha256::new();
    digest.update(b"aos.sandbox.create-q04.lower-clearance-recipe.v1\0");
    for value in [
        identity.bytes().as_slice(),
        root_settlement.bytes().as_slice(),
        cache_clear.as_bytes().as_slice(),
        source_clear.as_bytes().as_slice(),
        controller_settlement.bytes().as_slice(),
        status_three_effect,
    ] {
        let length = u32::try_from(value.len()).map_err(|_| CreateQ04ErrorV1::Bounds)?;
        digest.update(length.to_be_bytes());
        digest.update(value);
    }
    Ok(ObjectDigest::from_bytes(digest.finalize().into()))
}

// A borrowed, unbranded event recipe shared by the actual Controller and
// Root's independent reconstruction. Callers supply real observations for a
// live phase; using shaped future DATA during preflight grants no commit.
pub(crate) struct Q04ControllerPhaseEventsV1 {
    pub(crate) decision: ObjectDigest,
    pub(crate) consumed_gate: ObjectDigest,
    pub(crate) release: ObjectDigest,
    pub(crate) settlement: ObjectDigest,
    pub(crate) clearance: ObjectDigest,
    pub(crate) final_root: ObjectDigest,
    pub(crate) pairs: [ObjectDigest; 6],
    pub(crate) policy_ack: ObjectDigest,
    pub(crate) release_ack: ObjectDigest,
    pub(crate) settlement_ack: ObjectDigest,
    pub(crate) clearance_ack: ObjectDigest,
}

// A complete eligible suffix must fit before C1, although future Root events
// and signatures cannot yet exist. These fixed-width canonical representatives
// use the same codecs and are never eligible for a live Controller append.
pub(crate) fn q04_controller_capacity_events_v1(
    identity: &Q04CutIdentityV1,
    pairs: [ObjectDigest; 6],
    state_next: u64,
    authority_next: u64,
) -> Result<(Q04RootDecisionV1, Q04ControllerPhaseEventsV1), CreateQ04ErrorV1> {
    let earlier = Q04TransactionOwnerV1::Root.transaction_id(
        identity,
        2,
        q04_capacity_shape_digest_v1(identity, 13)?,
    )?;
    let decision = root::root_decision_record(
        identity,
        earlier,
        state_next.checked_add(5).ok_or(CreateQ04ErrorV1::Bounds)?,
        authority_next,
        pairs[2],
        pairs[4],
    )?;
    let gate = root::root_consumed_gate_record(identity, &decision)?;
    let events = Q04ControllerPhaseEventsV1 {
        decision: decision.digest(),
        consumed_gate: gate.digest(),
        release: q04_capacity_shape_digest_v1(identity, 7)?,
        settlement: q04_capacity_shape_digest_v1(identity, 8)?,
        clearance: q04_capacity_shape_digest_v1(identity, 9)?,
        final_root: q04_capacity_shape_digest_v1(identity, 10)?,
        pairs,
        policy_ack: q04_capacity_shape_digest_v1(identity, 14)?,
        release_ack: q04_capacity_shape_digest_v1(identity, 15)?,
        settlement_ack: q04_capacity_shape_digest_v1(identity, 16)?,
        clearance_ack: q04_capacity_shape_digest_v1(identity, 17)?,
    };
    Ok((decision, events))
}

pub(crate) fn controller_phase_recipe_v1(
    identity: &Q04CutIdentityV1,
    phase: u8,
    prior: Option<&Q04PhaseRecordV1>,
    events: &Q04ControllerPhaseEventsV1,
) -> Result<Q04PhaseRecordV1, CreateQ04ErrorV1> {
    if phase == 0
        || phase > 8
        || (phase == 1) != prior.is_none()
        || prior.is_some_and(|prior| {
            prior.owner() != Q04PhaseOwnerV1::Controller
                || prior.phase().checked_add(1) != Some(phase)
        })
    {
        return Err(CreateQ04ErrorV1::ChangedCut);
    }
    let predecessor = prior.map(Q04PhaseRecordV1::digest);
    let transaction = Q04TransactionOwnerV1::Controller.transaction_id(
        identity,
        phase,
        predecessor.unwrap_or(identity.before_controller_rows()),
    )?;
    let mut body = [0; PHASE_BYTES];
    body[16..48].copy_from_slice(identity.digest().as_bytes());
    body[48..64].copy_from_slice(&identity.stage_id());
    if let Some(predecessor) = predecessor {
        body[64..96].copy_from_slice(predecessor.as_bytes());
    }
    let introduced = [2, 2, 5, 6, 7, 8];
    for (index, event) in [
        events.decision,
        events.consumed_gate,
        events.release,
        events.settlement,
        events.clearance,
        events.final_root,
    ]
    .into_iter()
    .enumerate()
    {
        if phase >= introduced[index] {
            body[96 + index * 32..128 + index * 32].copy_from_slice(event.as_bytes());
        }
    }
    for (index, pair) in events.pairs.iter().enumerate() {
        if (index == 0 || phase >= 2) && (index % 2 == 0 || phase >= 5) {
            body[288 + index * 32..320 + index * 32].copy_from_slice(pair.as_bytes());
        }
    }
    let acknowledgement = match phase {
        3 | 4 => Some(events.policy_ack),
        5 => Some(events.release_ack),
        6 | 7 => Some(events.settlement_ack),
        8 => Some(events.clearance_ack),
        _ => None,
    };
    if let Some(acknowledgement) = acknowledgement {
        body[480..512].copy_from_slice(acknowledgement.as_bytes());
    }
    body[512..544].copy_from_slice(identity.before_controller_rows().as_bytes());
    body[544..560].copy_from_slice(&transaction);
    let record = Q04PhaseRecordV1::from_body(Q04PhaseOwnerV1::Controller, phase, body, identity)?;
    if let Some(prior) = prior {
        record.require_successor(prior)?;
    }
    Ok(record)
}

pub(crate) use aos_sandbox_policy::q04_data::{
    Q04AcknowledgementKindV1, Q04AcknowledgementV1, Q04ClaimChunkV1, Q04ClaimStorageRecipeV1,
    Q04ClaimV1, Q04PreholdChunkV1, Q04PreholdInputDataV1, Q04PreholdTransferRecipeV1,
    Q04PreviewChunkV1, Q04PreviewTransferRecipeV1, Q04PreviewV1,
    acknowledgement_signature_preimage, claim_body_fields, decode_length_prefixed_fields,
    encode_length_prefixed_fields, encode_q04_acknowledgement_data_v1, encode_q04_claim_body_v1,
    encode_q04_prehold_body_v1, encode_q04_preview_body_v1, finish_q04_acknowledgement_body_v1,
    fixed, nonzero, prehold_body_fields, prehold_index_shape, prepare_q04_acknowledgement_v1,
    prepare_q04_claim_v1, prepare_q04_prehold_body_v1, preview_index_shape,
    q04_original_precut_digest_v1, q04_publication_precut_seed_v1, read_integer_bytes, read_u32,
    read_u64, require_acknowledgement_body, require_claim_field_bounds,
    require_genesis_observation_pair_widths, require_prehold_fields, require_presence,
    signed_record_preimage,
};

#[cfg(test)]
pub(crate) fn sign_q04_acknowledgement_v1(
    kind: Q04AcknowledgementKindV1,
    body: &mut Vec<u8>,
    key: &SigningKey,
    identity: &Q04CutIdentityV1,
) -> Result<(), CreateQ04ErrorV1> {
    let preimage = prepare_q04_acknowledgement_v1(kind, body, identity)?;
    append_q04_signature(body, key, &preimage);
    Ok(())
}

pub(crate) fn sign_original_q04_acknowledgement_v1(
    kind: Q04AcknowledgementKindV1,
    body: &mut Vec<u8>,
    key: &SigningKey,
    identity: &Q04CutIdentityV1,
    original: &OriginalQ04RootCacheLoanV1<'_, '_, '_>,
) -> Result<(), CreateQ04ErrorV1> {
    let preimage = prepare_q04_acknowledgement_v1(kind, body, identity)?;

    original.require_signing_boundary()?;
    append_q04_signature(body, key, &preimage);
    Ok(())
}

fn append_q04_signature(body: &mut Vec<u8>, key: &SigningKey, preimage: &[u8]) {
    let signature = key.sign(preimage);
    body.extend_from_slice(&signature.to_bytes());
}

#[cfg(test)]
pub(crate) fn sign_q04_claim_v1(
    body: &mut Vec<u8>,
    key: &SigningKey,
    identity: &Q04CutIdentityV1,
) -> Result<(), CreateQ04ErrorV1> {
    let preimage = prepare_q04_claim_v1(body, identity)?;
    append_q04_signature(body, key, &preimage);
    Ok(())
}

pub(super) fn sign_original_q04_claim_v1(
    body: &mut Vec<u8>,
    key: &SigningKey,
    identity: &Q04CutIdentityV1,
    original: &super::source_genesis_root::OriginalRootGenesisFlightV1<'_>,
) -> Result<(), CreateQ04ErrorV1> {
    let preimage = prepare_q04_claim_v1(body, identity)?;

    original.require_q04_signing_boundary()?;
    append_q04_signature(body, key, &preimage);
    Ok(())
}

#[cfg(test)]
pub(super) fn sign_q04_prehold_body_v1(
    output: &mut Vec<u8>,
    key: &SigningKey,
) -> Result<(), CreateQ04ErrorV1> {
    let preimage = prepare_q04_prehold_body_v1(output)?;
    append_q04_signature(output, key, &preimage);
    Ok(())
}

pub(super) fn sign_original_q04_prehold_body_v1(
    output: &mut Vec<u8>,
    key: &SigningKey,
    original: &super::source_genesis_root::OriginalRootGenesisFlightV1<'_>,
) -> Result<(), CreateQ04ErrorV1> {
    let preimage = prepare_q04_prehold_body_v1(output)?;

    original.require_q04_signing_boundary()?;
    append_q04_signature(output, key, &preimage);
    Ok(())
}
#[cfg(test)]
mod tests {
    use super::*;
    use aos_sandbox_policy::controller_project_readback::CONTROLLER_PROJECT_ADMISSION_READBACK_BYTES_V1;

    // These format fixtures independently reseal malformed canonical packets.
    const CLAIM_INDEX_DOMAIN: &[u8] = b"aos.sandbox.create-q04.claim-index.v1\0";
    const CLAIM_CHUNK_DOMAIN: &[u8] = b"aos.sandbox.create-q04.claim-chunk.v1\0";
    const CLAIM_SIGNATURE_DOMAIN: &[u8] = b"aos.sandbox.create-q04.claim.signature.v1\0";

    #[test]
    fn signing_keeps_original_io_cause_and_separate_first_postcheck_debt() {
        let original = std::io::Error::from_raw_os_error(13);
        let mut first = Some(CreateQ04ErrorV1::Io(original));
        let mut debt = None;

        assert!(finish_controller_q04_signing_v1(
            Err(CreateQ04ErrorV1::Expired), &mut first, &mut debt,
        ).is_err());
        assert!(
            finish_controller_q04_signing_v1(
                Err(CreateQ04ErrorV1::ChangedCut),
                &mut first,
                &mut debt,
            )
            .is_err()
        );
        assert!(finish_controller_q04_signing_v1(Ok(()), &mut first, &mut debt).is_err());

        assert!(matches!(first, Some(CreateQ04ErrorV1::Io(ref error))
            if error.raw_os_error() == Some(13)));
        assert!(matches!(debt, Some(CreateQ04ErrorV1::Expired)));
    }

    #[test]
    fn signing_postcheck_failure_latches_without_an_earlier_signing_error() {
        let mut first = None;
        let mut debt = None;

        assert!(finish_controller_q04_signing_v1(Ok(()), &mut first, &mut debt).is_ok());
        assert!(
            finish_controller_q04_signing_v1(
                Err(CreateQ04ErrorV1::ChangedCut),
                &mut first,
                &mut debt,
            )
            .is_err()
        );

        assert!(matches!(first, Some(CreateQ04ErrorV1::ChangedCut)));
        assert!(debt.is_none());
    }

    #[test]
    fn signing_never_reopens_a_debt_only_negative_slot() {
        let mut first = None;
        let mut debt = Some(CreateQ04ErrorV1::Expired);

        assert!(finish_controller_q04_signing_v1(Ok(()), &mut first, &mut debt).is_err());

        assert!(first.is_none());
        assert!(matches!(debt, Some(CreateQ04ErrorV1::Expired)));
    }

    // These are inert canonical DATA fixtures, not genuine owners, signatures,
    // committed native history, current floors or live Create authority.
    fn identity() -> Q04CutIdentityV1 {
        let mut body = [0; IDENTITY_BYTES];
        body[16..80].fill(1);
        body[80..84].copy_from_slice(&1000_u32.to_be_bytes());
        body[84..88].copy_from_slice(&1001_u32.to_be_bytes());
        body[88..96].copy_from_slice(&1_u64.to_be_bytes());
        body[96..104].copy_from_slice(&1_u64.to_be_bytes());
        body[112..128].fill(2);
        for (offset, value) in [
            (128, 100_u64),
            (136, 60_000_000_100),
            (144, 200),
            (152, 65_000_000_200),
            (160, 1),
        ] {
            body[offset..offset + 8].copy_from_slice(&value.to_be_bytes());
        }
        body[168..184].fill(3);
        body[184..200].fill(4);
        for (index, offset) in (200..648).step_by(32).enumerate() {
            body[offset..offset + 32].fill(5 + index as u8);
        }
        Q04CutIdentityV1::from_body(body).unwrap()
    }

    fn decision(identity: &Q04CutIdentityV1) -> Q04RootDecisionV1 {
        let mut body = [0; DECISION_BYTES];
        body[16..48].copy_from_slice(identity.digest().as_bytes());
        body[48..64].fill(9);
        body[64..80].copy_from_slice(&identity.publication_id());
        body[80..112].copy_from_slice(identity.policy_transaction().as_bytes());
        body[112..120].copy_from_slice(&7_u64.to_be_bytes());
        body[120..152].copy_from_slice(identity.policy_current().as_bytes());
        body[152..184].copy_from_slice(identity.binding().as_bytes());
        body[184..216].copy_from_slice(identity.gate_identity().as_bytes());
        body[216..280].fill(10);
        body[280..312].copy_from_slice(identity.cache_quota().as_bytes());
        body[312..320].copy_from_slice(&5_u64.to_be_bytes());
        body[320..352].copy_from_slice(identity.before_controller_rows().as_bytes());
        Q04RootDecisionV1::from_body(body, identity).unwrap()
    }

    fn gate(identity: &Q04CutIdentityV1, decision: &Q04RootDecisionV1) -> Q04EffectSubgateV1 {
        let mut body = [0; GATE_BYTES];
        body[16..48].copy_from_slice(identity.digest().as_bytes());
        body[48..80].copy_from_slice(identity.binding().as_bytes());
        body[80..96].copy_from_slice(&identity.publication_id());
        body[96..128].copy_from_slice(identity.policy_current().as_bytes());
        body[128..160].copy_from_slice(decision.digest().as_bytes());
        body[160..176].copy_from_slice(&identity.stage_id());
        body[176..184].copy_from_slice(&identity.accepted_generation().to_be_bytes());
        body[184] = 1;
        body[224..256].copy_from_slice(identity.gen1_floor().as_bytes());
        Q04EffectSubgateV1::from_body(body).unwrap()
    }

    fn acknowledgement_body(
        kind: Q04AcknowledgementKindV1,
        identity: &Q04CutIdentityV1,
    ) -> Vec<u8> {
        let mut body = vec![0; kind.body_bytes()];
        body[16..24].copy_from_slice(&identity.bytes()[88..96]);
        body[24..40].copy_from_slice(&identity.nonce());
        body[40..72].copy_from_slice(identity.digest().as_bytes());
        body[72..76].copy_from_slice(&identity.bytes()[80..84]);
        body[76..84].copy_from_slice(&11_u64.to_be_bytes());
        body[84..100].copy_from_slice(identity.operation().as_bytes());
        body[100..116].copy_from_slice(identity.sandbox().as_bytes());
        body[116..124].copy_from_slice(&identity.accepted_generation().to_be_bytes());
        body[128..160].copy_from_slice(&identity.bytes()[232..264]);
        body[160..192].copy_from_slice(&identity.bytes()[264..296]);
        body[192..224].copy_from_slice(identity.binding().as_bytes());
        body[224..232].copy_from_slice(&identity.epoch().to_be_bytes());
        body[232..248].copy_from_slice(&identity.publication_id());
        body[248..280].copy_from_slice(identity.policy_current().as_bytes());
        body[280..312].copy_from_slice(gate(identity, &decision(identity)).digest().as_bytes());
        body[312..344].copy_from_slice(identity.gen1_floor().as_bytes());
        for (index, offset) in (344..kind.body_bytes()).step_by(32).enumerate() {
            body[offset..offset + 32].fill(40 + index as u8);
        }
        body
    }

    #[test]
    fn shared_ack_recipe_preserves_each_canonical_body() {
        let identity = identity();
        let consumed = gate(&identity, &decision(&identity)).digest();
        let pairs = std::array::from_fn(|index| ObjectDigest::from_bytes([40 + index as u8; 32]));
        let clear = std::array::from_fn(|index| ObjectDigest::from_bytes([46 + index as u8; 32]));

        for kind in [
            Q04AcknowledgementKindV1::Policy,
            Q04AcknowledgementKindV1::Release,
            Q04AcknowledgementKindV1::Settlement,
            Q04AcknowledgementKindV1::Clearance,
        ] {
            let mut expected = acknowledgement_body(kind, &identity);
            finish_q04_acknowledgement_body_v1(kind, &mut expected, &identity).unwrap();
            let mut actual = Vec::new();
            encode_q04_acknowledgement_data_v1(
                &mut actual,
                kind,
                &identity,
                11,
                consumed,
                pairs,
                (kind == Q04AcknowledgementKindV1::Clearance).then_some(clear),
            )
            .unwrap();

            assert_eq!(actual, expected);
            assert_eq!(actual.len(), kind.body_bytes());
        }
    }

    #[test]
    fn static_identity_hashes_one_nul_and_complete_canonical_cut() {
        let identity = identity();
        assert_eq!(GATE_IDENTITY_DOMAIN.len(), 47);
        assert_eq!(GATE_IDENTITY_DOMAIN.last(), Some(&0));
        assert_eq!(GATE_IDENTITY_DOMAIN.len() + identity.bytes().len(), 727);
        let expected = Sha256::new()
            .chain_update(GATE_IDENTITY_DOMAIN)
            .chain_update(identity.bytes())
            .finalize();

        assert_eq!(identity.gate_identity().as_bytes(), expected.as_slice());
        assert_ne!(identity.gate_identity(), identity.digest());
    }

    #[test]
    fn consumed_gate_hashes_full_record_not_its_internal_checksum() {
        let identity = identity();
        let decision = decision(&identity);
        let gate = gate(&identity, &decision);
        gate.require_identity(&identity, &decision).unwrap();

        assert_eq!(
            gate.digest().as_bytes(),
            Sha256::digest(gate.bytes()).as_slice()
        );
        assert_ne!(gate.digest().as_bytes().as_slice(), &gate.bytes()[256..288]);
        assert_ne!(gate.digest(), identity.gate_identity());
        assert_eq!(gate.acknowledgement().as_bytes(), &[0; 32]);
    }

    #[test]
    fn consumed_ack_is_zero_and_later_gate_acks_may_evolve() {
        let identity = identity();
        let decision = decision(&identity);
        let consumed = gate(&identity, &decision);
        let historical_consumed = consumed.digest();
        let mut invalid = *consumed.bytes();
        invalid[192..224].fill(1);
        assert!(Q04EffectSubgateV1::from_body(invalid).is_err());

        let mut prior = consumed;
        for status in 2..=4 {
            let mut body = *prior.bytes();
            body[184] = status;
            body[192..224].fill(20 + status);
            let next = Q04EffectSubgateV1::from_body(body).unwrap();
            next.require_successor(&prior).unwrap();
            next.require_identity(&identity, &decision).unwrap();
            assert_ne!(next.digest(), historical_consumed);
            prior = next;
        }
        assert_eq!(prior.status(), 4);
    }

    #[test]
    fn decision_rejects_a_gate_digest_substituted_for_static_identity() {
        let identity = identity();
        let decision = decision(&identity);
        let gate = gate(&identity, &decision);
        let mut body = *decision.bytes();
        body[184..216].copy_from_slice(gate.digest().as_bytes());

        assert!(Q04RootDecisionV1::from_body(body, &identity).is_err());
    }

    #[test]
    fn later_phase_ids_are_separate_from_initial_publication_and_owners() {
        let identity = identity();
        let predecessor = ObjectDigest::from_bytes([30; 32]);
        let controller = Q04TransactionOwnerV1::Controller
            .transaction_id(&identity, 2, predecessor)
            .unwrap();
        let root = Q04TransactionOwnerV1::Root
            .transaction_id(&identity, 2, predecessor)
            .unwrap();

        assert_ne!(controller, root);
        assert_ne!(root, identity.publication_id());
        assert!(
            Q04TransactionOwnerV1::Root
                .transaction_id(&identity, 8, predecessor)
                .is_err()
        );
        assert!(
            Q04TransactionOwnerV1::Controller
                .transaction_id(&identity, 0, predecessor)
                .is_err()
        );
        assert!(
            Q04TransactionOwnerV1::Cache
                .transaction_id(&identity, 1, ObjectDigest::from_bytes([0; 32]))
                .is_err()
        );
    }

    #[test]
    fn full_identity_width_checksum_and_original_deadline_are_required() {
        let identity = identity();
        assert!(Q04CutIdentityV1::decode(&identity.bytes()[..IDENTITY_BYTES - 1]).is_err());
        let mut changed = *identity.bytes();
        changed[647] ^= 1;
        assert!(Q04CutIdentityV1::decode(&changed).is_err());
        changed = *identity.bytes();
        changed[136..144].copy_from_slice(&60_000_000_101_u64.to_be_bytes());

        assert!(Q04CutIdentityV1::from_body(changed).is_err());
    }

    #[test]
    fn acknowledgement_binds_complete_cut_and_rejects_resigned_wrong_phase() {
        // Test-only key and public pin prove canonical/signature DATA behavior,
        // not installed credentials, actual owner custody or currentness.
        let identity = identity();
        let key = SigningKey::from_bytes(&[7; 32]);
        let credential =
            aos_sandbox_policy::controller_readback::encode_controller_hold_signer_credential_v1(
                1,
                &key.verifying_key(),
            )
            .map_err(crate::policy_compiler::ControllerHoldReadbackErrorV1::from)
            .unwrap();
        let pin = aos_sandbox_policy::controller_readback::PinnedControllerHoldSignerV1::decode(
            &credential,
        )
        .map_err(crate::policy_compiler::ControllerHoldReadbackErrorV1::from)
        .unwrap();
        let kind = Q04AcknowledgementKindV1::Policy;
        let mut packet = acknowledgement_body(kind, &identity);

        sign_q04_acknowledgement_v1(kind, &mut packet, &key, &identity).unwrap();
        let acknowledgement = Q04AcknowledgementV1::verify(kind, &packet, &pin, &identity).unwrap();
        assert_eq!(acknowledgement.bytes().len(), 408);
        assert_eq!(
            &acknowledgement.bytes()[40..72],
            identity.digest().as_bytes()
        );
        assert_ne!(
            &acknowledgement.bytes()[40..72],
            &identity.bytes()[392..424]
        );
        assert_eq!(acknowledgement.controller_sequence(), 11);

        let mut substituted = acknowledgement_body(kind, &identity);
        substituted[40..72].copy_from_slice(&identity.bytes()[392..424]);
        assert!(sign_q04_acknowledgement_v1(kind, &mut substituted, &key, &identity).is_err());

        packet[10] = 2;
        let signature = key
            .sign(&acknowledgement_signature_preimage(kind, &packet[..kind.body_bytes()]).unwrap());
        packet[kind.body_bytes()..].copy_from_slice(&signature.to_bytes());
        assert!(matches!(
            Q04AcknowledgementV1::verify(kind, &packet, &pin, &identity),
            Err(aos_sandbox_policy::q04_data::PolicyQ04DataErrorV1::ChangedCut),
        ));
    }

    #[test]
    fn acknowledgement_kinds_preserve_widths_and_distinct_signature_domains() {
        let identity = identity();
        let key = SigningKey::from_bytes(&[7; 32]);
        let credential =
            aos_sandbox_policy::controller_readback::encode_controller_hold_signer_credential_v1(
                1,
                &key.verifying_key(),
            )
            .map_err(crate::policy_compiler::ControllerHoldReadbackErrorV1::from)
            .unwrap();
        let pin = aos_sandbox_policy::controller_readback::PinnedControllerHoldSignerV1::decode(
            &credential,
        )
        .map_err(crate::policy_compiler::ControllerHoldReadbackErrorV1::from)
        .unwrap();

        for (kind, expected_length) in [
            (Q04AcknowledgementKindV1::Policy, 408),
            (Q04AcknowledgementKindV1::Release, 408),
            (Q04AcknowledgementKindV1::Settlement, 600),
            (Q04AcknowledgementKindV1::Clearance, 728),
        ] {
            let mut packet = acknowledgement_body(kind, &identity);
            sign_q04_acknowledgement_v1(kind, &mut packet, &key, &identity).unwrap();
            let acknowledgement =
                Q04AcknowledgementV1::verify(kind, &packet, &pin, &identity).unwrap();

            assert_eq!(acknowledgement.bytes().len(), expected_length);
            assert_eq!(acknowledgement.kind(), kind);
            assert_eq!(
                acknowledgement.digest().as_bytes(),
                Sha256::digest(&packet).as_slice()
            );
            assert!(
                Q04AcknowledgementV1::verify(kind, &packet[..packet.len() - 1], &pin, &identity)
                    .is_err()
            );
            assert!(sign_q04_acknowledgement_v1(kind, &mut packet, &key, &identity).is_err());
        }

        let release = Q04AcknowledgementKindV1::Release;
        let mut packet = acknowledgement_body(release, &identity);
        sign_q04_acknowledgement_v1(release, &mut packet, &key, &identity).unwrap();
        let foreign_signature = key.sign(
            &acknowledgement_signature_preimage(
                Q04AcknowledgementKindV1::Policy,
                &packet[..release.body_bytes()],
            )
            .unwrap(),
        );
        packet[release.body_bytes()..].copy_from_slice(&foreign_signature.to_bytes());

        assert!(matches!(
            Q04AcknowledgementV1::verify(release, &packet, &pin, &identity),
            Err(aos_sandbox_policy::q04_data::PolicyQ04DataErrorV1::AcknowledgementSignature(_)),
        ));
    }

    #[test]
    fn claim_signature_binds_every_original_byte_and_distinct_purpose() {
        let identity = identity();
        let key = SigningKey::from_bytes(&[7; 32]);
        let credential =
            aos_sandbox_policy::controller_readback::encode_controller_hold_signer_credential_v1(
                1,
                &key.verifying_key(),
            )
            .map_err(crate::policy_compiler::ControllerHoldReadbackErrorV1::from)
            .unwrap();
        let pin = aos_sandbox_policy::controller_readback::PinnedControllerHoldSignerV1::decode(
            &credential,
        )
        .map_err(crate::policy_compiler::ControllerHoldReadbackErrorV1::from)
        .unwrap();

        // These opaque width fixtures exercise only the Claim envelope. The
        // real Root consumer must separately decode/authenticate each old
        // field with its existing engine; no fixture constructs a live owner.
        let binding = vec![8; super::super::CLOSED_POLICY_BINDING_BYTES_V2];
        let current = vec![9; CONTROLLER_PROJECT_ADMISSION_READBACK_BYTES_V1];
        let held = vec![
                10;
                aos_sandbox_policy::controller_readback::CLOSED_CONTROLLER_HOLD_READBACK_BYTES_V1
            ];
        let source = vec![11; super::super::SOURCE_TREE_GENESIS_READBACK_BYTES_V1];
        let cache = vec![12; aos_sandbox_protocol::cache_owner_readback::CLOSED_CACHE_OWNER_READBACK_BYTES_V2];
        let fields = [
            b"operation".as_slice(),
            b"desired",
            b"effect",
            b"node",
            b"site",
            b"backend",
            b"catalogs",
            b"project",
            &binding,
            &current,
            &held,
            &source,
            &cache,
            identity.bytes(),
        ];
        let mut packet = Vec::new();
        encode_q04_claim_body_v1(&mut packet, fields, &identity).unwrap();
        sign_q04_claim_v1(&mut packet, &key, &identity).unwrap();
        let claim = Q04ClaimV1::verify(&packet, &pin, &identity).unwrap();

        assert_eq!(claim.fields()[0], b"operation");
        assert_eq!(claim.fields()[13], identity.bytes());
        assert_eq!(claim.bytes(), packet);
        assert!(sign_q04_claim_v1(&mut packet, &key, &identity).is_err());

        let mut tampered = packet.clone();
        tampered[CLAIM_PREFIX_BYTES] ^= 1;
        assert!(matches!(
            Q04ClaimV1::verify(&tampered, &pin, &identity).map_err(CreateQ04ErrorV1::from),
            Err(CreateQ04ErrorV1::ClaimSignature(_)),
        ));

        let signature_offset = packet.len() - 64;
        let wrong = key.sign(
            &signed_record_preimage(
                Q04AcknowledgementKindV1::Policy.signature_domain(),
                &packet[..signature_offset],
            )
            .unwrap(),
        );
        let mut foreign = packet.clone();
        foreign[signature_offset..].copy_from_slice(&wrong.to_bytes());
        assert!(matches!(
            Q04ClaimV1::verify(&foreign, &pin, &identity).map_err(CreateQ04ErrorV1::from),
            Err(CreateQ04ErrorV1::ClaimSignature(_)),
        ));
    }

    #[test]
    fn claim_rejects_substituted_cut_reserved_lengths_and_partial_fields() {
        let identity = identity();
        let binding = vec![8; super::super::CLOSED_POLICY_BINDING_BYTES_V2];
        let current = vec![9; CONTROLLER_PROJECT_ADMISSION_READBACK_BYTES_V1];
        let held = vec![
                10;
                aos_sandbox_policy::controller_readback::CLOSED_CONTROLLER_HOLD_READBACK_BYTES_V1
            ];
        let source = vec![11; super::super::SOURCE_TREE_GENESIS_READBACK_BYTES_V1];
        let cache = vec![12; aos_sandbox_protocol::cache_owner_readback::CLOSED_CACHE_OWNER_READBACK_BYTES_V2];
        let fields = [
            b"operation".as_slice(),
            b"desired",
            b"effect",
            b"node",
            b"site",
            b"backend",
            b"catalogs",
            b"project",
            &binding,
            &current,
            &held,
            &source,
            &cache,
            identity.bytes(),
        ];
        let mut body = Vec::new();
        encode_q04_claim_body_v1(&mut body, fields, &identity).unwrap();

        let mut other_cut = *identity.bytes();
        other_cut[392] ^= 1;
        let other_cut = Q04CutIdentityV1::from_body(other_cut).unwrap();
        let mut substituted = fields;
        substituted[13] = other_cut.bytes();
        assert!(encode_q04_claim_body_v1(&mut Vec::new(), substituted, &identity).is_err());

        for (offset, value) in [(10, 1), (16, 255), (CLAIM_PREFIX_BYTES - 1, 0)] {
            let mut changed = body.clone();
            changed[offset] = value;
            assert!(claim_body_fields(&changed, &identity).is_err());
        }
        assert!(claim_body_fields(&body[..body.len() - 1], &identity).is_err());
        body.push(0);
        assert!(claim_body_fields(&body, &identity).is_err());
    }

    // Opaque old-format fields deliberately test only the Q04 envelope. This
    // is not a canonical old ledger, independent pin admission or live owner.
    fn chunked_claim_fixture(identity: &Q04CutIdentityV1, key: &SigningKey) -> Vec<u8> {
        let operation = vec![1; 9000];
        let binding = vec![8; super::super::CLOSED_POLICY_BINDING_BYTES_V2];
        let current = vec![9; CONTROLLER_PROJECT_ADMISSION_READBACK_BYTES_V1];
        let held = vec![
                10;
                aos_sandbox_policy::controller_readback::CLOSED_CONTROLLER_HOLD_READBACK_BYTES_V1
            ];
        let source = vec![11; super::super::SOURCE_TREE_GENESIS_READBACK_BYTES_V1];
        let cache = vec![12; aos_sandbox_protocol::cache_owner_readback::CLOSED_CACHE_OWNER_READBACK_BYTES_V2];
        let fields = [
            operation.as_slice(),
            b"desired",
            b"effect",
            b"node",
            b"site",
            b"backend",
            b"catalogs",
            b"project",
            &binding,
            &current,
            &held,
            &source,
            &cache,
            identity.bytes(),
        ];
        let mut packet = Vec::new();
        encode_q04_claim_body_v1(&mut packet, fields, identity).unwrap();
        sign_q04_claim_v1(&mut packet, key, identity).unwrap();
        packet
    }

    #[test]
    fn index_and_chunks_reconstruct_only_the_exact_whole_signed_claim() {
        let identity = identity();
        let key = SigningKey::from_bytes(&[7; 32]);
        let credential =
            aos_sandbox_policy::controller_readback::encode_controller_hold_signer_credential_v1(
                1,
                &key.verifying_key(),
            )
            .map_err(crate::policy_compiler::ControllerHoldReadbackErrorV1::from)
            .unwrap();
        let pin = aos_sandbox_policy::controller_readback::PinnedControllerHoldSignerV1::decode(
            &credential,
        )
        .map_err(crate::policy_compiler::ControllerHoldReadbackErrorV1::from)
        .unwrap();
        let packet = chunked_claim_fixture(&identity, &key);
        let claim = Q04ClaimV1::verify(&packet, &pin, &identity).unwrap();
        let recipe = Q04ClaimStorageRecipeV1::new(&claim, &identity).unwrap();
        let mut reconstructed = Vec::new();

        for index in 0..recipe.chunk_count() {
            let mut encoded = Vec::new();
            recipe.encode_chunk(index, &mut encoded).unwrap();
            assert!(encoded.len() <= CLAIM_CHUNK_PREFIX_BYTES + CLAIM_CHUNK_BYTES);
            let chunk = Q04ClaimChunkV1::decode(&encoded, recipe.index_bytes(), &identity).unwrap();
            chunk.append_to(&mut reconstructed).unwrap();
            assert!(chunk.append_to(&mut reconstructed).is_err());
        }
        let reconstructed = Q04ClaimV1::verify(&reconstructed, &pin, &identity).unwrap();
        Q04ClaimStorageRecipeV1::verify_index(recipe.index_bytes(), &reconstructed, &identity)
            .unwrap();

        assert_eq!(reconstructed.bytes(), packet);
        assert_eq!(recipe.index_bytes().len(), 96);
        assert_eq!(claim_chunk_count(MAXIMUM_CLAIM_BYTES).unwrap(), 342);
        assert!(claim_chunk_count(MAXIMUM_CLAIM_BYTES + 1).is_err());
        assert!(
            recipe
                .encode_chunk(recipe.chunk_count(), &mut Vec::new())
                .is_err()
        );

        let mut changed = packet.clone();
        changed[CLAIM_PREFIX_BYTES] ^= 1;
        let changed = Q04ClaimV1::decode(&changed, &identity).unwrap();
        assert!(
            Q04ClaimStorageRecipeV1::verify_index(recipe.index_bytes(), &changed, &identity,)
                .is_err()
        );
    }

    #[test]
    fn index_refuses_header_only_or_wrong_domain_and_chunks_refuse_substitution() {
        let identity = identity();
        let key = SigningKey::from_bytes(&[7; 32]);
        let packet = chunked_claim_fixture(&identity, &key);
        let claim = Q04ClaimV1::decode(&packet, &identity).unwrap();
        let recipe = Q04ClaimStorageRecipeV1::new(&claim, &identity).unwrap();
        let mut index = *recipe.index_bytes();
        let header_only = Sha256::new()
            .chain_update(CLAIM_INDEX_DOMAIN)
            .chain_update(&index[..64])
            .finalize();
        index[64..96].copy_from_slice(&header_only);

        assert!(Q04ClaimStorageRecipeV1::verify_index(&index, &claim, &identity).is_err());
        let foreign = Sha256::new()
            .chain_update(CLAIM_CHUNK_DOMAIN)
            .chain_update(&index[..64])
            .chain_update(&packet)
            .finalize();
        index[64..96].copy_from_slice(&foreign);
        assert!(Q04ClaimStorageRecipeV1::verify_index(&index, &claim, &identity).is_err());

        let mut chunk = Vec::new();
        recipe.encode_chunk(1, &mut chunk).unwrap();
        let decoded = Q04ClaimChunkV1::decode(&chunk, recipe.index_bytes(), &identity).unwrap();
        assert!(decoded.append_to(&mut Vec::new()).is_err());
        for offset in [10, 16, 48, 50, 52, 88, CLAIM_CHUNK_PREFIX_BYTES] {
            let mut changed = chunk.clone();
            changed[offset] ^= 1;
            assert!(Q04ClaimChunkV1::decode(&changed, recipe.index_bytes(), &identity).is_err());
        }
        chunk.push(0);
        assert!(Q04ClaimChunkV1::decode(&chunk, recipe.index_bytes(), &identity).is_err());
    }

    fn preview_fixture(input_bytes: usize, layer_bytes: usize) -> Vec<u8> {
        // Only the bounded Preview codec is under test. The opaque source
        // fields are not signatures, independent pins or live owner custody.
        let mut metadata = [0; 120];
        metadata[..16].fill(2);
        metadata[16..24].copy_from_slice(&200_u64.to_be_bytes());
        metadata[24..32].copy_from_slice(&65_000_000_200_u64.to_be_bytes());
        metadata[32..40].copy_from_slice(&7_u64.to_be_bytes());
        metadata[40..88].fill(3);
        metadata[88..120].fill(4);

        let mut stage = [0; 128];
        stage[..16].fill(5);
        stage[48..56].copy_from_slice(&1_u64.to_be_bytes());
        stage[56..64].copy_from_slice(&2_u64.to_be_bytes());
        stage[64..72].copy_from_slice(&3_u64.to_be_bytes());
        stage[72..88].fill(13);
        stage[88..96].copy_from_slice(&9_u64.to_be_bytes());
        stage[96..128].fill(14);

        let deployment = [6; 224];
        let project = [7; 328];
        let input = vec![8; input_bytes];
        let layer = vec![9; layer_bytes];
        let fields = [
            metadata.as_slice(),
            stage.as_slice(),
            deployment.as_slice(),
            input.as_slice(),
            input.as_slice(),
            input.as_slice(),
            input.as_slice(),
            project.as_slice(),
            layer.as_slice(),
        ];
        let mut packet = Vec::new();
        encode_q04_preview_body_v1(&mut packet, fields, [13; 16]).unwrap();
        packet
    }

    #[test]
    fn preview_maximum_reconstructs_in_original_order_without_claim_identity() {
        let packet = preview_fixture(64 * 1024, 3 * 1024);
        let preview = Q04PreviewV1::decode(&packet, [13; 16]).unwrap();
        let recipe = Q04PreviewTransferRecipeV1::new(&preview).unwrap();

        assert_eq!(packet.len(), MAXIMUM_PREVIEW_BYTES);
        assert_eq!(recipe.chunk_count(), 87);
        assert_eq!(preview.staged().unwrap().base().next_generation(), 1);
        assert_eq!(preview.staged().unwrap().issue_epoch(), 9);

        let mut reconstructed = Vec::new();
        for index in 0..recipe.chunk_count() {
            let mut chunk = Vec::new();
            recipe.encode_chunk(index, &mut chunk).unwrap();
            let checked = Q04PreviewChunkV1::decode(&chunk, recipe.index_bytes()).unwrap();
            checked.append_to(&mut reconstructed).unwrap();
        }
        let reconstructed_preview = Q04PreviewV1::decode(&reconstructed, [13; 16]).unwrap();

        assert_eq!(reconstructed, packet);
        Q04PreviewTransferRecipeV1::verify_index(recipe.index_bytes(), &reconstructed_preview)
            .unwrap();
        assert!(Q04ClaimV1::decode(&reconstructed, &identity()).is_err());
        assert!(Q04PreviewV1::decode(&packet, [12; 16]).is_err());
    }

    #[test]
    fn preview_refuses_sparse_duplicate_tampered_and_foreign_purpose_chunks() {
        let packet = preview_fixture(1024, 3072);
        let preview = Q04PreviewV1::decode(&packet, [13; 16]).unwrap();
        let recipe = Q04PreviewTransferRecipeV1::new(&preview).unwrap();
        let mut second = Vec::new();
        recipe.encode_chunk(1, &mut second).unwrap();
        let second = Q04PreviewChunkV1::decode(&second, recipe.index_bytes()).unwrap();

        assert!(second.append_to(&mut Vec::new()).is_err());

        let mut first = Vec::new();
        recipe.encode_chunk(0, &mut first).unwrap();
        let mut reconstructed = Vec::new();
        let checked = Q04PreviewChunkV1::decode(&first, recipe.index_bytes()).unwrap();
        checked.append_to(&mut reconstructed).unwrap();
        assert!(checked.append_to(&mut reconstructed).is_err());

        for offset in [0, 8, 10, 16, 48, 50, 52, 56, 88, CLAIM_CHUNK_PREFIX_BYTES] {
            let mut changed = first.clone();
            changed[offset] ^= 1;
            assert!(Q04PreviewChunkV1::decode(&changed, recipe.index_bytes()).is_err());
        }
        let mut foreign = first;
        foreign[..8].copy_from_slice(b"AOSQ4B01");
        assert!(Q04PreviewChunkV1::decode(&foreign, recipe.index_bytes()).is_err());
    }

    #[test]
    fn preview_index_compares_whole_packet_after_exact_length_decode() {
        let packet = preview_fixture(1, 1);
        let preview = Q04PreviewV1::decode(&packet, [13; 16]).unwrap();
        let recipe = Q04PreviewTransferRecipeV1::new(&preview).unwrap();
        let mut changed = packet.clone();
        let final_byte = changed.len() - 1;
        changed[final_byte] ^= 1;
        let changed_preview = Q04PreviewV1::decode(&changed, [13; 16]).unwrap();

        assert!(
            Q04PreviewTransferRecipeV1::verify_index(recipe.index_bytes(), &changed_preview)
                .is_err()
        );
        changed.push(0);
        assert!(Q04PreviewV1::decode(&changed, [13; 16]).is_err());

        let mut wrong_domain = *recipe.index_bytes();
        let wrong_digest = Sha256::new()
            .chain_update(CLAIM_INDEX_DOMAIN)
            .chain_update(&packet)
            .finalize();
        wrong_domain[..32].copy_from_slice(&wrong_digest);
        assert!(Q04PreviewTransferRecipeV1::verify_index(&wrong_domain, &preview).is_err());

        let mut reserved = *recipe.index_bytes();
        reserved[47] = 1;
        assert!(preview_index_shape(&reserved).is_err());
        assert!(chunk_count(MAXIMUM_PREVIEW_BYTES + 1, MAXIMUM_PREVIEW_BYTES).is_err());
    }

    // Inert structural DATA fixtures exercise only these codecs. They do not
    // stand in for original journals, credential custody or live phase loans.
    fn prehold_fixture(row_bytes: usize) -> Vec<u8> {
        let mut metadata = [0; PREHOLD_METADATA_BYTES];
        metadata[..16].fill(4);
        metadata[16..24].copy_from_slice(&10_u64.to_be_bytes());
        metadata[24..32].copy_from_slice(&60_000_000_010_u64.to_be_bytes());
        metadata[32..40].copy_from_slice(&7_u64.to_be_bytes());
        metadata[40..48].copy_from_slice(&1_u64.to_be_bytes());
        metadata[48..464].fill(9);
        for offset in (464..512).step_by(8) {
            metadata[offset..offset + 8].copy_from_slice(&1_u64.to_be_bytes());
        }
        let rows = vec![3; row_bytes];
        let binding = [5; super::super::CLOSED_POLICY_BINDING_BYTES_V2];
        let current = [6; CONTROLLER_PROJECT_ADMISSION_READBACK_BYTES_V1];
        let mut packet = Vec::new();
        encode_q04_prehold_body_v1(
            &mut packet,
            [&metadata, &rows, &rows, &rows, &binding, &current],
        )
        .unwrap();
        sign_q04_prehold_body_v1(&mut packet, &SigningKey::from_bytes(&[42; 32])).unwrap();
        packet
    }

    #[test]
    fn prehold_signature_is_whole_original_data_and_not_claim_or_ack_purpose() {
        let key = SigningKey::from_bytes(&[42; 32]);
        let credential =
            aos_sandbox_policy::controller_readback::encode_controller_hold_signer_credential_v1(
                7,
                &key.verifying_key(),
            )
            .map_err(crate::policy_compiler::ControllerHoldReadbackErrorV1::from)
            .unwrap();
        let pin = aos_sandbox_policy::controller_readback::PinnedControllerHoldSignerV1::decode(
            &credential,
        )
        .map_err(crate::policy_compiler::ControllerHoldReadbackErrorV1::from)
        .unwrap();
        let packet = prehold_fixture(1);

        assert!(Q04PreholdInputDataV1::verify(&packet, &pin).is_ok());
        let mut altered = packet.clone();
        altered[PREHOLD_PREFIX_BYTES + PREHOLD_METADATA_BYTES] ^= 1;
        assert!(Q04PreholdInputDataV1::verify(&altered, &pin).is_err());
        let mut wrong_domain = packet;
        let signature_offset = wrong_domain.len() - 64;
        let signature = key.sign(
            &signed_record_preimage(CLAIM_SIGNATURE_DOMAIN, &wrong_domain[..signature_offset])
                .unwrap(),
        );
        wrong_domain[signature_offset..].copy_from_slice(&signature.to_bytes());
        assert!(Q04PreholdInputDataV1::verify(&wrong_domain, &pin).is_err());
    }

    #[test]
    fn prehold_maximum_shares_strict_ordered_chunk_engine_and_has_sixty_five_chunks() {
        let packet = prehold_fixture(64 * 1024);
        let request = Q04PreholdInputDataV1::decode(&packet).unwrap();
        let transfer = Q04PreholdTransferRecipeV1::new(&request).unwrap();

        assert_eq!(packet.len(), MAXIMUM_PREHOLD_BYTES);
        assert_eq!(transfer.chunk_count(), 65);
        let mut reconstructed = Vec::new();
        for index in 0..transfer.chunk_count() {
            let mut chunk = Vec::new();
            transfer.encode_chunk(index, &mut chunk).unwrap();
            let checked = Q04PreholdChunkV1::decode(&chunk, transfer.index_bytes()).unwrap();
            checked.append_to(&mut reconstructed).unwrap();

            assert!(checked.append_to(&mut reconstructed).is_err());
            assert!(Q04PreviewChunkV1::decode(&chunk, transfer.index_bytes()).is_err());
        }
        assert_eq!(reconstructed, packet);
        let reconstructed = Q04PreholdInputDataV1::decode(&reconstructed).unwrap();
        Q04PreholdTransferRecipeV1::verify_index(transfer.index_bytes(), &reconstructed).unwrap();
    }

    #[test]
    fn original_precut_whitelist_excludes_new_binding_current_signature_and_stage_fields() {
        let packet = prehold_fixture(1);
        let preview_packet = preview_fixture(1, 1);
        let request = Q04PreholdInputDataV1::decode(&packet).unwrap();
        let preview = Q04PreviewV1::decode(&preview_packet, [13; 16]).unwrap();
        let names =
            crate::journal::ProtectedJournalNamesV1::from_bytes(&request.fields()[0][176..224])
                .unwrap();
        let complete =
            [7; super::super::source_genesis_root::CONTROLLER_SOURCE_GENESIS_READBACK_BYTES_V1];
        let source = [8; super::super::SOURCE_TREE_GENESIS_READBACK_BYTES_V1];
        let original =
            q04_original_precut_digest_v1(&request, &preview, &complete, &source, names, 1)
                .unwrap();

        let mut changed = packet.clone();
        // Header40 + metadata512 + three one-byte rows precede B664/CTP03.
        changed[PREHOLD_PREFIX_BYTES + PREHOLD_METADATA_BYTES + 3] ^= 1;
        changed[PREHOLD_PREFIX_BYTES
            + PREHOLD_METADATA_BYTES
            + 3
            + super::super::CLOSED_POLICY_BINDING_BYTES_V2] ^= 1;
        let final_byte = changed.len() - 1;
        changed[final_byte] ^= 1;
        let changed = Q04PreholdInputDataV1::decode(&changed).unwrap();
        let mut changed_preview = preview_packet.clone();
        changed_preview[PREVIEW_PREFIX_BYTES + 120 + 96] ^= 1;
        let changed_preview = Q04PreviewV1::decode(&changed_preview, [13; 16]).unwrap();

        assert_eq!(
            q04_original_precut_digest_v1(&changed, &changed_preview, &complete, &source, names, 1)
                .unwrap(),
            original
        );
        let mut changed_row = packet.clone();
        changed_row[PREHOLD_PREFIX_BYTES + PREHOLD_METADATA_BYTES] ^= 1;
        let changed_row = Q04PreholdInputDataV1::decode(&changed_row).unwrap();
        assert_ne!(
            q04_original_precut_digest_v1(&changed_row, &preview, &complete, &source, names, 1)
                .unwrap(),
            original
        );
        assert_ne!(
            q04_original_precut_digest_v1(&request, &preview, &complete, &source, names, 2)
                .unwrap(),
            original
        );
    }
}

impl From<aos_sandbox_protocol::domain_ledger::create_q04_history::original_rows::Q04OriginalRowsDataErrorV1> for CreateQ04ErrorV1 {
    fn from(error: aos_sandbox_protocol::domain_ledger::create_q04_history::original_rows::Q04OriginalRowsDataErrorV1) -> Self {
        use aos_sandbox_protocol::domain_ledger::create_q04_history::original_rows::Q04OriginalRowsDataErrorV1 as Data;
        match error {
            Data::CorruptLedger(reason) => Self::Reconciler(crate::reconciler::ReconcilerError::CorruptLedger(reason)),
            Data::Operation(error) => Self::Reconciler(crate::reconciler::ReconcilerError::from(error)),
            Data::Effect(error) => Self::Reconciler(crate::reconciler::ReconcilerError::from(error)),
            Data::Projection(error) => Self::Projection(error),
            Data::Hash(error) => Self::Journal(match error {
                aos_sandbox_protocol::domain_ledger::create_q04_history::original_rows::Q04OriginalRowsHashDataErrorV1::ProtectedBoundary => JournalError::ProtectedBoundary,
                aos_sandbox_protocol::domain_ledger::create_q04_history::original_rows::Q04OriginalRowsHashDataErrorV1::Transaction(error) => JournalError::from(error),
            }),
        }
    }
}

// Origin failures retain their exact selected/ordinary native source. This
// projection never observes another Origin or reconstructs a currentness cut.
pub(crate) fn project_root_q04_origin_error_v1(
    error: aos_sandbox_broker::receiving::RootQ04OriginErrorV1,
) -> CreateQ04ErrorV1 {
    authority_error::map_root_authority_error_v1(
        aos_sandbox_policy::native::RootAuthorityErrorV1::Origin(error),
    )
}

impl From<aos_sandbox_cache::CacheQ04ErrorV1> for CreateQ04ErrorV1 {
    fn from(cause: aos_sandbox_cache::CacheQ04ErrorV1) -> Self {
        Self::NativeCache(Box::new(cause))
    }
}
