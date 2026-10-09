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

use aos_sandbox_core::{ObjectDigest, OperationId, ProjectId, SandboxId};
use ed25519_dalek::{Signature, Signer as _, SigningKey};
use sha2::{Digest as _, Sha256};

use crate::journal::JournalError;

mod client;
mod input_origin;
pub(super) mod root;

pub(crate) use client::{
    OriginalCreateQ04InvocationV1, OriginalQ04FinalRootObservationV1, OriginalQ04RootCacheLoanV1,
    Q04ControllerPreparationV1,
    OriginalQ04ProjectPreparationLoanV1,
    OriginalQ04CompletedPreparationLoanV1,
};
pub(crate) use root::{
    Q04RootAuthorityHistoryV1, RootOriginalInputLoanV1,
    require_root_q04_fixed_writer, require_root_q04_ordinary_boundary,
};
pub(crate) use root::capacity_shape_digest as q04_capacity_shape_digest_v1;
pub(crate) use root::root_consumed_gate_record as root_consumed_gate_v1;
pub(crate) use input_origin::{
    CONTROLLER_INPUT_ORIGIN_KEY, Q04OriginalInputDemandV1, Q04PreparedInputOriginV1,
    cache_replay_cell_bytes, candidate_capacity, original_input_demand, require_origin_identity,
};

pub(crate) const IDENTITY_BYTES: usize = 680;
pub(crate) const PHASE_BYTES: usize = 592;
pub(crate) const PENDING_BYTES: usize = 264;
pub(crate) const GATE_BYTES: usize = 288;
pub(crate) const DECISION_BYTES: usize = 384;
pub(crate) const MAXIMUM_CLAIM_BYTES: usize = 1024 * 1024;
pub(crate) const CLAIM_INDEX_BYTES: usize = 96;
pub(crate) const CLAIM_CHUNK_PREFIX_BYTES: usize = 96;
pub(crate) const CLAIM_CHUNK_BYTES: usize = 3072;
pub(crate) const PREVIEW_INDEX_BYTES: usize = 48;
pub(crate) const MAXIMUM_PREVIEW_BYTES: usize = 266_068;
pub(crate) const PREHOLD_METADATA_BYTES: usize = 512;
pub(crate) const PREHOLD_RESPONSE_BYTES: usize = 504;
pub(crate) const MAXIMUM_PREHOLD_BYTES: usize = 198_252;
const PREHOLD_FIELDS: usize = 6;
const PREHOLD_PREFIX_BYTES: usize = 16 + PREHOLD_FIELDS * 4;
const PREVIEW_FIELDS: usize = 9;
const PREVIEW_PREFIX_BYTES: usize = 16 + PREVIEW_FIELDS * 4;
const CLAIM_FIELDS: usize = 14;
const CLAIM_PREFIX_BYTES: usize = 16 + CLAIM_FIELDS * 4;
pub(crate) const CONTROLLER_IDENTITY_KEY: &[u8] = b"\0aos-controller-q04-cut-v1\0";
pub(crate) const CONTROLLER_PHASE_PREFIX: &[u8] = b"\0aos-controller-q04-phase-v1\0";
pub(crate) const SOURCE_PENDING_KEY: &[u8] = b"\0aos-source-domain-q04-pending-v1\0";
pub(crate) const CACHE_PENDING_KEY: &[u8] = b"\0aos-cache-q04-pending-v1\0";

const IDENTITY_DOMAIN: &[u8] = b"aos.sandbox.create-q04.cut-identity.v1\0";
const CONTROLLER_PHASE_DOMAIN: &[u8] = b"aos.sandbox.create-q04.controller-phase.v1\0";
const ROOT_PHASE_DOMAIN: &[u8] = b"aos.sandbox.create-q04.root-phase.v1\0";
const SOURCE_PENDING_DOMAIN: &[u8] = b"aos.sandbox.create-q04.source-pending.v1\0";
const CACHE_PENDING_DOMAIN: &[u8] = b"aos.sandbox.create-q04.cache-pending.v1\0";
const GATE_DOMAIN: &[u8] = b"aos.sandbox.create-q04.effect-subgate.v1\0";
const GATE_IDENTITY_DOMAIN: &[u8] = b"aos.sandbox.create-q04.effect-gate-identity.v1\0";
const DECISION_DOMAIN: &[u8] = b"aos.sandbox.create-q04.root-decision.v1\0";
const CLAIM_SIGNATURE_DOMAIN: &[u8] = b"aos.sandbox.create-q04.claim.signature.v1\0";
const CLAIM_INDEX_DOMAIN: &[u8] = b"aos.sandbox.create-q04.claim-index.v1\0";
const CLAIM_CHUNK_DOMAIN: &[u8] = b"aos.sandbox.create-q04.claim-chunk.v1\0";
const PREVIEW_DOMAIN: &[u8] = b"aos.sandbox.create-q04.preview.v1\0";
const PREVIEW_CHUNK_DOMAIN: &[u8] = b"aos.sandbox.create-q04.preview-chunk.v1\0";
const PREHOLD_SIGNATURE_DOMAIN: &[u8] = b"aos.sandbox.create-q04.prefund-request.signature.v1\0";
const PREHOLD_REQUEST_DOMAIN: &[u8] = b"aos.sandbox.create-q04.prefund-request.v1\0";
const PREHOLD_CHUNK_DOMAIN: &[u8] = b"aos.sandbox.create-q04.prefund-chunk.v1\0";
const PREHOLD_RESPONSE_DOMAIN: &[u8] = b"aos.sandbox.create-q04.prefund-response.v1\0";
const ORIGINAL_PRECUT_DOMAIN: &[u8] = b"aos.sandbox.create-q04.original-precut.v1\0";

// Both original owners compare the same canonical DATA. The recipe contains
// no live loan, signature brand, future phase or caller-created authority.
pub(super) struct Q04CutRecipeV1<'recipe> {
    pub(super) nonce: [u8; 16],
    pub(super) project: ProjectId,
    pub(super) operation: OperationId,
    pub(super) sandbox: SandboxId,
    pub(super) controller_uid: u32,
    pub(super) source_uid: u32,
    pub(super) controller_metadata: &'recipe [u8],
    pub(super) root_boot: [u8; 16],
    pub(super) root_started: u64,
    pub(super) handoff_epoch: u64,
    pub(super) stage: [u8; 16],
    pub(super) publication: [u8; 16],
    pub(super) digests: [ObjectDigest; 14],
}

pub(super) fn encode_q04_cut_recipe_v1(
    recipe: Q04CutRecipeV1<'_>,
) -> Result<Q04CutIdentityV1, CreateQ04ErrorV1> {
    if recipe.controller_metadata.len() != PREHOLD_METADATA_BYTES {
        return Err(CreateQ04ErrorV1::Bounds);
    }
    let mut body = [0; IDENTITY_BYTES];
    body[16..32].copy_from_slice(&recipe.nonce);
    body[32..48].copy_from_slice(recipe.project.as_bytes());
    body[48..64].copy_from_slice(recipe.operation.as_bytes());
    body[64..80].copy_from_slice(recipe.sandbox.as_bytes());
    body[80..84].copy_from_slice(&recipe.controller_uid.to_be_bytes());
    body[84..88].copy_from_slice(&recipe.source_uid.to_be_bytes());
    body[88..96].copy_from_slice(&recipe.controller_metadata[32..40]);
    body[96..104].copy_from_slice(&1_u64.to_be_bytes());
    body[112..128].copy_from_slice(&recipe.root_boot);
    body[128..144].copy_from_slice(&recipe.controller_metadata[16..32]);
    body[144..152].copy_from_slice(&recipe.root_started.to_be_bytes());
    body[152..160].copy_from_slice(&recipe.root_started
        .checked_add(65_000_000_000).ok_or(CreateQ04ErrorV1::Expired)?.to_be_bytes());
    body[160..168].copy_from_slice(&recipe.handoff_epoch.to_be_bytes());
    body[168..184].copy_from_slice(&recipe.stage);
    body[184..200].copy_from_slice(&recipe.publication);
    for (index, digest) in recipe.digests.into_iter().enumerate() {
        let start = 200 + index * 32;
        body[start..start + 32].copy_from_slice(digest.as_bytes());
    }
    Q04CutIdentityV1::from_body(body).map_err(CreateQ04ErrorV1::Journal)
}

/// Reports the original typed failure of a selected Q04 continuation.
///
/// This error is not a retry, clearance, receipt or public Create result.
/// Its caller retains the actual failed invocation and independent owners.
#[derive(Debug, thiserror::Error)]
pub enum CreateQ04ErrorV1 {
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
    PolicyCompiler(#[from] super::PolicyCompilerJournalErrorV1),
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
    Kernel(#[from] aos_sandbox_linux::Error),
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
    CachePacket(#[from] crate::cache_residency::CacheOwnerReadbackErrorV1),
    /// The actual fixed read-only Cache journal view failed its old engine.
    #[error(transparent)]
    CacheJournal(#[from] crate::cache_residency::CacheResidencyProtectedJournalErrorV1),
    /// The same retained physical Cache owner failed an original bookend.
    #[error(transparent)]
    CachePhysical(#[from] crate::cache_residency::CacheOwnerErrorV1),
    /// The original fixed Cache bootstrap source failed its existing engine.
    #[error(transparent)]
    CacheBootstrap(#[from] crate::cache_residency::CacheReplayControllerBootstrapErrorV1),
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
    Projection(#[from] crate::controller_service::public_projection::PublicProjectionError),
    /// The sole deterministic compiler rejected the retained original input.
    #[error(transparent)]
    Compilation(#[from] aos_sandbox_policy::PolicyCompilationError),
    /// The existing full original-input archive failed its sole codec.
    #[error(transparent)]
    InputOrigin(#[from] crate::publisher_policy::PublisherPolicyError),
    /// A purpose, identity, phase or original owner join changed.
    #[error("the original Q04 continuation cut changed")]
    ChangedCut,
    /// The unchanged original flight cutoff was reached.
    #[error("the original Q04 flight deadline expired")]
    Expired,
    /// A bounded original input or canonical suffix exceeded its limit.
    #[error("the original Q04 input or suffix exceeds its bound")]
    Bounds,
    /// A selected owner scope unwound before its final clearance.
    #[error("the original Q04 continuation unwound")]
    Unwind,
}

impl From<JournalTransactionDataError> for CreateQ04ErrorV1 {
    fn from(error: JournalTransactionDataError) -> Self {
        <Self as From<JournalError>>::from(JournalError::from(error))
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

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum Q04TransactionOwnerV1 {
    Controller,
    Source,
    Cache,
    Root,
}

// This nonissuing shape funds the same fixed-width lower suffix before Root5
// exists. Neither lower writer may commit a release with this value: the
// actual original-flight loan must bind the observed Root5 first.
pub(crate) fn lower_release_capacity_shape(identity: &Q04CutIdentityV1) -> ObjectDigest {
    ObjectDigest::from_bytes(Sha256::new()
        .chain_update(b"aos.sandbox.create-q04.lower-release-capacity-shape.v1\0")
        .chain_update(identity.bytes())
        .finalize().into())
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
    if root_settlement.owner() != Q04PhaseOwnerV1::Root || root_settlement.phase() != 6
        || controller_settlement.owner() != Q04PhaseOwnerV1::Controller
        || controller_settlement.phase() != 6
        || cache_clear.as_bytes() == &[0; 32] || source_clear.as_bytes() == &[0; 32]
        || status_three_effect.is_empty()
    {
        return Err(CreateQ04ErrorV1::ChangedCut);
    }
    let mut digest = Sha256::new();
    digest.update(b"aos.sandbox.create-q04.lower-clearance-recipe.v1\0");
    for value in [
        identity.bytes().as_slice(), root_settlement.bytes().as_slice(),
        cache_clear.as_bytes().as_slice(), source_clear.as_bytes().as_slice(),
        controller_settlement.bytes().as_slice(), status_three_effect,
    ] {
        let length = u32::try_from(value.len()).map_err(|_| CreateQ04ErrorV1::Bounds)?;
        digest.update(length.to_be_bytes());
        digest.update(value);
    }
    Ok(ObjectDigest::from_bytes(digest.finalize().into()))
}

impl Q04TransactionOwnerV1 {
    /// Derives comparison DATA without predicting an observed commit or head.
    pub(crate) fn transaction_id(
        self,
        identity: &Q04CutIdentityV1,
        phase: u8,
        predecessor: ObjectDigest,
    ) -> Result<[u8; 16], JournalError> {
        let (domain, last): (&[u8], u8) = match self {
            Self::Controller => (b"aos.sandbox.create-q04.transaction.controller.v1\0", 8),
            Self::Source => (b"aos.sandbox.create-q04.transaction.source.v1\0", 3),
            Self::Cache => (b"aos.sandbox.create-q04.transaction.cache.v1\0", 3),
            Self::Root => (b"aos.sandbox.create-q04.transaction.root.v1\0", 7),
        };
        if phase == 0 || phase > last || predecessor.as_bytes() == &[0; 32] {
            return Err(JournalError::ProtectedBoundary);
        }

        let digest = Sha256::new()
            .chain_update(domain)
            .chain_update(identity.digest().as_bytes())
            .chain_update([phase])
            .chain_update(predecessor.as_bytes())
            .finalize();
        let mut transaction = [0; 16];
        transaction.copy_from_slice(&digest[..16]);
        if transaction == [0; 16] {
            return Err(JournalError::ProtectedBoundary);
        }
        Ok(transaction)
    }
}

// Every offset below is fixed by the versioned contract. Accessors read only
// a fully length/checksum/shape-checked array, never a caller's unchecked slice.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct Q04CutIdentityV1([u8; IDENTITY_BYTES]);

impl Q04CutIdentityV1 {
    pub(crate) fn from_body(mut body: [u8; IDENTITY_BYTES]) -> Result<Self, JournalError> {
        finish_record(&mut body, b"AOSQ4I01", None, IDENTITY_DOMAIN)?;
        Self::decode(&body)
    }

    pub(crate) fn decode(bytes: &[u8]) -> Result<Self, JournalError> {
        let bytes = checked_record::<IDENTITY_BYTES>(bytes, b"AOSQ4I01", None, IDENTITY_DOMAIN)?;
        if bytes[108..112] != [0; 4]
            || bytes[104..108] != [0; 4]
            || nonzero::<16>(&bytes, 16).is_err()
            || nonzero::<16>(&bytes, 32).is_err()
            || nonzero::<16>(&bytes, 48).is_err()
            || nonzero::<16>(&bytes, 64).is_err()
            || nonzero::<16>(&bytes, 112).is_err()
            || nonzero::<16>(&bytes, 168).is_err()
            || nonzero::<16>(&bytes, 184).is_err()
            || read_u32(&bytes, 80)? == 0
            || read_u32(&bytes, 84)? == 0
            || read_u64(&bytes, 88)? == 0
            || read_u64(&bytes, 96)? != 1
            || read_u64(&bytes, 160)? == 0
            || read_u64(&bytes, 136)?.checked_sub(read_u64(&bytes, 128)?) != Some(60_000_000_000)
            || read_u64(&bytes, 152)?.checked_sub(read_u64(&bytes, 144)?) != Some(65_000_000_000)
            || (200..648).step_by(32).any(|offset| nonzero::<32>(&bytes, offset).is_err())
        {
            return Err(JournalError::ProtectedBoundary);
        }
        Ok(Self(bytes))
    }

    pub(crate) fn bytes(&self) -> &[u8; IDENTITY_BYTES] {
        &self.0
    }

    pub(crate) fn digest(&self) -> ObjectDigest {
        ObjectDigest::from_bytes(Sha256::digest(self.0).into())
    }

    pub(crate) fn nonce(&self) -> [u8; 16] {
        fixed(&self.0, 16)
    }

    pub(crate) fn project(&self) -> ProjectId {
        ProjectId::from_bytes(fixed(&self.0, 32))
    }

    pub(crate) fn operation(&self) -> OperationId {
        OperationId::from_bytes(fixed(&self.0, 48))
    }

    pub(crate) fn controller_uid(&self) -> u32 {
        u32::from_be_bytes(fixed(&self.0, 80))
    }

    pub(crate) fn source_uid(&self) -> u32 {
        u32::from_be_bytes(fixed(&self.0, 84))
    }

    pub(crate) fn operation_revision(&self) -> ObjectDigest {
        ObjectDigest::from_bytes(fixed(&self.0, 200))
    }

    pub(crate) fn desired_precondition(&self) -> ObjectDigest {
        ObjectDigest::from_bytes(fixed(&self.0, 232))
    }

    pub(crate) fn effect_plan_digest(&self) -> ObjectDigest {
        ObjectDigest::from_bytes(fixed(&self.0, 264))
    }

    pub(crate) fn sandbox(&self) -> SandboxId {
        SandboxId::from_bytes(fixed(&self.0, 64))
    }

    pub(crate) fn stage_id(&self) -> [u8; 16] {
        fixed(&self.0, 168)
    }

    pub(crate) fn publication_id(&self) -> [u8; 16] {
        fixed(&self.0, 184)
    }

    pub(crate) fn binding(&self) -> ObjectDigest {
        ObjectDigest::from_bytes(fixed(&self.0, 424))
    }

    pub(crate) fn gen1_floor(&self) -> ObjectDigest {
        ObjectDigest::from_bytes(fixed(&self.0, 328))
    }

    pub(crate) fn ancestry(&self) -> ObjectDigest {
        ObjectDigest::from_bytes(fixed(&self.0, 360))
    }

    /// Names the pre-decision comparator, not a consumed gate or authority.
    pub(crate) fn gate_identity(&self) -> ObjectDigest {
        ObjectDigest::from_bytes(
            Sha256::new()
                .chain_update(GATE_IDENTITY_DOMAIN)
                .chain_update(self.bytes())
                .finalize()
                .into(),
        )
    }

    pub(crate) fn accepted_generation(&self) -> u64 {
        u64::from_be_bytes(fixed(&self.0, 96))
    }

    pub(crate) fn epoch(&self) -> u64 {
        u64::from_be_bytes(fixed(&self.0, 160))
    }

    pub(crate) fn before_controller_rows(&self) -> ObjectDigest {
        ObjectDigest::from_bytes(fixed(&self.0, 296))
    }

    pub(crate) fn policy_transaction(&self) -> ObjectDigest {
        ObjectDigest::from_bytes(fixed(&self.0, 520))
    }

    pub(crate) fn policy_current(&self) -> ObjectDigest {
        ObjectDigest::from_bytes(fixed(&self.0, 552))
    }

    pub(crate) fn cache_quota(&self) -> ObjectDigest {
        ObjectDigest::from_bytes(fixed(&self.0, 584))
    }
}

/// Retains an exact historical publication observation, never a live grant.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct Q04RootDecisionV1([u8; DECISION_BYTES]);

impl Q04RootDecisionV1 {
    pub(crate) fn from_body(
        mut body: [u8; DECISION_BYTES],
        identity: &Q04CutIdentityV1,
    ) -> Result<Self, JournalError> {
        finish_record(&mut body, b"AOSQ4D01", None, DECISION_DOMAIN)?;
        Self::decode(&body, identity)
    }

    pub(crate) fn decode(
        bytes: &[u8],
        identity: &Q04CutIdentityV1,
    ) -> Result<Self, JournalError> {
        let bytes = checked_record::<DECISION_BYTES>(
            bytes,
            b"AOSQ4D01",
            None,
            DECISION_DOMAIN,
        )?;
        if bytes[16..48] != *identity.digest().as_bytes()
            || nonzero::<16>(&bytes, 48).is_err()
            || bytes[64..80] != identity.publication_id()
            || bytes[80..112] != *identity.policy_transaction().as_bytes()
            || read_u64(&bytes, 112)? == 0
            || bytes[120..152] != *identity.policy_current().as_bytes()
            || bytes[152..184] != *identity.binding().as_bytes()
            || bytes[184..216] != *identity.gate_identity().as_bytes()
            || nonzero::<32>(&bytes, 216).is_err()
            || nonzero::<32>(&bytes, 248).is_err()
            || bytes[280..312] != *identity.cache_quota().as_bytes()
            || read_u64(&bytes, 312)? == 0
            || bytes[320..352] != *identity.before_controller_rows().as_bytes()
        {
            return Err(JournalError::ProtectedBoundary);
        }
        Ok(Self(bytes))
    }

    pub(crate) fn bytes(&self) -> &[u8; DECISION_BYTES] {
        &self.0
    }

    pub(crate) fn digest(&self) -> ObjectDigest {
        ObjectDigest::from_bytes(Sha256::digest(self.bytes()).into())
    }

    pub(crate) fn authority_transaction_id(&self) -> [u8; 16] {
        fixed(&self.0, 48)
    }

    pub(crate) fn state_transaction_id(&self) -> [u8; 16] {
        fixed(&self.0, 64)
    }

    pub(crate) fn state_sequence(&self) -> u64 {
        u64::from_be_bytes(fixed(&self.0, 112))
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum Q04PhaseOwnerV1 {
    Controller,
    Root,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct Q04PhaseRecordV1 {
    owner: Q04PhaseOwnerV1,
    bytes: [u8; PHASE_BYTES],
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
        identity, 2, q04_capacity_shape_digest_v1(identity, 13)?,
    )?;
    let decision = root::root_decision_record(
        identity, earlier, state_next.checked_add(5).ok_or(CreateQ04ErrorV1::Bounds)?,
        authority_next, pairs[2], pairs[4],
    )?;
    let gate = root::root_consumed_gate_record(identity, &decision)?;
    let events = Q04ControllerPhaseEventsV1 {
        decision: decision.digest(), consumed_gate: gate.digest(),
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
    if phase == 0 || phase > 8 || (phase == 1) != prior.is_none()
        || prior.is_some_and(|prior| prior.owner() != Q04PhaseOwnerV1::Controller
            || prior.phase().checked_add(1) != Some(phase))
    {
        return Err(CreateQ04ErrorV1::ChangedCut);
    }
    let predecessor = prior.map(Q04PhaseRecordV1::digest);
    let transaction = Q04TransactionOwnerV1::Controller.transaction_id(
        identity, phase, predecessor.unwrap_or(identity.before_controller_rows()),
    )?;
    let mut body = [0; PHASE_BYTES];
    body[16..48].copy_from_slice(identity.digest().as_bytes());
    body[48..64].copy_from_slice(&identity.stage_id());
    if let Some(predecessor) = predecessor {
        body[64..96].copy_from_slice(predecessor.as_bytes());
    }
    let introduced = [2, 2, 5, 6, 7, 8];
    for (index, event) in [events.decision, events.consumed_gate, events.release,
        events.settlement, events.clearance, events.final_root].into_iter().enumerate()
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

impl Q04PhaseRecordV1 {
    pub(crate) fn from_body(
        owner: Q04PhaseOwnerV1,
        phase: u8,
        mut body: [u8; PHASE_BYTES],
        identity: &Q04CutIdentityV1,
    ) -> Result<Self, JournalError> {
        let (magic, domain) = match owner {
            Q04PhaseOwnerV1::Controller => (b"AOSQ4C01", CONTROLLER_PHASE_DOMAIN),
            Q04PhaseOwnerV1::Root => (b"AOSQ4R01", ROOT_PHASE_DOMAIN),
        };
        finish_record(&mut body, magic, Some(phase), domain)?;
        Self::decode(owner, &body, identity)
    }

    pub(crate) fn decode(
        owner: Q04PhaseOwnerV1,
        bytes: &[u8],
        identity: &Q04CutIdentityV1,
    ) -> Result<Self, JournalError> {
        let (magic, domain, last) = match owner {
            Q04PhaseOwnerV1::Controller => (b"AOSQ4C01", CONTROLLER_PHASE_DOMAIN, 8),
            Q04PhaseOwnerV1::Root => (b"AOSQ4R01", ROOT_PHASE_DOMAIN, 7),
        };
        let phase = *bytes.get(10).ok_or(JournalError::ProtectedBoundary)?;
        if phase == 0 || phase > last {
            return Err(JournalError::ProtectedBoundary);
        }
        let bytes = checked_record::<PHASE_BYTES>(bytes, magic, Some(phase), domain)?;
        if bytes[16..48] != *identity.digest().as_bytes()
            || bytes[48..64] != identity.stage_id()
            || nonzero::<16>(&bytes, 544).is_err()
            || nonzero::<32>(&bytes, 512).is_err()
        {
            return Err(JournalError::ProtectedBoundary);
        }
        require_phase_shape(owner, phase, &bytes)?;
        Ok(Self { owner, bytes })
    }

    pub(crate) fn bytes(&self) -> &[u8; PHASE_BYTES] {
        &self.bytes
    }

    pub(crate) fn owner(&self) -> Q04PhaseOwnerV1 {
        self.owner
    }

    pub(crate) fn phase(&self) -> u8 {
        self.bytes[10]
    }

    pub(crate) fn digest(&self) -> ObjectDigest {
        ObjectDigest::from_bytes(Sha256::digest(self.bytes).into())
    }

    pub(crate) fn native_transaction_id(&self) -> [u8; 16] {
        fixed(&self.bytes, 544)
    }

    pub(crate) fn acknowledgement(&self) -> ObjectDigest {
        ObjectDigest::from_bytes(fixed(&self.bytes, 480))
    }

    pub(crate) fn require_successor(&self, prior: &Self) -> Result<(), JournalError> {
        if self.owner != prior.owner
            || self.phase() != prior.phase() + 1
            || self.bytes[16..64] != prior.bytes[16..64]
            || self.bytes[64..96] != *prior.digest().as_bytes()
            || self.bytes[512..544] != prior.bytes[512..544]
        {
            return Err(JournalError::ProtectedBoundary);
        }
        // An introduced event remains immutable. A zero slot may be populated
        // only in the new phase's closed shape; the caller checks its real event.
        for offset in (96..480).step_by(32) {
            if self.owner == Q04PhaseOwnerV1::Root && prior.phase() == 5 && offset == 160 {
                // R5 carries its pre-write authorization recipe. R6 replaces
                // that one slot with the actually observed R5 record digest.
                if self.bytes[offset..offset + 32] != *prior.digest().as_bytes() {
                    return Err(JournalError::ProtectedBoundary);
                }
                continue;
            }
            if prior.bytes[offset..offset + 32] != [0; 32]
                && self.bytes[offset..offset + 32] != prior.bytes[offset..offset + 32]
            {
                return Err(JournalError::ProtectedBoundary);
            }
        }
        Ok(())
    }
}

// Slots after predecessor: decision, gate, release, settlement, clearance,
// final, three held/released pairs, acknowledgement and original-before recipe.
fn require_phase_shape(
    owner: Q04PhaseOwnerV1,
    phase: u8,
    bytes: &[u8; PHASE_BYTES],
) -> Result<(), JournalError> {
    let introduced = match owner {
        Q04PhaseOwnerV1::Controller => [2, 2, 5, 6, 7, 8],
        Q04PhaseOwnerV1::Root => [3, 4, 5, 7, 7, 0],
    };
    for (index, first) in introduced.into_iter().enumerate() {
        let offset = 96 + index * 32;
        require_presence(&bytes[offset..offset + 32], first != 0 && phase >= first)?;
    }

    let held_first = match owner {
        Q04PhaseOwnerV1::Controller => [1, 2, 2],
        Q04PhaseOwnerV1::Root => [1, 1, 1],
    };
    for (index, first) in held_first.into_iter().enumerate() {
        let held = 288 + index * 64;
        require_presence(&bytes[held..held + 32], phase >= first)?;
        require_presence(&bytes[held + 32..held + 64], phase >= match owner {
            Q04PhaseOwnerV1::Controller => 5,
            Q04PhaseOwnerV1::Root => 6,
        })?;
    }
    require_presence(&bytes[64..96], phase > 1)?;
    require_presence(&bytes[480..512], match owner {
        Q04PhaseOwnerV1::Controller => phase >= 3,
        Q04PhaseOwnerV1::Root => phase >= 4,
    })
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum Q04PendingOwnerV1 {
    Source,
    Cache,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct Q04PendingRecordV1 {
    owner: Q04PendingOwnerV1,
    bytes: [u8; PENDING_BYTES],
}

impl Q04PendingRecordV1 {
    pub(crate) fn from_body(
        owner: Q04PendingOwnerV1,
        phase: u8,
        mut body: [u8; PENDING_BYTES],
    ) -> Result<Self, JournalError> {
        let (magic, domain) = match owner {
            Q04PendingOwnerV1::Source => (b"AOSQ4S01", SOURCE_PENDING_DOMAIN),
            Q04PendingOwnerV1::Cache => (b"AOSQ4K01", CACHE_PENDING_DOMAIN),
        };
        finish_record(&mut body, magic, Some(phase), domain)?;
        Self::decode(owner, &body)
    }

    pub(crate) fn decode(
        owner: Q04PendingOwnerV1,
        bytes: &[u8],
    ) -> Result<Self, JournalError> {
        let (magic, domain) = match owner {
            Q04PendingOwnerV1::Source => (b"AOSQ4S01", SOURCE_PENDING_DOMAIN),
            Q04PendingOwnerV1::Cache => (b"AOSQ4K01", CACHE_PENDING_DOMAIN),
        };
        let phase = *bytes.get(10).ok_or(JournalError::ProtectedBoundary)?;
        if !matches!(phase, 1 | 2) {
            return Err(JournalError::ProtectedBoundary);
        }
        let bytes = checked_record::<PENDING_BYTES>(bytes, magic, Some(phase), domain)?;
        let fields = [(16, 32), (48, 16), (64, 32), (104, 32), (136, 32), (200, 32)];
        for (offset, width) in fields {
            require_presence(&bytes[offset..offset + width], true)?;
        }
        if read_u64(&bytes, 96)? == 0 {
            return Err(JournalError::ProtectedBoundary);
        }
        require_presence(&bytes[168..200], phase == 2)?;
        Ok(Self { owner, bytes })
    }

    pub(crate) fn bytes(&self) -> &[u8; PENDING_BYTES] {
        &self.bytes
    }

    pub(crate) fn is_held(&self) -> bool {
        self.bytes[10] == 1
    }

    /// Joins comparison bytes to the same finalized original cut.
    pub(crate) fn require_identity(&self, identity: &Q04CutIdentityV1) -> Result<(), JournalError> {
        if self.bytes[16..48] != *identity.digest().as_bytes()
            || self.bytes[48..64] != identity.nonce()
            || self.bytes[64..96] != *identity.binding().as_bytes()
            || self.bytes[96..104] != identity.epoch().to_be_bytes()
        {
            return Err(JournalError::ProtectedBoundary);
        }
        Ok(())
    }

    pub(crate) fn digest(&self) -> ObjectDigest {
        ObjectDigest::from_bytes(Sha256::digest(self.bytes()).into())
    }

    pub(crate) fn require_release_of(&self, held: &Self) -> Result<(), JournalError> {
        if self.owner != held.owner
            || self.is_held()
            || !held.is_held()
            || self.bytes[16..168] != held.bytes[16..168]
            || self.bytes[200..232] != held.bytes[200..232]
        {
            return Err(JournalError::ProtectedBoundary);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct Q04EffectSubgateV1([u8; GATE_BYTES]);

impl Q04EffectSubgateV1 {
    pub(crate) fn from_body(mut body: [u8; GATE_BYTES]) -> Result<Self, JournalError> {
        finish_record(&mut body, b"AOSQ4G01", None, GATE_DOMAIN)?;
        Self::decode(&body)
    }

    pub(crate) fn decode(bytes: &[u8]) -> Result<Self, JournalError> {
        let bytes = checked_record::<GATE_BYTES>(bytes, b"AOSQ4G01", None, GATE_DOMAIN)?;
        if !matches!(bytes[184], 1..=4)
            || bytes[185..192] != [0; 7]
            || read_u64(&bytes, 176)? != 1
        {
            return Err(JournalError::ProtectedBoundary);
        }
        let fields = [
            (16, 32), (48, 32), (80, 16), (96, 32),
            (128, 32), (160, 16), (224, 32),
        ];
        for (offset, width) in fields {
            require_presence(&bytes[offset..offset + width], true)?;
        }
        require_presence(&bytes[192..224], bytes[184] != 1)?;
        Ok(Self(bytes))
    }

    pub(crate) fn bytes(&self) -> &[u8; GATE_BYTES] {
        &self.0
    }

    pub(crate) fn status(&self) -> u8 {
        self.0[184]
    }

    // A nonauthorizing next-record recipe. The actual Controller transition
    // separately joins the named signed ACK and complete prior native/CAS cut.
    pub(crate) fn next_status_recipe(
        &self,
        acknowledgement: ObjectDigest,
    ) -> Result<Self, JournalError> {
        if self.status() >= 4 || acknowledgement.as_bytes() == &[0; 32] {
            return Err(JournalError::ProtectedBoundary);
        }
        let mut body = self.0;
        body[184] = self.status() + 1;
        body[192..224].copy_from_slice(acknowledgement.as_bytes());
        let next = Self::from_body(body)?;
        next.require_successor(self)?;
        Ok(next)
    }

    /// Hashes the complete canonical record, including its internal checksum.
    pub(crate) fn digest(&self) -> ObjectDigest {
        ObjectDigest::from_bytes(Sha256::digest(self.bytes()).into())
    }

    pub(crate) fn acknowledgement(&self) -> ObjectDigest {
        ObjectDigest::from_bytes(fixed(&self.0, 192))
    }

    pub(crate) fn require_identity(
        &self,
        identity: &Q04CutIdentityV1,
        decision: &Q04RootDecisionV1,
    ) -> Result<(), JournalError> {
        self.require_cut_identity(identity)?;
        if self.0[128..160] != *decision.digest().as_bytes() {
            return Err(JournalError::ProtectedBoundary);
        }
        Ok(())
    }

    pub(crate) fn require_cut_identity(
        &self,
        identity: &Q04CutIdentityV1,
    ) -> Result<(), JournalError> {
        if self.0[16..48] != *identity.digest().as_bytes()
            || self.0[48..80] != *identity.binding().as_bytes()
            || self.0[80..96] != identity.publication_id()
            || self.0[96..128] != *identity.policy_current().as_bytes()
            || self.0[160..176] != identity.stage_id()
            || self.0[176..184] != identity.accepted_generation().to_be_bytes()
            || self.0[224..256] != *identity.gen1_floor().as_bytes()
        {
            return Err(JournalError::ProtectedBoundary);
        }
        Ok(())
    }

    // Reconstructs only the canonical historical C2 comparison bytes. This
    // does not assert those bytes were committed or return a current gate.
    pub(crate) fn historical_consumed_record(&self) -> Result<Self, JournalError> {
        let mut body = self.0;
        body[184] = 1;
        body[192..224].fill(0);
        Self::from_body(body)
    }

    pub(crate) fn require_successor(&self, prior: &Self) -> Result<(), JournalError> {
        if self.status() != prior.status() + 1
            || self.0[..184] != prior.0[..184]
            || self.0[224..256] != prior.0[224..256]
        {
            return Err(JournalError::ProtectedBoundary);
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum Q04AcknowledgementKindV1 {
    Policy,
    Release,
    Settlement,
    Clearance,
}

impl Q04AcknowledgementKindV1 {
    fn body_bytes(self) -> usize {
        match self {
            Self::Policy | Self::Release => 344,
            Self::Settlement => 536,
            Self::Clearance => 664,
        }
    }

    fn phase(self) -> u8 {
        match self {
            Self::Policy => 1,
            Self::Release => 2,
            Self::Settlement => 3,
            Self::Clearance => 4,
        }
    }

    fn magic(self) -> &'static [u8; 8] {
        match self {
            Self::Policy => b"AOSQ4A01",
            Self::Release => b"AOSQ4E01",
            Self::Settlement => b"AOSQ4T01",
            Self::Clearance => b"AOSQ4F01",
        }
    }

    fn signature_domain(self) -> &'static [u8] {
        match self {
            Self::Policy => b"aos.sandbox.create-q04.policy-ack.signature.v1\0",
            Self::Release => b"aos.sandbox.create-q04.release-ack.signature.v1\0",
            Self::Settlement => b"aos.sandbox.create-q04.settlement-ack.signature.v1\0",
            Self::Clearance => b"aos.sandbox.create-q04.clearance-ack.signature.v1\0",
        }
    }
}

// One body recipe serves nonissuing capacity shapes and actual signed ACKs.
// The caller retains the output allocation before this fallible encoding and
// supplies actual current sequence/clear observations only on the live path.
pub(crate) fn encode_q04_acknowledgement_data_v1(
    output: &mut Vec<u8>,
    kind: Q04AcknowledgementKindV1,
    identity: &Q04CutIdentityV1,
    controller_sequence: u64,
    consumed_gate: ObjectDigest,
    pairs: [ObjectDigest; 6],
    clear_fields: Option<[ObjectDigest; 4]>,
) -> Result<(), CreateQ04ErrorV1> {
    if !output.is_empty() || (kind == Q04AcknowledgementKindV1::Clearance) != clear_fields.is_some() {
        return Err(CreateQ04ErrorV1::ChangedCut);
    }
    output.try_reserve_exact(kind.body_bytes() + 64)?;
    output.resize(kind.body_bytes(), 0);
    output[16..24].copy_from_slice(&identity.bytes()[88..96]);
    output[24..40].copy_from_slice(&identity.nonce());
    output[40..72].copy_from_slice(identity.digest().as_bytes());
    output[72..76].copy_from_slice(&identity.bytes()[80..84]);
    output[76..84].copy_from_slice(&controller_sequence.to_be_bytes());
    output[84..100].copy_from_slice(identity.operation().as_bytes());
    output[100..116].copy_from_slice(identity.sandbox().as_bytes());
    output[116..124].copy_from_slice(&identity.accepted_generation().to_be_bytes());
    output[128..160].copy_from_slice(identity.desired_precondition().as_bytes());
    output[160..192].copy_from_slice(identity.effect_plan_digest().as_bytes());
    output[192..224].copy_from_slice(identity.binding().as_bytes());
    output[224..232].copy_from_slice(&identity.epoch().to_be_bytes());
    output[232..248].copy_from_slice(&identity.publication_id());
    output[248..280].copy_from_slice(identity.policy_current().as_bytes());
    output[280..312].copy_from_slice(consumed_gate.as_bytes());
    output[312..344].copy_from_slice(identity.gen1_floor().as_bytes());
    if kind.body_bytes() >= 536 {
        for (index, pair) in pairs.into_iter().enumerate() {
            let start = 344 + index * 32;
            output[start..start + 32].copy_from_slice(pair.as_bytes());
        }
    }
    if let Some(fields) = clear_fields {
        for (index, field) in fields.into_iter().enumerate() {
            let start = 536 + index * 32;
            output[start..start + 32].copy_from_slice(field.as_bytes());
        }
    }
    finish_q04_acknowledgement_body_v1(kind, output, identity)
}

// Signature provenance over an original owned packet is comparison DATA.
// Actual current owners, fixed pins and phase/native joins remain separate.
pub(crate) struct Q04AcknowledgementV1<'packet> {
    kind: Q04AcknowledgementKindV1,
    bytes: &'packet [u8],
}

impl<'packet> Q04AcknowledgementV1<'packet> {
    pub(crate) fn verify(
        kind: Q04AcknowledgementKindV1,
        bytes: &'packet [u8],
        signer: &super::PinnedControllerHoldSignerV1,
        identity: &Q04CutIdentityV1,
    ) -> Result<Self, CreateQ04ErrorV1> {
        if bytes.len() != kind.body_bytes() + 64 {
            return Err(CreateQ04ErrorV1::Bounds);
        }
        let body = &bytes[..kind.body_bytes()];
        require_acknowledgement_body(kind, body, identity)?;
        if read_u64(body, 16)? != signer.generation() {
            return Err(CreateQ04ErrorV1::ChangedCut);
        }

        let signature = Signature::from_bytes(&fixed(bytes, kind.body_bytes()));
        signer.verifying_key().verify_strict(
            &acknowledgement_signature_preimage(kind, body)?,
            &signature,
        )?;
        Ok(Self { kind, bytes })
    }

    pub(crate) fn bytes(&self) -> &'packet [u8] {
        self.bytes
    }

    pub(crate) fn kind(&self) -> Q04AcknowledgementKindV1 {
        self.kind
    }

    pub(crate) fn digest(&self) -> ObjectDigest {
        ObjectDigest::from_bytes(Sha256::digest(self.bytes).into())
    }

    pub(crate) fn controller_sequence(&self) -> u64 {
        u64::from_be_bytes(fixed(self.bytes, 76))
    }
}

// The enclosing original owner already parks this exact body buffer. The
// helper borrows it through validation/allocation/signing, including failure;
// it does not consume a packet into a callee-local Result or mint live custody.
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

fn prepare_q04_acknowledgement_v1(
    kind: Q04AcknowledgementKindV1,
    body: &mut Vec<u8>,
    identity: &Q04CutIdentityV1,
) -> Result<Vec<u8>, CreateQ04ErrorV1> {
    finish_q04_acknowledgement_body_v1(kind, body, identity)?;

    let preimage = acknowledgement_signature_preimage(kind, body)?;
    body.try_reserve_exact(64)?;
    Ok(preimage)
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

// The caller retains this named preimage through the append, as before.
// Capacity and every fallible preparation step have already completed.
fn append_q04_signature(body: &mut Vec<u8>, key: &SigningKey, preimage: &[u8]) {
    let signature = key.sign(preimage);
    body.extend_from_slice(&signature.to_bytes());
}

// The same body/header checks may advise fixed-width future capacity DATA.
// Only the real signer above appends an authentic signature; body formation
// does not produce an acknowledgement, permission or positive observation.
pub(super) fn finish_q04_acknowledgement_body_v1(
    kind: Q04AcknowledgementKindV1,
    body: &mut Vec<u8>,
    identity: &Q04CutIdentityV1,
) -> Result<(), CreateQ04ErrorV1> {
    if body.len() != kind.body_bytes() {
        return Err(CreateQ04ErrorV1::Bounds);
    }
    body[..8].copy_from_slice(kind.magic());
    body[8..10].copy_from_slice(&1_u16.to_be_bytes());
    body[10] = kind.phase();
    body[11..16].fill(0);
    require_acknowledgement_body(kind, body, identity)?;

    Ok(())
}

fn require_acknowledgement_body(
    kind: Q04AcknowledgementKindV1,
    body: &[u8],
    identity: &Q04CutIdentityV1,
) -> Result<(), CreateQ04ErrorV1> {
    if body.len() != kind.body_bytes()
        || body[..8] != *kind.magic()
        || body[8..10] != 1_u16.to_be_bytes()
        || body[10] != kind.phase()
        || body[11..16] != [0; 5]
        || body[16..24] != identity.bytes()[88..96]
        || body[24..40] != identity.nonce()
        || body[40..72] != *identity.digest().as_bytes()
        || body[72..76] != identity.bytes()[80..84]
        || read_u64(body, 76)? == 0
        || body[84..100] != *identity.operation().as_bytes()
        || body[100..116] != *identity.sandbox().as_bytes()
        || body[116..124] != identity.accepted_generation().to_be_bytes()
        || body[124..128] != [0; 4]
        || body[128..160] != identity.bytes()[232..264]
        || body[160..192] != identity.bytes()[264..296]
        || body[192..224] != *identity.binding().as_bytes()
        || body[224..232] != identity.epoch().to_be_bytes()
        || body[232..248] != identity.publication_id()
        || body[248..280] != *identity.policy_current().as_bytes()
        || nonzero::<32>(body, 280).is_err()
        || body[312..344] != *identity.gen1_floor().as_bytes()
    {
        return Err(CreateQ04ErrorV1::ChangedCut);
    }

    if matches!(kind, Q04AcknowledgementKindV1::Settlement | Q04AcknowledgementKindV1::Clearance) {
        for offset in (344..536).step_by(32) {
            nonzero::<32>(body, offset)?;
        }
    }
    if kind == Q04AcknowledgementKindV1::Clearance {
        for offset in (536..664).step_by(32) {
            nonzero::<32>(body, offset)?;
        }
    }
    Ok(())
}

fn acknowledgement_signature_preimage(
    kind: Q04AcknowledgementKindV1,
    body: &[u8],
) -> Result<Vec<u8>, CreateQ04ErrorV1> {
    signed_record_preimage(kind.signature_domain(), body)
}

fn signed_record_preimage(
    domain: &[u8],
    body: &[u8],
) -> Result<Vec<u8>, CreateQ04ErrorV1> {
    let size = domain.len()
        .checked_add(body.len())
        .ok_or(CreateQ04ErrorV1::Bounds)?;
    let mut preimage = Vec::new();
    preimage.try_reserve_exact(size)?;
    preimage.extend_from_slice(domain);
    preimage.extend_from_slice(body);
    Ok(preimage)
}

// The view borrows the actual parked complete packet. Neither decode nor
// signature verification owns the writers, supplies currentness or admits a
// project. Root's same-flight consumer repeats those independent joins.
pub(crate) struct Q04ClaimV1<'packet> {
    bytes: &'packet [u8],
    fields: [&'packet [u8]; CLAIM_FIELDS],
}

impl<'packet> Q04ClaimV1<'packet> {
    pub(crate) fn decode(
        bytes: &'packet [u8],
        identity: &Q04CutIdentityV1,
    ) -> Result<Self, CreateQ04ErrorV1> {
        if bytes.len() < CLAIM_PREFIX_BYTES + 64 || bytes.len() > MAXIMUM_CLAIM_BYTES {
            return Err(CreateQ04ErrorV1::Bounds);
        }
        let fields = claim_body_fields(&bytes[..bytes.len() - 64], identity)?;
        Ok(Self { bytes, fields })
    }

    pub(crate) fn verify(
        bytes: &'packet [u8],
        signer: &super::PinnedControllerHoldSignerV1,
        identity: &Q04CutIdentityV1,
    ) -> Result<Self, CreateQ04ErrorV1> {
        let claim = Self::decode(bytes, identity)?;
        if identity.bytes()[88..96] != signer.generation().to_be_bytes() {
            return Err(CreateQ04ErrorV1::ChangedCut);
        }
        let signature_offset = bytes.len() - 64;
        let signature = Signature::from_bytes(&fixed(bytes, signature_offset));
        signer.verifying_key().verify_strict(
            &signed_record_preimage(CLAIM_SIGNATURE_DOMAIN, &bytes[..signature_offset])?,
            &signature,
        ).map_err(CreateQ04ErrorV1::ClaimSignature)?;
        Ok(claim)
    }

    pub(crate) fn fields(&self) -> &[&'packet [u8]; CLAIM_FIELDS] {
        &self.fields
    }

    pub(crate) fn bytes(&self) -> &'packet [u8] {
        self.bytes
    }
}

// The caller parks this buffer before the first allocation. Only unsigned
// DATA is constructed here; each existing field codec remains responsible
// for its canonical format and independently authenticated semantic checks.
pub(crate) fn encode_q04_claim_body_v1(
    body: &mut Vec<u8>,
    fields: [&[u8]; CLAIM_FIELDS],
    identity: &Q04CutIdentityV1,
) -> Result<(), CreateQ04ErrorV1> {
    if !body.is_empty() {
        return Err(CreateQ04ErrorV1::ChangedCut);
    }
    require_claim_field_bounds(&fields, identity)?;
    encode_length_prefixed_fields(body, b"AOSQ4L01", fields, MAXIMUM_CLAIM_BYTES - 64)?;
    claim_body_fields(body, identity)?;
    Ok(())
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

fn prepare_q04_claim_v1(
    body: &mut Vec<u8>,
    identity: &Q04CutIdentityV1,
) -> Result<Vec<u8>, CreateQ04ErrorV1> {
    claim_body_fields(body, identity)?;
    let preimage = signed_record_preimage(CLAIM_SIGNATURE_DOMAIN, body)?;
    body.try_reserve_exact(64)?;
    Ok(preimage)
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

fn claim_body_fields<'body>(
    body: &'body [u8],
    identity: &Q04CutIdentityV1,
) -> Result<[&'body [u8]; CLAIM_FIELDS], CreateQ04ErrorV1> {
    if body.len() < CLAIM_PREFIX_BYTES
        || body.len().checked_add(64).is_none_or(|size| size > MAXIMUM_CLAIM_BYTES)
        || body[..8] != *b"AOSQ4L01"
        || body[8..10] != 1_u16.to_be_bytes()
        || body[10..16] != [0; 6]
    {
        return Err(CreateQ04ErrorV1::Bounds);
    }

    let fields = decode_length_prefixed_fields(body)?;
    require_claim_field_bounds(&fields, identity)?;
    Ok(fields)
}

fn require_claim_field_bounds(
    fields: &[&[u8]; CLAIM_FIELDS],
    identity: &Q04CutIdentityV1,
) -> Result<(), CreateQ04ErrorV1> {
    if fields.iter().any(|field| field.is_empty())
        || fields[..7].iter().any(|field| field.len() > 64 * 1024)
        || fields[7].len() > 3 * 1024
        || fields[8].len() != super::CLOSED_POLICY_BINDING_BYTES_V2
        || fields[9].len() != super::CONTROLLER_PROJECT_ADMISSION_READBACK_BYTES_V1
        || fields[10].len() != super::CLOSED_CONTROLLER_HOLD_READBACK_BYTES_V1
        || !matches!(fields[11].len(), super::SOURCE_TREE_GENESIS_READBACK_BYTES_V1 | super::SOURCE_TREE_GENESIS_READBACK_BYTES_V2)
        || fields[12].len() != crate::cache_residency::CLOSED_CACHE_OWNER_READBACK_BYTES_V2
        || fields[13] != identity.bytes()
    {
        return Err(CreateQ04ErrorV1::ChangedCut);
    }
    Ok(())
}

// This recipe borrows the same complete parked Claim. It owns only the fixed
// index DATA; it cannot replace native membership, signature or currentness.
pub(crate) struct Q04ClaimStorageRecipeV1<'packet> {
    claim: &'packet [u8],
    index: [u8; CLAIM_INDEX_BYTES],
}

impl<'packet> Q04ClaimStorageRecipeV1<'packet> {
    pub(crate) fn new(
        claim: &Q04ClaimV1<'packet>,
        identity: &Q04CutIdentityV1,
    ) -> Result<Self, CreateQ04ErrorV1> {
        if claim.fields()[13] != identity.bytes() {
            return Err(CreateQ04ErrorV1::ChangedCut);
        }
        let count = claim_chunk_count(claim.bytes().len())?;
        let total = u32::try_from(claim.bytes().len()).map_err(|_| CreateQ04ErrorV1::Bounds)?;

        let mut index = [0; CLAIM_INDEX_BYTES];
        index[..8].copy_from_slice(b"AOSQ4X01");
        index[8..10].copy_from_slice(&1_u16.to_be_bytes());
        index[16..48].copy_from_slice(identity.digest().as_bytes());
        index[48..52].copy_from_slice(&total.to_be_bytes());
        index[52..54].copy_from_slice(&count.to_be_bytes());
        let digest = Sha256::new()
            .chain_update(CLAIM_INDEX_DOMAIN)
            .chain_update(&index[..64])
            .chain_update(claim.bytes())
            .finalize();
        index[64..96].copy_from_slice(&digest);
        Ok(Self { claim: claim.bytes(), index })
    }

    // There is intentionally no header-only digest verification. The
    // comparison includes every byte of the reconstructed signed Claim.
    pub(crate) fn verify_index(
        bytes: &[u8],
        claim: &Q04ClaimV1<'packet>,
        identity: &Q04CutIdentityV1,
    ) -> Result<Self, CreateQ04ErrorV1> {
        let recipe = Self::new(claim, identity)?;
        if bytes != recipe.index.as_slice() {
            return Err(CreateQ04ErrorV1::ChangedCut);
        }
        Ok(recipe)
    }

    pub(crate) fn index_bytes(&self) -> &[u8; CLAIM_INDEX_BYTES] {
        &self.index
    }

    pub(crate) fn chunk_count(&self) -> u16 {
        u16::from_be_bytes(fixed(&self.index, 52))
    }

    // The caller parks the output before this first possible allocation. All
    // chunk fields derive from the one immutable original packet, not a second
    // copy, callback or caller-supplied digest/count.
    pub(crate) fn encode_chunk(
        &self,
        chunk: u16,
        output: &mut Vec<u8>,
    ) -> Result<(), CreateQ04ErrorV1> {
        if !output.is_empty() {
            return Err(CreateQ04ErrorV1::ChangedCut);
        }
        Q04ChunkPurposeV1::Claim.encode_chunk(
            self.claim, fixed(&self.index, 16), chunk, output,
        )
    }
}

pub(crate) struct Q04ClaimChunkV1<'chunk> {
    chunk: Q04OrderedChunkV1<'chunk>,
}

impl<'chunk> Q04ClaimChunkV1<'chunk> {
    pub(crate) fn decode(
        bytes: &'chunk [u8],
        original_index: &[u8],
        identity: &Q04CutIdentityV1,
    ) -> Result<Self, CreateQ04ErrorV1> {
        let (indexed_total, indexed_count) = claim_index_shape(original_index, identity)?;
        let chunk = Q04ChunkPurposeV1::Claim.decode_chunk(
            bytes, *identity.digest().as_bytes(), indexed_total, indexed_count,
        )?;
        Ok(Self { chunk })
    }

    // Original chunk order and exact offsets are checked before growing the
    // caller-owned reconstruction. Complete index/signature checks follow.
    pub(crate) fn append_to(&self, output: &mut Vec<u8>) -> Result<(), CreateQ04ErrorV1> {
        self.chunk.append_to(output)
    }
}

// Reading the fixed index's shape only bounds reconstruction. Its final
// digest is deliberately not verified until the complete Claim is present.
fn claim_index_shape(
    bytes: &[u8],
    identity: &Q04CutIdentityV1,
) -> Result<(usize, u16), CreateQ04ErrorV1> {
    if bytes.len() != CLAIM_INDEX_BYTES
        || bytes[..8] != *b"AOSQ4X01"
        || bytes[8..10] != 1_u16.to_be_bytes()
        || bytes[10..16] != [0; 6]
        || bytes[16..48] != *identity.digest().as_bytes()
        || bytes[54..64] != [0; 10]
    {
        return Err(CreateQ04ErrorV1::Bounds);
    }
    let total = usize::try_from(read_u32(bytes, 48)?).map_err(|_| CreateQ04ErrorV1::Bounds)?;
    let count = u16::from_be_bytes(fixed(bytes, 52));
    if count != claim_chunk_count(total)? {
        return Err(CreateQ04ErrorV1::Bounds);
    }
    Ok((total, count))
}

fn claim_chunk_count(total: usize) -> Result<u16, CreateQ04ErrorV1> {
    chunk_count(total, MAXIMUM_CLAIM_BYTES)
}

fn chunk_count(total: usize, maximum: usize) -> Result<u16, CreateQ04ErrorV1> {
    if total == 0 || total > maximum {
        return Err(CreateQ04ErrorV1::Bounds);
    }
    let count = total.checked_add(CLAIM_CHUNK_BYTES - 1)
        .ok_or(CreateQ04ErrorV1::Bounds)? / CLAIM_CHUNK_BYTES;
    u16::try_from(count).map_err(|_| CreateQ04ErrorV1::Bounds)
}

fn chunk_range(
    total: usize,
    index: u16,
    count: u16,
    maximum: usize,
) -> Result<std::ops::Range<usize>, CreateQ04ErrorV1> {
    if count != chunk_count(total, maximum)? || index >= count {
        return Err(CreateQ04ErrorV1::Bounds);
    }
    let start = usize::from(index).checked_mul(CLAIM_CHUNK_BYTES)
        .ok_or(CreateQ04ErrorV1::Bounds)?;
    let end = start.checked_add(CLAIM_CHUNK_BYTES)
        .ok_or(CreateQ04ErrorV1::Bounds)?.min(total);
    Ok(start..end)
}

// Both transfers share coordinates, bounds and ordered reconstruction. The
// purpose selects its own canonical bytes/domain; Preview never needs a fake
// Cut or a Claim index to reuse this engine.
#[derive(Clone, Copy)]
enum Q04ChunkPurposeV1 {
    Claim,
    Preview,
    Prehold,
}

impl Q04ChunkPurposeV1 {
    fn magic(self) -> &'static [u8; 8] {
        match self {
            Self::Claim => b"AOSQ4B01",
            Self::Preview => b"AOSQ4U01",
            Self::Prehold => b"AOSQ4M01",
        }
    }

    fn maximum(self) -> usize {
        match self {
            Self::Claim => MAXIMUM_CLAIM_BYTES,
            Self::Preview => MAXIMUM_PREVIEW_BYTES,
            Self::Prehold => MAXIMUM_PREHOLD_BYTES,
        }
    }

    fn chunk_digest(self, header: &[u8], payload: &[u8]) -> [u8; 32] {
        let (domain, start): (&[u8], usize) = match self {
            Self::Claim => (CLAIM_CHUNK_DOMAIN, 16),
            Self::Preview => (PREVIEW_CHUNK_DOMAIN, 0),
            Self::Prehold => (PREHOLD_CHUNK_DOMAIN, 0),
        };
        Sha256::new()
            .chain_update(domain)
            .chain_update(&header[start..56])
            .chain_update(payload)
            .finalize()
            .into()
    }

    fn encode_chunk(
        self,
        original: &[u8],
        comparison_digest: [u8; 32],
        index: u16,
        output: &mut Vec<u8>,
    ) -> Result<(), CreateQ04ErrorV1> {
        if !output.is_empty() || comparison_digest == [0; 32] {
            return Err(CreateQ04ErrorV1::ChangedCut);
        }
        let count = chunk_count(original.len(), self.maximum())?;
        let range = chunk_range(original.len(), index, count, self.maximum())?;
        let payload = &original[range];
        let total = u32::try_from(original.len()).map_err(|_| CreateQ04ErrorV1::Bounds)?;

        let mut header = [0; CLAIM_CHUNK_PREFIX_BYTES];
        header[..8].copy_from_slice(self.magic());
        header[8..10].copy_from_slice(&1_u16.to_be_bytes());
        header[16..48].copy_from_slice(&comparison_digest);
        header[48..50].copy_from_slice(&index.to_be_bytes());
        header[50..52].copy_from_slice(&count.to_be_bytes());
        header[52..56].copy_from_slice(&total.to_be_bytes());
        let digest = self.chunk_digest(&header, payload);
        header[56..88].copy_from_slice(&digest);

        output.try_reserve_exact(CLAIM_CHUNK_PREFIX_BYTES + payload.len())?;
        output.extend_from_slice(&header);
        output.extend_from_slice(payload);
        Ok(())
    }

    fn decode_chunk<'chunk>(
        self,
        bytes: &'chunk [u8],
        comparison_digest: [u8; 32],
        indexed_total: usize,
        indexed_count: u16,
    ) -> Result<Q04OrderedChunkV1<'chunk>, CreateQ04ErrorV1> {
        if bytes.len() < CLAIM_CHUNK_PREFIX_BYTES
            || bytes.len() > CLAIM_CHUNK_PREFIX_BYTES + CLAIM_CHUNK_BYTES
            || bytes[..8] != *self.magic()
            || bytes[8..10] != 1_u16.to_be_bytes()
            || bytes[10..16] != [0; 6]
            || comparison_digest == [0; 32]
            || bytes[16..48] != comparison_digest
            || bytes[88..96] != [0; 8]
        {
            return Err(CreateQ04ErrorV1::Bounds);
        }

        let index = u16::from_be_bytes(fixed(bytes, 48));
        let count = u16::from_be_bytes(fixed(bytes, 50));
        let total = usize::try_from(read_u32(bytes, 52)?)
            .map_err(|_| CreateQ04ErrorV1::Bounds)?;
        let range = chunk_range(total, index, count, self.maximum())?;
        let payload = &bytes[CLAIM_CHUNK_PREFIX_BYTES..];
        if count != indexed_count
            || total != indexed_total
            || payload.len() != range.len()
            || bytes[56..88] != self.chunk_digest(bytes, payload)
        {
            return Err(CreateQ04ErrorV1::ChangedCut);
        }

        Ok(Q04OrderedChunkV1 { index, payload, maximum: self.maximum() })
    }
}

struct Q04OrderedChunkV1<'chunk> {
    index: u16,
    payload: &'chunk [u8],
    maximum: usize,
}

impl Q04OrderedChunkV1<'_> {
    fn append_to(&self, output: &mut Vec<u8>) -> Result<(), CreateQ04ErrorV1> {
        let offset = usize::from(self.index)
            .checked_mul(CLAIM_CHUNK_BYTES)
            .ok_or(CreateQ04ErrorV1::Bounds)?;
        if output.len() != offset
            || output.len().checked_add(self.payload.len())
                .is_none_or(|size| size > self.maximum)
        {
            return Err(CreateQ04ErrorV1::ChangedCut);
        }
        output.try_reserve_exact(self.payload.len())?;
        output.extend_from_slice(self.payload);
        Ok(())
    }
}

// The Preview borrows only a complete original transfer. All source fields
// remain untrusted DATA until the independent pins, same original Root peer,
// completed gen1 cut and actual held owners have each been rechecked.
pub(crate) struct Q04PreviewV1<'preview> {
    bytes: &'preview [u8],
    fields: [&'preview [u8]; PREVIEW_FIELDS],
}

impl<'preview> Q04PreviewV1<'preview> {
    pub(crate) fn decode(
        bytes: &'preview [u8],
        original_nonce: [u8; 16],
    ) -> Result<Self, CreateQ04ErrorV1> {
        if bytes.len() < PREVIEW_PREFIX_BYTES
            || bytes.len() > MAXIMUM_PREVIEW_BYTES
            || bytes[..8] != *b"AOSQ4V01"
            || bytes[8..10] != 1_u16.to_be_bytes()
            || bytes[10..16] != [0; 6]
        {
            return Err(CreateQ04ErrorV1::Bounds);
        }
        let fields = decode_length_prefixed_fields(bytes)?;
        require_preview_fields(&fields, original_nonce)?;
        Ok(Self { bytes, fields })
    }

    pub(crate) fn fields(&self) -> &[&'preview [u8]; PREVIEW_FIELDS] {
        &self.fields
    }

    pub(crate) fn bytes(&self) -> &'preview [u8] {
        self.bytes
    }

    pub(crate) fn staged(&self) -> Result<super::StagedClosedPolicyRootBaseV2, CreateQ04ErrorV1> {
        preview_stage(self.fields[1])
    }
}

pub(crate) fn encode_q04_preview_body_v1(
    output: &mut Vec<u8>,
    fields: [&[u8]; PREVIEW_FIELDS],
    original_nonce: [u8; 16],
) -> Result<(), CreateQ04ErrorV1> {
    if !output.is_empty() {
        return Err(CreateQ04ErrorV1::ChangedCut);
    }
    require_preview_fields(&fields, original_nonce)?;
    encode_length_prefixed_fields(output, b"AOSQ4V01", fields, MAXIMUM_PREVIEW_BYTES)?;
    Q04PreviewV1::decode(output, original_nonce)?;
    Ok(())
}

fn require_preview_fields(
    fields: &[&[u8]; PREVIEW_FIELDS],
    original_nonce: [u8; 16],
) -> Result<(), CreateQ04ErrorV1> {
    if fields[0].len() != 120
        || fields[1].len() != 128
        || fields[2].len() != 224
        || fields[3..7].iter().any(|field| field.is_empty() || field.len() > 64 * 1024)
        || fields[7].len() != 328
        || fields[8].is_empty()
        || fields[8].len() > 3 * 1024
        || original_nonce == [0; 16]
    {
        return Err(CreateQ04ErrorV1::Bounds);
    }
    let metadata = fields[0];
    if nonzero::<16>(metadata, 0).is_err()
        || read_u64(metadata, 24)?.checked_sub(read_u64(metadata, 16)?) != Some(65_000_000_000)
        || read_u64(metadata, 32)? == 0
        || nonzero::<32>(metadata, 88).is_err()
    {
        return Err(CreateQ04ErrorV1::ChangedCut);
    }
    crate::journal::ProtectedJournalNamesV1::from_bytes(&metadata[40..88]).map_err(crate::journal::JournalError::from)?;
    let staged = preview_stage(fields[1])?;
    if staged.challenge() != original_nonce || nonzero::<32>(fields[1], 96).is_err() {
        return Err(CreateQ04ErrorV1::ChangedCut);
    }
    Ok(())
}

fn preview_stage(bytes: &[u8]) -> Result<super::StagedClosedPolicyRootBaseV2, CreateQ04ErrorV1> {
    if bytes.len() != 128 {
        return Err(CreateQ04ErrorV1::Bounds);
    }
    let base = super::ClosedPolicyRootCasBaseV2::from_untrusted_remote_fields(
        fixed(bytes, 0), ObjectDigest::from_bytes(fixed(bytes, 16)),
        read_u64(bytes, 48)?, read_u64(bytes, 56)?, read_u64(bytes, 64)?,
    )?;
    Ok(super::StagedClosedPolicyRootBaseV2::from_untrusted_remote_fields(
        base, fixed(bytes, 72), read_u64(bytes, 88)?,
    )?)
}

// The retained packet and transfer index stay in the enclosing invocation.
// Shape bounds permit reconstruction; complete-domain comparison happens
// only after all original chunks have arrived in their exact order.
pub(crate) struct Q04PreviewTransferRecipeV1<'preview> {
    preview: &'preview [u8],
    index: [u8; PREVIEW_INDEX_BYTES],
}

impl<'preview> Q04PreviewTransferRecipeV1<'preview> {
    pub(crate) fn new(preview: &Q04PreviewV1<'preview>) -> Result<Self, CreateQ04ErrorV1> {
        let index = bounded_input_transfer_index(preview.bytes, PREVIEW_DOMAIN, MAXIMUM_PREVIEW_BYTES)?;
        Ok(Self { preview: preview.bytes, index })
    }

    pub(crate) fn verify_index(
        original_index: &[u8],
        preview: &Q04PreviewV1<'preview>,
    ) -> Result<Self, CreateQ04ErrorV1> {
        let recipe = Self::new(preview)?;
        if original_index != recipe.index.as_slice() {
            return Err(CreateQ04ErrorV1::ChangedCut);
        }
        Ok(recipe)
    }

    pub(crate) fn index_bytes(&self) -> &[u8; PREVIEW_INDEX_BYTES] {
        &self.index
    }

    pub(crate) fn chunk_count(&self) -> u16 {
        u16::from_be_bytes(fixed(&self.index, 36))
    }

    pub(crate) fn encode_chunk(
        &self,
        index: u16,
        output: &mut Vec<u8>,
    ) -> Result<(), CreateQ04ErrorV1> {
        Q04ChunkPurposeV1::Preview.encode_chunk(self.preview, fixed(&self.index, 0), index, output)
    }
}

pub(crate) struct Q04PreviewChunkV1<'chunk> {
    chunk: Q04OrderedChunkV1<'chunk>,
}

impl<'chunk> Q04PreviewChunkV1<'chunk> {
    pub(crate) fn decode(
        bytes: &'chunk [u8],
        original_index: &[u8],
    ) -> Result<Self, CreateQ04ErrorV1> {
        let (total, count) = preview_index_shape(original_index)?;
        let chunk = Q04ChunkPurposeV1::Preview.decode_chunk(
            bytes, fixed(original_index, 0), total, count,
        )?;
        Ok(Self { chunk })
    }

    pub(crate) fn append_to(&self, output: &mut Vec<u8>) -> Result<(), CreateQ04ErrorV1> {
        self.chunk.append_to(output)
    }
}

pub(crate) fn preview_index_shape(bytes: &[u8]) -> Result<(usize, u16), CreateQ04ErrorV1> {
    bounded_input_transfer_shape(bytes, PREVIEW_PREFIX_BYTES, MAXIMUM_PREVIEW_BYTES)
}

// Preview and prehold share the same fixed index coordinates and strict
// reconstruction bounds. Their complete-packet domains remain distinct.
fn bounded_input_transfer_index(
    original: &[u8],
    domain: &[u8],
    maximum: usize,
) -> Result<[u8; PREVIEW_INDEX_BYTES], CreateQ04ErrorV1> {
    let count = chunk_count(original.len(), maximum)?;
    let total = u32::try_from(original.len()).map_err(|_| CreateQ04ErrorV1::Bounds)?;
    let digest = Sha256::new().chain_update(domain).chain_update(original).finalize();
    let mut index = [0; PREVIEW_INDEX_BYTES];
    index[..32].copy_from_slice(&digest);
    index[32..36].copy_from_slice(&total.to_be_bytes());
    index[36..38].copy_from_slice(&count.to_be_bytes());
    Ok(index)
}

fn bounded_input_transfer_shape(
    bytes: &[u8],
    minimum: usize,
    maximum: usize,
) -> Result<(usize, u16), CreateQ04ErrorV1> {
    if bytes.len() != PREVIEW_INDEX_BYTES
        || bytes[38..48] != [0; 10]
        || nonzero::<32>(bytes, 0).is_err()
    {
        return Err(CreateQ04ErrorV1::Bounds);
    }
    let total = usize::try_from(read_u32(bytes, 32)?).map_err(|_| CreateQ04ErrorV1::Bounds)?;
    let count = u16::from_be_bytes(fixed(bytes, 36));
    if total < minimum || count != chunk_count(total, maximum)? {
        return Err(CreateQ04ErrorV1::Bounds);
    }
    Ok((total, count))
}

// This packet authenticates original comparison DATA only. Neither its
// signature nor its capacity reply supplies currentness, a logical hold or a
// publication permit. The same original owners remain independently required.
pub(crate) struct Q04PreholdInputDataV1<'packet> {
    bytes: &'packet [u8],
    fields: [&'packet [u8]; PREHOLD_FIELDS],
}

impl<'packet> Q04PreholdInputDataV1<'packet> {
    pub(crate) fn decode(bytes: &'packet [u8]) -> Result<Self, CreateQ04ErrorV1> {
        if bytes.len() < PREHOLD_PREFIX_BYTES + 64 || bytes.len() > MAXIMUM_PREHOLD_BYTES {
            return Err(CreateQ04ErrorV1::Bounds);
        }
        let fields = prehold_body_fields(&bytes[..bytes.len() - 64])?;
        Ok(Self { bytes, fields })
    }

    pub(crate) fn verify(
        bytes: &'packet [u8],
        signer: &super::PinnedControllerHoldSignerV1,
    ) -> Result<Self, CreateQ04ErrorV1> {
        let request = Self::decode(bytes)?;
        if read_u64(request.fields[0], 32)? != signer.generation() {
            return Err(CreateQ04ErrorV1::ChangedCut);
        }
        let signature_offset = bytes.len() - 64;
        let signature = Signature::from_bytes(&fixed(bytes, signature_offset));
        signer.verifying_key().verify_strict(
            &signed_record_preimage(PREHOLD_SIGNATURE_DOMAIN, &bytes[..signature_offset])?,
            &signature,
        ).map_err(CreateQ04ErrorV1::PreholdSignature)?;
        Ok(request)
    }

    pub(crate) fn fields(&self) -> &[&'packet [u8]; PREHOLD_FIELDS] {
        &self.fields
    }

    pub(crate) fn bytes(&self) -> &'packet [u8] {
        self.bytes
    }

    pub(crate) fn digest(&self) -> ObjectDigest {
        ObjectDigest::from_bytes(Sha256::new()
            .chain_update(PREHOLD_REQUEST_DOMAIN)
            .chain_update(self.bytes)
            .finalize().into())
    }
}

pub(crate) fn encode_q04_prehold_body_v1(
    output: &mut Vec<u8>,
    fields: [&[u8]; PREHOLD_FIELDS],
) -> Result<(), CreateQ04ErrorV1> {
    if !output.is_empty() {
        return Err(CreateQ04ErrorV1::ChangedCut);
    }
    require_prehold_fields(&fields)?;
    encode_length_prefixed_fields(output, b"AOSQ4N01", fields, MAXIMUM_PREHOLD_BYTES - 64)?;
    prehold_body_fields(output)?;
    Ok(())
}

// Only the genuine private Controller donor invokes this DATA serializer.
// The actual buffer is resident before allocation/signing; all original
// ledger/current-source/name/clock bookends remain in that donor and caller.
#[cfg(test)]
pub(super) fn sign_q04_prehold_body_v1(
    output: &mut Vec<u8>,
    key: &SigningKey,
) -> Result<(), CreateQ04ErrorV1> {
    let preimage = prepare_q04_prehold_body_v1(output)?;
    append_q04_signature(output, key, &preimage);
    Ok(())
}

fn prepare_q04_prehold_body_v1(
    output: &mut Vec<u8>,
) -> Result<Vec<u8>, CreateQ04ErrorV1> {
    prehold_body_fields(output)?;
    let preimage = signed_record_preimage(PREHOLD_SIGNATURE_DOMAIN, output)?;
    output.try_reserve_exact(64)?;
    Ok(preimage)
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

fn prehold_body_fields(body: &[u8]) -> Result<[&[u8]; PREHOLD_FIELDS], CreateQ04ErrorV1> {
    if body.len() < PREHOLD_PREFIX_BYTES
        || body.len().checked_add(64).is_none_or(|size| size > MAXIMUM_PREHOLD_BYTES)
        || body[..8] != *b"AOSQ4N01"
        || body[8..10] != 1_u16.to_be_bytes()
        || body[10..16] != [0; 6]
    {
        return Err(CreateQ04ErrorV1::Bounds);
    }
    let fields = decode_length_prefixed_fields(body)?;
    require_prehold_fields(&fields)?;
    Ok(fields)
}

fn require_prehold_fields(fields: &[&[u8]; PREHOLD_FIELDS]) -> Result<(), CreateQ04ErrorV1> {
    if fields[0].len() != PREHOLD_METADATA_BYTES
        || fields[1..4].iter().any(|field| field.is_empty() || field.len() > 64 * 1024)
        || fields[4].len() != super::CLOSED_POLICY_BINDING_BYTES_V2
        || fields[5].len() != super::CONTROLLER_PROJECT_ADMISSION_READBACK_BYTES_V1
    {
        return Err(CreateQ04ErrorV1::Bounds);
    }
    let metadata = fields[0];
    if nonzero::<16>(metadata, 0).is_err()
        || read_u64(metadata, 24)?.checked_sub(read_u64(metadata, 16)?) != Some(60_000_000_000)
        || read_u64(metadata, 32)? == 0
        || read_u64(metadata, 40)? != 1
        || (48..176).step_by(32).any(|offset| nonzero::<32>(metadata, offset).is_err())
        || (464..512).step_by(8).any(|offset| read_u64(metadata, offset).map_or(true, |value| value == 0))
    {
        return Err(CreateQ04ErrorV1::ChangedCut);
    }
    for offset in (176..464).step_by(48) {
        crate::journal::ProtectedJournalNamesV1::from_bytes(&metadata[offset..offset + 48]).map_err(crate::journal::JournalError::from)?;
    }
    Ok(())
}

// The exact sixteen-tag whitelist excludes request signatures, B664/CTP03,
// Stage fields, new transaction IDs and all own-future publication heads.
// Hashing the full request here would reintroduce Tli's identity cycle.
pub(crate) fn q04_original_precut_digest_v1(
    request: &Q04PreholdInputDataV1<'_>,
    preview: &Q04PreviewV1<'_>,
    controller_complete: &[u8],
    source_observation: &[u8],
    state_names: crate::journal::ProtectedJournalNamesV1,
    state_sequence: u64,
) -> Result<ObjectDigest, CreateQ04ErrorV1> {
    require_genesis_observation_pair_widths(controller_complete, source_observation)?;
    if state_sequence == 0 {
        return Err(CreateQ04ErrorV1::Bounds);
    }
    let original = request.fields();
    let preview = preview.fields();
    let names = state_names.to_bytes();
    let sequence = state_sequence.to_be_bytes();
    let fields = [
        original[0], original[1], original[2], original[3],
        preview[2], preview[3], preview[4], preview[5], preview[6], preview[7], preview[8],
        controller_complete, source_observation, preview[0], &names, &sequence,
    ];
    let mut digest = Sha256::new().chain_update(ORIGINAL_PRECUT_DOMAIN);
    for (index, field) in fields.into_iter().enumerate() {
        let tag = u8::try_from(index + 1).map_err(|_| CreateQ04ErrorV1::Bounds)?;
        let length = u32::try_from(field.len()).map_err(|_| CreateQ04ErrorV1::Bounds)?;
        digest.update([tag]);
        digest.update(length.to_be_bytes());
        digest.update(field);
    }
    Ok(ObjectDigest::from_bytes(digest.finalize().into()))
}

// This is shape DATA only. Root authenticates both complete packets on the
// current original owner before any caller may consume their semantic joins.
pub(super) fn require_genesis_observation_pair_widths(
    controller: &[u8], source: &[u8],
) -> Result<(), CreateQ04ErrorV1> {
    let legacy = controller.len() == super::source_genesis_root::CONTROLLER_SOURCE_GENESIS_READBACK_BYTES_V1
        && source.len() == super::SOURCE_TREE_GENESIS_READBACK_BYTES_V1;
    let resource = controller.len() == super::source_genesis_root::CONTROLLER_SOURCE_GENESIS_READBACK_BYTES_V2
        && source.len() == super::SOURCE_TREE_GENESIS_READBACK_BYTES_V2;
    if legacy || resource {
        Ok(())
    } else {
        Err(CreateQ04ErrorV1::Bounds)
    }
}

// This canonical pre-envelope seed excludes the final Cut and every future
// native/publication/phase identity. Both owners borrow the same actual
// original inputs and independently compare this nonauthorizing DATA hash.
pub(crate) fn q04_publication_precut_seed_v1(
    original_precut: ObjectDigest,
    root_before: ObjectDigest,
    controller_before: ObjectDigest,
    floor: ObjectDigest,
    ancestry: ObjectDigest,
    policy_before: ObjectDigest,
) -> Result<ObjectDigest, CreateQ04ErrorV1> {
    let fields = [original_precut, root_before, controller_before, floor, ancestry, policy_before];
    if fields.iter().any(|value| value.as_bytes() == &[0; 32]) {
        return Err(CreateQ04ErrorV1::ChangedCut);
    }
    let mut digest = Sha256::new()
        .chain_update(b"aos.sandbox.create-q04.publication-precut-seed.v1\0");
    for field in fields {
        digest.update(field.as_bytes());
    }
    digest.update(1_u64.to_be_bytes());
    Ok(ObjectDigest::from_bytes(digest.finalize().into()))
}

pub(crate) struct Q04PreholdTransferRecipeV1<'packet> {
    request: &'packet [u8],
    index: [u8; PREVIEW_INDEX_BYTES],
}

impl<'packet> Q04PreholdTransferRecipeV1<'packet> {
    pub(crate) fn new(request: &Q04PreholdInputDataV1<'packet>) -> Result<Self, CreateQ04ErrorV1> {
        let index = bounded_input_transfer_index(request.bytes, PREHOLD_REQUEST_DOMAIN, MAXIMUM_PREHOLD_BYTES)?;
        Ok(Self { request: request.bytes, index })
    }

    pub(crate) fn verify_index(
        original_index: &[u8],
        request: &Q04PreholdInputDataV1<'packet>,
    ) -> Result<Self, CreateQ04ErrorV1> {
        let recipe = Self::new(request)?;
        if original_index != recipe.index.as_slice() {
            return Err(CreateQ04ErrorV1::ChangedCut);
        }
        Ok(recipe)
    }

    pub(crate) fn index_bytes(&self) -> &[u8; PREVIEW_INDEX_BYTES] {
        &self.index
    }

    pub(crate) fn chunk_count(&self) -> u16 {
        u16::from_be_bytes(fixed(&self.index, 36))
    }

    pub(crate) fn encode_chunk(&self, index: u16, output: &mut Vec<u8>) -> Result<(), CreateQ04ErrorV1> {
        Q04ChunkPurposeV1::Prehold.encode_chunk(self.request, fixed(&self.index, 0), index, output)
    }
}

pub(crate) struct Q04PreholdChunkV1<'chunk> {
    chunk: Q04OrderedChunkV1<'chunk>,
}

impl<'chunk> Q04PreholdChunkV1<'chunk> {
    pub(crate) fn decode(bytes: &'chunk [u8], original_index: &[u8]) -> Result<Self, CreateQ04ErrorV1> {
        let (total, count) = prehold_index_shape(original_index)?;
        let chunk = Q04ChunkPurposeV1::Prehold.decode_chunk(bytes, fixed(original_index, 0), total, count)?;
        Ok(Self { chunk })
    }

    pub(crate) fn append_to(&self, output: &mut Vec<u8>) -> Result<(), CreateQ04ErrorV1> {
        self.chunk.append_to(output)
    }
}

pub(crate) fn prehold_index_shape(bytes: &[u8]) -> Result<(usize, u16), CreateQ04ErrorV1> {
    bounded_input_transfer_shape(bytes, PREHOLD_PREFIX_BYTES + 64, MAXIMUM_PREHOLD_BYTES)
}

// This fixed response is comparison DATA on the authenticated original
// stream. Its decoder never asserts a reservation or grants a hold/commit.
pub(crate) struct Q04PreholdPublicationDataV1([u8; PREHOLD_RESPONSE_BYTES]);

impl Q04PreholdPublicationDataV1 {
    pub(crate) fn from_body(
        mut body: [u8; PREHOLD_RESPONSE_BYTES],
        nonce: [u8; 16],
    ) -> Result<Self, CreateQ04ErrorV1> {
        finish_record(&mut body, b"AOSQ4J01", None, PREHOLD_RESPONSE_DOMAIN)?;
        Self::decode(&body, nonce)
    }

    pub(crate) fn decode(bytes: &[u8], nonce: [u8; 16]) -> Result<Self, CreateQ04ErrorV1> {
        let body = checked_record::<PREHOLD_RESPONSE_BYTES>(
            bytes, b"AOSQ4J01", None, PREHOLD_RESPONSE_DOMAIN,
        )?;
        if nonce == [0; 16] || body[16..32] != nonce
            || (32..128).step_by(32).any(|offset| nonzero::<32>(&body, offset).is_err())
            || nonzero::<16>(&body, 128).is_err()
            || nonzero::<16>(&body, 144).is_err()
            || body[128..144] == body[144..160]
            || (160..384).step_by(32).any(|offset| nonzero::<32>(&body, offset).is_err())
            || read_u64(&body, 384)? == 0
            || read_u64(&body, 392)? == 0
            || (456..472).step_by(4).any(|offset| read_u32(&body, offset).map_or(true, |value| value == 0))
        {
            return Err(CreateQ04ErrorV1::ChangedCut);
        }
        crate::journal::ProtectedJournalNamesV1::from_bytes(&body[400..448]).map_err(crate::journal::JournalError::from)?;
        let total = usize::try_from(read_u32(&body, 448)?).map_err(|_| CreateQ04ErrorV1::Bounds)?;
        let chunks = u16::from_be_bytes(fixed(&body, 452));
        let groups = u16::from_be_bytes(fixed(&body, 454));
        let expected_groups = chunks.checked_add(127).ok_or(CreateQ04ErrorV1::Bounds)? / 128;
        if total < 3432 || chunks != claim_chunk_count(total)? || groups != expected_groups {
            return Err(CreateQ04ErrorV1::Bounds);
        }
        Ok(Self(body))
    }

    pub(crate) fn bytes(&self) -> &[u8; PREHOLD_RESPONSE_BYTES] {
        &self.0
    }

    pub(crate) fn request_digest(&self) -> ObjectDigest {
        ObjectDigest::from_bytes(fixed(&self.0, 32))
    }

    pub(crate) fn original_precut(&self) -> ObjectDigest {
        ObjectDigest::from_bytes(fixed(&self.0, 64))
    }
}

fn decode_length_prefixed_fields<const COUNT: usize>(
    body: &[u8],
) -> Result<[&[u8]; COUNT], CreateQ04ErrorV1> {
    let lengths = COUNT.checked_mul(4).ok_or(CreateQ04ErrorV1::Bounds)?;
    let prefix = 16_usize.checked_add(lengths).ok_or(CreateQ04ErrorV1::Bounds)?;
    if body.len() < prefix {
        return Err(CreateQ04ErrorV1::Bounds);
    }
    let mut fields = [&[] as &[u8]; COUNT];
    let mut cursor = prefix;
    for (index, field) in fields.iter_mut().enumerate() {
        let length = usize::try_from(read_u32(body, 16 + index * 4)?)
            .map_err(|_| CreateQ04ErrorV1::Bounds)?;
        let end = cursor.checked_add(length).ok_or(CreateQ04ErrorV1::Bounds)?;
        *field = body.get(cursor..end).ok_or(CreateQ04ErrorV1::Bounds)?;
        cursor = end;
    }
    if cursor != body.len() {
        return Err(CreateQ04ErrorV1::Bounds);
    }
    Ok(fields)
}

fn encode_length_prefixed_fields<const COUNT: usize>(
    output: &mut Vec<u8>,
    magic: &[u8; 8],
    fields: [&[u8]; COUNT],
    maximum: usize,
) -> Result<(), CreateQ04ErrorV1> {
    let lengths = COUNT.checked_mul(4).ok_or(CreateQ04ErrorV1::Bounds)?;
    let prefix = 16_usize.checked_add(lengths).ok_or(CreateQ04ErrorV1::Bounds)?;
    let size = fields.iter().try_fold(prefix, |size, field| {
        size.checked_add(field.len()).ok_or(CreateQ04ErrorV1::Bounds)
    })?;
    if size > maximum {
        return Err(CreateQ04ErrorV1::Bounds);
    }
    output.try_reserve_exact(size)?;
    output.extend_from_slice(magic);
    output.extend_from_slice(&1_u16.to_be_bytes());
    output.extend_from_slice(&[0; 6]);
    for field in fields {
        let length = u32::try_from(field.len()).map_err(|_| CreateQ04ErrorV1::Bounds)?;
        output.extend_from_slice(&length.to_be_bytes());
    }
    for field in fields {
        output.extend_from_slice(field);
    }
    Ok(())
}

// Canonical DATA construction shares the same fixed header/checksum helper.
// Callers still pass the resulting bytes through the sole complete codec;
// neither this helper nor the decoded value supplies a live owner or grant.
fn finish_record<const SIZE: usize>(
    bytes: &mut [u8; SIZE],
    magic: &[u8; 8],
    phase: Option<u8>,
    domain: &[u8],
) -> Result<(), JournalError> {
    if SIZE < 48 {
        return Err(JournalError::ProtectedBoundary);
    }
    bytes[..8].copy_from_slice(magic);
    bytes[8..10].copy_from_slice(&1_u16.to_be_bytes());
    bytes[10] = phase.unwrap_or(0);
    bytes[11..16].fill(0);

    let checksum = Sha256::new()
        .chain_update(domain)
        .chain_update(&bytes[..SIZE - 32])
        .finalize();
    bytes[SIZE - 32..].copy_from_slice(&checksum);
    Ok(())
}

fn checked_record<const SIZE: usize>(
    bytes: &[u8],
    magic: &[u8; 8],
    phase: Option<u8>,
    domain: &[u8],
) -> Result<[u8; SIZE], JournalError> {
    if SIZE < 48
        || bytes.len() != SIZE
        || bytes[..8] != *magic
        || bytes[8..10] != 1_u16.to_be_bytes()
        || bytes[10] != phase.unwrap_or(0)
        || bytes[11..16] != [0; 5]
        || Sha256::new()
            .chain_update(domain)
            .chain_update(&bytes[..SIZE - 32])
            .finalize()
            .as_slice()
            != &bytes[SIZE - 32..]
    {
        return Err(JournalError::ProtectedBoundary);
    }
    bytes.try_into().map_err(|_| JournalError::ProtectedBoundary)
}

fn require_presence(bytes: &[u8], present: bool) -> Result<(), JournalError> {
    if bytes.iter().any(|byte| *byte != 0) != present {
        return Err(JournalError::ProtectedBoundary);
    }
    Ok(())
}

fn nonzero<const SIZE: usize>(bytes: &[u8], offset: usize) -> Result<[u8; SIZE], JournalError> {
    let end = offset
        .checked_add(SIZE)
        .ok_or(JournalError::ProtectedBoundary)?;
    let bytes = bytes
        .get(offset..end)
        .ok_or(JournalError::ProtectedBoundary)?;
    require_presence(bytes, true)?;
    bytes.try_into().map_err(|_| JournalError::ProtectedBoundary)
}

fn fixed<const SIZE: usize>(bytes: &[u8], offset: usize) -> [u8; SIZE] {
    let mut field = [0; SIZE];
    field.copy_from_slice(&bytes[offset..offset + SIZE]);
    field
}

fn read_u32(bytes: &[u8], offset: usize) -> Result<u32, JournalError> {
    Ok(u32::from_be_bytes(read_integer_bytes(bytes, offset)?))
}

fn read_u64(bytes: &[u8], offset: usize) -> Result<u64, JournalError> {
    Ok(u64::from_be_bytes(read_integer_bytes(bytes, offset)?))
}

fn read_integer_bytes<const SIZE: usize>(
    bytes: &[u8],
    offset: usize,
) -> Result<[u8; SIZE], JournalError> {
    let end = offset
        .checked_add(SIZE)
        .ok_or(JournalError::ProtectedBoundary)?;
    bytes
        .get(offset..end)
        .ok_or(JournalError::ProtectedBoundary)?
        .try_into()
        .map_err(|_| JournalError::ProtectedBoundary)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn signing_keeps_original_io_cause_and_separate_first_postcheck_debt() {
        let original = std::io::Error::from_raw_os_error(13);
        let mut first = Some(CreateQ04ErrorV1::Io(original));
        let mut debt = None;

        assert!(finish_controller_q04_signing_v1(
            Err(CreateQ04ErrorV1::Expired), &mut first, &mut debt,
        ).is_err());
        assert!(finish_controller_q04_signing_v1(
            Err(CreateQ04ErrorV1::ChangedCut), &mut first, &mut debt,
        ).is_err());
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
        assert!(finish_controller_q04_signing_v1(
            Err(CreateQ04ErrorV1::ChangedCut), &mut first, &mut debt,
        ).is_err());

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

    fn gate(
        identity: &Q04CutIdentityV1,
        decision: &Q04RootDecisionV1,
    ) -> Q04EffectSubgateV1 {
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

        for kind in [Q04AcknowledgementKindV1::Policy, Q04AcknowledgementKindV1::Release,
            Q04AcknowledgementKindV1::Settlement, Q04AcknowledgementKindV1::Clearance]
        {
            let mut expected = acknowledgement_body(kind, &identity);
            finish_q04_acknowledgement_body_v1(kind, &mut expected, &identity).unwrap();
            let mut actual = Vec::new();
            encode_q04_acknowledgement_data_v1(
                &mut actual, kind, &identity, 11, consumed, pairs,
                (kind == Q04AcknowledgementKindV1::Clearance).then_some(clear),
            ).unwrap();

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

        assert_eq!(gate.digest().as_bytes(), Sha256::digest(gate.bytes()).as_slice());
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
            .transaction_id(&identity, 2, predecessor).unwrap();
        let root = Q04TransactionOwnerV1::Root
            .transaction_id(&identity, 2, predecessor).unwrap();

        assert_ne!(controller, root);
        assert_ne!(root, identity.publication_id());
        assert!(Q04TransactionOwnerV1::Root.transaction_id(&identity, 8, predecessor).is_err());
        assert!(Q04TransactionOwnerV1::Controller
            .transaction_id(&identity, 0, predecessor).is_err());
        assert!(Q04TransactionOwnerV1::Cache
            .transaction_id(&identity, 1, ObjectDigest::from_bytes([0; 32])).is_err());
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
        let credential = super::super::encode_controller_hold_signer_credential_v1(
            1,
            &key.verifying_key(),
        ).unwrap();
        let pin = super::super::PinnedControllerHoldSignerV1::decode(&credential).unwrap();
        let kind = Q04AcknowledgementKindV1::Policy;
        let mut packet = acknowledgement_body(kind, &identity);

        sign_q04_acknowledgement_v1(kind, &mut packet, &key, &identity).unwrap();
        let acknowledgement = Q04AcknowledgementV1::verify(kind, &packet, &pin, &identity).unwrap();
        assert_eq!(acknowledgement.bytes().len(), 408);
        assert_eq!(&acknowledgement.bytes()[40..72], identity.digest().as_bytes());
        assert_ne!(&acknowledgement.bytes()[40..72], &identity.bytes()[392..424]);
        assert_eq!(acknowledgement.controller_sequence(), 11);

        let mut substituted = acknowledgement_body(kind, &identity);
        substituted[40..72].copy_from_slice(&identity.bytes()[392..424]);
        assert!(sign_q04_acknowledgement_v1(kind, &mut substituted, &key, &identity).is_err());

        packet[10] = 2;
        let signature = key.sign(
            &acknowledgement_signature_preimage(kind, &packet[..kind.body_bytes()]).unwrap(),
        );
        packet[kind.body_bytes()..].copy_from_slice(&signature.to_bytes());
        assert!(matches!(
            Q04AcknowledgementV1::verify(kind, &packet, &pin, &identity),
            Err(CreateQ04ErrorV1::ChangedCut),
        ));
    }

    #[test]
    fn acknowledgement_kinds_preserve_widths_and_distinct_signature_domains() {
        let identity = identity();
        let key = SigningKey::from_bytes(&[7; 32]);
        let credential = super::super::encode_controller_hold_signer_credential_v1(
            1,
            &key.verifying_key(),
        ).unwrap();
        let pin = super::super::PinnedControllerHoldSignerV1::decode(&credential).unwrap();

        for (kind, expected_length) in [
            (Q04AcknowledgementKindV1::Policy, 408),
            (Q04AcknowledgementKindV1::Release, 408),
            (Q04AcknowledgementKindV1::Settlement, 600),
            (Q04AcknowledgementKindV1::Clearance, 728),
        ] {
            let mut packet = acknowledgement_body(kind, &identity);
            sign_q04_acknowledgement_v1(kind, &mut packet, &key, &identity).unwrap();
            let acknowledgement = Q04AcknowledgementV1::verify(kind, &packet, &pin, &identity).unwrap();

            assert_eq!(acknowledgement.bytes().len(), expected_length);
            assert_eq!(acknowledgement.kind(), kind);
            assert_eq!(acknowledgement.digest().as_bytes(), Sha256::digest(&packet).as_slice());
            assert!(Q04AcknowledgementV1::verify(kind, &packet[..packet.len() - 1], &pin, &identity).is_err());
            assert!(sign_q04_acknowledgement_v1(kind, &mut packet, &key, &identity).is_err());
        }

        let release = Q04AcknowledgementKindV1::Release;
        let mut packet = acknowledgement_body(release, &identity);
        sign_q04_acknowledgement_v1(release, &mut packet, &key, &identity).unwrap();
        let foreign_signature = key.sign(&acknowledgement_signature_preimage(
            Q04AcknowledgementKindV1::Policy,
            &packet[..release.body_bytes()],
        ).unwrap());
        packet[release.body_bytes()..].copy_from_slice(&foreign_signature.to_bytes());

        assert!(matches!(
            Q04AcknowledgementV1::verify(release, &packet, &pin, &identity),
            Err(CreateQ04ErrorV1::AcknowledgementSignature(_)),
        ));
    }

    #[test]
    fn claim_signature_binds_every_original_byte_and_distinct_purpose() {
        let identity = identity();
        let key = SigningKey::from_bytes(&[7; 32]);
        let credential = super::super::encode_controller_hold_signer_credential_v1(
            1,
            &key.verifying_key(),
        ).unwrap();
        let pin = super::super::PinnedControllerHoldSignerV1::decode(&credential).unwrap();

        // These opaque width fixtures exercise only the Claim envelope. The
        // real Root consumer must separately decode/authenticate each old
        // field with its existing engine; no fixture constructs a live owner.
        let binding = vec![8; super::super::CLOSED_POLICY_BINDING_BYTES_V2];
        let current = vec![9; super::super::CONTROLLER_PROJECT_ADMISSION_READBACK_BYTES_V1];
        let held = vec![10; super::super::CLOSED_CONTROLLER_HOLD_READBACK_BYTES_V1];
        let source = vec![11; super::super::SOURCE_TREE_GENESIS_READBACK_BYTES_V1];
        let cache = vec![12; crate::cache_residency::CLOSED_CACHE_OWNER_READBACK_BYTES_V2];
        let fields = [
            b"operation".as_slice(), b"desired", b"effect", b"node",
            b"site", b"backend", b"catalogs", b"project",
            &binding, &current, &held, &source, &cache, identity.bytes(),
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
            Q04ClaimV1::verify(&tampered, &pin, &identity),
            Err(CreateQ04ErrorV1::ClaimSignature(_)),
        ));

        let signature_offset = packet.len() - 64;
        let wrong = key.sign(&signed_record_preimage(
            Q04AcknowledgementKindV1::Policy.signature_domain(),
            &packet[..signature_offset],
        ).unwrap());
        let mut foreign = packet.clone();
        foreign[signature_offset..].copy_from_slice(&wrong.to_bytes());
        assert!(matches!(
            Q04ClaimV1::verify(&foreign, &pin, &identity),
            Err(CreateQ04ErrorV1::ClaimSignature(_)),
        ));
    }

    #[test]
    fn claim_rejects_substituted_cut_reserved_lengths_and_partial_fields() {
        let identity = identity();
        let binding = vec![8; super::super::CLOSED_POLICY_BINDING_BYTES_V2];
        let current = vec![9; super::super::CONTROLLER_PROJECT_ADMISSION_READBACK_BYTES_V1];
        let held = vec![10; super::super::CLOSED_CONTROLLER_HOLD_READBACK_BYTES_V1];
        let source = vec![11; super::super::SOURCE_TREE_GENESIS_READBACK_BYTES_V1];
        let cache = vec![12; crate::cache_residency::CLOSED_CACHE_OWNER_READBACK_BYTES_V2];
        let fields = [
            b"operation".as_slice(), b"desired", b"effect", b"node",
            b"site", b"backend", b"catalogs", b"project",
            &binding, &current, &held, &source, &cache, identity.bytes(),
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
        let current = vec![9; super::super::CONTROLLER_PROJECT_ADMISSION_READBACK_BYTES_V1];
        let held = vec![10; super::super::CLOSED_CONTROLLER_HOLD_READBACK_BYTES_V1];
        let source = vec![11; super::super::SOURCE_TREE_GENESIS_READBACK_BYTES_V1];
        let cache = vec![12; crate::cache_residency::CLOSED_CACHE_OWNER_READBACK_BYTES_V2];
        let fields = [
            operation.as_slice(), b"desired", b"effect", b"node",
            b"site", b"backend", b"catalogs", b"project",
            &binding, &current, &held, &source, &cache, identity.bytes(),
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
        let credential = super::super::encode_controller_hold_signer_credential_v1(
            1,
            &key.verifying_key(),
        ).unwrap();
        let pin = super::super::PinnedControllerHoldSignerV1::decode(&credential).unwrap();
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
        Q04ClaimStorageRecipeV1::verify_index(
            recipe.index_bytes(),
            &reconstructed,
            &identity,
        ).unwrap();

        assert_eq!(reconstructed.bytes(), packet);
        assert_eq!(recipe.index_bytes().len(), 96);
        assert_eq!(claim_chunk_count(MAXIMUM_CLAIM_BYTES).unwrap(), 342);
        assert!(claim_chunk_count(MAXIMUM_CLAIM_BYTES + 1).is_err());
        assert!(recipe.encode_chunk(recipe.chunk_count(), &mut Vec::new()).is_err());

        let mut changed = packet.clone();
        changed[CLAIM_PREFIX_BYTES] ^= 1;
        let changed = Q04ClaimV1::decode(&changed, &identity).unwrap();
        assert!(Q04ClaimStorageRecipeV1::verify_index(
            recipe.index_bytes(),
            &changed,
            &identity,
        ).is_err());
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
            metadata.as_slice(), stage.as_slice(), deployment.as_slice(),
            input.as_slice(), input.as_slice(), input.as_slice(), input.as_slice(),
            project.as_slice(), layer.as_slice(),
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
        Q04PreviewTransferRecipeV1::verify_index(recipe.index_bytes(), &reconstructed_preview).unwrap();
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

        assert!(Q04PreviewTransferRecipeV1::verify_index(recipe.index_bytes(), &changed_preview).is_err());
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
        let current = [6; super::super::CONTROLLER_PROJECT_ADMISSION_READBACK_BYTES_V1];
        let mut packet = Vec::new();
        encode_q04_prehold_body_v1(&mut packet, [&metadata, &rows, &rows, &rows, &binding, &current]).unwrap();
        sign_q04_prehold_body_v1(&mut packet, &SigningKey::from_bytes(&[42; 32])).unwrap();
        packet
    }

    #[test]
    fn prehold_signature_is_whole_original_data_and_not_claim_or_ack_purpose() {
        let key = SigningKey::from_bytes(&[42; 32]);
        let credential = super::super::encode_controller_hold_signer_credential_v1(7, &key.verifying_key()).unwrap();
        let pin = super::super::PinnedControllerHoldSignerV1::decode(&credential).unwrap();
        let packet = prehold_fixture(1);

        assert!(Q04PreholdInputDataV1::verify(&packet, &pin).is_ok());
        let mut altered = packet.clone();
        altered[PREHOLD_PREFIX_BYTES + PREHOLD_METADATA_BYTES] ^= 1;
        assert!(Q04PreholdInputDataV1::verify(&altered, &pin).is_err());
        let mut wrong_domain = packet;
        let signature_offset = wrong_domain.len() - 64;
        let signature = key.sign(&signed_record_preimage(CLAIM_SIGNATURE_DOMAIN, &wrong_domain[..signature_offset]).unwrap());
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
        let names = crate::journal::ProtectedJournalNamesV1::from_bytes(&request.fields()[0][176..224]).unwrap();
        let complete = [7; super::super::source_genesis_root::CONTROLLER_SOURCE_GENESIS_READBACK_BYTES_V1];
        let source = [8; super::super::SOURCE_TREE_GENESIS_READBACK_BYTES_V1];
        let original = q04_original_precut_digest_v1(&request, &preview, &complete, &source, names, 1).unwrap();

        let mut changed = packet.clone();
        // Header40 + metadata512 + three one-byte rows precede B664/CTP03.
        changed[PREHOLD_PREFIX_BYTES + PREHOLD_METADATA_BYTES + 3] ^= 1;
        changed[PREHOLD_PREFIX_BYTES + PREHOLD_METADATA_BYTES + 3 + super::super::CLOSED_POLICY_BINDING_BYTES_V2] ^= 1;
        let final_byte = changed.len() - 1;
        changed[final_byte] ^= 1;
        let changed = Q04PreholdInputDataV1::decode(&changed).unwrap();
        let mut changed_preview = preview_packet.clone();
        changed_preview[PREVIEW_PREFIX_BYTES + 120 + 96] ^= 1;
        let changed_preview = Q04PreviewV1::decode(&changed_preview, [13; 16]).unwrap();

        assert_eq!(q04_original_precut_digest_v1(&changed, &changed_preview, &complete, &source, names, 1).unwrap(), original);
        let mut changed_row = packet.clone();
        changed_row[PREHOLD_PREFIX_BYTES + PREHOLD_METADATA_BYTES] ^= 1;
        let changed_row = Q04PreholdInputDataV1::decode(&changed_row).unwrap();
        assert_ne!(q04_original_precut_digest_v1(&changed_row, &preview, &complete, &source, names, 1).unwrap(), original);
        assert_ne!(q04_original_precut_digest_v1(&request, &preview, &complete, &source, names, 2).unwrap(), original);
    }
}
