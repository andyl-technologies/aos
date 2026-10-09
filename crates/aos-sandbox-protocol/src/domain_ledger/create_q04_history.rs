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

use aos_sandbox_core::bounded_codec::BoundedReader;
use aos_sandbox_core::{ObjectDigest, OperationId, ProjectId, SandboxId};
use sha2::{Digest as _, Sha256};

use super::ProtectedHistoryDataErrorV1;

/// Reports malformed publication DATA, changed comparison fields or numerical bounds.
#[derive(Debug, thiserror::Error)]
pub enum Q04HistoryDataErrorV1 {
    /// A fixed record or physical-name encoding is malformed.
    #[error("Q04 history DATA is malformed")]
    Malformed,
    /// The original historical comparison fields do not match.
    #[error("Q04 history comparison fields changed")]
    ChangedCut,
    /// The original numerical or representation bound was exceeded.
    #[error("Q04 history DATA exceeds its bound")]
    Bounds,
}

impl From<ProtectedHistoryDataErrorV1> for Q04HistoryDataErrorV1 {
    fn from(error: ProtectedHistoryDataErrorV1) -> Self {
        match error {
            ProtectedHistoryDataErrorV1::Malformed => Self::Malformed,
        }
    }
}

pub const IDENTITY_BYTES: usize = 680;
pub const PHASE_BYTES: usize = 592;
pub const PENDING_BYTES: usize = 264;
pub const GATE_BYTES: usize = 288;
pub const DECISION_BYTES: usize = 384;
pub const MAXIMUM_CLAIM_BYTES: usize = 1024 * 1024;
pub const CLAIM_CHUNK_BYTES: usize = 3072;
pub const PREHOLD_RESPONSE_BYTES: usize = 504;
const IDENTITY_DOMAIN: &[u8] = b"aos.sandbox.create-q04.cut-identity.v1\0";
const CONTROLLER_PHASE_DOMAIN: &[u8] = b"aos.sandbox.create-q04.controller-phase.v1\0";
const ROOT_PHASE_DOMAIN: &[u8] = b"aos.sandbox.create-q04.root-phase.v1\0";
const SOURCE_PENDING_DOMAIN: &[u8] = b"aos.sandbox.create-q04.source-pending.v1\0";
const CACHE_PENDING_DOMAIN: &[u8] = b"aos.sandbox.create-q04.cache-pending.v1\0";
const GATE_DOMAIN: &[u8] = b"aos.sandbox.create-q04.effect-subgate.v1\0";
pub const GATE_IDENTITY_DOMAIN: &[u8] = b"aos.sandbox.create-q04.effect-gate-identity.v1\0";
const DECISION_DOMAIN: &[u8] = b"aos.sandbox.create-q04.root-decision.v1\0";
const PREHOLD_RESPONSE_DOMAIN: &[u8] = b"aos.sandbox.create-q04.prefund-response.v1\0";


#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Q04TransactionOwnerV1 {
    Controller,
    Source,
    Cache,
    Root,
}

impl Q04TransactionOwnerV1 {
    /// Derives comparison DATA without predicting an observed commit or head.
    pub fn transaction_id(
        self,
        identity: &Q04CutIdentityV1,
        phase: u8,
        predecessor: ObjectDigest,
    ) -> Result<[u8; 16], ProtectedHistoryDataErrorV1> {
        let (domain, last): (&[u8], u8) = match self {
            Self::Controller => (b"aos.sandbox.create-q04.transaction.controller.v1\0", 8),
            Self::Source => (b"aos.sandbox.create-q04.transaction.source.v1\0", 3),
            Self::Cache => (b"aos.sandbox.create-q04.transaction.cache.v1\0", 3),
            Self::Root => (b"aos.sandbox.create-q04.transaction.root.v1\0", 7),
        };
        if phase == 0 || phase > last || predecessor.as_bytes() == &[0; 32] {
            return Err(ProtectedHistoryDataErrorV1::Malformed);
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
            return Err(ProtectedHistoryDataErrorV1::Malformed);
        }
        Ok(transaction)
    }
}


// Every offset below is fixed by the versioned contract. Accessors read only
// a fully length/checksum/shape-checked array, never a caller's unchecked slice.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Q04CutIdentityV1([u8; IDENTITY_BYTES]);

impl Q04CutIdentityV1 {
    pub fn from_body(mut body: [u8; IDENTITY_BYTES]) -> Result<Self, ProtectedHistoryDataErrorV1> {
        finish_record(&mut body, b"AOSQ4I01", None, IDENTITY_DOMAIN)?;
        Self::decode(&body)
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, ProtectedHistoryDataErrorV1> {
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
            return Err(ProtectedHistoryDataErrorV1::Malformed);
        }
        Ok(Self(bytes))
    }

    pub fn bytes(&self) -> &[u8; IDENTITY_BYTES] {
        &self.0
    }

    pub fn digest(&self) -> ObjectDigest {
        ObjectDigest::from_bytes(Sha256::digest(self.0).into())
    }

    pub fn nonce(&self) -> [u8; 16] {
        fixed(&self.0, 16)
    }

    pub fn project(&self) -> ProjectId {
        ProjectId::from_bytes(fixed(&self.0, 32))
    }

    pub fn operation(&self) -> OperationId {
        OperationId::from_bytes(fixed(&self.0, 48))
    }

    pub fn controller_uid(&self) -> u32 {
        u32::from_be_bytes(fixed(&self.0, 80))
    }

    pub fn source_uid(&self) -> u32 {
        u32::from_be_bytes(fixed(&self.0, 84))
    }

    pub fn operation_revision(&self) -> ObjectDigest {
        ObjectDigest::from_bytes(fixed(&self.0, 200))
    }

    pub fn desired_precondition(&self) -> ObjectDigest {
        ObjectDigest::from_bytes(fixed(&self.0, 232))
    }

    pub fn effect_plan_digest(&self) -> ObjectDigest {
        ObjectDigest::from_bytes(fixed(&self.0, 264))
    }

    pub fn sandbox(&self) -> SandboxId {
        SandboxId::from_bytes(fixed(&self.0, 64))
    }

    pub fn stage_id(&self) -> [u8; 16] {
        fixed(&self.0, 168)
    }

    pub fn publication_id(&self) -> [u8; 16] {
        fixed(&self.0, 184)
    }

    pub fn binding(&self) -> ObjectDigest {
        ObjectDigest::from_bytes(fixed(&self.0, 424))
    }

    pub fn gen1_floor(&self) -> ObjectDigest {
        ObjectDigest::from_bytes(fixed(&self.0, 328))
    }

    pub fn ancestry(&self) -> ObjectDigest {
        ObjectDigest::from_bytes(fixed(&self.0, 360))
    }

    /// Names the pre-decision comparator, not a consumed gate or authority.
    pub fn gate_identity(&self) -> ObjectDigest {
        ObjectDigest::from_bytes(
            Sha256::new()
                .chain_update(GATE_IDENTITY_DOMAIN)
                .chain_update(self.bytes())
                .finalize()
                .into(),
        )
    }

    pub fn accepted_generation(&self) -> u64 {
        u64::from_be_bytes(fixed(&self.0, 96))
    }

    pub fn epoch(&self) -> u64 {
        u64::from_be_bytes(fixed(&self.0, 160))
    }

    pub fn before_controller_rows(&self) -> ObjectDigest {
        ObjectDigest::from_bytes(fixed(&self.0, 296))
    }

    pub fn policy_transaction(&self) -> ObjectDigest {
        ObjectDigest::from_bytes(fixed(&self.0, 520))
    }

    pub fn policy_current(&self) -> ObjectDigest {
        ObjectDigest::from_bytes(fixed(&self.0, 552))
    }

    pub fn cache_quota(&self) -> ObjectDigest {
        ObjectDigest::from_bytes(fixed(&self.0, 584))
    }
}

/// Retains an exact historical publication observation, never a live grant.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Q04RootDecisionV1([u8; DECISION_BYTES]);

impl Q04RootDecisionV1 {
    pub fn from_body(
        mut body: [u8; DECISION_BYTES],
        identity: &Q04CutIdentityV1,
    ) -> Result<Self, ProtectedHistoryDataErrorV1> {
        finish_record(&mut body, b"AOSQ4D01", None, DECISION_DOMAIN)?;
        Self::decode(&body, identity)
    }

    pub fn decode(
        bytes: &[u8],
        identity: &Q04CutIdentityV1,
    ) -> Result<Self, ProtectedHistoryDataErrorV1> {
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
            return Err(ProtectedHistoryDataErrorV1::Malformed);
        }
        Ok(Self(bytes))
    }

    pub fn bytes(&self) -> &[u8; DECISION_BYTES] {
        &self.0
    }

    pub fn digest(&self) -> ObjectDigest {
        ObjectDigest::from_bytes(Sha256::digest(self.bytes()).into())
    }

    pub fn authority_transaction_id(&self) -> [u8; 16] {
        fixed(&self.0, 48)
    }

    pub fn state_transaction_id(&self) -> [u8; 16] {
        fixed(&self.0, 64)
    }

    pub fn state_sequence(&self) -> u64 {
        u64::from_be_bytes(fixed(&self.0, 112))
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Q04PhaseOwnerV1 {
    Controller,
    Root,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Q04PhaseRecordV1 {
    owner: Q04PhaseOwnerV1,
    bytes: [u8; PHASE_BYTES],
}


impl Q04PhaseRecordV1 {
    pub fn from_body(
        owner: Q04PhaseOwnerV1,
        phase: u8,
        mut body: [u8; PHASE_BYTES],
        identity: &Q04CutIdentityV1,
    ) -> Result<Self, ProtectedHistoryDataErrorV1> {
        let (magic, domain) = match owner {
            Q04PhaseOwnerV1::Controller => (b"AOSQ4C01", CONTROLLER_PHASE_DOMAIN),
            Q04PhaseOwnerV1::Root => (b"AOSQ4R01", ROOT_PHASE_DOMAIN),
        };
        finish_record(&mut body, magic, Some(phase), domain)?;
        Self::decode(owner, &body, identity)
    }

    pub fn decode(
        owner: Q04PhaseOwnerV1,
        bytes: &[u8],
        identity: &Q04CutIdentityV1,
    ) -> Result<Self, ProtectedHistoryDataErrorV1> {
        let (magic, domain, last) = match owner {
            Q04PhaseOwnerV1::Controller => (b"AOSQ4C01", CONTROLLER_PHASE_DOMAIN, 8),
            Q04PhaseOwnerV1::Root => (b"AOSQ4R01", ROOT_PHASE_DOMAIN, 7),
        };
        let phase = *bytes.get(10).ok_or(ProtectedHistoryDataErrorV1::Malformed)?;
        if phase == 0 || phase > last {
            return Err(ProtectedHistoryDataErrorV1::Malformed);
        }
        let bytes = checked_record::<PHASE_BYTES>(bytes, magic, Some(phase), domain)?;
        if bytes[16..48] != *identity.digest().as_bytes()
            || bytes[48..64] != identity.stage_id()
            || nonzero::<16>(&bytes, 544).is_err()
            || nonzero::<32>(&bytes, 512).is_err()
        {
            return Err(ProtectedHistoryDataErrorV1::Malformed);
        }
        require_phase_shape(owner, phase, &bytes)?;
        Ok(Self { owner, bytes })
    }

    pub fn bytes(&self) -> &[u8; PHASE_BYTES] {
        &self.bytes
    }

    pub fn owner(&self) -> Q04PhaseOwnerV1 {
        self.owner
    }

    pub fn phase(&self) -> u8 {
        self.bytes[10]
    }

    pub fn digest(&self) -> ObjectDigest {
        ObjectDigest::from_bytes(Sha256::digest(self.bytes).into())
    }

    pub fn native_transaction_id(&self) -> [u8; 16] {
        fixed(&self.bytes, 544)
    }

    pub fn acknowledgement(&self) -> ObjectDigest {
        ObjectDigest::from_bytes(fixed(&self.bytes, 480))
    }

    pub fn require_successor(&self, prior: &Self) -> Result<(), ProtectedHistoryDataErrorV1> {
        if self.owner != prior.owner
            || self.phase() != prior.phase() + 1
            || self.bytes[16..64] != prior.bytes[16..64]
            || self.bytes[64..96] != *prior.digest().as_bytes()
            || self.bytes[512..544] != prior.bytes[512..544]
        {
            return Err(ProtectedHistoryDataErrorV1::Malformed);
        }
        // An introduced event remains immutable. A zero slot may be populated
        // only in the new phase's closed shape; the caller checks its real event.
        for offset in (96..480).step_by(32) {
            if self.owner == Q04PhaseOwnerV1::Root && prior.phase() == 5 && offset == 160 {
                // R5 carries its pre-write authorization recipe. R6 replaces
                // that one slot with the actually observed R5 record digest.
                if self.bytes[offset..offset + 32] != *prior.digest().as_bytes() {
                    return Err(ProtectedHistoryDataErrorV1::Malformed);
                }
                continue;
            }
            if prior.bytes[offset..offset + 32] != [0; 32]
                && self.bytes[offset..offset + 32] != prior.bytes[offset..offset + 32]
            {
                return Err(ProtectedHistoryDataErrorV1::Malformed);
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
) -> Result<(), ProtectedHistoryDataErrorV1> {
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
pub enum Q04PendingOwnerV1 {
    Source,
    Cache,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Q04PendingRecordV1 {
    owner: Q04PendingOwnerV1,
    bytes: [u8; PENDING_BYTES],
}

impl Q04PendingRecordV1 {
    pub fn from_body(
        owner: Q04PendingOwnerV1,
        phase: u8,
        mut body: [u8; PENDING_BYTES],
    ) -> Result<Self, ProtectedHistoryDataErrorV1> {
        let (magic, domain) = match owner {
            Q04PendingOwnerV1::Source => (b"AOSQ4S01", SOURCE_PENDING_DOMAIN),
            Q04PendingOwnerV1::Cache => (b"AOSQ4K01", CACHE_PENDING_DOMAIN),
        };
        finish_record(&mut body, magic, Some(phase), domain)?;
        Self::decode(owner, &body)
    }

    pub fn decode(
        owner: Q04PendingOwnerV1,
        bytes: &[u8],
    ) -> Result<Self, ProtectedHistoryDataErrorV1> {
        let (magic, domain) = match owner {
            Q04PendingOwnerV1::Source => (b"AOSQ4S01", SOURCE_PENDING_DOMAIN),
            Q04PendingOwnerV1::Cache => (b"AOSQ4K01", CACHE_PENDING_DOMAIN),
        };
        let phase = *bytes.get(10).ok_or(ProtectedHistoryDataErrorV1::Malformed)?;
        if !matches!(phase, 1 | 2) {
            return Err(ProtectedHistoryDataErrorV1::Malformed);
        }
        let bytes = checked_record::<PENDING_BYTES>(bytes, magic, Some(phase), domain)?;
        let fields = [(16, 32), (48, 16), (64, 32), (104, 32), (136, 32), (200, 32)];
        for (offset, width) in fields {
            require_presence(&bytes[offset..offset + width], true)?;
        }
        if read_u64(&bytes, 96)? == 0 {
            return Err(ProtectedHistoryDataErrorV1::Malformed);
        }
        require_presence(&bytes[168..200], phase == 2)?;
        Ok(Self { owner, bytes })
    }

    pub fn bytes(&self) -> &[u8; PENDING_BYTES] {
        &self.bytes
    }

    pub fn is_held(&self) -> bool {
        self.bytes[10] == 1
    }

    /// Joins comparison bytes to the same finalized original cut.
    pub fn require_identity(&self, identity: &Q04CutIdentityV1) -> Result<(), ProtectedHistoryDataErrorV1> {
        if self.bytes[16..48] != *identity.digest().as_bytes()
            || self.bytes[48..64] != identity.nonce()
            || self.bytes[64..96] != *identity.binding().as_bytes()
            || self.bytes[96..104] != identity.epoch().to_be_bytes()
        {
            return Err(ProtectedHistoryDataErrorV1::Malformed);
        }
        Ok(())
    }

    pub fn digest(&self) -> ObjectDigest {
        ObjectDigest::from_bytes(Sha256::digest(self.bytes()).into())
    }

    pub fn require_release_of(&self, held: &Self) -> Result<(), ProtectedHistoryDataErrorV1> {
        if self.owner != held.owner
            || self.is_held()
            || !held.is_held()
            || self.bytes[16..168] != held.bytes[16..168]
            || self.bytes[200..232] != held.bytes[200..232]
        {
            return Err(ProtectedHistoryDataErrorV1::Malformed);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Q04EffectSubgateV1([u8; GATE_BYTES]);

impl Q04EffectSubgateV1 {
    pub fn from_body(mut body: [u8; GATE_BYTES]) -> Result<Self, ProtectedHistoryDataErrorV1> {
        finish_record(&mut body, b"AOSQ4G01", None, GATE_DOMAIN)?;
        Self::decode(&body)
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, ProtectedHistoryDataErrorV1> {
        let bytes = checked_record::<GATE_BYTES>(bytes, b"AOSQ4G01", None, GATE_DOMAIN)?;
        if !matches!(bytes[184], 1..=4)
            || bytes[185..192] != [0; 7]
            || read_u64(&bytes, 176)? != 1
        {
            return Err(ProtectedHistoryDataErrorV1::Malformed);
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

    pub fn bytes(&self) -> &[u8; GATE_BYTES] {
        &self.0
    }

    pub fn status(&self) -> u8 {
        self.0[184]
    }

    // A nonauthorizing next-record recipe. The actual Controller transition
    // separately joins the named signed ACK and complete prior native/CAS cut.
    pub fn next_status_recipe(
        &self,
        acknowledgement: ObjectDigest,
    ) -> Result<Self, ProtectedHistoryDataErrorV1> {
        if self.status() >= 4 || acknowledgement.as_bytes() == &[0; 32] {
            return Err(ProtectedHistoryDataErrorV1::Malformed);
        }
        let mut body = self.0;
        body[184] = self.status() + 1;
        body[192..224].copy_from_slice(acknowledgement.as_bytes());
        let next = Self::from_body(body)?;
        next.require_successor(self)?;
        Ok(next)
    }

    /// Hashes the complete canonical record, including its internal checksum.
    pub fn digest(&self) -> ObjectDigest {
        ObjectDigest::from_bytes(Sha256::digest(self.bytes()).into())
    }

    pub fn acknowledgement(&self) -> ObjectDigest {
        ObjectDigest::from_bytes(fixed(&self.0, 192))
    }

    pub fn require_identity(
        &self,
        identity: &Q04CutIdentityV1,
        decision: &Q04RootDecisionV1,
    ) -> Result<(), ProtectedHistoryDataErrorV1> {
        self.require_cut_identity(identity)?;
        if self.0[128..160] != *decision.digest().as_bytes() {
            return Err(ProtectedHistoryDataErrorV1::Malformed);
        }
        Ok(())
    }

    pub fn require_cut_identity(
        &self,
        identity: &Q04CutIdentityV1,
    ) -> Result<(), ProtectedHistoryDataErrorV1> {
        if self.0[16..48] != *identity.digest().as_bytes()
            || self.0[48..80] != *identity.binding().as_bytes()
            || self.0[80..96] != identity.publication_id()
            || self.0[96..128] != *identity.policy_current().as_bytes()
            || self.0[160..176] != identity.stage_id()
            || self.0[176..184] != identity.accepted_generation().to_be_bytes()
            || self.0[224..256] != *identity.gen1_floor().as_bytes()
        {
            return Err(ProtectedHistoryDataErrorV1::Malformed);
        }
        Ok(())
    }

    // Reconstructs only the canonical historical C2 comparison bytes. This
    // does not assert those bytes were committed or return a current gate.
    pub fn historical_consumed_record(&self) -> Result<Self, ProtectedHistoryDataErrorV1> {
        let mut body = self.0;
        body[184] = 1;
        body[192..224].fill(0);
        Self::from_body(body)
    }

    pub fn require_successor(&self, prior: &Self) -> Result<(), ProtectedHistoryDataErrorV1> {
        if self.status() != prior.status() + 1
            || self.0[..184] != prior.0[..184]
            || self.0[224..256] != prior.0[224..256]
        {
            return Err(ProtectedHistoryDataErrorV1::Malformed);
        }
        Ok(())
    }
}

// This fixed response is comparison DATA on the authenticated original
// stream. Its decoder never asserts a reservation or grants a hold/commit.
pub struct Q04PreholdPublicationDataV1([u8; PREHOLD_RESPONSE_BYTES]);

impl Q04PreholdPublicationDataV1 {
    pub fn from_body(
        mut body: [u8; PREHOLD_RESPONSE_BYTES],
        nonce: [u8; 16],
    ) -> Result<Self, Q04HistoryDataErrorV1> {
        finish_record(&mut body, b"AOSQ4J01", None, PREHOLD_RESPONSE_DOMAIN)?;
        Self::decode(&body, nonce)
    }

    pub fn decode(bytes: &[u8], nonce: [u8; 16]) -> Result<Self, Q04HistoryDataErrorV1> {
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
            return Err(Q04HistoryDataErrorV1::ChangedCut);
        }
        super::protected_names::ProtectedJournalNamesV1::from_bytes(&body[400..448])
            .map_err(Q04HistoryDataErrorV1::from)?;
        let total = usize::try_from(read_u32(&body, 448)?).map_err(|_| Q04HistoryDataErrorV1::Bounds)?;
        let chunks = u16::from_be_bytes(fixed(&body, 452));
        let groups = u16::from_be_bytes(fixed(&body, 454));
        let expected_groups = chunks.checked_add(127).ok_or(Q04HistoryDataErrorV1::Bounds)? / 128;
        if total < 3432 || chunks != claim_chunk_count(total)? || groups != expected_groups {
            return Err(Q04HistoryDataErrorV1::Bounds);
        }
        Ok(Self(body))
    }

    pub fn bytes(&self) -> &[u8; PREHOLD_RESPONSE_BYTES] {
        &self.0
    }

    pub fn request_digest(&self) -> ObjectDigest {
        ObjectDigest::from_bytes(fixed(&self.0, 32))
    }

    pub fn original_precut(&self) -> ObjectDigest {
        ObjectDigest::from_bytes(fixed(&self.0, 64))
    }
}

// Canonical DATA construction shares the same fixed header/checksum helper.
// Callers still pass the resulting bytes through the sole complete codec;
// neither this helper nor the decoded value supplies a live owner or grant.
fn finish_record<const SIZE: usize>(
    bytes: &mut [u8; SIZE],
    magic: &[u8; 8],
    phase: Option<u8>,
    domain: &[u8],
) -> Result<(), ProtectedHistoryDataErrorV1> {
    if SIZE < 48 {
        return Err(ProtectedHistoryDataErrorV1::Malformed);
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
) -> Result<[u8; SIZE], ProtectedHistoryDataErrorV1> {
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
        return Err(ProtectedHistoryDataErrorV1::Malformed);
    }
    bytes.try_into().map_err(|_| ProtectedHistoryDataErrorV1::Malformed)
}

fn require_presence(bytes: &[u8], present: bool) -> Result<(), ProtectedHistoryDataErrorV1> {
    if bytes.iter().any(|byte| *byte != 0) != present {
        return Err(ProtectedHistoryDataErrorV1::Malformed);
    }
    Ok(())
}

fn nonzero<const SIZE: usize>(bytes: &[u8], offset: usize) -> Result<[u8; SIZE], ProtectedHistoryDataErrorV1> {
    let end = offset
        .checked_add(SIZE)
        .ok_or(ProtectedHistoryDataErrorV1::Malformed)?;
    let mut reader = BoundedReader::new(bytes, |_| ProtectedHistoryDataErrorV1::Malformed);
    let prefix = reader.bytes(end)?;
    let field = &prefix[offset..end];

    require_presence(field, true)?;
    field.try_into().map_err(|_| ProtectedHistoryDataErrorV1::Malformed)
}

fn fixed<const SIZE: usize>(bytes: &[u8], offset: usize) -> [u8; SIZE] {
    let mut field = [0; SIZE];
    field.copy_from_slice(&bytes[offset..offset + SIZE]);
    field
}

fn read_u32(bytes: &[u8], offset: usize) -> Result<u32, ProtectedHistoryDataErrorV1> {
    Ok(u32::from_be_bytes(read_integer_bytes(bytes, offset)?))
}

fn read_u64(bytes: &[u8], offset: usize) -> Result<u64, ProtectedHistoryDataErrorV1> {
    Ok(u64::from_be_bytes(read_integer_bytes(bytes, offset)?))
}

fn read_integer_bytes<const SIZE: usize>(
    bytes: &[u8],
    offset: usize,
) -> Result<[u8; SIZE], ProtectedHistoryDataErrorV1> {
    let end = offset
        .checked_add(SIZE)
        .ok_or(ProtectedHistoryDataErrorV1::Malformed)?;
    let mut reader = BoundedReader::new(bytes, |_| ProtectedHistoryDataErrorV1::Malformed);
    let prefix = reader.bytes(end)?;
    prefix[offset..end]
        .try_into()
        .map_err(|_| ProtectedHistoryDataErrorV1::Malformed)
}



pub fn claim_chunk_count(total: usize) -> Result<u16, Q04HistoryDataErrorV1> {
    chunk_count(total, MAXIMUM_CLAIM_BYTES)
}

pub fn chunk_count(total: usize, maximum: usize) -> Result<u16, Q04HistoryDataErrorV1> {
    if total == 0 || total > maximum {
        return Err(Q04HistoryDataErrorV1::Bounds);
    }
    let count = total.checked_add(CLAIM_CHUNK_BYTES - 1)
        .ok_or(Q04HistoryDataErrorV1::Bounds)? / CLAIM_CHUNK_BYTES;
    u16::try_from(count).map_err(|_| Q04HistoryDataErrorV1::Bounds)
}
