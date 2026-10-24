//! Shares the complete existing fixed HOLD historical state decoder.
//!
//! Native writer claims, exact exclusive-birth COMMIT validation, Q04/V8
//! mutation and settlement purpose gates remain above this DATA decoder.
//! Historical fields cannot construct a live hold owner, capability or grant.
//!
//! ```text
//! desired rows = Genesis | [held/released CachePolicyHold] | [V8/Q04 pending]
//!             | Genesis | exclusive Git birth | exact matching Git fence
//! ```

/// Owns inert Q04 Cache suffix construction and exact historical comparisons.
#[cfg(target_os = "linux")]
pub mod q04_recipes;

#[cfg(target_os = "linux")]
use crate::domain_ledger::create_q04_history::{Q04PendingOwnerV1, Q04PendingRecordV1};
use crate::domain_ledger::{ProtectedHistoryDataErrorV1, cache_policy_hold::CachePolicyHoldV1};
use aos_sandbox_model::ObjectDigest;
#[cfg(target_os = "linux")]
use aos_sandbox_model::format::git_upload_enrollment::{
    GitCoverageBirthFieldsV1, GitCoverageBirthV1, GitCoverageFenceFieldsV1, GitCoverageFenceV1,
    GitCoverageOwnerKindV1,
};
use sha2::{Digest as _, Sha256};

const GENESIS_KEY: &[u8] = super::fixed_journals::CACHE_HOLD_GENESIS_KEY_V1;
const GENESIS: &[u8] = super::fixed_journals::CACHE_HOLD_GENESIS_V1;
/// Identifies the exact saved held/released row.
pub const HOLD_KEY: &[u8] = b"\0aos-cache-policy-hold-v1\0";
/// Identifies the exact V8 pending-settlement row.
pub const V8_PENDING_KEY: &[u8] = b"\0aos-cache-policy-v8-pending-settlement-v1\0";
/// Identifies the exact Q04 held/released-pending row.
pub const CACHE_PENDING_KEY: &[u8] = b"\0aos-cache-q04-pending-v1\0";
/// Identifies the exact exclusive Git birth row.
pub const GIT_BIRTH_KEY: &[u8] = b"\0aos-cache-policy-z-git-birth-v1\0";
/// Identifies the exact matching exclusive Git fence row.
pub const GIT_FENCE_KEY: &[u8] = b"\0aos-cache-policy-z-git-fence-v1\0";
const V8_PENDING_MAGIC: &[u8; 8] = b"AOSCPP08";
const V8_PENDING_CHECKSUM_DOMAIN: &[u8] = b"aos.sandbox.cache-policy-v8-pending.v1\0";
const V8_PENDING_RECORD_BYTES: usize = 152;

/// Retains the exact historical V8 held/released commitments without a grant.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CachePolicyV8PendingSettlementDataV1 {
    /// Exact original binding commitment.
    pub binding: ObjectDigest,
    /// Exact original handoff generation.
    pub epoch: u64,
    /// Exact canonical held-row digest.
    pub held_digest: ObjectDigest,
    /// Exact canonical released-row digest.
    pub released_digest: ObjectDigest,
}

/// Retains the ordinary historical hold and optional V8 pending row.
#[derive(Clone, Copy, Eq, PartialEq)]
pub struct CachePolicyHoldStateDataV1 {
    /// Same optional held/released comparison row.
    pub hold: Option<CachePolicyHoldV1>,
    /// Same optional exact V8 pending-settlement comparison.
    pub v8_pending: Option<CachePolicyV8PendingSettlementDataV1>,
}

/// Carries the complete ordinary historical fixed HOLD readback.
pub struct CachePolicyHoldReadbackDataV1 {
    /// Original ordinary and V8 comparison fields.
    pub legacy: CachePolicyHoldStateDataV1,
    /// Optional canonical generation-one Q04 pending row.
    #[cfg(target_os = "linux")]
    pub q04_pending: Option<Q04PendingRecordV1>,
}

/// Distinguishes the original closed HOLD grammars without live permission.
pub enum CachePolicyDecodedStateDataV1 {
    /// Original ordinary, V8 or Q04 saved rows.
    Ordinary(CachePolicyHoldReadbackDataV1),
    /// Original denial-only exclusive Git coordinates.
    #[cfg(target_os = "linux")]
    Exclusive {
        /// Exact decoded original Git birth coordinates.
        birth: GitCoverageBirthFieldsV1,
        /// Exact decoded original matching fence coordinates.
        fence: GitCoverageFenceFieldsV1,
    },
}

impl CachePolicyV8PendingSettlementDataV1 {
    /// Checks an exact held/released pair as historical DATA.
    ///
    /// # Errors
    /// Rejects malformed framing, phase or saved record correlations.
    pub fn new(
        held: CachePolicyHoldV1,
        released: CachePolicyHoldV1,
    ) -> Result<Self, ProtectedHistoryDataErrorV1> {
        if !held.is_held() || released != ((held).released_data()) {
            return Err(ProtectedHistoryDataErrorV1::Malformed);
        }

        Ok(Self {
            binding: held.binding(),
            epoch: held.epoch(),
            held_digest: held.record_digest()?,
            released_digest: released.record_digest()?,
        })
    }

    /// Checks this saved pending row against its exact released hold.
    ///
    /// # Errors
    /// Rejects malformed framing, phase or saved record correlations.
    pub fn validate_for(
        self,
        released: CachePolicyHoldV1,
    ) -> Result<(), ProtectedHistoryDataErrorV1> {
        if released.is_held() || self != Self::new((released).held_data(), released)? {
            return Err(ProtectedHistoryDataErrorV1::Malformed);
        }
        Ok(())
    }

    /// Encodes the existing canonical V8 pending bytes without side effects.
    pub fn encode(self) -> [u8; V8_PENDING_RECORD_BYTES] {
        let mut bytes = [0_u8; V8_PENDING_RECORD_BYTES];
        bytes[..8].copy_from_slice(V8_PENDING_MAGIC);
        bytes[8..10].copy_from_slice(&1_u16.to_be_bytes());
        bytes[10] = 1;
        bytes[16..48].copy_from_slice(self.binding.as_bytes());
        bytes[48..56].copy_from_slice(&self.epoch.to_be_bytes());
        bytes[56..88].copy_from_slice(self.held_digest.as_bytes());
        bytes[88..120].copy_from_slice(self.released_digest.as_bytes());
        let checksum = Sha256::new()
            .chain_update(V8_PENDING_CHECKSUM_DOMAIN)
            .chain_update(&bytes[..120])
            .finalize();
        bytes[120..].copy_from_slice(&checksum);
        bytes
    }

    /// Decodes the canonical fixed V8 pending row without live authority.
    ///
    /// # Errors
    /// Rejects malformed framing, phase or saved record correlations.
    pub fn decode(bytes: &[u8]) -> Result<Self, ProtectedHistoryDataErrorV1> {
        if bytes.len() != V8_PENDING_RECORD_BYTES
            || bytes.get(..8) != Some(V8_PENDING_MAGIC.as_slice())
            || bytes.get(8..10) != Some(1_u16.to_be_bytes().as_slice())
            || bytes[10] != 1
            || bytes[11..16] != [0; 5]
        {
            return Err(ProtectedHistoryDataErrorV1::Malformed);
        }
        let pending = Self {
            binding: ObjectDigest::from_bytes(
                bytes[16..48]
                    .try_into()
                    .map_err(|_| ProtectedHistoryDataErrorV1::Malformed)?,
            ),
            epoch: u64::from_be_bytes(
                bytes[48..56]
                    .try_into()
                    .map_err(|_| ProtectedHistoryDataErrorV1::Malformed)?,
            ),
            held_digest: ObjectDigest::from_bytes(
                bytes[56..88]
                    .try_into()
                    .map_err(|_| ProtectedHistoryDataErrorV1::Malformed)?,
            ),
            released_digest: ObjectDigest::from_bytes(
                bytes[88..120]
                    .try_into()
                    .map_err(|_| ProtectedHistoryDataErrorV1::Malformed)?,
            ),
        };
        if pending.encode().as_slice() != bytes {
            return Err(ProtectedHistoryDataErrorV1::Malformed);
        }
        Ok(pending)
    }
}

/// Decodes the complete ordinary fixed HOLD state, including Q04 pending DATA.
///
/// # Errors
/// Rejects malformed ordered rows, divergent pending markers or exclusive state.
pub fn decode_full_state<'records>(
    records: impl Iterator<Item = (&'records [u8], &'records [u8])>,
) -> Result<CachePolicyHoldReadbackDataV1, ProtectedHistoryDataErrorV1> {
    match decode_gate_state(records)? {
        CachePolicyDecodedStateDataV1::Ordinary(state) => Ok(state),
        #[cfg(target_os = "linux")]
        CachePolicyDecodedStateDataV1::Exclusive { .. } => {
            Err(ProtectedHistoryDataErrorV1::Malformed)
        }
    }
}

/// Decodes the closed ordinary or exclusive fixed HOLD state as DATA.
///
/// # Errors
/// Rejects malformed ordered rows, invalid envelopes or divergent pending joins.
pub fn decode_gate_state<'records>(
    mut records: impl Iterator<Item = (&'records [u8], &'records [u8])>,
) -> Result<CachePolicyDecodedStateDataV1, ProtectedHistoryDataErrorV1> {
    if records.next() != Some((GENESIS_KEY, GENESIS)) {
        return Err(ProtectedHistoryDataErrorV1::Malformed);
    }
    let hold = match records.next() {
        Some((HOLD_KEY, value)) => Some(CachePolicyHoldV1::decode(value)?),
        #[cfg(target_os = "linux")]
        Some((GIT_BIRTH_KEY, value)) => {
            let birth = GitCoverageBirthV1::decode(value)
                .map_err(|_| ProtectedHistoryDataErrorV1::Malformed)?;
            let fence_value = match records.next() {
                Some((GIT_FENCE_KEY, value)) => value,
                _ => return Err(ProtectedHistoryDataErrorV1::Malformed),
            };
            let fence = GitCoverageFenceV1::decode(fence_value)
                .map_err(|_| ProtectedHistoryDataErrorV1::Malformed)?;
            fence
                .compare_birth(&birth)
                .map_err(|_| ProtectedHistoryDataErrorV1::Malformed)?;
            if records.next().is_some()
                || birth.fields().owner != GitCoverageOwnerKindV1::CacheAuthority
            {
                return Err(ProtectedHistoryDataErrorV1::Malformed);
            }
            return Ok(CachePolicyDecodedStateDataV1::Exclusive {
                birth: birth.fields(),
                fence: fence.fields(),
            });
        }
        Some(_) => return Err(ProtectedHistoryDataErrorV1::Malformed),
        None => None,
    };
    #[cfg(target_os = "linux")]
    let mut q04_pending = None;
    let v8_pending = match records.next() {
        Some((V8_PENDING_KEY, value)) => Some(CachePolicyV8PendingSettlementDataV1::decode(value)?),
        #[cfg(target_os = "linux")]
        Some((CACHE_PENDING_KEY, value)) => {
            q04_pending = Some(Q04PendingRecordV1::decode(Q04PendingOwnerV1::Cache, value)?);
            None
        }
        Some(_) => return Err(ProtectedHistoryDataErrorV1::Malformed),
        None => None,
    };
    if records.next().is_some() {
        return Err(ProtectedHistoryDataErrorV1::Malformed);
    }
    if let Some(pending) = v8_pending {
        pending.validate_for(hold.ok_or(ProtectedHistoryDataErrorV1::Malformed)?)?;
    }
    #[cfg(target_os = "linux")]
    if let Some(marker) = &q04_pending {
        let row = hold.ok_or(ProtectedHistoryDataErrorV1::Malformed)?;
        let held = (row).held_data();
        let released = (row).released_data();
        if marker.is_held() != row.is_held()
            || marker.bytes()[64..96] != *row.binding().as_bytes()
            || marker.bytes()[96..104] != row.epoch().to_be_bytes()
            || marker.bytes()[104..136] != *held.record_digest()?.as_bytes()
            || marker.bytes()[136..168] != *released.record_digest()?.as_bytes()
        {
            return Err(ProtectedHistoryDataErrorV1::Malformed);
        }
    }
    Ok(CachePolicyDecodedStateDataV1::Ordinary(
        CachePolicyHoldReadbackDataV1 {
            legacy: CachePolicyHoldStateDataV1 { hold, v8_pending },
            #[cfg(target_os = "linux")]
            q04_pending,
        },
    ))
}
