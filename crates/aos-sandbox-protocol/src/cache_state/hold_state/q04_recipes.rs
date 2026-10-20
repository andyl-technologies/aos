//! Owns the exact Cache Q04 suffix and historical phase comparisons.
//!
//! Construction allocates only transaction DATA. It retains no file, flock,
//! clock, release observation, clearance loan, or paid receiving association.

use std::collections::BTreeMap;

use aos_sandbox_core::{ObjectDigest, RecordNamespace};
use sha2::{Digest as _, Sha256};

use super::{CACHE_PENDING_KEY, HOLD_KEY, decode_full_state};
use crate::domain_ledger::{
    ProtectedHistoryDataErrorV1,
    cache_policy_hold::CachePolicyHoldV1,
    create_q04_history::{
        PENDING_BYTES, Q04CutIdentityV1, Q04PendingOwnerV1, Q04PendingRecordV1,
        Q04TransactionOwnerV1,
        recipes::{Q04RecipeDataErrorV1, lower_clear_recipe_digest_data_v1},
    },
    protected_names::ProtectedJournalNamesV1,
    transaction::{JournalRecord, JournalTransaction},
};

/// Selects a historical Cache observation prefix without mutation permission.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Q04CacheTerminalPhaseV1 {
    /// The original held row and pending marker.
    Held,
    /// The released row with its retained pending marker.
    Released,
    /// The released row after the pending marker was removed.
    Cleared,
}

impl Q04CacheTerminalPhaseV1 {
    /// Returns the number of canonical transactions in this observation prefix.
    pub fn prefix(self) -> usize {
        match self {
            Self::Held => 1,
            Self::Released => 2,
            Self::Cleared => 3,
        }
    }
}

/// Holds the same canonical pending rows and three inert transactions.
pub struct CacheQ04HoldRecipeBodiesDataV1 {
    /// Exact held pending-marker bytes.
    pub held_marker: Q04PendingRecordV1,
    /// Exact released pending-marker bytes.
    pub released_marker: Q04PendingRecordV1,
    /// Exact acquire, release and clear transactions.
    pub transactions: [JournalTransaction; 3],
}

/// Builds the unchanged canonical markers and complete suffix as DATA.
///
/// # Errors
/// Rejects disagreeing historical cut/hold fields or a zero release digest;
/// retains the original marker, hold and transaction codec errors.
pub fn hold_recipe_bodies_data_v1(
    identity: &Q04CutIdentityV1,
    names: ProtectedJournalNamesV1,
    held: CachePolicyHoldV1,
    release_authorization: ObjectDigest,
) -> Result<CacheQ04HoldRecipeBodiesDataV1, Q04RecipeDataErrorV1> {
    if !held.is_held()
        || held.project() != identity.project()
        || held.binding() != identity.binding()
        || held.epoch() != identity.epoch()
        || release_authorization.as_bytes() == &[0; 32]
    {
        return Err(Q04RecipeDataErrorV1::ChangedCut);
    }
    let released = (held).released_data();
    let owner_recipe = ObjectDigest::from_bytes(
        Sha256::new()
            .chain_update(b"aos.sandbox.create-q04.cache-before-owner-recipe.v1\0")
            .chain_update(names.to_bytes())
            .chain_update(held.encode()?)
            .chain_update(released.encode()?)
            .finalize()
            .into(),
    );
    let mut body = [0; PENDING_BYTES];
    body[16..48].copy_from_slice(identity.digest().as_bytes());
    body[48..64].copy_from_slice(&identity.nonce());
    body[64..96].copy_from_slice(identity.binding().as_bytes());
    body[96..104].copy_from_slice(&identity.epoch().to_be_bytes());
    body[104..136].copy_from_slice(held.record_digest()?.as_bytes());
    body[136..168].copy_from_slice(released.record_digest()?.as_bytes());
    body[200..232].copy_from_slice(owner_recipe.as_bytes());
    let held_marker = Q04PendingRecordV1::from_body(Q04PendingOwnerV1::Cache, 1, body)?;
    body[168..200].copy_from_slice(release_authorization.as_bytes());
    let released_marker = Q04PendingRecordV1::from_body(Q04PendingOwnerV1::Cache, 2, body)?;
    released_marker.require_release_of(&held_marker)?;

    let acquire = q04_transaction(
        identity,
        1,
        owner_recipe,
        vec![
            JournalRecord::put(
                RecordNamespace::DesiredState,
                HOLD_KEY.to_vec(),
                held.encode()?.to_vec(),
            ),
            JournalRecord::put(
                RecordNamespace::DesiredState,
                CACHE_PENDING_KEY.to_vec(),
                held_marker.bytes().to_vec(),
            ),
        ],
    )?;
    let release = q04_transaction(
        identity,
        2,
        held_marker.digest(),
        vec![
            JournalRecord::put(
                RecordNamespace::DesiredState,
                HOLD_KEY.to_vec(),
                released.encode()?.to_vec(),
            ),
            JournalRecord::put(
                RecordNamespace::DesiredState,
                CACHE_PENDING_KEY.to_vec(),
                released_marker.bytes().to_vec(),
            ),
        ],
    )?;
    let clear = q04_transaction(
        identity,
        3,
        released_marker.digest(),
        vec![JournalRecord::delete(
            RecordNamespace::DesiredState,
            CACHE_PENDING_KEY.to_vec(),
        )],
    )?;
    Ok(CacheQ04HoldRecipeBodiesDataV1 {
        held_marker,
        released_marker,
        transactions: [acquire, release, clear],
    })
}

/// Retains the original prior/held/release comparisons and suffix DATA.
///
/// A release digest here is a historical comparison field. Its actual Root
/// observation and native writer association must be checked by their owners.
pub struct CacheQ04TransactionRecipesDataV1 {
    release_authorization: Option<ObjectDigest>,
    prior: Option<CachePolicyHoldV1>,
    held: CachePolicyHoldV1,
    bodies: CacheQ04HoldRecipeBodiesDataV1,
}

impl CacheQ04TransactionRecipesDataV1 {
    /// Counts only the additional DATA-return and caller-local header planes.
    ///
    /// The original marker/transaction constructor and final resident wrapper
    /// were already priced. This grouping adds one returned typed Result and
    /// one caller-local DATA value before its move into that same wrapper.
    /// The Vec payloads are moved, never cloned or charged again here.
    pub fn additional_construction_bytes_v1() -> Option<usize> {
        std::mem::size_of::<Result<Self, Q04RecipeDataErrorV1>>()
            .checked_add(std::mem::size_of::<Self>())
    }

    /// Constructs the complete inert suffix with an unbound capacity shape.
    ///
    /// # Errors
    /// Retains the canonical marker, hold and transaction construction refusal.
    pub fn new(
        identity: &Q04CutIdentityV1,
        names: ProtectedJournalNamesV1,
        prior: Option<CachePolicyHoldV1>,
        held: CachePolicyHoldV1,
        release_capacity_shape: ObjectDigest,
    ) -> Result<Self, Q04RecipeDataErrorV1> {
        let bodies = hold_recipe_bodies_data_v1(identity, names, held, release_capacity_shape)?;
        Ok(Self {
            release_authorization: None,
            prior,
            held,
            bodies,
        })
    }

    /// Borrows the exact acquire, release and clear transaction DATA.
    pub fn transactions(&self) -> &[JournalTransaction; 3] {
        &self.bodies.transactions
    }

    /// Returns the historical release comparison, if it has been bound.
    pub fn release_authorization(&self) -> Option<ObjectDigest> {
        self.release_authorization
    }

    /// Rebuilds the suffix with an actual caller-observed release digest.
    ///
    /// # Errors
    /// Rejects reentry or any change to the held marker/acquire transaction,
    /// and retains the canonical construction error. This checks DATA only.
    pub fn bind_release_data_v1(
        &mut self,
        identity: &Q04CutIdentityV1,
        names: ProtectedJournalNamesV1,
        release: ObjectDigest,
    ) -> Result<(), Q04RecipeDataErrorV1> {
        if self.release_authorization.is_some() {
            return Err(Q04RecipeDataErrorV1::ChangedCut);
        }
        let bodies = hold_recipe_bodies_data_v1(identity, names, self.held, release)?;
        if bodies.held_marker != self.bodies.held_marker
            || bodies.transactions[0] != self.bodies.transactions[0]
        {
            return Err(Q04RecipeDataErrorV1::ChangedCut);
        }
        self.bodies.released_marker = bodies.released_marker;
        self.bodies.transactions = bodies.transactions;
        self.release_authorization = Some(release);
        Ok(())
    }

    /// Hashes this suffix's exact clear frames at the original coordinates.
    ///
    /// # Errors
    /// Rejects an unbound release, sequence overflow or canonical framing error.
    pub fn clear_recipe_digest(
        &self,
        identity: &Q04CutIdentityV1,
        names: ProtectedJournalNamesV1,
        original_next: u64,
    ) -> Result<ObjectDigest, Q04RecipeDataErrorV1> {
        if self.release_authorization.is_none() {
            return Err(Q04RecipeDataErrorV1::ChangedCut);
        }
        lower_clear_recipe_digest_data_v1(
            identity,
            Q04TransactionOwnerV1::Cache,
            names,
            original_next
                .checked_add(8)
                .ok_or(Q04RecipeDataErrorV1::SequenceExhausted)?,
            &self.bodies.transactions[2],
        )
    }

    /// Returns the same held/released comparison for the requested prefix.
    pub fn terminal_hold(&self, phase: Q04CacheTerminalPhaseV1) -> CachePolicyHoldV1 {
        if phase == Q04CacheTerminalPhaseV1::Held {
            self.held
        } else {
            self.held.released_data()
        }
    }

    /// Compares the complete historical map against one exact suffix prefix.
    ///
    /// # Errors
    /// Rejects foreign namespaces, malformed history or any phase disagreement.
    pub fn require_prefix(
        &self,
        state: &BTreeMap<(RecordNamespace, Vec<u8>), Vec<u8>>,
        committed: usize,
    ) -> Result<(), ProtectedHistoryDataErrorV1> {
        if state
            .keys()
            .any(|(namespace, _)| *namespace != RecordNamespace::DesiredState)
        {
            return Err(ProtectedHistoryDataErrorV1::Malformed);
        }
        let decoded = decode_full_state(
            state
                .iter()
                .map(|((_, key), value)| (key.as_slice(), value.as_slice())),
        )?;
        if decoded.legacy.v8_pending.is_some() {
            return Err(ProtectedHistoryDataErrorV1::Malformed);
        }
        let expected = match committed {
            0 => decoded.legacy.hold == self.prior && decoded.q04_pending.is_none(),
            1 => {
                decoded.legacy.hold == Some(self.held)
                    && decoded.q04_pending.as_ref() == Some(&self.bodies.held_marker)
            }
            2 => {
                decoded.legacy.hold == Some(self.held.released_data())
                    && decoded.q04_pending.as_ref() == Some(&self.bodies.released_marker)
            }
            3 => {
                decoded.legacy.hold == Some(self.held.released_data())
                    && decoded.q04_pending.is_none()
            }
            _ => false,
        };
        if expected {
            Ok(())
        } else {
            Err(ProtectedHistoryDataErrorV1::Malformed)
        }
    }

    /// Compares the exact transaction and preceding complete historical prefix.
    ///
    /// # Errors
    /// Rejects a changed transaction, unknown phase or disagreeing prior state.
    pub fn require_transition(
        &self,
        state: &BTreeMap<(RecordNamespace, Vec<u8>), Vec<u8>>,
        transaction: &JournalTransaction,
        index: usize,
    ) -> Result<(), ProtectedHistoryDataErrorV1> {
        if self.transactions().get(index) != Some(transaction) {
            return Err(ProtectedHistoryDataErrorV1::Malformed);
        }
        self.require_prefix(state, index)
    }
}

/// Reconstructs and hashes the same Cache clear transaction from historical DATA.
///
/// # Errors
/// Retains cut/codec refusal, sequence overflow and canonical frame errors.
pub fn clear_recipe_digest_data_v1(
    identity: &Q04CutIdentityV1,
    names: ProtectedJournalNamesV1,
    original_next: u64,
    held: CachePolicyHoldV1,
    release_authorization: ObjectDigest,
) -> Result<ObjectDigest, Q04RecipeDataErrorV1> {
    let bodies = hold_recipe_bodies_data_v1(identity, names, held, release_authorization)?;
    lower_clear_recipe_digest_data_v1(
        identity,
        Q04TransactionOwnerV1::Cache,
        names,
        original_next
            .checked_add(8)
            .ok_or(Q04RecipeDataErrorV1::SequenceExhausted)?,
        &bodies.transactions[2],
    )
}

fn q04_transaction(
    identity: &Q04CutIdentityV1,
    phase: u8,
    predecessor: ObjectDigest,
    records: Vec<JournalRecord>,
) -> Result<JournalTransaction, Q04RecipeDataErrorV1> {
    JournalTransaction::new(
        Q04TransactionOwnerV1::Cache.transaction_id(identity, phase, predecessor)?,
        records,
    )
    .map_err(Q04RecipeDataErrorV1::from)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cache_state::fixed_journals::{CACHE_HOLD_GENESIS_KEY_V1, CACHE_HOLD_GENESIS_V1};
    use crate::domain_ledger::create_q04_history::IDENTITY_BYTES;

    // Canonical DATA fixture from the existing original-Q04 regression family.
    // It constructs no writer, release observation, native grant or paid loan.
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

    fn names() -> ProtectedJournalNamesV1 {
        ProtectedJournalNamesV1::from_historical_fields((1, 2), (1, 3), (1, 4))
    }

    fn held(identity: &Q04CutIdentityV1) -> CachePolicyHoldV1 {
        CachePolicyHoldV1::new(
            identity.project(),
            ObjectDigest::from_bytes([31; 32]),
            ObjectDigest::from_bytes([32; 32]),
            identity.binding(),
            identity.epoch(),
        )
        .unwrap()
    }

    fn apply(
        state: &mut BTreeMap<(RecordNamespace, Vec<u8>), Vec<u8>>,
        transaction: &JournalTransaction,
    ) {
        for record in transaction.records() {
            let key = (record.namespace(), record.key().to_vec());
            match record.value() {
                Some(value) => {
                    state.insert(key, value.to_vec());
                }
                None => {
                    state.remove(&key);
                }
            }
        }
    }

    #[test]
    fn exact_three_transaction_prefixes_reject_orphans_and_phase_changes() {
        let identity = identity();
        let held = held(&identity);
        let recipes = CacheQ04TransactionRecipesDataV1::new(
            &identity,
            names(),
            None,
            held,
            ObjectDigest::from_bytes([33; 32]),
        )
        .unwrap();
        let mut state = BTreeMap::from([(
            (
                RecordNamespace::DesiredState,
                CACHE_HOLD_GENESIS_KEY_V1.to_vec(),
            ),
            CACHE_HOLD_GENESIS_V1.to_vec(),
        )]);

        for (index, transaction) in recipes.transactions().iter().enumerate() {
            assert!(
                recipes
                    .require_transition(&state, transaction, index)
                    .is_ok()
            );
            assert!(recipes.require_prefix(&state, index + 1).is_err());
            apply(&mut state, transaction);
        }

        assert!(recipes.require_prefix(&state, 3).is_ok());
        assert!(recipes.require_prefix(&state, 4).is_err());
        assert_eq!(state.len(), 2);
        assert_eq!(
            state.get(&(RecordNamespace::DesiredState, HOLD_KEY.to_vec())),
            Some(&held.released_data().encode().unwrap().to_vec())
        );
        state.insert((RecordNamespace::Idempotency, vec![1]), vec![2]);
        assert!(recipes.require_prefix(&state, 3).is_err());
    }

    #[test]
    fn binding_changes_only_release_suffix_and_same_clear_digest() {
        let identity = identity();
        let held = held(&identity);
        let release = ObjectDigest::from_bytes([34; 32]);
        let mut recipes = CacheQ04TransactionRecipesDataV1::new(
            &identity,
            names(),
            None,
            held,
            ObjectDigest::from_bytes([33; 32]),
        )
        .unwrap();
        let acquire = recipes.transactions()[0].clone();
        assert!(matches!(
            recipes.clear_recipe_digest(&identity, names(), 1),
            Err(Q04RecipeDataErrorV1::ChangedCut)
        ));

        recipes
            .bind_release_data_v1(&identity, names(), release)
            .unwrap();

        assert_eq!(recipes.transactions()[0], acquire);
        assert_eq!(recipes.release_authorization(), Some(release));
        assert_eq!(
            recipes.clear_recipe_digest(&identity, names(), 1).unwrap(),
            clear_recipe_digest_data_v1(&identity, names(), 1, held, release).unwrap()
        );
        assert!(matches!(
            recipes.clear_recipe_digest(&identity, names(), u64::MAX),
            Err(Q04RecipeDataErrorV1::SequenceExhausted)
        ));
        assert!(
            recipes
                .bind_release_data_v1(&identity, names(), release)
                .is_err()
        );
    }

    #[test]
    fn canonical_markers_and_clear_owner_remain_exact() {
        let identity = identity();
        let release = ObjectDigest::from_bytes([34; 32]);
        let bodies =
            hold_recipe_bodies_data_v1(&identity, names(), held(&identity), release).unwrap();

        assert_eq!(&bodies.held_marker.bytes()[..8], b"AOSQ4K01");
        assert_eq!(bodies.held_marker.bytes()[10], 1);
        assert_eq!(bodies.released_marker.bytes()[10], 2);
        assert_eq!(
            &bodies.released_marker.bytes()[168..200],
            release.as_bytes()
        );
        assert!(
            bodies
                .released_marker
                .require_release_of(&bodies.held_marker)
                .is_ok()
        );
        assert!(matches!(
            lower_clear_recipe_digest_data_v1(
                &identity,
                Q04TransactionOwnerV1::Source,
                names(),
                9,
                &bodies.transactions[2]
            ),
            Err(Q04RecipeDataErrorV1::ChangedCut)
        ));
        assert!(matches!(
            lower_clear_recipe_digest_data_v1(
                &identity,
                Q04TransactionOwnerV1::Root,
                names(),
                9,
                &bodies.transactions[2]
            ),
            Err(Q04RecipeDataErrorV1::ChangedCut)
        ));
    }
}
