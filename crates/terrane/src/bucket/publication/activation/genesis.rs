//! Builds canonical empty genesis data without granting activation authority.
//!
//! The catalog and staged proposal contain only public record data. Their
//! binding and known-empty inventory must still be justified by the native
//! creator before any record is installed or selected.
//!
//! ```text
//! fixed profile + binding + timestamp -> empty catalog
//! empty catalog + native nonce -> full snapshot + genesis transaction
//! ```

use super::super::{corrupt, digest};
use crate::pack::MergedShard;
use crate::store::StoreFailure;
use std::collections::{BTreeMap, BTreeSet};
use terrane_core::bucket::{BucketCapabilities, GenerationManifest, GenerationShard, StoreProfile};
use terrane_core::gc::publication::{
    BackendBinding, LogicalChange, PortableCurrent, PortableSnapshot, ProjectionEntry,
    PublicationProof, PublicationState, PublicationTransaction, SelectedHistory,
};
use terrane_core::identity::{IdentityKind, TERRANE_V1};

/// Carries the complete empty proposal before its operation nonce is generated.
pub(super) struct EmptyCatalog {
    /// The proposed genesis state, with complete empty burn ownership.
    pub(super) state: PublicationState,
    /// The complete catalog, including explicit physical lease absence.
    pub(super) logical: BTreeMap<String, Option<Vec<u8>>>,
}

/// Carries staged canonical data, without a private registration capability.
pub(super) struct Genesis {
    /// The exact checkpoint body selected by the transaction's portable pointer.
    pub(super) snapshot_bytes: Vec<u8>,
    /// The whole genesis proposal and its exact logical changes.
    pub(super) transaction: PublicationTransaction,
}

/// Builds the existing complete empty catalog from fixed canonical inputs.
///
/// # Errors
/// Rejects inputs that cannot be encoded as supported canonical bucket and
/// publication records, or an invalid empty merged shard.
pub(super) fn catalog(
    profile: StoreProfile,
    binding: BackendBinding,
    timestamp: u64,
) -> Result<EmptyCatalog, StoreFailure> {
    let empty = MergedShard::rebuild(0, 1, &[], &BTreeSet::new(), None, &BTreeSet::new())
        .map_err(|_| corrupt())?
        .encode();
    let index_hash = TERRANE_V1
        .calculate(IdentityKind::Index, &empty)
        .map_err(|_| corrupt())?
        .terrane_v1_digest()
        .map_err(|_| corrupt())?;
    let manifest = GenerationManifest {
        generation: 1,
        shards: vec![GenerationShard {
            shard: 0,
            index_hash,
            index_size: empty.len() as u64,
            filter: None,
        }],
        written_at: timestamp,
        cycle: 0,
        inventory: Some(Vec::new()),
        exclusions: Some(Vec::new()),
        burns: Some(Vec::new()),
    }
    .encode()
    .map_err(|_| corrupt())?;
    let capabilities = BucketCapabilities {
        layout_version: 2,
        create_if_absent: true,
        compare_and_swap: true,
        ranges: true,
        presign: false,
        multi_writer: true,
        probed_at: timestamp,
        generation: Some(1),
        ref_names: Some(Vec::new()),
        publication_protocol: Some(1),
        profile,
    }
    .encode()
    .map_err(|_| corrupt())?;
    let history = SelectedHistory {
        branches: Vec::new(),
        origin: binding.clone(),
    }
    .encode()
    .map_err(|_| corrupt())?;
    let logical = BTreeMap::from([
        ("CAPABILITIES".into(), Some(capabilities)),
        ("gc/lease".into(), None),
        ("objects/index/1/0.idx".into(), Some(empty)),
        ("objects/index/1/MANIFEST".into(), Some(manifest)),
        ("publication/SELECTED-HISTORY".into(), Some(history)),
    ]);
    let state = PublicationState {
        revision: 0,
        loss_generation: 0,
        sources: Vec::new(),
        binding,
        branches: Vec::new(),
        guard: None,
        burn_owners: Some(Vec::new()),
    };
    Ok(EmptyCatalog { state, logical })
}

/// Binds the full empty checkpoint and transaction to a provided native nonce.
///
/// # Errors
/// Rejects noncanonical snapshot data or any disagreement between the whole
/// transaction, its portable pointer and its checkpoint projection.
pub(super) fn stage(catalog: EmptyCatalog, nonce: [u8; 32]) -> Result<Genesis, StoreFailure> {
    let operation: String = nonce.iter().map(|byte| format!("{byte:02x}")).collect();
    let snapshot = PortableSnapshot {
        revision: 0,
        origin: catalog.state.binding.clone(),
        projection: catalog
            .logical
            .iter()
            .map(|(key, value)| ProjectionEntry {
                key: key.clone(),
                value: value.clone(),
            })
            .collect(),
        predecessor: None,
    };
    let snapshot_bytes = snapshot.encode().map_err(|_| corrupt())?;
    let pointer = PortableCurrent {
        key: format!("publication/snapshots/0:{operation}"),
        digest: digest(&snapshot_bytes),
    };
    let transaction = PublicationTransaction {
        nonce,
        old: None,
        new: catalog.state,
        changes: catalog
            .logical
            .into_iter()
            .map(|(key, new)| LogicalChange {
                key,
                expected: None,
                new,
            })
            .collect(),
        proof: PublicationProof::Raw,
        predecessor: None,
        snapshot: pointer,
    };
    transaction
        .check_snapshot(&snapshot_bytes)
        .map_err(|_| corrupt())?;
    Ok(Genesis {
        snapshot_bytes,
        transaction,
    })
}

#[cfg(test)]
mod tests {
    #![allow(
        clippy::unwrap_used,
        reason = "Canonical model fixture assertions intentionally panic."
    )]

    use super::*;
    use terrane_core::gc::publication::PublicationCommit;

    fn inputs() -> (StoreProfile, BackendBinding) {
        (
            StoreProfile {
                identity: "terrane-v1".into(),
                algorithm: "blake3".into(),
                chunk: "cdc-1m".into(),
                seed: [3; 32],
            },
            BackendBinding::Local {
                root: b"/genesis-test".to_vec(),
                root_device: 1,
                root_inode: 2,
                coordination_device: 1,
                coordination_inode: 3,
            },
        )
    }

    #[test]
    fn empty_genesis_has_complete_catalog_and_explicit_lease_absence() {
        let (profile, binding) = inputs();
        let catalog = catalog(profile.clone(), binding.clone(), 41).unwrap();
        assert_eq!(
            catalog
                .logical
                .keys()
                .map(String::as_str)
                .collect::<Vec<_>>(),
            [
                "CAPABILITIES",
                "gc/lease",
                "objects/index/1/0.idx",
                "objects/index/1/MANIFEST",
                "publication/SELECTED-HISTORY",
            ]
        );
        assert_eq!(catalog.logical.get("gc/lease"), Some(&None));
        let bytes = |key: &str| catalog.logical[key].as_deref().unwrap();
        let cap = BucketCapabilities::decode(bytes("CAPABILITIES")).unwrap();
        assert_eq!(cap.profile, profile);
        assert_eq!(cap.probed_at, 41);
        assert_eq!(cap.ref_names, Some(Vec::new()));
        assert_eq!(cap.generation, Some(1));
        assert_eq!(cap.publication_protocol, Some(1));

        let manifest = GenerationManifest::decode(bytes("objects/index/1/MANIFEST")).unwrap();
        assert_eq!(manifest.inventory, Some(Vec::new()));
        assert_eq!(manifest.exclusions, Some(Vec::new()));
        assert_eq!(manifest.burns, Some(Vec::new()));
        assert_eq!(catalog.state.burn_owners, Some(Vec::new()));
        catalog.state.check_manifest_burns(&manifest).unwrap();
        assert_eq!(manifest.written_at, 41);
        let shard = &manifest.shards[0];
        let index = bytes("objects/index/1/0.idx");
        assert_eq!(shard.index_size, index.len() as u64);
        let identity = TERRANE_V1
            .from_digest(IdentityKind::Index, &shard.index_hash)
            .unwrap();
        TERRANE_V1.verify(&identity, index).unwrap();
        MergedShard::decode(index, 1, 0).unwrap();

        let history = SelectedHistory::decode(bytes("publication/SELECTED-HISTORY")).unwrap();
        assert_eq!(history.origin, binding);
        assert_eq!(history.branches, catalog.state.branches);
        assert!(catalog.state.sources.is_empty());
        assert!(catalog.state.guard.is_none());
    }

    #[test]
    fn empty_genesis_validates_exact_snapshot_transaction_and_slot() {
        let (profile, binding) = inputs();
        let proposal = stage(catalog(profile, binding, 41).unwrap(), [5; 32]).unwrap();
        let transaction = proposal.transaction;
        let bytes = transaction.encode().unwrap();
        assert_eq!(PublicationTransaction::decode(&bytes).unwrap(), transaction);
        transaction
            .check_snapshot(&proposal.snapshot_bytes)
            .unwrap();
        let snapshot = PortableSnapshot::decode(&proposal.snapshot_bytes).unwrap();
        assert_eq!(snapshot.projection.len(), transaction.changes.len());
        assert!(snapshot.predecessor.is_none());
        assert!(
            transaction
                .changes
                .iter()
                .all(|change| change.expected.is_none())
        );
        let commit = PublicationCommit {
            revision: 0,
            predecessor: None,
            transaction_key: format!("publication/transactions/{}", "05".repeat(32)),
            transaction_digest: digest(&bytes),
        };
        commit
            .check_transaction("publication/commits/0", &bytes)
            .unwrap();

        let mut missing = snapshot.clone();
        missing.projection.retain(|row| row.key != "CAPABILITIES");
        assert!(missing.encode().is_err());

        let mut contradictory = snapshot;
        let cap_row = contradictory
            .projection
            .iter_mut()
            .find(|row| row.key == "CAPABILITIES")
            .unwrap();
        let mut cap = BucketCapabilities::decode(cap_row.value.as_deref().unwrap()).unwrap();
        cap.probed_at += 1;
        cap_row.value = Some(cap.encode().unwrap());
        let contradictory_bytes = contradictory.encode().unwrap();
        let mut changed = transaction;
        changed.snapshot.digest = digest(&contradictory_bytes);
        assert!(changed.check_snapshot(&contradictory_bytes).is_err());
        let mut wrong_digest = commit;
        wrong_digest.transaction_digest = [0; 32];
        assert!(
            wrong_digest
                .check_transaction("publication/commits/0", &bytes)
                .is_err()
        );
    }
}
