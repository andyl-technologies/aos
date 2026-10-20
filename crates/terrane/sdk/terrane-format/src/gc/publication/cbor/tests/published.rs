//! Executes published binding and retained-history inputs against their models.

use super::*;
use crate::gc::publication::published_vectors;

macro_rules! witness {
    ($name:literal, $kind:ty, $model:expr) => {{
        let model = $model;
        let bytes = published_vectors::bytes($name);
        assert_eq!(model.encode().unwrap(), bytes, $name);
        assert_eq!(<$kind>::decode(&bytes).unwrap(), model, $name);
    }};
}

#[test]
fn published_bindings_and_activation_match_described_models() {
    witness!("d79-local-binding", BackendBinding, local());
    witness!(
        "d79-remote-binding",
        BackendBinding,
        BackendBinding::Remote {
            provider: RemoteProvider::S3,
            endpoint: "e".into(),
            bucket: "b".into(),
            prefix: vec![],
            resource_nonce: [1; 32],
            coordination_key: b"k".to_vec(),
            coordination_nonce: [2; 32],
        }
    );
    witness!(
        "d79-registration-pending",
        BackendRegistration,
        BackendRegistration {
            binding: local(),
            activation: Activation::Pending,
            genesis: None,
        }
    );
    witness!(
        "d79-registration-active",
        BackendRegistration,
        BackendRegistration {
            binding: local(),
            activation: Activation::Active,
            genesis: Some([5; 32]),
        }
    );
}

#[test]
fn published_empty_history_preserves_never_and_unknown_distinction() {
    witness!(
        "d79-selection-never",
        CommittedSelection,
        CommittedSelection::Never
    );
    witness!(
        "d79-selection-unknown",
        CommittedSelection,
        CommittedSelection::Unknown
    );
    witness!(
        "d79-empty-history",
        SelectedHistory,
        SelectedHistory {
            branches: vec![],
            origin: local(),
        }
    );
    witness!(
        "d79-selection-whole",
        CommittedSelection,
        CommittedSelection::Selected(published_vectors::legacy_ref().into())
    );
}

#[test]
fn published_state_and_pointers_match_described_models() {
    witness!("d79-empty-state", PublicationState, state(0));
    witness!(
        "d79-publication-current",
        PublicationCurrent,
        PublicationCurrent {
            revision: 0,
            digest: [6; 32],
        }
    );
    witness!("d79-portable-current", PortableCurrent, pointer(0));
    witness!(
        "d79-genesis-commit",
        PublicationCommit,
        PublicationCommit {
            revision: 0,
            predecessor: None,
            transaction_key: format!("publication/transactions/{}", "00".repeat(32)),
            transaction_digest: [1; 32],
        }
    );
}

#[test]
fn published_proof_variants_fix_structural_claims_only() {
    witness!("d79-proof-raw", PublicationProof, PublicationProof::Raw);
    witness!(
        "d79-proof-candidate",
        PublicationProof,
        PublicationProof::Candidate([3; 32])
    );
    witness!(
        "d79-proof-guard",
        PublicationProof,
        PublicationProof::Guard([3; 32])
    );
    witness!(
        "d79-proof-collection-claim",
        PublicationProof,
        PublicationProof::Collection {
            fence_key: "gc/0/fence/0".into(),
            fence_digest: [4; 32],
            removed: vec![],
            carried: vec![],
        }
    );
}

#[test]
fn published_delta_and_next_transaction_match_described_models() {
    witness!(
        "d79-delta-snapshot",
        PortableSnapshot,
        PortableSnapshot {
            revision: 1,
            origin: local(),
            projection: vec![],
            predecessor: Some(pointer(0)),
        }
    );
    witness!(
        "d79-next-transaction",
        PublicationTransaction,
        transaction()
    );
}

#[test]
fn published_missing_genesis_inventory_rejects_independent_wire_inputs() {
    let history = history_value(vec![]);
    let mut snapshot = Vec::new();
    cbor::write_map(&mut snapshot, 5);
    for (key, value) in [(0, 1), (1, 0)] {
        cbor::write_uint(&mut snapshot, key);
        cbor::write_uint(&mut snapshot, value);
    }
    cbor::write_uint(&mut snapshot, 2);
    snapshot.extend_from_slice(&local().encode().unwrap());
    cbor::write_uint(&mut snapshot, 3);
    cbor::write_array(&mut snapshot, 1);
    cbor::write_array(&mut snapshot, 2);
    cbor::write_text(&mut snapshot, "publication/SELECTED-HISTORY");
    cbor::write_bytes(&mut snapshot, &history);
    cbor::write_uint(&mut snapshot, 4);
    snapshot.push(0xf6);

    assert_eq!(
        snapshot,
        published_vectors::bytes("d79-full-snapshot-missing-inventory")
    );
    assert!(PortableSnapshot::decode(&snapshot).is_err());

    let mut transaction = Vec::new();
    cbor::write_map(&mut transaction, 8);
    cbor::write_uint(&mut transaction, 0);
    cbor::write_uint(&mut transaction, 1);
    cbor::write_uint(&mut transaction, 1);
    cbor::write_bytes(&mut transaction, &[0; 32]);
    cbor::write_uint(&mut transaction, 2);
    transaction.push(0xf6);
    cbor::write_uint(&mut transaction, 3);
    cbor::write_bytes(&mut transaction, &state(0).encode().unwrap());
    cbor::write_uint(&mut transaction, 4);
    cbor::write_array(&mut transaction, 0);
    cbor::write_uint(&mut transaction, 5);
    transaction.extend_from_slice(&[0x81, 0]);
    cbor::write_uint(&mut transaction, 6);
    transaction.push(0xf6);
    cbor::write_uint(&mut transaction, 7);
    cbor::write_array(&mut transaction, 2);
    cbor::write_text(&mut transaction, &pointer(0).key);
    cbor::write_bytes(&mut transaction, &pointer(0).digest);

    assert_eq!(
        transaction,
        published_vectors::bytes("d79-genesis-transaction-missing-inventory")
    );
    assert!(PublicationTransaction::decode(&transaction).is_err());
}
