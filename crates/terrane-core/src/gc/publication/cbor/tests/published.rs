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
}
