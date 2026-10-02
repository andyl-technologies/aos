//! Executes published D-79 inputs against independently constructed models.

use super::*;
use crate::gc::publication::{BackendBinding, RemoteProvider, published_vectors};

macro_rules! witness {
    ($name:literal, $kind:ty, $model:expr) => {{
        let model = $model;
        let bytes = published_vectors::bytes($name);
        assert_eq!(model.encode().unwrap(), bytes, $name);
        assert_eq!(<$kind>::decode(&bytes).unwrap(), model, $name);
    }};
}

#[test]
fn published_original_and_trust_vectors_match_described_models() {
    witness!("d79-local-original", LocalOriginalRegistration, local());
    witness!("d79-bootstrap", OriginalBootstrap, bootstrap());
    witness!("d79-association", OriginalAssociation, association());
    witness!("d79-local-import", OriginalImport, import());
    witness!("d79-issuer-row", IssuerRow, issuer());
    witness!("d79-disclosure-row", DisclosureRow, disclosure());

    let remote = PhysicalRegistration::Remote(RemoteOriginalRegistration {
        original_id: [1; 32],
        domain: "public".into(),
        control: b"c".to_vec(),
        binding: BackendBinding::Remote {
            provider: RemoteProvider::S3,
            endpoint: "e".into(),
            bucket: "b".into(),
            prefix: vec![],
            resource_nonce: [3; 32],
            coordination_key: b"k".to_vec(),
            coordination_nonce: [4; 32],
        },
    });
    witness!("d79-remote-original", PhysicalRegistration, remote.clone());
    witness!(
        "d79-remote-import",
        OriginalImport,
        OriginalImport {
            version: ImportVersion::PhysicalV2,
            registration: remote,
            bootstrap: bootstrap(),
            association: association(),
        }
    );
}

#[test]
fn published_guard_and_policy_vectors_match_described_models() {
    witness!("d79-seeded-profile", SeededChunkProfile, profile());
    witness!("d79-guard-config", TrustedGuardConfig, config());
    witness!("d79-registries", ConfiguredRegistryInputs, registries());
    witness!("d79-guard-snapshot", GuardSnapshot, guard());

    let root = ConsumedRootPolicy {
        root: [8; 32],
        path: b"/".to_vec(),
        layers: vec![ConsumedRootLayer {
            properties: vec![0xa0],
            overrides: vec![0xa0],
        }],
    };
    witness!("d79-root-policy", ConsumedRootPolicy, root.clone());
    witness!(
        "d79-view-policy",
        ConsumedViewPolicy,
        ConsumedViewPolicy {
            view: [9; 32],
            default_domain: "public".into(),
            roots: vec![root],
        }
    );
}
