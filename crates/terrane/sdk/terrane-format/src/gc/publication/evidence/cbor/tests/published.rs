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

#[test]
fn published_import_binding_and_trust_match_exact_raw_digests() {
    let import_digest = *blake3::hash(&import_fixture()).as_bytes();
    let binding = OriginalImportBinding {
        commit: [2; 32],
        source: [1; 32],
        destination: [9; 32],
        import_digest,
    };
    witness!("d79-import-binding", OriginalImportBinding, binding.clone());
    binding.check_import(&import_fixture()).unwrap();

    let trust = OriginalImportTrust {
        import_digest,
        source: [1; 32],
        destination: [9; 32],
        issuers: vec![issuer()],
        disclosures: vec![disclosure()],
    };
    witness!("d79-import-trust", OriginalImportTrust, trust.clone());
    trust.check_binding(&binding, &import_fixture()).unwrap();
}

#[test]
fn published_consumed_inputs_and_legacy_lineage_fix_claim_bytes_only() {
    witness!(
        "d79-registration-pin",
        RequiredControlPin,
        registration_pin()
    );
    witness!("d79-used-inputs-claim", LineageUsedInputs, used());

    // This deliberately incomplete legacy claim is structurally encodable.
    // Native qualification must independently refuse its missing authoring
    // context, graph policy and original association/bootstrap dependencies.
    let source = published_vectors::legacy_ref();
    let lineage = CheckedLineage {
        source_name: "refs/tags/_/alias".into(),
        commit_id: source.commit,
        source,
        commit_bytes: legacy_commit_fixture(),
        guard_digest: *blake3::hash(&guard_fixture()).as_bytes(),
        loss_generation: 0,
        controls: vec![registration_pin()],
        original: PhysicalRegistration::Local(local()),
        used: used(),
    };
    witness!("d79-legacy-lineage-claim", CheckedLineage, lineage);
}
