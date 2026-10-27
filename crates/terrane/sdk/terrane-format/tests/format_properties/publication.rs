//! Generates untrusted publication and retained-evidence byte-format models.

use super::{
    records,
    support::{Generator, check_record},
};
use terrane_format::cbor;
use terrane_format::gc::publication::evidence::*;
use terrane_format::gc::publication::reconciliation::LocalGcReconciliation;
use terrane_format::gc::publication::*;
use terrane_format::properties::PropertyName;
use terrane_format::refs::Locality;

/// Builds alternating local and remote backend binding models from a case number.
pub(super) fn binding(case: usize) -> BackendBinding {
    if case.is_multiple_of(2) {
        BackendBinding::Local {
            root: format!("/bucket-{case}").into_bytes(),
            root_device: case as u64,
            root_inode: u64::MAX,
            coordination_device: 0,
            coordination_inode: 1,
        }
    } else {
        BackendBinding::Remote {
            provider: if case.is_multiple_of(3) {
                RemoteProvider::Gcs
            } else {
                RemoteProvider::S3
            },
            endpoint: format!("endpoint-{case}"),
            bucket: format!("bucket-{case}"),
            prefix: if case.is_multiple_of(3) {
                vec![]
            } else {
                b"opaque-prefix/".to_vec()
            },
            resource_nonce: [1; 32],
            coordination_key: b"coordination".to_vec(),
            coordination_nonce: [2; 32],
        }
    }
}

fn state(case: usize, revision: u64) -> PublicationState {
    PublicationState {
        revision,
        loss_generation: case as u64,
        sources: vec![],
        binding: binding(case),
        branches: vec![],
        guard: (case.is_multiple_of(2)).then_some([3; 32]),
        burn_owners: (case.is_multiple_of(3)).then(Vec::new),
    }
}

fn pointer(revision: u64) -> PortableCurrent {
    PortableCurrent {
        key: format!("publication/snapshots/{revision}:{}", "00".repeat(32)),
        digest: [7; 32],
    }
}

#[test]
fn publication_models_preserve_binding_selection_pointers_and_transaction_fields() {
    let mut generator = Generator::new(0xf31a_c57d_44a0_9023);
    for case in 0..12 {
        check_record!("backend binding", binding(case), BackendBinding);
        for activation in [Activation::Pending, Activation::Active] {
            check_record!(
                "backend registration",
                BackendRegistration {
                    binding: binding(case),
                    activation,
                    genesis: if activation == Activation::Active || case % 2 == 0 {
                        Some(generator.bytes())
                    } else {
                        None
                    }
                },
                BackendRegistration
            );
        }
        let selection = match case % 3 {
            0 => CommittedSelection::Never,
            1 => CommittedSelection::Unknown,
            _ => CommittedSelection::Selected(Box::new(records::head(1))),
        };
        check_record!("committed selection", selection.clone(), CommittedSelection);
        check_record!(
            "selected history",
            SelectedHistory {
                branches: vec![HistoryEntry {
                    name: "refs/heads/_/main".into(),
                    selection
                }],
                origin: binding(case)
            },
            SelectedHistory
        );
        check_record!("portable current", pointer(case as u64), PortableCurrent);
        check_record!(
            "portable delta snapshot",
            PortableSnapshot {
                revision: case as u64 + 1,
                origin: binding(case),
                projection: vec![ProjectionEntry {
                    key: "refs/tags/_/snapshot:record".into(),
                    value: if case % 2 == 0 {
                        Some(records::head(1).encode().unwrap())
                    } else {
                        None
                    }
                }],
                predecessor: Some(pointer(case as u64))
            },
            PortableSnapshot
        );
        check_record!(
            "publication state",
            state(case, case as u64),
            PublicationState
        );
        check_record!(
            "publication current",
            PublicationCurrent {
                revision: generator.next(),
                digest: generator.bytes()
            },
            PublicationCurrent
        );
        check_record!(
            "publication commit",
            PublicationCommit {
                revision: case as u64,
                predecessor: (case > 0).then(|| generator.bytes()),
                transaction_key: format!("publication/transactions/{}", "00".repeat(32)),
                transaction_digest: generator.bytes()
            },
            PublicationCommit
        );
        for proof in [
            PublicationProof::Raw,
            PublicationProof::Candidate(generator.bytes()),
            PublicationProof::Guard(generator.bytes()),
            PublicationProof::Collection {
                fence_key: format!("gc/{case}/fence/0"),
                fence_digest: generator.bytes(),
                removed: vec![RemovedPack {
                    pack: generator.bytes(),
                    index: generator.bytes(),
                }],
                carried: vec![],
            },
        ] {
            check_record!("publication proof", proof, PublicationProof);
        }
        check_record!(
            "publication transaction",
            PublicationTransaction {
                nonce: [0; 32],
                old: Some(state(case, case as u64)),
                new: state(case, case as u64 + 1),
                changes: vec![],
                proof: PublicationProof::Raw,
                predecessor: Some(PredecessorSlot {
                    revision: case as u64,
                    digest: generator.bytes()
                }),
                snapshot: pointer(case as u64 + 1)
            },
            PublicationTransaction
        );
    }
}

fn registration(case: usize, original_id: [u8; 32]) -> PhysicalRegistration {
    if case.is_multiple_of(2) {
        PhysicalRegistration::Local(LocalOriginalRegistration {
            original_id,
            root: b"/root".to_vec(),
            domain: "public".into(),
            root_device: case as u64,
            root_inode: u64::MAX,
            coordination_device: 0,
            coordination_inode: 1,
            control: b"/control".to_vec(),
        })
    } else {
        PhysicalRegistration::Remote(RemoteOriginalRegistration {
            original_id,
            domain: "public".into(),
            binding: binding(case),
            control: b"original-control".to_vec(),
        })
    }
}

// PROP-30 fixes this historical vocabulary independently of compiled registrations.
const REVISION_ONE_NAMES: [&str; 33] = [
    "acl",
    "baseline",
    "chunk",
    "classify",
    "compaction_threshold",
    "compression",
    "dedup",
    "degraded",
    "domain",
    "durability",
    "encryption",
    "gap_merge_bytes",
    "hashes",
    "home",
    "index",
    "merge",
    "on-release",
    "passthrough",
    "prefetch",
    "quota",
    "reassembly",
    "redundancy",
    "reflog_retain",
    "replicate",
    "retain",
    "span_max_bytes",
    "store",
    "strict-attrs",
    "trust",
    "warm",
    "whole_pack_threshold",
    "wipe",
    "writers",
];

fn registries() -> ConfiguredRegistryInputs {
    let names = REVISION_ONE_NAMES
        .iter()
        .map(|name| (*name).into())
        .collect();
    ConfiguredRegistryInputs {
        property_revision: 1,
        behavioral_properties: names,
        attribute_revision: 1,
        selector_revision: 1,
        tree_revision: 1,
        chunk_revision: 1,
        identity_profile: "terrane-v1".into(),
        later_properties: vec![],
    }
}

// Assemble the schema from ordinary data rather than a revision-selection helper.
fn registry_wire(model: &ConfiguredRegistryInputs) -> Vec<u8> {
    let mut bytes = vec![];
    cbor::write_map(&mut bytes, 9);
    for (key, revision) in [(0, 1), (1, model.property_revision)] {
        cbor::write_uint(&mut bytes, key);
        cbor::write_uint(&mut bytes, revision);
    }
    cbor::write_uint(&mut bytes, 2);
    cbor::write_array(&mut bytes, model.behavioral_properties.len());
    for name in &model.behavioral_properties {
        cbor::write_text(&mut bytes, name);
    }
    for (key, revision) in [
        (3, model.attribute_revision),
        (4, model.selector_revision),
        (5, model.tree_revision),
        (6, model.chunk_revision),
    ] {
        cbor::write_uint(&mut bytes, key);
        cbor::write_uint(&mut bytes, revision);
    }
    cbor::write_uint(&mut bytes, 7);
    cbor::write_text(&mut bytes, &model.identity_profile);
    cbor::write_uint(&mut bytes, 8);
    cbor::write_array(&mut bytes, model.later_properties.len());
    for name in &model.later_properties {
        cbor::write_text(&mut bytes, name);
    }
    bytes
}

fn assert_registry_refuses(model: &ConfiguredRegistryInputs) {
    assert!(model.encode().is_err());
    assert!(ConfiguredRegistryInputs::decode(&registry_wire(model)).is_err());
}

#[test]
fn configured_registry_models_bind_exact_historical_and_current_vocabularies() {
    let legacy = registries();
    assert_eq!(legacy.behavioral_properties.len(), 33);
    check_record!(
        "historical property revision",
        legacy.clone(),
        ConfiguredRegistryInputs
    );

    let mut current = legacy.clone();
    current.property_revision = 2;
    current.behavioral_properties.push("index-roots".into());
    current.behavioral_properties.sort();
    assert_eq!(current.behavioral_properties.len(), 34);
    let previous = current.clone();
    current.property_revision = 3;
    current.attribute_revision = 2;
    current.behavioral_properties.push("index-gaps".into());
    current.behavioral_properties.sort();
    assert_eq!(current.behavioral_properties.len(), 35);
    let mut compiled: Vec<_> = PropertyName::ALL.iter().map(|name| name.as_str()).collect();
    compiled.sort();
    assert_eq!(current.behavioral_properties, compiled);
    check_record!(
        "current property revision",
        current.clone(),
        ConfiguredRegistryInputs
    );

    for model in [legacy.clone(), previous.clone(), current.clone()] {
        let wire = registry_wire(&model);
        assert_eq!(model.encode().unwrap(), wire);
        assert_eq!(ConfiguredRegistryInputs::decode(&wire).unwrap(), model);
        let mut later = model;
        later.later_properties = vec!["later.generated".into()];
        check_record!(
            "revision-specific later property",
            later,
            ConfiguredRegistryInputs
        );
    }
    let mut historical_later = legacy.clone();
    historical_later.later_properties = vec!["index-roots".into()];
    check_record!(
        "historical inert recognized name",
        historical_later,
        ConfiguredRegistryInputs
    );

    for mut mismatch in [legacy.clone(), previous.clone(), current.clone()] {
        mismatch.property_revision = if mismatch.property_revision == 1 {
            2
        } else {
            1
        };
        assert_registry_refuses(&mismatch);
    }
    for revision in [0, 4, u64::MAX] {
        let mut unknown = current.clone();
        unknown.property_revision = revision;
        assert_registry_refuses(&unknown);
    }
    let mut missing = current.clone();
    missing.behavioral_properties.pop();
    assert_registry_refuses(&missing);
    let mut extra = legacy;
    extra.behavioral_properties.push("later.generated".into());
    extra.behavioral_properties.sort();
    assert_registry_refuses(&extra);
    current.later_properties = vec!["index-roots".into()];
    assert_registry_refuses(&current);
}

fn configuration(seed: [u8; 32]) -> TrustedGuardConfig {
    TrustedGuardConfig {
        store_name: "store".into(),
        private_domain_hint: "private:hint".into(),
        home: Locality::default(),
        initial_acl: vec![
            AuthorityGrant {
                principal: "principal".into(),
                verbs: 1,
            },
            AuthorityGrant {
                principal: "principal".into(),
                verbs: 1,
            },
        ],
        minimum_chunk_size: 262144,
        storage_domain: "public".into(),
        chunk_profile_name: "cdc-1m".into(),
        chunk_profile: SeededChunkProfile {
            minimum: 262144,
            target: 1048576,
            maximum: 4194304,
            window: 48,
            normalization: 2,
            seed,
        },
        policy_authority: None,
    }
}

#[test]
fn retained_evidence_models_preserve_ordered_claims_seed_and_null_fields() {
    let mut generator = Generator::new(0x7134_be25_017c_9872);
    for case in 0..12 {
        let original_id = generator.bytes();
        let registration = registration(case, original_id);
        if let PhysicalRegistration::Local(local) = &registration {
            check_record!(
                "local original registration",
                local.clone(),
                LocalOriginalRegistration
            );
        }
        check_record!(
            "physical original registration",
            registration.clone(),
            PhysicalRegistration
        );
        let bootstrap = OriginalBootstrap {
            original_id,
            ref_name: "refs/heads/_/main".into(),
            epoch: case as u64,
            acl: vec![
                AuthorityGrant {
                    principal: "principal".into(),
                    verbs: 0,
                },
                AuthorityGrant {
                    principal: "principal".into(),
                    verbs: 31,
                },
            ],
        };
        check_record!("original bootstrap", bootstrap.clone(), OriginalBootstrap);
        let association = OriginalAssociation {
            original_id,
            ref_name: bootstrap.ref_name.clone(),
            epoch: bootstrap.epoch,
            commit: generator.bytes(),
        };
        check_record!(
            "original association",
            association.clone(),
            OriginalAssociation
        );
        let import = OriginalImport {
            version: if case % 2 == 0 {
                ImportVersion::LocalV1
            } else {
                ImportVersion::PhysicalV2
            },
            registration: registration.clone(),
            bootstrap,
            association: association.clone(),
        };
        check_record!("original import", import.clone(), OriginalImport);
        let import_digest = *blake3::hash(&import.encode().unwrap()).as_bytes();
        let destination = generator.bytes();
        check_record!(
            "original import binding",
            OriginalImportBinding {
                commit: association.commit,
                source: original_id,
                destination,
                import_digest
            },
            OriginalImportBinding
        );
        let issuer = IssuerRow {
            issuer: "issuer".into(),
            key_id: format!("key-{case}"),
            public_key: generator.bytes(),
            retired_at: (case % 2 == 0).then(|| generator.next()),
        };
        check_record!("issuer row", issuer.clone(), IssuerRow);
        let disclosure = DisclosureRow {
            repository: "01".repeat(32),
            domain: "public".into(),
            public_key: generator.bytes(),
            not_before: case as u64,
            not_after: (case % 2 == 0).then_some(u64::MAX),
        };
        check_record!("disclosure row", disclosure.clone(), DisclosureRow);
        check_record!(
            "import trust",
            OriginalImportTrust {
                import_digest,
                source: original_id,
                destination,
                issuers: vec![issuer.clone()],
                disclosures: vec![disclosure.clone()]
            },
            OriginalImportTrust
        );
        let config = configuration(generator.bytes());
        check_record!(
            "seeded chunk profile",
            config.chunk_profile.clone(),
            SeededChunkProfile
        );
        check_record!("guard configuration", config.clone(), TrustedGuardConfig);
        let registries = registries();
        check_record!(
            "configured registry inputs",
            registries.clone(),
            ConfiguredRegistryInputs
        );
        let guard = GuardSnapshot {
            registration: registration.clone(),
            issuers: vec![issuer.clone()],
            disclosures: vec![disclosure.clone()],
            configuration: config.clone(),
            registries: registries.clone(),
        };
        check_record!("guard snapshot", guard.clone(), GuardSnapshot);
        let pin = RequiredControlPin {
            kind: ControlKind::Registration,
            owner: registration.clone(),
            key: "registration.cbor".into(),
            digest: generator.bytes(),
        };
        check_record!("control pin", pin.clone(), RequiredControlPin);
        let root = ConsumedRootPolicy {
            root: generator.bytes(),
            path: b"/".to_vec(),
            layers: vec![ConsumedRootLayer {
                properties: vec![0xa0],
                overrides: vec![0xa0],
            }],
        };
        check_record!("consumed root policy", root.clone(), ConsumedRootPolicy);
        let view = ConsumedViewPolicy {
            view: generator.bytes(),
            default_domain: "public".into(),
            roots: vec![root],
        };
        check_record!("consumed view policy", view.clone(), ConsumedViewPolicy);
        let used = LineageUsedInputs {
            issuers: vec![issuer],
            disclosures: vec![disclosure],
            controls: vec![pin.clone()],
            registries,
            configuration: config,
            views: vec![view],
            view_interpretations: None,
        };
        check_record!("lineage used inputs", used.clone(), LineageUsedInputs);
        let mut commit = records::commit(&mut generator, case);
        commit.signature = Some(generator.bytes());
        let mut source = records::head(1);
        source.commit = commit.identity().unwrap();
        let lineage = CheckedLineage {
            source_name: "refs/heads/_/main".into(),
            commit_id: source.commit,
            source,
            commit_bytes: commit.encode().unwrap(),
            guard_digest: *blake3::hash(&guard.encode().unwrap()).as_bytes(),
            loss_generation: case as u64,
            controls: vec![pin],
            original: registration,
            used,
        };
        check_record!("checked lineage representation", lineage, CheckedLineage);
    }
}

#[test]
fn portable_full_checkpoint_models_require_complete_capabilities_and_retained_history() {
    use terrane_format::bucket::{BucketCapabilities, GenerationManifest, StoreProfile};
    let mut generator = Generator::new(0x488a_942e_e77b_241b);
    for case in 0..6 {
        let origin = binding(case);
        let capabilities = BucketCapabilities {
            layout_version: 2,
            create_if_absent: true,
            compare_and_swap: true,
            ranges: true,
            presign: false,
            multi_writer: true,
            probed_at: generator.next(),
            profile: StoreProfile {
                identity: "terrane-v1".into(),
                algorithm: "blake3".into(),
                chunk: "cdc-1m".into(),
                seed: generator.bytes(),
            },
            generation: Some(1),
            ref_names: Some(vec!["refs/heads/_/main".into()]),
            publication_protocol: Some(1),
        };
        let manifest = GenerationManifest {
            generation: 1,
            shards: vec![],
            written_at: generator.next(),
            cycle: case as u64,
            inventory: Some(vec![]),
            exclusions: Some(vec![]),
            burns: Some(vec![]),
        };
        let head = records::head(1);
        let history = SelectedHistory {
            branches: vec![HistoryEntry {
                name: "refs/heads/_/main".into(),
                selection: if case % 2 == 0 {
                    CommittedSelection::Selected(Box::new(head.clone()))
                } else {
                    CommittedSelection::Never
                },
            }],
            origin: origin.clone(),
        };
        let model = PortableSnapshot {
            revision: case as u64,
            origin,
            projection: vec![
                ProjectionEntry {
                    key: "CAPABILITIES".into(),
                    value: Some(capabilities.encode().unwrap()),
                },
                ProjectionEntry {
                    key: "gc/lease".into(),
                    value: None,
                },
                ProjectionEntry {
                    key: "objects/index/1/MANIFEST".into(),
                    value: Some(manifest.encode().unwrap()),
                },
                ProjectionEntry {
                    key: "publication/SELECTED-HISTORY".into(),
                    value: Some(history.encode().unwrap()),
                },
                ProjectionEntry {
                    key: "refs/heads/_/main:record".into(),
                    value: (case % 2 == 0).then(|| head.encode().unwrap()),
                },
            ],
            predecessor: None,
        };
        check_record!("portable full checkpoint", model.clone(), PortableSnapshot);
        let mut invalid = model;
        invalid.projection.remove(0);
        assert!(invalid.encode().is_err());
    }
}

#[test]
fn evidence_control_selectors_and_optional_configuration_fields_preserve_models() {
    let mut generator = Generator::new(0x7e31_558f_bce2_954b);
    for case in 0..6 {
        let owner = registration(case, generator.bytes());
        let original = owner
            .original_id()
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>();
        for (kind, key) in [
            (ControlKind::Registration, "registration.cbor".to_string()),
            (
                ControlKind::Bootstrap,
                format!("bootstrap-{original}-{}-{}.cbor", "00".repeat(32), u64::MAX),
            ),
            (
                ControlKind::Association,
                format!("commit-{}.cbor", "01".repeat(32)),
            ),
            (
                ControlKind::Import,
                format!("import-{}.cbor", "01".repeat(32)),
            ),
            (
                ControlKind::ImportBinding,
                format!("import-binding-{}.cbor", "01".repeat(32)),
            ),
            (
                ControlKind::ImportTrust,
                format!("import-trust-{}.cbor", "01".repeat(32)),
            ),
        ] {
            let model = RequiredControlPin {
                kind,
                owner: owner.clone(),
                key,
                digest: generator.bytes(),
            };
            check_record!("control selector", model.clone(), RequiredControlPin);
            let mut invalid = model;
            invalid.key.push('/');
            assert!(invalid.encode().is_err());
        }
        let mut config = configuration(generator.bytes());
        config.home = Locality {
            region: Some("region".into()),
            zone: Some("zone".into()),
            host: Some("host".into()),
        };
        config.policy_authority = Some("policy-owner".into());
        check_record!("complete guard configuration", config, TrustedGuardConfig);
        let mut registry = registries();
        registry.later_properties = vec!["later.generated".into()];
        check_record!(
            "inert later registry name",
            registry,
            ConfiguredRegistryInputs
        );
        let bootstrap = OriginalBootstrap {
            original_id: *owner.original_id(),
            ref_name: "refs/heads/_/main".into(),
            epoch: u64::MAX,
            acl: vec![],
        };
        let association = OriginalAssociation {
            original_id: *owner.original_id(),
            ref_name: bootstrap.ref_name.clone(),
            epoch: bootstrap.epoch,
            commit: generator.bytes(),
        };
        check_record!(
            "v2 import local or remote",
            OriginalImport {
                version: ImportVersion::PhysicalV2,
                registration: owner,
                bootstrap,
                association
            },
            OriginalImport
        );
        let layer = ConsumedRootLayer {
            properties: vec![0xa0],
            overrides: vec![0xa0],
        };
        let root = ConsumedRootPolicy {
            root: generator.bytes(),
            path: format!("/{}", super::support::maximum_key()).into_bytes(),
            layers: vec![layer; 65],
        };
        check_record!(
            "maximum policy occurrence",
            root.clone(),
            ConsumedRootPolicy
        );
        check_record!(
            "repeated equal policy occurrence",
            ConsumedViewPolicy {
                view: generator.bytes(),
                default_domain: "private:generated".into(),
                roots: vec![root.clone(), root.clone()]
            },
            ConsumedViewPolicy
        );
        let mut invalid = root;
        invalid.layers.push(invalid.layers[0].clone());
        assert!(invalid.encode().is_err());
        check_record!(
            "empty consumed views",
            ConsumedViewPolicy {
                view: generator.bytes(),
                default_domain: "public".into(),
                roots: vec![]
            },
            ConsumedViewPolicy
        );
    }
}

#[test]
fn publication_nonempty_sources_changes_and_genesis_fields_have_unique_bytes() {
    let mut generator = Generator::new(0xf26c_177d_960a_ce52);
    for case in 0..6 {
        let mut model = state(case, generator.next());
        model.guard = Some(generator.bytes());
        model.branches = ["conflicts", "derived", "heads", "jobs"]
            .into_iter()
            .map(|class| HistoryEntry {
                name: if class == "conflicts" {
                    "refs/conflicts/_/main/00000000000000000001".into()
                } else {
                    format!("refs/{class}/_/main")
                },
                selection: CommittedSelection::Selected(Box::new(records::head(1))),
            })
            .collect();
        model.sources = model
            .branches
            .iter()
            .map(|row| SourceLineage {
                name: row.name.clone(),
                digest: generator.bytes(),
            })
            .collect();
        model.sources.push(SourceLineage {
            name: "refs/tags/_/tag".into(),
            digest: generator.bytes(),
        });
        model.burn_owners = Some(vec![terrane_format::gc::retirement::PermanentBurnOwner {
            pack: [1; 16],
            selection: terrane_format::gc::retirement::PermanentOwnerSelection::CopiedVisibility,
        }]);
        check_record!(
            "nonempty publication state",
            model.clone(),
            PublicationState
        );
        check_record!(
            "collection carried lineage",
            PublicationProof::Collection {
                fence_key: "gc/0/fence/0".into(),
                fence_digest: generator.bytes(),
                removed: vec![],
                carried: model.sources
            },
            PublicationProof
        );
        let history = SelectedHistory {
            branches: vec![],
            origin: binding(case),
        };
        let changes = vec![
            LogicalChange {
                key: "CAPABILITIES".into(),
                expected: None,
                new: Some(vec![0xa0]),
            },
            LogicalChange {
                key: "gc/lease".into(),
                expected: None,
                new: None,
            },
            LogicalChange {
                key: "publication/SELECTED-HISTORY".into(),
                expected: None,
                new: Some(history.encode().unwrap()),
            },
        ];
        check_record!(
            "genesis transaction",
            PublicationTransaction {
                nonce: [0; 32],
                old: None,
                new: state(case, 0),
                changes,
                proof: PublicationProof::Raw,
                predecessor: None,
                snapshot: pointer(0),
            },
            PublicationTransaction
        );
        for (expected, new) in [
            (None, Some(vec![0xf4])),
            (Some(vec![0xf4]), None),
            (Some(vec![0xf4]), Some(vec![0xf5])),
        ] {
            check_record!(
                "opaque note change",
                PublicationTransaction {
                    nonce: [0; 32],
                    old: Some(state(case, 1)),
                    new: state(case, 2),
                    changes: vec![LogicalChange {
                        key: "refs/notes/profiles/_/note:record".into(),
                        expected,
                        new
                    }],
                    proof: PublicationProof::Raw,
                    predecessor: Some(PredecessorSlot {
                        revision: 1,
                        digest: generator.bytes()
                    }),
                    snapshot: pointer(2),
                },
                PublicationTransaction
            );
        }
    }
}

fn interpretation_fields_wire(
    view: &[u8],
    original_root: &[u8],
    mode: u64,
    registry: &ConfiguredRegistryInputs,
) -> Vec<u8> {
    let mut bytes = vec![];
    cbor::write_array(&mut bytes, 4);
    cbor::write_bytes(&mut bytes, view);
    cbor::write_bytes(&mut bytes, original_root);
    cbor::write_uint(&mut bytes, mode);
    bytes.extend_from_slice(&registry_wire(registry));
    bytes
}

fn interpretation_wire(model: &ConsumedViewInterpretation, mode: u64) -> Vec<u8> {
    interpretation_fields_wire(&model.view, &model.original_root, mode, &model.registries)
}

// This fixed configuration uses primitive fields, not an evidence encoder.
fn used_interpretation_wire(model: &LineageUsedInputs) -> Vec<u8> {
    let mut bytes = vec![];
    cbor::write_map(
        &mut bytes,
        7 + usize::from(model.view_interpretations.is_some()),
    );
    cbor::write_uint(&mut bytes, 0);
    cbor::write_uint(&mut bytes, 1);
    for key in 1..=3 {
        cbor::write_uint(&mut bytes, key);
        cbor::write_array(&mut bytes, 0);
    }
    cbor::write_uint(&mut bytes, 4);
    bytes.extend_from_slice(&registry_wire(&model.registries));
    cbor::write_uint(&mut bytes, 5);
    cbor::write_map(&mut bytes, 10);
    cbor::write_uint(&mut bytes, 0);
    cbor::write_uint(&mut bytes, 1);
    for (key, text) in [(1, "store"), (2, "private:hint")] {
        cbor::write_uint(&mut bytes, key);
        cbor::write_text(&mut bytes, text);
    }
    cbor::write_uint(&mut bytes, 3);
    cbor::write_map(&mut bytes, 0);
    cbor::write_uint(&mut bytes, 4);
    cbor::write_array(&mut bytes, 2);
    for _ in 0..2 {
        cbor::write_array(&mut bytes, 2);
        cbor::write_text(&mut bytes, "principal");
        cbor::write_uint(&mut bytes, 1);
    }
    cbor::write_uint(&mut bytes, 5);
    cbor::write_uint(&mut bytes, 262144);
    for (key, text) in [(6, "public"), (7, "cdc-1m")] {
        cbor::write_uint(&mut bytes, key);
        cbor::write_text(&mut bytes, text);
    }
    cbor::write_uint(&mut bytes, 8);
    cbor::write_array(&mut bytes, 6);
    for value in [262144, 1048576, 4194304, 48, 2] {
        cbor::write_uint(&mut bytes, value);
    }
    cbor::write_bytes(&mut bytes, &model.configuration.chunk_profile.seed);
    cbor::write_uint(&mut bytes, 9);
    bytes.push(0xf6);
    cbor::write_uint(&mut bytes, 6);
    cbor::write_array(&mut bytes, model.views.len());
    for view in &model.views {
        cbor::write_array(&mut bytes, 3);
        cbor::write_bytes(&mut bytes, &view.view);
        cbor::write_text(&mut bytes, "public");
        cbor::write_array(&mut bytes, 1);
        cbor::write_array(&mut bytes, 3);
        cbor::write_bytes(&mut bytes, &view.roots[0].root);
        cbor::write_bytes(&mut bytes, b"/");
        cbor::write_array(&mut bytes, 1);
        cbor::write_array(&mut bytes, 2);
        cbor::write_bytes(&mut bytes, &[0xa0]);
        cbor::write_bytes(&mut bytes, &[0xa0]);
    }
    if let Some(contexts) = &model.view_interpretations {
        cbor::write_uint(&mut bytes, 7);
        cbor::write_array(&mut bytes, contexts.len());
        for context in contexts {
            let mode = if context.mode == ViewInterpretationMode::Legacy {
                0
            } else {
                1
            };
            bytes.extend_from_slice(&interpretation_wire(context, mode));
        }
    }
    bytes
}

#[test]
fn consumed_view_interpretations_preserve_modes_and_registered_context_fields() {
    use super::support::cbor_properties;
    let mut generator = Generator::new(0x7480_b1c2_3eca_2174);
    for revision in 1..=3 {
        let mut registry = registries();
        registry.property_revision = revision;
        if revision >= 2 {
            registry.behavioral_properties.push("index-roots".into());
        }
        if revision == 3 {
            registry.behavioral_properties.push("index-gaps".into());
            registry.attribute_revision = 2;
        }
        registry.behavioral_properties.sort();
        registry.later_properties = vec!["later.generated".into()];
        for (mode, code) in [
            (ViewInterpretationMode::Legacy, 0),
            (ViewInterpretationMode::Recorded, 1),
        ] {
            let model = ConsumedViewInterpretation {
                view: generator.bytes(),
                original_root: generator.bytes(),
                mode,
                registries: registry.clone(),
            };
            let expected = interpretation_wire(&model, code);
            assert_eq!(model.encode().unwrap(), expected);
            assert_eq!(
                ConsumedViewInterpretation::decode(&expected).unwrap(),
                model
            );
            cbor_properties(
                "ordinary consumed view interpretation",
                &expected,
                |bytes| ConsumedViewInterpretation::decode(bytes)?.encode(),
            );
            assert!(ConsumedViewInterpretation::decode(&interpretation_wire(&model, 2)).is_err());
            assert_ne!(expected, interpretation_wire(&model, 1 - code));
            for length in [0, 31, 33] {
                for (view, root) in [
                    (vec![0; length], model.original_root.to_vec()),
                    (model.view.to_vec(), vec![0; length]),
                ] {
                    let malformed = interpretation_fields_wire(&view, &root, code, &registry);
                    assert!(ConsumedViewInterpretation::decode(&malformed).is_err());
                }
            }

            let mut used = LineageUsedInputs {
                issuers: vec![],
                disclosures: vec![],
                controls: vec![],
                registries: registries(),
                configuration: configuration(generator.bytes()),
                views: vec![ConsumedViewPolicy {
                    view: model.view,
                    default_domain: "public".into(),
                    roots: vec![ConsumedRootPolicy {
                        root: model.original_root,
                        path: b"/".to_vec(),
                        layers: vec![ConsumedRootLayer {
                            properties: vec![0xa0],
                            overrides: vec![0xa0],
                        }],
                    }],
                }],
                view_interpretations: Some(vec![model.clone()]),
            };
            for contexts in [Some(vec![model.clone()]), None] {
                used.view_interpretations = contexts;
                let expected = used_interpretation_wire(&used);
                assert_eq!(used.encode().unwrap(), expected);
                assert_eq!(LineageUsedInputs::decode(&expected).unwrap(), used);
                cbor_properties(
                    "present or absent consumed interpretations",
                    &expected,
                    |bytes| LineageUsedInputs::decode(bytes)?.encode(),
                );
            }

            // Registered property vocabularies remain exact even as unsupported
            // non-property uints survive ordinary representation decoding.
            let mut unsupported = model.clone();
            unsupported.registries.attribute_revision = generator.next().max(3);
            unsupported.registries.selector_revision = u64::MAX;
            unsupported.registries.tree_revision = u64::MAX;
            unsupported.registries.chunk_revision = u64::MAX;
            let wire = interpretation_wire(&unsupported, code);
            assert_eq!(unsupported.encode().unwrap(), wire);
            assert_eq!(
                ConsumedViewInterpretation::decode(&wire).unwrap(),
                unsupported
            );
            assert!(unsupported.check_supported_interpretation().is_err());
            for revision in [0, 4, u64::MAX] {
                let mut invalid = model.clone();
                invalid.registries.property_revision = revision;
                assert!(invalid.encode().is_err());
                assert!(
                    ConsumedViewInterpretation::decode(&interpretation_wire(&invalid, code))
                        .is_err()
                );
            }
            let mut missing = model.clone();
            missing.registries.behavioral_properties.pop();
            assert!(
                ConsumedViewInterpretation::decode(&interpretation_wire(&missing, code)).is_err()
            );
            let mut maximum = model.clone();
            maximum.registries.later_properties = vec!["x".repeat(255)];
            let wire = interpretation_wire(&maximum, code);
            assert_eq!(maximum.encode().unwrap(), wire);
            assert_eq!(ConsumedViewInterpretation::decode(&wire).unwrap(), maximum);
            let mut excessive = model;
            excessive.registries.later_properties = vec!["x".repeat(256)];
            assert!(
                ConsumedViewInterpretation::decode(&interpretation_wire(&excessive, code)).is_err()
            );
        }
    }
}

fn reconciliation_fields(model: &LocalGcReconciliation) -> Vec<Vec<u8>> {
    let mut fields = vec![vec![]; 5];
    for (key, bytes) in fields.iter_mut().enumerate() {
        cbor::write_uint(bytes, key as u64);
    }
    cbor::write_uint(&mut fields[0], 1);
    cbor::write_bytes(&mut fields[1], &model.authorization);
    cbor::write_array(&mut fields[2], 2);
    cbor::write_text(&mut fields[2], &model.fence_key);
    cbor::write_bytes(&mut fields[2], &model.fence_digest);
    cbor::write_array(&mut fields[3], 3);
    cbor::write_bytes(&mut fields[3], &model.pack);
    cbor::write_uint(&mut fields[3], model.cycle);
    cbor::write_uint(&mut fields[3], model.epoch);
    cbor::write_bytes(&mut fields[4], &model.index);
    fields
}

fn reconciliation_wire(fields: &[Vec<u8>]) -> Vec<u8> {
    let mut bytes = vec![];
    cbor::write_map(&mut bytes, fields.len());
    for field in fields {
        bytes.extend_from_slice(field);
    }
    bytes
}

#[test]
fn local_gc_reconciliation_models_preserve_registered_fences_and_full_fields() {
    use super::support::cbor_properties;
    let mut generator = Generator::new(0x0bb5_2c97_3702_f598);
    for case in 0..12 {
        let model = LocalGcReconciliation {
            authorization: generator.bytes(),
            fence_key: format!("gc/{}/fence/{}", generator.next(), generator.next()),
            fence_digest: generator.bytes(),
            pack: generator.bytes(),
            cycle: if case % 2 == 0 { 0 } else { u64::MAX },
            epoch: generator.next(),
            index: generator.bytes(),
        };
        let fields = reconciliation_fields(&model);
        let expected = reconciliation_wire(&fields);
        assert_eq!(model.encode().unwrap(), expected);
        assert_eq!(LocalGcReconciliation::decode(&expected).unwrap(), model);
        cbor_properties("complete local GC reconciliation", &expected, |bytes| {
            LocalGcReconciliation::decode(bytes)?.encode()
        });

        // Every field is mandatory; no fabricated optional variant is valid.
        for missing in 0..fields.len() {
            let mut incomplete = fields.clone();
            incomplete.remove(missing);
            assert!(LocalGcReconciliation::decode(&reconciliation_wire(&incomplete)).is_err());
        }
        for (key, lengths) in [
            (1, [0, 31, 33]),
            (4, [0, 31, 33]),
            (3, [0, 15, 17]),
            (2, [0, 31, 33]),
        ] {
            for length in lengths {
                let mut malformed = fields.clone();
                let mut field = vec![];
                cbor::write_uint(&mut field, key);
                match key {
                    2 => {
                        cbor::write_array(&mut field, 2);
                        cbor::write_text(&mut field, &model.fence_key);
                        cbor::write_bytes(&mut field, &vec![0; length]);
                    }
                    3 => {
                        cbor::write_array(&mut field, 3);
                        cbor::write_bytes(&mut field, &vec![0; length]);
                        cbor::write_uint(&mut field, model.cycle);
                        cbor::write_uint(&mut field, model.epoch);
                    }
                    _ => cbor::write_bytes(&mut field, &vec![0; length]),
                }
                malformed[key as usize] = field;
                assert!(LocalGcReconciliation::decode(&reconciliation_wire(&malformed)).is_err());
            }
        }
        let mut unknown = fields.clone();
        unknown.push(vec![5, 0xf6]);
        assert!(LocalGcReconciliation::decode(&reconciliation_wire(&unknown)).is_err());
        let mut version = fields;
        version[0] = vec![0, 2];
        assert!(LocalGcReconciliation::decode(&reconciliation_wire(&version)).is_err());
        for key in [
            "gc/01/fence/0",
            "gc/0/fence/01",
            "gc/0/fence",
            "gc/0/fence/0/extra",
            "other/0/fence/0",
            "gc/18446744073709551616/fence/0",
        ] {
            let mut invalid = model.clone();
            invalid.fence_key = key.into();
            assert!(invalid.encode().is_err());
            assert!(
                LocalGcReconciliation::decode(&reconciliation_wire(&reconciliation_fields(
                    &invalid
                )))
                .is_err()
            );
        }
    }
}
