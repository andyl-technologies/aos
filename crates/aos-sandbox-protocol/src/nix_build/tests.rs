//! UNRUN pure-schema vectors; none manufactures protected production custody.

use aos_sandbox_core::{MediaType, descriptor_for_bytes};
use aos_sandbox_core::model::{Directory, FilesystemMetadata, Tree};
use ed25519_dalek::{Signer as _, SigningKey};

use super::*;

fn descriptor(media_type: PortableMediaType, bytes: &[u8]) -> ObjectDescriptor {
    descriptor_for_bytes(MediaType::new(media_type.as_str()).unwrap(), bytes)
}

fn content_object(name: char, bytes: &[u8]) -> NixStoreObjectV2 {
    NixStoreObjectV2 {
        path: format!("/nix/store/{}-{name}", "0".repeat(32)),
        portable: descriptor(PortableMediaType::Content, bytes),
        nar_sha256: ObjectDigest::from_bytes([3; 32]),
        nar_size: 64,
        references: Vec::new(),
        portable_objects: Vec::new(),
    }
}

fn tree_object() -> NixStoreObjectV2 {
    let metadata = FilesystemMetadata::new(0o555, 0, 0, 1, 0, Vec::new(), None).unwrap();
    let directory = Directory::new(metadata, Vec::new()).unwrap();
    let directory_bytes = aos_sandbox_core::format::encode_directory(&directory);
    let directory_descriptor = descriptor(PortableMediaType::Directory, &directory_bytes);
    let tree = Tree::new(directory_descriptor.clone(), Vec::new()).unwrap();
    let tree_bytes = aos_sandbox_core::format::encode_tree(&tree);
    let tree_descriptor = descriptor(PortableMediaType::Tree, &tree_bytes);
    let mut records = vec![
        NixPortableObjectV2 {
            descriptor: directory_descriptor,
            bytes: directory_bytes,
        },
        NixPortableObjectV2 {
            descriptor: tree_descriptor.clone(),
            bytes: tree_bytes,
        },
    ];
    records.sort_by(|left, right| left.descriptor.cmp(&right.descriptor));

    NixStoreObjectV2 {
        path: format!("/nix/store/{}-b", "0".repeat(32)),
        portable: tree_descriptor,
        nar_sha256: ObjectDigest::from_bytes([4; 32]),
        nar_size: 80,
        references: Vec::new(),
        portable_objects: records,
    }
}

fn recipe() -> NixPreadmittedRecipeV2 {
    let source = tree_object();
    let lock = content_object('a', b"lock");
    let mut derivation = content_object('c', b"derivation");
    derivation.path.push_str(".drv");
    derivation.references = vec![lock.path.clone(), source.path.clone()];

    // Generation bytes and NAR coordinates are shape-only fixture DATA.
    // Only real Core/backing owners may independently admit their semantics.
    NixPreadmittedRecipeV2 {
        version: 2,
        node: NodeId::from_bytes([1; 16]),
        deployment: ObjectDigest::from_bytes([2; 32]),
        endpoint: ResourceId::from_bytes([3; 16]),
        domain: ResourceId::from_bytes([4; 16]),
        domain_commitment: ObjectDigest::from_bytes([5; 32]),
        disclosure: ObjectDigest::from_bytes([6; 32]),
        project: ProjectId::from_bytes([7; 16]),
        sandbox: SandboxId::from_bytes([8; 16]),
        specification: descriptor(PortableMediaType::SandboxSpec, b"specification"),
        environment: descriptor(PortableMediaType::Environment, b"environment"),
        generation_manifest: vec![1],
        policy: descriptor(PortableMediaType::Policy, b"policy"),
        source: source.portable.clone(),
        lock: lock.portable.clone(),
        source_path: source.path.clone(),
        lock_path: lock.path.clone(),
        selected_output: "packages.default".into(),
        target_system: "x86_64-linux".into(),
        derivation,
        derivation_bytes: b"derivation".to_vec(),
        inputs: vec![lock, source],
        outputs: vec![NixExpectedOutputV2 {
            name: "out".into(),
            object: content_object('d', b"result"),
        }],
    }
}

fn signed_recipe(recipe: &NixPreadmittedRecipeV2, key: &SigningKey) -> Vec<u8> {
    let json = serde_json::to_vec(recipe).unwrap();
    let mut artifact = Vec::new();
    artifact.extend_from_slice(RECIPE_MAGIC);
    artifact.extend_from_slice(&(json.len() as u32).to_be_bytes());
    artifact.extend_from_slice(&json);

    let mut message = Vec::new();
    message.extend_from_slice(RECIPE_SIGNATURE_DOMAIN);
    message.extend_from_slice(&artifact);
    artifact.extend_from_slice(&key.sign(&message).to_bytes());
    artifact
}

#[test]
fn canonical_content_identity_matches_the_rfc_golden_descriptor() {
    let expected = descriptor(PortableMediaType::Content, b"hello");

    assert_eq!(expected.encoded_size(), 5);
    assert_eq!(
        expected.digest().to_string(),
        "sha256:a40bf7a4525f9711f56ba2f9a4e91cf0ee0fe60a01f7716c9eb6d03dde09d903"
    );
    assert!(verify_portable_object_bytes(&expected, b"hello").is_ok());
    assert_ne!(
        expected.digest(),
        ObjectDigest::from_bytes(Sha256::digest(b"hello").into())
    );
}

#[test]
fn canonical_derivation_and_complete_tree_use_the_core_object_contract() {
    let fixture = recipe();
    let source = &fixture.inputs[1];

    let recipe_validation = fixture.validate();
    let derivation_validation = verify_portable_object_bytes(
        &fixture.derivation.portable,
        &fixture.derivation_bytes,
    );

    assert!(recipe_validation.is_ok());
    assert!(derivation_validation.is_ok());
    assert_eq!(source.portable_objects.len(), 2);
    for record in &source.portable_objects {
        assert_eq!(
            record.descriptor,
            descriptor_for_bytes(record.descriptor.media_type().clone(), &record.bytes)
        );
        assert!(verify_portable_object_bytes(&record.descriptor, &record.bytes).is_ok());
    }
    assert!(portable_graph::validate(source).is_ok());
}

#[test]
fn raw_derivation_digest_is_invalid_even_in_an_independently_signed_recipe() {
    let mut fixture = recipe();
    let canonical = fixture.derivation.portable.clone();
    fixture.derivation.portable = ObjectDescriptor::new(
        canonical.media_type().clone(),
        ObjectDigest::from_bytes(Sha256::digest(&fixture.derivation_bytes).into()),
        canonical.encoded_size(),
    );
    let key = SigningKey::from_bytes(&[9; 32]);
    let artifact = signed_recipe(&fixture, &key);

    assert_ne!(fixture.derivation.portable, canonical);
    assert!(matches!(fixture.validate(), Err(NixBuildSchemaErrorV2::Invalid)));
    assert!(matches!(
        verify_nix_recipe_artifact_v2(&artifact, key.verifying_key().to_bytes()),
        Err(NixBuildSchemaErrorV2::Invalid)
    ));
}

#[test]
fn reachable_raw_tree_and_directory_digests_are_not_a_compatibility_format() {
    for media_type in [PortableMediaType::Tree, PortableMediaType::Directory] {
        let mut object = tree_object();
        let index = object
            .portable_objects
            .iter()
            .position(|record| record.descriptor.media_type().as_str() == media_type.as_str())
            .unwrap();
        let record = &mut object.portable_objects[index];
        let raw = ObjectDescriptor::new(
            record.descriptor.media_type().clone(),
            ObjectDigest::from_bytes(Sha256::digest(&record.bytes).into()),
            record.descriptor.encoded_size(),
        );
        assert_ne!(raw, record.descriptor);
        record.descriptor = raw.clone();

        if media_type == PortableMediaType::Tree {
            object.portable = raw;
        } else {
            // Keep the substituted Directory reachable through a canonical
            // parent, so a missing graph member cannot explain this refusal.
            let tree_index = object
                .portable_objects
                .iter()
                .position(|record| record.descriptor == object.portable)
                .unwrap();
            let tree = Tree::new(raw, Vec::new()).unwrap();
            let bytes = aos_sandbox_core::format::encode_tree(&tree);
            let parent = descriptor(PortableMediaType::Tree, &bytes);
            object.portable_objects[tree_index] = NixPortableObjectV2 {
                descriptor: parent.clone(),
                bytes,
            };
            object.portable = parent;
        }
        object
            .portable_objects
            .sort_by(|left, right| left.descriptor.cmp(&right.descriptor));

        // Graph decoding itself succeeds with complete, ordered membership.
        // Only exact canonical object identity rejects the raw-hash carrier.
        assert!(portable_graph::validate(&object).is_ok(), "graph {media_type:?}");
        assert!(
            matches!(object.validate(), Err(NixBuildSchemaErrorV2::Invalid)),
            "raw identity {media_type:?}"
        );
        let mut fixture = recipe();
        fixture.source = object.portable.clone();
        fixture.inputs[1] = object;

        assert!(
            matches!(fixture.validate(), Err(NixBuildSchemaErrorV2::Invalid)),
            "recipe input {media_type:?}"
        );
    }
}

#[test]
fn exact_payload_verification_rejects_changed_media_size_or_bytes() {
    let expected = descriptor(PortableMediaType::Content, b"hello");
    let wrong_media = ObjectDescriptor::new(
        MediaType::new(PortableMediaType::Tree.as_str()).unwrap(),
        expected.digest(),
        expected.encoded_size(),
    );
    let shorter_size = ObjectDescriptor::new(
        expected.media_type().clone(),
        expected.digest(),
        expected.encoded_size() - 1,
    );
    let longer_size = ObjectDescriptor::new(
        expected.media_type().clone(),
        expected.digest(),
        expected.encoded_size() + 1,
    );
    let cases = [
        ("changed media", wrong_media, b"hello".as_slice()),
        ("smaller encoded size", shorter_size, b"hello".as_slice()),
        ("larger encoded size", longer_size, b"hello".as_slice()),
        ("same-length substitution", expected.clone(), b"jello".as_slice()),
        ("truncated payload", expected.clone(), b"hell".as_slice()),
        ("appended payload", expected.clone(), b"hello!".as_slice()),
    ];

    assert!(verify_portable_object_bytes(&expected, b"hello").is_ok());
    for (case, descriptor, bytes) in cases {
        assert!(
            matches!(
                verify_portable_object_bytes(&descriptor, bytes),
                Err(NixBuildSchemaErrorV2::Invalid)
            ),
            "{case}"
        );
    }
}

#[test]
fn recipe_rejects_same_length_derivation_payload_substitution() {
    let mut fixture = recipe();
    let original = fixture.derivation.portable.clone();
    fixture.derivation_bytes[0] ^= 1;

    assert_eq!(fixture.derivation.portable, original);
    assert_eq!(original.encoded_size(), fixture.derivation_bytes.len() as u64);
    assert!(matches!(fixture.validate(), Err(NixBuildSchemaErrorV2::Invalid)));
}

#[test]
fn canonical_identity_does_not_relax_reconstruction_order_or_record_bounds() {
    let complete = tree_object();
    let mut reversed = complete.clone();
    reversed.portable_objects.reverse();

    let mut repeated = complete.clone();
    repeated.portable_objects.push(repeated.portable_objects[0].clone());
    repeated
        .portable_objects
        .sort_by(|left, right| left.descriptor.cmp(&right.descriptor));

    let mut empty = complete.clone();
    empty.portable_objects[0].bytes.clear();

    let mut oversized = complete.clone();
    let record = &mut oversized.portable_objects[0];
    let media_type = record.descriptor.media_type().clone();
    record.bytes = vec![0; NIX_REQUEST_MAXIMUM_BYTES_V2 + 1];
    record.descriptor = descriptor_for_bytes(media_type, &record.bytes);
    oversized
        .portable_objects
        .sort_by(|left, right| left.descriptor.cmp(&right.descriptor));

    assert!(complete.validate().is_ok());
    for (case, object) in [
        ("reversed", reversed),
        ("repeated", repeated),
        ("empty", empty),
        ("oversized", oversized),
    ] {
        assert!(
            matches!(object.validate(), Err(NixBuildSchemaErrorV2::Invalid)),
            "{case}"
        );
    }
}

#[test]
fn independent_signature_is_bound_to_exact_canonical_artifact() {
    let fixture = recipe();
    let key = SigningKey::from_bytes(&[9; 32]);
    let original = signed_recipe(&fixture, &key);

    let verified = verify_nix_recipe_artifact_v2(&original, key.verifying_key().to_bytes()).unwrap();
    assert_eq!(verified.recipe(), &fixture);
    assert_eq!(verified.canonical_bytes(), original);

    let foreign = SigningKey::from_bytes(&[10; 32]);
    assert!(verify_nix_recipe_artifact_v2(&original, foreign.verifying_key().to_bytes()).is_err());
    let mut modified = original.clone();
    *modified.last_mut().unwrap() ^= 1;
    assert!(verify_nix_recipe_artifact_v2(&modified, key.verifying_key().to_bytes()).is_err());
    let mut trailing = original;
    trailing.push(0);
    assert!(verify_nix_recipe_artifact_v2(&trailing, key.verifying_key().to_bytes()).is_err());
}

#[test]
fn recipe_input_closure_does_not_claim_predicted_output_backing() {
    let mut fixture = recipe();
    assert!(fixture.validate().is_ok());

    fixture.inputs.push(fixture.outputs[0].object.clone());
    assert!(fixture.validate().is_err());

    let mut foreign_reference = recipe();
    foreign_reference.derivation.references.push(format!("/nix/store/{}-z", "0".repeat(32)));
    assert!(foreign_reference.validate().is_err());
}

#[test]
fn specification_role_accepts_both_registered_versions_not_foreign_media() {
    let mut fixture = recipe();
    fixture.specification = descriptor(PortableMediaType::SandboxSpecV2, b"specification-v2");
    assert!(fixture.validate().is_ok());

    fixture.specification = descriptor(PortableMediaType::Content, b"not-a-specification");
    assert!(fixture.validate().is_err());
}

#[test]
fn target_system_accepts_bounded_ascii_platform_names_not_paths_or_control_bytes() {
    for target in ["x86_64-linux", "aarch64-linux"] {
        let mut fixture = recipe();
        fixture.target_system = target.into();

        assert!(fixture.validate().is_ok(), "valid target {target}");
    }

    for target in [
        "",
        "x86_64 linux",
        "x86_64-linux\n",
        "x86_64-linux\t",
        "/x86_64-linux",
        "../x86_64-linux",
        "x86_64\0-linux",
    ] {
        let mut fixture = recipe();
        fixture.target_system = target.into();

        assert!(fixture.validate().is_err(), "invalid target {target:?}");
    }

    let mut oversized = recipe();
    oversized.target_system = "a".repeat(256);
    assert!(oversized.validate().is_err());
}

#[test]
fn portable_graph_requires_every_record_and_rejects_unused_records() {
    let complete = tree_object();
    assert!(complete.validate().is_ok());

    let mut missing = complete.clone();
    missing.portable_objects.retain(|record| record.descriptor == missing.portable);
    assert!(missing.validate().is_err());

    let mut substituted = complete.clone();
    substituted.portable_objects[0].bytes[0] ^= 1;
    assert!(substituted.validate().is_err());

    let mut content = content_object('a', b"content");
    content.portable_objects = complete.portable_objects;
    assert!(content.validate().is_err());
}

#[test]
fn complete_graph_validates_and_missing_directory_returns_invalid() {
    let complete = tree_object();
    assert!(complete.validate().is_ok());

    let mut missing = complete.clone();
    missing
        .portable_objects
        .retain(|record| record.descriptor == missing.portable);

    assert!(matches!(
        missing.validate(),
        Err(NixBuildSchemaErrorV2::Invalid)
    ));
}

#[test]
fn reachable_hash_correct_malformed_tree_and_directory_return_invalid() {
    let mut malformed_tree = tree_object();
    let tree_index = malformed_tree
        .portable_objects
        .iter()
        .position(|record| record.descriptor == malformed_tree.portable)
        .unwrap();
    let malformed_bytes = vec![0x80];
    let tree_descriptor = descriptor(PortableMediaType::Tree, &malformed_bytes);
    malformed_tree.portable_objects[tree_index] = NixPortableObjectV2 {
        descriptor: tree_descriptor.clone(),
        bytes: malformed_bytes,
    };
    malformed_tree.portable = tree_descriptor;
    malformed_tree
        .portable_objects
        .sort_by(|left, right| left.descriptor.cmp(&right.descriptor));

    let mut malformed_directory = tree_object();
    let directory_index = malformed_directory
        .portable_objects
        .iter()
        .position(|record| {
            record.descriptor.media_type().as_str() == PortableMediaType::Directory.as_str()
        })
        .unwrap();
    let malformed_bytes = vec![0x80];
    let directory_descriptor = descriptor(PortableMediaType::Directory, &malformed_bytes);
    malformed_directory.portable_objects[directory_index] = NixPortableObjectV2 {
        descriptor: directory_descriptor.clone(),
        bytes: malformed_bytes,
    };
    let tree_index = malformed_directory
        .portable_objects
        .iter()
        .position(|record| record.descriptor == malformed_directory.portable)
        .unwrap();
    let tree = Tree::new(directory_descriptor, Vec::new()).unwrap();
    let tree_bytes = aos_sandbox_core::format::encode_tree(&tree);
    let tree_descriptor = descriptor(PortableMediaType::Tree, &tree_bytes);
    malformed_directory.portable_objects[tree_index] = NixPortableObjectV2 {
        descriptor: tree_descriptor.clone(),
        bytes: tree_bytes,
    };
    malformed_directory.portable = tree_descriptor;
    malformed_directory
        .portable_objects
        .sort_by(|left, right| left.descriptor.cmp(&right.descriptor));

    // Both malformed records have matching descriptors and hashes, so these
    // failures require canonical graph decoding rather than byte-digest checks.
    assert!(matches!(
        malformed_tree.validate(),
        Err(NixBuildSchemaErrorV2::Invalid)
    ));
    assert!(matches!(
        malformed_directory.validate(),
        Err(NixBuildSchemaErrorV2::Invalid)
    ));
}

#[test]
fn unused_hash_correct_canonical_and_malformed_records_return_invalid() {
    let metadata = FilesystemMetadata::new(0o555, 1, 0, 1, 0, Vec::new(), None).unwrap();
    let directory = Directory::new(metadata, Vec::new()).unwrap();
    let directory_bytes = aos_sandbox_core::format::encode_directory(&directory);
    let directory_descriptor = descriptor(PortableMediaType::Directory, &directory_bytes);
    let tree = Tree::new(directory_descriptor.clone(), Vec::new()).unwrap();
    let tree_bytes = aos_sandbox_core::format::encode_tree(&tree);
    let malformed_bytes = vec![0x80];
    let records = [
        (
            "canonical Directory",
            NixPortableObjectV2 {
                descriptor: directory_descriptor,
                bytes: directory_bytes,
            },
        ),
        (
            "canonical Tree",
            NixPortableObjectV2 {
                descriptor: descriptor(PortableMediaType::Tree, &tree_bytes),
                bytes: tree_bytes,
            },
        ),
        (
            "malformed Directory",
            NixPortableObjectV2 {
                descriptor: descriptor(PortableMediaType::Directory, &malformed_bytes),
                bytes: malformed_bytes.clone(),
            },
        ),
        (
            "malformed Tree",
            NixPortableObjectV2 {
                descriptor: descriptor(PortableMediaType::Tree, &malformed_bytes),
                bytes: malformed_bytes,
            },
        ),
    ];

    for (case, record) in records {
        let mut object = tree_object();
        object.portable_objects.push(record);
        object
            .portable_objects
            .sort_by(|left, right| left.descriptor.cmp(&right.descriptor));

        assert!(
            matches!(object.validate(), Err(NixBuildSchemaErrorV2::Invalid)),
            "unused {case}"
        );
    }
}

#[test]
fn store_and_output_names_are_closed_not_command_options() {
    assert!(valid_store_path(&format!("/nix/store/{}-package.drv", "0".repeat(32))));
    for path in ["--store", "/nix/store/../host", "/tmp/recipe.drv", "/nix/store/x-name", "daemon"] {
        assert!(!valid_store_path(path));
    }
    for name in ["", "../out", "--option", "out/name", "out name"] {
        assert!(!valid_output_name(name));
    }
}
