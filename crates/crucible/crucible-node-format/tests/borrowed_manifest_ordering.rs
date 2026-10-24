//! Checks complete manifest roster ordering and its original refusal precedence.

// crucible-lint: allow panic-shortcut -- Contract controls panic on invalid fixtures or failed invariants.
#![allow(clippy::unwrap_used)]

use crucible_node_format::{
    ArtifactIdentity, ContentRef, ContractError, FacetSelection, Id, ImplementationIdentity,
    MAX_ARRAY_ELEMENTS, NodeManifest, ProviderManifest, SchemaRef, Validate, canonical,
};

fn id(value: &str) -> Id {
    Id::new(value).unwrap()
}

fn references() -> Vec<ContentRef> {
    let mut values = vec![
        canonical::content_ref(b"first", "application/json").unwrap(),
        canonical::content_ref(b"second", "application/json").unwrap(),
    ];
    values.sort_by(|left, right| {
        (&left.hash.domain, &left.hash.digest).cmp(&(&right.hash.domain, &right.hash.digest))
    });
    values
}

fn manifest() -> ProviderManifest {
    let references = references();
    let schemas: Vec<_> = ["schema/a", "schema/b"]
        .into_iter()
        .map(|name| SchemaRef {
            id: id(name),
            version: 1,
            definition: references[0].clone(),
            extensions: Default::default(),
        })
        .collect();
    let node = NodeManifest {
        schema_version: 1,
        profile_id: id("profile/a"),
        roles: vec![id("role/a"), id("role/b")],
        configuration_schema: schemas[0].clone(),
        allowed_combinations_ref: references[0].clone(),
        port_templates_ref: references[0].clone(),
        state_formats: schemas.clone(),
        operation_facets: ["facet/a", "facet/b"]
            .into_iter()
            .map(|name| FacetSelection {
                id: id(name),
                version: 1,
                configuration_ref: references[0].clone(),
                guarantees_ref: references[0].clone(),
                extensions: Default::default(),
            })
            .collect(),
        extensions: Default::default(),
    };
    let mut second = node.clone();
    second.profile_id = id("profile/b");

    ProviderManifest {
        schema_version: 1,
        provider_id: id("provider"),
        implementation: ImplementationIdentity {
            schema_version: 1,
            implementation_id: id("implementation"),
            artifacts: ["artifact/a", "artifact/b"]
                .into_iter()
                .map(|name| ArtifactIdentity {
                    id: id(name),
                    role: id("executable"),
                    content: references[0].clone(),
                    extensions: Default::default(),
                })
                .collect(),
            model_definitions: references.clone(),
            formats: schemas,
            extensions: Default::default(),
        },
        protocol_versions: vec![id("CNP/1"), id("CNP/2")],
        supported_profiles: vec![node, second],
        extensions_supported: vec![id("extension/a"), id("extension/b")],
        qualification_refs: references,
        extensions: Default::default(),
    }
}

fn disorder<T: Clone>(values: &mut [T], duplicate: bool) {
    if duplicate {
        values[1] = values[0].clone();
    } else {
        values.swap(0, 1);
    }
}

#[test]
fn every_hello_manifest_roster_rejects_duplicates_and_reverse_order() {
    manifest().validate().unwrap();

    for duplicate in [false, true] {
        for field in [
            "artifacts",
            "model_definitions",
            "formats",
            "protocol_versions",
            "supported_profiles",
            "extensions_supported",
            "qualification_refs",
            "roles",
            "state_formats",
            "operation_facets",
        ] {
            let mut actual = manifest();
            match field {
                "artifacts" => disorder(&mut actual.implementation.artifacts, duplicate),
                "model_definitions" => {
                    disorder(&mut actual.implementation.model_definitions, duplicate)
                }
                "formats" => disorder(&mut actual.implementation.formats, duplicate),
                "protocol_versions" => disorder(&mut actual.protocol_versions, duplicate),
                "supported_profiles" => disorder(&mut actual.supported_profiles, duplicate),
                "extensions_supported" => disorder(&mut actual.extensions_supported, duplicate),
                "qualification_refs" => disorder(&mut actual.qualification_refs, duplicate),
                "roles" => disorder(&mut actual.supported_profiles[0].roles, duplicate),
                "state_formats" => {
                    disorder(&mut actual.supported_profiles[0].state_formats, duplicate)
                }
                "operation_facets" => disorder(
                    &mut actual.supported_profiles[0].operation_facets,
                    duplicate,
                ),
                _ => unreachable!(),
            }

            let ContractError::Invalid {
                field: rejected,
                reason,
            } = actual.validate().unwrap_err()
            else {
                panic!("unexpected validation error for {field}");
            };
            assert_eq!(rejected, field);
            assert_eq!(reason, "set must be strictly sorted with no duplicates");
        }
    }
}

#[test]
fn compound_keys_keep_their_version_and_digest_tiebreakers() {
    let mut actual = manifest();
    actual.implementation.formats[1].id = actual.implementation.formats[0].id.clone();
    actual.implementation.formats[1].version = 2;
    actual.supported_profiles[0].state_formats = actual.implementation.formats.clone();
    let facets = &mut actual.supported_profiles[0].operation_facets;
    facets[1].id = facets[0].id.clone();
    facets[1].version = 2;

    actual.validate().unwrap();

    // Both content rosters have equal domains and distinct, ordered digests.
    assert_eq!(
        actual.qualification_refs[0].hash.domain,
        actual.qualification_refs[1].hash.domain
    );
    assert_ne!(
        actual.qualification_refs[0].hash.digest,
        actual.qualification_refs[1].hash.digest
    );
}

#[test]
fn oversized_rosters_refuse_before_duplicate_or_child_validation() {
    let mut actual = manifest();
    let mut invalid = actual.implementation.formats[0].clone();
    invalid.version = 0;
    actual.implementation.formats = vec![invalid; MAX_ARRAY_ELEMENTS + 1];

    let ContractError::Invalid { field, reason } = actual.validate().unwrap_err() else {
        panic!("unexpected validation error");
    };
    assert_eq!(field, "formats");
    assert_eq!(reason, "array exceeds 65536 elements");
}
