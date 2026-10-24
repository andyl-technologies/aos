//! Admits the explicit first-Observe schema without upgrading older worlds.
//!
//! Original capture and its target must carry the same complete schema before
//! launch. Live World completion and the separately funded once action remain
//! independent of this declaration, schema roster or negotiated feature.

use super::*;
use crucible_node_transport::reference_packet::service::complete_restore::restoration_observe::{
    PACKET_RESTORATION_OBSERVE_FEATURE, authenticate_restoration_observe_schema_data,
    restoration_observe_contract_data,
};

pub(super) fn authenticate_profile_declaration_data(
    selected: &Manifest,
) -> Result<(), QualificationError> {
    let schema = selected.schema.as_str();
    let rosters = selected.participants.each_ref().map(|one| {
        (
            one.installation.provider.implementation.formats.as_slice(),
            one.installation
                .binding
                .compatibility
                .implementation
                .formats
                .as_slice(),
        )
    });
    let features = selected
        .participants
        .each_ref()
        .map(|one| one.installation.provider.extensions_supported.as_slice());
    if schema == "crucible.complete-scene.installation/5" {
        return authenticate_five_profile_data(rosters, features, &selected.content);
    }
    restoration_activation::authenticate_profile_declaration_data(selected)?;
    authenticate_observation_rosters_data(schema, rosters, features, &selected.content)
}

pub(super) fn authenticate_five_profile_data(
    rosters: [(&[SchemaRef], &[SchemaRef]); 3],
    features: [&[Id]; 3],
    content: &[Content],
) -> Result<(), QualificationError> {
    // Parent validators and complete definitions are unchanged. Only this
    // explicit successor supplies their already-required parent editions.
    authenticate_snapshot_declaration_data(
        "crucible.complete-scene.installation/3",
        rosters,
        content,
    )?;
    restoration_activation::authenticate_activation_rosters_data(
        "crucible.complete-scene.installation/4",
        rosters,
        features,
        content,
    )?;
    authenticate_observation_rosters_data(
        "crucible.complete-scene.installation/5",
        rosters,
        features,
        content,
    )
}

fn authenticate_observation_rosters_data(
    schema: &str,
    rosters: [(&[SchemaRef], &[SchemaRef]); 3],
    features: [&[Id]; 3],
    content: &[Content],
) -> Result<(), QualificationError> {
    if schema != "crucible.complete-scene.installation/5" {
        for (provider, binding) in rosters {
            for formats in [provider, binding] {
                if formats
                    .iter()
                    .any(|row| row.id.as_str() == PACKET_RESTORATION_OBSERVE_FEATURE)
                {
                    return Err(refused());
                }
            }
        }
        return Ok(());
    }
    for (provider, binding) in rosters {
        for formats in [provider, binding] {
            let mut found = false;
            for row in formats {
                if row.id.as_str() != PACKET_RESTORATION_OBSERVE_FEATURE {
                    continue;
                }
                if found {
                    return Err(refused());
                }
                authenticate_restoration_observe_schema_data(row).map_err(|_| refused())?;
                let mut actual = None;
                for item in content {
                    if item.reference == row.definition {
                        if actual.is_some() {
                            return Err(refused());
                        }
                        actual = Some(item);
                    }
                }
                if actual.ok_or_else(refused)?.bytes.as_slice()
                    != restoration_observe_contract_data()
                {
                    return Err(refused());
                }
                found = true;
            }
            if !found {
                return Err(refused());
            }
        }
    }
    for supported in features {
        let mut found = false;
        for feature in supported {
            if feature.as_str() == PACKET_RESTORATION_OBSERVE_FEATURE {
                if found {
                    return Err(refused());
                }
                found = true;
            }
        }
        if !found {
            return Err(refused());
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crucible_node_transport::reference_packet::service::complete_restore::restoration_observe::restoration_observe_schema;

    fn definitions() -> ([SchemaRef; 1], [Content; 1], [Id; 1]) {
        let schema = restoration_observe_schema().unwrap();
        let content = Content {
            reference: schema.definition.clone(),
            bytes: Bytes::new(restoration_observe_contract_data().to_vec()),
        };
        (
            [schema],
            [content],
            [Id::new(PACKET_RESTORATION_OBSERVE_FEATURE).unwrap()],
        )
    }

    #[test]
    fn explicit_five_observation_addition_cannot_retag_three_or_four() {
        let (schemas, content, features) = definitions();
        authenticate_observation_rosters_data(
            "crucible.complete-scene.installation/5",
            [(&schemas, &schemas); 3],
            [&features; 3],
            &content,
        )
        .unwrap();
        for legacy in [
            "crucible.complete-scene.installation/3",
            "crucible.complete-scene.installation/4",
        ] {
            assert!(
                authenticate_observation_rosters_data(
                    legacy,
                    [(&schemas, &schemas); 3],
                    [&features; 3],
                    &content
                )
                .is_err()
            );
            // Advertisement alone preserves the old path, selecting no Observe.
            authenticate_observation_rosters_data(legacy, [(&[], &[]); 3], [&features; 3], &[])
                .unwrap();
        }
        assert!(
            authenticate_observation_rosters_data(
                "crucible.complete-scene.installation/5",
                [(&[], &[]); 3],
                [&features; 3],
                &[]
            )
            .is_err()
        );
        let tuple = serde_json::json!({"complete_restore":"SourceSignedTransfer12",
            "restore_input_emitter":"CanonicalSdkRestoreInputs12", "fresh_restore_allocation":"completed_admit13"});
        let selection: CompleteMechanism = serde_json::from_value(tuple).unwrap();
        authenticate_selection_data("crucible.complete-scene.installation/5", Some(selection))
            .unwrap();
        assert!(
            authenticate_selection_data("crucible.complete-scene.installation/5", None).is_err()
        );
    }

    #[test]
    fn every_observation_member_roster_feature_and_exact_content_remains_required() {
        let (schemas, content, features) = definitions();
        for member in 0..3 {
            for provider in [false, true] {
                for change in 0..4 {
                    let mut changed = schemas.to_vec();
                    match change {
                        0 => {
                            changed.clear();
                        }
                        1 => {
                            changed.push(changed[0].clone());
                        }
                        2 => {
                            changed[0].version += 1;
                        }
                        3 => {
                            changed[0].definition.hash.digest = "0".repeat(64);
                        }
                        _ => unreachable!(),
                    }
                    let mut rosters = [(&schemas[..], &schemas[..]); 3];
                    rosters[member] = if provider {
                        (&changed, &schemas)
                    } else {
                        (&schemas, &changed)
                    };
                    assert!(
                        authenticate_observation_rosters_data(
                            "crucible.complete-scene.installation/5",
                            rosters,
                            [&features; 3],
                            &content
                        )
                        .is_err()
                    );
                }
            }
            let mut missing = [&features[..]; 3];
            missing[member] = &[];
            assert!(
                authenticate_observation_rosters_data(
                    "crucible.complete-scene.installation/5",
                    [(&schemas, &schemas); 3],
                    missing,
                    &content
                )
                .is_err()
            );
        }
        assert!(
            authenticate_observation_rosters_data(
                "crucible.complete-scene.installation/5",
                [(&schemas, &schemas); 3],
                [&features; 3],
                &[]
            )
            .is_err()
        );
        let changed = [Content {
            reference: content[0].reference.clone(),
            bytes: Bytes::new(b"changed".to_vec()),
        }];
        assert!(
            authenticate_observation_rosters_data(
                "crucible.complete-scene.installation/5",
                [(&schemas, &schemas); 3],
                [&features; 3],
                &changed
            )
            .is_err()
        );
        let duplicate = [
            Content {
                reference: content[0].reference.clone(),
                bytes: content[0].bytes.clone(),
            },
            Content {
                reference: content[0].reference.clone(),
                bytes: content[0].bytes.clone(),
            },
        ];
        assert!(
            authenticate_observation_rosters_data(
                "crucible.complete-scene.installation/5",
                [(&schemas, &schemas); 3],
                [&features; 3],
                &duplicate
            )
            .is_err()
        );
    }

    #[test]
    fn full_five_profile_keeps_every_exact_parent_definition_and_six_rosters() {
        use crucible_node_transport::reference_packet::service::{
            complete_restore::activation::{
                restoration_activation_contract_data, restoration_activation_schema,
                upload::{
                    restoration_activation_upload_contract_data,
                    restoration_activation_upload_schema,
                },
            },
            native_snapshot::{native_owned14_snapshot_contract, native_owned14_snapshot_schema},
        };
        let mut schemas = vec![
            native_owned14_snapshot_schema().unwrap(),
            restoration_activation_schema().unwrap(),
            restoration_activation_upload_schema().unwrap(),
            restoration_observe_schema().unwrap(),
        ];
        let bodies = vec![
            native_owned14_snapshot_contract().unwrap(),
            restoration_activation_contract_data().to_vec(),
            restoration_activation_upload_contract_data().to_vec(),
            restoration_observe_contract_data().to_vec(),
        ];
        let content: Vec<_> = schemas
            .iter()
            .zip(bodies)
            .map(|(schema, bytes)| Content {
                reference: schema.definition.clone(),
                bytes: Bytes::new(bytes),
            })
            .collect();
        let mut features: Vec<_> = schemas[1..]
            .iter()
            .map(|schema| schema.id.clone())
            .collect();
        schemas.sort_by(|a, b| a.id.cmp(&b.id));
        features.sort();

        authenticate_five_profile_data([(&schemas, &schemas); 3], [&features; 3], &content)
            .unwrap();
        for member in 0..3 {
            for provider in [false, true] {
                for schema in &schemas {
                    let mut changed = schemas.clone();
                    changed.retain(|row| row.id != schema.id);
                    let mut rosters = [(&schemas[..], &schemas[..]); 3];
                    rosters[member] = if provider {
                        (&changed, &schemas)
                    } else {
                        (&schemas, &changed)
                    };
                    assert!(
                        authenticate_five_profile_data(rosters, [&features; 3], &content).is_err()
                    );
                }
            }
        }
    }

    #[test]
    fn actual_installer_refuses_relabelled_five_before_namespace_birth() {
        use crate::node_qualification::packet_collection::complete::{
            installed::{InstalledCompleteScene, InstalledCompleteSceneManifest},
            tests::installed_scene_declaration,
        };
        let (_original, mut declaration) = installed_scene_declaration();
        declaration["schema"] = serde_json::json!("crucible.complete-scene.installation/5");
        declaration["mechanism"] = serde_json::json!({"complete_restore":"SourceSignedTransfer12",
            "restore_input_emitter":"CanonicalSdkRestoreInputs12", "fresh_restore_allocation":"completed_admit13"});
        let bytes = canonical::canonical_json(&declaration).unwrap();
        let reference = canonical::content_ref(&bytes, "application/json").unwrap();
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("installation.json");
        std::fs::write(&path, &bytes).unwrap();
        let scene = directory.path().join("uncreated-scene");
        assert!(
            InstalledCompleteScene::install(
                InstalledCompleteSceneManifest::new(path.clone(), reference).unwrap(),
                scene.clone()
            )
            .is_err()
        );
        assert!(!scene.exists());
        assert_eq!(std::fs::read(path).unwrap(), bytes);
    }
}
