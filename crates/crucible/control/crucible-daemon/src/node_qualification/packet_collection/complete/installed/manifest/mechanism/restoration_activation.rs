//! Admits the distinct installation-four schemas without upgrading edition three.
//!
//! The same immutable full schemas belong to both original capture and target
//! installation. No declaration or negotiation field chooses live purpose.

use super::*;
use crucible_node_transport::reference_packet::service::complete_restore::activation::{
    PACKET_RESTORATION_ACTIVATION_FEATURE, authenticate_restoration_activation_schema_data,
    restoration_activation_contract_data,
    upload::{
        PACKET_RESTORATION_ACTIVATION_UPLOAD_FEATURE,
        authenticate_restoration_activation_upload_schema_data,
        restoration_activation_upload_contract_data,
    },
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
    // Edition four retains all of the existing edition-three premises. The
    // old checker is unchanged; the distinct wrapper adds the new pair only.
    authenticate_snapshot_declaration_data(
        if schema == "crucible.complete-scene.installation/4" {
            "crucible.complete-scene.installation/3"
        } else {
            schema
        },
        rosters,
        &selected.content,
    )?;
    authenticate_activation_rosters_data(
        schema,
        rosters,
        selected
            .participants
            .each_ref()
            .map(|one| one.installation.provider.extensions_supported.as_slice()),
        &selected.content,
    )
}

pub(super) fn authenticate_activation_rosters_data(
    schema: &str,
    rosters: [(&[SchemaRef], &[SchemaRef]); 3],
    features: [&[Id]; 3],
    content: &[Content],
) -> Result<(), QualificationError> {
    if schema != "crucible.complete-scene.installation/4" {
        // Ordinary capability advertisement alone does not select a new mode.
        // Full schema placement requires its explicit declaration, however;
        // an archived edition-three world is never retagged or repaired here.
        if rosters.iter().any(|(provider, binding)| {
            provider.iter().chain(binding.iter()).any(|one| {
                matches!(
                    one.id.as_str(),
                    PACKET_RESTORATION_ACTIVATION_FEATURE
                        | PACKET_RESTORATION_ACTIVATION_UPLOAD_FEATURE
                )
            })
        }) {
            return Err(refused());
        }
        return Ok(());
    }
    for (provider, binding) in rosters {
        for formats in [provider, binding] {
            for expected in [
                PACKET_RESTORATION_ACTIVATION_FEATURE,
                PACKET_RESTORATION_ACTIVATION_UPLOAD_FEATURE,
            ] {
                let mut matching = formats.iter().filter(|one| one.id.as_str() == expected);
                let selected = matching.next().ok_or_else(refused)?;
                if matching.next().is_some() {
                    return Err(refused());
                }
                let bytes = if expected == PACKET_RESTORATION_ACTIVATION_FEATURE {
                    authenticate_restoration_activation_schema_data(selected)
                        .map_err(|_| refused())?;
                    restoration_activation_contract_data()
                } else {
                    authenticate_restoration_activation_upload_schema_data(selected)
                        .map_err(|_| refused())?;
                    restoration_activation_upload_contract_data()
                };
                let mut rows = content
                    .iter()
                    .filter(|row| row.reference == selected.definition);
                let row = rows.next().ok_or_else(refused)?;
                if rows.next().is_some() || row.bytes.as_slice() != bytes {
                    return Err(refused());
                }
            }
        }
    }
    for features in features {
        for expected in [
            PACKET_RESTORATION_ACTIVATION_FEATURE,
            PACKET_RESTORATION_ACTIVATION_UPLOAD_FEATURE,
        ] {
            let mut matching = features
                .iter()
                .filter(|feature| feature.as_str() == expected);
            if matching.next().is_none() || matching.next().is_some() {
                return Err(refused());
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crucible_node_transport::reference_packet::service::complete_restore::activation::{
        restoration_activation_schema, upload::restoration_activation_upload_schema,
    };

    fn definitions() -> ([SchemaRef; 2], [Content; 2], [Id; 2]) {
        let schemas = [
            restoration_activation_schema().unwrap(),
            restoration_activation_upload_schema().unwrap(),
        ];
        let content = [
            Content {
                reference: schemas[0].definition.clone(),
                bytes: Bytes::new(restoration_activation_contract_data().to_vec()),
            },
            Content {
                reference: schemas[1].definition.clone(),
                bytes: Bytes::new(restoration_activation_upload_contract_data().to_vec()),
            },
        ];
        let features = [
            Id::new(PACKET_RESTORATION_ACTIVATION_FEATURE).unwrap(),
            Id::new(PACKET_RESTORATION_ACTIVATION_UPLOAD_FEATURE).unwrap(),
        ];
        (schemas, content, features)
    }

    #[test]
    fn explicit_four_admits_full_pair_and_three_never_acquires_it_by_advertisement() {
        let (schemas, content, features) = definitions();
        authenticate_activation_rosters_data(
            "crucible.complete-scene.installation/4",
            [(&schemas, &schemas); 3],
            [&features; 3],
            &content,
        )
        .unwrap();
        assert!(
            authenticate_activation_rosters_data(
                "crucible.complete-scene.installation/3",
                [(&schemas, &schemas); 3],
                [&features; 3],
                &content
            )
            .is_err()
        );
        // The legacy feature advertisement does not choose edition four.
        authenticate_activation_rosters_data(
            "crucible.complete-scene.installation/3",
            [(&[], &[]); 3],
            [&features; 3],
            &[],
        )
        .unwrap();
        assert!(
            authenticate_activation_rosters_data(
                "crucible.complete-scene.installation/4",
                [(&[], &[]); 3],
                [&features; 3],
                &[]
            )
            .is_err()
        );
        let tuple = serde_json::json!({"complete_restore":"SourceSignedTransfer12",
            "restore_input_emitter":"CanonicalSdkRestoreInputs12", "fresh_restore_allocation":"completed_admit13"});
        let selection: CompleteMechanism = serde_json::from_value(tuple.clone()).unwrap();
        authenticate_selection_data("crucible.complete-scene.installation/4", Some(selection))
            .unwrap();
        assert!(
            authenticate_selection_data("crucible.complete-scene.installation/4", None).is_err()
        );
        let mut purpose = tuple;
        purpose["purpose"] = serde_json::json!("RestorationTarget");
        assert!(serde_json::from_value::<CompleteMechanism>(purpose).is_err());
    }

    #[test]
    fn each_member_roster_content_and_negotiated_feature_remains_required() {
        let (schemas, content, features) = definitions();
        for member in 0..3 {
            for provider in [false, true] {
                for index in 0..2 {
                    for change in 0..4 {
                        let mut changed = schemas.to_vec();
                        match change {
                            0 => {
                                changed.remove(index);
                            }
                            1 => {
                                changed.push(changed[index].clone());
                            }
                            2 => {
                                changed[index].version += 1;
                            }
                            3 => {
                                changed[index].definition.hash.digest = "0".repeat(64);
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
                            authenticate_activation_rosters_data(
                                "crucible.complete-scene.installation/4",
                                rosters,
                                [&features; 3],
                                &content
                            )
                            .is_err()
                        );
                    }
                    let mut negotiated = [&features[..]; 3];
                    negotiated[member] = &features[index..index + 1];
                    assert!(
                        authenticate_activation_rosters_data(
                            "crucible.complete-scene.installation/4",
                            [(&schemas, &schemas); 3],
                            negotiated,
                            &content
                        )
                        .is_err()
                    );
                }
            }
        }
        assert!(
            authenticate_activation_rosters_data(
                "crucible.complete-scene.installation/4",
                [(&schemas, &schemas); 3],
                [&features; 3],
                &content[..1]
            )
            .is_err()
        );
        let changed = [
            Content {
                reference: content[0].reference.clone(),
                bytes: Bytes::new(b"changed".to_vec()),
            },
            Content {
                reference: content[1].reference.clone(),
                bytes: content[1].bytes.clone(),
            },
        ];
        assert!(
            authenticate_activation_rosters_data(
                "crucible.complete-scene.installation/4",
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
                reference: content[1].reference.clone(),
                bytes: content[1].bytes.clone(),
            },
            Content {
                reference: content[0].reference.clone(),
                bytes: content[0].bytes.clone(),
            },
        ];
        assert!(
            authenticate_activation_rosters_data(
                "crucible.complete-scene.installation/4",
                [(&schemas, &schemas); 3],
                [&features; 3],
                &duplicate
            )
            .is_err()
        );
    }

    #[test]
    fn actual_installer_refuses_relabelled_four_before_namespace_birth() {
        use crate::node_qualification::packet_collection::complete::{
            installed::{InstalledCompleteScene, InstalledCompleteSceneManifest},
            tests::installed_scene_declaration,
        };
        let (_original, mut declaration) = installed_scene_declaration();
        declaration["schema"] = serde_json::json!("crucible.complete-scene.installation/4");
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
