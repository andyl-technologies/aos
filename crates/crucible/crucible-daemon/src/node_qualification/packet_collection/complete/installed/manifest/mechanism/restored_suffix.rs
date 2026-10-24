//! Selects suffix declaration only for an explicit fresh-target installation.
//!
//! ```json
//! {"schema":"crucible.complete-scene.installation/6","mechanism":{
//!   "complete_restore":"SourceSignedTransfer12",
//!   "restore_input_emitter":"CanonicalSdkRestoreInputs12",
//!   "fresh_restore_allocation":"completed_admit13"}}
//! ```
//!
//! This edition inherits the exact first-Observe profile. Startup wire class16
//! remains a separate issued carrier: only a real ticketed fresh holder can
//! admit it. Neither this manifest nor an advertised feature is native authority.

use super::*;
use crucible_node_transport::reference_packet::service::native_startup::{
    PACKET_RESTORATION_SUFFIX_FEATURE, authenticate_restoration_suffix_schema_data,
    restoration_suffix_contract_data,
};

pub(super) fn authenticate_profile_declaration_data(
    selected: &Manifest,
) -> Result<(), QualificationError> {
    if selected.schema != "crucible.complete-scene.installation/6" {
        return restoration_observation::authenticate_profile_declaration_data(selected);
    }

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

    restoration_observation::authenticate_five_profile_data(rosters, features, &selected.content)?;
    authenticate_suffix_rosters_data(rosters, features, &selected.content)
}

pub(super) fn authenticate_suffix_rosters_data(
    rosters: [(&[SchemaRef], &[SchemaRef]); 3],
    features: [&[Id]; 3],
    content: &[Content],
) -> Result<(), QualificationError> {
    for (provider, binding) in rosters {
        for formats in [provider, binding] {
            let mut found = false;
            for row in formats {
                if row.id.as_str() != PACKET_RESTORATION_SUFFIX_FEATURE {
                    continue;
                }
                if found {
                    return Err(refused());
                }
                authenticate_restoration_suffix_schema_data(row).map_err(|_| refused())?;
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
                    != restoration_suffix_contract_data()
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
            if feature.as_str() == PACKET_RESTORATION_SUFFIX_FEATURE {
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
    use crucible_node_transport::reference_packet::service::native_startup::restoration_suffix_schema;

    #[test]
    fn fresh_suffix_profile_requires_every_original_roster_feature_and_exact_content() {
        let schema = restoration_suffix_schema().unwrap();
        let formats = [schema.clone()];
        let feature = [Id::new(PACKET_RESTORATION_SUFFIX_FEATURE).unwrap()];
        let content = [Content {
            reference: schema.definition.clone(),
            bytes: Bytes::new(restoration_suffix_contract_data().to_vec()),
        }];
        let rosters = [(formats.as_slice(), formats.as_slice()); 3];
        let features = [feature.as_slice(); 3];
        assert!(authenticate_suffix_rosters_data(rosters, features, &content).is_ok());

        for member in 0..3 {
            for binding in [false, true] {
                let mut missing = rosters;
                if binding {
                    missing[member].1 = &[];
                } else {
                    missing[member].0 = &[];
                }
                assert!(authenticate_suffix_rosters_data(missing, features, &content).is_err());
            }
            let mut missing = features;
            missing[member] = &[];
            assert!(authenticate_suffix_rosters_data(rosters, missing, &content).is_err());
        }

        let duplicate = [schema.clone(), schema.clone()];
        let mut duplicated = rosters;
        duplicated[1].1 = &duplicate;
        assert!(authenticate_suffix_rosters_data(duplicated, features, &content).is_err());

        let mut changed = content;
        changed[0].bytes = Bytes::new(b"changed suffix definition".to_vec());
        assert!(authenticate_suffix_rosters_data(rosters, features, &changed).is_err());
    }

    #[test]
    fn original_scene_installer_refuses_fresh_target_before_namespace() {
        use crate::node_qualification::packet_collection::complete::{
            installed::source, tests::installed_scene_declaration,
        };

        let (_original, mut declaration) = installed_scene_declaration();
        declaration["schema"] = serde_json::json!("crucible.complete-scene.installation/6");
        let selected: Manifest = serde_json::from_value(declaration).unwrap();
        let directory = tempfile::tempdir().unwrap();
        let target = directory.path().join("fresh-only");

        assert!(source::install(selected, target.clone()).is_err());
        assert!(!target.exists());
    }
}
