//! Authenticates the complete optional settled17 capability before roster matching.
//!
//! Original15 and fresh17 Sources can advertise the same immutable definitions.
//! These borrowed rosters supply no native startup, decoder or Capture permission.

use super::*;
use crucible_engine::node_adapters::cnp::CnpSemanticInstallation;
use crucible_node_transport::reference_packet::service::complete_restore::settled_recapture::{
    authenticate_restored_settled_capture_immutable_declaration_data,
    restored_settled_capture_declared_contracts_data,
    restored_settled_capture_declared_features_data,
};

// These names detect a partial declaration; the defining validator authenticates
// every complete SchemaRef and feature before any body joins the exact roster.
const SCHEMA_IDS: [&str; 8] = [
    "source-owned.packet-restored-settled-recapture/1",
    "source-owned.packet-native-continuation/17",
    "source-owned.packet-restored-settled-capture/17",
    "source-owned.packet-restored-settled-capture-upload/17",
    "source-owned.packet-native-after-restored-settled-confirmation/17",
    "source-owned.packet-restored-settled-startup/17",
    "source-owned.coordinator-commitment-checkpoint/17",
    "source-owned.packet-restored-input-reactive/17",
];

pub(super) fn declared_contracts_data(
    selected: &CnpSemanticInstallation,
) -> Result<Vec<(SchemaRef, Vec<u8>)>, QualificationError> {
    declared_rosters_data(
        [
            &selected.provider.implementation.formats,
            &selected.binding.compatibility.implementation.formats,
        ],
        &selected.provider.extensions_supported,
    )
}

fn declared_rosters_data(
    rosters: [&[SchemaRef]; 2],
    features: &[Id],
) -> Result<Vec<(SchemaRef, Vec<u8>)>, QualificationError> {
    let declared = rosters.iter().any(|formats| {
        formats
            .iter()
            .any(|schema| SCHEMA_IDS.contains(&schema.id.as_str()))
    }) || features.iter().any(|feature| {
        restored_settled_capture_declared_features_data().contains(&feature.as_str())
    });
    if !declared {
        return Ok(Vec::new());
    }

    authenticate_restored_settled_capture_immutable_declaration_data(
        rosters[0], rosters[1], features,
    )
    .map_err(|_| refused())?;
    Ok(restored_settled_capture_declared_contracts_data()
        .map_err(|_| refused())?
        .map(|(schema, bytes)| (schema, bytes.to_vec()))
        .collect())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn optional_capability_requires_all_eight_definitions_and_six_features() {
        let definitions: Vec<_> = restored_settled_capture_declared_contracts_data()
            .unwrap()
            .collect();
        assert_eq!(definitions.len(), SCHEMA_IDS.len());
        let formats: Vec<_> = definitions
            .iter()
            .map(|(schema, _)| schema.clone())
            .collect();
        let features: Vec<_> = restored_settled_capture_declared_features_data()
            .iter()
            .map(|feature| Id::new(*feature).unwrap())
            .collect();
        let rosters = [formats.as_slice(); 2];

        assert!(declared_rosters_data([&[]; 2], &[]).unwrap().is_empty());
        assert_eq!(declared_rosters_data(rosters, &features).unwrap().len(), 8);
        for (schema, bytes) in &definitions {
            assert!(SCHEMA_IDS.contains(&schema.id.as_str()));
            schema.definition.verify(bytes).unwrap();
        }

        for side in 0..2 {
            for index in 0..formats.len() {
                let mut changed = formats.clone();
                changed.remove(index);
                let mut altered = rosters;
                altered[side] = &changed;
                assert!(declared_rosters_data(altered, &features).is_err());

                let mut changed = formats.clone();
                changed.push(formats[index].clone());
                altered[side] = &changed;
                assert!(declared_rosters_data(altered, &features).is_err());

                let mut changed = formats.clone();
                changed[index].definition =
                    canonical::content_ref(b"changed", "application/json").unwrap();
                altered[side] = &changed;
                assert!(declared_rosters_data(altered, &features).is_err());
            }
        }
        for index in 0..features.len() {
            let mut changed = features.clone();
            changed.remove(index);
            assert!(declared_rosters_data(rosters, &changed).is_err());

            let mut changed = features.clone();
            changed.push(features[index].clone());
            assert!(declared_rosters_data(rosters, &changed).is_err());
        }
        assert!(declared_rosters_data(rosters, &[]).is_err());
        assert!(declared_rosters_data([&[]; 2], &features).is_err());
    }
}
