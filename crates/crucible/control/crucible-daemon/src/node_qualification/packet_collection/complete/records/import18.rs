//! Authenticates optional import18 definitions without selecting a live mechanism.
//!
//! Both immutable rosters and all required features precede the exact outer
//! format comparison. Partial announcements refuse; absent announcements leave
//! legacy declarations unchanged. These bodies convey no startup permission.

use super::*;
use crucible_engine::node_adapters::cnp::CnpSemanticInstallation;
use crucible_node_transport::reference_packet::service::complete_restore::import18::{
    NATIVE_IMPORT18_EXTENSION, NATIVE_IMPORT18_RESTORED_RECORD_SCHEMA,
    NATIVE_IMPORT18_STAGE_SELECTION, authenticate_native_import18_immutable_declaration_data,
    native_import18_contract_data, native_import18_declared_features_data,
    native_import18_restored_record_contract_data, native_import18_restored_record_schema_data,
    native_import18_schema_data, native_import18_stage_contract_data,
    native_import18_stage_schema_data,
};

pub(super) fn declared_contracts_data(
    selected: &CnpSemanticInstallation,
) -> Result<Vec<(SchemaRef, Vec<u8>)>, QualificationError> {
    let provider = &selected.provider.implementation.formats;
    let binding = &selected.binding.compatibility.implementation.formats;
    let features = &selected.provider.extensions_supported;
    declared_rosters_data([provider, binding], features)
}

fn declared_rosters_data(
    [provider, binding]: [&[SchemaRef]; 2],
    features: &[Id],
) -> Result<Vec<(SchemaRef, Vec<u8>)>, QualificationError> {
    let declared = [provider, binding].iter().any(|formats| {
        formats.iter().any(|schema| {
            [
                NATIVE_IMPORT18_EXTENSION,
                NATIVE_IMPORT18_STAGE_SELECTION,
                NATIVE_IMPORT18_RESTORED_RECORD_SCHEMA,
            ]
            .contains(&schema.id.as_str())
        })
    }) || features
        .iter()
        .any(|feature| native_import18_declared_features_data().contains(&feature.as_str()));
    if !declared {
        return Ok(Vec::new());
    }

    authenticate_native_import18_immutable_declaration_data(provider, binding, features)
        .map_err(|_| refused())?;
    Ok(vec![
        (
            native_import18_schema_data().map_err(|_| refused())?,
            native_import18_contract_data().map_err(|_| refused())?,
        ),
        (
            native_import18_stage_schema_data().map_err(|_| refused())?,
            native_import18_stage_contract_data().map_err(|_| refused())?,
        ),
        (
            native_import18_restored_record_schema_data().map_err(|_| refused())?,
            native_import18_restored_record_contract_data().map_err(|_| refused())?,
        ),
    ])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn complete_optional_declaration_materializes_all_three_verified_bodies() {
        let formats = vec![
            native_import18_schema_data().unwrap(),
            native_import18_stage_schema_data().unwrap(),
            native_import18_restored_record_schema_data().unwrap(),
        ];
        let features: Vec<_> = native_import18_declared_features_data()
            .into_iter()
            .map(|name| Id::new(name).unwrap())
            .collect();

        let definitions = declared_rosters_data([&formats, &formats], &features).unwrap();

        assert_eq!(definitions.len(), 3);
        for (schema, body) in definitions {
            assert!(formats.contains(&schema));
            schema.definition.verify(&body).unwrap();
        }
    }

    #[test]
    fn absent_declaration_is_legacy_but_each_partial_announcement_refuses() {
        assert!(declared_rosters_data([&[], &[]], &[]).unwrap().is_empty());
        for schema in [
            native_import18_schema_data().unwrap(),
            native_import18_stage_schema_data().unwrap(),
            native_import18_restored_record_schema_data().unwrap(),
        ] {
            let announcement = std::slice::from_ref(&schema);
            assert!(declared_rosters_data([announcement, &[]], &[]).is_err());
            assert!(declared_rosters_data([&[], announcement], &[]).is_err());
        }
        for name in native_import18_declared_features_data() {
            let feature = Id::new(name).unwrap();
            assert!(declared_rosters_data([&[], &[]], &[feature]).is_err());
        }
    }
}
