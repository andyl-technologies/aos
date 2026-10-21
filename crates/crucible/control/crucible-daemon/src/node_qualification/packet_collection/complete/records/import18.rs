//! Authenticates optional import18 definitions without selecting a live mechanism.
//!
//! Both immutable rosters and all required features precede the exact outer
//! format comparison. Partial announcements refuse; absent announcements leave
//! legacy declarations unchanged. These bodies convey no startup permission.

use super::*;
use crucible_engine::node_adapters::cnp::CnpSemanticInstallation;
use crucible_node_transport::reference_packet::service::complete_restore::import18::{
    NATIVE_IMPORT18_EXTENSION, NATIVE_IMPORT18_STAGE_SELECTION,
    authenticate_native_import18_immutable_declaration_data, native_import18_contract_data,
    native_import18_declared_features_data, native_import18_schema_data,
    native_import18_stage_contract_data, native_import18_stage_schema_data,
};

pub(super) fn declared_contracts_data(
    selected: &CnpSemanticInstallation,
) -> Result<Vec<(SchemaRef, Vec<u8>)>, QualificationError> {
    let provider = &selected.provider.implementation.formats;
    let binding = &selected.binding.compatibility.implementation.formats;
    let features = &selected.provider.extensions_supported;
    let declared = [provider, binding].iter().any(|formats| {
        formats.iter().any(|schema| {
            [NATIVE_IMPORT18_EXTENSION, NATIVE_IMPORT18_STAGE_SELECTION]
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
    ])
}
