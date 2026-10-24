//! Validates explicit fresh-only17 selection before Source banks or namespaces.
//!
//! ```text
//! {schema:"crucible.complete-scene.installation/7",mechanism:{...transfer12...}}
//! ```
//!
//! Original15 may advertise the same immutable capabilities without choosing
//! this fresh target family. The installer must retain genuine archive tickets,
//! actual admitted17 rows and a private carrier before any native effect.

use super::*;
use crucible_node_transport::reference_packet::service::complete_restore::settled_recapture::authenticate_restored_settled_capture_immutable_declaration_data;

pub(super) fn authenticate_profile_declaration_data(
    selected: &Manifest,
) -> Result<(), QualificationError> {
    if selected.schema != "crucible.complete-scene.installation/7" {
        return restored_suffix::authenticate_profile_declaration_data(selected);
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
    restored_suffix::authenticate_suffix_rosters_data(rosters, features, &selected.content)?;
    for ((provider, binding), features) in rosters.into_iter().zip(features) {
        authenticate_restored_settled_capture_immutable_declaration_data(
            provider, binding, features,
        )
        .map_err(|_| refused())?;
    }
    // Compare actual full definition bytes, not merely matching identifier tags.
    let expected = crucible_node_transport::reference_packet::service::complete_restore::settled_recapture::restored_settled_capture_declared_contracts_data()
        .map_err(|_| refused())?;
    for (schema, bytes) in expected {
        let mut found = false;
        for content in &selected.content {
            if content.reference == schema.definition {
                if found || content.bytes.as_slice() != bytes {
                    return Err(refused());
                }
                content.reference.verify(content.bytes.as_slice())?;
                found = true;
            }
        }
        if !found {
            return Err(refused());
        }
    }
    Ok(())
}
