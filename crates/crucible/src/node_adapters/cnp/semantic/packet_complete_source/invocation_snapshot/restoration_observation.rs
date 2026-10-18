//! Retains the explicit first-Observe profile before Source construction banks.
//!
//! Full immutable schema placement is DATA shared by original capture and its
//! genuine restoration target. It never grants a current operation or infers a
//! native purpose from feature advertisement, request fields or absent state.

use super::*;
use crucible_node_provider::reference_packet::service::complete_restore::restoration_observe::{
    PACKET_RESTORATION_OBSERVE_FEATURE, authenticate_restoration_observe_schema_data,
    restoration_observe_schema_counter_scratch_data,
};

impl PacketCompleteSemanticSource {
    /// Binds the distinct installation-five declaration before banks or birth.
    ///
    /// The parent invocation and activation declarations remain required. This
    /// binder creates no scope, key, native grant, startup allocation or action.
    /// A failed additional full-schema check poisons this same occurrence.
    ///
    /// # Errors
    /// Refuses foreign, late or duplicate binding, missing parent premises or a
    /// missing, duplicate, changed Observe schema or unsupported feature roster.
    pub fn bind_original_restoration_observation_declaration(
        &mut self,
    ) -> Result<(), RuntimeError> {
        self.bind_original_restoration_activation_declaration()?;
        self.invocation_snapshot_declaration = Some(Declaration::Attempted);
        self.authenticate_restoration_observation_declaration_tuple_data()?;
        self.storage_origin_with_error::<RuntimeError>()?;
        self.invocation_snapshot_declaration = Some(Declaration::RestorationObservation14);
        Ok(())
    }

    /// Reports only the actually retained explicit first-Observe declaration.
    ///
    /// Legacy invocation/activation declarations stay false. Even a true result
    /// requires the same original scope, World originals, current Source and
    /// independent Core/native permissions before the once-only live action.
    ///
    /// # Errors
    /// Refuses foreign origin, a poisoned declaration or changed immutable data.
    pub fn is_original_restoration_observation_declaration_data(
        &self,
    ) -> Result<bool, RuntimeError> {
        self.is_original_invocation_snapshot_declaration_data()?;
        Ok(matches!(
            self.invocation_snapshot_declaration,
            Some(
                Declaration::RestorationObservation14
                    | Declaration::RestorationSuffix14
                    | Declaration::RestoredSettledRecapture17
            )
        ))
    }

    /// Names the complete inherited borrowed classifier's defining fixed views.
    pub fn original_restoration_observation_declaration_counter_scratch_data() -> usize {
        Self::original_invocation_snapshot_declaration_counter_scratch_data()
    }

    pub(super) fn authenticate_restoration_observation_declaration_tuple_data(
        &self,
    ) -> Result<(), RuntimeError> {
        authenticate_rosters(self.installation())
    }
}

fn authenticate_rosters(installation: &CnpSemanticInstallation) -> Result<(), RuntimeError> {
    for formats in [
        installation.provider.implementation.formats.as_slice(),
        installation
            .binding
            .compatibility
            .implementation
            .formats
            .as_slice(),
    ] {
        let mut found = false;
        for schema in formats {
            if schema.id.as_str() == PACKET_RESTORATION_OBSERVE_FEATURE {
                if found {
                    return Err(RuntimeError::ForeignAuthority);
                }
                authenticate_restoration_observe_schema_data(schema)
                    .map_err(|_| RuntimeError::ForeignAuthority)?;
                found = true;
            }
        }
        if !found {
            return Err(RuntimeError::ForeignAuthority);
        }
    }
    let mut found = false;
    for feature in &installation.provider.extensions_supported {
        if feature.as_str() == PACKET_RESTORATION_OBSERVE_FEATURE {
            if found {
                return Err(RuntimeError::ForeignAuthority);
            }
            found = true;
        }
    }
    if !found {
        return Err(RuntimeError::ForeignAuthority);
    }
    Ok(())
}

pub(super) fn counter_scratch_data() -> usize {
    size_of::<&CnpSemanticInstallation>()
        + size_of::<[&[SchemaRef]; 2]>()
        + size_of::<std::array::IntoIter<&[SchemaRef], 2>>()
        + size_of::<std::slice::Iter<'_, SchemaRef>>()
        + size_of::<std::slice::Iter<'_, Id>>()
        + size_of::<&SchemaRef>()
        + size_of::<&Id>()
        + size_of::<&str>()
        + 2 * size_of::<bool>()
        + size_of::<Option<Declaration>>()
        + size_of::<Result<bool, RuntimeError>>()
        + size_of::<Result<(), RuntimeError>>()
        + size_of::<Result<(), crucible_node_provider::ProviderError>>()
        + restoration_observe_schema_counter_scratch_data()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crucible_node_provider::reference_packet::service::complete_restore::restoration_observe::restoration_observe_schema;

    fn installation() -> CnpSemanticInstallation {
        let coordinator = super::super::super::tests::coordinator();
        let mut installed = super::super::super::tests::installation(&coordinator, 0);
        let schema = restoration_observe_schema().unwrap();
        for formats in [
            &mut installed.provider.implementation.formats,
            &mut installed.binding.compatibility.implementation.formats,
        ] {
            formats.push(schema.clone());
            formats.sort_by(|a, b| a.id.cmp(&b.id));
        }
        installed
            .provider
            .extensions_supported
            .push(Id::new(PACKET_RESTORATION_OBSERVE_FEATURE).unwrap());
        installed.provider.extensions_supported.sort();
        installed
    }

    #[test]
    fn observation_addition_requires_exact_definition_in_each_roster_and_feature() {
        authenticate_rosters(&installation()).unwrap();
        for binding in [false, true] {
            for change in 0..5 {
                let mut installed = installation();
                let formats = if binding {
                    &mut installed.binding.compatibility.implementation.formats
                } else {
                    &mut installed.provider.implementation.formats
                };
                let index = formats
                    .iter()
                    .position(|row| row.id.as_str() == PACKET_RESTORATION_OBSERVE_FEATURE)
                    .unwrap();
                match change {
                    0 => {
                        formats.remove(index);
                    }
                    1 => {
                        formats.push(formats[index].clone());
                    }
                    2 => {
                        formats[index].version += 1;
                    }
                    3 => {
                        formats[index].definition.hash.digest = "0".repeat(64);
                    }
                    4 => {
                        formats[index]
                            .extensions
                            .insert("changed".into(), serde_json::Value::Null);
                    }
                    _ => unreachable!(),
                }
                assert!(authenticate_rosters(&installed).is_err());
            }
        }
        let mut installed = installation();
        installed
            .provider
            .extensions_supported
            .retain(|feature| feature.as_str() != PACKET_RESTORATION_OBSERVE_FEATURE);
        assert!(authenticate_rosters(&installed).is_err());
    }

    #[test]
    fn legacy_source_does_not_infer_observation_and_failed_binding_stays_spent() {
        let coordinator = super::super::super::tests::coordinator();
        let mut source = PacketCompleteSemanticSource::new_producer_for_collecting_world(
            super::super::super::tests::installation(&coordinator, 0),
            super::super::super::tests::producer(),
            coordinator,
            super::super::super::tests::storage_selection(),
        )
        .unwrap();
        assert!(
            !source
                .is_original_restoration_observation_declaration_data()
                .unwrap()
        );
        assert!(
            source
                .bind_original_restoration_observation_declaration()
                .is_err()
        );
        assert!(
            source
                .is_original_restoration_observation_declaration_data()
                .is_err()
        );
        assert!(
            source
                .bind_original_restoration_observation_declaration()
                .is_err()
        );
        assert!(source.capture_banks.get_mut().is_none());
        assert!(source.ack_peer_birth.get_mut().is_none());
        assert!(source.capture_execution.get_mut().is_none());
    }
}
