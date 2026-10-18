//! Retains explicit suffix startup selection before Source banks or native birth.
//!
//! The complete first-Observe declaration remains an inherited requirement.
//! This allocation-free operator-install marker supplies neither an action
//! claim nor a startup reservation. A live path must independently admit the
//! new carrier and retain its real native post-first-Observe witness.

use super::*;
use crucible_node_provider::reference_packet::service::native_startup::{
    PACKET_RESTORATION_SUFFIX_FEATURE, authenticate_restoration_suffix_schema_data,
    restoration_suffix_schema_counter_scratch_data,
};

impl PacketCompleteSemanticSource {
    /// Binds the distinct full suffix family before any preparation bank.
    ///
    /// The caller explicitly selects this declaration. An advertised feature or
    /// matching schema alone does not upgrade an existing Source. Every failed
    /// additional comparison leaves the actual declaration irreversibly spent.
    ///
    /// # Errors
    /// Refuses foreign/late/repeated binding, missing inherited premises, or a
    /// changed, absent or duplicate full schema/feature in either actual roster.
    pub fn bind_original_restored_suffix_declaration(&mut self) -> Result<(), RuntimeError> {
        self.bind_original_restoration_observation_declaration()?;
        self.invocation_snapshot_declaration = Some(Declaration::Attempted);
        self.authenticate_restored_suffix_declaration_tuple_data()?;
        self.storage_origin_with_error::<RuntimeError>()?;
        self.invocation_snapshot_declaration = Some(Declaration::RestorationSuffix14);
        Ok(())
    }

    /// Reports only the retained explicit suffix selection as immutable DATA.
    ///
    /// True does not issue a native reservation, SourceRead, suffix checkpoint,
    /// evolving inventory, action permission or replacement Capture codec.
    ///
    /// # Errors
    /// Refuses foreign origin, a poisoned attempt or changed immutable rosters.
    pub fn is_original_restored_suffix_declaration_data(&self) -> Result<bool, RuntimeError> {
        self.is_original_invocation_snapshot_declaration_data()?;
        Ok(matches!(
            self.invocation_snapshot_declaration,
            Some(Declaration::RestorationSuffix14 | Declaration::RestoredSettledRecapture17)
        ))
    }

    /// Names complete inherited declaration scratch before later live queries.
    pub fn original_restored_suffix_declaration_counter_scratch_data() -> usize {
        Self::original_invocation_snapshot_declaration_counter_scratch_data()
    }

    pub(super) fn authenticate_restored_suffix_declaration_tuple_data(
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
            if schema.id.as_str() == PACKET_RESTORATION_SUFFIX_FEATURE {
                if found {
                    return Err(RuntimeError::ForeignAuthority);
                }
                authenticate_restoration_suffix_schema_data(schema)
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
        if feature.as_str() == PACKET_RESTORATION_SUFFIX_FEATURE {
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
    // The new caller, tuple classifier and installation loan are distinct
    // borrowed views beside the inherited declaration validators.
    3 * size_of::<&PacketCompleteSemanticSource>()
        + size_of::<&mut PacketCompleteSemanticSource>()
        + size_of::<&CnpSemanticInstallation>()
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
        + restoration_suffix_schema_counter_scratch_data()
}

#[cfg(test)]
mod tests {
    use super::super::super::tests as fixture;
    use super::*;
    use crucible_node_provider::reference_packet::service::native_startup::restoration_suffix_schema;

    fn installation(
        coordinator: &PacketNative5CoordinatorInstallation,
        index: usize,
    ) -> CnpSemanticInstallation {
        let mut installed = fixture::installation(coordinator, index);
        let suffix = restoration_suffix_schema().expect("compiled full suffix schema");
        for roster in [
            &mut installed.provider.implementation.formats,
            &mut installed.binding.compatibility.implementation.formats,
        ] {
            roster.push(suffix.clone());
            roster.sort_by(|left, right| left.id.cmp(&right.id));
        }
        installed
            .provider
            .extensions_supported
            .push(Id::new(PACKET_RESTORATION_SUFFIX_FEATURE).unwrap());
        installed.provider.extensions_supported.sort();
        installed
    }

    #[test]
    fn suffix_rosters_require_full_definition_in_both_rosters_and_unique_feature() {
        let coordinator = fixture::coordinator();
        authenticate_rosters(&installation(&coordinator, 0)).unwrap();

        for binding in [false, true] {
            for axis in 0..9 {
                let mut installed = installation(&coordinator, 0);
                let roster = if binding {
                    &mut installed.binding.compatibility.implementation.formats
                } else {
                    &mut installed.provider.implementation.formats
                };
                let index = roster
                    .iter()
                    .position(|schema| schema.id.as_str() == PACKET_RESTORATION_SUFFIX_FEATURE)
                    .unwrap();
                match axis {
                    0 => {
                        roster.remove(index);
                    }
                    1 => {
                        roster.push(roster[index].clone());
                    }
                    2 => {
                        roster[index].version += 1;
                    }
                    3 => {
                        roster[index].definition.hash.digest = "0".repeat(64);
                    }
                    4 => {
                        roster[index].definition.length = U64::new(1);
                    }
                    5 => {
                        roster[index].definition.media_type = "application/octet-stream".into();
                    }
                    6 => {
                        roster[index].definition.hash.domain = "cnp.changed.v1".into();
                    }
                    7 => {
                        roster[index].definition.hash.algorithm = "changed-256".into();
                    }
                    _ => {
                        roster[index]
                            .extensions
                            .insert("unknown".into(), serde_json::Value::Null);
                    }
                }
                assert!(authenticate_rosters(&installed).is_err());
            }
        }

        let mut missing = installation(&coordinator, 0);
        missing
            .provider
            .extensions_supported
            .retain(|feature| feature.as_str() != PACKET_RESTORATION_SUFFIX_FEATURE);
        assert!(authenticate_rosters(&missing).is_err());

        let mut duplicate = installation(&coordinator, 0);
        duplicate
            .provider
            .extensions_supported
            .push(Id::new(PACKET_RESTORATION_SUFFIX_FEATURE).unwrap());
        assert!(authenticate_rosters(&duplicate).is_err());
    }

    #[test]
    fn actual_source_does_not_infer_suffix_and_failed_binding_cannot_renew() {
        for reactive in [false, true] {
            let coordinator = fixture::coordinator();
            let mut source = if reactive {
                PacketCompleteSemanticSource::new_reactive_for_collecting_world(
                    fixture::installation(&coordinator, 1),
                    fixture::reactive(&coordinator, 1),
                    coordinator,
                    fixture::storage_selection(),
                )
                .expect("actual reactive Source")
            } else {
                PacketCompleteSemanticSource::new_producer_for_collecting_world(
                    fixture::installation(&coordinator, 0),
                    fixture::producer(),
                    coordinator,
                    fixture::storage_selection(),
                )
                .expect("actual producer Source")
            };

            // An actual legacy constructor does not manufacture the inherited
            // selected tuple, private member, SourceRead or native authority.
            assert!(
                !source
                    .is_original_restored_suffix_declaration_data()
                    .unwrap()
            );
            assert!(source.bind_original_restored_suffix_declaration().is_err());
            assert!(matches!(
                source.invocation_snapshot_declaration,
                Some(Declaration::Attempted)
            ));
            assert!(
                source
                    .is_original_restored_suffix_declaration_data()
                    .is_err()
            );
            assert!(source.bind_original_restored_suffix_declaration().is_err());

            assert!(source.capture_banks.get_mut().is_none());
            assert!(source.capture_execution.get_mut().is_none());
            assert!(source.ack_peer_birth.get_mut().is_none());
            assert!(source.authenticate_current_native().is_err());
        }
    }

    #[test]
    fn foreign_source_origin_precedes_suffix_selection_and_attempt_state() {
        let coordinator = fixture::coordinator();
        let mut source = PacketCompleteSemanticSource::new_producer_for_collecting_world(
            fixture::installation(&coordinator, 0),
            fixture::producer(),
            coordinator,
            fixture::storage_selection(),
        )
        .unwrap();

        let process = source.process;
        source.process = process.wrapping_add(1);

        assert!(matches!(
            source.bind_original_restored_suffix_declaration(),
            Err(RuntimeError::ForeignAuthority)
        ));
        assert!(source.invocation_snapshot_declaration.is_none());
        assert!(matches!(
            source.is_original_restored_suffix_declaration_data(),
            Err(RuntimeError::ForeignAuthority)
        ));

        source.process = process;
        assert!(
            !source
                .is_original_restored_suffix_declaration_data()
                .unwrap()
        );
        assert!(source.ack_peer_birth.get_mut().is_none());
    }
}
