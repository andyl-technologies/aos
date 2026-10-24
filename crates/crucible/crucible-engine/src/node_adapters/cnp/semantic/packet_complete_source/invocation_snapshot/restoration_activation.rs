//! Binds the explicit installation-four profile without selecting live purpose.
//!
//! Original capture and restoration targets retain the same full schemas. This
//! allocation-free DATA marker cannot issue an activation/upload claim, infer a
//! native permit from advertisement, or change historical world identities.

use super::*;
use crucible_node_transport::reference_packet::service::complete_restore::activation::{
    PACKET_RESTORATION_ACTIVATION_FEATURE, authenticate_restoration_activation_schema_data,
    restoration_activation_schema_counter_scratch_data,
    upload::{
        PACKET_RESTORATION_ACTIVATION_UPLOAD_FEATURE,
        authenticate_restoration_activation_upload_schema_data,
        restoration_activation_upload_schema_counter_scratch_data,
    },
};

impl PacketCompleteSemanticSource {
    /// Binds the explicit full activation profile before Source banks or birth.
    ///
    /// The ordinary declaration validator selects this method only for edition
    /// four. The original invocation tuple is still required; a failed attempt
    /// stays spent. No live purpose, startup bank, MAC key or permit is created.
    ///
    /// # Errors
    /// Refuses foreign/repeated/late binding, an incomplete invocation tuple,
    /// absent or changed full schemas, duplicate entries or missing features.
    pub fn bind_original_restoration_activation_declaration(&mut self) -> Result<(), RuntimeError> {
        self.bind_original_invocation_snapshot_declaration()?;
        self.invocation_snapshot_declaration = Some(Declaration::Attempted);
        self.authenticate_restoration_activation_declaration_tuple_data()?;
        self.storage_origin_with_error::<RuntimeError>()?;
        self.invocation_snapshot_declaration = Some(Declaration::RestorationActivation14);
        Ok(())
    }

    /// Reports the retained explicit profile as DATA across legitimate phases.
    ///
    /// Feature advertisement or a valid schema alone leaves legacy Sources
    /// unselected. Actual currentness, private purpose and owned claims remain
    /// independent requirements of every selected live operation.
    ///
    /// # Errors
    /// Refuses foreign origin, a failed declaration or changed immutable data.
    pub fn is_original_restoration_activation_declaration_data(
        &self,
    ) -> Result<bool, RuntimeError> {
        self.is_original_invocation_snapshot_declaration_data()?;
        Ok(matches!(
            self.invocation_snapshot_declaration,
            Some(
                Declaration::RestorationActivation14
                    | Declaration::RestorationObservation14
                    | Declaration::RestorationSuffix14
                    | Declaration::RestoredSettledRecapture17
            )
        ))
    }

    /// Names the full borrowed classifier's fixed views before later queries.
    ///
    /// No heap bank is built. The existing Source inline marker root is counted
    /// by its actual owner; these headers also include the parent tuple query.
    pub fn original_restoration_activation_declaration_counter_scratch_data() -> usize {
        Self::original_invocation_snapshot_declaration_counter_scratch_data()
    }

    pub(super) fn authenticate_restoration_activation_declaration_tuple_data(
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
        let mut activation = false;
        let mut upload = false;
        for schema in formats {
            match schema.id.as_str() {
                PACKET_RESTORATION_ACTIVATION_FEATURE => {
                    if activation {
                        return Err(RuntimeError::ForeignAuthority);
                    }
                    authenticate_restoration_activation_schema_data(schema)
                        .map_err(|_| RuntimeError::ForeignAuthority)?;
                    activation = true;
                }
                PACKET_RESTORATION_ACTIVATION_UPLOAD_FEATURE => {
                    if upload {
                        return Err(RuntimeError::ForeignAuthority);
                    }
                    authenticate_restoration_activation_upload_schema_data(schema)
                        .map_err(|_| RuntimeError::ForeignAuthority)?;
                    upload = true;
                }
                _ => {}
            }
        }
        if !activation || !upload {
            return Err(RuntimeError::ForeignAuthority);
        }
    }
    for expected in [
        PACKET_RESTORATION_ACTIVATION_FEATURE,
        PACKET_RESTORATION_ACTIVATION_UPLOAD_FEATURE,
    ] {
        let mut found = false;
        for feature in &installation.provider.extensions_supported {
            if feature.as_str() == expected {
                if found {
                    return Err(RuntimeError::ForeignAuthority);
                }
                found = true;
            }
        }
        if !found {
            return Err(RuntimeError::ForeignAuthority);
        }
    }
    Ok(())
}

pub(super) fn counter_scratch_data() -> usize {
    size_of::<&CnpSemanticInstallation>()
        + size_of::<[&[SchemaRef]; 2]>()
        + size_of::<std::array::IntoIter<&[SchemaRef], 2>>()
        + size_of::<std::slice::Iter<'_, SchemaRef>>()
        + size_of::<[&str; 2]>()
        + size_of::<std::array::IntoIter<&str, 2>>()
        + size_of::<std::slice::Iter<'_, Id>>()
        + size_of::<&SchemaRef>()
        + size_of::<&Id>()
        + size_of::<&str>()
        + 3 * size_of::<bool>()
        + size_of::<Option<Declaration>>()
        + size_of::<Result<bool, RuntimeError>>()
        + size_of::<Result<(), RuntimeError>>()
        + restoration_activation_schema_counter_scratch_data()
        + restoration_activation_upload_schema_counter_scratch_data()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crucible_node_transport::reference_packet::service::complete_restore::activation::{
        restoration_activation_schema, upload::restoration_activation_upload_schema,
    };

    fn installation() -> CnpSemanticInstallation {
        let coordinator = super::super::super::tests::coordinator();
        let mut installation = super::super::super::tests::installation(&coordinator, 0);
        let formats = [
            restoration_activation_schema().unwrap(),
            restoration_activation_upload_schema().unwrap(),
        ];
        for roster in [
            &mut installation.provider.implementation.formats,
            &mut installation.binding.compatibility.implementation.formats,
        ] {
            roster.extend(formats.iter().cloned());
            roster.sort_by(|left, right| left.id.cmp(&right.id));
        }
        installation.provider.extensions_supported.extend([
            Id::new(PACKET_RESTORATION_ACTIVATION_FEATURE).unwrap(),
            Id::new(PACKET_RESTORATION_ACTIVATION_UPLOAD_FEATURE).unwrap(),
        ]);
        installation.provider.extensions_supported.sort();
        installation
    }

    #[test]
    fn full_activation_profile_requires_both_actual_definitions_in_each_roster() {
        let original = installation();
        authenticate_rosters(&original).unwrap();
        for binding in [false, true] {
            for feature in [
                PACKET_RESTORATION_ACTIVATION_FEATURE,
                PACKET_RESTORATION_ACTIVATION_UPLOAD_FEATURE,
            ] {
                for change in 0..4 {
                    let mut changed = installation();
                    let roster = if binding {
                        &mut changed.binding.compatibility.implementation.formats
                    } else {
                        &mut changed.provider.implementation.formats
                    };
                    let position = roster
                        .iter()
                        .position(|schema| schema.id.as_str() == feature)
                        .unwrap();
                    match change {
                        0 => {
                            roster.remove(position);
                        }
                        1 => {
                            roster.push(roster[position].clone());
                        }
                        2 => {
                            roster[position].definition.hash.digest = "0".repeat(64);
                        }
                        3 => {
                            roster[position]
                                .extensions
                                .insert("foreign".into(), serde_json::Value::Null);
                        }
                        _ => unreachable!(),
                    }
                    assert!(authenticate_rosters(&changed).is_err());
                }
            }
        }
        for feature in [
            PACKET_RESTORATION_ACTIVATION_FEATURE,
            PACKET_RESTORATION_ACTIVATION_UPLOAD_FEATURE,
        ] {
            let mut changed = installation();
            changed
                .provider
                .extensions_supported
                .retain(|one| one.as_str() != feature);
            assert!(authenticate_rosters(&changed).is_err());
        }
    }

    #[test]
    fn legacy_source_never_infers_profile_and_failed_explicit_attempt_stays_spent() {
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
                .is_original_restoration_activation_declaration_data()
                .unwrap()
        );
        assert!(
            source
                .bind_original_restoration_activation_declaration()
                .is_err()
        );
        assert!(
            source
                .is_original_restoration_activation_declaration_data()
                .is_err()
        );
        assert!(
            source
                .bind_original_restoration_activation_declaration()
                .is_err()
        );
        assert!(source.capture_banks.get_mut().is_none());
        assert!(source.ack_peer_birth.get_mut().is_none());
    }
}
