//! Retains an explicitly selected complete settled-recapture declaration.
//!
//! This installation marker inherits the entire restored suffix declaration.
//! It does not replace original Capture permission, select a live decoder or
//! create a current ledger, SourceRead, Window, target or execution grant.

use super::*;
use crucible_node_transport::reference_packet::service::complete_restore::settled_recapture::{
    authenticate_restored_settled_capture_immutable_declaration_data,
    restored_settled_capture_selection_counter_scratch_data,
};

impl PacketCompleteSemanticSource {
    /// Binds the full settled-recapture family before preparation or private birth.
    ///
    /// A failed additional comparison poisons this same occurrence. The
    /// underlying original and restored Capture paths retain their separate
    /// issuer, profile, complete codec and currentness requirements.
    ///
    /// # Errors
    /// Refuses foreign, late or repeated binding, missing inherited premises,
    /// or a missing, duplicated or changed full schema or provider feature.
    pub fn bind_original_restored_settled_capture_declaration(
        &mut self,
    ) -> Result<(), RuntimeError> {
        self.bind_original_restored_suffix_declaration()?;
        self.invocation_snapshot_declaration = Some(Declaration::Attempted);
        self.authenticate_restored_settled_recapture_declaration_tuple_data()?;
        self.storage_origin_with_error::<RuntimeError>()?;
        self.invocation_snapshot_declaration = Some(Declaration::RestoredSettledRecapture17);
        Ok(())
    }

    /// Reports the retained explicit selection as DATA without issuing rights.
    ///
    /// The inherited suffix marker stays true for this family. An earlier
    /// invocation or suffix declaration does not implicitly select recapture.
    ///
    /// # Errors
    /// Refuses foreign origin, a poisoned declaration or changed immutable data.
    pub fn is_original_restored_settled_capture_declaration_data(
        &self,
    ) -> Result<bool, RuntimeError> {
        self.is_original_invocation_snapshot_declaration_data()?;
        Ok(matches!(
            self.invocation_snapshot_declaration,
            Some(Declaration::RestoredSettledRecapture17)
        ))
    }

    /// Borrows the exact future Capture17 key schema from both immutable rosters.
    ///
    /// This DATA loan does not choose a historical archive decoder. A new
    /// explicit17 source can still load an actual signed InitialInvocation15
    /// key through its separate closed historical-family classifier.
    ///
    /// # Errors
    /// Refuses another declaration, missing/duplicate/substituted full schema,
    /// foreign source origin or differing binding and provider definitions.
    pub fn original_restored_settled_capture_schema_data(
        &self,
    ) -> Result<&SchemaRef, OperationFailure> {
        use crucible_node_transport::reference_packet::service::{
            complete_restore::settled_recapture::PACKET_RESTORED_SETTLED_NATIVE_SNAPSHOT,
            native_snapshot::authenticate_native_restored_settled17_snapshot_schema_data,
        };
        if !self
            .is_original_restored_settled_capture_declaration_data()
            .map_err(unknown)?
        {
            return Err(refused("settled Capture17 source declaration is absent"));
        }
        let installation = self.installation();
        let mut selected = None;
        for schema in &installation.provider.implementation.formats {
            if schema.id.as_str() == PACKET_RESTORED_SETTLED_NATIVE_SNAPSHOT {
                if selected.replace(schema).is_some() {
                    return Err(refused("settled Capture17 provider schema is duplicate"));
                }
                authenticate_native_restored_settled17_snapshot_schema_data(schema)
                    .map_err(unknown)?;
            }
        }
        let schema =
            selected.ok_or_else(|| refused("settled Capture17 provider schema is absent"))?;
        let mut matched = false;
        for candidate in &installation.binding.compatibility.implementation.formats {
            if candidate.id.as_str() == PACKET_RESTORED_SETTLED_NATIVE_SNAPSHOT {
                if matched || candidate != schema {
                    return Err(refused("settled Capture17 binding schema differs"));
                }
                matched = true;
            }
        }
        if !matched {
            return Err(refused("settled Capture17 binding schema is absent"));
        }
        Ok(schema)
    }

    /// Names the actual borrowed future schema loan and inherited full checks.
    pub fn original_restored_settled_capture_schema_counter_scratch_data() -> usize {
        Self::original_restored_settled_capture_declaration_counter_scratch_data()
            + size_of::<&SchemaRef>()
            + size_of::<Option<&SchemaRef>>()
            + size_of::<Result<&SchemaRef, OperationFailure>>()
            + 2 * size_of::<std::slice::Iter<'static, SchemaRef>>()
            + size_of::<Result<(), OperationFailure>>()
    }

    /// Names the full inherited comparison before later admission queries.
    pub fn original_restored_settled_capture_declaration_counter_scratch_data() -> usize {
        Self::original_invocation_snapshot_declaration_counter_scratch_data()
    }

    pub(super) fn authenticate_restored_settled_recapture_declaration_tuple_data(
        &self,
    ) -> Result<(), RuntimeError> {
        authenticate_rosters(self.installation())
    }
}

fn authenticate_rosters(installation: &CnpSemanticInstallation) -> Result<(), RuntimeError> {
    authenticate_restored_settled_capture_immutable_declaration_data(
        &installation.provider.implementation.formats,
        &installation.binding.compatibility.implementation.formats,
        &installation.provider.extensions_supported,
    )
    .map_err(|_| RuntimeError::ForeignAuthority)
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
        + size_of::<Option<&SchemaRef>>()
        + size_of::<Result<&SchemaRef, OperationFailure>>()
        + size_of::<Result<(), OperationFailure>>()
        + size_of::<Result<(), RuntimeError>>()
        + size_of::<Result<(), crucible_node_transport::ProviderError>>()
        + restored_settled_capture_selection_counter_scratch_data()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn unselected_source() -> PacketCompleteSemanticSource {
        let coordinator = super::super::super::tests::coordinator();
        PacketCompleteSemanticSource::new_producer_for_collecting_world(
            super::super::super::tests::installation(&coordinator, 0),
            super::super::super::tests::producer(),
            coordinator,
            super::super::super::tests::storage_selection(),
        )
        .unwrap()
    }

    #[test]
    fn failed_binding_cannot_issue_a_completed_startup_or_retry_as_an_old_family() {
        let mut source = unselected_source();
        assert!(
            !source
                .is_original_restored_settled_capture_declaration_data()
                .unwrap()
        );
        assert!(
            source
                .original_completed_restored_settled_startup_data()
                .is_err()
        );

        assert!(
            source
                .bind_original_restored_settled_capture_declaration()
                .is_err()
        );
        assert!(
            source
                .is_original_restored_settled_capture_declaration_data()
                .is_err()
        );
        assert!(
            source
                .original_completed_restored_settled_startup_data()
                .is_err()
        );
        assert!(matches!(
            source.bind_original_restored_settled_capture_declaration(),
            Err(RuntimeError::DuplicateOperation)
        ));
        assert!(source.ack_peer_birth.get_mut().is_none());
        assert!(source.ack_peer_association.get_mut().is_none());
        assert!(source.capture_banks.get_mut().is_none());
    }
}
