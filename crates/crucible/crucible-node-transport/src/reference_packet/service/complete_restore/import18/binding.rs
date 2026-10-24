//! Checks complete import18 fields against their actual defining inputs.

use super::*;
use crate::protocol_snapshot::restored_settled17::RestoredSettledNativeImportGeometryData;

impl PacketNativeImport18Binding {
    /// Checks the closed payload without authenticating its provenance or granting work.
    ///
    /// # Errors
    /// Refuses another grammar, malformed fullrefs/digests, changed role lengths,
    /// exhausted bounds or normalization beyond its independent original maximum.
    pub fn validate_data(&self) -> Result<(), ProviderError> {
        if self.schema != NATIVE_IMPORT18_EXTENSION {
            return Err(invalid());
        }
        let _: &[u8; 32] = self
            .prepare_digest
            .as_slice()
            .try_into()
            .map_err(|_| invalid())?;
        let _: &[u8; 32] = self
            .geometry_identity
            .as_slice()
            .try_into()
            .map_err(|_| invalid())?;
        self.limits.validate_data()?;
        for reference in [
            &self.native_before,
            &self.controller17,
            &self.node25,
            &self.normalization,
        ] {
            reference.validate()?;
            if reference.media_type != "application/json" || reference.length.get() == 0 {
                return Err(invalid());
            }
        }
        self.source_family
            .authenticate_reference_data(&self.source17)?;
        self.semantic_spend_family
            .authenticate_reference_data(&self.semantic_spend)?;
        if self.semantic_spend.length.get() == 0
            || self.semantic_spend_maximum.get() == 0
            || self.semantic_spend_maximum > self.limits.maximum_requested_bytes
            || self.semantic_spend.length > self.semantic_spend_maximum
        {
            return Err(invalid());
        }
        if self.native_before.length > self.limits.maximum_before_bytes
            || self.normalization_maximum.get() == 0
            || self.normalization_maximum > self.limits.maximum_requested_bytes
            || self.normalization.length > self.normalization_maximum
        {
            return Err(invalid());
        }
        for (length, maximum) in self.role_extents.iter().zip(self.limits.role_maximums) {
            if length.get() == 0 || *length > maximum {
                return Err(invalid());
            }
        }
        crate::connection::serialized_credit(self, MAXIMUM_NATIVE_IMPORT18_BINDING_BYTES)?;
        Ok(())
    }

    /// Hashes every binding field under the distinct complete Native17 domain.
    ///
    /// The caller independently admits serializer/DOM/canonical work. No native
    /// mapping, cold-group association or allocation follows from this digest.
    ///
    /// # Errors
    /// Refuses invalid binding DATA or bounded canonical serialization failure.
    pub fn digest_data(&self) -> Result<[u8; 32], ProviderError> {
        self.validate_data()?;
        let bytes = bounded(self, MAXIMUM_NATIVE_IMPORT18_BINDING_BYTES)?;
        let mut hash =
            blake3::Hasher::new_derive_key("source-owned.packet-native-import-binding/18");
        hash.update(&bytes);
        Ok(*hash.finalize().as_bytes())
    }

    /// Joins every native role and the full original Prepare without partial-field selection.
    ///
    /// The exact Controller, Source, Node25 and parent/body conjunction is still
    /// the actual Source producer's duty before signing this binding. This check
    /// cannot manufacture those owners from portable fullrefs or a valid MAC.
    /// The caller supplies the full compiled backend definition from its genuine
    /// selected roster; this borrowed expectation is DATA, never an issuer.
    ///
    /// # Errors
    /// Refuses another full backend definition, any altered Prepare field,
    /// Controller/normalization difference or changed five-role body extent.
    pub fn authenticate_prepare_data(
        &self,
        request: &PacketCompleteRestorePrepareRequest,
        expected_backend_schema: &SchemaRef,
    ) -> Result<(), ProviderError> {
        self.validate_data()?;
        request.validate_data()?;
        expected_backend_schema.validate()?;
        let (schema_id, version) = self.native_family.snapshot_schema_data();
        if expected_backend_schema.id.as_str() != schema_id
            || expected_backend_schema.version != version
            || &request.restoration.backend_schema != expected_backend_schema
        {
            return Err(invalid());
        }
        if self.controller17 != request.host_protocol
            || self.normalization != request.restoration.mapping
        {
            return Err(invalid());
        }
        let original = bounded(
            request,
            super::super::transfer::MAXIMUM_COMPLETE_RESTORE_TRANSFER_REQUEST_BYTES,
        )?;
        compare_digest(
            self.prepare_digest.as_slice(),
            blake3::hash(&original).as_bytes(),
        )?;
        for (length, reference) in self.role_extents.iter().zip([
            &request.restoration.owner_state,
            &request.native_protocol,
            &request.native_control,
            &request.native_anchor,
            &request.restoration.journal,
        ]) {
            if *length != reference.length {
                return Err(invalid());
            }
        }
        Ok(())
    }

    /// Joins this payload to the same genuinely completed defining geometry.
    ///
    /// The geometry remains DATA. The actual Source/Window/factory and native
    /// issuer still provide their separate live custody and once-only admission.
    ///
    /// # Errors
    /// Refuses another class, geometry identity, original limit, extent or maximum.
    /// Snapshot18 is deliberately unsupported until its distinct complete native
    /// geometry exists. Source18 with actual Snapshot17 uses that exact decoder;
    /// the Source family never selects a native grammar.
    pub fn authenticate_geometry_data(
        &self,
        geometry: &RestoredSettledNativeImportGeometryData,
    ) -> Result<(), ProviderError> {
        self.validate_data()?;
        if self.native_family != PacketNativeImport18NativeFamily::Snapshot17 {
            return Err(invalid());
        }
        let expected = PacketNativeImport17Limits::from_geometry_data(
            geometry,
            extent(self.limits.maximum_target_requested_bytes)?,
            extent(self.limits.maximum_before_bytes)?,
        )?;
        if expected != self.limits
            || extent(self.normalization_maximum)? != geometry.normalization_maximum_data()
        {
            return Err(invalid());
        }
        compare_digest(self.geometry_identity.as_slice(), &geometry.identity_data())?;
        for (actual, expected) in self
            .role_extents
            .iter()
            .zip(geometry.archived_input_byte_extents_data())
        {
            if extent(*actual)? != expected {
                return Err(invalid());
            }
        }
        Ok(())
    }
}

fn extent(value: U64) -> Result<usize, ProviderError> {
    usize::try_from(value.get()).map_err(|_| invalid())
}

fn compare_digest(left: &[u8], right: &[u8]) -> Result<(), ProviderError> {
    if left.len() != 32 || right.len() != 32 || left != right {
        return Err(invalid());
    }
    Ok(())
}
