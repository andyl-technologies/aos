//! Checks complete Native17 import fields against their actual defining inputs.

use super::*;
use crate::protocol_snapshot::restored_settled17::{
    RestoredSettledNative17Limits, RestoredSettledNativeImportGeometryData,
};

impl PacketNativeImport17Limits {
    /// Projects limits from the actual completed native17 geometry.
    ///
    /// Target and before limits are independent original constructor inputs;
    /// they are not inferred from encoded role lengths or a schema label.
    ///
    /// # Errors
    /// Refuses another import class, unsupported scalar width or invalid limits.
    pub fn from_geometry_data(
        geometry: &RestoredSettledNativeImportGeometryData,
        maximum_target_requested_bytes: usize,
        maximum_before_bytes: usize,
    ) -> Result<Self, ProviderError> {
        let (_, limits) = geometry
            .settled17_decoder_geometry_data()
            .ok_or_else(invalid)?;
        let (objects, bytes, depth) = limits.immutable_limits_data();
        let mut role_maximums = [U64::new(0); 5];
        for (slot, actual) in role_maximums
            .iter_mut()
            .zip(limits.input_role_limits_data())
        {
            *slot = quantity(actual)?;
        }
        let result = Self {
            role_maximums,
            immutable_objects: quantity(objects)?,
            immutable_bytes: quantity(bytes)?,
            immutable_depth: quantity(depth)?,
            maximum_nodes: quantity(limits.maximum_nodes_data())?,
            maximum_requested_bytes: quantity(limits.maximum_requested_bytes_data())?,
            maximum_target_requested_bytes: quantity(maximum_target_requested_bytes)?,
            maximum_before_bytes: quantity(maximum_before_bytes)?,
        };
        result.validate_data()?;
        Ok(result)
    }

    /// Checks finite values using the same defining native reader limit rules.
    ///
    /// # Errors
    /// Refuses zero, overflow, unsupported depth, limits above the unchanged
    /// transfer allocation ceiling or inconsistent independent target/before rows.
    pub fn validate_data(&self) -> Result<(), ProviderError> {
        const MAXIMUM: u64 = 512 * 1024 * 1024;
        for value in self.role_maximums.iter().chain([
            &self.immutable_objects,
            &self.immutable_bytes,
            &self.immutable_depth,
            &self.maximum_nodes,
            &self.maximum_requested_bytes,
            &self.maximum_target_requested_bytes,
            &self.maximum_before_bytes,
        ]) {
            if value.get() == 0 || value.get() > MAXIMUM {
                return Err(invalid());
            }
        }
        self.reader_limits_data()?;
        if self.maximum_target_requested_bytes > self.maximum_requested_bytes
            || self.maximum_before_bytes > self.maximum_requested_bytes
        {
            return Err(invalid());
        }
        Ok(())
    }

    /// Reconstructs only the original reader's fixed Copy limits, without parsing.
    ///
    /// # Errors
    /// Refuses scalar conversion, zero, depth or defining reader-limit failures.
    pub fn reader_limits_data(&self) -> Result<RestoredSettledNative17Limits, ProviderError> {
        let mut roles = [0usize; 5];
        for (slot, value) in roles.iter_mut().zip(self.role_maximums) {
            *slot = extent(value)?;
        }
        RestoredSettledNative17Limits::new(
            roles,
            extent(self.immutable_bytes)?,
            extent(self.immutable_objects)?,
            extent(self.immutable_depth)?,
            extent(self.maximum_nodes)?,
            extent(self.maximum_requested_bytes)?,
        )
    }
}

impl PacketNativeImport17Binding {
    /// Checks the closed payload without authenticating its provenance or granting work.
    ///
    /// # Errors
    /// Refuses another grammar, malformed fullrefs/digests, changed role lengths,
    /// exhausted bounds or normalization beyond its independent original maximum.
    pub fn validate_data(&self) -> Result<(), ProviderError> {
        if self.schema != NATIVE_IMPORT17_EXTENSION {
            return Err(invalid());
        }
        digest32(&self.prepare_digest)?;
        digest32(&self.geometry_identity)?;
        self.limits.validate_data()?;
        for reference in [
            &self.native_before,
            &self.controller17,
            &self.source17,
            &self.node25,
            &self.normalization,
        ] {
            reference.validate()?;
            if reference.media_type != "application/json" || reference.length.get() == 0 {
                return Err(invalid());
            }
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
        crate::connection::serialized_credit(self, MAXIMUM_NATIVE_IMPORT17_BINDING_BYTES)?;
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
        let bytes = bounded(self, MAXIMUM_NATIVE_IMPORT17_BINDING_BYTES)?;
        let mut hash =
            blake3::Hasher::new_derive_key("source-owned.packet-native-import-binding/17");
        hash.update(&bytes);
        Ok(*hash.finalize().as_bytes())
    }

    /// Joins every native role and the full original Prepare without partial-field selection.
    ///
    /// The exact Controller, Source, Node25 and parent/body conjunction is still
    /// the actual Source producer's duty before signing this binding. This check
    /// cannot manufacture those owners from portable fullrefs or a valid MAC.
    ///
    /// # Errors
    /// Refuses another full backend definition, any altered Prepare field,
    /// Controller/normalization difference or changed five-role body extent.
    pub fn authenticate_prepare_data(
        &self,
        request: &PacketCompleteRestorePrepareRequest,
    ) -> Result<(), ProviderError> {
        self.validate_data()?;
        request.validate_data()?;
        crate::reference_packet::service::native_snapshot::authenticate_native_restored_settled17_snapshot_schema_data(
            &request.restoration.backend_schema,
        )?;
        if self.controller17 != request.host_protocol
            || self.normalization != request.restoration.mapping
        {
            return Err(invalid());
        }
        let original = bounded(
            request,
            super::super::transfer::MAXIMUM_COMPLETE_RESTORE_TRANSFER_REQUEST_BYTES,
        )?;
        same_digest(
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
    pub fn authenticate_geometry_data(
        &self,
        geometry: &RestoredSettledNativeImportGeometryData,
    ) -> Result<(), ProviderError> {
        self.validate_data()?;
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
        same_digest(self.geometry_identity.as_slice(), &geometry.identity_data())?;
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

fn quantity(value: usize) -> Result<U64, ProviderError> {
    u64::try_from(value).map(U64::new).map_err(|_| invalid())
}

fn extent(value: U64) -> Result<usize, ProviderError> {
    usize::try_from(value.get()).map_err(|_| invalid())
}
