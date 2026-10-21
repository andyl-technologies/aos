//! Retains actual decoded bootstrap DATA beside its original raw bank owner.
//!
//! Successful prefixes stay installed before the next fallible decoder. These
//! slots contain no validated model, opaque recipe, Initial or native grant.

use super::*;
use crate::retained_metadata::{
    BootstrapBodyMetadataProfileData, MetadataObserver,
    bootstrap_body_metadata_counter_scratch_data, requested_metadata_backing_storage_data,
};

/// Owns the three actual DTO slots and their original lexical census profiles.
pub(in crate::reference_packet) struct OriginalImport18DecodedBodies {
    recipe: Option<PacketNativeImport18PrebirthRecipeWireData>,
    launch: Option<PacketNativeImport18SelectedLaunchWireData>,
    boot: Option<PacketNativeImport18PrivateBootWireData>,
    profiles: [Option<BootstrapBodyMetadataProfileData>; 3],
}

/// Borrows all three original decoded DATA bodies without duplicating storage.
pub(in crate::reference_packet) struct OriginalImport18DecodedBodyLoans<'a> {
    /// Borrows the inert fixed recipe announcement.
    pub(in crate::reference_packet) recipe: &'a PacketNativeImport18PrebirthRecipeWireData,
    /// Borrows the actual selected9 launch.
    pub(in crate::reference_packet) launch: &'a PacketNativeImport18SelectedLaunchWireData,
    /// Borrows the actual private boot18 DATA.
    pub(in crate::reference_packet) boot: &'a PacketNativeImport18PrivateBootWireData,
}

impl OriginalImport18DecodedBodies {
    /// Constructs empty typed slots without parsing or allocating backing.
    pub(in crate::reference_packet) fn empty() -> Self {
        Self {
            recipe: None,
            launch: None,
            boot: None,
            profiles: [None; 3],
        }
    }

    /// Quotes the real decoders and retains their allocation-free census profiles.
    ///
    /// # Errors
    /// Refuses unsupported raw populations, checked overflow or the independent restriction.
    pub(in crate::reference_packet) fn construction_data(
        &mut self,
        raw: [&[u8]; 3],
        maximum: usize,
    ) -> Result<[[usize; 3]; 3], ProviderError> {
        let mut rows = private_body_decode_backing_data(raw, maximum)?;
        for index in 0..3 {
            let syntax =
                crate::reference_packet::service::native_startup::raw_json_extent_data(raw[index])?;
            let reset = crate::protocol_snapshot::raw_value_reparse::quote_raw_json_data(
                raw[index], maximum,
            )?;
            let profile = BootstrapBodyMetadataProfileData::from_populations_data(
                syntax.maximum_value_nodes,
                syntax.maximum_object_members,
                &reset,
            )?;
            self.profiles[index] = Some(profile);
            rows[index][2] = rows[index][2]
                .checked_add(profile.walk_scratch_data()?)
                .and_then(|n| n.checked_add(private_body_owner_counter_scratch_data()))
                .ok_or_else(exhausted)?;
        }
        Ok(rows)
    }

    /// Installs a successful fixed recipe announcement without producing a Recipe.
    ///
    /// # Errors
    /// Refuses occupied slots or invalid strict JSON/typed DATA.
    pub(in crate::reference_packet) fn decode_recipe(
        &mut self,
        raw: &[u8],
    ) -> Result<(), ProviderError> {
        if self.recipe.is_some() || self.profiles[0].is_none() {
            return Err(invalid());
        }
        self.recipe = Some(decode(raw)?);
        Ok(())
    }

    /// Installs the actual selected9 launch before any later boot decoder.
    ///
    /// # Errors
    /// Refuses occupied slots or invalid strict JSON/typed DATA.
    pub(in crate::reference_packet) fn decode_launch(
        &mut self,
        raw: &[u8],
    ) -> Result<(), ProviderError> {
        if self.launch.is_some() || self.recipe.is_none() || self.profiles[1].is_none() {
            return Err(invalid());
        }
        self.launch = Some(decode(raw)?);
        Ok(())
    }

    /// Installs the actual private boot18 DATA without creating a native Boot.
    ///
    /// # Errors
    /// Refuses occupied slots or invalid strict JSON/typed DATA.
    pub(in crate::reference_packet) fn decode_boot(
        &mut self,
        raw: &[u8],
    ) -> Result<(), ProviderError> {
        if self.boot.is_some() || self.launch.is_none() || self.profiles[2].is_none() {
            return Err(invalid());
        }
        self.boot = Some(decode(raw)?);
        Ok(())
    }

    /// Lends all three completed inert DATA bodies without copying them.
    ///
    /// # Errors
    /// Refuses an incomplete typed prefix.
    pub(in crate::reference_packet) fn bodies_data(
        &self,
    ) -> Result<OriginalImport18DecodedBodyLoans<'_>, ProviderError> {
        Ok(OriginalImport18DecodedBodyLoans {
            recipe: self.recipe.as_ref().ok_or_else(invalid)?,
            launch: self.launch.as_ref().ok_or_else(invalid)?,
            boot: self.boot.as_ref().ok_or_else(invalid)?,
        })
    }

    #[cfg(test)]
    pub(in crate::reference_packet) fn partial_presence_data(&self) -> [bool; 3] {
        [
            self.recipe.is_some(),
            self.launch.is_some(),
            self.boot.is_some(),
        ]
    }

    /// Counts real typed backing, including every successful prefix after refusal.
    ///
    /// Inline slots belong to the physical owner and are excluded here.
    ///
    /// # Errors
    /// Refuses absent original profiles or checked capacity/population overflow.
    pub(in crate::reference_packet) fn retained_backing_data(
        &self,
    ) -> Result<usize, ProviderError> {
        // The fixed recipe is Copy and cannot retain backing.
        const {
            assert!(!std::mem::needs_drop::<
                PacketNativeImport18PrebirthRecipeWireData,
            >());
        }
        let mut observer = MetadataObserver::new();
        if let Some(launch) = &self.launch {
            let profile = self.profiles[1].ok_or_else(invalid)?;
            observer.with_bootstrap_body_profile_data(profile, |observer| {
                launch.observe_backing_data(observer)
            })?;
        }
        if let Some(boot) = &self.boot {
            let profile = self.profiles[2].ok_or_else(invalid)?;
            observer.with_bootstrap_body_profile_data(profile, |observer| {
                boot.observe_backing_data(observer)
            })?;
        }
        requested_metadata_backing_storage_data(&observer.finish())
    }
}

fn decode<T: serde::de::DeserializeOwned>(raw: &[u8]) -> Result<T, ProviderError> {
    let strict = canonical::parse_json(raw, raw.len())?;
    serde_json::from_value(strict)
        .map_err(ContractError::from)
        .map_err(ProviderError::from)
}

impl PacketNativeImport18SelectedLaunchWireData {
    fn observe_backing_data(
        &self,
        observer: &mut MetadataObserver<'_>,
    ) -> Result<(), ProviderError> {
        let Self {
            schema_version,
            mechanism,
            launch,
            prebirth_recipe_identity,
            initial_funding,
        } = self;
        const {
            assert!(!std::mem::needs_drop::<(
                u16,
                PacketNativeImport18Selection,
                [u8; 32],
                PacketNativeStartupAllocationRow
            )>());
        }
        let _ = (
            schema_version,
            mechanism,
            prebirth_recipe_identity,
            initial_funding,
        );
        observer.observe_bootstrap_launch_data(launch)
    }
}

impl PacketNativeImport18SourceBindingWireData {
    fn observe_backing_data(
        &self,
        observer: &mut MetadataObserver<'_>,
    ) -> Result<(), ProviderError> {
        let Self {
            schema,
            declaration,
            mechanism,
            prebirth_recipe,
            initial_funding,
        } = self;
        const {
            assert!(!std::mem::needs_drop::<(
                SourceSchema,
                PacketNativeImport18Selection,
                PacketNativeImport18PrebirthRecipeWireData,
                PacketNativeStartupAllocationRow
            )>());
        }
        let _ = (schema, mechanism, prebirth_recipe, initial_funding);
        declaration.observe_backing_data(observer)
    }
}

impl PacketNativeImport18PrivateBootWireData {
    fn observe_backing_data(
        &self,
        observer: &mut MetadataObserver<'_>,
    ) -> Result<(), ProviderError> {
        let Self {
            schema,
            private_key,
            birth_id,
            source_birth,
            expected_host_registration,
            private_launch,
            host_executable,
        } = self;
        const {
            assert!(!std::mem::needs_drop::<BootSchema>());
        }
        let _ = schema;
        observer.observe(private_key)?;
        observer.observe(birth_id)?;
        source_birth.observe_backing_data(observer)?;
        observer.observe(expected_host_registration)?;
        observer.observe(private_launch)?;
        observer.observe(host_executable)
    }
}

/// Names actual output slots, quote views and fallible decode/census controls.
pub(in crate::reference_packet) fn private_body_owner_counter_scratch_data() -> usize {
    bootstrap_body_metadata_counter_scratch_data()
        + size_of::<&mut OriginalImport18DecodedBodies>()
        + size_of::<&OriginalImport18DecodedBodies>()
        + size_of::<[&[u8]; 3]>()
        + size_of::<[[usize; 3]; 3]>()
        + size_of::<Result<[[usize; 3]; 3], ProviderError>>()
        + size_of::<std::ops::Range<usize>>()
        + size_of::<usize>() * 3
        + size_of::<OriginalImport18DecodedBodyLoans<'static>>()
        + size_of::<Result<OriginalImport18DecodedBodyLoans<'static>, ProviderError>>()
        + size_of::<Value>()
        + size_of::<Result<Value, ContractError>>()
        + size_of::<Result<(), ProviderError>>() * 3
        + size_of::<Result<usize, ProviderError>>()
}

fn exhausted() -> ProviderError {
    ProviderError::ResourceExhausted("original import18 typed body storage")
}
