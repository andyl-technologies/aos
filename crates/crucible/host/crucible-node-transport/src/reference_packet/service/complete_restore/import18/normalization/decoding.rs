//! Retains one strictly decoded normalization and its original construction row.
//!
//! The original bootstrap lends the completed raw bank. Its enclosing native
//! phase admits the quote before decoding and observes actual backing afterward,
//! including failed correspondence. This owner creates no Prepare or model.

use super::*;
use crate::reference_packet::continuation_models::serde_partials::decoder_struct;
use crate::retained_metadata::{
    BootstrapBodyMetadataProfileData, MetadataObserver,
    bootstrap_body_metadata_counter_scratch_data, requested_metadata_backing_storage_data,
};
use crucible_node_format::{ContractError, canonical};
use std::mem::size_of;

decoder_struct!(PacketNativeImport17Limits {
    role_maximums,
    immutable_objects,
    immutable_bytes,
    immutable_depth,
    maximum_nodes,
    maximum_requested_bytes,
    maximum_target_requested_bytes,
    maximum_before_bytes,
});

decoder_struct!(PacketNativeImport18Normalization {
    schema,
    archive_index,
    capture_manifest,
    source_runtime,
    native_family,
    native_snapshot,
    native_after,
    native_control,
    native_anchor,
    native_journal,
    native_before,
    controller17,
    source_family,
    source17,
    node25,
    backend_implementation,
    backend_profile,
    backend_schema,
    archived_cut,
    archived_ordinal,
    host_registration,
    target_world,
    target_owner,
    target_owner_binding,
    target_activation,
    target_generation,
    target_owner_generation,
    transaction_id,
    commit_request_id,
    lease_generation,
    nonce,
    limits,
    semantic_spend_family,
    semantic_spend,
    semantic_spend_maximum,
});

/// Owns spent state, actual parsed DATA and failures independently of bootstrap.
pub(in crate::reference_packet) struct OriginalImport18NormalizationAttempt {
    stage: DecodeStage,
    row: Option<[usize; 3]>,
    profile: Option<BootstrapBodyMetadataProfileData>,
    pub(in crate::reference_packet) decoded: Option<PacketNativeImport18Normalization>,
    failure: Option<String>,
    raw_fingerprint: Option<[u8; 32]>,
}

#[derive(Clone, Copy, Eq, PartialEq)]
enum DecodeStage {
    Empty,
    Quoting,
    Quoted,
    Decoding,
    Decoded,
    Complete,
    Failed,
}

impl OriginalImport18NormalizationAttempt {
    /// Creates only empty physical slots; the caller charges this inline root.
    pub(in crate::reference_packet) fn empty() -> Self {
        Self {
            stage: DecodeStage::Empty,
            row: None,
            profile: None,
            decoded: None,
            failure: None,
            raw_fingerprint: None,
        }
    }

    /// Saves the actual strict decoder row before its independent admission.
    ///
    /// # Errors
    /// Refuses repeated use, malformed populations, overflow or short restriction.
    pub(in crate::reference_packet) fn quote_data(
        &mut self,
        raw: &[u8],
        maximum: usize,
    ) -> Result<[usize; 3], ProviderError> {
        if self.stage != DecodeStage::Empty {
            return Err(refused());
        }
        self.stage = DecodeStage::Quoting;
        if raw.is_empty() || raw.len() > 65_536 {
            return Err(refused());
        }
        self.raw_fingerprint = Some(*blake3::hash(raw).as_bytes());

        let mut row = super::super::startup_wire::normalization_decode_backing_data(raw, maximum)?;
        let syntax = crate::reference_packet::service::native_startup::raw_json_extent_data(raw)?;
        let reset = crate::protocol_snapshot::raw_value_reparse::quote_raw_json_data(raw, maximum)?;
        let profile = BootstrapBodyMetadataProfileData::from_populations_data(
            syntax.maximum_value_nodes,
            syntax.maximum_object_members,
            &reset,
        )?;
        self.profile = Some(profile);
        row[1] = row[1]
            .checked_add(size_of::<PacketNativeImport18Normalization>())
            .and_then(|n| {
                n.checked_add(size_of::<
                    Result<PacketNativeImport18Normalization, ProviderError>,
                >())
            })
            .and_then(|n| n.checked_add(size_of::<Option<PacketNativeImport18Normalization>>()))
            .ok_or_else(refused)?;
        row[2] = row[2]
            .checked_add(profile.walk_scratch_data()?)
            .and_then(|n| n.checked_add(Self::counter_scratch_data()))
            .ok_or_else(refused)?;
        self.row = Some(row);
        let peak = row
            .into_iter()
            .try_fold(0usize, usize::checked_add)
            .ok_or_else(refused)?;
        if peak > maximum {
            return Err(refused());
        }
        self.stage = DecodeStage::Quoted;
        Ok(row)
    }

    /// Installs actual typed DATA before any fallible correspondence check.
    ///
    /// # Errors
    /// Refuses absent quote, reused slots or strict JSON/typed decoding errors.
    pub(in crate::reference_packet) fn decode_data(
        &mut self,
        raw: &[u8],
    ) -> Result<(), ProviderError> {
        if self.stage != DecodeStage::Quoted {
            return Err(refused());
        }
        self.stage = DecodeStage::Decoding;
        if self.row.is_none()
            || self.profile.is_none()
            || self.decoded.is_some()
            || self.raw_fingerprint != Some(*blake3::hash(raw).as_bytes())
        {
            return Err(refused());
        }
        let result = canonical::parse_json(raw, raw.len())
            .map_err(ProviderError::from)
            .and_then(|value| {
                serde_json::from_value(value)
                    .map_err(ContractError::from)
                    .map_err(ProviderError::from)
            });
        match result {
            Ok(value) => {
                self.decoded = Some(value);
                self.stage = DecodeStage::Decoded;
                Ok(())
            }
            Err(error) => {
                self.stage = DecodeStage::Failed;
                Err(error)
            }
        }
    }

    /// Counts actual surviving typed backing after either outcome.
    ///
    /// A refused decoder or correspondence retains its actual formatted
    /// diagnostic String; its capacity is counted independently of the quote.
    ///
    /// # Errors
    /// Refuses missing profiles or metadata capacity/population overflow.
    pub(in crate::reference_packet) fn retained_backing_data(
        &self,
    ) -> Result<usize, ProviderError> {
        let mut observer = MetadataObserver::new();
        if let Some(decoded) = &self.decoded {
            observer.with_bootstrap_body_profile_data(
                self.profile.ok_or_else(refused)?,
                |observer| decoded.observe_backing_data(observer),
            )?;
        }
        observer.observe(&self.failure)?;
        requested_metadata_backing_storage_data(&observer.finish())
    }

    /// Retains a refused operation's actual diagnostic before terminal census.
    pub(in crate::reference_packet) fn retain_failure_data(&mut self, error: ProviderError) {
        self.stage = DecodeStage::Failed;
        self.failure = Some(error.to_string());
    }

    /// Reports whether this physical attempt has spent its original occurrence.
    pub(in crate::reference_packet) fn started_data(&self) -> bool {
        self.stage != DecodeStage::Empty
    }

    /// Reports completion of decoding, correspondence and terminal guards only.
    pub(in crate::reference_packet) fn completed_data(&self) -> bool {
        self.stage == DecodeStage::Complete
    }

    /// Closes a successful occurrence after its original terminal guard.
    ///
    /// # Errors
    /// Refuses an attempt without a complete actual typed decode.
    pub(in crate::reference_packet) fn complete_data(&mut self) -> Result<(), ProviderError> {
        if self.stage != DecodeStage::Decoded {
            return Err(refused());
        }
        self.stage = DecodeStage::Complete;
        Ok(())
    }

    /// Retains partials while fencing every failed terminal occurrence.
    pub(in crate::reference_packet) fn refuse_data(&mut self) {
        self.stage = DecodeStage::Failed;
    }

    /// Names actual quote, retained metadata and correspondence controls.
    pub(in crate::reference_packet) fn counter_scratch_data() -> usize {
        bootstrap_body_metadata_counter_scratch_data()
            + super::super::prebirth_recipe::normalization_counter_scratch_data()
            + size_of::<&Self>()
            + size_of::<&mut Self>()
            + size_of::<[usize; 3]>()
            + size_of::<Option<[usize; 3]>>()
            + size_of::<BootstrapBodyMetadataProfileData>()
            + size_of::<MetadataObserver<'static>>()
            + size_of::<&PacketNativeImport18Normalization>()
            + size_of::<blake3::Hasher>()
            + size_of::<blake3::Hash>()
            + size_of::<[u8; 32]>()
            + size_of::<Value>()
            + size_of::<DecodeStage>()
            + size_of::<std::array::IntoIter<usize, 3>>()
            + size_of::<Option<usize>>()
            + size_of::<std::fmt::Formatter<'static>>()
            + size_of::<std::fmt::Arguments<'static>>()
            + size_of::<String>()
            + size_of::<Option<String>>()
            + size_of::<ProviderError>()
            + size_of::<Result<Value, ContractError>>()
            + size_of::<Result<PacketNativeImport18Normalization, serde_json::Error>>()
            + size_of::<Result<PacketNativeImport18Normalization, ProviderError>>()
            + size_of::<Result<(), ProviderError>>() * 3
            + size_of::<Result<usize, ProviderError>>()
    }
}

impl PacketNativeImport18Normalization {
    fn observe_backing_data(
        &self,
        observer: &mut MetadataObserver<'_>,
    ) -> Result<(), ProviderError> {
        let Self {
            schema,
            archive_index,
            capture_manifest,
            source_runtime,
            native_family: _,
            native_snapshot,
            native_after,
            native_control,
            native_anchor,
            native_journal,
            native_before,
            controller17,
            source_family: _,
            source17,
            node25,
            backend_implementation,
            backend_profile,
            backend_schema,
            archived_cut: _,
            archived_ordinal: _,
            host_registration,
            target_world,
            target_owner,
            target_owner_binding,
            target_activation,
            target_generation: _,
            target_owner_generation: _,
            transaction_id,
            commit_request_id,
            lease_generation: _,
            nonce,
            limits: _,
            semantic_spend_family: _,
            semantic_spend,
            semantic_spend_maximum: _,
        } = self;

        observer.observe(schema)?;
        for reference in [
            archive_index,
            capture_manifest,
            source_runtime,
            native_snapshot,
            native_after,
            native_control,
            native_anchor,
            native_journal,
            native_before,
            controller17,
            source17,
            node25,
            backend_implementation,
            semantic_spend,
        ] {
            observer.observe(reference)?;
        }
        observer.observe(backend_profile)?;
        observer.observe(backend_schema)?;
        observer.observe(host_registration)?;
        observer.observe(target_world)?;
        observer.observe(target_owner)?;
        observer.observe(target_owner_binding)?;
        observer.observe(target_activation)?;
        observer.observe(transaction_id)?;
        observer.observe(commit_request_id)?;
        observer.observe(nonce)
    }
}

fn refused() -> ProviderError {
    ProviderError::Correlation("original import18 normalization decode DATA")
}
