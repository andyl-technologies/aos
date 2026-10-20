//! Borrows the complete known host registry family and original issuer gate.
//!
//! The explicit source-private archive tuple is:
//! ```text
//! (host-registry/12, full-negotiation, actual-authority-data,
//!  erased-empty-registry, concrete-empty-registry, selected-Arc,
//!  retained-creator, source-loan-creator)
//! ```
//! Shared rows record the actual Rc/Arc alias relationships. Creator data remains
//! historical; fresh trusted enrollment creates a new creator and registrar.

use super::*;
use crate::protocol_snapshot::OriginalProtocolCreatorView;
use crate::retained_metadata::aliases::MetadataSharedKind;
use crate::retained_metadata::{MetadataObserver, RetainedProtocolMetadataFacts};

/// Identifies the complete SDK-owned host registry archive class.
///
/// Backend identity must explicitly require this class beside the complete host
/// controller/connection classes. A metadata-only owner is not this archive.
pub const ORIGINAL_HOST_EXTENSION_REGISTRY_FORMAT: &str =
    "source-private.original-host-extension-registry/12";

/// Holds the same live issuer lock, callback family and selected Arc by borrowing.
///
/// The source must retain the real process/owner and validate its currentness
/// before taking this loan. Count and encoding must not call registration or
/// containment while this original gate is held. The loan serializes private
/// negotiation secrets and belongs only in source-owned signed archive custody.
/// It is never a fresh authority, callback reconstruction or Capture permit.
pub struct OriginalExtensionRegistryView<'a> {
    original: &'a ExtensionHandshake,
    authority: &'a ConnectionAuthority,
    owner: &'a OriginalExtensionRegistryOwner,
    negotiation: super::super::OriginalNegotiationView<'a>,
    retained_creator: OriginalProtocolCreatorView<'a>,
    source_creator: OriginalProtocolCreatorView<'a>,
}

impl ExtensionHandshake {
    /// Borrows the complete known host registry and same original Hello issuer.
    ///
    /// Generic erased callbacks remain unsupported even when their rosters are
    /// empty. Both callback Rc views, both creator Rc views and the selected Arc
    /// must be the actual same owners previously installed by the SDK family.
    ///
    /// # Errors
    /// Refuses another creator/registry/selection backing, unresolved negotiation,
    /// a stale registrar or a poisoned original gate. No owner is consumed.
    pub fn original_complete_registry_view<'a>(
        &'a self,
        authority: &'a ConnectionAuthority,
        owner: &'a OriginalExtensionRegistryOwner,
    ) -> Result<OriginalExtensionRegistryView<'a>, ProviderError> {
        owner.authenticate_original(self)?;
        self.verify_authority(authority)?;
        let retained = self
            .original_registry
            .as_ref()
            .ok_or_else(registry_refused)?;
        let selected = self.selected.as_ref().ok_or_else(registry_refused)?;
        if !selected.is_empty()
            || authority
                .extensions
                .as_ref()
                .is_none_or(|actual| !Arc::ptr_eq(actual, selected))
        {
            return Err(registry_refused());
        }
        let retained_creator = retained.origin.original_creator_view()?;
        let source_creator = owner.origin.original_creator_view()?;
        let negotiation = self.handshake.original_negotiation_view(authority)?;
        Ok(OriginalExtensionRegistryView {
            original: self,
            authority,
            owner,
            negotiation,
            retained_creator,
            source_creator,
        })
    }
}

impl OriginalExtensionRegistryView<'_> {
    fn authenticate(&self) -> Result<(), ProviderError> {
        self.owner.authenticate_original(self.original)?;
        self.original.verify_authority(self.authority)?;
        let selected = self
            .original
            .selected
            .as_ref()
            .ok_or_else(registry_refused)?;
        if !selected.is_empty()
            || self
                .authority
                .extensions
                .as_ref()
                .is_none_or(|actual| !Arc::ptr_eq(actual, selected))
        {
            return Err(registry_refused());
        }
        Ok(())
    }

    /// Reports actual complete issuer/callback/creator/selection retained storage.
    ///
    /// Each actual shared view is reported conservatively; equal labels do not
    /// earn an alias refund. The outer view/lock and encoder stack remain distinct
    /// compiled layout terms for the source's whole simultaneous admission.
    ///
    /// # Errors
    /// Refuses changed original owners/current registrar or checked walk overflow.
    pub fn original_retained_metadata_facts(
        &self,
    ) -> Result<RetainedProtocolMetadataFacts, ProviderError> {
        let mut observer = MetadataObserver::new();
        self.observe_original_metadata(&mut observer)?;
        Ok(observer.finish())
    }

    /// Encodes complete historical registry data in caller-precharged banks.
    ///
    /// The source admits the simultaneous encoded bank, record/alias banks and
    /// live borrowed owners before calling. The actual original gate stays held
    /// through metadata walking, counting and encoding. This method reserves or
    /// grows no bank and grants no capture, source or restoration authority.
    ///
    /// # Errors
    /// Refuses used banks, changed owners, insufficient actual capacity or
    /// metadata/encoding overflow. Partial rows or bytes remain caller-owned.
    pub fn encode_complete_data_into(
        &self,
        records: &mut crate::retained_metadata::records::MetadataRecordBank,
        aliases: &mut crate::retained_metadata::aliases::MetadataAliasBank,
        encoded: &mut Vec<u8>,
    ) -> Result<(), ProviderError> {
        self.authenticate()?;
        if !records.rows().is_empty() || aliases.retained_rows() != 0 || !encoded.is_empty() {
            return Err(registry_refused());
        }
        {
            let mut observer = MetadataObserver::recording_with_aliases(records, aliases);
            self.observe_original_metadata(&mut observer)?;
        }
        aliases.finish_lookup();
        let maximum = encoded.capacity();
        crate::protocol_snapshot::ProtocolSnapshotReservation::encode_buffer(
            encoded,
            maximum,
            &("source-private.cnp-protocol/11", self, records, aliases),
        )
    }

    pub(crate) fn observe_original_metadata(
        &self,
        observer: &mut MetadataObserver,
    ) -> Result<(), ProviderError> {
        self.authenticate()?;
        let ExtensionHandshake {
            handshake: _,
            installed,
            selected,
            original_registry,
        } = self.original;
        let retained = original_registry.as_ref().ok_or_else(registry_refused)?;
        self.negotiation.observe_owned11_metadata(observer)?;
        self.authority.observe_retained_metadata(observer)?;
        observer.shared_original(MetadataSharedKind::InstalledRegistry, installed.as_ref())?;
        observer.shared_original(
            MetadataSharedKind::InstalledRegistry,
            retained.registry.as_ref(),
        )?;
        observer.shared_original(MetadataSharedKind::ProtocolOwner, retained.origin.as_ref())?;
        observer.shared_original(
            MetadataSharedKind::ProtocolOwner,
            self.owner.origin.as_ref(),
        )?;
        // The source-held opaque owner itself has a concrete strong registry Rc.
        observer.shared_original(
            MetadataSharedKind::InstalledRegistry,
            self.owner.registry.as_ref(),
        )?;
        let selected = selected.as_ref().ok_or_else(registry_refused)?;
        observer.shared_original(MetadataSharedKind::SelectedExtensions, selected.as_ref())?;
        for item in selected.iter() {
            observer.observe(item)?;
        }
        Ok(())
    }
}

impl serde::Serialize for OriginalExtensionRegistryView<'_> {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        self.authenticate().map_err(serde::ser::Error::custom)?;
        serde::Serialize::serialize(
            &(
                ORIGINAL_HOST_EXTENSION_REGISTRY_FORMAT,
                &self.negotiation,
                self.authority.historical_owned_view(),
                "source-private.sdk-empty-extension-registry/12",
                "source-private.sdk-empty-extension-registry/12",
                &self.original.selected,
                &self.retained_creator,
                &self.source_creator,
            ),
            serializer,
        )
    }
}
