//! Observes newly decoded archived installation DATA without live-owner guards.
//!
//! These borrowed fields are actual retained typed values. Their existence and
//! capacity facts do not authenticate a Source, archive, process or admission.
//! The owning cold reader separately proves native and signed-archive joins.

use super::{MetadataObserver, RetainedProtocolMetadataFacts};
use crate::{ProviderError, bodies::RealizeRequest};
use crucible_node_format::*;
use std::mem::size_of;

/// Borrows the exact fifteen heap-bearing public installation fields.
///
/// Four generic numeric limits occupy the owning DTO's inline root. The actual
/// independently owned native launch has its existing separate typed observer.
pub struct RetainedArchivedSourceInstallation17<'a> {
    /// Borrows the retained provider declaration.
    pub provider: &'a ProviderManifest,
    /// Borrows the retained selected node profile.
    pub profile: &'a NodeManifest,
    /// Borrows the retained complete node descriptor.
    pub descriptor: &'a NodeDescriptor,
    /// Borrows the retained archived binding.
    pub binding: &'a NodeBinding,
    /// Borrows the retained capability contract.
    pub capabilities: &'a CapabilityProfile,
    /// Borrows the retained selected exact facet.
    pub exact_facet: &'a FacetSelection,
    /// Borrows the retained guarantee contract.
    pub guarantees: &'a GuaranteeProfile,
    /// Borrows the retained complete owner binding.
    pub owner: &'a OwnerBinding,
    /// Borrows the retained original realization request.
    pub realize: &'a RealizeRequest,
    /// Borrows the retained original admission identifier.
    pub admission: &'a Id,
    /// Borrows the retained original transaction identifier.
    pub transaction: &'a Id,
    /// Borrows the retained original gate identifier.
    pub gate: &'a Id,
    /// Borrows the retained original admission receipt.
    pub admission_receipt: &'a ContentRef,
    /// Borrows the retained archived world identity.
    pub world_binding_hash: &'a HashRef,
    /// Borrows the retained selected receipt schema.
    pub receipt_schema: &'a SchemaRef,
}

impl RetainedArchivedSourceInstallation17<'_> {
    /// Counts actual String/Vec/tree/Box/shared backing without serialization.
    ///
    /// # Errors
    /// Refuses finite typed traversal/depth exhaustion or checked extent overflow.
    pub fn observe_retained_metadata(
        &self,
    ) -> Result<RetainedProtocolMetadataFacts, ProviderError> {
        let Self {
            provider,
            profile,
            descriptor,
            binding,
            capabilities,
            exact_facet,
            guarantees,
            owner,
            realize,
            admission,
            transaction,
            gate,
            admission_receipt,
            world_binding_hash,
            receipt_schema,
        } = self;
        let mut observer = MetadataObserver::new();
        observer.observe(*provider)?;
        observer.observe(*profile)?;
        observer.observe(*descriptor)?;
        observer.observe(*binding)?;
        observer.observe(*capabilities)?;
        observer.observe(*exact_facet)?;
        observer.observe(*guarantees)?;
        observer.observe(*owner)?;
        observer.observe(*realize)?;
        observer.observe(*admission)?;
        observer.observe(*transaction)?;
        observer.observe(*gate)?;
        observer.observe(*admission_receipt)?;
        observer.observe(*world_binding_hash)?;
        observer.observe(*receipt_schema)?;
        Ok(observer.finish())
    }

    /// Names fixed borrowed-view and defining observer/result controls.
    pub fn counter_scratch_data() -> usize {
        size_of::<Self>()
            + size_of::<&Self>()
            + size_of::<MetadataObserver<'static>>()
            + size_of::<RetainedProtocolMetadataFacts>()
            + size_of::<Result<RetainedProtocolMetadataFacts, ProviderError>>()
            + size_of::<Result<(), ProviderError>>()
    }
}
