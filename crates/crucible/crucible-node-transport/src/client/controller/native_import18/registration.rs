//! Lends the actual complete host registration to the Source normalization writer.
//!
//! The view serializes the real ConnectionAuthority historical tuple. It cannot
//! extract an authority, replace an epoch, or reconstruct an executable lease.

use super::*;
use crate::retained_metadata::serialization_storage::{
    actual_serialization_storage_data, original_serialization_counter_scratch_data,
    original_serialization_formatter_temporary_storage_data,
};
use serde::ser::Error;
use std::mem::{size_of, size_of_val};

/// Borrows complete historical host registration DATA through its real Controller.
///
/// Its immutable Controller loan prevents Session mutation during serialization.
/// The original actor, emitter and literal frontier are checked on every pass.
pub struct OriginalNativeImport18HostRegistrationView<'a> {
    controller: &'a CnpController,
    emitter: &'a OriginalCanonicalBlobAckEmitter,
    frontier: OriginalProtocolStorageFacts,
}

impl Serialize for OriginalNativeImport18HostRegistrationView<'_> {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        self.authenticate().map_err(S::Error::custom)?;
        let result = self
            .controller
            .authority()
            .historical_owned_view()
            .serialize(serializer);
        self.authenticate().map_err(S::Error::custom)?;
        result
    }
}

impl OriginalNativeImport18HostRegistrationView<'_> {
    fn authenticate(&self) -> Result<(), ProviderError> {
        self.emitter.authenticate_original(self.controller)?;
        self.controller.protocol_owner.ensure_current()?;
        self.controller.authority().ensure_live()?;
        if self.frontier != self.controller.original_native5_storage_facts()? {
            return Err(invalid());
        }
        Ok(())
    }
}

impl CnpController {
    /// Names exact real registration-view and metadata/serialization headers.
    pub fn original_native_import18_host_registration_counter_scratch_data(&self) -> usize {
        size_of::<OriginalNativeImport18HostRegistrationView<'static>>()
            + size_of_val(&self.authority().historical_owned_view())
            + size_of::<MetadataObserver<'static>>()
            + size_of::<RetainedProtocolMetadataFacts>()
            + size_of::<(usize, usize, usize, usize)>()
            + size_of::<Result<(usize, usize, usize, usize), ProviderError>>()
            + size_of::<Result<OriginalNativeImport18HostRegistrationView<'static>, ProviderError>>(
            )
            + Self::original_native_import18_assignment_counter_scratch_data()
            + original_serialization_counter_scratch_data()
    }

    /// Quotes the actual registration's formatter and full-schema factory prewalk.
    ///
    /// This only observes actual retained fields; no parser, serializer, I/O or
    /// native/current grant runs. The returned window precedes the full quote.
    ///
    /// # Errors
    /// Refuses a foreign actor/emitter, metadata or checked geometry overflow.
    pub fn original_native_import18_host_registration_prewalk_data(
        &self,
        emitter: &OriginalCanonicalBlobAckEmitter,
    ) -> Result<(usize, usize), ProviderError> {
        emitter.authenticate_original(self)?;
        let mut observer = MetadataObserver::new();
        self.authority().observe_retained_metadata(&mut observer)?;
        let formatters =
            original_serialization_formatter_temporary_storage_data(&observer.finish())?;
        let (contract, _) = native_import18_contract_storage_data(usize::MAX)?;
        let transient = formatters
            .checked_add(contract)
            .and_then(|n| n.checked_add("blake3-256".len() + "cnp.blob.v1".len() + 64))
            .ok_or_else(credit)?;
        Ok((
            transient,
            self.original_native_import18_host_registration_counter_scratch_data(),
        ))
    }

    /// Borrows the genuine full host registration after its admitted prewalk.
    ///
    /// This view grants no native permission. Source must bind its own cold,
    /// fresh World/owner/Window/key and independently admitted normalization row.
    ///
    /// # Errors
    /// Refuses a foreign/stale query, absent full18 codec/roster selection or actor.
    pub fn original_native_import18_host_registration_data<'a>(
        &'a self,
        emitter: &'a OriginalCanonicalBlobAckEmitter,
        query: &OriginalFreshRestoreQuery,
    ) -> Result<OriginalNativeImport18HostRegistrationView<'a>, ProviderError> {
        query.authenticate_current(self, emitter)?;
        self.session.native_import18_selection_data()?;
        let view = OriginalNativeImport18HostRegistrationView {
            controller: self,
            emitter,
            frontier: self.original_native5_storage_facts()?,
        };
        view.authenticate()?;
        Ok(view)
    }

    /// Quotes independent registration DOM/canonical backing and temporary work.
    ///
    /// Returns retained, transient, fixed-counter and encoded-extent axes. The
    /// Source independently admits those axes before constructing normalization.
    /// The prewalk returned by the defining helper must already be admitted.
    ///
    /// # Errors
    /// Refuses the actual query/selection/currentness guards or storage overflow.
    pub fn original_native_import18_host_registration_construction_data(
        &self,
        emitter: &OriginalCanonicalBlobAckEmitter,
        query: &OriginalFreshRestoreQuery,
        maximum: usize,
    ) -> Result<(usize, usize, usize, usize), ProviderError> {
        let view = self.original_native_import18_host_registration_data(emitter, query)?;
        let mut observer = MetadataObserver::new();
        self.authority().observe_retained_metadata(&mut observer)?;
        let data = actual_serialization_storage_data(&view, observer.finish(), maximum)?;
        let retained = data
            .retained_value_backing_bytes
            .checked_add(data.canonical_output_requested_bytes)
            .and_then(|n| n.checked_add(size_of::<Value>() + size_of::<Vec<u8>>()))
            .ok_or_else(credit)?;
        let transient = data.requested_total()?;
        let scratch = self.original_native_import18_host_registration_counter_scratch_data();
        if retained
            .checked_add(transient)
            .and_then(|n| n.checked_add(scratch))
            .is_none_or(|n| n > maximum)
        {
            return Err(credit());
        }
        view.authenticate()?;
        Ok((retained, transient, scratch, data.maximum_encoded_bytes))
    }
}
