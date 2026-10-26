//! Owns the separate complete known-host registry archive bank before Child birth.
//!
//! The encoded body includes the actual negotiation/callback/creator view and
//! capacity/alias rosters. It remains an inert source-held component until the
//! settled journal, backend and whole archive validators bind its full reference.

use super::*;
use crate::node_adapters::cnp::semantic::packet_complete_source::storage_error::StorageError;
use crucible_node_transport::retained_metadata::{
    aliases::MetadataAliasBank,
    records::{MetadataCapacityRecord, MetadataRecordBank},
};
use std::{cell::Ref, mem::size_of};

#[path = "registry_capture/metadata.rs"]
mod metadata;

pub(super) const HOST_REGISTRY_MEDIA: &str =
    "application/vnd.source-owned.packet-host-extension-registry.v12+json";

pub(super) struct OriginalCompleteRegistryCapture {
    maximum_encoded_bytes: usize,
    maximum_rows: usize,
    encoded: Vec<u8>,
    records: Option<MetadataRecordBank>,
    aliases: Option<MetadataAliasBank>,
    payload: Option<InputPayload>,
    reserved: bool,
    attempted: bool,
    failed: bool,
}

impl OriginalCompleteRegistryCapture {
    pub(super) fn completed_payload(&self) -> Result<&InputPayload, OperationFailure> {
        if !self.reserved || !self.attempted || self.failed {
            return Err(refused("original registry output is incomplete"));
        }
        self.payload
            .as_ref()
            .ok_or_else(|| refused("original registry output is absent"))
    }

    pub(super) fn take_completed_payload(&mut self) -> Option<InputPayload> {
        self.payload.take()
    }

    pub(super) fn restore_completed_payload(&mut self, payload: Option<InputPayload>) {
        self.payload = payload;
    }

    fn reservation_storage(encoded: usize, rows: usize) -> Result<usize, OperationFailure> {
        if encoded == 0 {
            return Err(refused("complete registry encoded bank is empty"));
        }
        let aliases = MetadataAliasBank::reservation_requested_bytes(rows).map_err(unknown)?;
        let records = rows
            .checked_mul(size_of::<MetadataCapacityRecord>())
            .ok_or_else(|| refused("complete registry record bank overflow"))?;
        retained_values::sum([encoded, records, aliases, size_of::<Self>()], usize::MAX)
    }

    fn reserve_into(
        completed: &mut Option<Self>,
        encoded: usize,
        rows: usize,
        admitted: usize,
    ) -> Result<(), OperationFailure> {
        if completed.is_some() || Self::reservation_storage(encoded, rows)? > admitted {
            return Err(refused(
                "complete registry reservation exceeds original bank admission",
            ));
        }
        *completed = Some(Self {
            maximum_encoded_bytes: encoded,
            maximum_rows: rows,
            encoded: Vec::new(),
            records: None,
            aliases: None,
            payload: None,
            reserved: false,
            attempted: false,
            failed: false,
        });
        let original = completed
            .as_mut()
            .ok_or_else(|| refused("complete registry slot absent"))?;
        let result = (|| {
            original
                .encoded
                .try_reserve_exact(encoded)
                .map_err(unknown)?;
            // The SDK writer uses this actual capacity as its no-growth bound.
            // Refuse a larger allocator return before metadata walking or copy.
            if original.encoded.capacity() != encoded {
                return Err(refused(
                    "complete registry encoded allocation differs from selected bound",
                ));
            }
            original.records = Some(MetadataRecordBank::reserve(rows).map_err(unknown)?);
            original.aliases = Some(MetadataAliasBank::reserve(rows).map_err(unknown)?);
            if original.retained_storage(admitted)? > admitted {
                return Err(refused("actual complete registry banks exceed admission"));
            }
            original.reserved = true;
            Ok(())
        })();
        if result.is_err() {
            original.failed = true;
        }
        result
    }

    fn retained_storage(&self, maximum: usize) -> Result<usize, OperationFailure> {
        self.retained_storage_with_error::<OperationFailure>(maximum)
    }

    pub(in crate::node_adapters::cnp::semantic) fn retained_storage_with_error<E: StorageError>(
        &self,
        maximum: usize,
    ) -> Result<usize, E> {
        let facts = self.capacity_facts_data(None).map_err(E::runtime)?;
        PacketCompleteSemanticSource::complete_retained_metadata_storage_with_error::<E>(
            &facts, maximum,
        )
    }
}

impl PacketCompleteSemanticSource {
    /// Reserves a separate complete registry body and metadata banks before Child birth.
    ///
    /// The selected bounds describe these physical banks only. The whole Source,
    /// process, factory and archive allocations require their independent original
    /// admission. Partial allocations remain in this Source on any later failure.
    ///
    /// # Errors
    /// Refuses foreign origin, a non-owning profile, native association, repeated
    /// reservation, invalid bounds or actual capacities beyond admitted storage.
    pub fn reserve_original_complete_registry_bank(
        &mut self,
        maximum_encoded_bytes: usize,
        maximum_rows: usize,
        admitted_bytes: usize,
    ) -> Result<(), OperationFailure> {
        self.ensure_origin()?;
        // The Source spends this flag before the actual launch-slot callback.
        // Native-unbound alone can persist after that reservation or Child birth.
        if self.complete_bytes_launch_reserved.get() {
            return Err(refused(
                "complete registry banks follow original launch reservation",
            ));
        }
        if !matches!(
            self.selected_capture_profile()?,
            PacketNative5CaptureProfile::OwnedProtocol11 { .. }
        ) {
            return Err(refused(
                "complete registry bank requires original owning profile",
            ));
        }
        let unbound = match &self.original {
            CompletePacketOriginal::Producer(source) => source.complete_preparation_unbound(),
            CompletePacketOriginal::Reactive(source) => source.complete_preparation_unbound(),
        }?;
        if !unbound {
            return Err(refused(
                "complete registry bank must precede native association",
            ));
        }
        let selected_memory = usize::try_from(
            self.installation()
                .realize
                .resource_limits
                .memory_bytes
                .get(),
        )
        .map_err(unknown)?;
        OriginalCompleteRegistryCapture::reserve_into(
            self.registry_capture.get_mut(),
            maximum_encoded_bytes,
            maximum_rows,
            admitted_bytes.min(selected_memory),
        )
    }

    pub(super) fn record_original_complete_registry(
        &self,
        scope: &CnpSemanticCaptureScope<'_>,
    ) -> Result<(), OperationFailure> {
        self.authenticate_witness_scope(&scope.realization()?)?;
        let owner = self.original_extension_registry_owner_data()?;
        let mut slot = self
            .registry_capture
            .try_borrow_mut()
            .map_err(|_| refused("complete registry banks are borrowed"))?;
        let original = slot
            .as_mut()
            .ok_or_else(|| refused("complete registry banks absent"))?;
        if !original.reserved || original.failed || original.attempted {
            return Err(refused("complete registry capture is unavailable or spent"));
        }
        if original
            .records
            .as_ref()
            .is_none_or(|records| records.maximum_rows() != original.maximum_rows)
            || original.aliases.as_ref().is_none_or(|aliases| {
                aliases.allocation_facts().maximum_rows != original.maximum_rows
            })
        {
            return Err(refused("complete registry original row selections differ"));
        }
        original.attempted = true;
        let result = (|| {
            scope.native.encode_original_complete_registry_into(
                &owner,
                original
                    .records
                    .as_mut()
                    .ok_or_else(|| refused("complete registry record bank absent"))?,
                original
                    .aliases
                    .as_mut()
                    .ok_or_else(|| refused("complete registry alias bank absent"))?,
                &mut original.encoded,
            )?;
            if original.encoded.len() > original.maximum_encoded_bytes {
                return Err(refused("complete registry exceeds selected encoded bound"));
            }
            let reference =
                canonical::content_ref(&original.encoded, HOST_REGISTRY_MEDIA).map_err(unknown)?;
            // The same allocation enters its owning result before the final
            // source/process fences; refusal never drops a completed body.
            original.payload = Some(InputPayload {
                reference,
                bytes: std::mem::take(&mut original.encoded),
            });
            self.authenticate_witness_scope(&scope.realization()?)
        })();
        if result.is_err() {
            original.failed = true;
        }
        result
    }

    /// Borrows the unchanged complete registry body for the settled journal producer.
    ///
    /// This loan is origin-only historical data. It does not enroll a callback,
    /// prove full journal membership or require an old retired Child to be live.
    ///
    /// # Errors
    /// Refuses foreign, borrowed, partial or failed original capture custody.
    pub fn original_complete_registry_payload_data(
        &self,
    ) -> Result<Ref<'_, InputPayload>, OperationFailure> {
        self.ensure_origin()?;
        let slot = self
            .registry_capture
            .try_borrow()
            .map_err(|_| refused("complete registry payload is borrowed"))?;
        Ref::filter_map(slot, |slot| {
            slot.as_ref()
                .filter(|original| original.reserved && original.attempted && !original.failed)
                .and_then(|original| original.payload.as_ref())
        })
        .map_err(|_| refused("complete original registry payload is incomplete"))
    }

    pub(super) fn original_registry_decoder_selection_data(
        &self,
    ) -> Result<(usize, usize), OperationFailure> {
        self.ensure_origin()?;
        let slot = self
            .registry_capture
            .try_borrow()
            .map_err(|_| refused("complete registry decoder selection is borrowed"))?;
        let original = slot
            .as_ref()
            .filter(|original| original.reserved && !original.failed)
            .ok_or_else(|| refused("complete registry born banks are absent or failed"))?;
        Ok((original.maximum_encoded_bytes, original.maximum_rows))
    }

    pub(super) fn original_registry_capture_storage_data(
        &self,
        maximum: usize,
    ) -> Result<usize, OperationFailure> {
        self.original_registry_capture_storage_data_with_error::<OperationFailure>(maximum)
    }

    pub(in crate::node_adapters::cnp::semantic) fn original_registry_capture_storage_data_with_error<
        E: StorageError,
    >(
        &self,
        maximum: usize,
    ) -> Result<usize, E> {
        self.storage_origin_with_error::<E>()?;
        self.registry_capture
            .try_borrow()
            .map_err(|_| E::refused("retained complete registry bank is borrowed"))?
            .as_ref()
            .map(|original| original.retained_storage_with_error::<E>(maximum))
            .transpose()
            .map(|bytes| bytes.unwrap_or(0))
    }
}

#[cfg(test)]
// crucible-lint: allow panic-shortcut -- Pure bank controls fail at the exact allocation or invariant.
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn registry_precharge_includes_both_private_alias_banks_and_exact_limit() {
        let required = OriginalCompleteRegistryCapture::reservation_storage(1024, 8).unwrap();
        let mut short = None;
        assert!(
            OriginalCompleteRegistryCapture::reserve_into(&mut short, 1024, 8, required - 1)
                .is_err()
        );
        assert!(short.is_none());

        let mut original = None;
        OriginalCompleteRegistryCapture::reserve_into(&mut original, 1024, 8, required).unwrap();
        let bank = original.as_ref().unwrap();
        let alias_facts = bank.aliases.as_ref().unwrap().allocation_facts();
        assert!(alias_facts.row_bytes > 0 && alias_facts.lookup_bytes > 0);
        assert!(bank.retained_storage(required).unwrap() <= required);
        assert!(
            OriginalCompleteRegistryCapture::reserve_into(&mut original, 1024, 8, required)
                .is_err()
        );
        assert!(original.as_ref().unwrap().reserved);
    }

    #[test]
    fn registry_bounds_refuse_before_any_bank_and_completed_bytes_are_counted_once() {
        let mut invalid = None;
        assert!(
            OriginalCompleteRegistryCapture::reserve_into(&mut invalid, 1024, 0, usize::MAX)
                .is_err()
        );
        assert!(invalid.is_none());
        assert!(OriginalCompleteRegistryCapture::reservation_storage(usize::MAX, 8).is_err());

        let mut original = None;
        OriginalCompleteRegistryCapture::reserve_into(&mut original, 1024, 8, 65536).unwrap();
        let bank = original.as_mut().unwrap();
        let before = bank.retained_storage(65536).unwrap();
        bank.payload = Some(InputPayload {
            reference: canonical::content_ref(b"original complete registry", "application/json")
                .unwrap(),
            bytes: std::mem::take(&mut bank.encoded),
        });
        let reference =
            NodeRuntime::capture_reference_storage(&bank.payload.as_ref().unwrap().reference)
                .unwrap();
        assert_eq!(bank.retained_storage(65536).unwrap(), before + reference);
    }
}
