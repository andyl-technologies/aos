//! Lends private completed producer banks and walks every retained partial.
//!
//! Completion is established only by the actual funded native comparer and
//! producer. These borrowed checks allocate no canonical/hash/DTO bank and
//! cannot reconstruct a live action from historical fields.

use super::*;

/// Borrows complete private producer fields without creating publication rights.
pub(crate) struct NativeObservation17PublishedProductionData<'a> {
    model: (&'a ContentRef, &'a [u8]),
    restored: (&'a ContentRef, &'a [u8]),
    body: &'a Map<String, Value>,
}

impl<'a> NativeObservation17PublishedProductionData<'a> {
    /// Borrows the completed owner's actual native model bank.
    pub(crate) fn model_data(&self) -> (&'a ContentRef, &'a [u8]) {
        self.model
    }

    /// Borrows the completed owner's actual restored proof bank.
    pub(crate) fn restored_data(&self) -> (&'a ContentRef, &'a [u8]) {
        self.restored
    }

    /// Borrows its retained produced response body.
    pub(crate) fn body_data(&self) -> &'a Map<String, Value> {
        self.body
    }
}

impl NativeObservation17CheckpointAttempt {
    /// Checks the defining private comparison's completed retained owners.
    ///
    /// # Errors
    /// Refuses incomplete comparison, lost banks or changed receipt custody.
    pub(crate) fn authenticate_validated_data(&self) -> Result<(), ProviderError> {
        let receipt = self.receipt.as_ref().ok_or_else(refused)?;
        let restored = self.restored.as_ref().ok_or_else(refused)?;
        if !self.validated
            || self.model_bytes.is_empty()
            || self.restored_bytes.is_empty()
            || restored.native_receipt != *receipt
            || restored.physical_gate_held
            || u64::try_from(self.model_bytes.len()).ok()
                != Some(receipt.native_record.length.get())
        {
            return Err(refused());
        }
        Ok(())
    }

    /// Walks actual retained comparison partials in the strict reader's order.
    ///
    /// # Errors
    /// Refuses exhausted metadata banks or checked layout overflow.
    pub(crate) fn observe_retained_data(
        &self,
        observer: &mut MetadataObserver<'_>,
    ) -> Result<(), ProviderError> {
        let Self {
            model_bytes,
            receipt,
            restored,
            restored_bytes,
            validated,
        } = self;
        observer.observe(model_bytes)?;
        observer.observe(receipt)?;
        observer.observe(restored)?;
        observer.observe(restored_bytes)?;
        observer.observe(validated)
    }
}

impl NativeObservation17ProductionAttempt {
    /// Lends only banks retained by the genuine completed producer.
    ///
    /// # Errors
    /// Refuses incomplete production, another original, absent proof/body,
    /// lost independent evidence banks or changed complete reference custody.
    pub(crate) fn published_data(
        &self,
        original: &Envelope,
    ) -> Result<NativeObservation17PublishedProductionData<'_>, ProviderError> {
        let model = self.model_reference.as_ref().ok_or_else(refused)?;
        let restored_reference = self.restored_reference.as_ref().ok_or_else(refused)?;
        let receipt = self.receipt.as_ref().ok_or_else(refused)?;
        let restored = self.restored.as_ref().ok_or_else(refused)?;
        let body = self.body.as_ref().ok_or_else(refused)?;
        let [model_evidence, restored_evidence] = self.evidence.as_slice() else {
            return Err(refused());
        };
        if !self.started
            || !self.complete
            || self.model_bytes.is_empty()
            || self.restored_bytes.is_empty()
            || &receipt.original != original
            || receipt.native_record != *model
            || restored.native_receipt != *receipt
            || restored.physical_gate_held
            || u64::try_from(self.model_bytes.len()).ok() != Some(model.length.get())
            || u64::try_from(self.restored_bytes.len()).ok()
                != Some(restored_reference.length.get())
            || &model_evidence.0 != model
            || model_evidence.1 != self.model_bytes
            || &restored_evidence.0 != restored_reference
            || restored_evidence.1 != self.restored_bytes
        {
            return Err(refused());
        }
        Ok(NativeObservation17PublishedProductionData {
            model: (model, &self.model_bytes),
            restored: (restored_reference, &self.restored_bytes),
            body,
        })
    }

    /// Walks every actual producer partial in its defining field order.
    ///
    /// # Errors
    /// Refuses exhausted metadata banks or checked layout overflow.
    pub(crate) fn observe_retained_data(
        &self,
        observer: &mut MetadataObserver<'_>,
    ) -> Result<(), ProviderError> {
        let Self {
            model_bytes,
            model_reference,
            receipt,
            restored,
            restored_bytes,
            restored_reference,
            body,
            evidence,
            started,
            complete,
        } = self;
        observer.observe(model_bytes)?;
        observer.observe(model_reference)?;
        observer.observe(receipt)?;
        observer.observe(restored)?;
        observer.observe(restored_bytes)?;
        observer.observe(restored_reference)?;
        observer.observe(body)?;
        observer.observe(evidence)?;
        observer.observe(started)?;
        observer.observe(complete)
    }
}

impl NativeObservation17ProductionAttempt {
    /// Names the defining completed producer's fixed borrowed views.
    pub(crate) const fn retained_counter_scratch_data() -> usize {
        size_of::<NativeObservation17PublishedProductionData<'static>>()
            + size_of::<Result<NativeObservation17PublishedProductionData<'static>, ProviderError>>(
            )
            + size_of::<&ContentRef>() * 2
            + size_of::<&PacketNative5Record>()
            + size_of::<&PacketNativeRestoredRecord>()
            + size_of::<&Map<String, Value>>()
            + size_of::<&[(ContentRef, Vec<u8>)]>()
            + size_of::<Result<(), ProviderError>>()
    }
}

impl NativeObservation17CheckpointAttempt {
    /// Names the defining comparison's fixed borrowed completion views.
    pub(crate) const fn retained_counter_scratch_data() -> usize {
        size_of::<&PacketNative5Record>()
            + size_of::<&PacketNativeRestoredRecord>()
            + size_of::<Result<(), ProviderError>>()
    }
}

#[cfg(test)]
mod tests {
    // crucible-lint: allow panic-shortcut -- These inert partial/metadata controls deliberately panic on invalid setup.
    #![allow(clippy::unwrap_used)]

    use super::*;
    use crate::protocol_snapshot::owned11::{json_value::HistoricalJsonLimits, typed::Ledger};
    use crate::protocol_snapshot::restored_settled17::current_actions::{
        CurrentObservationCheckpoint17, CurrentObservationProduction17,
    };
    use crate::retained_metadata::records::{MetadataRecordBank, ValidatedMetadataRecords};

    fn limits() -> HistoricalJsonLimits {
        HistoricalJsonLimits {
            maximum_input_bytes: 65_536,
            maximum_nodes: 4096,
            maximum_depth: 32,
            maximum_owned_backing_bytes: 65_536,
            maximum_tree_entries: 1024,
        }
    }

    #[test]
    fn actual_partial_comparison_banks_preserve_independent_spare_capacity() {
        // This is retained DATA, not a fabricated published native owner.
        let mut model_bytes = Vec::with_capacity(37);
        model_bytes.extend_from_slice(b"partial-model");
        let mut restored_bytes = Vec::with_capacity(41);
        restored_bytes.extend_from_slice(b"unfinished-proof");
        let mut actual = NativeObservation17CheckpointAttempt {
            model_bytes,
            receipt: None,
            restored: None,
            restored_bytes,
            validated: false,
        };
        assert!(actual.authenticate_validated_data().is_err());
        actual.validated = true;
        assert!(actual.authenticate_validated_data().is_err());
        actual.validated = false;
        let input = serde_json::to_vec(&actual).unwrap();
        let mut records = MetadataRecordBank::reserve(8).unwrap();
        let mut observer = MetadataObserver::recording(&mut records);
        actual.observe_retained_data(&mut observer).unwrap();
        let _ = observer.finish();
        let rows = serde_json::to_vec(&records).unwrap();
        let rows = ValidatedMetadataRecords::validate(&rows, 8, 65_536).unwrap();

        let mut ledger = Ledger::new(rows.rows(), limits());
        assert!(
            ledger
                .read::<CurrentObservationCheckpoint17>(&input, false)
                .unwrap()
                .is_none()
        );
        assert!(ledger.rows.next().is_none());
        let mut ledger = Ledger::new(rows.rows(), limits());
        let restored = ledger
            .read::<CurrentObservationCheckpoint17>(&input, true)
            .unwrap()
            .unwrap();

        assert_eq!(restored.model_bytes, actual.model_bytes);
        assert_eq!(
            restored.model_bytes.capacity(),
            actual.model_bytes.capacity()
        );
        assert_eq!(restored.restored_bytes, actual.restored_bytes);
        assert_eq!(
            restored.restored_bytes.capacity(),
            actual.restored_bytes.capacity()
        );
        assert!(!restored.validated);
        assert!(restored.receipt.is_none() && restored.restored.is_none());
        assert!(ledger.rows.next().is_none());
    }

    #[test]
    fn actual_partial_producer_keeps_all_banks_and_refuses_one_short_capacity() {
        let mut model_bytes = Vec::with_capacity(47);
        model_bytes.extend_from_slice(b"partial-native");
        let mut actual = NativeObservation17ProductionAttempt {
            model_bytes,
            model_reference: None,
            receipt: None,
            restored: None,
            restored_bytes: Vec::with_capacity(53),
            restored_reference: None,
            body: None,
            evidence: Vec::with_capacity(3),
            started: true,
            complete: false,
        };
        let original = crate::envelope::tests::request();
        assert!(actual.published_data(&original).is_err());
        actual.complete = true;
        assert!(actual.published_data(&original).is_err());
        actual.complete = false;
        let before_model = actual.model_bytes.capacity();
        let before_evidence = actual.evidence.capacity();
        let input = serde_json::to_vec(&actual).unwrap();
        let mut records = MetadataRecordBank::reserve(8).unwrap();
        let mut observer = MetadataObserver::recording(&mut records);
        actual.observe_retained_data(&mut observer).unwrap();
        let _ = observer.finish();
        let rows = serde_json::to_vec(&records).unwrap();
        let validated = ValidatedMetadataRecords::validate(&rows, 8, 65_536).unwrap();
        let mut ledger = Ledger::new(validated.rows(), limits());
        let restored = ledger
            .read::<CurrentObservationProduction17>(&input, true)
            .unwrap()
            .unwrap();
        assert_eq!(restored.model_bytes, actual.model_bytes);
        assert_eq!(
            restored.model_bytes.capacity(),
            actual.model_bytes.capacity()
        );
        assert_eq!(
            restored.restored_bytes.capacity(),
            actual.restored_bytes.capacity()
        );
        assert_eq!(restored.evidence.capacity(), actual.evidence.capacity());
        assert!(restored.started && !restored.complete);
        assert!(restored.body.is_none() && restored.receipt.is_none());
        assert!(ledger.rows.next().is_none());

        let mut shortened: Vec<(String, usize, usize, usize)> =
            serde_json::from_slice(&rows).unwrap();
        shortened[0].1 = actual.model_bytes.len() - 1;
        let shortened = serde_json::to_vec(&shortened).unwrap();
        let shortened = ValidatedMetadataRecords::validate(&shortened, 8, 65_536).unwrap();
        let mut ledger = Ledger::new(shortened.rows(), limits());
        assert!(
            ledger
                .read::<CurrentObservationProduction17>(&input, false)
                .is_err()
        );
        assert_eq!(actual.model_bytes.capacity(), before_model);
        assert_eq!(actual.evidence.capacity(), before_evidence);
    }
}
