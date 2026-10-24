//! Borrows complete live receipts together with their unchanged native records.
//!
//! Only the original complete source issues these witnesses after joining its
//! retained process allocation, installed controller and source-validated journal.
//! Historical raw record dialects stay intact; no decoder or matching metadata
//! can issue a complete-source witness or enroll a foreign native capsule.

use super::*;
use crucible_node_transport::reference_packet::{
    connected::PacketConnectedNativeRecord,
    control::{PacketNative5Record, PacketNativeRecord},
};

/// Borrows the unchanged native record validated beneath a live complete receipt.
///
/// These records are observation data, not native execution or capture authority.
pub enum PacketCompleteNativeRecord<'a> {
    /// Borrows the original producer-two record without changing its dialect.
    Producer(&'a PacketNativeRecord),
    /// Borrows the original reactive-four record without changing its dialect.
    Reactive(&'a PacketConnectedNativeRecord),
}

enum OriginalNativeWitness<'a> {
    Producer(PacketNativeWitness<'a>),
    Reactive(PacketConnectedNativeWitness<'a>),
}

/// Borrows the original complete receipt and separate unchanged raw record bytes.
///
/// Its private constructor requires the same actual source, process allocation,
/// controller and complete receipt association. It grants no qualification,
/// acknowledgement, native grant, capture or restoration permission.
pub struct PacketCompleteNativeWitness<'a> {
    reference: ContentRef,
    bytes: &'a [u8],
    receipt: PacketNative5Record,
    native_bytes: &'a [u8],
    original: OriginalNativeWitness<'a>,
    allocation: Option<super::OriginalCaptureAllocationData<'a>>,
}

impl PacketCompleteNativeWitness<'_> {
    /// Borrows the selected original report and complete reference when present.
    ///
    /// The same source/kernel/original receipt guards constructed this data loan.
    /// Allocation/current-frontier admission must still use the actual Source.
    pub fn allocation_data(&self) -> Option<&super::OriginalCaptureAllocationData<'_>> {
        self.allocation.as_ref()
    }

    /// Borrows the exact original complete receipt identity.
    pub fn reference(&self) -> &ContentRef {
        &self.reference
    }

    /// Borrows the complete original receipt bytes retained by the same controller.
    pub fn bytes(&self) -> &[u8] {
        self.bytes
    }

    /// Borrows the source-authenticated live complete receipt tuple.
    pub fn receipt(&self) -> &PacketNative5Record {
        &self.receipt
    }

    /// Borrows the separate unchanged raw native record identity.
    pub fn native_reference(&self) -> &ContentRef {
        &self.receipt.native_record
    }

    /// Borrows the complete original producer-two or reactive-four raw bytes.
    pub fn native_bytes(&self) -> &[u8] {
        self.native_bytes
    }

    /// Borrows the exact source-validated unchanged native record variant.
    pub fn native_record(&self) -> PacketCompleteNativeRecord<'_> {
        match &self.original {
            OriginalNativeWitness::Producer(original) => {
                PacketCompleteNativeRecord::Producer(original.record())
            }
            OriginalNativeWitness::Reactive(original) => {
                PacketCompleteNativeRecord::Reactive(original.record())
            }
        }
    }
}

impl PacketCompleteSemanticSource {
    /// Borrows actual native metadata birth facts through the original receipt.
    ///
    /// The complete witness binds the actual native child, original controller
    /// reply and unchanged underlying model record. These capacities remain
    /// accounting facts; live quote and whole-world admission are independent.
    ///
    /// # Errors
    /// Refuses changed original source/native custody, missing live evidence,
    /// absent or inconsistent born row limits, or invalid actual capacity data.
    pub fn original_protocol_metadata_birth_facts(
        &self,
        scope: &CnpSemanticRealizationScope<'_>,
    ) -> Result<Option<crucible_node_transport::reference_packet::service::PacketNative5ProtocolMetadataBirthFacts>, OperationFailure>{
        let witness = self.latest_original_native_witness(scope)?;
        let facts = witness.receipt.protocol_metadata_birth_facts;
        match (self.selected_protocol_metadata_limits()?, facts) {
            (Some(limits), Some(facts)) => facts.validate_data(&limits).map_err(unknown)?,
            (None, None) => {}
            _ => {
                return Err(refused(
                    "complete original native metadata birth facts absent",
                ));
            }
        }
        self.authenticate_witness_scope(scope)?;
        Ok(facts)
    }

    pub(super) fn authenticate_witness_scope(
        &self,
        scope: &CnpSemanticRealizationScope<'_>,
    ) -> Result<(), OperationFailure> {
        self.ensure_origin()?;
        if !std::ptr::eq(self.installation(), scope.installation)
            || !scope
                .native
                .controller()
                .is_some_and(|original| std::ptr::eq(original, scope.controller))
        {
            return Err(refused(
                "complete witness scope is not original source/controller",
            ));
        }
        self.authenticate_original_native_owner(scope.native)?;
        if scope
            .controller
            .original_native5_codec_metadata_extent()
            .map_err(unknown)?
            != self.selected_ack_codec_metadata_extent()?
        {
            return Err(refused(
                "complete source actual codec metadata extent differs",
            ));
        }
        if scope
            .controller
            .original_native5_ack_emitter_selection()
            .map_err(unknown)?
            != self.selected_ack_emitter_selection()?
        {
            return Err(refused("complete source installed ACK selection changed"));
        }
        if scope
            .controller
            .original_native5_confirmation_selection()
            .map_err(unknown)?
            != self.selected_confirmation_selection()?
        {
            return Err(refused(
                "complete witness installed confirmation selection differs",
            ));
        }
        self.source().authenticate_provider(scope.native)?;
        self.authenticate_original_native_owner(scope.native)
    }

    /// Borrows one complete original receipt and its separately retained raw record.
    ///
    /// # Errors
    /// Refuses foreign source/controller allocations, changed creator or native
    /// custody, absent original records, malformed complete receipts, storage
    /// mismatch or inconsistent source-native request, inventory and grant data.
    pub fn original_native_witness<'a>(
        &self,
        scope: &CnpSemanticRealizationScope<'a>,
        reference: &ContentRef,
    ) -> Result<PacketCompleteNativeWitness<'a>, OperationFailure> {
        self.authenticate_witness_scope(scope)?;
        let original = match &self.original {
            CompletePacketOriginal::Producer(source) => {
                OriginalNativeWitness::Producer(source.original_native_witness(scope, reference)?)
            }
            CompletePacketOriginal::Reactive(source) => {
                OriginalNativeWitness::Reactive(source.original_native_witness(scope, reference)?)
            }
        };
        self.finish_native_witness(scope, reference.clone(), original)
    }

    /// Borrows the latest complete original receipt selected by actual controller sequence.
    ///
    /// # Errors
    /// Refuses foreign or stale original scope, missing current source evidence,
    /// changed complete receipt/storage or inconsistent original native history.
    pub fn latest_original_native_witness<'a>(
        &self,
        scope: &CnpSemanticRealizationScope<'a>,
    ) -> Result<PacketCompleteNativeWitness<'a>, OperationFailure> {
        self.authenticate_witness_scope(scope)?;
        let original = match &self.original {
            CompletePacketOriginal::Producer(source) => {
                OriginalNativeWitness::Producer(source.latest_original_native_witness(scope)?)
            }
            CompletePacketOriginal::Reactive(source) => {
                OriginalNativeWitness::Reactive(source.latest_original_native_witness(scope)?)
            }
        };
        let reference = match &original {
            OriginalNativeWitness::Producer(original) => original.reference().clone(),
            OriginalNativeWitness::Reactive(original) => original.reference().clone(),
        };
        self.finish_native_witness(scope, reference, original)
    }

    fn finish_native_witness<'a>(
        &self,
        scope: &CnpSemanticRealizationScope<'a>,
        reference: ContentRef,
        original: OriginalNativeWitness<'a>,
    ) -> Result<PacketCompleteNativeWitness<'a>, OperationFailure> {
        let bytes = scope.controller.content(&reference).map_err(unknown)?;
        reference.verify(bytes).map_err(unknown)?;
        // The concrete native source above already joined this complete receipt
        // to the exact original reply and verified its unchanged raw record.
        let value =
            canonical::parse_json(bytes, self.installation().maximum_result_bytes.min(65_536))
                .map_err(unknown)?;
        let decoded = super::capture_allocation_receipt::decode_complete_receipt_data(
            scope,
            bytes,
            value,
            self.selected_capture_allocation_selection()?,
        )?;
        let receipt = decoded.receipt;
        if receipt.protocol_metadata_limits != self.selected_protocol_metadata_limits()?
            || receipt.complete_restore_selection != self.selected_complete_restore_selection()?
            || receipt.restore_input_emitter_selection
                != self.selected_restore_input_emitter_selection()?
        {
            return Err(refused(
                "complete native receipt metadata row selection differs",
            ));
        }

        let native_bytes = scope
            .controller
            .content(&receipt.native_record)
            .map_err(unknown)?;
        receipt
            .native_record
            .verify(native_bytes)
            .map_err(unknown)?;
        self.authenticate_witness_scope(scope)?;
        Ok(PacketCompleteNativeWitness {
            reference,
            bytes,
            receipt,
            native_bytes,
            original,
            allocation: decoded.allocation,
        })
    }

    /// Borrows genuine original Stage or Commit4 input custody beneath this complete source.
    ///
    /// # Errors
    /// Refuses producer input use, foreign or stale original scope, absent input
    /// bytes or changed original Stage/Commit cuts, acknowledgements and payloads.
    pub fn original_input_witness<'a>(
        &self,
        scope: &CnpSemanticRealizationScope<'a>,
        reference: &ContentRef,
    ) -> Result<PacketConnectedInputWitness<'a>, OperationFailure> {
        self.authenticate_witness_scope(scope)?;
        let CompletePacketOriginal::Reactive(source) = &self.original else {
            return Err(refused("complete producer has no original input witness"));
        };
        let original = source.original_input_witness(scope, reference)?;
        self.authenticate_witness_scope(scope)?;
        Ok(original)
    }
}
