//! Retains the actual native Observe report and its complete owning codec.
//!
//! Partial report preparation is not this completed owner. The real Observe
//! producer must retain its preparation slots before fallible work and move
//! their exact original owners here only after complete publication. No public
//! data constructor or serialized report can create this opaque native owner.

use super::*;
use crate::connection::{Connection, NativeCaptureSdkCompletedQuote};
use crate::reference_packet::control::PacketLiveCaptureControlCurrency;
use crate::reference_packet::service::{
    OriginalNativeCaptureContext,
    capture_allocation::{
        PACKET_NATIVE_CAPTURE_ALLOCATION_MEDIA, PacketNativeCaptureAllocationReport,
    },
};
use crate::retained_metadata::MetadataObserver;
use serde::Serialize;

// Fields are exposed only to the actual parent endpoint, which owns the sole
// producer and its sticky failure slots. Outside callers cannot assemble one.
pub(super) struct NativeCaptureAllocationOwner {
    pub(super) creator: u32,
    pub(super) thread: std::thread::ThreadId,
    pub(super) original_observe: Envelope,
    pub(super) sdk: NativeCaptureSdkCompletedQuote,
    pub(super) currency: PacketLiveCaptureControlCurrency,
    pub(super) report: PacketNativeCaptureAllocationReport,
    pub(super) report_reference: crucible_node_format::ContentRef,
    pub(super) encoded_report: Vec<u8>,
    pub(super) capture: Option<Envelope>,
}

impl NativeCaptureAllocationOwner {
    pub(super) fn authenticate_native(&self, native: &PacketControl) -> Result<(), ProviderError> {
        if self.creator != std::process::id()
            || self.thread != std::thread::current().id()
            || self.original_observe.message != crate::envelope::MessageKind::Request
            || self.original_observe.method != crate::envelope::Method::Observe
            || self.original_observe.request_id.0.as_ref()
                != Some(&self.report.scope.observe_request)
            || self.original_observe.sequence != self.report.scope.observe_sequence
            || self.report.scope.native_pid.get() != u64::from(self.creator)
            || self.report.scope.control_originals_before.get()
                != self.currency.originals_before() as u64
            || self.report.scope.model_cursor != self.currency.cursor()
            || self.report_reference.media_type != PACKET_NATIVE_CAPTURE_ALLOCATION_MEDIA
            || self.report_reference.length.get() != self.encoded_report.len() as u64
        {
            return Err(ProviderError::Correlation(
                "native completed Observe report owner differs",
            ));
        }
        self.report.validate_data()?;
        self.currency
            .authenticate_capture_boundary(native, self.capture.as_ref())
    }
}

/// Borrows the same actual completed endpoint owner for an inner native12 cut.
///
/// Construction is private to the real endpoint, after its complete Observe
/// producer. No pointers or live association constructors cross the codec.
pub(crate) struct OriginalNativeCaptureAllocationOwned12<'a> {
    owner: &'a NativeCaptureAllocationOwner,
    native: &'a PacketControl,
}

impl<'a> OriginalNativeCaptureAllocationOwned12<'a> {
    pub(super) fn borrow_original(
        owner: &'a NativeCaptureAllocationOwner,
        native: &'a PacketControl,
    ) -> Result<Self, ProviderError> {
        owner.authenticate_native(native)?;
        Ok(Self { owner, native })
    }

    /// Joins this retained fourth leaf to the SDK's actual incoming Capture.
    ///
    /// This checks data correspondence after the SDK's independent actual
    /// original/suffix guard. No portable Envelope creates the private owner.
    pub(crate) fn authenticate_capture_original_data(
        &self,
        original: &Envelope,
    ) -> Result<(), ProviderError> {
        self.owner.authenticate_native(self.native)?;
        if self.owner.capture.as_ref() != Some(original) {
            return Err(ProviderError::Correlation(
                "native Capture allocation fourth owner has another original",
            ));
        }
        Ok(())
    }

    pub(crate) fn authenticate_original(
        &self,
        connection: &Connection<crate::client::DeadlineStream>,
        blobs: &crate::blob::BlobReceiver,
        context: &OriginalNativeCaptureContext<'_>,
    ) -> Result<(), ProviderError> {
        self.owner.authenticate_native(self.native)?;
        self.owner
            .sdk
            .authenticate_same_target_data(connection, blobs, context)
    }

    pub(crate) fn borrowed_owned12_protocol_view<'b>(
        &'b self,
        connection: &Connection<crate::client::DeadlineStream>,
        blobs: &crate::blob::BlobReceiver,
        context: &OriginalNativeCaptureContext<'_>,
    ) -> Result<impl Serialize + 'b + use<'b>, ProviderError> {
        self.authenticate_original(connection, blobs, context)?;
        let sdk = self
            .owner
            .sdk
            .borrowed_owned12_protocol_view(connection, blobs, context)?;
        let currency = self
            .owner
            .currency
            .borrowed_owned12_protocol_view(self.native, self.owner.capture.as_ref())?;
        Ok((
            "source-private.native-capture-allocation-owner/12",
            self.owner.creator,
            "same-original-thread",
            "complete-original-observe",
            &self.owner.original_observe,
            sdk,
            currency,
            &self.owner.report,
            &self.owner.report_reference,
            (
                self.owner.encoded_report.capacity(),
                crate::protocol_snapshot::compact_bytes::BorrowedCompactBytes::new(
                    &self.owner.encoded_report,
                ),
            ),
            &self.owner.capture,
        ))
    }

    pub(crate) fn observe_owned12_metadata(
        &self,
        connection: &Connection<crate::client::DeadlineStream>,
        blobs: &crate::blob::BlobReceiver,
        context: &OriginalNativeCaptureContext<'_>,
        observer: &mut MetadataObserver,
    ) -> Result<(), ProviderError> {
        self.authenticate_original(connection, blobs, context)?;
        observer.observe(&self.owner.creator)?;
        observer.observe(&self.owner.original_observe)?;
        self.owner
            .sdk
            .observe_owned12_metadata(connection, blobs, context, observer)?;
        self.owner.currency.observe_owned12_metadata(
            self.native,
            self.owner.capture.as_ref(),
            observer,
        )?;
        observer.observe(&self.owner.report)?;
        observer.observe(&self.owner.report_reference)?;
        observe_original_report_byte_bank(&self.owner.encoded_report, observer)?;
        observer.observe(&self.owner.capture)?;
        self.authenticate_original(connection, blobs, context)
    }
}

// Primitive bytes have no owning children. Metadata records the actual byte
// allocation once, while compact encoding and cold canonical/hash verification
// still process every byte under their independent byte/work limits.
fn observe_original_report_byte_bank(
    bytes: &Vec<u8>,
    observer: &mut MetadataObserver,
) -> Result<(), ProviderError> {
    observer.vector::<u8>(bytes.capacity())?;
    observer.observe(&bytes.len())
}

#[cfg(test)]
mod byte_bank_metadata_tests {
    use super::*;

    #[test]
    fn actual_report_byte_bank_counts_full_spare_capacity_with_constant_metadata_work()
    -> Result<(), ProviderError> {
        for length in [0usize, 1, 4096, 16 * 1024] {
            let mut bytes = Vec::with_capacity(17 * 1024);
            bytes.resize(length, 255);
            let before = (bytes.as_ptr(), bytes.len(), bytes.capacity());
            let mut observer = MetadataObserver::new();
            observe_original_report_byte_bank(&bytes, &mut observer)?;
            let facts = observer.finish();
            assert_eq!(facts.vector_banks, 1);
            assert_eq!(facts.capacity_records, 1);
            assert_eq!(facts.vector_capacity_bytes, bytes.capacity());
            assert_eq!(facts.observed_nodes, 1);
            assert_eq!(before, (bytes.as_ptr(), bytes.len(), bytes.capacity()));
            assert!(bytes.iter().all(|byte| *byte == 255));
        }
        Ok(())
    }

    #[test]
    fn byte_bank_observer_avoids_generic_primitive_iteration_without_dropping_storage()
    -> Result<(), ProviderError> {
        let bytes = vec![127u8; 16 * 1024];
        let mut generic = MetadataObserver::new();
        generic.observe(&bytes)?;
        let generic = generic.finish();
        let mut typed = MetadataObserver::new();
        observe_original_report_byte_bank(&bytes, &mut typed)?;
        let typed = typed.finish();
        assert_eq!(generic.vector_capacity_bytes, typed.vector_capacity_bytes);
        assert_eq!(generic.capacity_records, typed.capacity_records);
        assert_eq!(generic.observed_nodes, typed.observed_nodes + bytes.len());
        Ok(())
    }
}

/// Names the real retained publication phase payload, without child backing.
///
/// The same Box holds partial preparation or the completed owner. Its compiled
/// maximum includes the larger phase rather than borrowing another type's size.
pub(crate) const fn original_capture_report_owner_layout_data() -> usize {
    std::mem::size_of::<super::capture_publication::NativeCaptureAllocationAttempt>()
}
