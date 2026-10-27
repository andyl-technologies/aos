//! Preserves ordinary and native Hello backing through incomplete exchanges.
//!
//! The journal's inline slot belongs to its enclosing Source. This walk neither
//! interprets a response nor publishes bytes or reconstructs a registration.

use super::*;
use crate::retained_metadata::MetadataObserver;
use crate::transport::original_frames::OriginalFrameReservation;
use std::{
    cell::{BorrowError, Ref, RefCell},
    mem::size_of,
    rc::Rc,
};

impl OriginalHelloJournal {
    /// Checks the native original's creator when literal-frame custody exists.
    ///
    /// Ordinary journals have no creator; their owning Source checks its origin.
    ///
    /// # Errors
    /// Refuses native custody created by another process or thread.
    pub(crate) fn check_capacity_creator_data(&self) -> Result<(), ProviderError> {
        // Ordinary journals have no private creator field; their containing
        // capsule must check origin before lending any physical record rows.
        if let Some(literal) = &self.literal {
            literal.original_cut.ensure_current()?;
        }
        Ok(())
    }

    /// Records retained request, response and native-frame backing without I/O.
    ///
    /// # Errors
    /// Refuses foreign creators, a busy native bank, exhausted rows or checked
    /// traversal/layout bounds. A busy bank refuses before any Hello row appends.
    pub(crate) fn observe_capacity_data(
        &self,
        observer: &mut MetadataObserver<'_>,
    ) -> Result<(), ProviderError> {
        self.check_capacity_creator_data()?;
        let Self {
            request,
            request_value,
            response,
            maximum_bytes,
            maximum_nesting,
            attempted,
            received,
            literal,
        } = self;
        inline(maximum_bytes);
        inline(maximum_nesting);
        inline(attempted);
        inline(received);
        let bank = match literal {
            None => None,
            Some(LiteralHello {
                bank,
                outgoing,
                write_started,
                original_cut,
            }) => {
                inline(outgoing);
                inline(write_started);
                original_cut.ensure_current()?;
                Some(bank.try_borrow().map_err(|_| {
                    ProviderError::Conflict("original Hello capacity bank borrowed")
                })?)
            }
        };

        // Borrow native custody before appending any component rows. A refused
        // loan leaves earlier Source components intact without a Hello prefix.
        observer.observe(request)?;
        observer.observe(request_value)?;
        observer.observe(response)?;
        if let (Some(literal), Some(bank)) = (literal.as_ref(), bank.as_ref()) {
            observer.shared_value(literal.bank.as_ref())?;
            bank.observe_owned11_metadata(observer)?;
        }
        self.check_capacity_creator_data()
    }

    /// Names compiled borrowed controls for this Hello component's census.
    ///
    /// Dynamic banks and whole-Source traversal work are charged separately.
    pub(crate) fn capacity_counter_scratch_data() -> usize {
        size_of::<&Self>()
            + size_of::<(
                &Envelope,
                &Value,
                &Vec<u8>,
                &usize,
                &usize,
                &bool,
                &bool,
                &Option<LiteralHello>,
            )>()
            + size_of::<(
                &Rc<RefCell<OriginalFrameReservation>>,
                &usize,
                &bool,
                &crate::protocol_snapshot::ProtocolCaptureOwner,
            )>()
            + size_of::<Option<Ref<'_, OriginalFrameReservation>>>()
            + size_of::<Result<Ref<'_, OriginalFrameReservation>, BorrowError>>()
            + size_of::<Option<&Ref<'_, OriginalFrameReservation>>>()
            + size_of::<Option<&LiteralHello>>()
            + size_of::<&mut MetadataObserver<'_>>()
            + size_of::<Result<(), ProviderError>>()
    }
}

const fn inline<T: Copy>(_value: &T) {}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::retained_metadata::{
        RetainedCaptureProtocolData,
        records::{MetadataCapacityRecord, MetadataRecordBank, MetadataRecordKind},
    };

    fn prefix() -> MetadataCapacityRecord {
        MetadataCapacityRecord {
            kind: MetadataRecordKind::Boxed,
            extent: 113,
            element_bytes: 1,
            alignment: 1,
        }
    }

    #[test]
    fn hello_capacity_data_keeps_ordinary_spares_and_failed_response_without_decoding() {
        let request = crate::handshake::tests::original_hello_envelope();
        let mut journal = OriginalHelloJournal::reserve(&request, 65_536, 64).unwrap();
        journal.response.reserve(173);
        let response_capacity = journal.response.capacity();
        let mut observer = MetadataObserver::new();
        observer.observe(&journal.request).unwrap();
        observer.observe(&journal.request_value).unwrap();
        let before_response = observer.finish();
        let before = RetainedCaptureProtocolData::HelloJournal(&journal)
            .observe_retained_metadata()
            .unwrap();
        assert_eq!(
            before.vector_capacity_bytes,
            before_response.vector_capacity_bytes + response_capacity
        );
        assert_eq!(before.vector_banks, before_response.vector_banks + 1);
        assert!(journal.original_retained_metadata_facts().is_err());

        journal.begin(&request, 65_536, 64).unwrap();
        journal
            .retain_response(b"{ malformed original response")
            .unwrap();

        assert!(Envelope::decode(journal.response().unwrap(), 65_536).is_err());
        let mut expected = before;
        // Retained capacity is unchanged; the SDK separately visits each newly
        // initialized response byte as scalar traversal work.
        expected.observed_nodes += journal.response().unwrap().len();
        assert_eq!(
            RetainedCaptureProtocolData::HelloJournal(&journal)
                .observe_retained_metadata()
                .unwrap(),
            expected
        );
        assert!(journal.begin(&request, 65_536, 64).is_err());
        assert!(journal.retain_response(b"replacement").is_err());
    }

    #[test]
    fn hello_capacity_data_keeps_native_literal_banks_and_refuses_busy_custody_before_rows() {
        let request = crate::handshake::tests::original_hello_envelope();
        let journal = OriginalHelloJournal::reserve_native5(&request, 16_384, 64).unwrap();
        let expected = journal.original_retained_metadata_facts().unwrap();
        assert_eq!(
            RetainedCaptureProtocolData::HelloJournal(&journal)
                .observe_retained_metadata()
                .unwrap(),
            expected
        );
        let mut records = MetadataRecordBank::reserve(expected.capacity_records + 1).unwrap();
        records.append(prefix()).unwrap();
        let literal = journal.literal.as_ref().unwrap();
        let held = literal.bank.borrow_mut();
        let mut observer = MetadataObserver::appending(&mut records);
        assert!(journal.observe_capacity_data(&mut observer).is_err());
        assert_eq!(observer.finish().capacity_records, 0);
        assert_eq!(records.rows(), [prefix()]);
        drop(held);

        let mut observer = MetadataObserver::appending(&mut records);
        journal.observe_capacity_data(&mut observer).unwrap();
        assert_eq!(observer.finish(), expected);
        assert_eq!(records.rows()[0], prefix());
        assert_eq!(records.rows().len(), expected.capacity_records + 1);
        assert!(!journal.attempted());
    }
}
