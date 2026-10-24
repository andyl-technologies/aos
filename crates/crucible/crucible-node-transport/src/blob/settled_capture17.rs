//! Checks actual resolved Blob custody before a settled Capture/output effect.
//!
//! A completed verified inert record or discharged retirement may remain `Some`.
//! Unfinished uploads and unresolved operation pins must remain live custody,
//! and therefore refuse this safe point. No field, byte bank, pin, tombstone or
//! reservation is changed by this predicate; it provides no native authority.

use super::*;

fn refused() -> ProviderError {
    ProviderError::Correlation("settled Capture17 requires resolved original Blob custody")
}

fn authenticate_record(record: &TransferRecord) -> Result<(), ProviderError> {
    // Retirement is not by itself discharge: an Operation retirement can still
    // owe a live Held/Quarantined operation pin. Conversely, an abandoned failed
    // upload retains its original quarantine flag as immutable tombstone data.
    for pin in record.pins.values() {
        if pin.state != PinState::Settled || pin.receipt.is_none() {
            return Err(refused());
        }
    }
    if record.exposed && record.pins.is_empty() {
        return Err(refused());
    }
    if record.retirement.is_some() {
        if record.charged || !record.bytes.is_empty() || !record.chunks.is_empty() {
            return Err(refused());
        }
        return Ok(());
    }
    if record.quarantined
        || !record.verified
        || !record.charged
        || record.bytes.len() != record.length
        || u64::try_from(record.length).map_err(|_| refused())? != record.content.length.get()
    {
        return Err(refused());
    }

    // The real Chunk transition records precisely one entry per contiguous
    // original boundary. This walk borrows those entries; it cannot complete a
    // missing Finish or reinterpret a full-but-unverified bank as evidence.
    let mut next = 0usize;
    for (&offset, &length) in &record.chunks {
        if offset != next || length == 0 {
            return Err(refused());
        }
        next = next
            .checked_add(length)
            .filter(|end| *end <= record.length)
            .ok_or_else(refused)?;
    }
    if next != record.length {
        return Err(refused());
    }
    Ok(())
}

impl BlobReceiver {
    /// Checks every actual transfer and pin without releasing original custody.
    ///
    /// Completed verified inert bytes and fully discharged tombstones remain
    /// eligible. A full bank still requires its actual successful Finish. This
    /// predicate belongs after selected Capture auxiliary transfers finish; it
    /// cannot be used as an exception for an ongoing ordinary transfer.
    ///
    /// # Errors
    /// Refuses partial/unverified uploads, active quarantine, unresolved pins,
    /// foreign original scope, inconsistent reservation accounting or a busy
    /// ledger. Refusal preserves all original bytes, flags, pins and counts.
    pub(crate) fn authenticate_settled_capture17_custody_data(&self) -> Result<(), ProviderError> {
        let state = self.state.try_borrow().map_err(|_| refused())?;
        let mut reserved = 0usize;
        for (key, record) in &state.records {
            self.check_scope(key)?;
            authenticate_record(record)?;
            if record.charged {
                reserved = reserved.checked_add(record.length).ok_or_else(refused)?;
            }
        }
        if reserved != state.reserved {
            return Err(refused());
        }
        Ok(())
    }
}

impl OperationContentPin {
    /// Checks the exact discharged wrapper against its original receiver entry.
    ///
    /// A retained settled wrapper remains evidence. Matching a numeric pin or
    /// old receipt does not settle an active wrapper or grant byte/native access.
    ///
    /// # Errors
    /// Refuses another receiver/scope, missing or changed key/pin/owner/schema,
    /// stale wrapper settlement, unresolved custody or a conflicting ledger loan.
    pub(crate) fn authenticate_settled_capture17_custody_data(
        &self,
        receiver: &BlobReceiver,
    ) -> Result<(), ProviderError> {
        if !Rc::ptr_eq(&self.receiver, &receiver.state) || !self.settled {
            return Err(refused());
        }
        receiver.check_scope(&self.key)?;
        let state = receiver.state.try_borrow().map_err(|_| refused())?;
        let record = state.records.get(&self.key).ok_or_else(refused)?;
        authenticate_record(record)?;
        let pin = record.pins.get(&self.pin).ok_or_else(refused)?;
        if pin.owner != self.owner
            || pin.schema != self.schema
            || pin.state != PinState::Settled
            || pin.receipt.is_none()
        {
            return Err(refused());
        }
        Ok(())
    }
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    reason = "actual Blob custody transition controls"
)]
mod tests {
    use super::*;
    use crucible_node_format::canonical;

    #[derive(Default)]
    struct Supervisor(RefCell<Vec<BlobQuarantine>>);

    impl BlobSupervisor for Supervisor {
        fn quarantine(&self, custody: BlobQuarantine) {
            self.0.borrow_mut().push(custody);
        }
    }

    struct Verifier;

    impl BlobSchemaVerifier for Verifier {
        fn verify_schema(
            &self,
            _: &ContentRef,
            content: &ContentRef,
            bytes: &[u8],
        ) -> Result<(), ProviderError> {
            content.verify(bytes)?;
            Ok(())
        }
    }

    impl BlobCustodyVerifier for Verifier {
        fn verify_custody(
            &self,
            _: &TransferKey,
            _: &ContentRef,
            _: &BlobCustody,
            _: &ContentRef,
        ) -> Result<(), ProviderError> {
            Ok(())
        }
    }

    fn id(value: &str) -> Id {
        Id::new(value).unwrap()
    }

    fn key() -> TransferKey {
        TransferKey {
            origin: RequestOrigin::Controller,
            session: id("session"),
            incarnation: id("incarnation"),
            transfer: id("original-upload"),
        }
    }

    fn new_receiver() -> BlobReceiver {
        BlobReceiver::new(
            id("session"),
            id("incarnation"),
            BlobLimits {
                reserved_bytes: 1024,
                content_bytes: 512,
                chunk_bytes: 64,
                transfers_per_origin: 4,
                tombstones_per_origin: 4,
                chunks_per_transfer: 16,
                operation_pins: 4,
            },
            Rc::new(Supervisor::default()),
        )
        .unwrap()
    }

    fn verified(receiver: &mut BlobReceiver) -> VerifiedTransfer {
        let reference =
            canonical::content_ref(b"actual-inert-object", "application/octet-stream").unwrap();
        receiver.begin(key(), reference).unwrap();
        receiver
            .chunk(
                &key(),
                U64::new(0),
                &Bytes::new(b"actual-inert-object".to_vec()),
            )
            .unwrap();
        receiver.finish(&key()).unwrap()
    }

    #[test]
    fn same_retained_upload_becomes_eligible_only_after_actual_finish() {
        let mut receiver = new_receiver();
        receiver
            .authenticate_settled_capture17_custody_data()
            .unwrap();
        let reference = canonical::content_ref(b"actual", "application/octet-stream").unwrap();
        receiver.begin(key(), reference).unwrap();
        assert!(
            receiver
                .authenticate_settled_capture17_custody_data()
                .is_err()
        );
        receiver
            .chunk(&key(), U64::new(0), &Bytes::new(b"actual".to_vec()))
            .unwrap();
        let before = receiver
            .state
            .borrow()
            .records
            .get(&key())
            .unwrap()
            .bytes
            .clone();
        let capacity = receiver
            .state
            .borrow()
            .records
            .get(&key())
            .unwrap()
            .bytes
            .capacity();

        // Complete octets still have no successful Finish or verified custody.
        assert!(
            receiver
                .authenticate_settled_capture17_custody_data()
                .is_err()
        );
        assert_eq!(
            receiver.state.borrow().records.get(&key()).unwrap().bytes,
            before
        );
        receiver.finish(&key()).unwrap();
        receiver
            .authenticate_settled_capture17_custody_data()
            .unwrap();

        let state = receiver.state.borrow();
        let retained = state.records.get(&key()).unwrap();
        assert_eq!(state.records.len(), 1);
        assert_eq!(retained.bytes, before);
        assert_eq!(retained.bytes.capacity(), capacity);
        assert!(retained.verified);
        assert!(retained.retirement.is_none());
        assert_eq!(state.reserved, 6);
    }

    #[test]
    fn same_retired_operation_is_ineligible_until_its_actual_pin_settles() {
        let mut receiver = new_receiver();
        let possession = verified(&mut receiver);
        let schema = canonical::content_ref(b"schema", "application/json").unwrap();
        let mut pin = receiver
            .pin_operation(&possession, id("original-operation"), schema, &Verifier)
            .unwrap();
        let transfer = canonical::content_ref(b"transfer-custody", "application/json").unwrap();
        receiver
            .retire(
                RequestOrigin::Controller,
                &key(),
                BlobRetirement::Operation {
                    owner: id("original-operation"),
                    receipt: transfer,
                },
                &Verifier,
            )
            .unwrap();

        assert!(
            receiver
                .authenticate_settled_capture17_custody_data()
                .is_err()
        );
        assert!(
            pin.authenticate_settled_capture17_custody_data(&receiver)
                .is_err()
        );
        let reserved = receiver.reserved_bytes().unwrap();
        receiver.contain_operation_pins().unwrap();
        assert!(
            receiver
                .authenticate_settled_capture17_custody_data()
                .is_err()
        );
        assert_eq!(receiver.reserved_bytes().unwrap(), reserved);

        let receipt =
            canonical::content_ref(b"actual-operation-settled", "application/json").unwrap();
        receiver.settle_pin(&mut pin, &receipt, &Verifier).unwrap();
        receiver
            .authenticate_settled_capture17_custody_data()
            .unwrap();
        pin.authenticate_settled_capture17_custody_data(&receiver)
            .unwrap();
        assert!(
            pin.authenticate_settled_capture17_custody_data(&new_receiver())
                .is_err()
        );

        let state = receiver.state.borrow();
        let record = state.records.get(&key()).unwrap();
        assert!(record.retirement.is_some());
        assert_eq!(record.pins.len(), 1);
        assert_eq!(
            record.pins.values().next().unwrap().receipt.as_ref(),
            Some(&receipt)
        );
        assert_eq!(state.reserved, 0);
        assert!(!record.charged);
    }

    #[test]
    fn discharged_failed_tombstone_keeps_original_failure_evidence() {
        let mut receiver = new_receiver();
        let reference = canonical::content_ref(b"correct", "application/octet-stream").unwrap();
        receiver.begin(key(), reference.clone()).unwrap();
        receiver
            .chunk(&key(), U64::new(0), &Bytes::new(b"corrupt".to_vec()))
            .unwrap();
        assert!(receiver.finish(&key()).is_err());
        assert!(
            receiver
                .authenticate_settled_capture17_custody_data()
                .is_err()
        );
        assert_eq!(
            receiver.state.borrow().records.get(&key()).unwrap().bytes,
            b"corrupt"
        );

        receiver
            .retire(
                RequestOrigin::Controller,
                &key(),
                BlobRetirement::AbandonInert,
                &Verifier,
            )
            .unwrap();
        receiver
            .authenticate_settled_capture17_custody_data()
            .unwrap();

        let state = receiver.state.borrow();
        let record = state.records.get(&key()).unwrap();
        assert_eq!(record.content, reference);
        assert!(record.quarantined);
        assert!(!record.verified);
        assert!(record.retirement.is_some());
        assert!(record.bytes.is_empty());
        assert_eq!(state.reserved, 0);
    }

    #[test]
    fn conflicting_borrow_refuses_without_changing_completed_custody() {
        let mut receiver = new_receiver();
        let _possession = verified(&mut receiver);
        let before = receiver.reserved_bytes().unwrap();
        let borrowed = receiver.state.borrow_mut();
        assert!(
            receiver
                .authenticate_settled_capture17_custody_data()
                .is_err()
        );
        drop(borrowed);
        receiver
            .authenticate_settled_capture17_custody_data()
            .unwrap();
        assert_eq!(receiver.reserved_bytes().unwrap(), before);
    }
}
