//! Borrows every original blob transfer, tombstone and pin without draining it.

use super::*;
use crate::protocol_snapshot::Sequence;
use serde::{Serialize, Serializer, ser::SerializeStruct};
use std::cell::Ref;

/// Holds the original operation wrapper and its receiver ledger under one borrow.
///
/// This is capture data only. Keeping the borrow prevents settlement or ledger
/// replacement during the caller's bounded count-and-encode pass.
pub(crate) struct OperationPinProtocolView<'a> {
    pin: &'a OperationContentPin,
    _original: Ref<'a, ReceiverState>,
}

impl OperationContentPin {
    /// Borrows this wrapper only with the exact original receiver and pin entry.
    ///
    /// No byte allocation, settlement or source-currentness authority is issued.
    /// The enclosing source authenticates its process and charges serialization.
    ///
    /// # Errors
    /// Refuses a foreign receiver, concurrent mutation, or inconsistent wrapper
    /// and original ledger identities or settlement state.
    pub(crate) fn original_protocol_view<'a>(
        &'a self,
        receiver: &'a BlobReceiver,
    ) -> Result<OperationPinProtocolView<'a>, ProviderError> {
        if !Rc::ptr_eq(&self.receiver, &receiver.state)
            || self.key.session != receiver.session
            || self.key.incarnation != receiver.incarnation
        {
            return Err(ProviderError::Correlation(
                "operation pin belongs to another original receiver",
            ));
        }
        let original = self.receiver.try_borrow().map_err(|_| {
            ProviderError::Correlation("original pin ledger is already mutably borrowed")
        })?;
        let entry = original
            .records
            .get(&self.key)
            .and_then(|record| record.pins.get(&self.pin))
            .ok_or(ProviderError::Correlation(
                "original operation pin is unavailable",
            ))?;
        if entry.owner != self.owner
            || entry.schema != self.schema
            || self.settled != (entry.state == PinState::Settled)
        {
            return Err(ProviderError::Correlation(
                "operation pin wrapper conflicts with its original ledger",
            ));
        }
        Ok(OperationPinProtocolView {
            pin: self,
            _original: original,
        })
    }
}

impl Serialize for OperationPinProtocolView<'_> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let pin = self.pin;
        let mut view = serializer.serialize_struct("Native5OperationContentPin", 5)?;
        view.serialize_field(
            "key",
            &(
                &pin.key.origin,
                &pin.key.session,
                &pin.key.incarnation,
                &pin.key.transfer,
            ),
        )?;
        view.serialize_field("pin", &U64::new(pin.pin))?;
        view.serialize_field("owner", &pin.owner)?;
        view.serialize_field("schema", &pin.schema)?;
        view.serialize_field("settled", &pin.settled)?;
        view.end()
    }
}

pub(crate) struct BlobProtocolOwner(Rc<RefCell<ReceiverState>>);

impl BlobReceiver {
    pub(crate) fn protocol_owner(&self) -> BlobProtocolOwner {
        BlobProtocolOwner(self.state.clone())
    }
    pub(crate) fn same_protocol_owner(&self, owner: &BlobProtocolOwner) -> bool {
        Rc::ptr_eq(&self.state, &owner.0)
    }
}

pub(crate) struct BlobProtocolView<'a> {
    receiver: &'a BlobReceiver,
    original: Ref<'a, ReceiverState>,
    compact: bool,
}

impl BlobReceiver {
    pub(crate) fn original_protocol_view(
        &self,
        authority: &crate::handshake::ConnectionAuthority,
    ) -> Result<BlobProtocolView<'_>, ProviderError> {
        authority.ensure_live()?;
        if authority.session_id() != &self.session
            || authority.incarnation_id() != &self.incarnation
        {
            return Err(ProviderError::Correlation(
                "blob snapshot belongs to another original connection scope",
            ));
        }
        let original = self.state.try_borrow().map_err(|_| {
            ProviderError::Correlation("original blob ledger is already mutably borrowed")
        })?;
        Ok(BlobProtocolView {
            receiver: self,
            original,
            compact: false,
        })
    }
}

impl BlobProtocolView<'_> {
    pub(crate) fn with_compact_encoding(mut self, compact: bool) -> Self {
        self.compact = compact;
        self
    }
}

impl Serialize for BlobProtocolView<'_> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let receiver = self.receiver;
        let state = &*self.original;
        let limits = receiver.limits;
        let mut snapshot = serializer.serialize_struct("Native5BlobReceiver", 8)?;
        snapshot.serialize_field("session", &receiver.session)?;
        snapshot.serialize_field("incarnation", &receiver.incarnation)?;
        snapshot.serialize_field(
            "limits",
            &(
                limits.reserved_bytes,
                limits.content_bytes,
                limits.chunk_bytes,
                limits.transfers_per_origin,
                limits.tombstones_per_origin,
                limits.chunks_per_transfer,
                limits.operation_pins,
            ),
        )?;
        snapshot.serialize_field("reserved", &state.reserved)?;
        snapshot.serialize_field("next_pin", &U64::new(state.next_pin))?;
        snapshot.serialize_field("pins_created", &state.pins_created)?;
        snapshot.serialize_field(
            "records",
            &Sequence(|| {
                state.records.iter().map(|(key, record)| {
                    let retirement = match &record.retirement {
                        None => ("none", None, None),
                        Some(BlobRetirement::AbandonInert) => ("abandon-inert", None, None),
                        Some(BlobRetirement::Operation { owner, receipt }) => {
                            ("operation", Some(owner), Some(receipt))
                        }
                        Some(BlobRetirement::DurableStore { receipt }) => {
                            ("durable-store", None, Some(receipt))
                        }
                    };
                    let pins = Sequence(move || {
                        record.pins.iter().map(|(id, pin)| {
                            (
                                U64::new(*id),
                                &pin.owner,
                                &pin.schema,
                                match pin.state {
                                    PinState::Held => "held",
                                    PinState::Quarantined => "quarantined",
                                    PinState::Settled => "settled",
                                },
                                &pin.receipt,
                            )
                        })
                    });
                    (
                        (&key.origin, &key.session, &key.incarnation, &key.transfer),
                        &record.content,
                        record.length,
                        crate::protocol_snapshot::ProtocolBytes {
                            bytes: &record.bytes,
                            compact: self.compact,
                        },
                        record.bytes.capacity(),
                        &record.chunks,
                        record.verified,
                        record.quarantined,
                        record.exposed,
                        retirement,
                        pins,
                        record.charged,
                    )
                })
            }),
        )?;
        snapshot.serialize_field(
            "codec",
            &if self.compact {
                "source-private.blob-receiver/7"
            } else {
                "source-private.blob-receiver/5"
            },
        )?;
        snapshot.end()
    }
}

#[cfg(test)]
// crucible-lint: allow panic-shortcut -- These blob ledger snapshot controls deliberately panic on invalid fixtures.
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use crate::handshake::ConnectionAuthority;
    use crucible_node_format::canonical;

    #[derive(Default)]
    struct Supervisor(RefCell<Vec<BlobQuarantine>>);
    impl BlobSupervisor for Supervisor {
        fn quarantine(&self, custody: BlobQuarantine) {
            self.0.borrow_mut().push(custody);
        }
    }
    struct Schema;
    impl BlobSchemaVerifier for Schema {
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
    fn receiver(authority: &ConnectionAuthority) -> BlobReceiver {
        BlobReceiver::new(
            authority.session_id().clone(),
            authority.incarnation_id().clone(),
            BlobLimits {
                reserved_bytes: 1024,
                content_bytes: 512,
                chunk_bytes: 64,
                transfers_per_origin: 4,
                tombstones_per_origin: 4,
                chunks_per_transfer: 8,
                operation_pins: 4,
            },
            Rc::new(Supervisor::default()),
        )
        .unwrap()
    }

    #[test]
    fn native5_original_blob_snapshot_preserves_actual_bytes_pin_quarantine_and_lifetime_credit() {
        let (_handshake, authority) = crate::handshake::tests::authority();
        let mut blob = receiver(&authority);
        let key = TransferKey {
            origin: RequestOrigin::Controller,
            session: authority.session_id().clone(),
            incarnation: authority.incarnation_id().clone(),
            transfer: Id::new("original-transfer").unwrap(),
        };
        let content = canonical::content_ref(b"abc", "application/octet-stream").unwrap();
        blob.begin(key.clone(), content.clone()).unwrap();
        blob.chunk(&key, U64::new(0), &Bytes::new(b"abc".to_vec()))
            .unwrap();
        let verified = blob.finish(&key).unwrap();
        let pin = blob
            .pin_operation(
                &verified,
                Id::new("original-operation").unwrap(),
                content,
                &Schema,
            )
            .unwrap();
        drop(pin);
        let view = blob.original_protocol_view(&authority).unwrap();
        let snapshot = serde_json::to_value(&view).unwrap();
        assert_eq!(snapshot["reserved"], 3);
        assert_eq!(snapshot["next_pin"], "2");
        assert_eq!(snapshot["pins_created"], 1);
        let row = &snapshot["records"][0];
        assert_eq!(row[3], serde_json::json!([97, 98, 99]));
        assert_eq!(row[6], true);
        assert_eq!(row[8], true);
        assert_eq!(row[10][0][0], "1");
        assert_eq!(row[10][0][3], "quarantined");
        assert!(blob.state.try_borrow_mut().is_err());
        drop(view);
        assert_eq!(blob.reserved_bytes().unwrap(), 3);
    }

    #[test]
    fn native5_original_blob_snapshot_refuses_foreign_owner_even_with_same_labels() {
        let (_handshake, authority) = crate::handshake::tests::authority();
        let original = receiver(&authority);
        let foreign = receiver(&authority);
        let owner = original.protocol_owner();
        assert!(original.same_protocol_owner(&owner));
        assert!(!foreign.same_protocol_owner(&owner));
        let lock = original.state.borrow_mut();
        assert!(original.original_protocol_view(&authority).is_err());
        drop(lock);
        original.original_protocol_view(&authority).unwrap();
    }
    #[test]
    fn native5_original_pin_wrapper_preserves_exact_owner_and_borrow() {
        let (_handshake, authority) = crate::handshake::tests::authority();
        let mut blob = receiver(&authority);
        let foreign = receiver(&authority);
        let key = TransferKey {
            origin: RequestOrigin::Controller,
            session: authority.session_id().clone(),
            incarnation: authority.incarnation_id().clone(),
            transfer: Id::new("original-pin-transfer").unwrap(),
        };
        let content = canonical::content_ref(b"abc", "application/octet-stream").unwrap();
        blob.begin(key.clone(), content.clone()).unwrap();
        blob.chunk(&key, U64::new(0), &Bytes::new(b"abc".to_vec()))
            .unwrap();
        let verified = blob.finish(&key).unwrap();
        let mut pin = blob
            .pin_operation(
                &verified,
                Id::new("original-operation").unwrap(),
                content.clone(),
                &Schema,
            )
            .unwrap();

        assert!(pin.original_protocol_view(&foreign).is_err());
        let view = pin.original_protocol_view(&blob).unwrap();
        let data = serde_json::to_value(&view).unwrap();
        assert_eq!(data["pin"], "1");
        assert_eq!(data["owner"], "original-operation");
        assert_eq!(data["settled"], false);
        assert_eq!(data["key"][3], "original-pin-transfer");
        assert!(blob.state.try_borrow_mut().is_err());
        drop(view);

        let lock = blob.state.borrow_mut();
        assert!(pin.original_protocol_view(&blob).is_err());
        drop(lock);
        pin.settled = true;
        assert!(pin.original_protocol_view(&blob).is_err());
        pin.settled = false;
        pin.schema = canonical::content_ref(b"other", "application/octet-stream").unwrap();
        assert!(pin.original_protocol_view(&blob).is_err());
        pin.schema = content;
        assert_eq!(pin.with_bytes(|bytes| bytes.to_vec()).unwrap(), b"abc");
        assert_eq!(blob.reserved_bytes().unwrap(), 3);
    }
}

impl BlobProtocolOwner {
    pub(crate) fn borrowed_owned11_protocol_view(
        &self,
    ) -> Result<super::owned11::BlobStateOwned11View<'_>, ProviderError> {
        super::owned11::borrow_state(&self.0)
    }
}
