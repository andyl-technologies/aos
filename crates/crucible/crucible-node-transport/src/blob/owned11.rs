//! Borrows every native blob ledger owner for the explicit whole-eleven edition.
//!
//! This data view preserves complete records, spare byte capacity, chunk history,
//! pins and tombstones. It neither settles custody nor reconstructs a supervisor.

use super::*;
use crate::{
    protocol_snapshot::{Sequence, compact_bytes::BorrowedCompactBytes},
    retained_metadata::{MetadataObserver, aliases::MetadataSharedKind},
};
use serde::{Serialize, Serializer};
use std::cell::Ref;

#[derive(Clone, Copy)]
pub(crate) struct OriginalBlobLayouts {
    pub(crate) state: usize,
    pub(crate) record_tree: usize,
    pub(crate) pin_tree: usize,
}

pub(crate) const fn original_blob_layouts() -> OriginalBlobLayouts {
    OriginalBlobLayouts {
        state: std::mem::size_of::<RefCell<ReceiverState>>(),
        record_tree: std::mem::size_of::<TransferKey>() + std::mem::size_of::<TransferRecord>(),
        pin_tree: std::mem::size_of::<u64>() + std::mem::size_of::<PinRecord>(),
    }
}

pub(crate) struct BlobStateOwned11View<'a> {
    owner: &'a Rc<RefCell<ReceiverState>>,
    original: Ref<'a, ReceiverState>,
}

pub(super) fn borrow_state(
    owner: &Rc<RefCell<ReceiverState>>,
) -> Result<BlobStateOwned11View<'_>, ProviderError> {
    let original = owner
        .try_borrow()
        .map_err(|_| ProviderError::Conflict("native blob original ledger borrowed"))?;
    Ok(BlobStateOwned11View { owner, original })
}

pub(crate) struct BlobOwned11View<'a> {
    receiver: &'a BlobReceiver,
    state: BlobStateOwned11View<'a>,
}

impl BlobReceiver {
    pub(crate) fn authenticate_original_supervisor<T: BlobSupervisor>(
        &self,
        supervisor: &Rc<T>,
    ) -> Result<(), ProviderError> {
        if !std::ptr::addr_eq(Rc::as_ptr(&self.supervisor), Rc::as_ptr(supervisor)) {
            return Err(ProviderError::Correlation(
                "native blob original supervisor changed",
            ));
        }
        Ok(())
    }

    pub(crate) fn borrowed_owned11_protocol_view(
        &self,
        authority: &crate::handshake::ConnectionAuthority,
    ) -> Result<BlobOwned11View<'_>, ProviderError> {
        authority.ensure_live()?;
        if authority.session_id() != &self.session
            || authority.incarnation_id() != &self.incarnation
        {
            return Err(ProviderError::Correlation(
                "native blob original authority differs",
            ));
        }
        Ok(BlobOwned11View {
            receiver: self,
            state: borrow_state(&self.state)?,
        })
    }
}

impl BlobStateOwned11View<'_> {
    pub(crate) fn observe_owned11_metadata(
        &self,
        observer: &mut MetadataObserver,
    ) -> Result<(), ProviderError> {
        observer.shared_original(MetadataSharedKind::BlobLedger, self.owner.as_ref())?;
        self.observe_owned_children(observer)
    }

    fn observe_owned_children(&self, observer: &mut MetadataObserver) -> Result<(), ProviderError> {
        let ReceiverState {
            records,
            reserved,
            next_pin,
            pins_created,
        } = &*self.original;
        observer.observe(reserved)?;
        observer.observe(next_pin)?;
        observer.observe(pins_created)?;
        observer.tree::<TransferKey, TransferRecord>(records.len())?;
        for (key, record) in records {
            let TransferKey {
                origin: _,
                session,
                incarnation,
                transfer,
            } = key;
            observer.observe(session)?;
            observer.observe(incarnation)?;
            observer.observe(transfer)?;
            let TransferRecord {
                content,
                length,
                bytes,
                chunks,
                verified,
                quarantined,
                exposed,
                retirement,
                pins,
                charged,
            } = record;
            observer.observe(content)?;
            observer.observe(length)?;
            observer.observe(bytes)?;
            observer.observe(chunks)?;
            observer.observe(verified)?;
            observer.observe(quarantined)?;
            observer.observe(exposed)?;
            match retirement {
                None | Some(BlobRetirement::AbandonInert) => {}
                Some(BlobRetirement::Operation { owner, receipt }) => {
                    observer.observe(owner)?;
                    observer.observe(receipt)?;
                }
                Some(BlobRetirement::DurableStore { receipt }) => observer.observe(receipt)?,
            }
            observer.tree::<u64, PinRecord>(pins.len())?;
            for (id, pin) in pins {
                observer.observe(id)?;
                let PinRecord {
                    owner,
                    schema,
                    state: _,
                    receipt,
                } = pin;
                observer.observe(owner)?;
                observer.observe(schema)?;
                observer.observe(receipt)?;
            }
            observer.observe(charged)?;
        }
        Ok(())
    }
}

impl BlobOwned11View<'_> {
    pub(crate) fn observe_owned11_metadata(
        &self,
        observer: &mut MetadataObserver,
    ) -> Result<(), ProviderError> {
        let BlobReceiver {
            session,
            incarnation,
            limits: _,
            state: _,
            supervisor,
        } = self.receiver;
        observer.observe(session)?;
        observer.observe(incarnation)?;
        self.state.observe_owned11_metadata(observer)?;
        observer.shared_original(MetadataSharedKind::NativeSupervisor, supervisor.as_ref())
    }
}

impl Serialize for BlobStateOwned11View<'_> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let state = &*self.original;
        let records = Sequence(|| {
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
                let chunks = Sequence(move || record.chunks.iter());
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
                    (
                        record.bytes.capacity(),
                        BorrowedCompactBytes::new(&record.bytes),
                    ),
                    chunks,
                    record.verified,
                    record.quarantined,
                    record.exposed,
                    retirement,
                    pins,
                    record.charged,
                )
            })
        });
        (
            "source-private.native-blob-ledger/11",
            state.reserved,
            U64::new(state.next_pin),
            state.pins_created,
            records,
        )
            .serialize(serializer)
    }
}

impl Serialize for BlobOwned11View<'_> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let limits = self.receiver.limits;
        (
            "source-private.native-blob-receiver/11",
            &self.receiver.session,
            &self.receiver.incarnation,
            (
                limits.reserved_bytes,
                limits.content_bytes,
                limits.chunk_bytes,
                limits.transfers_per_origin,
                limits.tombstones_per_origin,
                limits.chunks_per_transfer,
                limits.operation_pins,
            ),
            &self.state,
            "source-private.native-supervisor-owner/11",
        )
            .serialize(serializer)
    }
}

impl OperationContentPin {
    /// Observes this same receiver's retained pin and actual ledger allocations.
    ///
    /// The owning Connection must check its actual creator/current registration
    /// before calling. A generic content pin has no independent process origin;
    /// this data walk cannot manufacture that guard or native permission.
    pub(crate) fn observe_original_owned11_metadata(
        &self,
        receiver: &BlobReceiver,
        observer: &mut MetadataObserver,
    ) -> Result<(), ProviderError> {
        self.observe_original_pin_fields(receiver, observer)?
            .observe_owned11_metadata(observer)
    }

    /// Observes this actual pin edge in the same native Capture identity roster.
    ///
    /// Pin-owned identifiers and schema backing are independent. Only the real
    /// shared receiver ledger payload is walked once across receiver and pins.
    /// The caller authenticates its original Connection before this data loan.
    pub(crate) fn observe_unique_capture_metadata(
        &self,
        receiver: &BlobReceiver,
        roots: &mut crate::retained_metadata::NativeCaptureMetadataRoots,
        observer: &mut MetadataObserver,
    ) -> Result<(), ProviderError> {
        self.observe_original_pin_fields(receiver, observer)?
            .observe_unique_capture_metadata(roots, observer)
    }

    fn observe_original_pin_fields<'a>(
        &'a self,
        receiver: &BlobReceiver,
        observer: &mut MetadataObserver,
    ) -> Result<BlobStateOwned11View<'a>, ProviderError> {
        let Self {
            receiver: owner,
            key,
            pin,
            owner: operation,
            schema,
            settled,
        } = self;
        if !Rc::ptr_eq(owner, &receiver.state)
            || key.session != receiver.session
            || key.incarnation != receiver.incarnation
        {
            return Err(ProviderError::Correlation(
                "original content pin receiver changed",
            ));
        }
        let state = borrow_state(owner)?;
        let record = state
            .original
            .records
            .get(key)
            .ok_or(ProviderError::Correlation(
                "original content pin record absent",
            ))?;
        let retained = record.pins.get(pin).ok_or(ProviderError::Correlation(
            "original content pin identity absent",
        ))?;
        if retained.owner != *operation
            || retained.schema != *schema
            || record.quarantined
            || !record.verified
            || retained.state
                != if *settled {
                    PinState::Settled
                } else {
                    PinState::Held
                }
        {
            return Err(ProviderError::Correlation(
                "original content pin state changed",
            ));
        }
        let TransferKey {
            origin,
            session,
            incarnation,
            transfer,
        } = key;
        match origin {
            RequestOrigin::Controller | RequestOrigin::Provider => {}
        }
        observer.observe(session)?;
        observer.observe(incarnation)?;
        observer.observe(transfer)?;
        observer.observe(pin)?;
        observer.observe(operation)?;
        observer.observe(schema)?;
        observer.observe(settled)?;
        Ok(state)
    }
}

impl BlobStateOwned11View<'_> {
    pub(crate) fn observe_unique_capture_metadata(
        &self,
        roots: &mut crate::retained_metadata::NativeCaptureMetadataRoots,
        observer: &mut MetadataObserver,
    ) -> Result<(), ProviderError> {
        if roots.observe_shared(
            observer,
            MetadataSharedKind::BlobLedger,
            self.owner.as_ref(),
        )? {
            self.observe_owned_children(observer)?;
        }
        Ok(())
    }
}

impl BlobOwned11View<'_> {
    pub(crate) fn observe_unique_capture_metadata(
        &self,
        roots: &mut crate::retained_metadata::NativeCaptureMetadataRoots,
        observer: &mut MetadataObserver,
    ) -> Result<(), ProviderError> {
        let BlobReceiver {
            session,
            incarnation,
            limits: _,
            state: _,
            supervisor,
        } = self.receiver;
        observer.observe(session)?;
        observer.observe(incarnation)?;
        self.state
            .observe_unique_capture_metadata(roots, observer)?;
        roots.observe_shared_edge(
            observer,
            MetadataSharedKind::NativeSupervisor,
            supervisor.as_ref(),
        )
    }
}

// crucible-lint: allow panic-shortcut -- actual pin/ledger identity, ownership and borrow refusal observations.
#[cfg(test)]
#[expect(
    clippy::unwrap_used,
    reason = "real pin and shared-ledger data assertions"
)]
mod capture_pin_tests {
    use super::*;
    use crate::retained_metadata::NativeCaptureMetadataRoots;
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

    fn receiver(authority: &crate::handshake::ConnectionAuthority) -> BlobReceiver {
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

    fn pins(receiver: &mut BlobReceiver) -> (OperationContentPin, OperationContentPin) {
        let key = TransferKey {
            origin: RequestOrigin::Controller,
            session: receiver.session.clone(),
            incarnation: receiver.incarnation.clone(),
            transfer: Id::new("pin-transfer").unwrap(),
        };
        let content =
            canonical::content_ref(b"actual retained content", "application/octet-stream").unwrap();
        receiver.begin(key.clone(), content.clone()).unwrap();
        receiver
            .chunk(
                &key,
                U64::new(0),
                &Bytes::new(b"actual retained content".to_vec()),
            )
            .unwrap();
        let verified = receiver.finish(&key).unwrap();
        let first = receiver
            .pin_operation(
                &verified,
                Id::new("first-operation").unwrap(),
                content.clone(),
                &Schema,
            )
            .unwrap();
        let second = receiver
            .pin_operation(
                &verified,
                Id::new("second-operation").unwrap(),
                content,
                &Schema,
            )
            .unwrap();
        (first, second)
    }

    #[test]
    fn two_actual_pins_retain_independent_fields_and_walk_one_shared_ledger() {
        let (_handshake, authority) = crate::handshake::tests::authority();
        let mut receiver = receiver(&authority);
        let (first, second) = pins(&mut receiver);
        let mut roots = NativeCaptureMetadataRoots::new();
        let mut observer = MetadataObserver::new();

        first
            .observe_unique_capture_metadata(&receiver, &mut roots, &mut observer)
            .unwrap();
        assert_eq!(roots.finish().unwrap(), (1, 1));
        let once = observer.finish();
        // Observe the same actual ledger with a second independently owned pin.
        let mut roots = NativeCaptureMetadataRoots::new();
        let mut observer = MetadataObserver::new();
        first
            .observe_unique_capture_metadata(&receiver, &mut roots, &mut observer)
            .unwrap();
        second
            .observe_unique_capture_metadata(&receiver, &mut roots, &mut observer)
            .unwrap();
        assert_eq!(roots.finish().unwrap(), (2, 1));
        let twice = observer.finish();

        assert_eq!(twice.shared_backing_views, once.shared_backing_views);
        assert_eq!(twice.shared_value_bytes, once.shared_value_bytes);
        assert_eq!(twice.vector_capacity_bytes, once.vector_capacity_bytes);
        assert_eq!(twice.tree_entries, once.tree_entries);
        assert!(twice.string_capacity_bytes > once.string_capacity_bytes);
    }

    #[test]
    fn unique_pin_walk_refuses_foreign_receiver_and_mutable_ledger_before_root_credit() {
        let (_handshake, authority) = crate::handshake::tests::authority();
        let mut original = receiver(&authority);
        let foreign = receiver(&authority);
        let (first, _second) = pins(&mut original);
        let mut roots = NativeCaptureMetadataRoots::new();
        let mut observer = MetadataObserver::new();

        assert!(
            first
                .observe_unique_capture_metadata(&foreign, &mut roots, &mut observer)
                .is_err()
        );
        assert_eq!(roots.finish().unwrap(), (0, 0));
        let guard = original.state.borrow_mut();
        assert!(
            first
                .observe_unique_capture_metadata(&original, &mut roots, &mut observer)
                .is_err()
        );
        assert_eq!(roots.finish().unwrap(), (0, 0));
        drop(guard);

        first
            .observe_unique_capture_metadata(&original, &mut roots, &mut observer)
            .unwrap();
        assert_eq!(roots.finish().unwrap(), (1, 1));
    }
}

/// Reports exact original ledger/tree alignments for explicit17 recorded views.
pub(crate) fn original_blob_alignment17_data() -> (usize, usize, usize) {
    (
        std::mem::align_of::<RefCell<ReceiverState>>(),
        std::mem::align_of::<TransferKey>().max(std::mem::align_of::<TransferRecord>()),
        std::mem::align_of::<u64>().max(std::mem::align_of::<PinRecord>()),
    )
}
