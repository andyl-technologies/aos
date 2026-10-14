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
        state.observe_owned11_metadata(observer)
    }
}
