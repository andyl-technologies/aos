//! Borrows complete exchange originals and actual decoder caches without copying.
//!
//! The source supplies its own bounded count-and-encode writer and authenticates
//! endpoint ownership. This view cannot install state or settle correlation.

use super::*;
use crate::bodies::MethodResult;
use crate::protocol_snapshot::Sequence;
use serde::{Serialize, Serializer, ser::SerializeStruct};

impl ExchangeRecord {
    /// Borrows planned frames, original archive slots and actual reply progress.
    ///
    /// Container capacities are retained alongside every cached semantic value.
    /// Literal transport bytes remain in the separate original frame bank; these
    /// canonical planned buffers must never substitute for that literal history.
    pub(crate) fn original_protocol_view(&self) -> impl Serialize + '_ {
        ExchangeProtocolView(self)
    }
}

struct ExchangeProtocolView<'a>(&'a ExchangeRecord);

impl Serialize for ExchangeProtocolView<'_> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let record = self.0;
        let mut view = serializer.serialize_struct("Native5ExchangeRecord", 10)?;
        view.serialize_field("originals", &record.originals)?;
        view.serialize_field("originals_capacity", &record.originals.capacity())?;
        view.serialize_field(
            "canonical",
            &Sequence(|| {
                record
                    .canonical
                    .iter()
                    .map(|bytes| (bytes, bytes.capacity()))
            }),
        )?;
        view.serialize_field("canonical_capacity", &record.canonical.capacity())?;
        view.serialize_field(
            "acknowledgements",
            &Sequence(|| {
                record
                    .acknowledgements
                    .iter()
                    .map(|frame| (&frame.envelope, DecodedBodyView(&frame.body)))
            }),
        )?;
        view.serialize_field(
            "acknowledgements_capacity",
            &record.acknowledgements.capacity(),
        )?;
        view.serialize_field("sent", &record.sent)?;
        view.serialize_field("original_slots", &record.original_slots)?;
        view.serialize_field("original_slots_capacity", &record.original_slots.capacity())?;
        // This graph edge denotes the enclosing endpoint's actor/bank, not a
        // portable pointer or decoded capability. Fresh installation is separate.
        view.serialize_field(
            "original_actor",
            &record
                .original_actor
                .as_ref()
                .map(|_| "same-original-endpoint"),
        )?;
        view.end()
    }
}

struct DecodedBodyView<'a>(&'a ReceivedBody);

impl Serialize for DecodedBodyView<'_> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        match self.0 {
            ReceivedBody::Request(body) => ("Request", RequestView(body)).serialize(serializer),
            ReceivedBody::Response(body) => (
                "Response",
                &body.shape,
                body.result.as_ref().map(MethodResultView),
            )
                .serialize(serializer),
            ReceivedBody::NativeImport18Bootstrap(_) => Err(serde::ser::Error::custom(
                "bootstrap18 requires its distinct history grammar",
            )),
            ReceivedBody::Notification(body) => ("Notification", body).serialize(serializer),
        }
    }
}

struct RequestView<'a>(&'a RequestBody);

impl Serialize for RequestView<'_> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        match self.0 {
            RequestBody::Hello(data) => ("Hello", data).serialize(serializer),
            RequestBody::Discover(data) => ("Discover", data).serialize(serializer),
            RequestBody::Realize(data) => ("Realize", data).serialize(serializer),
            RequestBody::Admit(data) => ("Admit", data).serialize(serializer),
            RequestBody::Activate(data) => ("Activate", data).serialize(serializer),
            RequestBody::Input(data) => ("Input", data).serialize(serializer),
            RequestBody::Observe(data) => ("Observe", data).serialize(serializer),
            RequestBody::Begin(data) => ("Begin", data).serialize(serializer),
            RequestBody::Poll(data) => ("Poll", data).serialize(serializer),
            RequestBody::Cancel(data) => ("Cancel", data).serialize(serializer),
            RequestBody::QuantumClose(data) => ("QuantumClose", data).serialize(serializer),
            RequestBody::WorldActivate(data) => ("WorldActivate", data).serialize(serializer),
            RequestBody::Abort(data) => ("Abort", data).serialize(serializer),
            RequestBody::Retire(data) => ("Retire", data).serialize(serializer),
            RequestBody::BlobBegin(data) => ("BlobBegin", data).serialize(serializer),
            RequestBody::BlobChunk(data) => ("BlobChunk", data).serialize(serializer),
            RequestBody::BlobFinish(data) => ("BlobFinish", data).serialize(serializer),
            RequestBody::Release(data) => ("Release", data).serialize(serializer),
        }
    }
}

struct MethodResultView<'a>(&'a MethodResult);

impl Serialize for MethodResultView<'_> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        match self.0 {
            MethodResult::Hello(data) => ("Hello", data).serialize(serializer),
            MethodResult::Discover(data) => ("Discover", data).serialize(serializer),
            MethodResult::Realize(data) => ("Realize", data).serialize(serializer),
            MethodResult::Admit(data) => ("Admit", data).serialize(serializer),
            MethodResult::Activate(data) => ("Activate", data).serialize(serializer),
            MethodResult::Input(data) => ("Input", data).serialize(serializer),
            MethodResult::Observe(data) => ("Observe", data).serialize(serializer),
            MethodResult::Poll(data) => ("Poll", data).serialize(serializer),
            MethodResult::Cancel(data) => ("Cancel", data).serialize(serializer),
            MethodResult::QuantumClose(data) => ("QuantumClose", data).serialize(serializer),
            MethodResult::WorldActivate(data) => ("WorldActivate", data).serialize(serializer),
            MethodResult::Abort(data) => ("Abort", data).serialize(serializer),
            MethodResult::Retire(data) => ("Retire", data).serialize(serializer),
            MethodResult::BlobBegin(data) => ("BlobBegin", data).serialize(serializer),
            MethodResult::BlobChunk(data) => ("BlobChunk", data).serialize(serializer),
            MethodResult::BlobFinish(data) => ("BlobFinish", data).serialize(serializer),
            MethodResult::Release(data) => ("Release", data).serialize(serializer),
            MethodResult::BeginAccepted(data) => ("BeginAccepted", data).serialize(serializer),
            MethodResult::ExactRun(data) => ("ExactRun", data).serialize(serializer),
            MethodResult::BoundarySettle(data) => ("BoundarySettle", data).serialize(serializer),
            MethodResult::QuantumBegin(data) => ("QuantumBegin", data).serialize(serializer),
            MethodResult::Pause(data) => ("Pause", data).serialize(serializer),
            MethodResult::Capture(data) => ("Capture", data).serialize(serializer),
            MethodResult::PrepareRestore(data) => ("PrepareRestore", data).serialize(serializer),
            MethodResult::Shutdown(data) => ("Shutdown", data).serialize(serializer),
        }
    }
}

impl ExchangeRecord {
    /// Observes actual complete native Blob-proof exchanges for restore admission.
    ///
    /// Other cached decoder families remain unresolved until their full owning
    /// walker is installed. This observes actual current banks, not wire lengths.
    pub(crate) fn observe_owned11_metadata(
        &self,
        observer: &mut crate::retained_metadata::MetadataObserver,
    ) -> Result<(), ProviderError> {
        use crate::bodies::{OperationState, ResponseShape};
        use crate::retained_metadata::aliases::MetadataSharedKind;
        let (actor, bank) = self
            .original_actor
            .as_ref()
            .ok_or(ProviderError::Correlation(
                "restore exchange original actor absent",
            ))?;
        actor.ensure_current()?;
        if self.sent != self.originals.len() || self.original_slots.len() != self.originals.len() {
            return Err(ProviderError::Correlation("restore exchange unresolved"));
        }
        observer.shared_original(MetadataSharedKind::ProtocolOwner, actor.as_ref())?;
        observer.shared_original(MetadataSharedKind::FrameBank, bank.as_ref())?;
        bank.try_borrow()
            .map_err(|_| ProviderError::Conflict("restore exchange literal bank borrowed"))?
            .observe_owned11_metadata(observer)?;
        observer.observe(&self.originals)?;
        observer.observe(&self.canonical)?;
        observer.observe(&self.original_slots)?;
        observer.vector::<ReceivedFrame>(self.acknowledgements.capacity())?;
        for frame in &self.acknowledgements {
            observer.observe(&frame.envelope)?;
            let ReceivedBody::Response(body) = &frame.body else {
                return Err(ProviderError::Correlation(
                    "restore exchange cached request/notification unresolved",
                ));
            };
            observer.boxed_value(body.as_ref())?;
            let ResponseShape::Completed {
                operation_state: OperationState::Completed,
                result,
                extensions,
            } = &body.shape
            else {
                return Err(ProviderError::Correlation(
                    "restore exchange cached noncompleted ACK unresolved",
                ));
            };
            observer.observe(result)?;
            observer.observe(extensions)?;
            match body.result.as_ref() {
                Some(MethodResult::BlobBegin(result)) => observer.observe(&result.transfer_id)?,
                Some(MethodResult::BlobChunk(result)) => observer.observe(&result.transfer_id)?,
                Some(MethodResult::BlobFinish(result)) => {
                    observer.observe(&result.transfer_id)?;
                    observer.observe(&result.content)?;
                }
                _ => {
                    return Err(ProviderError::Correlation(
                        "restore exchange cached family unresolved",
                    ));
                }
            }
        }
        Ok(())
    }
}

impl ExchangeRecord {
    /// Observes the actual complete endpoint record in one shared native quote.
    ///
    /// The current connection must be authenticated before this method. Both
    /// actual retained Rc edges join the same typed identity roster; repeated
    /// frame-bank payloads are visited once. Ordinary wire metadata is unchanged.
    pub(crate) fn observe_unique_capture_metadata<S: ProviderStream>(
        &self,
        connection: &Connection<S>,
        roots: &mut crate::retained_metadata::NativeCaptureMetadataRoots,
        observer: &mut crate::retained_metadata::MetadataObserver,
    ) -> Result<(), ProviderError> {
        use crate::retained_metadata::aliases::MetadataSharedKind;
        let Self {
            originals,
            canonical,
            acknowledgements: _,
            sent,
            original_slots,
            original_actor,
        } = self;
        connection.protocol_owner.ensure_current()?;
        connection.authenticate_native5_source_codec()?;
        let (actor, bank) = original_actor.as_ref().ok_or(ProviderError::Correlation(
            "native Capture record original actor absent",
        ))?;
        actor.ensure_current()?;
        if !Rc::ptr_eq(actor, &connection.protocol_owner)
            || connection
                .original_frames
                .as_ref()
                .is_none_or(|actual| !Rc::ptr_eq(bank, actual))
            || *sent != originals.len()
            || originals.is_empty()
            || original_slots.len() != originals.len()
            || canonical.len() != originals.len()
        {
            return Err(ProviderError::Correlation(
                "native Capture record owner or progress differs",
            ));
        }
        roots.observe_shared(observer, MetadataSharedKind::ProtocolOwner, actor.as_ref())?;
        if roots.observe_shared(observer, MetadataSharedKind::FrameBank, bank.as_ref())? {
            bank.try_borrow()
                .map_err(|_| ProviderError::Conflict("native Capture record frame bank borrowed"))?
                .observe_owned11_metadata(observer)?;
        }
        self.observe_owned12_capture_children(observer)?;
        actor.ensure_current()
    }
}

impl ExchangeRecord {
    // Selected full-class child storage only. Ordinary owned11/None keeps its
    // historical traversal. Actor and frame-bank edges belong to its caller.
    pub(super) fn observe_owned12_capture_children(
        &self,
        observer: &mut crate::retained_metadata::MetadataObserver,
    ) -> Result<(), ProviderError> {
        use crate::bodies::{
            BlobBeginResult, BlobChunkResult, BlobFinishResult, OperationState, ResponseShape,
        };
        let Self {
            originals,
            canonical,
            acknowledgements,
            sent,
            original_slots,
            original_actor: _,
        } = self;
        observer.observe(originals)?;
        observe_original_canonical_byte_banks(canonical, observer)?;
        observer.observe(original_slots)?;
        observer.observe(sent)?;
        observer.vector::<ReceivedFrame>(acknowledgements.capacity())?;
        for frame in acknowledgements {
            let ReceivedFrame { envelope, body } = frame;
            observer.observe(envelope)?;
            let ReceivedBody::Response(body) = body else {
                return Err(ProviderError::Correlation(
                    "native Capture cached request/notification unresolved",
                ));
            };
            observer.boxed_value(body.as_ref())?;
            let ResponseBody { shape, result } = body.as_ref();
            let ResponseShape::Completed {
                operation_state: OperationState::Completed,
                result: raw_result,
                extensions,
            } = shape
            else {
                return Err(ProviderError::Correlation(
                    "native Capture cached proof not completed",
                ));
            };
            observer.observe(raw_result)?;
            observer.observe(extensions)?;
            match result.as_ref() {
                Some(MethodResult::BlobBegin(BlobBeginResult {
                    transfer_id,
                    next_offset,
                    maximum_chunk_bytes,
                })) => {
                    observer.observe(transfer_id)?;
                    observer.observe(next_offset)?;
                    observer.observe(maximum_chunk_bytes)?;
                }
                Some(MethodResult::BlobChunk(BlobChunkResult {
                    transfer_id,
                    next_offset,
                })) => {
                    observer.observe(transfer_id)?;
                    observer.observe(next_offset)?;
                }
                Some(MethodResult::BlobFinish(BlobFinishResult {
                    transfer_id,
                    content,
                })) => {
                    observer.observe(transfer_id)?;
                    observer.observe(content)?;
                }
                _ => {
                    return Err(ProviderError::Correlation(
                        "native Capture cached family unresolved",
                    ));
                }
            }
        }
        Ok(())
    }
}

fn observe_original_canonical_byte_banks(
    banks: &Vec<Vec<u8>>,
    observer: &mut crate::retained_metadata::MetadataObserver,
) -> Result<(), ProviderError> {
    // Primitive bytes have no nested owners. Record every actual allocation
    // and initialized extent once. Integer-array serialization, byte work,
    // physical literal correspondence and cold reconstruction stay unchanged.
    observer.vector::<Vec<u8>>(banks.capacity())?;
    for bytes in banks {
        observer.vector::<u8>(bytes.capacity())?;
        observer.observe(&bytes.len())?;
    }
    Ok(())
}

#[cfg(test)]
// crucible-lint: allow panic-shortcut -- Fixture failures deliberately panic.
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use crucible_node_format::U64;

    #[test]
    fn selected_canonical_bank_metadata_preserves_allocations_without_primitive_visits()
    -> Result<(), ProviderError> {
        let mut banks = Vec::with_capacity(7);
        let mut first = Vec::with_capacity(4096);
        first.extend_from_slice(&[0, 127, 255]);
        banks.push(first);
        banks.push(vec![255; 65_536]);
        let original_bytes =
            serde_json::to_vec(&banks).map_err(crucible_node_format::ContractError::from)?;
        let mut ordinary = crate::retained_metadata::MetadataObserver::new();
        ordinary.observe(&banks)?;
        let ordinary = ordinary.finish();
        let mut selected = crate::retained_metadata::MetadataObserver::new();
        observe_original_canonical_byte_banks(&banks, &mut selected)?;
        let selected = selected.finish();

        assert_eq!(selected.capacity_records, ordinary.capacity_records);
        assert_eq!(
            selected.vector_capacity_bytes,
            ordinary.vector_capacity_bytes
        );
        assert_eq!(selected.observed_nodes, banks.len());
        assert_eq!(
            ordinary.observed_nodes,
            selected.observed_nodes + 1 + banks.iter().map(Vec::len).sum::<usize>()
        );
        assert_eq!(
            serde_json::to_vec(&banks).map_err(crucible_node_format::ContractError::from)?,
            original_bytes
        );
        assert_eq!(banks.capacity(), 7);
        assert_eq!(banks[0].capacity(), 4096);
        Ok(())
    }

    #[test]
    fn native5_original_exchange_view_preserves_slots_capacities_and_decoded_refusal() {
        let mut originals = Vec::with_capacity(3);
        let mut canonical = Vec::with_capacity(5);
        let mut acknowledgements = Vec::with_capacity(7);
        let mut slots = Vec::with_capacity(9);
        let mut request = crate::envelope::tests::request();
        request.method = Method::BlobFinish;
        request.body = serde_json::from_value(
            serde_json::json!({"transfer_id":"original-transfer","extensions":{}}),
        )
        .unwrap();
        originals.push(request.clone());
        let mut planned = Vec::with_capacity(64);
        planned.extend_from_slice(b"actual-planned-original");
        canonical.push(planned);
        slots.push(Some(13));
        let mut reply = request;
        reply.message = MessageKind::Response;
        reply.sequence = U64::new(9);
        reply.body = serde_json::from_value(serde_json::json!({
            "status":"error","operation_state":"not_started",
            "error":{"code":"UNSUPPORTED_FEATURE","message":"original refusal","retryable":false,"effect":"not_started","details":{}},
            "extensions":{}
        })).unwrap();
        let shape = crate::bodies::decode_response_shape(&reply.body).unwrap();
        acknowledgements.push(ReceivedFrame {
            envelope: reply,
            body: ReceivedBody::Response(Box::new(ResponseBody {
                shape,
                result: None,
            })),
        });
        let record = ExchangeRecord {
            originals,
            canonical,
            acknowledgements,
            sent: 1,
            original_slots: slots,
            original_actor: None,
        };

        let data = serde_json::to_value(record.original_protocol_view()).unwrap();
        assert_eq!(data["originals_capacity"], 3);
        assert_eq!(data["canonical_capacity"], 5);
        assert_eq!(data["canonical"][0][1], 64);
        assert_eq!(data["acknowledgements_capacity"], 7);
        assert_eq!(data["original_slots_capacity"], 9);
        assert_eq!(data["original_slots"][0], 13);
        assert_eq!(data["sent"], 1);
        assert_eq!(data["acknowledgements"][0][0]["sequence"], "9");
        assert_eq!(data["acknowledgements"][0][1][0], "Response");
        assert_eq!(
            data["acknowledgements"][0][1][1]["error"]["message"],
            "original refusal"
        );
        assert!(data["acknowledgements"][0][1][2].is_null());
        assert_eq!(record.original_slots, [Some(13)]);
        assert_eq!(record.canonical[0], b"actual-planned-original");
    }
}

#[path = "exchange_snapshot/settled_record17.rs"]
mod settled_record17;
pub(crate) use settled_record17::HistoricalExchangeRecord17;

#[path = "exchange_snapshot/settled17.rs"]
pub(crate) mod settled17;

impl ReceivedFrame {
    /// Borrows raw envelope and independent typed cache as retained history.
    pub(crate) fn borrowed_settled17_data(&self) -> impl Serialize + '_ {
        (&self.envelope, DecodedBodyView(&self.body))
    }
}
impl ReceivedFrame {
    /// Names the actual existing raw/typed borrowed serializer controls.
    pub(crate) fn borrowed_settled17_counter_scratch_data() -> usize {
        std::mem::size_of::<(&Envelope, DecodedBodyView<'static>)>()
            + std::mem::size_of::<RequestView<'static>>()
            + std::mem::size_of::<MethodResultView<'static>>()
            + std::mem::size_of::<Option<MethodResultView<'static>>>()
            + std::mem::size_of::<&crate::bodies::NotificationBody>()
            + std::mem::size_of::<&crate::bodies::ResponseShape>()
    }
}
