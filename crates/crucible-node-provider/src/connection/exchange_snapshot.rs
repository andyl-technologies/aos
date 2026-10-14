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

#[cfg(test)]
// crucible-lint: allow panic-shortcut -- Fixture failures deliberately panic.
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use crucible_node_contract::U64;

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
