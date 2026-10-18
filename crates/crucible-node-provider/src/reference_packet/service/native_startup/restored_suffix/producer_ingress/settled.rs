//! Serializes every actual recurring request partial without reopening its scope.

use super::*;
use serde::ser::SerializeStruct;
use serde::{Serialize, Serializer};

impl NativeRestoredProducerAttempt {
    pub(crate) fn borrowed_settled_history_data(&self) -> impl Serialize + '_ {
        History(self)
    }
}

struct History<'a>(&'a NativeRestoredProducerAttempt);
impl Serialize for History<'_> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let NativeRestoredProducerAttempt {
            ordinal,
            original,
            body,
            arguments,
            terminal,
            prepared_reply,
            stage,
        } = self.0;
        let mut state = serializer.serialize_struct("NativeSuffixHistory", 8)?;
        state.serialize_field(
            "schema",
            "source-private.native-restored-producer-attempt/1",
        )?;
        state.serialize_field("ordinal", ordinal)?;
        state.serialize_field("original", original)?;
        state.serialize_field("body", &body.as_ref().map(BodyView))?;
        state.serialize_field("arguments", arguments)?;
        state.serialize_field("terminal", terminal)?;
        state.serialize_field("prepared_reply", prepared_reply)?;
        state.serialize_field(
            "stage",
            &match stage {
                Stage::Receiving => "receiving",
                Stage::Raw => "raw",
                Stage::Typed => "typed",
                Stage::Dispatched => "dispatched",
                Stage::Published => "published",
                Stage::Failed => "failed",
            },
        )?;
        state.end()
    }
}

struct BodyView<'a>(&'a Body);
impl Serialize for BodyView<'_> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        match self.0 {
            Body::Begin(value) => {
                serializer.serialize_newtype_variant("NativeProducerBody", 0, "begin", value)
            }
            Body::Poll(value) => {
                serializer.serialize_newtype_variant("NativeProducerBody", 1, "poll", value)
            }
            Body::Retire(value) => {
                serializer.serialize_newtype_variant("NativeProducerBody", 2, "retire", value)
            }
            Body::Observe(value) => {
                serializer.serialize_newtype_variant("NativeProducerBody", 3, "observe", value)
            }
            Body::BlobBegin(value) => {
                serializer.serialize_newtype_variant("NativeProducerBody", 4, "blob_begin", value)
            }
            Body::BlobChunk(value) => {
                serializer.serialize_newtype_variant("NativeProducerBody", 5, "blob_chunk", value)
            }
            Body::BlobFinish(value) => {
                serializer.serialize_newtype_variant("NativeProducerBody", 6, "blob_finish", value)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejected_partial_writer_keeps_raw_typed_body_and_failed_stage() {
        let mut raw = crate::envelope::tests::request();
        raw.method = crate::envelope::Method::BlobChunk;
        raw.capture_owner_id = crate::envelope::Nullable(None);
        raw.operation_id = crate::envelope::Nullable(None);
        raw.body =
            serde_json::json!({"transfer_id":"partial", "offset":"0", "bytes":"", "extensions":{}})
                .as_object()
                .unwrap()
                .clone();
        raw.extensions.clear();
        let mut actual = NativeRestoredProducerAttempt::new_data(2);
        actual.retain_original_data(raw.clone()).unwrap();
        assert!(actual.decode_body_data(65_536).is_err());
        let bytes = crucible_node_contract::canonical::canonical_json(
            &serde_json::to_value(actual.borrowed_settled_history_data()).unwrap(),
        )
        .unwrap();
        let value: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(value["stage"], "failed");
        assert_eq!(value["ordinal"], 2);
        assert_eq!(value["original"], serde_json::to_value(raw).unwrap());
        assert!(value["body"]["blob_chunk"].is_object());
        assert!(value["terminal"].is_null());
        assert!(actual.begin_dispatch_data().is_err());
    }
}

impl NativeRestoredProducerAttempt {
    pub(crate) fn settled_history_counter_scratch_data() -> usize {
        use std::mem::size_of;
        size_of::<History<'static>>()
            + size_of::<BodyView<'static>>()
            + size_of::<Option<BodyView<'static>>>()
    }
}

impl NativeRestoredProducerAttempt {
    /// Appends the selected17 emitted field order without resetting aggregate banks.
    ///
    /// # Errors
    /// Refuses finite metadata exhaustion or checked backing-layout overflow.
    pub(crate) fn observe_current_settled17_metadata_data(
        &self,
        observer: &mut crate::retained_metadata::MetadataObserver<'_>,
    ) -> Result<(), ProviderError> {
        use crate::protocol_snapshot::restored_settled17::current_contracts::CurrentContract17;

        let Self {
            ordinal,
            original,
            body,
            arguments,
            terminal,
            prepared_reply,
            stage: _,
        } = self;
        observer.observe(ordinal)?;
        observer.observe(original)?;
        if let Some(body) = body {
            match body {
                Body::Begin(value) => value.observe_current(observer)?,
                Body::Poll(value) => value.observe_current(observer)?,
                Body::Retire(value) => value.observe_current(observer)?,
                Body::Observe(value) => value.observe_current(observer)?,
                Body::BlobBegin(value) => value.observe_current(observer)?,
                Body::BlobChunk(value) => value.observe_current(observer)?,
                Body::BlobFinish(value) => value.observe_current(observer)?,
            }
        }
        if let Some(arguments) = arguments {
            arguments.observe_current(observer)?;
        }
        observer.observe(terminal)?;
        observer.observe(prepared_reply)
    }
}
