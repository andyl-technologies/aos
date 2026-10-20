//! Observes actual SDK18 response partials without a fabricated received frame.
//!
//! This delegates the existing exhaustive ReceivedFrame response branch. An
//! Accepted Begin response may be retained before the SDK's Completed guard
//! refuses it; every actual raw/typed field still belongs to that failed owner.
//! Observation alone certifies no receipt, completion or protocol permission.

use super::*;
use crucible_node_contract::Id;

impl ResponseBody {
    /// Observes independently owned shape and typed result backing as DATA.
    ///
    /// # Errors
    /// Refuses checked layout overflow or the actual observer's traversal bound.
    pub(crate) fn observe_native_import18_metadata_data(
        &self,
        observer: &mut MetadataObserver<'_>,
    ) -> Result<(), ProviderError> {
        let Self { shape, result } = self;
        ResponseShape::observe_output_data(shape, observer)?;
        if let Some(result) = result {
            observe_result(result, observer)?;
        }
        Ok(())
    }

    /// Names the actual borrowed controls of this shared response-only walk.
    pub(crate) fn native_import18_metadata_counter_scratch_data() -> usize {
        ReceivedFrame::native_import17_upload_counter_scratch_data()
            + size_of::<(&Self, &ResponseShape, &Option<MethodResult>)>()
            + size_of::<&MethodResult>()
            + size_of::<Option<&MethodResult>>()
            + size_of::<&BeginAccepted>()
            + size_of::<(&Id, &BeginKind)>()
            + size_of::<&BeginKind>()
            + size_of::<&mut MetadataObserver<'static>>()
            + size_of::<Result<(), ProviderError>>()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::Value;

    #[test]
    fn refused_accepted_prepare_keeps_both_raw_and_typed_result_backing() {
        let mut raw = String::with_capacity(227);
        raw.push_str("actual retained raw registration result");
        let raw_capacity = raw.capacity();
        let mut result = serde_json::Map::new();
        result.insert("partial".into(), Value::String(raw));
        let mut id = String::with_capacity(173);
        id.push_str("retained/accepted-operation");
        let id = crucible_node_contract::Id::new(id).unwrap();
        let id_capacity = id.allocated_capacity();
        let body = ResponseBody {
            shape: ResponseShape::Accepted {
                operation_state: OperationState::Running,
                result,
                extensions: Default::default(),
            },
            result: Some(MethodResult::BeginAccepted(BeginAccepted {
                operation_id: id,
                kind: BeginKind::PrepareRestore,
            })),
        };
        let mut observer = MetadataObserver::new();

        body.observe_native_import18_metadata_data(&mut observer)
            .unwrap();
        let facts = observer.finish();

        assert!(facts.string_capacity_bytes >= raw_capacity + id_capacity);
        assert!(matches!(&body.shape, ResponseShape::Accepted { .. }));
        assert!(matches!(&body.result, Some(MethodResult::BeginAccepted(_))));
    }
}
