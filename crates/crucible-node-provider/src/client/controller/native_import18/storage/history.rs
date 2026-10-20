//! Lends the actual retained SDK18 assignment row as passive historical DATA.
//!
//! Private construction and a nonescaping callback preserve actual row custody.
//! Full frontier, request correspondence hash and all requested axes remain
//! observable even for a failed handoff. No row, Rc, authenticator, live Session
//! or assignment method is exposed through this view.

use super::*;

/// Borrows complete modeled row fields without exposing the operational row.
pub struct OriginalNativeImport18AssignmentRowHistoryData<'a> {
    _row: &'a OriginalNativeImport18AssignmentStorageData,
    // Retain the same original constructor population with this historical view.
    // This private loan exposes no mutable profile or reusable observation grant.
    _json_profile: &'a NativeImport18JsonMetadataProfileData,
    /// Borrows the exact actual phase without completing or authorizing it.
    pub phase: &'a PacketNativeImport18Phase,
    /// Borrows the complete actual stored frontier, including allocation facts.
    ///
    /// These eleven scalar facts confer no Session currentness or new credit.
    pub frontier: &'a OriginalProtocolStorageFacts,
    /// Borrows the exact request/normalization/backend correspondence digest.
    pub identity: &'a [u8; 32],
    /// Borrows the actual independently quoted retained-growth axis.
    pub retained: &'a usize,
    /// Borrows the actual independently quoted temporary axis.
    pub transient: &'a usize,
    /// Borrows the actual defining fixed-control axis.
    pub scratch: &'a usize,
    /// Borrows the actual original frame-byte bound used by this row.
    pub maximum_frame: &'a usize,
    /// Records only the actual Rc relation to the supplied bank's capsule.
    ///
    /// None preserves an absent capsule; false preserves a mismatched failed
    /// handoff. This DATA relation is not a Controller identity or permission.
    pub controller_matches_capsule: Option<bool>,
}

impl OriginalNativeImport18AssignmentStorageData {
    /// Lends full actual row facts through an origin-guarded callback.
    ///
    /// The caller supplies only its actual optional same-bank capsule and owns
    /// any output banks separately. A missing or different capsule does not
    /// hide the row: its actual relation is retained as None or Some(false).
    /// No selection, quota, phase authenticator, schema, hash or allocation runs.
    /// Process/thread origin is checked on both callback outcomes. No live Rc,
    /// thread token, row method or reference to the operational row escapes.
    ///
    /// # Errors
    /// Refuses foreign row/capsule creator origin or propagates the callback
    /// error after both actual origin postguards have run.
    pub fn with_row_history_data<R>(
        &self,
        capsule: Option<&OriginalNativeImport18Assignment>,
        inspect: impl for<'view> FnOnce(
            OriginalNativeImport18AssignmentRowHistoryData<'view>,
        ) -> Result<R, ProviderError>,
    ) -> Result<R, ProviderError> {
        self.controller.ensure_current()?;
        if let Some(capsule) = capsule {
            capsule.controller.ensure_current()?;
        }
        let Self {
            controller,
            frontier,
            phase,
            identity,
            retained,
            transient,
            scratch,
            maximum_frame,
            json_profile,
        } = self;
        let controller_matches_capsule =
            capsule.map(|capsule| Rc::ptr_eq(controller, &capsule.controller));
        let result = inspect(OriginalNativeImport18AssignmentRowHistoryData {
            _row: self,
            _json_profile: json_profile,
            phase,
            frontier,
            identity: identity.as_bytes(),
            retained,
            transient,
            scratch,
            maximum_frame,
            controller_matches_capsule,
        });
        self.controller.ensure_current()?;
        if let Some(capsule) = capsule {
            capsule.controller.ensure_current()?;
        }
        result
    }

    /// Names direct row/view/origin/relation/result controls before borrowing.
    ///
    /// The caller separately owns its callback capture and prepared output
    /// banks. No metadata traversal or operational phase row is supplied here.
    pub fn row_history_counter_scratch_data<R>() -> usize {
        size_of::<OriginalNativeImport18AssignmentRowHistoryData<'static>>()
            + size_of::<&OriginalNativeImport18AssignmentStorageData>()
            + size_of::<&NativeImport18JsonMetadataProfileData>()
            + size_of::<Option<&OriginalNativeImport18Assignment>>()
            + size_of::<&OriginalNativeImport18Assignment>()
            + size_of::<&Rc<ProtocolCaptureOwner>>() * 2
            + size_of::<&ProtocolCaptureOwner>()
            + size_of::<&OriginalProtocolStorageFacts>()
            + size_of::<&PacketNativeImport18Phase>()
            + size_of::<&blake3::Hash>()
            + size_of::<&[u8; 32]>()
            // The actual exhaustive row destructure binds all four axes/bounds.
            + size_of::<&usize>() * 4
            + size_of::<Option<bool>>()
            + size_of::<bool>()
            + size_of::<std::thread::Thread>()
            + size_of::<std::thread::ThreadId>()
            + size_of::<&std::thread::ThreadId>()
            + size_of::<u32>()
            + size_of::<&u32>()
            + size_of::<R>()
            + size_of::<Result<R, ProviderError>>()
            + size_of::<Result<(), ProviderError>>()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn absent_capsule_and_callback_error_keep_the_actual_row_correspondence() {
        use crate::retained_metadata::serialization_storage::actual_serialization_storage_data;

        let actual = serde_json::json!({"same_original": [1, 2, {"retained": "population"}]});
        let mut observer = MetadataObserver::new();
        observer.observe(&actual).unwrap();
        let facts = observer.finish();
        let serialized = actual_serialization_storage_data(&actual, facts, usize::MAX).unwrap();
        let json_profile = NativeImport18JsonMetadataProfileData::assignment_data(
            facts.observed_nodes,
            serialized.serialized_value_nodes,
            serialized.serialized_capacity_records,
        )
        .unwrap();
        assert!(json_profile.has_constructed_population_data());

        let row = OriginalNativeImport18AssignmentStorageData {
            controller: Rc::new(ProtocolCaptureOwner::new()),
            frontier: OriginalProtocolStorageFacts {
                maximum_frame_bytes: 100,
                maximum_history_bytes: 200,
                maximum_frames_per_direction: 3,
                byte_capacity: 300,
                descriptor_capacity: 4,
                descriptor_bytes: 400,
                allocated_bytes: 700,
                retained_bytes: 90,
                incoming_frames: 1,
                outgoing_frames: 2,
                all_io_complete: false,
            },
            phase: PacketNativeImport18Phase::Prepare,
            identity: blake3::hash(b"retained failed row"),
            retained: 11,
            transient: 22,
            scratch: 33,
            maximum_frame: 44,
            json_profile,
        };
        let before = *row.identity.as_bytes();

        let result: Result<(), ProviderError> = row.with_row_history_data(None, |data| {
            assert!(data.controller_matches_capsule.is_none());
            assert!(std::ptr::eq(data.frontier, &row.frontier));
            assert!(std::ptr::eq(data._json_profile, &row.json_profile));
            assert_eq!(
                data._json_profile.maximum_work_data().unwrap(),
                json_profile.maximum_work_data().unwrap()
            );
            assert_eq!(data.identity, &before);
            assert_eq!(data.frontier.allocated_bytes, 700);
            assert!(!data.frontier.all_io_complete);
            assert_eq!(
                (
                    *data.retained,
                    *data.transient,
                    *data.scratch,
                    *data.maximum_frame
                ),
                (11, 22, 33, 44)
            );
            Err(ProviderError::Frame("retain callback refusal"))
        });

        assert!(result.is_err());
        assert_eq!(row.identity.as_bytes(), &before);
        assert_eq!(row.retained, 11);

        let observed_work = row.with_row_history_data(None, |data| {
            assert!(std::ptr::eq(data._json_profile, &row.json_profile));
            data._json_profile.maximum_work_data()
        }).unwrap();
        assert_eq!(observed_work, json_profile.maximum_work_data().unwrap());
    }
}
