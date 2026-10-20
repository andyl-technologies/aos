//! Borrows every actual restoration stage field without creating a native permit.

use super::super::settled::StageHistory;
use super::*;
use crate::protocol_snapshot::compact_bytes::BorrowedCompactBytes;
use serde::Serializer;
use serde::ser::SerializeStruct;

impl StageHistory for NativeRestorationUploadAttempt {
    fn write_history<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        self.ensure_origin().map_err(serde::ser::Error::custom)?;
        let NativeRestorationUploadAttempt {
            creator,
            thread,
            ordinal,
            original,
            artifact,
            context,
            pending,
            terminal,
            seen,
            bytes,
            content_attempted,
            next_offset,
            published_requests,
            verified,
            begun,
            complete,
            next_progress,
        } = self;
        let mut state = serializer.serialize_struct("NativeRestorationStageHistory", 20)?;
        state.serialize_field(
            "schema",
            "source-private.native-restoration-upload-history/1",
        )?;
        state.serialize_field("creator", creator)?;
        let _ = thread;
        state.serialize_field("thread", "same-original-thread-history-only")?;
        state.serialize_field("ordinal", ordinal)?;
        state.serialize_field("original", original)?;
        state.serialize_field("artifact", artifact)?;
        state.serialize_field("context", context)?;
        state.serialize_field("pending", pending)?;
        state.serialize_field("terminal", terminal)?;
        state.serialize_field("seen", seen)?;
        state.serialize_field("seen_capacity", &seen.capacity())?;
        state.serialize_field("bytes", &BorrowedCompactBytes::new(bytes))?;
        state.serialize_field("bytes_capacity", &bytes.capacity())?;
        state.serialize_field("content_attempted", content_attempted)?;
        state.serialize_field("next_offset", next_offset)?;
        state.serialize_field("published_requests", published_requests)?;
        state.serialize_field("verified", verified)?;
        state.serialize_field("begun", begun)?;
        state.serialize_field("complete", complete)?;
        state.serialize_field("next_progress", next_progress)?;
        state.end()
    }
}

#[cfg(test)]
mod tests {
    use super::super::super::settled::StageOwner;
    use super::*;

    #[test]
    fn actual_partial_upload_writer_preserves_failed_bytes_and_spare_capacity() {
        let mut bytes = Vec::with_capacity(37);
        bytes.extend_from_slice(b"unverified");
        let mut seen = Vec::with_capacity(3);
        seen.push(Id::new("failed-upload").unwrap());
        let attempt = NativeRestorationUploadAttempt {
            creator: std::process::id(),
            thread: std::thread::current().id(),
            ordinal: 1,
            original: None,
            artifact: None,
            context: None,
            pending: None,
            terminal: None,
            seen,
            bytes,
            content_attempted: true,
            next_offset: 2,
            published_requests: 0,
            verified: false,
            begun: false,
            complete: false,
            next_progress: None,
        };
        let value = serde_json::to_value(StageOwner(&attempt)).unwrap();
        assert_eq!(value["seen_capacity"], attempt.seen.capacity());
        assert_eq!(value["bytes_capacity"], attempt.bytes.capacity());
        assert_eq!(value["next_offset"], 2);
        assert_eq!(value["content_attempted"], true);
        assert_eq!(value["verified"], false);
        assert_eq!(value["seen"][0], "failed-upload");
        assert_eq!(
            value["bytes"],
            serde_json::to_value(BorrowedCompactBytes::new(&attempt.bytes)).unwrap()
        );
    }
}

impl NativeRestorationUploadAttempt {
    pub(super) fn observe_settled_history_metadata_data(
        &self,
        observer: &mut MetadataObserver<'_>,
    ) -> Result<(), ProviderError> {
        self.ensure_origin()?;
        let NativeRestorationUploadAttempt {
            creator,
            thread: _,
            ordinal,
            original,
            artifact,
            context,
            pending,
            terminal,
            seen,
            bytes,
            content_attempted,
            next_offset,
            published_requests,
            verified,
            begun,
            complete,
            next_progress,
        } = self;
        observer.observe(creator)?;
        observer.observe(ordinal)?;
        observer.observe(original)?;
        if let Some(artifact) = artifact {
            artifact.observe_owned_metadata_data(observer)?;
        }
        if let Some(context) = context {
            context.observe_owned_metadata_data(observer)?;
        }
        observer.observe(pending)?;
        observer.observe(terminal)?;
        observer.observe(seen)?;
        observer.observe(bytes)?;
        observer.observe(content_attempted)?;
        observer.observe(next_offset)?;
        observer.observe(published_requests)?;
        observer.observe(verified)?;
        observer.observe(begun)?;
        observer.observe(complete)?;
        if let Some((offset, complete)) = next_progress {
            observer.observe(offset)?;
            observer.observe(complete)?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod alias_roundtrip_tests {
    use super::super::super::settled::Stages;
    use super::*;
    use crate::protocol_snapshot::native_restoration_stage_history::NativeRestorationStagesDecodePlan;
    use crate::retained_metadata::{
        MetadataObserver,
        aliases::{MetadataAliasBank, MetadataSharedKind},
        records::MetadataRecordBank,
    };

    #[test]
    fn actual_nonempty_failed_upload_writer_roundtrips_its_capacity_and_alias_rows() {
        let mut bytes = Vec::with_capacity(37);
        bytes.extend_from_slice(b"unverified failed chunk");
        let mut seen = Vec::with_capacity(3);
        seen.push(Id::new("failed-real-upload-id").unwrap());
        let attempt = Rc::new(RefCell::new(NativeRestorationUploadAttempt {
            creator: std::process::id(),
            thread: std::thread::current().id(),
            ordinal: 1,
            original: None,
            artifact: None,
            context: None,
            pending: None,
            terminal: None,
            seen,
            bytes,
            content_attempted: true,
            next_offset: 2,
            published_requests: 0,
            verified: false,
            begun: false,
            complete: false,
            next_progress: None,
        }));
        let mut records = MetadataRecordBank::reserve(128).unwrap();
        let mut aliases = MetadataAliasBank::reserve(8).unwrap();
        let mut observer = MetadataObserver::recording_with_aliases(&mut records, &mut aliases);
        observer
            .shared_original(
                MetadataSharedKind::NativeRestorationUploadAttempt,
                attempt.as_ref(),
            )
            .unwrap();
        attempt
            .borrow()
            .observe_settled_history_metadata_data(&mut observer)
            .unwrap();
        let _ = observer.finish();
        let activation = [None, None];
        let uploads = [None, Some(attempt)];
        let first_observation = None;
        let writer = Stages {
            creator: std::process::id(),
            thread: std::thread::current().id(),
            activation: &activation,
            uploads: &uploads,
            first_observation: &first_observation,
            capacities: &records,
            aliases: &aliases,
        };
        let value = serde_json::to_value(writer).unwrap();
        assert_eq!(
            value["aliases"],
            serde_json::json!([["native-restoration-upload-attempt", 0]])
        );
        assert!(!records.rows().is_empty());
        let bytes = crucible_node_format::canonical::canonical_json(&value).unwrap();
        let plan =
            NativeRestorationStagesDecodePlan::validate(&bytes, bytes.len(), usize::MAX).unwrap();
        let mut historical = None;
        plan.reconstruct_into(plan.demand_data(), &mut historical)
            .unwrap();
        let owner = historical.as_ref().unwrap();
        owner.authenticate_data().unwrap();
        assert_eq!(owner.original_bytes_data(), bytes);

        let mut changed = value;
        changed["aliases"][0][0] = serde_json::Value::String("native-boot".into());
        let bytes = crucible_node_format::canonical::canonical_json(&changed).unwrap();
        let plan =
            NativeRestorationStagesDecodePlan::validate(&bytes, bytes.len(), usize::MAX).unwrap();
        let mut refused = None;
        assert!(
            plan.reconstruct_into(plan.demand_data(), &mut refused)
                .is_err()
        );
        assert!(refused.is_some());
    }
}
