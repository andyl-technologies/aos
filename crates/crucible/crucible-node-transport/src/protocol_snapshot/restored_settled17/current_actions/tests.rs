//! Checks reconstruction boundaries against the actual raw-first action writer.

use super::*;
use crate::{
    envelope::{Method, Nullable},
    protocol_snapshot::owned11::json_value::HistoricalJsonLimits,
    reference_packet::service::{
        native_startup::NativeRestoredSettledActionAttempt,
        restored_settled_capture::RESTORED_SETTLED_CAPTURE_FEATURE,
    },
    retained_metadata::{
        MetadataObserver,
        records::{MetadataRecordBank, ValidatedMetadataRecords},
    },
};
use crucible_node_format::Id;

fn original_capture(method: Method) -> Result<Envelope, Box<dyn std::error::Error>> {
    let mut original = crate::envelope::tests::request();
    original.method = method;
    original.node_id = Nullable(Some(Id::new("current-action-node")?));
    original.operation_id = Nullable(None);
    original.execution_owner_id = Nullable(None);
    original.capture_owner_id = Nullable(Some(Id::new("current-action-capture")?));
    original.extensions.clear();
    let feature = if method == Method::Begin {
        RESTORED_SETTLED_CAPTURE_FEATURE
    } else {
        RESTORED_SETTLED_CAPTURE_UPLOAD_FEATURE
    };
    original.extensions.insert(feature.into(), Value::Null);
    Ok(original)
}

fn limits() -> HistoricalJsonLimits {
    HistoricalJsonLimits {
        maximum_input_bytes: 65_536,
        maximum_nodes: 8192,
        maximum_depth: 32,
        maximum_owned_backing_bytes: 2 * 1024 * 1024,
        maximum_tree_entries: 8192,
    }
}

fn recorded(
    attempt: &NativeRestoredSettledActionAttempt,
) -> Result<(Vec<u8>, Vec<u8>), Box<dyn std::error::Error>> {
    let input = serde_json::to_vec(attempt)?;
    let mut rows = MetadataRecordBank::reserve(8192)?;
    let mut observer = MetadataObserver::recording(&mut rows);
    attempt.observe_settled_history_metadata_data(&mut observer)?;
    observer.finish();
    Ok((input, serde_json::to_vec(&rows)?))
}

#[test]
fn actual_input_raw_and_failed_prefixes_reconstruct_with_complete_metadata()
-> Result<(), Box<dyn std::error::Error>> {
    // Preserve the accepted raw roster while making a typed field fail. The
    // fixture's proof is DATA here; no Source authentication is performed.
    let mut raw =
        crate::reference_packet::service::restored_input_reactive17::tests::sealed_fixture(
            &[73; 32],
        )?;
    raw.body
        .insert("owner_generation".into(), Value::Bool(false));
    let mut attempt = NativeRestoredSettledActionAttempt::new_data(7);
    attempt.retain_original_data(raw.clone())?;

    for failed in [false, true] {
        if failed {
            assert!(attempt.decode_body_data(65_536).is_err());
        }
        let (input, rows) = recorded(&attempt)?;
        let records = ValidatedMetadataRecords::validate(&rows, 8192, 2 * 1024 * 1024)?;
        let mut borrowed = Ledger::new(records.rows(), limits());
        assert!(
            borrowed
                .read::<HistoricalRestoredAction17>(&input, false)?
                .is_none()
        );
        assert!(borrowed.rows.next().is_none());

        let mut owning = Ledger::new(records.rows(), limits());
        let restored = owning
            .read::<HistoricalRestoredAction17>(&input, true)?
            .ok_or_else(invalid)?;
        let selected = restored.selected.ok_or_else(invalid)?;

        assert_eq!(restored.ordinal, 7);
        assert!(restored.original.is_none());
        assert!(!restored.decoded);
        assert_eq!(restored.failed, failed);
        assert_eq!(selected.input_reactive.ordinal, 7);
        assert_eq!(selected.input_reactive.original.as_ref(), Some(&raw));
        assert!(selected.input_reactive.body.is_none());
        assert!(selected.input_reactive.arguments.is_none());
        assert!(selected.input_reactive.artifact.is_none());
        assert!(selected.input_reactive.context.is_none());
        assert!(selected.input_reactive.checkpoint.is_none());
        assert!(selected.input_reactive.terminal.is_none());
        assert!(selected.input_reactive.prepared_reply.is_none());
        assert!(selected.input_reactive.observation.is_none());
        assert!(matches!(
            (selected.input_reactive.stage, failed),
            (CurrentAttemptStage17::Raw, false) | (CurrentAttemptStage17::Failed, true)
        ));
        assert!(owning.rows.next().is_none());
    }
    Ok(())
}

#[test]
fn actual_capture_and_upload_prefixes_preserve_existing_reader_restrictions()
-> Result<(), Box<dyn std::error::Error>> {
    for method in [
        Method::Begin,
        Method::BlobBegin,
        Method::BlobChunk,
        Method::BlobFinish,
    ] {
        let raw = original_capture(method)?;
        let mut attempt = NativeRestoredSettledActionAttempt::new_data(11);
        attempt.retain_original_data(raw.clone())?;

        for failed in [false, true] {
            if failed {
                assert!(attempt.decode_body_data(65_536).is_err());
            }
            assert_eq!(attempt.original_data()?, &raw);
            let (input, rows) = recorded(&attempt)?;
            let records = ValidatedMetadataRecords::validate(&rows, 8192, 2 * 1024 * 1024)?;
            let mut borrowed = Ledger::new(records.rows(), limits());
            let validated = borrowed.read::<HistoricalRestoredAction17>(&input, false);
            if method == Method::Begin {
                // The ordinary Capture writer has fifteen fields. It does not
                // satisfy the separate current-Capture reader's seventeen-field
                // grammar, even before reconstructing owners. Keep that refusal.
                assert!(validated.is_err());
            } else {
                assert!(validated?.is_none());
                assert!(borrowed.rows.next().is_none());
            }

            let mut owning = Ledger::new(records.rows(), limits());
            assert!(
                owning
                    .read::<HistoricalRestoredAction17>(&input, true)
                    .is_err()
            );
        }
    }
    Ok(())
}
