//! Distinguishes strict framing/reference DATA from complete live capture proof.

// These inert format controls deliberately panic on broken static fixtures.
#![allow(clippy::unwrap_used)]

use super::*;
use serde_json::json;

#[test]
fn framing_never_turns_incomplete_components_into_valid_settlement() {
    let mut value = json!({"schema":RESTORED_SETTLED_JOURNAL17_SCHEMA,"ancestry":{},"objects":{},"history_cut":{},
        "capture_request":{},"capture_terminal":{},"confirmation_request":{},"confirmation_terminal":{}});
    let original = canonical::canonical_json(&value).unwrap();

    PacketRestoredSettledJournal17Plan::validate(&original, original.len()).unwrap();
    assert!(validate_restored_settled_journal17_logical_data(&value).is_err());
    assert!(PacketRestoredSettledJournal17Plan::validate(&original, original.len() - 1).is_err());
    value["schema"] = json!("source-owned.packet-native-settled-journal/12");
    let old = canonical::canonical_json(&value).unwrap();
    assert!(PacketRestoredSettledJournal17Plan::validate(&old, old.len()).is_err());
    value["schema"] = json!(RESTORED_SETTLED_JOURNAL17_SCHEMA);
    value["unknown"] = json!(null);
    let extra = canonical::canonical_json(&value).unwrap();
    assert!(PacketRestoredSettledJournal17Plan::validate(&extra, extra.len()).is_err());
}

fn reference(label: &str, media: &str) -> ContentRef {
    canonical::content_ref(label.as_bytes(), media).unwrap()
}

#[test]
fn exact_runtime_index_and_semantic_media_are_independent_reference_axes() {
    let mut ancestry = PacketRestoredSettledAncestry17 {
        parent_archive_index: reference("index", INDEX3_MEDIA),
        parent_manifest: reference("manifest", "application/json"),
        first_semantic: reference("semantic-old", "application/json"),
        first_journal: reference("journal-old", "application/json"),
        first_observation: reference("observe-first", "application/json"),
        restoration_commit: reference("commit", "application/json"),
        restoration_hold: reference("hold", "application/json"),
    };
    let mut objects = PacketRestoredSettledJournal17Objects {
        snapshot: reference("snapshot", "application/json"),
        before: reference("before", "application/json"),
        control: reference("control", "application/json"),
        anchor: reference("anchor", "application/json"),
        after: reference("after", "application/json"),
        host_protocol: reference("host", "application/json"),
        semantic: reference("semantic", RESTORED_SETTLED_SEMANTIC17_MEDIA),
        coordinator_checkpoint: canonical::content_ref(
            b"checkpoint",
            crate::reference_packet::service::complete_restore::settled_recapture::COORDINATOR_CHECKPOINT17_MEDIA
        ).unwrap(),
        runtime_object: reference("runtime", RUNTIME7_MEDIA)
    };

    ancestry.validate_data().unwrap();
    objects.validate_data().unwrap();
    ancestry.parent_archive_index.media_type = "application/json".into();
    assert!(ancestry.validate_data().is_err());
    objects.runtime_object.media_type = "application/json".into();
    assert!(objects.validate_data().is_err());
    objects.runtime_object.media_type = RUNTIME7_MEDIA.into();
    objects.semantic.media_type = "application/json".into();
    assert!(objects.validate_data().is_err());
}

#[test]
fn semantic_framing_keeps_child_validation_a_separate_required_stage() {
    let mut value = json!({"ancestry":{},"node":{"schema":"source-owned.packet-restored-node-history/17"},
        "schema":"source-private.semantic-state-restored-settled/17","source":{"schema":"source-private.source-restored-settled-state/17"}});
    let bytes = canonical::canonical_json(&value).unwrap();
    let plan = PacketRestoredSettledSemantic17Plan::validate(&bytes, bytes.len()).unwrap();
    assert!(
        plan.node_bytes()
            .windows(b"restored-node-history".len())
            .any(|b| b == b"restored-node-history")
    );
    assert!(plan.source_bytes().starts_with(b"{"));
    assert!(PacketRestoredSettledSemantic17Plan::validate(&bytes, bytes.len() - 1).is_err());
    value["schema"] = json!("source-private.semantic-state/5");
    let old = canonical::canonical_json(&value).unwrap();
    assert!(PacketRestoredSettledSemantic17Plan::validate(&old, old.len()).is_err());
}
