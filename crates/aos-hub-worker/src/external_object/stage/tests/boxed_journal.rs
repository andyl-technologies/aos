//! Byte-identical journal compatibility for a heap-owned stage session.

use super::*;
use crate::external_object::{protocol as object_protocol, state::VisibleReceipt};
use serde::{Deserialize, Serialize};

// This is the pre-correction journal representation, kept only as a codec witness.
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct InlineHead {
    version: u8,
    scope: aos_hub_core::storage_authority::control::StorageAuthorityObjectScope,
    configuration: String,
    floor: EpochLeaseFloor,
    pending: Option<object_protocol::Pending>,
    #[serde(default)]
    observation: Option<crate::external_object::observation::Pending>,
    #[serde(default)]
    visible_receipt: Option<VisibleReceipt>,
    receipts: LeaseInteger,
    #[serde(default)]
    incarnation: WireInteger,
    #[serde(default)]
    stage: Option<state::Session>,
}

fn assert_inline_journal_identity(head: &Head) {
    let boxed_bytes = serde_json::to_vec(head).unwrap();
    let old: InlineHead = serde_json::from_slice(&boxed_bytes).unwrap();
    assert_eq!(serde_json::to_vec(&old).unwrap(), boxed_bytes);

    let restored: Head = serde_json::from_slice(&boxed_bytes).unwrap();
    assert!(restored == *head);
    assert_eq!(serde_json::to_vec(&restored).unwrap(), boxed_bytes);
}

#[tokio::test]
async fn boxed_stage_journal_preserves_inline_bytes_and_pending_turns() {
    let f = Fixture::new(1).await;
    let fresh = f.fresh(false);
    assert_inline_journal_identity(&fresh);

    let (pending, _) = f
        .begin(
            &fresh,
            f.intent("original-source-create", Operation::CreateStage),
            None,
            None,
        )
        .unwrap();
    assert!(pending.stage.as_ref().unwrap().pending.is_some());
    assert_inline_journal_identity(&pending);

    let (destination, proof) = f.destination();
    assert_inline_journal_identity(&destination);
    let (copy_pending, _) = f
        .begin(&destination, f.copy_intent(&proof, 1), Some(proof), None)
        .unwrap();
    assert_eq!(copy_pending.stage.as_ref().unwrap().pending_parts.len(), 1);
    assert_inline_journal_identity(&copy_pending);
}
