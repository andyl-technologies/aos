//! Tests bounded administrative archive data; native owners and all captures are modeled.
//!
//! These grammar controls issue no runtime ticket, installed source, signature,
//! capture permission or native restoration authority.

#![allow(clippy::unwrap_used)]

use super::*;
use crate::node_contract::{
    OriginalCaptureAttemptRecord, OriginalCaptureOwnerRecord, OwnerIdentity, SavedRuntimeActivation,
};
use crucible_node_format::{Id, Phase, Position, U64, canonical};

fn journal() -> RuntimeOriginalCaptureJournal {
    let (graph, _) = crate::node_admission::test_fixture_isolated_execution(false);
    let owners: Vec<_> = (0..4)
        .map(|index| OwnerIdentity {
            owner: Id::new(format!("model/owner/{index}")).unwrap(),
            incarnation: Id::new(format!("model/incarnation/{index}")).unwrap(),
            generation: 1.into(),
        })
        .collect();
    let boundary = Position::new(0.into(), 0.into(), Phase::BoundaryControl);
    RuntimeOriginalCaptureJournal {
        schema_version: 1,
        maximum_attempts: 64.into(),
        attempts: vec![OriginalCaptureAttemptRecord {
            sequence: 1.into(),
            capture_id: Id::new("model/capture/1").unwrap(),
            source_runtime: canonical::content_ref(
                b"{}",
                super::super::ORIGINAL_LINEAGE_RUNTIME_MEDIA,
            )
            .unwrap(),
            source_activation: SavedRuntimeActivation {
                generation: 1.into(),
                activation_id: Id::new("model/activation").unwrap(),
                world_binding_hash: graph.world_binding_hash().clone(),
                owners: owners.clone(),
                boundary,
            },
            cut: boundary,
            ordinal: 0.into(),
            owners: owners
                .into_iter()
                .enumerate()
                .map(|(index, owner)| OriginalCaptureOwnerRecord {
                    owner,
                    participants: vec![Id::new(format!("model/node/{index}")).unwrap()],
                    operation: Id::new(format!("native-capture/1/{index}")).unwrap(),
                    state: OriginalCaptureOwnerState::Settled {
                        snapshot: canonical::content_ref(b"{}", "model/snapshot").unwrap(),
                        journal: Box::new(
                            canonical::content_ref(b"[]", "model/settlement").unwrap(),
                        ),
                    },
                })
                .collect(),
        }],
    }
}

#[test]
fn modeled_closed_journal_preserves_lifetime_ids_and_refuses_reordering_or_renewal() {
    let mut journal = journal();
    validate_journal(&journal, 512 * 1024).unwrap();
    let mut next: OriginalCaptureAttemptRecord =
        serde_json::from_value(serde_json::to_value(&journal.attempts[0]).unwrap()).unwrap();
    next.sequence = 2.into();
    next.capture_id = Id::new("model/capture/2").unwrap();
    for (index, owner) in next.owners.iter_mut().enumerate() {
        owner.operation = Id::new(format!("native-capture/2/{index}")).unwrap();
    }
    journal.attempts.push(next);
    validate_journal(&journal, 512 * 1024).unwrap();

    journal.attempts.swap(0, 1);
    assert!(validate_journal(&journal, 512 * 1024).is_err());
    journal.attempts.swap(0, 1);
    journal.attempts[1].capture_id = journal.attempts[0].capture_id.clone();
    assert!(validate_journal(&journal, 512 * 1024).is_err());
    journal.maximum_attempts = U64::new(128);
    assert!(validate_journal(&journal, 512 * 1024).is_err());
}

#[test]
fn modeled_uncertain_owner_or_missing_original_incarnation_refuses_signable_history() {
    let mut journal = journal();
    journal.attempts[0].owners[0].state = OriginalCaptureOwnerState::Uncertain;
    assert!(validate_journal(&journal, 512 * 1024).is_err());

    journal = self::journal();
    journal.attempts[0].source_activation.owners[0].incarnation =
        Id::new("model/another-incarnation").unwrap();
    assert!(validate_journal(&journal, 512 * 1024).is_err());
    journal = self::journal();
    assert!(validate_journal(&journal, 1).is_err());
}

#[test]
fn index_three_requires_mandatory_nonnull_journal_without_aliasing_legacy_grammars() {
    let reference = canonical::content_ref(b"{}", "application/json").unwrap();
    let journal = canonical::content_ref(b"[]", JOURNAL_MEDIA).unwrap();
    let mut three = serde_json::json!({
        "schema_version":3,"artifact":reference,"typed_inventory":{"schema_version":2,"objects":[]},
        "owners":[],"original_capture_journal":journal,
    });
    let decoded: Index = serde_json::from_value(three.clone()).unwrap();
    assert_eq!(decoded.schema_version, 3);
    assert_eq!(serde_json::to_value(&decoded).unwrap(), three);
    three["original_capture_journal"] = serde_json::Value::Null;
    assert!(serde_json::from_value::<Index>(three.clone()).is_err());
    three
        .as_object_mut()
        .unwrap()
        .remove("original_capture_journal");
    assert!(serde_json::from_value::<Index>(three.clone()).is_err());

    let two = serde_json::json!({
        "schema_version":2,"artifact":reference,"typed_inventory":{"schema_version":2,"objects":[]},
        "owners":[],"selected_extensions":null,
    });
    let decoded: Index = serde_json::from_value(two.clone()).unwrap();
    assert_eq!(serde_json::to_value(&decoded).unwrap(), two);
    let mut alias = two;
    alias["original_capture_journal"] = serde_json::to_value(journal).unwrap();
    assert!(serde_json::from_value::<Index>(alias).is_err());
}
