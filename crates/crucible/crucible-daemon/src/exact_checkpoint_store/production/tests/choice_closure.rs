//! Exact-root choice children: restart, lazy frames, and fail-closed roots.

use super::*;

use crate::qemu_campaign_lifecycle::GuardedCampaignReplayClosure;

/// Prepares a root that carries `closure` as its choice children.
fn prepare_with_choices(
    label: &[u8],
    closure: GuardedCampaignReplayClosure,
) -> PreparedProductionExactCheckpoint {
    prepare_production_source_with_cancellation(ProductionSourcePreparation {
        source: Arc::new(memory_source(1)),
        production_identity: ContentHash::from_bytes(label),
        scenario: ContentHash::from_bytes(b"choice scenario"),
        configuration: ContentHash::from_bytes(b"choice configuration"),
        maximum_checkpoint_bytes: 64 * 1024 * 1024,
        cancellation: None,
        native_retirement: None,
        promotion_source: None,
        promotion_evidence: None,
        choice_closure: closure,
        reuse: None,
    })
    .expect("prepare v5 root with choices")
}

fn prepared_root(prepared: &PreparedProductionExactCheckpoint) -> ContentEnvelope {
    let bytes = prepared
        .root_source
        .read_all(MAX_PRODUCTION_ROOT_BYTES)
        .expect("read prepared root");
    ContentEnvelope::from_canonical_bytes(&bytes).expect("decode prepared root")
}

/// Re-encodes `original` with only the children `keep` admits.
fn root_without(
    original: &ContentEnvelope,
    keep: impl Fn(&ContentChild) -> bool,
) -> ContentEnvelope {
    let children = original
        .children()
        .iter()
        .filter(|child| keep(child))
        .cloned()
        .collect();
    ContentEnvelope::new(
        EXACT_CHECKPOINT_ROOT_SCHEMA,
        EXACT_CHECKPOINT_ROOT_SCHEMA_VERSION,
        children,
        original.body().to_vec(),
    )
    .expect("encode edited root")
}

#[test]
fn production_root_requires_choice_child_even_when_no_selections_exist() {
    let prepared = prepare_production_source(
        Arc::new(memory_source(1)),
        ContentHash::from_bytes(b"missing choice closure"),
        ContentHash::from_bytes(b"missing choice scenario"),
        ContentHash::from_bytes(b"missing choice configuration"),
        64 * 1024 * 1024,
    )
    .expect("prepare v5 root with empty choices");
    let missing = root_without(&prepared_root(&prepared), |child| {
        child.role() != PRODUCTION_CHOICE_CLOSURE_ROLE
    });

    assert!(matches!(
        decode_production_root_children(&missing, 1),
        Err(ExactCheckpointStoreError::InvalidRoot { .. })
    ));
}

#[test]
fn production_choice_frames_survive_store_reopen_as_lazy_children() {
    let closure = GuardedCampaignReplayClosure::synthetic_for_test(5_000).expect("build closure");
    let backend = Arc::new(DurableMemoryBackend::new());
    let store = ExactCheckpointStore::new(backend.clone(), 64 * 1024 * 1024)
        .expect("admit production store");
    let prepared = prepare_with_choices(b"reopened choice closure", closure.clone());

    let children = decode_production_root_children(&prepared_root(&prepared), 1)
        .expect("decode prepared children");
    assert_eq!(children.choice_closure, closure.root_id());
    assert_eq!(
        children.choice_frames,
        closure.frame_ids().collect::<Vec<_>>()
    );

    let root = store
        .publish_production_closure(&prepared)
        .expect("publish root-bound choices")
        .root();
    drop(store);

    let reopened = ExactCheckpointStore::new(backend, 64 * 1024 * 1024)
        .expect("reopen production store")
        .load_production_closure(root)
        .expect("load choice closure through authenticated root");
    assert_eq!(reopened.choice_closure(), &closure);
    assert_eq!(
        reopened
            .choice_closure()
            .to_canonical_bytes()
            .expect("read stored frames"),
        closure.to_canonical_bytes().expect("read memory frames")
    );
    let retained = reopened
        .retained_content_ids()
        .expect("inventory retained ids");
    assert!(retained.contains(&closure.root_id()));
    assert!(closure.frame_ids().all(|frame| retained.contains(&frame)));
}

#[test]
fn production_root_rejects_a_choice_frame_sequence_with_a_gap() {
    let closure = GuardedCampaignReplayClosure::synthetic_for_test(5_000).expect("build closure");
    let prepared = prepare_with_choices(b"gapped choice closure", closure);
    let gapped = root_without(&prepared_root(&prepared), |child| {
        child.role() != "checkpoint-choice-frame-00000001"
    });

    assert!(matches!(
        decode_production_root_children(&gapped, 1),
        Err(ExactCheckpointStoreError::InvalidRoot {
            reason: "checkpoint choice frame sequence is incomplete"
        })
    ));
}
