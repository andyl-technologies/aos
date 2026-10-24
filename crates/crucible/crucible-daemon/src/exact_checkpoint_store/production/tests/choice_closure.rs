//! Exact-root choice child restart and fail-closed regressions.

use super::*;

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
    let bytes = prepared
        .root_source
        .read_all(MAX_PRODUCTION_ROOT_BYTES)
        .expect("read prepared root");
    let original = ContentEnvelope::from_canonical_bytes(&bytes).expect("decode prepared root");
    let children = original
        .children()
        .iter()
        .filter(|child| child.role() != PRODUCTION_CHOICE_CLOSURE_ROLE)
        .cloned()
        .collect();
    let missing = ContentEnvelope::new(
        EXACT_CHECKPOINT_ROOT_SCHEMA,
        EXACT_CHECKPOINT_ROOT_SCHEMA_VERSION,
        children,
        original.body().to_vec(),
    )
    .expect("encode root missing choices");

    assert!(matches!(
        decode_production_root_children(&missing, 1),
        Err(ExactCheckpointStoreError::InvalidRoot { .. })
    ));
}

#[test]
fn production_choice_child_survives_store_reopen_and_rejects_malformed_preparation() {
    let backend = Arc::new(DurableMemoryBackend::new());
    let store = ExactCheckpointStore::new(backend.clone(), 64 * 1024 * 1024)
        .expect("admit production store");
    let prepared = prepare_production_source(
        Arc::new(memory_source(1)),
        ContentHash::from_bytes(b"reopened choice closure"),
        ContentHash::from_bytes(b"reopened choice scenario"),
        ContentHash::from_bytes(b"reopened choice configuration"),
        64 * 1024 * 1024,
    )
    .expect("prepare v5 root");
    let root = store
        .publish_production_closure(&prepared)
        .expect("publish root-bound choices")
        .root();
    drop(store);

    let reopened = ExactCheckpointStore::new(backend, 64 * 1024 * 1024)
        .expect("reopen production store")
        .load_production_closure(root)
        .expect("load choice closure through authenticated root");
    assert_eq!(
        reopened.choice_closure(),
        crate::qemu_campaign_lifecycle::GuardedCampaignReplayClosure::empty()
            .to_canonical_bytes()
            .expect("encode empty choices")
    );

    let malformed = prepare_production_source_with_cancellation(ProductionSourcePreparation {
        source: Arc::new(memory_source(1)),
        production_identity: ContentHash::from_bytes(b"malformed choices"),
        scenario: ContentHash::from_bytes(b"malformed choice scenario"),
        configuration: ContentHash::from_bytes(b"malformed choice configuration"),
        maximum_checkpoint_bytes: 64 * 1024 * 1024,
        cancellation: None,
        native_retirement: None,
        promotion_source: None,
        promotion_evidence: None,
        choice_closure: b"malformed".to_vec(),
        reuse: None,
    });
    assert!(matches!(
        malformed,
        Err(ExactCheckpointStoreError::InvalidRoot {
            reason: "checkpoint choice closure is malformed"
        })
    ));
}
