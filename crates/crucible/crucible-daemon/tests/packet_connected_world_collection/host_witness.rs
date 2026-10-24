//! Retains the original live common ledger after genuine nonempty commitment.
//!
//! These observations supply data about the same host owner and runtime. They
//! do not grant capture, restoration, repeatability or conformance acceptance.

use super::{id, schedule, setup};
use crucible_engine::node_contract::{
    ConformanceRuntime, HostSchedulingContinuationLimits, HostSchedulingContinuationRecord,
    HostSchedulingContinuationV2, HostSchedulingRuntimeRecord, OriginalInputLineageLimits,
    SavedRuntimeActivation,
};
use crucible_node_format::{Phase, U64};

pub(super) fn retain_nonempty(
    runtime: &mut ConformanceRuntime,
    installed: &setup::Installed,
) -> HostSchedulingContinuationV2 {
    // The relay has stopped at Delivery. The pending input cut independently
    // excludes Reaction; neither observation delivers or evaluates that input.
    let cut = schedule::position(6, 0, Phase::Delivery);
    let ordinal = U64::new(0);
    let limits = HostSchedulingContinuationLimits {
        maximum_record_bytes: 64 * 1024 * 1024,
        lineage: OriginalInputLineageLimits::default(),
    };
    let first = runtime
        .host_scheduling_observation(&installed.scene.host_source)
        .unwrap()
        .continuation_v2(cut, ordinal, limits)
        .unwrap();
    first
        .encoded()
        .reference
        .verify(&first.encoded().bytes)
        .unwrap();
    let decoded = HostSchedulingContinuationRecord::decode(&first.encoded().bytes, limits).unwrap();
    assert_eq!(&decoded, first.record());

    let second = runtime
        .host_scheduling_observation(&installed.scene.host_source)
        .unwrap()
        .continuation_v2(cut, ordinal, limits)
        .unwrap();
    assert_eq!(first.record(), second.record());
    assert_eq!(first.encoded(), second.encoded());
    let record = first.record();
    assert_eq!(record.source, *installed.scene.host_source.selection());
    let HostSchedulingRuntimeRecord::OriginalLineage(common) = &record.runtime else {
        panic!("nonempty original host ledger lost its Runtime7 ancestry");
    };
    assert_eq!(common.schema_version, 7);
    assert_eq!(
        common.source_activation,
        SavedRuntimeActivation::from(&installed.scene.activation)
    );
    assert_eq!(common.capture_cut, cut);
    assert_eq!(common.capture_ordinal, ordinal);
    assert_eq!(record.scheduling.capture_cut, cut);
    assert_eq!(record.scheduling.capture_ordinal, ordinal);
    let staged = common
        .inputs
        .iter()
        .find(|input| input.stage_operation == id("connected-stage-6"))
        .unwrap();
    let scheduling = record
        .scheduling
        .input_batches
        .iter()
        .find(|input| input.stage_operation == staged.stage_operation)
        .unwrap();
    assert_eq!(staged.node, schedule::node(1));
    assert_eq!(staged.batch, id("connected-batch-6"));
    assert_eq!(staged.cutoff, schedule::position(6, 0, Phase::Reaction));
    assert_eq!(staged.cutoff, scheduling.cutoff);
    assert_eq!(staged.inventory, scheduling.inventory);
    assert_eq!(staged.deliveries, scheduling.deliveries);
    assert_eq!(staged.acknowledgement, scheduling.acknowledgement);
    assert!(staged.acknowledgement.is_some());
    assert!(staged.committed && staged.coordinator_committed && scheduling.consumer_committed);
    assert!(!staged.deliveries.is_empty() && !staged.payloads.is_empty());
    assert!(scheduling.consumed.is_empty());
    let lineage = staged.lineage.as_ref().unwrap();
    assert!(!lineage.publications.is_empty());
    for reference in staged.payloads.iter().chain(
        lineage
            .publications
            .iter()
            .flat_map(|publication| publication.objects.iter()),
    ) {
        let body = record
            .objects
            .iter()
            .find(|body| &body.reference == reference)
            .unwrap();
        reference.verify(&body.bytes).unwrap();
    }
    for payload in &scheduling.payloads {
        let body = record
            .objects
            .iter()
            .find(|body| body.reference == payload.reference)
            .unwrap();
        assert_eq!(body.bytes, payload.bytes);
    }

    std::fs::write(
        installed
            .directory
            .join("original-host-nonempty-before-delivery.json"),
        &first.encoded().bytes,
    )
    .unwrap();
    std::fs::write(
        installed
            .directory
            .join("original-host-nonempty-before-delivery-ref.json"),
        serde_json::to_vec(&first.encoded().reference).unwrap(),
    )
    .unwrap();
    eprintln!(
        "original host nonempty continuation witness: same runtime, committed input before Delivery"
    );
    first
}
