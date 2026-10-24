//! Requires original failed-world custody through durable seal refusal and Stop.
//!
//! The genuine installed four-owner behavioral gate remains mandatory. The
//! current default service cannot satisfy that prerequisite; this ignored entry
//! fails on its refusal rather than treating it as successful native cleanup.
//! A future catalog-aware constructor can pass the same owning service to the
//! workflow without changing the storage, history or supervisor assertions.

use super::*;
use crucible_campaign::CampaignRepository;
use crucible_daemon::node_observed_executor::{
    CapabilityPreparationRequest, InstalledIoArtifact, InstalledNodeSelection,
    NodeObservationRetention, NodeObservationService, NodeObservationServiceConfig,
};
use crucible_node_transport::client::ExchangeDeadline;
use crucible_store::content_store::{
    ContentId, DirectoryBlobBackend, DirectoryRefBackend, ImmutableBlobBackend, MutableRefBackend,
    ObjectKind, RefName,
};
use std::sync::Arc;

#[path = "seal_fault.rs"]
mod seal_fault;

use seal_fault::SealPlacement;

struct OriginalOwner {
    service: Option<NodeObservationService>,
    retention: NodeObservationRetention,
    fault: Arc<SealPlacement>,
}

impl OriginalOwner {
    fn new(service: NodeObservationService, fault: Arc<SealPlacement>) -> Self {
        Self {
            retention: service.retention_owner(),
            service: Some(service),
            fault,
        }
    }
}

impl Drop for OriginalOwner {
    fn drop(&mut self) {
        // Unwind removes only our fixed storage fault and requests Stop through
        // the same service. It cannot signal a native child, replace an owner,
        // or discard a still-unresolved supervisor capsule on deadline expiry.
        self.fault.release_storage_fault();
        self.service.take();
        while !self.retention.is_retired() {
            std::thread::park_timeout(Duration::from_millis(100));
        }
    }
}

fn wait_until(mut predicate: impl FnMut() -> bool) {
    let deadline = ExchangeDeadline::start(Duration::from_secs(1200)).unwrap();
    loop {
        deadline.remaining().unwrap();
        let done = predicate();
        let remaining = deadline.remaining().unwrap();
        if done {
            return;
        }

        std::thread::park_timeout(remaining.min(Duration::from_millis(100)));
        deadline.remaining().unwrap();
    }
}

fn wait_refusal(service: &NodeObservationService, execution: &str) -> CapabilityPreparationRecord {
    let mut settled = None;
    wait_until(|| {
        let record = service.capability_preparation_status(execution).unwrap();
        if matches!(
            record.outcome,
            CapabilityPreparationState::AwaitingAdmission {}
        ) {
            return false;
        }
        settled = Some(record);
        true
    });
    settled.unwrap()
}

fn read_refusal(
    blobs: &dyn ImmutableBlobBackend,
    refs: &dyn MutableRefBackend,
    execution: &str,
) -> Vec<u8> {
    let name = RefName::new(format!("node-capability-preparations/{execution}")).unwrap();
    let identity = refs.read_ref(&name).unwrap().unwrap();
    let bytes = blobs
        .read(identity, None)
        .unwrap()
        .read_all(16 << 20)
        .unwrap();
    assert_eq!(identity.kind(), ObjectKind::Trace);
    assert_eq!(identity.schema_version(), 1);
    assert!(identity.authenticates(&bytes));
    bytes
}

/// Exercises storage refusal with a service that already owns its installation.
///
/// The caller must retain the original request-bound backend and independently
/// authenticated installed class. This helper grants neither that class nor a
/// release token. Original assertion failures retain the same service capsule.
///
/// # Panics
/// Panics on storage errors, expiration, an absent genuine first-round refusal,
/// changed original data, false retirement or a missing final durable seal.
fn exercise_original(
    mut owner: OriginalOwner,
    refs: Arc<dyn MutableRefBackend>,
    state: &Path,
    output: &Path,
    baseline: &NodeScenario,
    original: CapabilityPreparationRequest,
) {
    let request_bytes =
        canonical::canonical_json(&serde_json::to_value(&original).unwrap()).unwrap();
    let request_id = ContentId::for_bytes(ObjectKind::Trace, 1, &request_bytes);
    owner.fault.bind(request_id).unwrap();
    let service = owner.service.as_ref().unwrap();
    service
        .submit_capability_preparation(original.clone())
        .unwrap();

    let refused = wait_refusal(service, &original.execution);
    let CapabilityPreparationState::Unavailable { reason } = &refused.outcome else {
        panic!("one-round original did not refuse: {:?}", refused.outcome);
    };
    assert!(
        reason.ends_with("original common planner exceeds bounded round credit"),
        "genuine installed first-round execution prerequisite failed: {reason}"
    );
    assert_eq!(ContentId::parse(&refused.request).unwrap(), request_id);
    let fixed_record = read_refusal(owner.fault.as_ref(), refs.as_ref(), &original.execution);
    fs::write(output.join("original-refusal.json"), &fixed_record).unwrap();
    fs::write(output.join("original-request.json"), request_bytes).unwrap();

    // Actual source/history/private ACK and terminal data must exist before the
    // worker attempts this seal. No archive-root absence or Unavailable DTO is
    // used to substitute for the exact execution-before-capture branch.
    wait_until(|| owner.fault.completed_placements() > 0);
    let (identity, bytes) = owner.fault.original();
    let seal_name = RefName::new(format!(
        "node-capability-failed-retirement/{}",
        original.execution
    ))
    .unwrap();
    assert!(refs.read_ref(&seal_name).unwrap().is_none());
    assert!(!owner.retention.is_retired());
    evidence::verify_unplaced_original(state, output, &refused, baseline, identity, &bytes)
        .unwrap();
    fs::write(output.join("original-unpublished-seal.json"), &bytes).unwrap();

    // Duplicate requests are ordinary durable lookups. They must preserve the
    // original record and cannot create a fresh execution or retirement owner.
    for _ in 0..2 {
        let duplicate = service
            .submit_capability_preparation(original.clone())
            .unwrap();
        let encoded = canonical::canonical_json(&serde_json::to_value(duplicate).unwrap()).unwrap();
        assert_eq!(encoded, fixed_record);
    }

    // Stop removes only the public service handle. Its actor must retry the same
    // placement while retaining the original worker, even after native reap.
    let placements = owner.fault.completed_placements();
    owner.service.take();
    wait_until(|| owner.fault.completed_placements() > placements);
    assert!(!owner.retention.is_retired());
    assert!(refs.read_ref(&seal_name).unwrap().is_none());
    assert_eq!(owner.fault.original(), (identity, bytes.clone()));
    assert_eq!(
        read_refusal(owner.fault.as_ref(), refs.as_ref(), &original.execution),
        fixed_record
    );
    evidence::verify_unplaced_original(state, output, &refused, baseline, identity, &bytes)
        .unwrap();

    owner.fault.release_storage_fault();
    wait_until(|| owner.retention.is_retired());
    assert_eq!(refs.read_ref(&seal_name).unwrap(), Some(identity));
    let reopened =
        evidence::verify_original(state, output, &refused, baseline, Some(&bytes)).unwrap();
    assert_eq!(reopened, bytes);
    assert_eq!(owner.fault.original(), (identity, bytes.clone()));
    assert_eq!(
        read_refusal(owner.fault.as_ref(), refs.as_ref(), &original.execution),
        fixed_record
    );
    fs::write(output.join("reconciled-failed-retirement.json"), bytes).unwrap();
    fs::write(output.join("reconciled-refusal.json"), fixed_record).unwrap();
}

#[test]
#[ignore = "requires genuine Accepted catalog-aware SE four-owner installation; default service refuses before native work; no current native/release credit"]
fn same_failed_world_survives_seal_storage_refusal_and_service_stop() {
    let directory = tempfile::Builder::new()
        .prefix("gem5-failed-seal-")
        .tempdir()
        .unwrap()
        .keep();
    eprintln!("same original failed-seal custody: {}", directory.display());
    let device = PathBuf::from(std::env::var("CRUCIBLE_REFERENCE_DEVICE").unwrap());
    let state = directory.join("state");
    let (policy_path, _) = policy(&state, &device);
    let installed: Value = serde_json::from_slice(&fs::read(policy_path).unwrap()).unwrap();
    let (selected, base, script) = authored(&directory);
    let selections: Vec<InstalledNodeSelection> = serde_json::from_value(selected.clone()).unwrap();
    let artifacts = [base, script]
        .into_iter()
        .map(|artifact| {
            InstalledIoArtifact::path(
                PathBuf::from(artifact["path"].as_str().unwrap()),
                serde_json::from_value(artifact["expected"].clone()).unwrap(),
            )
        })
        .collect();

    // The complete storage holder exists before start and before any world
    // preparation. The service retains these same backends throughout Stop.
    let fault = Arc::new(SealPlacement::new(Arc::new(DirectoryBlobBackend::new(
        "original-failed-seal",
        state.join("blobs"),
    ))));
    let refs = Arc::new(DirectoryRefBackend::new(state.join("refs")));
    let repository = Arc::new(CampaignRepository::new(fault.clone(), refs.clone()));
    let service = NodeObservationService::start(
        NodeObservationServiceConfig {
            installed_artifacts: artifacts,
            device_executable: device,
            expected_device: serde_json::from_value(installed["expected_device"].clone()).unwrap(),
            socket_parent: state.clone(),
            control_timeout: Duration::from_secs(3),
            maximum_worlds: 4,
            maximum_pending_requests: 4,
        },
        repository,
        fault.clone(),
        refs.clone(),
    )
    .unwrap();
    let owner = OriginalOwner::new(service, fault);
    let baseline_bytes = owner.service.as_ref().unwrap().compile(selections).unwrap();
    let baseline = NodeScenario::from_json(&baseline_bytes).unwrap();
    fs::write(directory.join("original-baseline.json"), baseline_bytes).unwrap();
    let mut original = request(
        "48484848484848484848484848484848",
        &complete_demands(&baseline),
        json!([{"id":"complete-four-owners","selections":selected}]),
        json!({"operation":"capture"}),
        11,
    );
    original["configuration"] = serde_json::to_value(Bytes::new(
        serde_json::to_vec(&json!({
            "format":"crucible.node-run-configuration", "version":1,
            "horizon_ps":"11", "maximum_rounds":"1"
        }))
        .unwrap(),
    ))
    .unwrap();
    let original = serde_json::from_value(original).unwrap();
    exercise_original(owner, refs, &state, &directory, &baseline, original);
}
