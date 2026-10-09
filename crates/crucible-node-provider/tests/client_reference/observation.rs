//! Actual opt-in observation and overflow beneath retained public native custody.
//!
//! These cases prove original control/byte observation across realization and
//! cleanup. They do not exercise complete-world activation or qualify a model.

use super::*;

fn observed_controller(
    maximum_requests: usize,
) -> (
    fixture::NativeService,
    Handshake,
    ReferenceController,
    ObservationHandle,
) {
    let provider = Path::new(env!("CARGO_BIN_EXE_crucible-reference-provider"));
    let device = Path::new(env!("CARGO_BIN_EXE_crucible-reference-device"));
    let service = fixture::NativeService::launch_public_linked(provider, device, 32, true);
    let bootstrap = &service.bootstrap;
    let binding = service.profile.bind(bootstrap.authority.clone()).unwrap().0;
    let features = vec![
        fixture::id("cnp.control-evidence/1"),
        fixture::id("cnp.core/1"),
    ];
    let mut token = [0; 32];
    token.copy_from_slice(bootstrap.admission_token.as_slice());
    let mut handshake = Handshake::new(
        TrustedInstallation {
            session_id: bootstrap.authority.session_id.clone(),
            incarnation_id: bootstrap.authority.incarnation_id.clone(),
            measured_implementation: service.profile.implementation.clone(),
            launch_receipt: bootstrap.admission_receipt.clone(),
            admission_token: token,
        },
        NegotiationPolicy {
            supported_features: features.clone(),
            required_features: features.clone(),
            provider_limits: bootstrap.limits,
            required_schemas: Vec::new(),
            required_guarantees: binding.compatibility.guarantees_ref,
            envelope_extension_features: BTreeMap::new(),
        },
    )
    .unwrap();
    let mut hello = request(&service, Method::Hello, "observation-hello", json!({}));
    hello.session_id = Nullable(None);
    hello.incarnation_id = Nullable(None);
    hello.sequence = U64::new(1);
    hello.body = body(HelloRequest {
        versions: vec!["CNP/1".into()],
        session_id: bootstrap.authority.session_id.clone(),
        controller_nonce: Bytes::new(vec![9; 32]),
        required_features: features,
        optional_features: Vec::new(),
        limits: bootstrap.limits,
        admission_token: bootstrap.admission_token.clone(),
        resume_session: None,
        extensions: Extensions::new(),
    });
    let peer = ClientPeer {
        pid: service.process.id(),
        uid: rustix::process::geteuid().as_raw(),
        executable: crucible_node_provider::conformance::measure_executable(provider).unwrap(),
    };
    let session = ClientSession::negotiate(
        UnixStream::connect(service.socket()).unwrap(),
        &peer,
        &hello,
        fixture::id("observation-connection"),
        &mut handshake,
        &mut Installed(&service),
        Rc::new(Supervisor::default()),
        Rc::new(Schemas),
        Duration::from_secs(3),
        1_048_576,
        64,
    )
    .unwrap();
    let custody = ClientCustody::new(
        256,
        ClientContent::new(16 * 1024 * 1024, 256, 16384).unwrap(),
    )
    .unwrap();
    let mut controller = ReferenceController::new(
        service.profile.clone(),
        bootstrap.clone(),
        session,
        custody,
        Duration::from_secs(3),
    )
    .unwrap();
    let handle = controller
        .observe(ObservationLimits {
            maximum_requests,
            maximum_objects: 256,
            maximum_bytes: 16 * 1024 * 1024,
        })
        .unwrap();
    (service, handshake, controller, handle)
}

fn realize(controller: &mut ReferenceController) -> RealizeResult {
    let bootstrap = controller.bootstrap.clone();
    let result = controller
        .call(
            fixture::id("observed-realize"),
            None,
            Method::Realize,
            false,
            RealizeRequest {
                realization_id: bootstrap.authority.realization_id,
                configuration: controller.profile.configuration_ref.clone(),
                requested_node_ids: vec![bootstrap.node_id],
                resource_limits: bootstrap.resource_limits,
                extensions: Extensions::new(),
            },
        )
        .unwrap();
    let Some(MethodResult::Realize(result)) = result.result else {
        panic!("actual observed realization did not complete");
    };
    result
}

fn child_pid(controller: &ReferenceController, result: &RealizeResult) -> u64 {
    let receipt: ControlReceipt = controller.record(&result.closed_gate_receipt).unwrap();
    let record: ClosedGateRecord = controller.record(&receipt.record_ref).unwrap();
    let native = canonical::parse_json(
        controller.content(&record.physical_status_ref).unwrap(),
        1_048_576,
    )
    .unwrap();
    let pid: U64 = serde_json::from_value(native["child_pid"].clone()).unwrap();
    let status = std::fs::read_to_string(format!("/proc/{}/status", pid.get())).unwrap();
    assert!(
        status
            .lines()
            .any(|line| { line == format!("PPid:\t{}", controller.peer_pid()) })
    );
    pid.get()
}

fn abort(controller: &mut ReferenceController) {
    let transaction = controller.bootstrap.transaction_id.clone();
    let result = controller
        .call(
            fixture::id("observed-abort"),
            None,
            Method::Abort,
            false,
            AbortRequest {
                transaction_id: transaction,
                reason: fixture::id("observation-complete"),
                extensions: Extensions::new(),
            },
        )
        .unwrap();
    assert!(matches!(result.result, Some(MethodResult::Abort(_))));
}

fn output_limits() -> ObservationLimits {
    ObservationLimits {
        maximum_requests: 256,
        maximum_objects: 256,
        maximum_bytes: 16 * 1024 * 1024,
    }
}

#[test]
fn actual_original_controls_and_receipts_remain_readable_after_native_retirement() {
    let (service, handshake, mut controller, handle) = observed_controller(256);
    let result = realize(&mut controller);
    let pid = child_pid(&controller, &result);
    let repeated = realize(&mut controller);
    assert_eq!(result, repeated);
    assert!(controller.observe(output_limits()).is_err());
    abort(&mut controller);
    assert!(!Path::new(&format!("/proc/{pid}")).exists());
    let provider_pid = service.process.id();
    let expected_executable = controller.peer_executable().clone();
    let secret = serde_json::to_value(&controller.bootstrap.admission_token)
        .unwrap()
        .as_str()
        .unwrap()
        .to_owned();
    controller.fence();
    drop(controller);
    drop(handshake);
    drop(service);
    assert!(!Path::new(&format!("/proc/{provider_pid}")).exists());

    let keys = handle.request_keys().unwrap();
    let references = handle.content_references().unwrap();
    let snapshot = handle
        .snapshot(&keys, &references, output_limits())
        .unwrap();
    assert!(snapshot.recording_complete);
    assert!(!snapshot.observed_unknown);
    assert_eq!(
        snapshot.evidence.scope.provider_executable,
        expected_executable
    );
    let original = snapshot
        .evidence
        .requests
        .iter()
        .find(|original| {
            original.key.origin == RequestOrigin::Controller
                && original.key.request_id == fixture::id("observed-realize")
        })
        .unwrap();
    let envelope = Envelope::decode(original.request.bytes.as_slice(), 1_048_576).unwrap();
    assert_eq!(envelope.method, Method::Realize);
    assert_eq!(envelope.sequence, U64::new(2));
    assert_eq!(
        envelope.request_hash(original.key.origin).unwrap(),
        original.identity
    );
    assert!(original.response.0.is_some());
    assert!(
        snapshot
            .evidence
            .objects
            .iter()
            .any(|object| { object.reference == result.closed_gate_receipt })
    );
    let encoded = snapshot.encode(32 * 1024 * 1024).unwrap();
    let public = std::str::from_utf8(&encoded).unwrap();
    assert!(!public.contains(&secret));
    for original in &snapshot.evidence.requests {
        assert_ne!(
            Envelope::decode(original.request.bytes.as_slice(), 1_048_576)
                .unwrap()
                .method,
            Method::Hello,
        );
    }
}

#[test]
fn actual_archive_credit_failure_preserves_native_result_and_original_request() {
    let (service, handshake, mut controller, handle) = observed_controller(1);
    let result = realize(&mut controller);
    let pid = child_pid(&controller, &result);
    let key = ObservedRequestKey {
        origin: RequestOrigin::Controller,
        request_id: fixture::id("observed-realize"),
    };
    let recorded = handle
        .snapshot(std::slice::from_ref(&key), &[], output_limits())
        .unwrap();
    assert!(!recorded.recording_complete);
    assert!(recorded.recording_failure.0.is_some());
    assert!(recorded.evidence.requests[0].response.0.is_some());
    assert_eq!(realize(&mut controller), result);
    abort(&mut controller);
    assert!(!Path::new(&format!("/proc/{pid}")).exists());
    controller.fence();
    drop(controller);
    drop(handshake);
    drop(service);
    let after = handle.snapshot(&[key], &[], output_limits()).unwrap();
    assert!(!after.recording_complete);
    assert_eq!(after.recording_failure, recorded.recording_failure);
    assert_eq!(
        after.evidence.requests[0].request.bytes,
        recorded.evidence.requests[0].request.bytes,
    );
}
