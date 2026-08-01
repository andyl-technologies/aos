//! Checks the execution-fingerprint definition and host observation boundary.

#![forbid(unsafe_code)]

use crucible_harness::fingerprint::{
    CANONICAL_FINGERPRINT_PERIOD_ICOUNT, FINGERPRINT_DIGEST_BYTES, FingerprintDefinition,
    FingerprintEventBoundary, FingerprintMismatchKind, FingerprintObservationError,
    FingerprintObservationRequest, FingerprintObserver, FingerprintSampleError,
    FingerprintSampleMaterial, FingerprintSampleTrigger, FingerprintStream,
    HostFingerprintObservation, RrSchedulerState, VcpuRegisterDigest, VcpuRetiredCount,
    compare_fingerprint_streams, compute_fingerprint_sample, initial_rolling_fingerprint,
    observe_fingerprint_sample,
};

const CANONICAL_DEFINITION_DIGEST_HEX: &str =
    "2f91ef0f0ce8df7b111a6cb0f737557821e6312719bda867445398cea2f46373";

#[test]
fn fingerprint_definition_digest_is_stable_and_content_addressed() {
    let first = FingerprintDefinition::canonical();
    let second = FingerprintDefinition::canonical();

    assert_eq!(first.digest(), second.digest());
    assert_eq!(hex(&first.digest()), CANONICAL_DEFINITION_DIGEST_HEX);
    assert_eq!(
        first.cadence().period_icount(),
        CANONICAL_FINGERPRINT_PERIOD_ICOUNT
    );
    assert!(
        first
            .cadence()
            .samples_periodic_icount(CANONICAL_FINGERPRINT_PERIOD_ICOUNT)
    );
    assert!(
        !first
            .cadence()
            .samples_periodic_icount(CANONICAL_FINGERPRINT_PERIOD_ICOUNT - 1)
    );
    assert!(first.include_device_state());
    assert!(first.include_rr_scheduler_state());
}

#[test]
fn fingerprint_observer_boundary_supplies_black_box_state() {
    let definition = FingerprintDefinition::canonical();
    let previous = initial_rolling_fingerprint(&definition);
    let request = periodic_request(0, CANONICAL_FINGERPRINT_PERIOD_ICOUNT);
    let mut observer = RecordingObserver::default();

    let sample =
        match observe_fingerprint_sample(&definition, &previous, request.clone(), &mut observer) {
            Ok(sample) => sample,
            Err(error) => panic!("host observation should produce a sample: {error}"),
        };

    assert_eq!(sample.seq, request.seq);
    assert_eq!(sample.node, request.node);
    assert_eq!(sample.icount, request.icount);
    assert_eq!(observer.calls, vec!["atomic-sample"]);
}

#[test]
fn fingerprint_observer_boundary_rejects_mismatched_icount() {
    let definition = FingerprintDefinition::canonical();
    let previous = initial_rolling_fingerprint(&definition);
    let request = periodic_request(0, CANONICAL_FINGERPRINT_PERIOD_ICOUNT);
    let mut observer = RecordingObserver {
        observed_icount: Some(CANONICAL_FINGERPRINT_PERIOD_ICOUNT + 1),
        ..RecordingObserver::default()
    };

    let error = match observe_fingerprint_sample(&definition, &previous, request, &mut observer) {
        Ok(_) => panic!("mismatched observed icount should fail"),
        Err(error) => error,
    };

    assert_eq!(
        error,
        FingerprintSampleError::ObservedIcountMismatch {
            requested: CANONICAL_FINGERPRINT_PERIOD_ICOUNT,
            observed: CANONICAL_FINGERPRINT_PERIOD_ICOUNT + 1,
        }
    );
}

#[test]
fn fingerprint_sample_hashes_icount_register_memory_device_and_rr_state() {
    let definition = FingerprintDefinition::canonical();
    let initial = initial_rolling_fingerprint(&definition);
    let base = sample_for(
        periodic_request(0, CANONICAL_FINGERPRINT_PERIOD_ICOUNT),
        digest(1),
        17,
        digest(3),
        digest(4),
    );
    let changed_icount = sample_for(
        periodic_request(0, CANONICAL_FINGERPRINT_PERIOD_ICOUNT * 2),
        digest(1),
        17,
        digest(3),
        digest(4),
    );
    let changed_register = sample_for(
        periodic_request(0, CANONICAL_FINGERPRINT_PERIOD_ICOUNT),
        digest(9),
        17,
        digest(3),
        digest(4),
    );
    let changed_rr = sample_for(
        periodic_request(0, CANONICAL_FINGERPRINT_PERIOD_ICOUNT),
        digest(1),
        18,
        digest(3),
        digest(4),
    );
    let changed_memory = sample_for(
        periodic_request(0, CANONICAL_FINGERPRINT_PERIOD_ICOUNT),
        digest(1),
        17,
        digest(9),
        digest(4),
    );
    let changed_device = sample_for(
        periodic_request(0, CANONICAL_FINGERPRINT_PERIOD_ICOUNT),
        digest(1),
        17,
        digest(3),
        digest(9),
    );

    let base_hash = computed(&definition, &initial, &base);
    assert_ne!(base_hash, computed(&definition, &initial, &changed_icount));
    assert_ne!(
        base_hash,
        computed(&definition, &initial, &changed_register)
    );
    assert_ne!(base_hash, computed(&definition, &initial, &changed_rr));
    assert_ne!(base_hash, computed(&definition, &initial, &changed_memory));
    assert_ne!(base_hash, computed(&definition, &initial, &changed_device));
}

#[test]
fn fingerprint_sample_enforces_periodic_or_event_boundary_cadence() {
    let definition = FingerprintDefinition::canonical();
    let initial = initial_rolling_fingerprint(&definition);
    let off_cadence = sample_for(periodic_request(0, 7), digest(1), 17, digest(3), digest(4));
    let event = sample_for(
        FingerprintObservationRequest {
            seq: 0,
            node: "node-a".to_string(),
            icount: 7,
            trigger: FingerprintSampleTrigger::Event(FingerprintEventBoundary::FrameDelivery),
        },
        digest(1),
        17,
        digest(3),
        digest(4),
    );

    assert_eq!(
        compute_fingerprint_sample(&definition, &initial, &off_cadence),
        Err(FingerprintSampleError::OffCadence {
            icount: 7,
            trigger: FingerprintSampleTrigger::Periodic,
        })
    );
    assert!(
        compute_fingerprint_sample(&definition, &initial, &event).is_ok(),
        "event boundary samples are accepted off the periodic cadence"
    );
}

#[test]
fn fingerprint_sample_material_sorts_vcpu_state_by_id() {
    let request = periodic_request(0, CANONICAL_FINGERPRINT_PERIOD_ICOUNT);
    let left = material(
        request.clone(),
        vec![register(1, 2, 7), register(0, 1, 11)],
        vec![VcpuRetiredCount::new(1, 7), VcpuRetiredCount::new(0, 11)],
    );
    let right = material(
        request,
        vec![register(0, 1, 11), register(1, 2, 7)],
        vec![VcpuRetiredCount::new(0, 11), VcpuRetiredCount::new(1, 7)],
    );

    assert_eq!(left, right);
}

#[test]
fn fingerprint_sample_material_rejects_ambiguous_vcpu_sets() {
    assert_eq!(
        RrSchedulerState::new(0, 1, Vec::new()),
        Err(FingerprintSampleError::EmptyVcpuSet)
    );
    assert_eq!(
        RrSchedulerState::new(
            0,
            1,
            vec![VcpuRetiredCount::new(0, 1), VcpuRetiredCount::new(0, 2)],
        ),
        Err(FingerprintSampleError::DuplicateVcpu { vcpu_id: 0 })
    );
    assert_eq!(
        FingerprintSampleMaterial::new(
            FingerprintObservationRequest {
                seq: 0,
                node: String::new(),
                icount: 1,
                trigger: FingerprintSampleTrigger::Periodic,
            },
            vec![register(0, 1, 1)],
            rr_state(vec![VcpuRetiredCount::new(0, 1)]),
            digest(1),
            digest(1),
        ),
        Err(FingerprintSampleError::EmptyNode)
    );
}

#[test]
fn fingerprint_sample_material_rejects_mismatched_vcpu_sets() {
    assert_eq!(
        FingerprintSampleMaterial::new(
            periodic_request(0, CANONICAL_FINGERPRINT_PERIOD_ICOUNT),
            vec![register(0, 1, 1)],
            rr_state(vec![VcpuRetiredCount::new(1, 1)]),
            digest(3),
            digest(4),
        ),
        Err(FingerprintSampleError::MismatchedVcpuSet)
    );
}

#[test]
fn fingerprint_sample_material_requires_current_vcpu_in_sample() {
    let rr_scheduler = match RrSchedulerState::new(2, 4, vec![VcpuRetiredCount::new(0, 1)]) {
        Ok(state) => state,
        Err(error) => panic!("test RR state should be structurally valid: {error}"),
    };

    assert_eq!(
        FingerprintSampleMaterial::new(
            periodic_request(0, CANONICAL_FINGERPRINT_PERIOD_ICOUNT),
            vec![register(0, 1, 1)],
            rr_scheduler,
            digest(3),
            digest(4),
        ),
        Err(FingerprintSampleError::CurrentVcpuMissing { current_vcpu: 2 })
    );
}

#[test]
fn fingerprint_sample_material_rejects_non_canonical_digest_lengths() {
    assert_eq!(
        VcpuRegisterDigest::new(0, vec![1], 1),
        Err(FingerprintSampleError::InvalidDigestLength {
            field: "register_digest",
            len: 1,
        })
    );
    assert_eq!(
        FingerprintSampleMaterial::new(
            periodic_request(0, CANONICAL_FINGERPRINT_PERIOD_ICOUNT),
            vec![register(0, 1, 1)],
            rr_state(vec![VcpuRetiredCount::new(0, 1)]),
            vec![1],
            digest(4),
        ),
        Err(FingerprintSampleError::InvalidDigestLength {
            field: "memory_digest",
            len: 1,
        })
    );
}

#[test]
fn compare_fingerprint_streams_rejects_definition_mismatch() {
    let mut left = FingerprintStream::from_samples(&FingerprintDefinition::canonical(), Vec::new());
    let mut right = left.clone();
    right.definition_digest = vec![0];
    let mismatch = match compare_fingerprint_streams(&left, &right) {
        Ok(()) => panic!("definition mismatch should fail"),
        Err(error) => error,
    };

    assert!(matches!(
        mismatch.kind,
        FingerprintMismatchKind::Definition { .. }
    ));

    left.final_fingerprint = right.final_fingerprint.clone();
    assert!(compare_fingerprint_streams(&left, &left.clone()).is_ok());
}

#[derive(Default)]
struct RecordingObserver {
    calls: Vec<&'static str>,
    observed_icount: Option<u64>,
}

impl FingerprintObserver for RecordingObserver {
    fn observe_sample(
        &mut self,
        request: &FingerprintObservationRequest,
        _definition: &FingerprintDefinition,
    ) -> Result<HostFingerprintObservation, FingerprintObservationError> {
        self.calls.push("atomic-sample");
        Ok(HostFingerprintObservation {
            observed_icount: self.observed_icount.unwrap_or(request.icount),
            vcpu_registers: vec![register(0, 1, 17)],
            rr_scheduler: rr_state(vec![VcpuRetiredCount::new(0, 17)]),
            memory_digest: digest(3),
            device_digest: digest(4),
        })
    }
}

fn periodic_request(seq: u64, icount: u64) -> FingerprintObservationRequest {
    FingerprintObservationRequest {
        seq,
        node: "node-a".to_string(),
        icount,
        trigger: FingerprintSampleTrigger::Periodic,
    }
}

fn sample_for(
    request: FingerprintObservationRequest,
    register_digest: Vec<u8>,
    retired_count: u64,
    memory_digest: Vec<u8>,
    device_digest: Vec<u8>,
) -> FingerprintSampleMaterial {
    match FingerprintSampleMaterial::new(
        request,
        vec![register_with_digest(0, register_digest, retired_count)],
        rr_state(vec![VcpuRetiredCount::new(0, retired_count)]),
        memory_digest,
        device_digest,
    ) {
        Ok(material) => material,
        Err(error) => panic!("test fingerprint material should be valid: {error}"),
    }
}

fn material(
    request: FingerprintObservationRequest,
    registers: Vec<VcpuRegisterDigest>,
    counts: Vec<VcpuRetiredCount>,
) -> FingerprintSampleMaterial {
    match FingerprintSampleMaterial::new(request, registers, rr_state(counts), digest(3), digest(4))
    {
        Ok(material) => material,
        Err(error) => panic!("test fingerprint material should be valid: {error}"),
    }
}

fn register(vcpu_id: u64, byte: u8, retired_count: u64) -> VcpuRegisterDigest {
    register_with_digest(vcpu_id, digest(byte), retired_count)
}

fn register_with_digest(
    vcpu_id: u64,
    register_digest: Vec<u8>,
    retired_count: u64,
) -> VcpuRegisterDigest {
    match VcpuRegisterDigest::new(vcpu_id, register_digest, retired_count) {
        Ok(register) => register,
        Err(error) => panic!("test register digest should be valid: {error}"),
    }
}

fn digest(byte: u8) -> Vec<u8> {
    vec![byte; FINGERPRINT_DIGEST_BYTES]
}

fn rr_state(counts: Vec<VcpuRetiredCount>) -> RrSchedulerState {
    match RrSchedulerState::new(0, 4, counts) {
        Ok(state) => state,
        Err(error) => panic!("test RR state should be valid: {error}"),
    }
}

fn computed(
    definition: &FingerprintDefinition,
    previous: &[u8],
    material: &FingerprintSampleMaterial,
) -> Vec<u8> {
    match compute_fingerprint_sample(definition, previous, material) {
        Ok(sample) => sample.rolling_fingerprint,
        Err(error) => panic!("test fingerprint sample should compute: {error}"),
    }
}

fn hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut encoded = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        encoded.push(HEX[(byte >> 4) as usize] as char);
        encoded.push(HEX[(byte & 0x0f) as usize] as char);
    }
    encoded
}
