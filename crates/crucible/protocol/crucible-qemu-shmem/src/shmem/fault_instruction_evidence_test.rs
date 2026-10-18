//! Instruction-fault evidence codec tests.

use super::*;

fn skip_evidence() -> FaultInstructionEvidenceV1 {
    let instruction_bytes = vec![0x90];
    let before_cpu_sha256 = [1; 32];
    let after_cpu_sha256 = [2; 32];
    let before_ram_sha256 = [5; 32];
    let after_ram_sha256 = [6; 32];
    let before_device_sha256 = [7; 32];
    let after_device_sha256 = [8; 32];
    FaultInstructionEvidenceV1 {
        architecture: FaultCapabilityScope::X86_64,
        mutation_kind: FaultInstructionMutationKindV1::Skip,
        outcome: FaultInstructionEvidenceOutcomeV1::Applied,
        replay_ordinal: 0,
        replay_total: 0,
        opcode_class: 0x0100_0001,
        flags: 0,
        pc: 0x1000,
        physical_address: 0x2000,
        observed_icount: 17,
        vcpu_index: 0,
        destinations: vec![1],
        instruction_sha256: Sha256::digest(&instruction_bytes).into(),
        before_state_sha256: instruction_system_digest(
            before_cpu_sha256,
            before_ram_sha256,
            before_device_sha256,
            4096,
            128,
        ),
        after_state_sha256: instruction_system_digest(
            after_cpu_sha256,
            after_ram_sha256,
            after_device_sha256,
            4096,
            128,
        ),
        manifest_sha256: [3; 32],
        before_cpu_sha256,
        after_cpu_sha256,
        input_state_sha256: None,
        matched_input_state_sha256: instruction_system_digest(
            before_cpu_sha256,
            before_ram_sha256,
            before_device_sha256,
            4096,
            128,
        ),
        code_page_bases: vec![0x2000],
        code_page_sha256: vec![[4; 32]],
        before_ram_sha256,
        after_ram_sha256,
        before_device_sha256,
        after_device_sha256,
        before_ram_bytes: 4096,
        after_ram_bytes: 4096,
        before_device_bytes: 128,
        after_device_bytes: 128,
        instruction_bytes,
        detail: Vec::new(),
    }
}

#[test]
fn instruction_round_trip_rejects_reserved_bytes() {
    let evidence = skip_evidence();
    let bytes = evidence.encode().expect("valid instruction evidence");
    assert_eq!(
        FaultInstructionEvidenceV1::decode(&bytes).expect("canonical instruction evidence"),
        evidence
    );
    let mut malformed = bytes;
    malformed[607] = 1;
    assert!(FaultInstructionEvidenceV1::decode(&malformed).is_err());
}

#[test]
fn suppressed_instruction_binds_mismatched_input_digest() {
    let mut evidence = skip_evidence();
    evidence.outcome = FaultInstructionEvidenceOutcomeV1::Suppressed;
    evidence.after_cpu_sha256 = evidence.before_cpu_sha256;
    evidence.after_ram_sha256 = evidence.before_ram_sha256;
    evidence.after_device_sha256 = evidence.before_device_sha256;
    evidence.after_ram_bytes = evidence.before_ram_bytes;
    evidence.after_device_bytes = evidence.before_device_bytes;
    evidence.after_state_sha256 = evidence.before_state_sha256;
    evidence.input_state_sha256 = Some([9; 32]);
    let bytes = evidence.encode().expect("valid suppressed evidence");
    assert_eq!(
        FaultInstructionEvidenceV1::decode(&bytes).expect("canonical suppressed evidence"),
        evidence
    );
}

#[test]
fn device_replay_requires_an_authenticated_completed_port_io_transcript() {
    let transcript = FaultInstructionPortIoEvidenceV1 {
        entries: vec![FaultInstructionPortIoEntryV1 {
            direction: FaultInstructionPortIoDirectionV1::Write,
            port: 0xe9,
            value: vec![b'X'],
            completed: true,
        }],
    };
    let encoded = transcript.encode().expect("valid port-I/O transcript");
    assert_eq!(
        FaultInstructionPortIoEvidenceV1::decode(&encoded)
            .expect("authenticated port-I/O transcript"),
        transcript
    );

    let mut evidence = skip_evidence();
    evidence.mutation_kind = FaultInstructionMutationKindV1::Replay;
    evidence.replay_total = 1;
    evidence.opcode_class = 0x0100_0008;
    evidence.flags = 1 << 5;
    evidence.detail = encoded.clone();
    assert!(evidence.encode().is_ok());

    let mut missing = evidence.clone();
    missing.detail.clear();
    assert!(missing.encode().is_err());

    let mut corrupted = evidence;
    let last = corrupted.detail.len() - 1;
    corrupted.detail[last] ^= 1;
    assert!(corrupted.encode().is_err());
}

#[test]
fn delivered_exception_round_trip_rejects_delivery_disagreement() {
    let evidence = FaultExceptionEvidenceV1 {
        architecture: FaultCapabilityScope::Aarch64,
        model_phase: 2,
        vcpu_index: 0,
        vector: 1,
        syndrome: 0x0200_0000,
        fault_address: None,
        before_instruction: true,
        command_icount: 11,
        delivered_icount: 11,
        entry_pc: 0x800,
        before_sha256: [1; 32],
        after_sha256: [2; 32],
    };
    let bytes = evidence.encode().expect("valid exception evidence");
    assert_eq!(
        FaultExceptionEvidenceV1::decode(&bytes).expect("canonical exception evidence"),
        evidence
    );
    let mut malformed = bytes;
    malformed[72] = 2;
    assert!(FaultExceptionEvidenceV1::decode(&malformed).is_err());
}
