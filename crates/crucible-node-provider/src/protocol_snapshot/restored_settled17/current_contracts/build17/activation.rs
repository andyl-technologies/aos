//! Retains each exact raw-object field through later typed build errors.

use super::super::*;
use crate::protocol_snapshot::restored_settled17::current_build17::current_contract_builder17;

current_contract_builder17!(
    PacketRestorationActivationAllocationRow,
    PacketRestorationActivationAllocationRowRaw17ReadAttempt,
    [
        retained_requested_bytes,
        maximum_simultaneous_transient_bytes,
        declared_counter_scratch_bytes
    ],
    {
        0 => retained_requested_bytes: Plain17<U64>,
        1 => maximum_simultaneous_transient_bytes: Plain17<U64>,
        2 => declared_counter_scratch_bytes: Plain17<U64>,
    }
);

current_contract_builder17!(
    PacketRestorationActivationTarget,
    PacketRestorationActivationTargetRaw17ReadAttempt,
    [
        native_pid,
        session,
        incarnation,
        node,
        owner,
        owner_generation,
        binding_hash,
        world,
        activation,
        generation,
        prepared_token,
        gate,
        admission,
        transaction
    ],
    {
        0 => native_pid: Plain17<U64>,
        1 => session: Plain17<Id>,
        2 => incarnation: Plain17<Id>,
        3 => node: Plain17<Id>,
        4 => owner: Plain17<Id>,
        5 => owner_generation: Plain17<U64>,
        6 => binding_hash: Plain17<HashRef>,
        7 => world: Plain17<HashRef>,
        8 => activation: Plain17<Id>,
        9 => generation: Plain17<U64>,
        10 => prepared_token: Plain17<Id>,
        11 => gate: Plain17<Id>,
        12 => admission: Plain17<Id>,
        13 => transaction: Plain17<Id>,
    }
);

current_contract_builder17!(
    PacketRestorationActivationOriginals,
    PacketRestorationActivationOriginalsRaw17ReadAttempt,
    [
        captured_owner_state,
        captured_control,
        captured_journal,
        mapping,
        commit_request,
        commit_response,
        context_digest
    ],
    {
        0 => captured_owner_state: Plain17<ContentRef>,
        1 => captured_control: Plain17<ContentRef>,
        2 => captured_journal: Plain17<ContentRef>,
        3 => mapping: Plain17<ContentRef>,
        4 => commit_request: Plain17<ContentRef>,
        5 => commit_response: Plain17<ContentRef>,
        6 => context_digest: Plain17<Bytes>,
    }
);

current_contract_builder17!(
    PacketRestorationActivationScope,
    PacketRestorationActivationScopeRaw17ReadAttempt,
    [
        source_birth,
        source_runtime,
        scope_proof,
        target,
        restoration
    ],
    {
        0 => source_birth: Plain17<ContentRef>,
        1 => source_runtime: Plain17<ContentRef>,
        2 => scope_proof: Plain17<ContentRef>,
        3 => target: CurrentDto17<PacketRestorationActivationTarget>,
        4 => restoration: CurrentDto17<PacketRestorationActivationOriginals>,
    }
);

current_contract_builder17!(
    PacketRestorationActivationRequest,
    PacketRestorationActivationRequestRaw17ReadAttempt,
    [
        schema,
        phase,
        scope,
        native_allocation
    ],
    {
        0 => schema: Plain17<String>,
        1 => phase: Inline17<PacketRestorationActivationPhase>,
        2 => scope: CurrentDto17<PacketRestorationActivationScope>,
        3 => native_allocation: CurrentDto17<PacketRestorationActivationAllocationRow>,
    }
);

current_contract_builder17!(
    PacketRestorationActivationContext,
    PacketRestorationActivationContextRaw17ReadAttempt,
    [
        request,
        assigned_request
    ],
    {
        0 => request: CurrentDto17<PacketRestorationActivationRequest>,
        1 => assigned_request: Plain17<Bytes>,
    }
);

current_contract_builder17!(
    PacketRestorationActivationProof,
    PacketRestorationActivationProofRaw17ReadAttempt,
    [
        schema,
        algorithm,
        context_digest,
        mac
    ],
    {
        0 => schema: Plain17<String>,
        1 => algorithm: Plain17<String>,
        2 => context_digest: Plain17<Bytes>,
        3 => mac: Plain17<Bytes>,
    }
);

current_contract_builder17!(
    PacketRestorationActivationArtifact,
    PacketRestorationActivationArtifactRaw17ReadAttempt,
    [
        request,
        proof
    ],
    {
        0 => request: CurrentDto17<PacketRestorationActivationRequest>,
        1 => proof: CurrentDto17<PacketRestorationActivationProof>,
    }
);

current_contract_builder17!(
    PacketRestorationActivationUploadRequest,
    PacketRestorationActivationUploadRequestRaw17ReadAttempt,
    [
        schema,
        scope,
        role,
        coordinator,
        manifest,
        maximum_frame_bytes,
        chunk_bytes,
        maximum_requests,
        native_allocation
    ],
    {
        0 => schema: Plain17<String>,
        1 => scope: CurrentDto17<PacketRestorationActivationScope>,
        2 => role: Inline17<PacketRestorationActivationUploadRole>,
        3 => coordinator: Plain17<ContentRef>,
        4 => manifest: Plain17<ContentRef>,
        5 => maximum_frame_bytes: Plain17<U64>,
        6 => chunk_bytes: Plain17<U64>,
        7 => maximum_requests: Plain17<U64>,
        8 => native_allocation: CurrentDto17<PacketRestorationActivationAllocationRow>,
    }
);

current_contract_builder17!(
    PacketRestorationActivationUploadContext,
    PacketRestorationActivationUploadContextRaw17ReadAttempt,
    [
        request,
        assigned_request
    ],
    {
        0 => request: CurrentDto17<PacketRestorationActivationUploadRequest>,
        1 => assigned_request: Plain17<Bytes>,
    }
);

current_contract_builder17!(
    PacketRestorationActivationUploadArtifact,
    PacketRestorationActivationUploadArtifactRaw17ReadAttempt,
    [
        request,
        proof
    ],
    {
        0 => request: CurrentDto17<PacketRestorationActivationUploadRequest>,
        1 => proof: CurrentDto17<PacketRestorationActivationProof>,
    }
);
