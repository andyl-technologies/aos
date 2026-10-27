//! Retains each exact raw-object field through later typed build errors.

use super::super::*;
use crate::protocol_snapshot::restored_settled17::current_build17::current_contract_builder17;

current_contract_builder17!(
    PacketCompleteRestoreRequest,
    PacketCompleteRestoreRequestRaw17ReadAttempt,
    [
        schema,
        archive_index,
        capture_manifest,
        owner_state,
        journal,
        source_runtime,
        backend_implementation,
        backend_schema,
        archived_cut,
        archived_ordinal,
        target_world,
        target_owner,
        target_owner_binding,
        target_activation,
        target_generation,
        target_owner_generation,
        mapping,
        nonce
    ],
    {
        0 => schema: Plain17<String>,
        1 => archive_index: Plain17<ContentRef>,
        2 => capture_manifest: Plain17<ContentRef>,
        3 => owner_state: Plain17<ContentRef>,
        4 => journal: Plain17<ContentRef>,
        5 => source_runtime: Plain17<ContentRef>,
        6 => backend_implementation: Plain17<ContentRef>,
        7 => backend_schema: Plain17<SchemaRef>,
        8 => archived_cut: Plain17<Position>,
        9 => archived_ordinal: Plain17<U64>,
        10 => target_world: Plain17<HashRef>,
        11 => target_owner: Plain17<Id>,
        12 => target_owner_binding: Plain17<HashRef>,
        13 => target_activation: Plain17<Id>,
        14 => target_generation: Plain17<U64>,
        15 => target_owner_generation: Plain17<U64>,
        16 => mapping: Plain17<ContentRef>,
        17 => nonce: Plain17<Bytes>,
    }
);

current_contract_builder17!(
    PacketCompleteRestoreContext,
    PacketCompleteRestoreContextRaw17ReadAttempt,
    [
        schema,
        algorithm,
        source_birth,
        kernel_binding,
        policy_binding,
        host_registration,
        native_registration,
        hello_request,
        hello_response,
        assigned_restore,
        archive_binding,
        target_binding,
        mapping_binding,
        request_binding
    ],
    {
        0 => schema: Plain17<String>,
        1 => algorithm: Plain17<String>,
        2 => source_birth: Plain17<Bytes>,
        3 => kernel_binding: Plain17<Bytes>,
        4 => policy_binding: Plain17<Bytes>,
        5 => host_registration: Plain17<Bytes>,
        6 => native_registration: Plain17<Bytes>,
        7 => hello_request: Plain17<Bytes>,
        8 => hello_response: Plain17<Bytes>,
        9 => assigned_restore: Plain17<Bytes>,
        10 => archive_binding: Plain17<Bytes>,
        11 => target_binding: Plain17<Bytes>,
        12 => mapping_binding: Plain17<Bytes>,
        13 => request_binding: Plain17<Bytes>,
    }
);

current_contract_builder17!(
    PacketCompleteRestoreInputAllocation,
    PacketCompleteRestoreInputAllocationRaw17ReadAttempt,
    [
        maximum_known_requested_bytes,
        maximum_input_bytes,
        maximum_nodes,
        maximum_depth,
        maximum_owned_backing_bytes,
        maximum_tree_entries,
        maximum_metadata_rows,
        maximum_literal_backing_bytes,
        maximum_content_transfers,
        maximum_content_objects,
        maximum_content_groups,
        maximum_content_bytes,
        maximum_content_metadata_bytes,
        maximum_model_bytes
    ],
    {
        0 => maximum_known_requested_bytes: Plain17<U64>,
        1 => maximum_input_bytes: Plain17<U64>,
        2 => maximum_nodes: Plain17<U64>,
        3 => maximum_depth: Plain17<U64>,
        4 => maximum_owned_backing_bytes: Plain17<U64>,
        5 => maximum_tree_entries: Plain17<U64>,
        6 => maximum_metadata_rows: Plain17<U64>,
        7 => maximum_literal_backing_bytes: Plain17<U64>,
        8 => maximum_content_transfers: Plain17<U64>,
        9 => maximum_content_objects: Plain17<U64>,
        10 => maximum_content_groups: Plain17<U64>,
        11 => maximum_content_bytes: Plain17<U64>,
        12 => maximum_content_metadata_bytes: Plain17<U64>,
        13 => maximum_model_bytes: Plain17<U64>,
    }
);

current_contract_builder17!(
    PacketCompleteRestorePrepareRequest,
    PacketCompleteRestorePrepareRequestRaw17ReadAttempt,
    [
        schema,
        restoration,
        host_protocol,
        native_protocol,
        native_control,
        native_anchor,
        transaction_id,
        generation,
        allocation
    ],
    {
        0 => schema: Plain17<String>,
        1 => restoration: CurrentDto17<PacketCompleteRestoreRequest>,
        2 => host_protocol: Plain17<ContentRef>,
        3 => native_protocol: Plain17<ContentRef>,
        4 => native_control: Plain17<ContentRef>,
        5 => native_anchor: Plain17<ContentRef>,
        6 => transaction_id: Plain17<Id>,
        7 => generation: Plain17<U64>,
        8 => allocation: CurrentDto17<PacketCompleteRestoreInputAllocation>,
    }
);

current_contract_builder17!(
    PacketCompleteRestorePrepareContext,
    PacketCompleteRestorePrepareContextRaw17ReadAttempt,
    [
        schema,
        algorithm,
        source_birth,
        kernel_binding,
        policy_binding,
        host_registration,
        native_registration,
        hello_request,
        hello_response,
        assigned_prepare,
        prepare_request,
        input_roster
    ],
    {
        0 => schema: Plain17<String>,
        1 => algorithm: Plain17<String>,
        2 => source_birth: Plain17<Bytes>,
        3 => kernel_binding: Plain17<Bytes>,
        4 => policy_binding: Plain17<Bytes>,
        5 => host_registration: Plain17<Bytes>,
        6 => native_registration: Plain17<Bytes>,
        7 => hello_request: Plain17<Bytes>,
        8 => hello_response: Plain17<Bytes>,
        9 => assigned_prepare: Plain17<Bytes>,
        10 => prepare_request: Plain17<Bytes>,
        11 => input_roster: Plain17<Bytes>,
    }
);

current_contract_builder17!(
    PacketCompleteRestoreTransferProof,
    PacketCompleteRestoreTransferProofRaw17ReadAttempt,
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
    PacketCompleteRestoreCommitRequest,
    PacketCompleteRestoreCommitRequestRaw17ReadAttempt,
    [
        schema,
        prepare,
        capture_terminal,
        prepare_request_id,
        prepare_request_sequence,
        prepare_request_digest,
        prepare_response_sequence,
        prepare_response_digest,
        transfer_token
    ],
    {
        0 => schema: Plain17<String>,
        1 => prepare: CurrentDto17<PacketCompleteRestorePrepareRequest>,
        2 => capture_terminal: Plain17<Envelope>,
        3 => prepare_request_id: Plain17<Id>,
        4 => prepare_request_sequence: Plain17<U64>,
        5 => prepare_request_digest: Plain17<Bytes>,
        6 => prepare_response_sequence: Plain17<U64>,
        7 => prepare_response_digest: Plain17<Bytes>,
        8 => transfer_token: Plain17<Bytes>,
    }
);

current_contract_builder17!(
    PacketCompleteRestoreCommitContext,
    PacketCompleteRestoreCommitContextRaw17ReadAttempt,
    [
        schema,
        algorithm,
        restoration,
        commit_request,
        prepare_request,
        prepare_response,
        transfer_token,
        input_roster
    ],
    {
        0 => schema: Plain17<String>,
        1 => algorithm: Plain17<String>,
        2 => restoration: CurrentDto17<PacketCompleteRestoreContext>,
        3 => commit_request: Plain17<Bytes>,
        4 => prepare_request: Plain17<Bytes>,
        5 => prepare_response: Plain17<Bytes>,
        6 => transfer_token: Plain17<Bytes>,
        7 => input_roster: Plain17<Bytes>,
    }
);

current_contract_builder17!(
    PacketCanonicalAckAdmissionContext,
    PacketCanonicalAckAdmissionContextRaw17ReadAttempt,
    [
        schema,
        algorithm,
        source_birth,
        kernel_binding,
        policy_binding,
        host_registration,
        native_registration,
        hello_request,
        hello_response,
        assigned_admit
    ],
    {
        0 => schema: Plain17<String>,
        1 => algorithm: Plain17<String>,
        2 => source_birth: Plain17<Bytes>,
        3 => kernel_binding: Plain17<Bytes>,
        4 => policy_binding: Plain17<Bytes>,
        5 => host_registration: Plain17<Bytes>,
        6 => native_registration: Plain17<Bytes>,
        7 => hello_request: Plain17<Bytes>,
        8 => hello_response: Plain17<Bytes>,
        9 => assigned_admit: Plain17<Bytes>,
    }
);

current_contract_builder17!(
    PacketCanonicalAckAdmissionProof,
    PacketCanonicalAckAdmissionProofRaw17ReadAttempt,
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
    PrepareRestoreResult,
    PrepareRestoreResultRaw17ReadAttempt,
    [
        transaction_id,
        prepared_token,
        world_binding_hash,
        owner_binding_hash,
        staged_owner_ids,
        closed_gate_receipt,
        validated_manifest
    ],
    {
        0 => transaction_id: Plain17<Id>,
        1 => prepared_token: Plain17<Id>,
        2 => world_binding_hash: Plain17<HashRef>,
        3 => owner_binding_hash: Plain17<HashRef>,
        4 => staged_owner_ids: Plain17<IdSet>,
        5 => closed_gate_receipt: Plain17<ContentRef>,
        6 => validated_manifest: Plain17<ContentRef>,
    }
);
