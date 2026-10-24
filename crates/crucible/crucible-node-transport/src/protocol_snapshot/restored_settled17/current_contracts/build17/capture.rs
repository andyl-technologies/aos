//! Retains each exact raw-object field through later typed build errors.

use super::super::*;
use crate::protocol_snapshot::restored_settled17::current_build17::current_contract_builder17;

current_contract_builder17!(
    PacketRestoredSettledCaptureOutputLimits,
    PacketRestoredSettledCaptureOutputLimitsRaw17ReadAttempt,
    [
        native_snapshot_bytes,
        current_control_bytes,
        native_before_bytes,
        anchor_bytes,
        native_after_bytes
    ],
    {
        0 => native_snapshot_bytes: Plain17<U64>,
        1 => current_control_bytes: Plain17<U64>,
        2 => native_before_bytes: Plain17<U64>,
        3 => anchor_bytes: Plain17<U64>,
        4 => native_after_bytes: Plain17<U64>,
    }
);

current_contract_builder17!(
    PacketRestoredSettledCaptureRequest,
    PacketRestoredSettledCaptureRequestRaw17ReadAttempt,
    [
        schema,
        scope,
        capture,
        capture_owner,
        capture_operation,
        runtime_object,
        coordinator_checkpoint,
        parent_archive,
        first_observation,
        current_record,
        current_model,
        history_prefix,
        history_next_sequence,
        native_schema,
        native_allocation
    ],
    {
        0 => schema: Plain17<String>,
        1 => scope: CurrentDto17<PacketRestorationActivationScope>,
        2 => capture: CurrentDto17<CaptureArguments>,
        3 => capture_owner: Plain17<Id>,
        4 => capture_operation: Plain17<Id>,
        5 => runtime_object: Plain17<ContentRef>,
        6 => coordinator_checkpoint: Plain17<ContentRef>,
        7 => parent_archive: Plain17<ContentRef>,
        8 => first_observation: Plain17<ContentRef>,
        9 => current_record: Plain17<ContentRef>,
        10 => current_model: Plain17<ContentRef>,
        11 => history_prefix: Plain17<ContentRef>,
        12 => history_next_sequence: Plain17<U64>,
        13 => native_schema: Plain17<ContentRef>,
        14 => native_allocation: ScalarRow17,
    }
);

current_contract_builder17!(
    PacketRestoredSettledCaptureContext,
    PacketRestoredSettledCaptureContextRaw17ReadAttempt,
    [
        schema,
        request,
        assigned_request
    ],
    {
        0 => schema: Plain17<String>,
        1 => request: CurrentDto17<PacketRestoredSettledCaptureRequest>,
        2 => assigned_request: Plain17<Bytes>,
    }
);

current_contract_builder17!(
    PacketRestoredSettledCaptureArtifact,
    PacketRestoredSettledCaptureArtifactRaw17ReadAttempt,
    [
        request,
        proof
    ],
    {
        0 => request: CurrentDto17<PacketRestoredSettledCaptureRequest>,
        1 => proof: CurrentDto17<PacketRestorationActivationProof>,
    }
);

current_contract_builder17!(
    PacketRestoredSettledCaptureUploadRequest,
    PacketRestoredSettledCaptureUploadRequestRaw17ReadAttempt,
    [
        schema,
        capture,
        ordinal,
        transfer_id,
        content,
        native_allocation
    ],
    {
        0 => schema: Plain17<String>,
        1 => capture: CurrentDto17<PacketRestoredSettledCaptureRequest>,
        2 => ordinal: Inline17<PacketRestoredSettledCaptureUploadOrdinal>,
        3 => transfer_id: Plain17<Id>,
        4 => content: Plain17<ContentRef>,
        5 => native_allocation: ScalarRow17,
    }
);

current_contract_builder17!(
    PacketRestoredSettledCaptureUploadContext,
    PacketRestoredSettledCaptureUploadContextRaw17ReadAttempt,
    [
        schema,
        request,
        assigned_request
    ],
    {
        0 => schema: Plain17<String>,
        1 => request: CurrentDto17<PacketRestoredSettledCaptureUploadRequest>,
        2 => assigned_request: Plain17<Bytes>,
    }
);

current_contract_builder17!(
    PacketRestoredSettledCaptureUploadArtifact,
    PacketRestoredSettledCaptureUploadArtifactRaw17ReadAttempt,
    [
        request,
        proof
    ],
    {
        0 => request: CurrentDto17<PacketRestoredSettledCaptureUploadRequest>,
        1 => proof: CurrentDto17<PacketRestorationActivationProof>,
    }
);

current_contract_builder17!(
    PacketRestoredSettledCaptureUploadContinuation,
    PacketRestoredSettledCaptureUploadContinuationRaw17ReadAttempt,
    [
        schema,
        context_digest,
        capture_operation,
        transfer_id
    ],
    {
        0 => schema: Plain17<String>,
        1 => context_digest: Plain17<Bytes>,
        2 => capture_operation: Plain17<Id>,
        3 => transfer_id: Plain17<Id>,
    }
);

current_contract_builder17!(
    PacketRestoredSettledAfterConfirmationRequest,
    PacketRestoredSettledAfterConfirmationRequestRaw17ReadAttempt,
    [
        schema,
        capture_request_id,
        capture_request_hash,
        capture_operation_id,
        capture_terminal_hash,
        capture_terminal_sequence,
        settled_capture_request,
        native_snapshot_ref,
        native_control_ref,
        native_anchor_ref
    ],
    {
        0 => schema: Plain17<String>,
        1 => capture_request_id: Plain17<Id>,
        2 => capture_request_hash: Plain17<HashRef>,
        3 => capture_operation_id: Plain17<Id>,
        4 => capture_terminal_hash: Plain17<HashRef>,
        5 => capture_terminal_sequence: Plain17<U64>,
        6 => settled_capture_request: Plain17<ContentRef>,
        7 => native_snapshot_ref: Plain17<ContentRef>,
        8 => native_control_ref: Plain17<ContentRef>,
        9 => native_anchor_ref: Plain17<ContentRef>,
    }
);
