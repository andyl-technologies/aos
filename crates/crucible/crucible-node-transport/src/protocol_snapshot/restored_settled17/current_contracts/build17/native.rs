//! Retains each exact raw-object field through later typed build errors.

use super::super::*;
use crate::protocol_snapshot::restored_settled17::current_build17::current_contract_builder17;

current_contract_builder17!(
    PacketNativeRestoredCommitHold,
    PacketNativeRestoredCommitHoldRaw17ReadAttempt,
    [
        schema,
        native_pid,
        target_world,
        target_owner,
        target_owner_binding,
        target_activation,
        target_generation,
        captured_owner_state,
        captured_control,
        captured_journal,
        mapping,
        restore_commit,
        context_digest,
        local_cursor,
        inventory_hash,
        physical_gate_held
    ],
    {
        0 => schema: Plain17<String>,
        1 => native_pid: Plain17<U64>,
        2 => target_world: Plain17<crucible_node_format::HashRef>,
        3 => target_owner: Plain17<Id>,
        4 => target_owner_binding: Plain17<crucible_node_format::HashRef>,
        5 => target_activation: Plain17<Id>,
        6 => target_generation: Plain17<U64>,
        7 => captured_owner_state: Plain17<ContentRef>,
        8 => captured_control: Plain17<ContentRef>,
        9 => captured_journal: Plain17<ContentRef>,
        10 => mapping: Plain17<ContentRef>,
        11 => restore_commit: Plain17<ContentRef>,
        12 => context_digest: Plain17<Bytes>,
        13 => local_cursor: Plain17<Position>,
        14 => inventory_hash: Plain17<crucible_node_format::HashRef>,
        15 => physical_gate_held: Plain17<bool>,
    }
);

current_contract_builder17!(
    InstalledContent,
    InstalledContentRaw17ReadAttempt,
    [
        reference,
        bytes
    ],
    {
        0 => reference: Plain17<ContentRef>,
        1 => bytes: Plain17<Bytes>,
    }
);

current_contract_builder17!(
    PacketRestoredSuffixReservationData,
    PacketRestoredSuffixReservationDataRaw17ReadAttempt,
    [
        maximum_originals,
        ingress,
        actions
    ],
    {
        0 => maximum_originals: Plain17<U64>,
        1 => ingress: ScalarRow17,
        2 => actions: ScalarRow17,
    }
);

current_contract_builder17!(
    PacketRestoredSettledNativeCarrierData,
    PacketRestoredSettledNativeCarrierDataRaw17ReadAttempt,
    [
        version,
        launch_identity,
        import_identity,
        normalization_maximum,
        maximum_originals,
        ingress,
        actions,
        output_limits
    ],
    {
        0 => version: Plain17<U64>,
        1 => launch_identity: FixedArray32Field17,
        2 => import_identity: FixedArray32Field17,
        3 => normalization_maximum: Plain17<U64>,
        4 => maximum_originals: Plain17<U64>,
        5 => ingress: ScalarRow17,
        6 => actions: ScalarRow17,
        7 => output_limits: CurrentDto17<PacketRestoredSettledCaptureOutputLimits>,
    }
);

current_contract_builder17!(
    PacketRestoredSettledNativeExistingRowsData,
    PacketRestoredSettledNativeExistingRowsDataRaw17ReadAttempt,
    [
        native_birth,
        restore_prepare,
        suffix
    ],
    {
        0 => native_birth: ScalarRow17,
        1 => restore_prepare: Optional17<ScalarRow17>,
        2 => suffix: CurrentDto17<PacketRestoredSuffixReservationData>,
    }
);

current_contract_builder17!(
    PacketNative5StorageSelection,
    PacketNative5StorageSelectionRaw17ReadAttempt,
    [
        storage,
        limits
    ],
    {
        0 => storage: CurrentDto17<PacketNative5StorageLimits>,
        1 => limits: Plain17<Limits>,
    }
);

current_contract_builder17!(
    PacketConnectedNativeRecord,
    PacketConnectedNativeRecordRaw17ReadAttempt,
    [
        schema,
        native_pid,
        original,
        inventory,
        grant
    ],
    {
        0 => schema: Plain17<String>,
        1 => native_pid: Plain17<U64>,
        2 => original: Plain17<Envelope>,
        3 => inventory: Plain17<PacketConnectedInventory>,
        4 => grant: Plain17<Option<PacketConnectedGrant>>,
    }
);

current_contract_builder17!(
    PacketNativeRestoredRecord,
    PacketNativeRestoredRecordRaw17ReadAttempt,
    [
        schema,
        native_receipt,
        captured_owner_state,
        captured_journal,
        mapping,
        restore_commit,
        restore_response,
        context_digest,
        physical_gate_held
    ],
    {
        0 => schema: Plain17<String>,
        1 => native_receipt: CurrentDto17<PacketNative5Record>,
        2 => captured_owner_state: Plain17<ContentRef>,
        3 => captured_journal: Plain17<ContentRef>,
        4 => mapping: Plain17<ContentRef>,
        5 => restore_commit: Plain17<ContentRef>,
        6 => restore_response: Plain17<ContentRef>,
        7 => context_digest: Plain17<Bytes>,
        8 => physical_gate_held: Plain17<bool>,
    }
);

current_contract_builder17!(
    PacketProgramDefinition,
    PacketProgramDefinitionRaw17ReadAttempt,
    [
        schema,
        events
    ],
    {
        0 => schema: Plain17<String>,
        1 => events: Plain17<Vec<PacketEvent>>,
    }
);

current_contract_builder17!(
    PacketNative5StorageLimits,
    PacketNative5StorageLimitsRaw17ReadAttempt,
    [
        snapshot_bytes,
        control_snapshot_bytes,
        protocol_snapshot_bytes,
        frame_bank_bytes,
        frames_per_direction,
        hello_bytes,
        settlement_bytes
    ],
    {
        0 => snapshot_bytes: Plain17<U64>,
        1 => control_snapshot_bytes: Plain17<U64>,
        2 => protocol_snapshot_bytes: Plain17<U64>,
        3 => frame_bank_bytes: Plain17<U64>,
        4 => frames_per_direction: Plain17<U64>,
        5 => hello_bytes: Plain17<U64>,
        6 => settlement_bytes: Plain17<U64>,
    }
);
