//! Retains each exact raw-object field through later typed build errors.

use super::super::*;
use crate::protocol_snapshot::restored_settled17::current_build17::current_contract_builder17;

current_contract_builder17!(
    PacketInputCut,
    PacketInputCutRaw17ReadAttempt,
    [
        schema_version,
        session_id,
        incarnation_id,
        node_id,
        execution_owner_id,
        owner_generation,
        activation_id,
        world_generation,
        world_binding_hash,
        stage_operation_id,
        batch_id,
        batch_sequence,
        input_epoch,
        batch_hash,
        delivery_inventory,
        cutoff
    ],
    {
        0 => schema_version: Plain17<u16>,
        1 => session_id: Plain17<Id>,
        2 => incarnation_id: Plain17<Id>,
        3 => node_id: Plain17<Id>,
        4 => execution_owner_id: Plain17<Id>,
        5 => owner_generation: Plain17<U64>,
        6 => activation_id: Plain17<Id>,
        7 => world_generation: Plain17<U64>,
        8 => world_binding_hash: Plain17<HashRef>,
        9 => stage_operation_id: Plain17<Id>,
        10 => batch_id: Plain17<Id>,
        11 => batch_sequence: Plain17<U64>,
        12 => input_epoch: Plain17<Id>,
        13 => batch_hash: Plain17<HashRef>,
        14 => delivery_inventory: Plain17<ContentRef>,
        15 => cutoff: Plain17<Position>,
    }
);

current_contract_builder17!(
    PacketRestoredInputReactive17Request,
    PacketRestoredInputReactive17RequestRaw17ReadAttempt,
    [
        schema,
        command,
        scope,
        first_observation,
        current_record,
        current_model,
        history_prefix,
        history_next_sequence,
        native_allocation
    ],
    {
        0 => schema: Plain17<String>,
        1 => command: CurrentInputCommand17,
        2 => scope: CurrentDto17<PacketRestorationActivationScope>,
        3 => first_observation: Plain17<ContentRef>,
        4 => current_record: Plain17<ContentRef>,
        5 => current_model: Plain17<ContentRef>,
        6 => history_prefix: Plain17<ContentRef>,
        7 => history_next_sequence: Plain17<U64>,
        8 => native_allocation: ScalarRow17,
    }
);

current_contract_builder17!(
    PacketRestoredInputReactive17Context,
    PacketRestoredInputReactive17ContextRaw17ReadAttempt,
    [
        schema,
        request,
        assigned_request
    ],
    {
        0 => schema: Plain17<String>,
        1 => request: CurrentDto17<PacketRestoredInputReactive17Request>,
        2 => assigned_request: Plain17<Bytes>,
    }
);

current_contract_builder17!(
    PacketRestoredInputReactive17Artifact,
    PacketRestoredInputReactive17ArtifactRaw17ReadAttempt,
    [
        request,
        proof
    ],
    {
        0 => request: CurrentDto17<PacketRestoredInputReactive17Request>,
        1 => proof: CurrentDto17<PacketRestorationActivationProof>,
    }
);
