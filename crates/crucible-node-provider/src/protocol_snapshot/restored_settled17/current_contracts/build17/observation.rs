//! Retains each exact raw-object field through later typed build errors.

use super::super::*;
use crate::protocol_snapshot::restored_settled17::current_build17::current_contract_builder17;

current_contract_builder17!(
    PacketRestorationObservationRequest,
    PacketRestorationObservationRequestRaw17ReadAttempt,
    [
        schema,
        scope,
        world_original,
        world_terminal,
        maximum_items,
        native_allocation
    ],
    {
        0 => schema: Plain17<String>,
        1 => scope: CurrentDto17<PacketRestorationActivationScope>,
        2 => world_original: Plain17<ContentRef>,
        3 => world_terminal: Plain17<ContentRef>,
        4 => maximum_items: Plain17<U64>,
        5 => native_allocation: CurrentDto17<PacketRestorationActivationAllocationRow>,
    }
);

current_contract_builder17!(
    PacketRestorationObservationContext,
    PacketRestorationObservationContextRaw17ReadAttempt,
    [
        request,
        assigned_request
    ],
    {
        0 => request: CurrentDto17<PacketRestorationObservationRequest>,
        1 => assigned_request: Plain17<Bytes>,
    }
);

current_contract_builder17!(
    PacketRestorationObservationProof,
    PacketRestorationObservationProofRaw17ReadAttempt,
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
    PacketRestorationObservationArtifact,
    PacketRestorationObservationArtifactRaw17ReadAttempt,
    [
        request,
        proof
    ],
    {
        0 => request: CurrentDto17<PacketRestorationObservationRequest>,
        1 => proof: CurrentDto17<PacketRestorationObservationProof>,
    }
);
