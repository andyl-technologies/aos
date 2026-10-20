//! Retains each exact raw-object field through later typed build errors.

use super::super::*;
use crate::protocol_snapshot::restored_settled17::current_build17::current_contract_builder17;

current_contract_builder17!(
    ActivationManifest,
    ActivationManifestRaw17ReadAttempt,
    [
        schema_version,
        transaction_id,
        activation_id,
        world_generation,
        gate_id,
        world_binding_hash,
        owners,
        coordinator_state_ref,
        extensions
    ],
    {
        0 => schema_version: Plain17<Version>,
        1 => transaction_id: Plain17<Id>,
        2 => activation_id: Plain17<Id>,
        3 => world_generation: Plain17<U64>,
        4 => world_binding_hash: Plain17<HashRef>,
        5 => gate_id: Plain17<Id>,
        6 => owners: Vector17<CurrentDto17<PreparedOwner>>,
        7 => coordinator_state_ref: Plain17<ContentRef>,
        8 => extensions: Plain17<Extensions>,
    }
);

current_contract_builder17!(
    PreparedOwner,
    PreparedOwnerRaw17ReadAttempt,
    [
        owner_id,
        incarnation_id,
        owner_generation,
        prepared_token,
        binding_hashes,
        ready_receipt,
        extensions
    ],
    {
        0 => owner_id: Plain17<Id>,
        1 => incarnation_id: Plain17<Id>,
        2 => owner_generation: Plain17<U64>,
        3 => binding_hashes: Plain17<Vec<HashRef>>,
        4 => prepared_token: Plain17<Id>,
        5 => ready_receipt: Plain17<ContentRef>,
        6 => extensions: Plain17<Extensions>,
    }
);
