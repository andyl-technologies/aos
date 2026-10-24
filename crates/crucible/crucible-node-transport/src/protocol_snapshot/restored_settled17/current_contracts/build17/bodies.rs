//! Retains each exact raw-object field through later typed build errors.

use super::super::*;
use crate::protocol_snapshot::restored_settled17::current_build17::current_contract_builder17;

current_contract_builder17!(
    InputRequest,
    InputRequestRaw17ReadAttempt,
    [
        binding_hash,
        owner_generation,
        batch_id,
        batch_sequence,
        input_epoch,
        events,
        batch_hash,
        extensions
    ],
    {
        0 => binding_hash: Plain17<HashRef>,
        1 => owner_generation: Plain17<U64>,
        2 => batch_id: Plain17<Id>,
        3 => batch_sequence: Plain17<U64>,
        4 => input_epoch: Plain17<Id>,
        5 => events: Plain17<Vec<Event>>,
        6 => batch_hash: Plain17<HashRef>,
        7 => extensions: Plain17<Extensions>,
    }
);

current_contract_builder17!(
    BeginRequest,
    BeginRequestRaw17ReadAttempt,
    [
        kind,
        binding_hash,
        owner_generation,
        activation_id,
        world_generation,
        arguments,
        extensions
    ],
    {
        0 => kind: Plain17<BeginKind>,
        1 => binding_hash: Plain17<HashRef>,
        2 => owner_generation: Plain17<U64>,
        3 => activation_id: Plain17<Nullable<Id>>,
        4 => world_generation: Plain17<U64>,
        5 => arguments: Plain17<Map<String, Value>>,
        6 => extensions: Plain17<Extensions>,
    }
);

current_contract_builder17!(
    PollRequest,
    PollRequestRaw17ReadAttempt,
    [
        after_observation_sequence,
        extensions
    ],
    {
        0 => after_observation_sequence: Plain17<U64>,
        1 => extensions: Plain17<Extensions>,
    }
);

current_contract_builder17!(
    RetireRequest,
    RetireRequestRaw17ReadAttempt,
    [
        request_ids,
        operation_ids,
        disposition,
        custody_receipt,
        extensions
    ],
    {
        0 => request_ids: Plain17<IdSet>,
        1 => operation_ids: Plain17<IdSet>,
        2 => disposition: Inline17<RetirementDisposition>,
        3 => custody_receipt: Plain17<Nullable<ContentRef>>,
        4 => extensions: Plain17<Extensions>,
    }
);

current_contract_builder17!(
    ObserveRequest,
    ObserveRequestRaw17ReadAttempt,
    [
        binding_hash,
        owner_generation,
        after_observation_sequence,
        maximum_items,
        extensions
    ],
    {
        0 => binding_hash: Plain17<HashRef>,
        1 => owner_generation: Plain17<U64>,
        2 => after_observation_sequence: Plain17<U64>,
        3 => maximum_items: Plain17<U64>,
        4 => extensions: Plain17<Extensions>,
    }
);

current_contract_builder17!(
    BlobBeginRequest,
    BlobBeginRequestRaw17ReadAttempt,
    [
        transfer_id,
        content,
        extensions
    ],
    {
        0 => transfer_id: Plain17<Id>,
        1 => content: Plain17<ContentRef>,
        2 => extensions: Plain17<Extensions>,
    }
);

current_contract_builder17!(
    BlobChunkRequest,
    BlobChunkRequestRaw17ReadAttempt,
    [
        transfer_id,
        offset,
        bytes,
        extensions
    ],
    {
        0 => transfer_id: Plain17<Id>,
        1 => offset: Plain17<U64>,
        2 => bytes: Plain17<Bytes>,
        3 => extensions: Plain17<Extensions>,
    }
);

current_contract_builder17!(
    BlobFinishRequest,
    BlobFinishRequestRaw17ReadAttempt,
    [
        transfer_id,
        extensions
    ],
    {
        0 => transfer_id: Plain17<Id>,
        1 => extensions: Plain17<Extensions>,
    }
);

current_contract_builder17!(
    ExactRunArguments,
    ExactRunArgumentsRaw17ReadAttempt,
    [
        grant_id,
        participant_ids,
        realization_id,
        activation_id,
        world_generation,
        owner_generation,
        input_epoch,
        mode,
        ordering_profile,
        start,
        limit,
        boundary_policy,
        input_authorization,
        input_watermark
    ],
    {
        0 => grant_id: Plain17<Id>,
        1 => participant_ids: Plain17<IdSet>,
        2 => realization_id: Plain17<Id>,
        3 => activation_id: Plain17<Id>,
        4 => world_generation: Plain17<U64>,
        5 => owner_generation: Plain17<U64>,
        6 => input_epoch: Plain17<Id>,
        7 => mode: Plain17<OperatingMode>,
        8 => ordering_profile: Plain17<String>,
        9 => start: Plain17<Position>,
        10 => limit: Plain17<Position>,
        11 => boundary_policy: Inline17<BoundaryPolicy>,
        12 => input_authorization: Plain17<ContentRef>,
        13 => input_watermark: Plain17<U64>,
    }
);

current_contract_builder17!(
    CaptureArguments,
    CaptureArgumentsRaw17ReadAttempt,
    [
        capture_id,
        participant_ids,
        cut_id,
        cut,
        event_ordinal,
        ordering_profile,
        preservation_contract
    ],
    {
        0 => capture_id: Plain17<Id>,
        1 => participant_ids: Plain17<IdSet>,
        2 => cut_id: Plain17<Id>,
        3 => cut: Plain17<Position>,
        4 => event_ordinal: Plain17<U64>,
        5 => ordering_profile: Plain17<String>,
        6 => preservation_contract: Plain17<Id>,
    }
);
