//! Shares exact operation-plan bounds and ordered admission row construction.
//!
//! Lexical expansion adds no callbacks, owning adapter or protected role. The
//! native caller alone retains its ownership/runtime stage at the same slot.

/// Checks the original ordinary plan shape with its concrete error projection.
#[macro_export]
macro_rules! require_operation_plan_shape_data_v3 {
    ($operation_id:expr, $desired_key:expr, $desired_value:expr, $effects:expr, $invalid:path) => {{
        if $operation_id.as_bytes() == &[0; 16]
            || $desired_key.is_empty()
            || $desired_value.is_empty()
            || $effects.is_empty()
            || $effects.len() > $crate::domain_ledger::operation::MAXIMUM_EFFECTS
            || $effects.iter().any(|effect| effect.authority().is_some())
        {
            return Err($invalid("invalid operation plan"));
        }
    }};
}

/// Checks the original public metadata/atomic-row bound without admission.
#[macro_export]
macro_rules! require_public_operation_shape_data_v3 {
    ($effects:expr, $local_records:expr, $public_operation:expr,
     $maximum_effects:expr, $invalid:path) => {{
        let atomic_records = $effects
            .len()
            .checked_add($local_records.len())
            .ok_or($invalid(
                "public operation metadata exceeds admission bounds",
            ))?;
        if $public_operation.is_some() || atomic_records > $maximum_effects {
            return Err($invalid(
                "public operation metadata is duplicate or exceeds admission bounds",
            ));
        }
    }};
}

/// Builds the sole ordered admission record sequence around a native stage.
#[macro_export]
macro_rules! prepare_admission_records_data_v3 {
    (plan: $plan:ident, records: $records:ident, ownership_gated: $ownership_gated:expr,
     runtime_digest: $runtime_digest:expr, accepted_start: $accepted_start:expr,
     invalid: $invalid:path, effect_error: $effect_error:path,
     ownership_records: { $($ownership_records:tt)* }) => {{

    let effect_count = u32::try_from($plan.effects.len())
        .map_err(|_| $invalid("too many effects"))?;
    let mut $records = Vec::with_capacity(
        $plan.effects.len()
            + $plan.local_records.len()
            + 3
            + usize::from($ownership_gated)
            + usize::from($plan.public_operation.is_some()),
    );
    $records.push(JournalRecord::put(
        RecordNamespace::DesiredState,
        $plan.desired_key.clone(),
        $plan.desired_value.clone(),
    ));
    let operation = OperationRecord::new(
        if $plan.effects.is_empty() && !$plan.local_records.is_empty() {
            OperationState::Succeeded
        } else if $ownership_gated {
            OperationState::OwnershipPending
        } else {
            OperationState::Accepted
        },
        effect_count,
        $ownership_gated,
        $runtime_digest,
        $plan.public_operation.as_ref().map(|public| {
            if $plan.effects.is_empty() {
                public.durable_completed()
            } else {
                public.durable()
            }
        }),
    );
    let operation = match $accepted_start {
        Some(origin) => operation.with_accepted_start_origin_v1(origin),
        None => operation,
    };
    $records.push(JournalRecord::put(
        RecordNamespace::Operation,
        $plan.operation_id.into_bytes().to_vec(),
        encode_operation_record(operation),
    ));
    $records.push(JournalRecord::idempotency(
        &$plan.idempotency_key,
        $plan.request_digest,
        $plan.operation_id,
    ));
    if let Some(public) = &$plan.public_operation {
        $records.push(JournalRecord::put(
            RecordNamespace::PublicOperationAuthorization,
            $plan.operation_id.into_bytes().to_vec(),
            public.authorization().encode()?,
        ));
    }
    $($ownership_records)*

    $records.extend($plan.local_records.iter().cloned());
    for (index, effect) in $plan.effects.iter().enumerate() {
        let step = u32::try_from(index)
            .map_err(|_| $invalid("too many effects"))?;
        $records.push(JournalRecord::put(
            RecordNamespace::Effect,
            effect_key($plan.operation_id, step).to_vec(),
            encode_effect(&EffectLedgerRecord::from_parts((
                effect.clone(),
                EffectState::Planned,
                None,
                None,
            )))
            .map_err($effect_error)?,
        ));
    }
    Ok($records)

    }};
}
