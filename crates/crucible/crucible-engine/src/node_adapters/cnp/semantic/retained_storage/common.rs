//! Counts the same common operation/input histories, including failed originals.

use super::*;
use crate::node_contract::NodeRuntime;
use crucible_node_transport::retained_metadata::RetainedCommonProtocolData;

macro_rules! core {
    ($counter:expr, $value:expr) => {{
        let facts = $value
            .retained_requested_storage_data($counter.ceiling())
            .map_err(unknown)?;
        $counter.add(facts.independent_bytes())?;
        for owner in facts.shared_allocations() {
            $counter.shared(owner.identity(), owner.requested_bytes())?;
        }
    }};
}

macro_rules! plain {
    ($counter:expr, $method:ident, $value:expr) => {
        $counter.add(NodeRuntime::$method($value, $counter.remaining()).map_err(unknown)?)?
    };
}

macro_rules! optional_plain {
    ($counter:expr, $method:ident, $value:expr) => {
        if let Some(value) = $value {
            plain!($counter, $method, value);
        }
    };
}

pub(in crate::node_adapters::cnp::semantic) fn activation(
    value: &crate::node_contract::WorldActivation,
    counter: &mut Counter,
) -> Result<(), OperationFailure> {
    core!(counter, value);
    Ok(())
}

pub(super) fn preparation(
    value: &super::super::CnpSemanticPreparation,
    registry: Option<&crucible_node_transport::handshake::OriginalExtensionRegistryOwner>,
    counter: &mut Counter,
) -> Result<(), OperationFailure> {
    let super::super::CnpSemanticPreparation {
        guard,
        discovery,
        realization,
    } = value;
    counter.add(size_of::<super::super::CnpSemanticPreparation>())?;
    counter.metadata(
        &RetainedCommonProtocolData::Discover(discovery)
            .observe_retained_metadata()
            .map_err(unknown)?,
    )?;
    counter.metadata(
        &RetainedCommonProtocolData::Realize(realization)
            .observe_retained_metadata()
            .map_err(unknown)?,
    )?;
    guard.charge_retained_storage_data(registry, counter)
}

pub(in crate::node_adapters::cnp::semantic) fn runtime(
    value: &super::super::state::SemanticRuntimeCustody,
    counter: &mut Counter,
) -> Result<(), OperationFailure> {
    use super::super::state::SemanticRuntimeCustody;

    let SemanticRuntimeCustody {
        installed_restoration,
        arm_attempt,
        ready,
        prepared_owner,
        activate_response,
        observe_sequence: _,
        activation_attempt,
        active,
        inputs,
        operations,
        watermark: _,
        observation,
        reclaimed,
        credit: _,
        quarantined: _,
    } = value;
    if let Some(selected) = installed_restoration {
        counter.add(
            selected
                .retained_requested_storage_data(counter.ceiling())
                .map_err(unknown)?,
        )?;
    }
    optional_plain!(counter, capture_activation_storage_data, arm_attempt);
    optional_plain!(counter, capture_ready_storage_data, ready);
    optional_plain!(counter, capture_prepared_owner_storage_data, prepared_owner);
    if let Some(value) = activate_response {
        counter.metadata(
            &RetainedCommonProtocolData::WorldActivate(value)
                .observe_retained_metadata()
                .map_err(unknown)?,
        )?;
    }
    for value in [activation_attempt, active].into_iter().flatten() {
        activation(value, counter)?;
    }
    counter.tree(inputs)?;
    for (key, value) in inputs {
        counter.charge(key)?;
        input(value, counter)?;
    }
    counter.tree(operations)?;
    for (key, value) in operations {
        counter.charge(key)?;
        operation(value, counter)?;
    }
    if let Some((active, observation)) = observation {
        activation(active, counter)?;
        plain!(
            counter,
            capture_scheduling_observation_storage_data,
            observation
        );
    }
    optional_plain!(counter, capture_reclamation_storage_data, reclaimed);
    Ok(())
}

fn operation(
    value: &super::super::state::OriginalOperation,
    counter: &mut Counter,
) -> Result<(), OperationFailure> {
    use super::super::state::{OriginalCancellation, OriginalOperation};

    let OriginalOperation {
        admission,
        begin,
        outcome,
        failure,
        polls: _,
        begin_acknowledged: _,
        cancellation,
        acknowledged: _,
        retirement,
    } = value;
    core!(counter, admission);
    counter.metadata(
        &RetainedCommonProtocolData::Begin(begin)
            .observe_retained_metadata()
            .map_err(unknown)?,
    )?;
    optional_plain!(counter, capture_outcome_storage_data, outcome);
    optional_plain!(counter, capture_failure_storage_data, failure);
    match cancellation {
        OriginalCancellation::Failed(value) => {
            plain!(counter, capture_failure_storage_data, value);
        }
        OriginalCancellation::NotAttempted
        | OriginalCancellation::Pending
        | OriginalCancellation::Requested
        | OriginalCancellation::Unsupported => {}
    }
    counter.charge(retirement)
}

fn input(
    value: &super::super::state::OriginalInput,
    counter: &mut Counter,
) -> Result<(), OperationFailure> {
    use super::super::state::{OriginalInput, OriginalInputCommit};

    let OriginalInput {
        original,
        acknowledgement,
        watermark: _,
        request,
        commitment,
        response,
    } = value;
    {
        let facts = NodeRuntime::capture_input_batch_rc_storage_data(original, counter.ceiling())
            .map_err(unknown)?;
        counter.add(facts.independent_bytes())?;
        for owner in facts.shared_allocations() {
            counter.shared(owner.identity(), owner.requested_bytes())?;
        }
    }
    optional_plain!(counter, capture_input_ack_storage_data, acknowledgement);
    counter.metadata(
        &RetainedCommonProtocolData::InputRequest(request)
            .observe_retained_metadata()
            .map_err(unknown)?,
    )?;
    if let Some(OriginalInputCommit {
        original,
        request_id,
        extensions,
        context,
        response,
    }) = commitment
    {
        core!(counter, original);
        counter.charge(request_id)?;
        counter.extensions(extensions)?;
        if counter.rc(context)? {
            counter.charge(context.as_ref())?;
        }
        if let Some(value) = response {
            counter.metadata(
                &RetainedCommonProtocolData::InputResult(value)
                    .observe_retained_metadata()
                    .map_err(unknown)?,
            )?;
        }
    }
    if let Some(value) = response {
        counter.metadata(
            &RetainedCommonProtocolData::InputResult(value)
                .observe_retained_metadata()
                .map_err(unknown)?,
        )?;
    }
    Ok(())
}
