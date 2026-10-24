//! Counts independent admission copies and actual retained alias owners.
//!
//! The prospective term deliberately repeats the complete archived heap census
//! instead of projecting away a later cloned request. Shared runtime/batch owners
//! already belong to the separate Core roster; their actual alias backing is
//! observed again in the retained walk, never interpreted as a zero owner.

use std::{mem::size_of, rc::Rc};

use crate::{
    node_contract::{
        ActivationRecord, NodeRoute, NodeRuntime, OperationAdmission, OriginalLineageRuntimeRecord,
        RuntimeError,
    },
    node_scheduling::RuntimeInputBatch,
};

pub(super) fn prospective_copies(
    record: &OriginalLineageRuntimeRecord,
    target: &ActivationRecord,
    route: &NodeRoute,
    maximum: usize,
) -> Result<usize, RuntimeError> {
    let (operations, inputs) = counts(record, route)?;
    let slots = operations
        .checked_mul(size_of::<OperationAdmission>())
        .and_then(|bytes| {
            inputs
                .checked_mul(size_of::<Rc<RuntimeInputBatch>>())
                .and_then(|inputs| bytes.checked_add(inputs))
        })
        .ok_or(RuntimeError::ResourceLimit)?;
    let repeated = NodeRuntime::capture_activation_storage_data(target, maximum)?
        .checked_add(NodeRuntime::capture_route_storage_data(route, maximum)?)
        .and_then(|bytes| bytes.checked_mul(operations))
        .ok_or(RuntimeError::ResourceLimit)?;
    // Cloning admissions retains their actual target activation record, route
    // and request. No new batch, authority or preparation backing is created.
    // The complete original record is a conservative upper for all requests
    // and operation identities; target owners replace the captured route.
    sum(
        &[
            slots,
            repeated,
            NodeRuntime::capture_runtime_record_storage(record)?,
            NodeRuntime::capture_activation_storage_data(target, maximum)?,
        ],
        maximum,
    )
}

pub(super) fn retained_aliases(
    operations: &Vec<OperationAdmission>,
    inputs: &Vec<Rc<RuntimeInputBatch>>,
    maximum: usize,
) -> Result<usize, RuntimeError> {
    let slots = operations
        .capacity()
        .checked_mul(size_of::<OperationAdmission>())
        .and_then(|bytes| {
            inputs
                .capacity()
                .checked_mul(size_of::<Rc<RuntimeInputBatch>>())
                .and_then(|inputs| bytes.checked_add(inputs))
        })
        .ok_or(RuntimeError::ResourceLimit)?;
    let mut requested = sum(&[slots], maximum)?;
    // Independent alias views are conservatively charged in full. This raw
    // observer invokes no source/currentness callback and grants no token.
    for operation in operations {
        let facts = operation.retained_requested_storage_data(maximum)?;
        requested = sum(&[requested, facts.independent_bytes()], maximum)?;
        for allocation in facts.shared_allocations() {
            requested = sum(&[requested, allocation.requested_bytes()], maximum)?;
        }
    }
    for batch in inputs {
        let facts = NodeRuntime::capture_input_batch_rc_storage_data(batch, maximum)?;
        requested = sum(&[requested, facts.independent_bytes()], maximum)?;
        for allocation in facts.shared_allocations() {
            requested = sum(&[requested, allocation.requested_bytes()], maximum)?;
        }
    }
    Ok(requested)
}

pub(super) fn counter_scratch_data() -> usize {
    size_of::<std::slice::Iter<'static, Option<crate::node_contract::RetainedCoreSharedAllocation>>>()
        + size_of::<std::iter::Flatten<std::slice::Iter<'static, Option<crate::node_contract::RetainedCoreSharedAllocation>>>>()
        + size_of::<std::option::Iter<'static, crate::node_contract::RetainedCoreSharedAllocation>>()
        + size_of::<[usize; 4]>()
        + size_of::<Result<usize, RuntimeError>>()
        + size_of::<crate::node_contract::RetainedCoreOwnerStorage<'static>>()
        + size_of::<Result<crate::node_contract::RetainedCoreOwnerStorage<'static>, RuntimeError>>()
        + size_of::<&Vec<OperationAdmission>>()
        + size_of::<&Vec<Rc<RuntimeInputBatch>>>()
        + size_of::<[crucible_node_transport::reference_packet::service::complete_restore::activation::PacketRestorationActivationPhase; 2]>()
        + size_of::<std::array::IntoIter<crucible_node_transport::reference_packet::service::complete_restore::activation::PacketRestorationActivationPhase, 2>>()
        + size_of::<std::slice::Iter<'static, OperationAdmission>>()
        + size_of::<std::slice::Iter<'static, Rc<RuntimeInputBatch>>>()
        + size_of::<std::slice::Iter<'static, crate::node_scheduling::InputPayload>>()
        + size_of::<std::slice::Iter<'static, crucible_node_format::ContentRef>>()
        + size_of::<std::iter::Zip<std::slice::Iter<'static, crucible_node_format::ContentRef>,
            std::slice::Iter<'static, crate::node_scheduling::InputPayload>>>()
        + size_of::<(&crucible_node_format::ContentRef, &crate::node_scheduling::InputPayload)>()
        + size_of::<Option<(&crucible_node_format::ContentRef, &crate::node_scheduling::InputPayload)>>()
        + size_of::<(usize, usize)>() + size_of::<Result<(usize, usize), RuntimeError>>()
        + size_of::<&RuntimeInputBatch>()
        + size_of::<std::slice::Iter<'static, crate::node_contract::OriginalLineageInputRecord>>()
        + size_of::<std::slice::Iter<'static, crate::node_contract::SavedRuntimeOperation>>()
        + size_of::<std::slice::Iter<'static, crate::node_scheduling::NativeInputAcknowledgement>>()
        + size_of::<Option<&crate::node_contract::OriginalLineageInputRecord>>()
        + size_of::<Result<&crate::node_contract::OriginalLineageInputRecord, RuntimeError>>()
        + size_of::<Option<&crate::node_contract::SavedRuntimeOperation>>()
        + size_of::<Result<&crate::node_contract::SavedRuntimeOperation, RuntimeError>>()
        + size_of::<Option<&crate::node_scheduling::NativeInputAcknowledgement>>()
        + size_of::<Result<&crate::node_scheduling::NativeInputAcknowledgement, RuntimeError>>()
        + size_of::<(
            &NodeRoute,
            &crate::node_contract::WorldActivation,
            &[OperationAdmission],
            &[Rc<RuntimeInputBatch>],
            &mut Vec<OperationAdmission>,
            &mut Vec<Rc<RuntimeInputBatch>>,
            &mut bool,
            &crate::node_contract::OriginalLineageRestoration<'static>,
        )>()
}

pub(super) fn sum(terms: &[usize], maximum: usize) -> Result<usize, RuntimeError> {
    terms.iter().try_fold(0usize, |total, term| {
        total
            .checked_add(*term)
            .filter(|total| *total <= maximum)
            .ok_or(RuntimeError::ResourceLimit)
    })
}

pub(super) fn node_activation_copies(
    data: &crucible_node_transport::reference_packet::service::complete_restore::activation::OriginalInstalledRestorationActivationConstructionData,
    coordinator: &crate::node_admission::OriginalRestorationCoordinatorConstructionData,
    maximum: usize,
) -> Result<usize, RuntimeError> {
    use crucible_node_transport::reference_packet::service::complete_restore::activation::PacketRestorationActivationPhase;
    let mut requested = sum(
        &[
            coordinator.retained_requested_bytes_data(),
            coordinator.maximum_simultaneous_transient_bytes_data(),
            coordinator.counter_scratch_bytes_data(),
            size_of::<super::InstalledRestorationCustody>(),
        ],
        maximum,
    )?;
    for phase in [
        PacketRestorationActivationPhase::Arm,
        PacketRestorationActivationPhase::WorldActivate,
    ] {
        // Explicit independent Node copies of the defining closed command and
        // returned full terminal upper. The actual SDK keeps its own row too.
        requested = sum(
            &[
                requested,
                data.host_retained_requested_bytes_data(phase),
                data.host_maximum_simultaneous_transient_bytes_data(phase),
                data.host_declared_counter_scratch_bytes_data(phase),
            ],
            maximum,
        )?;
    }
    Ok(requested)
}

pub(super) fn counts(
    record: &OriginalLineageRuntimeRecord,
    route: &NodeRoute,
) -> Result<(usize, usize), RuntimeError> {
    let mut operations = 0usize;
    let mut inputs = 0usize;
    for saved in &record.operations {
        if saved.route.node == route.node {
            operations = operations
                .checked_add(1)
                .ok_or(RuntimeError::ResourceLimit)?;
        }
    }
    for saved in &record.inputs {
        if saved.node == route.node {
            inputs = inputs.checked_add(1).ok_or(RuntimeError::ResourceLimit)?;
        }
    }
    Ok((operations, inputs))
}
