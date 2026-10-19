//! Prices the exact initial runtime's additional conservative owning reports.
//!
//! New allocations remain in retained_requested_bytes. This separate row funds
//! unchanged graph/Source backing repeated across independent scalar observers,
//! plus the actual named after-attachment metadata paths. It grants no effects.

use super::*;
use crucible::node_adapters::cnp::{
    CnpSemanticRegistrationPolicy, CnpSemanticRegistry, PacketCompleteSemanticSource,
};
use crucible::node_contract::{HostSchedulingSource, OriginalHostRuntimeAttachmentStorageData};
use std::mem::size_of;

/// Separates the genuine new Source clone from conservative report growth.
pub(super) struct ObservationGrowthData {
    /// Prices the actual world hash retained by the original attachment handle.
    pub(super) retained_requested_bytes: usize,
    /// Prices additional complete reports without claiming new allocations.
    pub(super) retained_observation_growth_bytes: usize,
}

/// Names the quote's real owning counters, original loans and fixed result rows.
///
/// # Errors
/// Refuses checked fixed-layout overflow before any quote callback.
pub(super) fn counter_scratch_data() -> Result<usize, RuntimeError> {
    let original = [
        ConformanceGraph::original_fixed_four_runtime_observation_counter_scratch_data(),
        HostSchedulingSource::original_initial_runtime_attachment_counter_scratch_data(),
        CnpSemanticConformanceNode::original_initial_runtime_observation_counter_scratch_data()?,
        size_of::<Counter>(), // concrete nested installed-authority DATA counter
        size_of::<std::cell::Ref<'_, super::super::scene::OriginalSceneOwners>>(),
        size_of::<&PacketCompleteReportStartupHolder>(),
        size_of::<&ConformanceGraph>(),
        size_of::<[&CnpSemanticConformanceNode; 3]>(),
        size_of::<&PreparedHostSchedulingNode>(),
        size_of::<&[Rc<PacketCompleteSemanticSource>; 3]>(),
        size_of::<OriginalHostRuntimeAttachmentStorageData>(),
        size_of::<ObservationGrowthData>(),
        size_of::<super::inactive::InactiveConstructionStorageData>(),
        size_of::<Result<super::inactive::InactiveConstructionStorageData, RuntimeError>>(),
        size_of::<Result<ObservationGrowthData, RuntimeError>>(),
        size_of::<[usize; 7]>(),
        size_of::<
            std::iter::Enumerate<std::slice::Iter<'static, &'static CnpSemanticConformanceNode>>,
        >(),
        size_of::<std::array::IntoIter<&'static CnpSemanticConformanceNode, 3>>(),
        size_of::<std::array::IntoIter<usize, 7>>(),
        size_of::<[usize; 5]>(),
    ]
    .into_iter()
    .try_fold(0usize, |total, bytes| add(total, bytes, usize::MAX))?;

    // The original sum above has twenty actual terms. Its array, consuming
    // iterator, fold controls and final checked return are DATA prework too.
    let controls = size_of::<[usize; 20]>()
        + size_of::<std::array::IntoIter<usize, 20>>()
        + size_of::<Result<usize, RuntimeError>>()
        + size_of::<[usize; 4]>() // fold total/bytes and original/controls locals
        // The nested scene loan overlaps inactive::quote's original scene loan.
        + size_of::<Option<&std::cell::RefCell<super::super::scene::OriginalSceneOwners>>>()
        + size_of::<Result<&std::cell::RefCell<super::super::scene::OriginalSceneOwners>, RuntimeError>>()
        + size_of::<Result<std::cell::Ref<'static, super::super::scene::OriginalSceneOwners>, std::cell::BorrowError>>()
        + size_of::<Result<std::cell::Ref<'static, super::super::scene::OriginalSceneOwners>, RuntimeError>>()
        // Registry comparison is a borrowed identity check, not an owning walk.
        + size_of::<&CnpSemanticRegistry>()
        + size_of::<&dyn CnpSemanticRegistrationPolicy>() // supplied original
        + size_of::<&dyn CnpSemanticRegistrationPolicy>() // retained policy view
        + size_of::<bool>()
        // Per-node guard results and enumerate items end before attachment
        // pricing. Scalar Option/Result windows are reused by the later loops
        // and checked additions, which retain no separate aggregate owners.
        + size_of::<Result<(), RuntimeError>>()
        + size_of::<(usize, &&CnpSemanticConformanceNode)>()
        + size_of::<Option<(usize, &&CnpSemanticConformanceNode)>>()
        + size_of::<Option<&CnpSemanticConformanceNode>>()
        + size_of::<Option<usize>>()
        + size_of::<Result<usize, RuntimeError>>();
    add(original, controls, usize::MAX)
}

/// Quotes only the same original scene's future independent owner reports.
///
/// # Errors
/// Refuses another Source/plan/registry/node/Host allocation, an unsupported or
/// spent attachment, unknown backing, checked overflow or the requested bound.
pub(super) fn quote(
    held: &PacketCompleteReportStartupHolder,
    graph: &ConformanceGraph,
    nodes: [&CnpSemanticConformanceNode; 3],
    host: &PreparedHostSchedulingNode,
    maximum: usize,
) -> Result<ObservationGrowthData, RuntimeError> {
    if !matches!(&held.purpose, StartupHolderPurpose::OriginalScene)
        || !graph.plan().is_original_plan_data(&held.plan)
    {
        return Err(RuntimeError::ForeignAuthority);
    }
    let scene = held
        .original_scene
        .get()
        .ok_or(RuntimeError::OwnerUnavailable)?
        .try_borrow()
        .map_err(|_| RuntimeError::OwnerBusy)?;
    if !scene
        .inputs
        .registry
        .is_original_registration_policy_data(held.authority.as_ref())
    {
        return Err(RuntimeError::ForeignAuthority);
    }
    let sources = &held.authority.roster.sources;
    for (index, node) in nodes.iter().enumerate() {
        node.authenticate_original_initial_runtime_observation_data(&sources[index], &held.plan)?;
    }
    let attachment = held
        .authority
        .host_source()
        .original_initial_runtime_attachment_storage_data(host, &held.plan, maximum)?;

    // Standalone I+B becomes two independent Rc-root reports. The provider's
    // existing new-allocation row already funds I+header, leaving B+header.
    let mut reported = graph.original_fixed_four_runtime_observation_growth_data(maximum)?;
    reported = add(
        reported,
        attachment.existing_source_observation_bytes(),
        maximum,
    )?;
    // The same existing Source is also reported by ConformanceRuntime.exact_inputs.
    reported = add(
        reported,
        attachment.existing_source_observation_bytes(),
        maximum,
    )?;

    // The direct holder authority is the first attached metadata view. Its real
    // world clone is new retained storage below; only the Weak report is extra.
    reported = add(
        reported,
        attachment.attached_weak_observation_bytes(),
        maximum,
    )?;
    let attached = attachment.attached_observation_bytes()?;
    for _node in nodes {
        // Each original CNP process dedups its registration/conformance Rc and
        // has exactly one full installed-authority report after transfer.
        reported = add(reported, attached, maximum)?;
    }
    let other_attached_views = [
        attached, // original scene registry's installed policy
        attached, // genuine Host node's retained plan authority
        attached, // NodeRuntime.collecting graph authority
        attached, // ConformanceRuntime.graph authority
        attached, // genuine Host node's direct Source observer
        attached, // retained exact provider's Source observer
        attached, // ConformanceRuntime.exact_inputs Source observer
    ];
    for bytes in other_attached_views {
        reported = add(reported, bytes, maximum)?;
    }
    Ok(ObservationGrowthData {
        retained_requested_bytes: attachment.retained_requested_bytes(),
        retained_observation_growth_bytes: reported,
    })
}
