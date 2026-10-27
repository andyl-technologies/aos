//! Retains both independently admitted native cuts before their final proof join.

use super::{sealed::RestoredSettledNative17DecodeAttempt, *};
use crate::protocol_snapshot::native_wholegraph17::{
    NativeCurrentGraph17Data, NativeCurrentGraph17DecodeAttempt, NativeCurrentGraph17ReadLimits,
    native_current_graph17_banks_data,
};

pub(super) fn read_graph_pair_into_data(
    decoded: &mut RestoredSettledNative17DecodeAttempt,
    maximum_requested: usize,
    maximum_target_requested: usize,
    maximum_nodes: usize,
) -> Result<(), ProviderError> {
    read_graph_pair_with_admission_into_data(
        decoded,
        maximum_requested,
        maximum_target_requested,
        maximum_nodes,
        None,
    )
}

pub(super) fn read_graph_pair_with_admission_into_data(
    decoded: &mut RestoredSettledNative17DecodeAttempt,
    maximum_requested: usize,
    maximum_target_requested: usize,
    maximum_nodes: usize,
    boundary: Option<&super::cold_admission::NativeCold17Boundary<'_>>,
) -> Result<(), ProviderError> {
    if maximum_target_requested == 0 || maximum_nodes == 0 {
        return Err(invalid());
    }
    for before in [true, false] {
        let banks = if before {
            NativeCold17Work::BeforeGraphBanks
        } else {
            NativeCold17Work::AfterGraphBanks
        };
        let targets = if before {
            NativeCold17Work::BeforeGraphTargets
        } else {
            NativeCold17Work::AfterGraphTargets
        };
        let retained = match boundary {
            Some(boundary) => boundary.retained_data(),
            None => decoded.retained_requested_storage_data(maximum_requested)?,
        };
        let limits = NativeCurrentGraph17ReadLimits {
            maximum_requested: maximum_requested
                .checked_sub(retained)
                .ok_or_else(invalid)?,
            maximum_target_requested,
            maximum_nodes,
            maximum_depth: 64,
        };
        let input = if before {
            decoded.before_encoded.as_slice()
        } else {
            decoded.raw[1].as_slice()
        };
        let header = std::mem::size_of::<Option<NativeCurrentGraph17DecodeAttempt>>();
        let admission = if let Some(boundary) = boundary {
            let scratch = super::restored_settled_native17_counter_scratch_data();
            boundary.begin_data(banks, 0, scratch)?;
            let new = header
                .checked_add(native_current_graph17_banks_data(input, limits)?)
                .ok_or_else(invalid)?;
            boundary.construct_data(banks, new, 0, scratch)?;
            Some(super::cold_admission::NativeCold17GraphAdmission {
                boundary,
                base: retained.checked_add(header).ok_or_else(invalid)?,
                banks,
                targets,
            })
        } else {
            None
        };
        let graph = if before {
            &mut decoded.before_native_graph
        } else {
            &mut decoded.native_graph
        };
        graph.read_with_admission_into_data(input, limits, admission.as_ref())?;
    }
    if boundary.is_none() {
        decoded.retained_requested_storage_data(maximum_requested)?;
    }
    Ok(())
}

pub(super) fn completed_graph_pair_data(
    decoded: &RestoredSettledNative17DecodeAttempt,
) -> Result<(&NativeCurrentGraph17Data, &NativeCurrentGraph17Data), ProviderError> {
    let before = decoded.before_native_graph.as_ref().ok_or_else(invalid)?;
    let after = decoded.native_graph.as_ref().ok_or_else(invalid)?;
    before.validate_data()?;
    after.validate_data()?;

    Ok((
        before.completed_data().ok_or_else(invalid)?,
        after.completed_data().ok_or_else(invalid)?,
    ))
}
