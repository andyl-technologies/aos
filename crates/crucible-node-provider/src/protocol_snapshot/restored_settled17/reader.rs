//! Retains both independently admitted native cuts before their final proof join.

use super::{sealed::RestoredSettledNative17DecodeAttempt, *};
use crate::protocol_snapshot::native_wholegraph17::{
    NativeCurrentGraph17Data, NativeCurrentGraph17ReadLimits,
};

pub(super) fn read_graph_pair_into_data(
    decoded: &mut RestoredSettledNative17DecodeAttempt,
    maximum_requested: usize,
    maximum_target_requested: usize,
    maximum_nodes: usize,
) -> Result<(), ProviderError> {
    if maximum_target_requested == 0 || maximum_nodes == 0 {
        return Err(invalid());
    }

    let retained = decoded.retained_requested_storage_data(maximum_requested)?;
    decoded.before_native_graph.read_into_data(
        &decoded.before_encoded,
        NativeCurrentGraph17ReadLimits {
            maximum_requested: maximum_requested
                .checked_sub(retained)
                .ok_or_else(invalid)?,
            maximum_target_requested,
            maximum_nodes,
            maximum_depth: 64,
        },
    )?;

    let retained = decoded.retained_requested_storage_data(maximum_requested)?;
    decoded.native_graph.read_into_data(
        &decoded.raw[1],
        NativeCurrentGraph17ReadLimits {
            maximum_requested: maximum_requested
                .checked_sub(retained)
                .ok_or_else(invalid)?,
            maximum_target_requested,
            maximum_nodes,
            maximum_depth: 64,
        },
    )?;
    decoded.retained_requested_storage_data(maximum_requested)?;
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
