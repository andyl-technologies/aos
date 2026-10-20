//! Adapts the common passive names parser to the existing Root startup cause.

use super::NormalRootStartupErrorV1;

pub(crate) fn names(maximum: usize) -> Result<Vec<String>, NormalRootStartupErrorV1> {
    aos_sandbox_broker::receiving::original_activation_names_v1(maximum)
        .map_err(|_| NormalRootStartupErrorV1::Activation)
}
