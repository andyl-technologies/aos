//! Borrows the actual paid source of the single runtime native recipe.
//!
//! Active execution keeps its original phase loan. Fresh cleanup uses the
//! current-control preparation loan and cannot reconsume an old phase.

use super::*;

pub(super) enum ArgumentNativeReceivingV2<'original> {
    Active(crate::plan::HostExecutionReceivingLoanV2<'original>),
    Cleanup(crate::plan::HostControlPreparationReceivingV5<'original>),
}

impl ArgumentNativeReceivingV2<'_> {
    pub(super) fn observation_round_start_data_v2(&self) -> usize {
        match self {
            Self::Active(original) => original.observation_round_start_data_v2(),
            Self::Cleanup(original) => original.observation_round_start_data_v1(),
        }
    }

    pub(super) fn require_complete_v2(&mut self, complete: ResourceVector) -> Result<()> {
        match self {
            Self::Active(original) => original.require_complete_v2(complete),
            Self::Cleanup(original) => original.raise_complete_v1(complete),
        }
    }

    pub(super) async fn observe_after_v2(&mut self) -> Result<()> {
        match self {
            Self::Active(original) => original.observe_after_v2().await,
            Self::Cleanup(original) => original.observe_after_once_v5().await,
        }
    }

    pub(super) async fn observe_before_v2(&mut self) -> Result<()> {
        match self {
            Self::Active(original) => original.observe_before_v2().await,
            Self::Cleanup(original) => original.observe_before_once_v5().await,
        }
    }

    pub(super) fn finish_native_v2(&mut self) -> Result<()> {
        match self {
            Self::Active(original) => original.finish_native_v2(),
            Self::Cleanup(original) => original.finish_cleanup_native_once_v1(),
        }
    }

    pub(super) fn retain_pending_authenticated_v2(
        self,
    ) -> Result<Option<crate::plan::HostControlCleanupTokenV1>> {
        match self {
            Self::Active(original) => {
                original.retain_pending_authenticated_v2()?;
                Ok(None)
            }
            Self::Cleanup(original) => original.retain_pending_authenticated_v1().map(Some),
        }
    }
}
