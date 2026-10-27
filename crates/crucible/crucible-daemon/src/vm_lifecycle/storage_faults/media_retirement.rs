//! Retires block media and flash continuations that no live action can name.
//!
//! A device keeps one media or flash continuation per resolved action. Once an
//! action leaves the host state it never returns, so its continuation matters
//! only while a retained directive still names it. The coordinator reports the
//! live action set right after each directive install; the device retires the
//! rest that no retained directive names.

use std::collections::BTreeSet;

use super::*;

impl ProductionBlockFaultCoordinator {
    /// Retires device media and flash continuations that no action can name.
    ///
    /// Every persistent media or flash action in the host state is live,
    /// whatever its target; over-inclusion only keeps a continuation longer.
    /// Callers invoke this right after installing a directive resolved from
    /// the same host action state, so retirement points are exactly as
    /// deterministic as directive resolution.
    pub(super) fn retire_inactive_media(
        &self,
        servicer: &mut LiveBlockServicer,
    ) -> Result<(), DeviceRuntimeError> {
        let live = {
            let runtime = self.runtime.lock().map_err(|_| {
                storage_error(
                    "retire inactive block media",
                    "production fault runtime lock is poisoned",
                )
            })?;
            runtime
                .host_state()
                .active()
                .values()
                .filter(|action| {
                    matches!(
                        action.effect.specification(),
                        EffectSpecification::Storage(
                            StorageEffectSpecification::MediaRange { .. }
                                | StorageEffectSpecification::FlashState { .. }
                        )
                    )
                })
                .map(|action| action.id().bytes)
                .collect::<BTreeSet<_>>()
        };
        self.after_evaluation(
            "retire inactive block media",
            servicer.retire_inactive_storage_media(&live),
        )?;
        Ok(())
    }
}
