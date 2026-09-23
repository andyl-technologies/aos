//! Controller custody for cold public Cache pin acquisition recovery.
//!
//! A recovered protected event names its original partition and physical pin.
//! Recovery never selects a fresh source or destination; a state-only result
//! still requires the separate authenticated View source execution path.

use aos_sandbox::cache_residency::{
    CacheOwnerErrorV1, CacheOwnerOutcomeUnknownV1, CacheOwnerPinSettlementErrorV1,
};
use aos_sandbox::production_operation_compiler::RecheckedCacheConsumerV1;

use super::{EffectFailure, EffectReceipt, OperationId, ProductionEffectExecutor};
use crate::{PublicCachePinRecoveryV1, recover_public_cache_pin_v1};

/// Retains an ambiguous physical acquisition until its exact outcome is known.
pub(super) struct PendingControllerCachePinV1 {
    operation_id: OperationId,
    physical: CacheOwnerOutcomeUnknownV1,
}

impl ProductionEffectExecutor {
    /// Cold-recovers a public pin without selecting a new source or partition.
    ///
    /// # Errors
    ///
    /// Returns a retryable error while source execution or exact physical
    /// recovery is pending, or when protected replay cannot validate the pin.
    pub(super) fn recover_public_cache_pin(
        &mut self,
        operation_id: OperationId,
        consumer: &RecheckedCacheConsumerV1,
    ) -> Result<EffectReceipt, EffectFailure> {
        self.ensure_cache_physical_owner()?;
        self.recover_pending_cache_pin(operation_id)?;

        let protected = self.cache_inventory.as_mut().ok_or_else(|| {
            EffectFailure::Permanent("protected Cache inventory is unavailable".to_owned())
        })?;
        let physical = self.cache_physical.as_mut().ok_or_else(|| {
            EffectFailure::Permanent("physical Cache owner is unavailable".to_owned())
        })?;
        let recovery = recover_public_cache_pin_v1(protected, physical, consumer, operation_id)
            .map_err(|error| EffectFailure::Retryable(error.to_string()))?;
        match recovery {
            PublicCachePinRecoveryV1::Acquired(_) | PublicCachePinRecoveryV1::Retained(_) => {
                cache_pin_receipt(operation_id)
            }
            PublicCachePinRecoveryV1::StateOnly => Err(EffectFailure::Retryable(
                "public Cache pin awaits authenticated View source execution".to_owned(),
            )),
            PublicCachePinRecoveryV1::PhysicalError(CacheOwnerPinSettlementErrorV1::Owner(
                CacheOwnerErrorV1::OutcomeUnknown(physical),
            )) => {
                self.pending_cache_pin = Some(PendingControllerCachePinV1 {
                    operation_id,
                    physical,
                });
                Err(EffectFailure::Retryable(
                    "physical Cache pin acquisition requires exact recovery".to_owned(),
                ))
            }
            PublicCachePinRecoveryV1::PhysicalError(error) => {
                Err(EffectFailure::Retryable(error.to_string()))
            }
        }
    }

    /// Resolves retained physical custody for the same public operation.
    ///
    /// # Errors
    ///
    /// Returns a retryable error when another operation owns the custody or
    /// the physical owner cannot confirm its exact outcome.
    pub(super) fn recover_pending_cache_pin(
        &mut self,
        operation_id: OperationId,
    ) -> Result<(), EffectFailure> {
        let Some(pending) = self.pending_cache_pin.take() else {
            return Ok(());
        };
        if pending.operation_id != operation_id {
            self.pending_cache_pin = Some(pending);
            return Err(EffectFailure::Retryable(
                "another public Cache pin still requires exact recovery".to_owned(),
            ));
        }

        let Some(physical) = self.cache_physical.as_mut() else {
            self.pending_cache_pin = Some(pending);
            return Err(EffectFailure::Retryable(
                "physical Cache owner is unavailable during pin recovery".to_owned(),
            ));
        };
        match physical.recover_outcome_unknown(pending.physical) {
            Ok(_) => Ok(()),
            Err(failure) => {
                let (physical, cause) = failure.into_parts();
                self.pending_cache_pin = Some(PendingControllerCachePinV1 {
                    operation_id,
                    physical,
                });
                Err(EffectFailure::Retryable(format!(
                    "physical Cache pin recovery remains unresolved: {cause}"
                )))
            }
        }
    }
}

fn cache_pin_receipt(operation_id: OperationId) -> Result<EffectReceipt, EffectFailure> {
    let mut receipt = Vec::with_capacity(24);
    receipt.extend_from_slice(b"AOSCPN01");
    receipt.extend_from_slice(operation_id.as_bytes());
    EffectReceipt::new(receipt).map_err(|error| EffectFailure::Permanent(error.to_string()))
}
