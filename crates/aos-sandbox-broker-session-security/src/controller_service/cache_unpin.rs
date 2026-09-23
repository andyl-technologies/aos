//! Controller custody for consumer-wide public Cache unpin effects.
//!
//! A protected release and its physical owner effect are independent durable
//! steps. This module retains ambiguous tokens in the single controller owner
//! and rechecks every partition before publishing one public receipt.

use aos_sandbox::cache_residency::{
    CacheOwnerErrorV1, CacheOwnerOutcomeUnknownV1, CacheOwnerPinSettlementErrorV1, CachePinV1,
    CacheResidencyCommitOutcomeV1, CacheResidencyOutcomeUnknownV1,
    CacheResidencyProtectedOwnerRecoveryV1, CacheResidencyRecoveryV1,
};
use aos_sandbox::production_operation_compiler::RecheckedCacheConsumerV1;

use super::{
    DormantSandboxRequestKindV1, EffectFailure, EffectReceipt, Journal, OperationId,
    ProductionEffectExecutor,
};
use crate::{
    PublicCacheUnpinProgressV1, PublicCacheUnpinRecoveryV1, execute_public_cache_unpin_consumer_v1,
    public_cache_unpin_transaction_id_v1,
};

pub(super) struct PendingControllerCacheUnpinV1 {
    operation_id: OperationId,
    pin: CachePinV1,
    custody: PendingCacheUnpinCustodyV1,
}

enum PendingCacheUnpinCustodyV1 {
    Protected(CacheResidencyOutcomeUnknownV1),
    Physical(CacheOwnerOutcomeUnknownV1),
}

impl ProductionEffectExecutor {
    pub(super) fn apply_public_cache_unpin(
        &mut self,
        operation_id: OperationId,
        consumer: &RecheckedCacheConsumerV1,
        journal: &Journal,
        request: &DormantSandboxRequestKindV1,
    ) -> Result<EffectReceipt, EffectFailure> {
        self.ensure_cache_physical_owner()?;
        self.recover_pending_cache_unpin(operation_id)?;

        let progress = {
            let protected = self.cache_inventory.as_mut().ok_or_else(|| {
                EffectFailure::Permanent("protected Cache inventory is unavailable".to_owned())
            })?;
            let physical = self.cache_physical.as_mut().ok_or_else(|| {
                EffectFailure::Permanent("physical Cache owner is unavailable".to_owned())
            })?;
            execute_public_cache_unpin_consumer_v1(
                protected,
                physical,
                consumer,
                journal,
                request,
                operation_id,
            )
            .map_err(|error| EffectFailure::Retryable(error.to_string()))?
        };
        match progress {
            PublicCacheUnpinProgressV1::Complete => cache_unpin_receipt(operation_id),
            PublicCacheUnpinProgressV1::PendingCommit { pin, execution } => {
                match execution.outcome {
                    CacheResidencyCommitOutcomeV1::OutcomeUnknown { pending, .. }
                    | CacheResidencyCommitOutcomeV1::ValidationUnknown { pending, .. } => {
                        self.pending_cache_unpin = Some(PendingControllerCacheUnpinV1 {
                            operation_id,
                            pin,
                            custody: PendingCacheUnpinCustodyV1::Protected(pending),
                        });
                    }
                    CacheResidencyCommitOutcomeV1::Applied(_) => {
                        if let Some(Err(CacheOwnerPinSettlementErrorV1::Owner(
                            CacheOwnerErrorV1::OutcomeUnknown(pending),
                        ))) = execution.settlement
                        {
                            self.pending_cache_unpin = Some(PendingControllerCacheUnpinV1 {
                                operation_id,
                                pin,
                                custody: PendingCacheUnpinCustodyV1::Physical(pending),
                            });
                        }
                    }
                }
                Err(EffectFailure::Retryable(
                    "public Cache unpin release requires exact recovery".to_owned(),
                ))
            }
            PublicCacheUnpinProgressV1::PendingRecovery { pin, recovery } => {
                if let PublicCacheUnpinRecoveryV1::PhysicalError(
                    CacheOwnerPinSettlementErrorV1::Owner(CacheOwnerErrorV1::OutcomeUnknown(
                        pending,
                    )),
                ) = recovery
                {
                    self.pending_cache_unpin = Some(PendingControllerCacheUnpinV1 {
                        operation_id,
                        pin,
                        custody: PendingCacheUnpinCustodyV1::Physical(pending),
                    });
                }
                Err(EffectFailure::Retryable(
                    "public Cache unpin physical release is not confirmed".to_owned(),
                ))
            }
            PublicCacheUnpinProgressV1::RecheckRequired => Err(EffectFailure::Retryable(
                "public Cache unpin requires a fresh protected recheck".to_owned(),
            )),
        }
    }

    pub(super) fn recover_pending_cache_unpin(
        &mut self,
        operation_id: OperationId,
    ) -> Result<(), EffectFailure> {
        if self.pending_cache_unpin.is_some()
            && (self.cache_inventory.is_none() || self.cache_physical.is_none())
        {
            return Err(EffectFailure::Retryable(
                "Cache owners are unavailable while exact unpin custody is retained".to_owned(),
            ));
        }
        let Some(pending) = self.pending_cache_unpin.take() else {
            return Ok(());
        };
        if pending.operation_id != operation_id {
            self.pending_cache_unpin = Some(pending);
            return Err(EffectFailure::Retryable(
                "another public Cache unpin still requires exact recovery".to_owned(),
            ));
        }

        match pending.custody {
            PendingCacheUnpinCustodyV1::Physical(token) => {
                let physical = self.cache_physical.as_mut().ok_or_else(|| {
                    EffectFailure::Permanent("physical Cache owner is unavailable".to_owned())
                })?;
                match physical.recover_outcome_unknown(token) {
                    Ok(_) => Ok(()),
                    Err(failure) => {
                        let (token, cause) = failure.into_parts();
                        self.pending_cache_unpin = Some(PendingControllerCacheUnpinV1 {
                            custody: PendingCacheUnpinCustodyV1::Physical(token),
                            ..pending
                        });
                        Err(EffectFailure::Retryable(format!(
                            "physical Cache unpin recovery remains unresolved: {cause}"
                        )))
                    }
                }
            }
            PendingCacheUnpinCustodyV1::Protected(token) => {
                let recovery = {
                    let protected = self.cache_inventory.as_mut().ok_or_else(|| {
                        EffectFailure::Permanent(
                            "protected Cache inventory is unavailable".to_owned(),
                        )
                    })?;
                    let physical = self.cache_physical.as_mut().ok_or_else(|| {
                        EffectFailure::Permanent("physical Cache owner is unavailable".to_owned())
                    })?;
                    protected.recover(
                        public_cache_unpin_transaction_id_v1(&pending.pin),
                        token,
                        |postcommit| postcommit.settle_cache_owner_pin_change(physical),
                    )
                };
                match recovery {
                    CacheResidencyProtectedOwnerRecoveryV1::Pending {
                        pending: token,
                        cause,
                        ..
                    } => {
                        self.pending_cache_unpin = Some(PendingControllerCacheUnpinV1 {
                            custody: PendingCacheUnpinCustodyV1::Protected(token),
                            ..pending
                        });
                        Err(EffectFailure::Retryable(format!(
                            "protected Cache unpin recovery remains unresolved: {cause}"
                        )))
                    }
                    CacheResidencyProtectedOwnerRecoveryV1::Classified {
                        recovery: CacheResidencyRecoveryV1::Diverged(token),
                        ..
                    } => {
                        self.pending_cache_unpin = Some(PendingControllerCacheUnpinV1 {
                            custody: PendingCacheUnpinCustodyV1::Protected(token),
                            ..pending
                        });
                        Err(EffectFailure::Permanent(
                            "protected Cache unpin transaction diverged".to_owned(),
                        ))
                    }
                    CacheResidencyProtectedOwnerRecoveryV1::Classified {
                        recovery:
                            CacheResidencyRecoveryV1::Indeterminate {
                                pending: token,
                                cause,
                            },
                        ..
                    } => {
                        self.pending_cache_unpin = Some(PendingControllerCacheUnpinV1 {
                            custody: PendingCacheUnpinCustodyV1::Protected(token),
                            ..pending
                        });
                        Err(EffectFailure::Retryable(format!(
                            "protected Cache unpin replay remains indeterminate: {cause}"
                        )))
                    }
                    CacheResidencyProtectedOwnerRecoveryV1::Classified {
                        recovery: CacheResidencyRecoveryV1::Applied(_),
                        handoff:
                            Some(Err(CacheOwnerPinSettlementErrorV1::Owner(
                                CacheOwnerErrorV1::OutcomeUnknown(token),
                            ))),
                        ..
                    } => {
                        self.pending_cache_unpin = Some(PendingControllerCacheUnpinV1 {
                            custody: PendingCacheUnpinCustodyV1::Physical(token),
                            ..pending
                        });
                        Err(EffectFailure::Retryable(
                            "physical Cache unpin durability remains unknown".to_owned(),
                        ))
                    }
                    CacheResidencyProtectedOwnerRecoveryV1::Classified { .. }
                    | CacheResidencyProtectedOwnerRecoveryV1::ColdLookupRequired { .. } => {
                        // An exact predecessor permits a fresh release; an
                        // applied transaction is checked against its tombstone
                        // and physical owner by the next batch pass.
                        Ok(())
                    }
                }
            }
        }
    }
}

fn cache_unpin_receipt(operation_id: OperationId) -> Result<EffectReceipt, EffectFailure> {
    let mut receipt = Vec::with_capacity(24);
    receipt.extend_from_slice(b"AOSCUN01");
    receipt.extend_from_slice(operation_id.as_bytes());
    EffectReceipt::new(receipt).map_err(|error| EffectFailure::Permanent(error.to_string()))
}
