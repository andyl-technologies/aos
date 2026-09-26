//! Controller custody for consumer-wide public Cache unpin effects.
//!
//! A protected release and its physical owner effect are independent durable
//! steps. This module retains ambiguous tokens in the single controller owner
//! and rechecks every partition before publishing one public receipt.

use aos_sandbox::cache_residency::{CacheOwnerErrorV1, CacheOwnerPinSettlementErrorV1, CachePinV1};
use aos_sandbox::production_operation_compiler::RecheckedCacheConsumerV1;

use super::{
    DormantSandboxRequestKindV1, EffectFailure, EffectReceipt, Journal, OperationId,
    ProductionEffectExecutor,
};
use crate::{
    PublicCacheUnpinProgressV1, PublicCacheUnpinRecoveryV1, execute_public_cache_unpin_consumer_v1,
    public_cache_unpin_transaction_id_v1,
};

use super::cache_pin::cache_custody::{
    CacheCustodyMessages, CacheCustodyV1, PendingControllerCacheCustodyV1,
    cache_custody_from_commit, recover_pending_cache_custody,
};

pub(super) type PendingControllerCacheUnpinV1 = PendingControllerCacheCustodyV1<CachePinV1>;

const UNPIN_CUSTODY_MESSAGES: CacheCustodyMessages = CacheCustodyMessages {
    owners_unavailable: "Cache owners are unavailable while exact unpin custody is retained",
    another_operation: "another public Cache unpin still requires exact recovery",
    physical_unresolved: "physical Cache unpin recovery remains unresolved",
    protected_pending: "protected Cache unpin recovery remains unresolved",
    protected_indeterminate: "protected Cache unpin replay remains indeterminate",
    protected_diverged: "protected Cache unpin transaction diverged",
    physical_unknown: "physical Cache unpin durability remains unknown",
};

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
                if let Some(custody) =
                    cache_custody_from_commit(execution.outcome, execution.settlement)
                {
                    self.pending_cache_unpin = Some(PendingControllerCacheUnpinV1 {
                        operation_id,
                        payload: pin,
                        custody,
                    });
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
                        payload: pin,
                        custody: CacheCustodyV1::Physical(pending),
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
        recover_pending_cache_custody(
            &mut self.pending_cache_unpin,
            &mut self.cache_inventory,
            &mut self.cache_physical,
            operation_id,
            public_cache_unpin_transaction_id_v1,
            &UNPIN_CUSTODY_MESSAGES,
        )
    }
}

fn cache_unpin_receipt(operation_id: OperationId) -> Result<EffectReceipt, EffectFailure> {
    let mut receipt = Vec::with_capacity(24);
    receipt.extend_from_slice(b"AOSCUN01");
    receipt.extend_from_slice(operation_id.as_bytes());
    EffectReceipt::new(receipt).map_err(|error| EffectFailure::Permanent(error.to_string()))
}
