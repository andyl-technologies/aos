//! Joins initial and genuine recovered Delete intake through one authorization.
//!
//! This private entry splits actual executor fields before lending Source. The
//! whole original stays in `delete_original`; the initial path alone claims it.
//! The public Delete ingress enters only the concrete final-disposition caller
//! below, which keeps these same borrowers through actual destruction.

use super::*;
use aos_sandbox::public_api_session::PublicApiPeer;
use aos_sandbox::{ControllerDeleteAuthorizedScopeV1, ResourceReservationErrorV1};
use aos_sandbox_core::CapabilityId;

/// Retains authorization beside the exact disjoint Source/Cache/runtime fields.
pub(in crate::controller_service) struct ControllerDeleteRuntimeEntryV3<'runtime> {
    authorization: ControllerDeleteAuthorizedScopeV1<'runtime>,
    fields: ControllerDeleteSourceRuntimeSplitV1<'runtime>,
    source_result: Option<Result<(), ResourceReservationErrorV1>>,
    source_attempted: bool,
    source_entered: bool,
}

/// Keeps the actual Source/native lender beside the same non-Source fields.
pub(in crate::controller_service) struct ControllerDeleteSourceEntryV3<'scope, 'runtime> {
    pub(in crate::controller_service) source:
        ControllerDeleteSourceAuthorizedScopeV1<'scope, 'runtime>,
    pub(in crate::controller_service) cache:
        &'scope mut ControllerDeleteCacheRuntimeFieldsV1<'runtime>,
    pub(in crate::controller_service) local: &'scope ControllerDeleteLocalRuntimeFieldsV1<'runtime>,
}

impl ProductionEffectExecutor {
    pub(in crate::controller_service) fn run_original_delete_once_v4(
        &mut self,
        controller: &mut Journal,
        peer: &PublicApiPeer,
        capability: CapabilityId,
        handle: &[u8],
        encoded: &[u8],
    ) -> Result<aos_sandbox::AcceptOutcome, ResourceReservationErrorV1> {
        // Cloning these Arc headers preserves the same original owners while
        // the executor's disjoint Source/cache/authorization fields are lent.
        let bank = Arc::clone(
            self.resource_bank
                .as_ref()
                .ok_or(ResourceReservationErrorV1::Conflict)?,
        );
        let sessions = Arc::clone(&self.sessions);
        let profile = Arc::clone(
            self.execution_profile
                .as_ref()
                .ok_or(ResourceReservationErrorV1::Conflict)?,
        );
        let mut entry = self
            .prepare_delete_runtime_entry_once_v3(controller, peer, capability, handle, encoded)?;
        let bank = match bank.lock() {
            Ok(bank) => bank,
            Err(cause) => {
                // The poisoned guard is usable solely for the directly owed
                // original post, never a fresh healthy admission or effect.
                let bank = cause.into_inner();
                let _post = entry.finish_before_source_once_v3(&bank, controller);
                let _whole = (entry, bank);
                std::process::abort();
            }
        };
        let mut sessions = match sessions.lock() {
            Ok(sessions) => sessions,
            Err(cause) => {
                let _post = entry.finish_before_source_once_v3(&bank, controller);
                let _whole = (entry, cause);
                std::process::abort();
            }
        };
        match entry.run_collection_once_v4(&mut sessions, &bank, controller, &profile) {
            Ok(outcome) => Ok(outcome),
            Err(cause) => {
                let _whole = (entry, cause);
                std::process::abort();
            }
        }
    }

    pub(in crate::controller_service) fn prepare_delete_runtime_entry_once_v3(
        &mut self,
        controller: &mut Journal,
        peer: &PublicApiPeer,
        capability: CapabilityId,
        handle: &[u8],
        encoded: &[u8],
    ) -> Result<ControllerDeleteRuntimeEntryV3<'_>, ResourceReservationErrorV1> {
        let profile = self
            .execution_profile
            .as_ref()
            .ok_or(ResourceReservationErrorV1::Conflict)?;
        let ownership = self
            .snapshot_ownership
            .as_ref()
            .filter(|owner| owner.get().is_some())
            .ok_or(ResourceReservationErrorV1::Conflict)?;
        let bank = self
            .resource_bank
            .as_ref()
            .ok_or(ResourceReservationErrorV1::Conflict)?;
        let bank = bank
            .lock()
            .map_err(|_| ResourceReservationErrorV1::Conflict)?;
        // A recovered Some is the actual moved original from the atomic D/X
        // placement. It reaches the same authorization engine without a claim.
        if self.delete_original.is_none() {
            if self.delete_claim.is_some() {
                return Err(ResourceReservationErrorV1::Conflict);
            }
            match aos_sandbox::ControllerDeleteAuthorizationOriginalV1::claim_once_v1(
                &bank, controller, profile,
            ) {
                Ok(original) => {
                    self.delete_original = Some(original);
                    self.delete_claim = Some(Ok(()));
                }
                Err(cause) => {
                    self.delete_claim = Some(Err(cause));
                    return Err(ResourceReservationErrorV1::Conflict);
                }
            }
        }
        let original = self
            .delete_original
            .as_mut()
            .ok_or(ResourceReservationErrorV1::Conflict)?;
        let mut authorization = original.authorize_once_v1(
            &bank, controller, profile, peer, capability, handle, encoded,
        )?;
        let construction = std::mem::size_of::<ControllerDeleteRuntimeEntryV3<'_>>()
            .checked_mul(3)
            .and_then(|bytes| {
                bytes.checked_add(
                    std::mem::size_of::<ControllerDeleteSourceEntryV3<'_, '_>>().checked_mul(3)?,
                )
            })
            .and_then(|bytes| {
                bytes.checked_add(
                    std::mem::size_of::<(
                        Arc<Mutex<aos_sandbox::ControllerResourceBankOpeningV1>>,
                        Arc<Mutex<ControllerBrokerSessions>>,
                        Arc<aos_sandbox::normal_root::ProductionControllerNormalRootProfileV1>,
                        std::sync::MutexGuard<'_, aos_sandbox::ControllerResourceBankOpeningV1>,
                        std::sync::MutexGuard<'_, ControllerBrokerSessions>,
                    )>()
                    .checked_mul(3)?,
                )
            });
        let paid = match construction {
            Some(bytes) => authorization
                .reserve_runtime_construction_once_v3(&bank, controller, profile, bytes),
            None => {
                authorization.reserve_runtime_construction_once_v3(&bank, controller, profile, 0)
            }
        };
        if paid.is_err() {
            // No Runtime wrapper or Source scope exists yet; the original
            // authorization retains the funding error and its C post is owed.
            authorization.finish_without_source_v1(&bank, controller, profile);
            return Err(ResourceReservationErrorV1::Conflict);
        }
        // Explicit field splitting avoids borrowing the whole executor while
        // its original financial/authorization owner is continuously borrowed.
        let fields = ControllerDeleteSourceRuntimeSplitV1 {
            source: &mut self.source_domains,
            cache: ControllerDeleteCacheRuntimeFieldsV1 {
                initialized: &mut self.cache_resident_usage,
                owner: &mut self.cache_inventory,
                physical: &self.cache_physical,
            },
            local: ControllerDeleteLocalRuntimeFieldsV1 {
                request_scope: self.request_scope,
                transfer: &self.transfer_inventory,
                profile,
                ownership,
                signer: &self.broker_plan_signer,
            },
        };
        Ok(ControllerDeleteRuntimeEntryV3 {
            authorization,
            fields,
            source_result: None,
            source_attempted: false,
            source_entered: false,
        })
    }
}

impl<'runtime> ControllerDeleteRuntimeEntryV3<'runtime> {
    fn run_collection_once_v4(
        &mut self,
        sessions: &mut ControllerBrokerSessions,
        bank: &aos_sandbox::ControllerResourceBankOpeningV1,
        controller: &mut Journal,
        profile: &aos_sandbox::normal_root::ProductionControllerNormalRootProfileV1,
    ) -> Result<aos_sandbox::AcceptOutcome, ResourceReservationErrorV1> {
        let entered = self.borrow_source_once_v3(bank, controller);
        if entered.is_err() {
            let _cause = entered.err();
            let _post = self.finish_before_source_once_v3(bank, controller);
            return Err(ResourceReservationErrorV1::Conflict);
        }
        let mut entry = match entered {
            Ok(entry) => entry,
            Err(_) => std::process::abort(),
        };
        let collected = ControllerDeletePlanningCollectionV2::collect_authorized_once_v2(
            sessions,
            entry.cache,
            entry.local,
            &mut entry.source,
            bank,
            controller,
            profile,
        );
        let mut collection = match collected {
            Ok(collection) => collection,
            Err(cause) => {
                let _cause = cause;
                let _after = bank.finish_delete_planning_source_failure_once_v1(
                    &mut entry.source,
                    controller,
                    profile,
                );
                std::process::abort();
            }
        };
        let (mut pending, mut client) = {
            let mut loan = collection.borrow_initial_planning_once_v2(
                entry.local,
                &mut entry.source,
                bank,
                controller,
                profile,
            );
            loan.plan_pending_and_verify_initial_once_v2(
                entry.local,
                entry.source,
                bank,
                controller,
                profile,
            )
        };
        // This is the canonical operation selected by the genuine planner,
        // retained before final positive disposal clears its pure caches.
        let identity = pending.operation_id_data_v4();
        let operation = match identity {
            Ok(operation) => operation,
            Err(cause) => {
                let _cause = cause;
                let _after = bank.finish_delete_pending_source_failure_once_v2(
                    &mut pending,
                    controller,
                    profile,
                );
                std::process::abort();
            }
        };
        let completed = collection.collect_pending_sessions_once_v2(
            &mut pending,
            &mut client,
            bank,
            controller,
            profile,
            entry.local,
        );
        if let Err(cause) = completed {
            let _after = bank.finish_delete_pending_source_failure_once_v2(
                &mut pending,
                controller,
                profile,
            );
            let _whole = (collection, client, cause);
            std::process::abort();
        }
        collection.dispose_completed_once_v4(&mut pending, client, bank, controller, profile);
        drop(pending);
        Ok(aos_sandbox::AcceptOutcome::Accepted(operation))
    }

    pub(in crate::controller_service) fn borrow_source_once_v3<'scope>(
        &'scope mut self,
        bank: &aos_sandbox::ControllerResourceBankOpeningV1,
        controller: &Journal,
    ) -> Result<ControllerDeleteSourceEntryV3<'scope, 'runtime>, ResourceReservationErrorV1> {
        if self.source_attempted {
            return Err(ResourceReservationErrorV1::Conflict);
        }
        self.source_attempted = true;
        // Err returns no Source owner and has performed no Source IO. Its C
        // post remains on the early path. Ok retains even a failed Source
        // before-original, whose independent after belongs to that real scope.
        let source = match self.authorization.borrow_source_authorized_v1(
            self.fields.source,
            bank,
            controller,
            self.fields.local.profile,
        ) {
            Ok(source) => {
                self.source_result = Some(Ok(()));
                self.source_entered = true;
                source
            }
            Err(cause) => {
                self.source_result = Some(Err(cause));
                return Err(ResourceReservationErrorV1::Conflict);
            }
        };
        Ok(ControllerDeleteSourceEntryV3 {
            source,
            cache: &mut self.fields.cache,
            local: &self.fields.local,
        })
    }

    pub(in crate::controller_service) fn finish_before_source_once_v3(
        &mut self,
        bank: &aos_sandbox::ControllerResourceBankOpeningV1,
        controller: &mut Journal,
    ) -> Result<(), ResourceReservationErrorV1> {
        if self.source_entered {
            return Err(ResourceReservationErrorV1::Conflict);
        }
        self.authorization
            .finish_without_source_v1(bank, controller, self.fields.local.profile);
        Ok(())
    }
}
