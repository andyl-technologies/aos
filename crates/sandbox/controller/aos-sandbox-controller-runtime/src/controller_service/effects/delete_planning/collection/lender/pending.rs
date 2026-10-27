//! Connects actual initial-Six originals to the same durable pending consumer.
//!
//! This retains the complete borrowed collection and its exclusive Session
//! writers across the Source append. It neither accepts a public operation nor
//! releases the loan before the later real Root initial-prefix ACK.

use aos_sandbox_protocol::domain_ledger::delete_batch::{
    DeleteBatchViewV1, LifecycleDeleteBatchV1,
};

use super::*;
use aos_sandbox_protocol::domain_ledger::delete_root::{
    initial_inventory::DeleteRootInitialFrameDataV3, planning::DeleteRootPlanningDataErrorV3,
};

#[derive(Debug, thiserror::Error)]
enum InitialFrameConstructionErrorV2 {
    #[error(transparent)]
    Planning(#[from] DeleteRootPlanningDataErrorV3),
    #[error(transparent)]
    Cache(#[from] aos_sandbox_controller_domain::JournalError),
}

impl ControllerDeleteInitialSixPlanningLoanV2<'_, '_> {
    fn initial_frame_from_originals_v2(
        &self,
        association: ([u8; 32], [u8; 32]),
    ) -> Result<DeleteRootInitialFrameDataV3, InitialFrameConstructionErrorV2> {
        let (planning, challenge, observation) = self.planning_root_v2();
        let (cache_nonce, cache_cutoff) = self.cache_v2().coordinates_v1()?;
        Ok(DeleteRootInitialFrameDataV3 {
            open: association.0,
            challenge: association.1,
            planning_open: planning.encode_v3()?,
            planning_challenge: challenge.encode_v3()?,
            planning_observation: *observation,
            cache_nonce,
            cache_cutoff,
        })
    }

    /// Consumes the genuine authorization only after exact six/preimage binding.
    ///
    /// The candidate is produced privately from this collection's same real
    /// Cache graph and genuine authorization, with no caller-supplied operation
    /// or batch. It remains canonical DATA. The sole Source planner rechecks
    /// its actual authorization, three native base cuts, operation and full
    /// grammar. The same loan retains the exclusive Session writers through
    /// Root's independent initial EOF checks and actual same-flight ACK. Any
    /// refusal finishes the already owed outer Source after while all native
    /// clients, frames and original causes remain resident, then aborts.
    /// Later fresh-six owners and complete graph validation remain mandatory.
    pub(in crate::controller_service) fn plan_pending_and_verify_initial_once_v2<
        'scope,
        'original,
        'profile,
    >(
        &mut self,
        fields: &ControllerDeleteLocalRuntimeFieldsV1<'_>,
        mut authorized: ControllerDeleteSourceAuthorizedScopeV1<'scope, 'original>,
        bank: &aos_sandbox_controller_domain::ControllerResourceBankOpeningV1,
        controller: &mut Journal,
        profile: &'profile aos_sandbox_controller_domain::normal_root::ProductionControllerNormalRootProfileV1,
    ) -> (
        aos_sandbox_controller_domain::ControllerDeletePendingOriginalV2<'scope, 'original>,
        aos_sandbox_controller_domain::ControllerDeletePendingRootClientOriginalV2<'profile>,
    ) {
        if self.candidate.is_some() {
            let _after = bank.finish_delete_planning_source_failure_once_v1(
                &mut authorized, controller, profile,
            );
            std::process::abort();
        }
        self.candidate = Some(bank.prepare_authorized_delete_candidate_once_v2(
            &mut authorized, controller, profile, self.cache,
            fields.request_scope, self.cuts, self.initial,
        ));
        let prepared = match self.candidate.as_mut() {
            Some(Ok(original)) if original.failure_v2().is_none() => original.take_prepared_once_v2(),
            _ => {
                let _after = bank.finish_delete_planning_source_failure_once_v1(
                    &mut authorized, controller, profile,
                );
                std::process::abort();
            }
        };
        let (operation, batch) = match prepared {
            Ok(data) => data,
            Err(cause) => {
                let _primary = cause;
                let _after = bank.finish_delete_planning_source_failure_once_v1(
                    &mut authorized, controller, profile,
                );
                std::process::abort();
            }
        };

        let admitted = (|| {
            if !std::ptr::eq(profile, fields.profile.as_ref()) {
                return Err(ResourceReservationErrorV1::Conflict);
            }
            let bytes = DeleteBatchViewV1::decode_receiving_bytes_v1(batch.as_bytes().len())
                .and_then(|bytes| bytes.checked_mul(3))
                .and_then(|bytes| {
                    bytes.checked_add(
                        std::mem::size_of::<Result<(), ResourceReservationErrorV1>>()
                            .checked_mul(3)?,
                    )
                })
                .and_then(|bytes| {
                    bytes.checked_add(
                        std::mem::size_of::<
                            Result<DeleteRootInitialFrameDataV3, InitialFrameConstructionErrorV2>,
                        >()
                        .checked_mul(3)?,
                    )
                })
                .and_then(|bytes| {
                    bytes.checked_add(
                        std::mem::size_of::<
                            Result<
                                (
                                    aos_sandbox_controller_domain::ControllerDeletePendingOriginalV2<'_, '_>,
                                    aos_sandbox_controller_domain::ControllerDeletePendingRootClientOriginalV2<'_>,
                                ),
                                ResourceReservationErrorV1,
                            >,
                        >()
                        .checked_mul(3)?,
                    )
                })
                .ok_or(ResourceReservationErrorV1::Conflict)?;
            bank.reserve_delete_planning_collection_v2(&mut authorized, controller, profile, bytes)
        })();
        if admitted.is_err() {
            let _after = bank.finish_delete_planning_source_failure_once_v1(
                &mut authorized,
                controller,
                profile,
            );
            std::process::abort();
        }

        let matched = (|| {
            let view = batch
                .view()
                .map_err(|_| ResourceReservationErrorV1::Conflict)?;
            let commitments = view
                .named_commitments_v2()
                .ok_or(ResourceReservationErrorV1::Conflict)?;
            if commitments.initial_six != self.initial {
                return Err(ResourceReservationErrorV1::Conflict);
            }
            for (index, actual) in self.cuts.iter().enumerate() {
                let role =
                    u8::try_from(index + 1).map_err(|_| ResourceReservationErrorV1::Conflict)?;
                if view
                    .native_owner_cut_v2(role)
                    .map_err(|_| ResourceReservationErrorV1::Conflict)?
                    != *actual
                {
                    return Err(ResourceReservationErrorV1::Conflict);
                }
            }
            Ok(())
        })();

        if matched.is_err() {
            let _after = bank.finish_delete_planning_source_failure_once_v1(
                &mut authorized,
                controller,
                profile,
            );
            std::process::abort();
        }
        let mut pending = bank.commit_authorized_delete_pending_once_v2(
            authorized,
            controller,
            profile,
            fields.request_scope,
            operation,
            batch,
        );
        let opened =
            bank.begin_retained_delete_pending_root_client_v2(&mut pending, controller, profile);
        let mut client = match opened {
            Ok(client) => client,
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

        // No frame byte is constructed before this same-pending C17 debit.
        // The original planning nonce/cutoff stay historical; association comes
        // from the real current Root client without a pre-ACK challenge loan.
        let prepared = bank.prepare_delete_initial_frame_data_v2(
            &mut pending,
            &mut client,
            controller,
            profile,
        );
        let association = match &prepared {
            Ok(association) => *association,
            Err(_) => {
                let _after = bank.finish_delete_pending_source_failure_once_v2(
                    &mut pending,
                    controller,
                    profile,
                );
                std::process::abort();
            }
        };
        let frame = self.initial_frame_from_originals_v2(association);
        let actual_frame = match &frame {
            Ok(frame) => frame,
            Err(_) => {
                let _after = bank.finish_delete_pending_source_failure_once_v2(
                    &mut pending,
                    controller,
                    profile,
                );
                std::process::abort();
            }
        };
        let exchanged = bank.send_retained_delete_initial_inventory_once_v2(
            &mut pending,
            &mut client,
            controller,
            profile,
            actual_frame,
        );
        if exchanged.is_err() {
            let _after = bank.finish_delete_pending_source_failure_once_v2(
                &mut pending,
                controller,
                profile,
            );
            std::process::abort();
        }

        // The real client alone withholds fresh query loans until the ACK,
        // independent C/Root posts and positive local native disposal complete.
        // Returning it never releases a public lifecycle or effect guard.
        (pending, client)
    }
}
