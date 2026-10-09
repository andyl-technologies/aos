//! Owned ordinary Query stages under genuine original RootClosed custody.
//!
//! Original Sent/Pending/native2 remain occupied. Query candidates, packets and
//! independent count-one debt survive returned errors and unwind through the
//! guarded broker/Session boundary, starting from a genuine phase11 tuple.
//! Older original construction and panic-abort are not covered by that boundary.

use std::collections::BTreeMap;

use aos_sandbox::{
    JournalTransaction, MountOriginalInventoryJournalAuthorityV6,
    OriginalInventoryProtectedReadbackV6, PreparedOriginalInventoryAppendV6,
};
use aos_sandbox_protocol::mount_source_acquisition_state::native_held_completion::RootNativeHeldSidecarV2;
use aos_sandbox_source_provider_security::{
    CurrentRootMountSourceProviderSessionV1, OriginalInventoryPreparationV6,
    OriginalInventoryReceivedOutcomeV6, OriginalInventorySendV6,
};

use super::format::{MutationTagV2, state_error};
use super::model::*;
use super::native_selection::OriginalNativeAcquireFlightV5;
use super::reservation::{SentProviderQueryV2, sealed_attempt, sealed_head};
use super::transition::{MutationIdentityV2, prepare_mutation, record_ref};
use super::{
    FixedMountSourceAcquisitionOwnerV2, SourceAcquisitionRuntimeV2, SourceAcquisitionTableV2,
};
use crate::Result;

#[derive(Clone, Copy, Eq, PartialEq)]
enum Stage {
    Begin,
    Sign,
    ReserveOwners,
    ReserveCommit,
    ReserveInstall,
    Confirm,
    Send,
    Receive,
    DispositionOwners,
    DispositionCommit,
    DispositionInstall,
    Finished,
}

/// Holds move-only Query progress without references into its original owner.
pub(super) struct OriginalInventoryFlightV6 {
    stage: Stage,
    stopped: bool,
    root: Option<[u8; 32]>,
    query: Option<[u8; 32]>,
    preparation: Option<OriginalInventoryPreparationV6>,
    send: Option<OriginalInventorySendV6>,
    received: Option<OriginalInventoryReceivedOutcomeV6>,
    reservation_owners: Option<JournalTransaction>,
    reservation_table: Option<SourceAcquisitionTableV2>,
    reservation_append: Option<PreparedOriginalInventoryAppendV6>,
    reservation_readback: Option<OriginalInventoryProtectedReadbackV6>,
    disposition_owners: Option<JournalTransaction>,
    disposition_table: Option<SourceAcquisitionTableV2>,
    disposition_append: Option<PreparedOriginalInventoryAppendV6>,
    disposition_readback: Option<OriginalInventoryProtectedReadbackV6>,
}

impl OriginalInventoryFlightV6 {
    fn new() -> Self {
        Self {
            stage: Stage::Begin,
            stopped: false,
            root: None,
            query: None,
            preparation: None,
            send: None,
            received: None,
            reservation_owners: None,
            reservation_table: None,
            reservation_append: None,
            reservation_readback: None,
            disposition_owners: None,
            disposition_table: None,
            disposition_append: None,
            disposition_readback: None,
        }
    }

    fn finished(&self) -> bool {
        !self.stopped && self.stage == Stage::Finished
    }

    fn stop(&mut self, session: &mut CurrentRootMountSourceProviderSessionV1) {
        self.stopped = true;
        session.invalidate_original_inventory_progress_v6(
            self.preparation.as_mut(),
            self.send.as_mut(),
            self.received.as_mut(),
        );
    }

    fn advance(
        &mut self,
        table: &mut SourceAcquisitionTableV2,
        index: &mut BTreeMap<[u8; 32], RootNativeHeldSidecarV2>,
        writer: &mut MountOriginalInventoryJournalAuthorityV6<'_>,
        session: &mut CurrentRootMountSourceProviderSessionV1,
        original: &OriginalNativeAcquireFlightV5,
        sent: &SentProviderQueryV2,
    ) -> Result<bool> {
        if self.stopped {
            return Err(state_error("Query flight is permanently stopped"));
        }

        let endpoint = original.borrow_root_closed_for_inventory_v6(sent)?;
        let check = |session: &mut CurrentRootMountSourceProviderSessionV1,
                     writer: &MountOriginalInventoryJournalAuthorityV6<'_>| {
            session
                .revalidate_original_inventory_continuation_v6(writer, endpoint)
                .map_err(|_| state_error("Query original/current-cut check failed"))
        };
        check(session, writer)?;
        let current = writer.current_graph()?;
        let awaiting_install = matches!(self.stage, Stage::ReserveInstall | Stage::DispositionInstall);
        // A successful append intentionally leaves the private table at its
        // predecessor until the dedicated actual-readback installation stage.
        if (!awaiting_install && !table.matches_state(current.legacy()))
            || &*index != current.sidecars()
        {
            return Err(state_error("Query private table/index differ from actual full graph"));
        }
        let root = endpoint.2.attempt();
        if self.root.is_some_and(|stored| stored != root) {
            return Err(state_error("Query changed original association"));
        }
        self.root = Some(root);

        match self.stage {
            Stage::Begin => {
                session
                    .begin_original_inventory_v6(writer, endpoint, &mut self.preparation)
                    .map_err(|_| state_error("Query retained preparation failed"))?;
                self.stage = Stage::Sign;
            }
            Stage::Sign => {
                session.advance_original_inventory_preparation_v6(
                    writer,
                    endpoint,
                    self.preparation.as_mut()
                        .ok_or_else(|| state_error("Query preparation absent"))?,
                )
                .map_err(|_| state_error("Query signature failed; output retained"))?;
                self.stage = Stage::ReserveOwners;
            }
            Stage::ReserveOwners => {
                let preparation = self.preparation.as_ref()
                    .ok_or_else(|| state_error("Query signed preparation absent"))?;
                let (owners, tentative, query) =
                    table.prepare_original_inventory_reservation_v6(preparation)?;
                self.query = Some(query);
                self.reservation_owners = Some(owners);
                self.reservation_table = Some(tentative);

                writer.prepare_reservation(
                    root,
                    self.reservation_owners.as_ref()
                        .ok_or_else(|| state_error("Query Q1 owners absent"))?,
                    &mut self.reservation_append,
                )?;
                check(session, writer)?;
                self.stage = Stage::ReserveCommit;
            }
            Stage::ReserveCommit => {
                writer.commit_prepared(
                    self.reservation_append.as_mut()
                        .ok_or_else(|| state_error("Query Q1 candidate absent"))?,
                    &mut self.reservation_readback,
                )?;
                self.stage = Stage::ReserveInstall;
                writer.validate_readback(
                    self.reservation_readback.as_ref()
                        .ok_or_else(|| state_error("Query Q1 actual readback absent"))?,
                )?;
                check(session, writer)?;
            }
            Stage::ReserveInstall => {
                Self::install(
                    table,
                    index,
                    writer,
                    self.reservation_readback.as_ref()
                        .ok_or_else(|| state_error("Query Q1 readback absent"))?,
                    self.reservation_table.as_ref()
                        .ok_or_else(|| state_error("Query Q1 table absent"))?,
                )?;
                check(session, writer)?;
                self.stage = Stage::Confirm;
            }
            Stage::Confirm => {
                session.confirm_original_inventory_v6(
                    writer,
                    endpoint,
                    self.reservation_readback.as_ref()
                        .ok_or_else(|| state_error("Query confirmation actual Q1 absent"))?,
                    self.preparation.as_mut()
                        .ok_or_else(|| state_error("Query confirmation preparation absent"))?,
                    &mut self.send,
                )
                .map_err(|_| state_error("Query confirmation failed; custody retained"))?;
                self.stage = Stage::Send;
            }
            Stage::Send => {
                let accepted = session.send_original_inventory_v6(
                    writer,
                    endpoint,
                    self.send.as_mut().ok_or_else(|| state_error("Query send owner absent"))?,
                )
                .map_err(|_| state_error("Query send failed; possible-send custody retained"))?;
                if !accepted {
                    return Ok(false);
                }
                self.stage = Stage::Receive;
            }
            Stage::Receive => {
                let received = session.advance_original_inventory_receive_v6(
                    writer,
                    endpoint,
                    self.send.as_ref().ok_or_else(|| state_error("Query Sent owner absent"))?,
                    &mut self.received,
                )
                .map_err(|_| state_error("Query receive failed; packet custody retained"))?;
                if !received {
                    return Ok(false);
                }
                self.stage = Stage::DispositionOwners;
            }
            Stage::DispositionOwners => {
                let query = self.query.ok_or_else(|| state_error("Query Attempt absent"))?;
                let send = self.send.as_ref().ok_or_else(|| state_error("Query Sent absent"))?;
                let received = self.received.as_ref().ok_or_else(|| state_error("Query packet absent"))?;
                session
                    .revalidate_original_inventory_received_v6(writer, endpoint, send, received)
                    .map_err(|_| state_error("Query packet lost currentness"))?;
                let (owners, tentative) = table.prepare_original_inventory_disposition_v6(
                    query,
                    received.verified_inventory()
                        .ok_or_else(|| state_error("Query verified DATA absent"))?,
                )?;
                self.disposition_owners = Some(owners);
                self.disposition_table = Some(tentative);
                let owners = self.disposition_owners.as_ref()
                    .ok_or_else(|| state_error("Query Q2 owners absent"))?;
                session
                    .validate_original_inventory_prospective_v6(writer, endpoint, send, received, owners)
                    .map_err(|_| state_error("Query owner bytes differ from actual verified packet"))?;
                writer.prepare_disposition(root, query, owners, &mut self.disposition_append)?;
                session
                    .validate_original_inventory_prospective_v6(writer, endpoint, send, received, owners)
                    .map_err(|_| state_error("Query Q2 preparation lost currentness"))?;
                self.stage = Stage::DispositionCommit;
            }
            Stage::DispositionCommit => {
                let send = self.send.as_ref().ok_or_else(|| state_error("Query Sent absent"))?;
                let received = self.received.as_ref().ok_or_else(|| state_error("Query received absent"))?;
                session.validate_original_inventory_prospective_v6(
                    writer,
                    endpoint,
                    send,
                    received,
                    self.disposition_owners.as_ref()
                        .ok_or_else(|| state_error("Query Q2 owners absent"))?,
                )
                .map_err(|_| state_error("Query Q2 commit lost original/packet currentness"))?;
                writer.commit_prepared(
                    self.disposition_append.as_mut()
                        .ok_or_else(|| state_error("Query Q2 candidate absent"))?,
                    &mut self.disposition_readback,
                )?;
                self.stage = Stage::DispositionInstall;
                session.validate_original_inventory_readback_v6(
                    writer,
                    endpoint,
                    send,
                    received,
                    self.disposition_readback.as_ref()
                        .ok_or_else(|| state_error("Query Q2 actual readback absent"))?,
                )
                .map_err(|_| state_error("Query actual Q2 differs from packet; custody retained"))?;
            }
            Stage::DispositionInstall => {
                let send = self.send.as_ref().ok_or_else(|| state_error("Query Sent absent"))?;
                let received = self.received.as_ref().ok_or_else(|| state_error("Query received absent"))?;
                let actual = self.disposition_readback.as_ref()
                    .ok_or_else(|| state_error("Query Q2 actual readback absent"))?;
                session
                    .validate_original_inventory_readback_v6(writer, endpoint, send, received, actual)
                    .map_err(|_| state_error("Query pre-install packet/readback check failed"))?;

                Self::install(
                    table,
                    index,
                    writer,
                    actual,
                    self.disposition_table.as_ref()
                        .ok_or_else(|| state_error("Query Q2 table absent"))?,
                )?;
                session
                    .validate_original_inventory_readback_v6(writer, endpoint, send, received, actual)
                    .map_err(|_| state_error("Query installed packet/readback check failed"))?;
                self.stage = Stage::Finished;
            }
            Stage::Finished => {
                check(session, writer)?;
                return Ok(true);
            }
        }

        check(session, writer)?;
        Ok(self.finished())
    }

    fn install(
        table: &mut SourceAcquisitionTableV2,
        index: &mut BTreeMap<[u8; 32], RootNativeHeldSidecarV2>,
        writer: &MountOriginalInventoryJournalAuthorityV6<'_>,
        actual: &OriginalInventoryProtectedReadbackV6,
        tentative: &SourceAcquisitionTableV2,
    ) -> Result<()> {
        writer.validate_readback(actual)?;
        let graph = actual.graph()?;
        if !tentative.matches_state(graph.legacy()) {
            return Err(state_error("Query owner proposal differs from actual protected graph"));
        }

        *table = SourceAcquisitionTableV2::from_state(graph.legacy().clone());
        *index = graph.sidecars().clone();
        if !table.matches_state(graph.legacy()) || &*index != graph.sidecars() {
            return Err(state_error("Query private installation differs from actual protected graph"));
        }
        writer.validate_readback(actual)?;
        Ok(())
    }
}

impl SourceAcquisitionRuntimeV2 {
    /// Revokes actual owners after returned errors, including failed reattachment.
    pub(crate) fn invalidate_original_inventory_v6(
        &mut self,
        session: &mut CurrentRootMountSourceProviderSessionV1,
    ) {
        if let Some(original) = self.pending_original_native.as_mut() {
            original.stop_original_inventory_v6(session);
        } else {
            session.invalidate_original_inventory_continuation_v6(None);
        }

        if let Some(query) = self.pending_original_inventory.as_mut() {
            query.stop(session);
        }
        for query in &mut self.retained_original_inventory {
            query.stop(session);
        }
    }
}

impl FixedMountSourceAcquisitionOwnerV2<'_> {
    /// Parks a new independent Query without releasing an older Query's debt.
    ///
    /// # Errors
    /// Revokes retained runtime owners on occupied progress, capacity or boundary failure.
    pub(crate) fn begin_original_inventory_v6(
        &mut self,
        session: &mut CurrentRootMountSourceProviderSessionV1,
    ) -> Result<()> {
        let result = (|| {
            if let Some(prior) = self.runtime.pending_original_inventory.as_ref() {
                if !prior.finished() {
                    return Err(state_error("Query owner is already occupied"));
                }
                if self.runtime.retained_original_inventory.len()
                    >= super::format::MAXIMUM_SOURCE_PROVIDER_ATTEMPTS
                {
                    return Err(state_error("retained Query runtime bound exhausted"));
                }

                // Allocate before moving an older actual owner out of its slot.
                self.runtime.retained_original_inventory
                    .try_reserve(1)
                    .map_err(|_| state_error("retained Query archive capacity unavailable"))?;
                if let Some(prior) = self.runtime.pending_original_inventory.take() {
                    self.runtime.retained_original_inventory.push(prior);
                }
            }

            self.runtime.pending_original_inventory = Some(OriginalInventoryFlightV6::new());
            self.advance_original_inventory_v6(session)?;
            Ok(())
        })();
        if result.is_err() {
            self.runtime.invalidate_original_inventory_v6(session);
        }
        result
    }

    /// Advances one retained Query stage with fresh disjoint original reborrows.
    ///
    /// # Errors
    /// Revokes all retained owners, including on missing Sent or failed writer borrowing.
    pub(crate) fn advance_original_inventory_v6(
        &mut self,
        session: &mut CurrentRootMountSourceProviderSessionV1,
    ) -> Result<bool> {
        let result = (|| {
            let original = self.runtime.pending_original_native.as_ref()
                .ok_or_else(|| state_error("Query original owner absent"))?;
            let sent = self.runtime.pending_provider.as_ref()
                .ok_or_else(|| state_error("Query actual original Sent absent"))?;
            let query = self.runtime.pending_original_inventory.as_mut()
                .ok_or_else(|| state_error("Query runtime owner absent"))?;
            let mut writer = self.protected
                .root_original_inventory_authority_v6()
                .map_err(|error| state_error(error.to_string()))?;
            query.advance(
                &mut self.runtime.table,
                &mut self.runtime.original_native_sidecars,
                &mut writer,
                session,
                original,
                sent,
            )
        })();

        // All disjoint immutable endpoint loans have ended before revocation.
        if result.is_err() {
            self.runtime.invalidate_original_inventory_v6(session);
        }
        result
    }

    pub(super) fn require_no_original_inventory_v6(
        &mut self,
        session: &mut CurrentRootMountSourceProviderSessionV1,
    ) -> Result<()> {
        if self.runtime.pending_original_inventory.is_some()
            || !self.runtime.retained_original_inventory.is_empty()
        {
            self.runtime.invalidate_original_inventory_v6(session);
            return Err(state_error("old original stages cannot cross retained Query progress"));
        }
        Ok(())
    }
}

impl SourceAcquisitionTableV2 {
    fn prepare_original_inventory_reservation_v6(
        &self,
        preparation: &OriginalInventoryPreparationV6,
    ) -> Result<(JournalTransaction, Self, [u8; 32])> {
        let (prepared, draft) = preparation
            .reservation_data()
            .ok_or_else(|| state_error("Query reservation DATA unavailable"))?;
        let projection = prepared.projection();
        let head = self.provider_heads
            .get(&(draft.scope.holder_authority_id, draft.scope.provider_authority_id))
            .ok_or_else(|| state_error("Query current Head absent"))?;
        if head.pending_attempt.is_some()
            || head.recovery_barrier.is_some()
            || projection.method() != aos_sandbox_source_provider_protocol::SourceProviderMethod::Inventory
            || projection.request_identity() != (draft.request_id, draft.request_sequence)
            || projection.expected_response_sequence() != head.next_response_sequence
            || projection.acquisition_identity().is_some()
            || projection.normalized_intent().is_some()
        {
            return Err(state_error("Query signed request differs from retained draft/current Head"));
        }
        let session = self.provider_sessions.get(&draft.session_id)
            .ok_or_else(|| state_error("Query current Session absent"))?;
        let projected = super::security::session_from_request(projection, session.predecessor_session_id)?;
        if &projected != session {
            return Err(state_error("Query preparation differs from exact current Session"));
        }

        let mut attempt = draft.clone();
        attempt.signed_request = prepared.canonical_signed_request().to_vec();
        attempt.signed_request_digest = *projection.request_digests().2.as_bytes();
        attempt.inventory_correlations = projection.inventory_correlations().cloned();
        let attempt = sealed_attempt(attempt)?;
        let attempt_record = StoredRecordV2::ProviderQueryAttempt { value: attempt };
        let reference = record_ref(&attempt_record)?;
        let query = reference.id;
        let next_head = sealed_head(
            aos_sandbox_protocol::mount_source_acquisition_state::derive_inventory_reservation_head_v2(
                head,
                reference,
            )
            .map_err(super::format::inventory_owner_derivation_error)?,
        )?;
        let identity = MutationIdentityV2 {
            tag: MutationTagV2::ReserveRetry,
            holder_id: head.scope.holder_authority_id,
            provider_id: head.scope.provider_authority_id,
            next_holder_sequence_revision: self.holder_sequences
                .get(&head.scope.holder_authority_id)
                .map_or(0, |holder| holder.revision),
            next_head_revision: next_head.revision,
            acquisition_id: None,
            next_row_revision: None,
            attempt_id: Some(query),
            next_attempt_revision: Some(reference.revision),
            session_id: None,
        };
        let (owners, tentative) = prepare_mutation(
            self,
            identity,
            vec![attempt_record, StoredRecordV2::ProviderHead { value: next_head }],
        )?;
        Ok((owners, tentative, query))
    }
}
