//! Retains the whole original Storage Inventory predecessor validation interval.
//!
//! The existing ordinary validator immediately enters the same ordered engine
//! without destinations. This owner retains reached context, peer, canonical
//! replay and terminal semantics before later refusals. It creates no Session,
//! Journal, terminal authority or resource grant; the closed selected caller
//! must first pay the actual receiving geometry under its genuine original.

use super::*;
use aos_sandbox_broker_session_protocol::durable::{BrokerSessionDurableError, BrokerSessionPeerBindingV1};
use super::current_context::CurrentContextOriginalsV1;
use super::peer_current::CurrentPeerOriginalsV1;
use super::super::TerminalSemanticsOriginalsV1;
use super::super::current_replay::{
    ReplayValue, ReopenCurrentOriginalsV1, head_value, security_value,
};

#[derive(Default)]
pub(crate) struct OutcomeCurrentOriginalsV1 {
    entry: Option<Result<(), BrokerSessionSecurityError>>,
    floor_method: Option<Result<(), BrokerSessionSecurityError>>,
    context: CurrentContextOriginalsV1,
    context_comparison: Option<Result<(), BrokerSessionSecurityError>>,
    before_peer: CurrentPeerOriginalsV1,
    peer_binding: Option<Result<BrokerSessionPeerBindingV1, BrokerSessionSecurityError>>,
    replay: ReopenCurrentOriginalsV1,
    head: Option<Result<(), BrokerSessionDurableError>>,
    protected_binding: Option<Result<BrokerSessionProtectedBindingsV1, BrokerSessionSecurityError>>,
    head_comparison: Option<Result<(), BrokerSessionSecurityError>>,
    terminal: TerminalSemanticsOriginalsV1,
    terminal_comparison: Option<Result<(), BrokerSessionSecurityError>>,
    after_peer: CurrentPeerOriginalsV1,
    after_binding: Option<Result<BrokerSessionPeerBindingV1, BrokerSessionSecurityError>>,
    after_comparison: Option<Result<(), BrokerSessionSecurityError>>,
    returned: Option<Result<(), BrokerSessionSecurityError>>,
    closed: Option<BrokerSessionSecurityError>,
}

#[derive(Clone, Copy)]
enum RetainedInventoryPurposeV1 { Storage, Delete, Reconciliation(BrokerMethod), DeletePreparation, DeleteApply, DeleteNetwork, DeleteMount }

impl OutcomeCurrentOriginalsV1 {
    pub(in crate::recovery) fn observe_storage_receiving_v3(&mut self,
        journal: &mut ProtectedBrokerSessionJournalV1,
        owner: &ProtectedBrokerOutcomeCurrentnessOwnerV1,
        peer: &ConnectionPeerIdentity,
        receiving: &mut dyn StorageFloorFinancialSourceV2,
    ) -> Result<(), BrokerSessionSecurityError> {
        if self.entry.is_some() || self.closed.is_some() {
            self.closed.get_or_insert(BrokerSessionSecurityError::Currentness);
            return Err(BrokerSessionSecurityError::Currentness);
        }
        self.entry = Some(Ok(()));
        self.returned = Some(journal.validate_broker_outcome_with_storage_receiving_v3(
            owner, peer, Some(self), Some(receiving),
        ));
        self.require_complete()
    }

    pub(super) fn observe_execution_once_v1(&mut self,
        journal: &mut ProtectedBrokerSessionJournalV1,
        owner: &ProtectedBrokerOutcomeCurrentnessOwnerV1,
        peer: &ConnectionPeerIdentity,
    ) -> Result<(), BrokerSessionSecurityError> {
        if self.entry.is_some() || self.closed.is_some() {
            self.closed.get_or_insert(BrokerSessionSecurityError::Currentness);
            return Err(BrokerSessionSecurityError::Currentness);
        }
        // Only the concrete prearmed execution original enters this private
        // named route, after its same-writer/socket/transcript comparison.
        self.entry = Some(Ok(()));
        self.returned = Some(journal.validate_broker_outcome_with_originals(owner, peer, Some(self)));
        self.require_complete()
    }

    pub(crate) fn observe_inventory_once(
        &mut self,
        journal: &mut ProtectedBrokerSessionJournalV1,
        owner: &ProtectedBrokerOutcomeCurrentnessOwnerV1,
        connection_peer: &ConnectionPeerIdentity,
    ) -> Result<(), BrokerSessionSecurityError> {
        self.observe_inventory_engine(journal, owner, connection_peer, RetainedInventoryPurposeV1::Storage)
    }

    pub(crate) fn observe_delete_inventory_once(
        &mut self,
        journal: &mut ProtectedBrokerSessionJournalV1,
        owner: &ProtectedBrokerOutcomeCurrentnessOwnerV1,
        connection_peer: &ConnectionPeerIdentity,
    ) -> Result<(), BrokerSessionSecurityError> {
        self.observe_inventory_engine(journal, owner, connection_peer, RetainedInventoryPurposeV1::Delete)
    }

    pub(crate) fn observe_reconciliation_inventory_once_v2(&mut self,
        journal: &mut ProtectedBrokerSessionJournalV1,
        owner: &ProtectedBrokerOutcomeCurrentnessOwnerV1,
        peer: &ConnectionPeerIdentity, method: BrokerMethod,
    ) -> Result<(), BrokerSessionSecurityError> {
        self.observe_inventory_engine(journal, owner, peer, RetainedInventoryPurposeV1::Reconciliation(method))
    }

    pub(crate) fn observe_delete_preparation_once_v3(&mut self,
        journal: &mut ProtectedBrokerSessionJournalV1,
        owner: &ProtectedBrokerOutcomeCurrentnessOwnerV1,
        peer: &ConnectionPeerIdentity,
    ) -> Result<(), BrokerSessionSecurityError> {
        self.observe_inventory_engine(journal, owner, peer, RetainedInventoryPurposeV1::DeletePreparation)
    }

    pub(super) fn observe_delete_apply_once_v3(&mut self,
        journal: &mut ProtectedBrokerSessionJournalV1,
        owner: &ProtectedBrokerOutcomeCurrentnessOwnerV1,
        peer: &ConnectionPeerIdentity,
    ) -> Result<(), BrokerSessionSecurityError> {
        self.observe_inventory_engine(journal, owner, peer, RetainedInventoryPurposeV1::DeleteApply)
    }

    pub(super) fn observe_delete_network_once_v4(&mut self,
        journal: &mut ProtectedBrokerSessionJournalV1,
        owner: &ProtectedBrokerOutcomeCurrentnessOwnerV1, peer: &ConnectionPeerIdentity,
    ) -> Result<(), BrokerSessionSecurityError> {
        self.observe_inventory_engine(journal, owner, peer, RetainedInventoryPurposeV1::DeleteNetwork)
    }

    pub(super) fn observe_delete_mount_once_v4(&mut self,
        journal: &mut ProtectedBrokerSessionJournalV1,
        owner: &ProtectedBrokerOutcomeCurrentnessOwnerV1, peer: &ConnectionPeerIdentity,
    ) -> Result<(), BrokerSessionSecurityError> {
        self.observe_inventory_engine(journal, owner, peer, RetainedInventoryPurposeV1::DeleteMount)
    }

    fn observe_inventory_engine(
        &mut self,
        journal: &mut ProtectedBrokerSessionJournalV1,
        owner: &ProtectedBrokerOutcomeCurrentnessOwnerV1,
        connection_peer: &ConnectionPeerIdentity,
        purpose: RetainedInventoryPurposeV1,
    ) -> Result<(), BrokerSessionSecurityError> {
        if self.entry.is_some() || self.closed.is_some() {
            self.closed.get_or_insert(BrokerSessionSecurityError::Currentness);
            return Err(BrokerSessionSecurityError::Currentness);
        }
        self.entry = Some(match purpose {
            RetainedInventoryPurposeV1::DeleteNetwork => journal.delete_inventory_client_method_v1()
                .and_then(|method| {
                    if method != BrokerMethod::BROKER_METHOD_NETWORK_INVENTORY_RESOURCES {
                        return Err(BrokerSessionSecurityError::Currentness);
                    }
                    journal.require_controller_inventory_predecessor_method_v2(owner, BrokerMethod::BROKER_METHOD_NETWORK_APPLY)
                }),
            RetainedInventoryPurposeV1::DeleteMount => journal.delete_inventory_client_method_v1()
                .and_then(|method| {
                    if method != BrokerMethod::BROKER_METHOD_MOUNT_INVENTORY_DESTINATION_SLOTS {
                        return Err(BrokerSessionSecurityError::Currentness);
                    }
                    journal.require_controller_inventory_predecessor_method_v2(owner, BrokerMethod::BROKER_METHOD_MOUNT_APPLY_ATTACHMENT_ANCHOR_V1)
                }),
            RetainedInventoryPurposeV1::Storage => journal.require_storage_inventory_predecessor_v1(owner),
            RetainedInventoryPurposeV1::DeleteApply => journal.retained_storage_client_recipe_v1()
                .and_then(|()| journal.require_controller_inventory_predecessor_method_v2(
                    owner, BrokerMethod::BROKER_METHOD_STORAGE_APPLY)),
            RetainedInventoryPurposeV1::DeletePreparation => journal.retained_storage_client_recipe_v1()
                .and_then(|()| journal.require_controller_inventory_predecessor_method_v2(
                    owner, BrokerMethod::BROKER_METHOD_STORAGE_PREPARE_CATALOG)),
            RetainedInventoryPurposeV1::Delete => journal.require_delete_inventory_predecessor_v1(owner),
            RetainedInventoryPurposeV1::Reconciliation(method) => journal.require_reconciliation_inventory_predecessor_v2(owner, method),
        });
        if !matches!(self.entry, Some(Ok(()))) {
            return Err(BrokerSessionSecurityError::Currentness);
        }
        if matches!(purpose, RetainedInventoryPurposeV1::Delete) {
            self.replay.bind_delete_inventory_once_v1(journal, owner)?;
        }
        if let RetainedInventoryPurposeV1::Reconciliation(method) = purpose {
            self.replay.bind_reconciliation_inventory_once_v2(journal, owner, method)?;
        }
        self.returned = Some(journal.validate_broker_outcome_with_originals(
            owner,
            connection_peer,
            Some(self),
        ));
        self.require_complete()
    }

    pub(crate) fn require_complete(&self) -> Result<(), BrokerSessionSecurityError> {
        if self.failure().is_some() || !matches!(self.returned, Some(Ok(()))) {
            return Err(BrokerSessionSecurityError::Currentness);
        }
        Ok(())
    }

    pub(crate) fn negotiated_delete_preimages_v2(&self) -> Option<(
        &[u8], &HistoricalSessionCheckpointV1,
        &BrokerSessionDurableHistoryV1,
    )> {
        self.require_complete().ok()?;
        self.replay.negotiated_delete_preimages_v2()
    }

    pub(crate) fn retained_endpoint_open_files_v1() -> Option<usize> {
        CurrentPeerOriginalsV1::retained_endpoint_open_files_v1()?.checked_mul(2)
    }

    // Q04's private flight headers allocate their leaves only after the actual
    // typed fixed entry. The old supplier retains one construction plane; add
    // two planes and actual carriers for the separately stored pointee. Other
    // inline and SDK owners continue using their unchanged suppliers.
    pub(crate) fn boxed_receiving_footprint_v2() -> Option<(usize, usize)> {
        let (memory, cells) = Self::receiving_footprint_v1()?;
        let bytes = std::mem::size_of::<Self>()
            .checked_mul(2)?
            .checked_add(std::mem::size_of::<Box<Self>>().checked_mul(2)?)?
            .checked_add(std::mem::size_of::<std::alloc::Layout>())?;

        Some((memory.checked_add(bytes)?, cells))
    }

    pub(crate) fn receiving_footprint_v1() -> Option<(usize, usize)> {
        let context = CurrentContextOriginalsV1::receiving_footprint_v1()?;
        let peer = CurrentPeerOriginalsV1::receiving_footprint_v1()?;
        let replay = super::super::current_replay::receiving_footprint_v1()?;
        let terminal = TerminalSemanticsOriginalsV1::receiving_footprint_v1()?;
        // The outer flight includes this resident owner in its own sizeof.
        // This additional copy bounds its actual default-construction carrier;
        // each nested supplier also includes its explicit construction/return
        // temporaries and retained non-inline backing.
        // The destination constructor and moved closure captures coexist with
        // the post destination and its construction carrier. The remaining
        // references and interval Results are ordinary stack Memory.
        let interval_carriers = std::mem::size_of::<OutcomeDestinationsV1<'static>>()
            .checked_mul(2)?
            .checked_add(std::mem::size_of::<OutcomePeerPostDestinationsV1<'static>>().checked_mul(2)?)?
            .checked_add(std::mem::size_of::<[usize; 4]>())?
            .checked_add(std::mem::size_of::<bool>())?
            .checked_add(std::mem::size_of::<[Result<(), BrokerSessionSecurityError>; 2]>())?;
        let memory = std::mem::size_of::<Self>()
            .checked_add(interval_carriers)?
            .checked_add(context.0)?
            .checked_add(peer.0.checked_mul(2)?)?
            .checked_add(replay.0)?
            .checked_add(terminal.0)?;
        // Twelve direct Result/refusal cells are separate from the complete
        // nested context, two peers, canonical replay and terminal suppliers.
        let cells = 12_usize.checked_add(context.1)?
            .checked_add(peer.1.checked_mul(2)?)?
            .checked_add(replay.1)?
            .checked_add(terminal.1)?;
        Some((memory, cells))
    }

    pub(crate) fn failure(&self) -> Option<&(dyn std::error::Error + 'static)> {
        fn cause<T, E: std::error::Error + 'static>(
            result: &Option<Result<T, E>>,
        ) -> Option<&(dyn std::error::Error + 'static)> {
            result.as_ref()?.as_ref().err().map(|cause| cause as _)
        }

        cause(&self.entry)
            .or_else(|| cause(&self.floor_method))
            .or_else(|| self.context.failure())
            .or_else(|| cause(&self.context_comparison))
            .or_else(|| self.before_peer.failure())
            .or_else(|| cause(&self.peer_binding))
            .or_else(|| self.replay.failure())
            .or_else(|| cause(&self.head))
            .or_else(|| cause(&self.protected_binding))
            .or_else(|| cause(&self.head_comparison))
            .or_else(|| self.terminal.failure())
            .or_else(|| cause(&self.terminal_comparison))
            .or_else(|| self.after_peer.failure())
            .or_else(|| cause(&self.after_binding))
            .or_else(|| cause(&self.after_comparison))
            .or_else(|| cause(&self.returned))
            .or_else(|| self.closed.as_ref().map(|cause| cause as _))
    }
}

#[derive(Default)]
struct OutcomeDestinationsV1<'owner> {
    floor_method: Option<&'owner mut Option<Result<(), BrokerSessionSecurityError>>>,
    context: Option<&'owner mut CurrentContextOriginalsV1>,
    context_comparison: Option<&'owner mut Option<Result<(), BrokerSessionSecurityError>>>,
    before_peer: Option<&'owner mut CurrentPeerOriginalsV1>,
    peer_binding: Option<&'owner mut Option<Result<BrokerSessionPeerBindingV1, BrokerSessionSecurityError>>>,
    replay: Option<&'owner mut ReopenCurrentOriginalsV1>,
    head: Option<&'owner mut Option<Result<(), BrokerSessionDurableError>>>,
    protected_binding: Option<&'owner mut Option<Result<BrokerSessionProtectedBindingsV1, BrokerSessionSecurityError>>>,
    head_comparison: Option<&'owner mut Option<Result<(), BrokerSessionSecurityError>>>,
    terminal: Option<&'owner mut TerminalSemanticsOriginalsV1>,
    terminal_comparison: Option<&'owner mut Option<Result<(), BrokerSessionSecurityError>>>,
    after_peer: Option<&'owner mut CurrentPeerOriginalsV1>,
    after_binding: Option<&'owner mut Option<Result<BrokerSessionPeerBindingV1, BrokerSessionSecurityError>>>,
    after_comparison: Option<&'owner mut Option<Result<(), BrokerSessionSecurityError>>>,
}

/// Separates the already-paid peer post from fallible terminal reconstruction.
struct OutcomePeerPostDestinationsV1<'owner> {
    peer: Option<&'owner mut CurrentPeerOriginalsV1>,
    binding: Option<&'owner mut Option<Result<BrokerSessionPeerBindingV1, BrokerSessionSecurityError>>>,
    comparison: Option<&'owner mut Option<Result<(), BrokerSessionSecurityError>>>,
}

impl<'owner> From<Option<&'owner mut OutcomeCurrentOriginalsV1>> for OutcomeDestinationsV1<'owner> {
    fn from(originals: Option<&'owner mut OutcomeCurrentOriginalsV1>) -> Self {
        let Some(originals) = originals else {
            return Self::default();
        };
        Self {
            floor_method: Some(&mut originals.floor_method),
            context: Some(&mut originals.context),
            context_comparison: Some(&mut originals.context_comparison),
            before_peer: Some(&mut originals.before_peer),
            peer_binding: Some(&mut originals.peer_binding),
            replay: Some(&mut originals.replay),
            head: Some(&mut originals.head),
            protected_binding: Some(&mut originals.protected_binding),
            head_comparison: Some(&mut originals.head_comparison),
            terminal: Some(&mut originals.terminal),
            terminal_comparison: Some(&mut originals.terminal_comparison),
            after_peer: Some(&mut originals.after_peer),
            after_binding: Some(&mut originals.after_binding),
            after_comparison: Some(&mut originals.after_comparison),
        }
    }
}

fn context_value<'owner>(
    journal: &mut ProtectedBrokerSessionJournalV1,
    transcript: &VerifiedBrokerSessionTranscriptV1,
    originals: Option<&'owner mut CurrentContextOriginalsV1>,
    receiving: Option<&mut dyn StorageFloorFinancialSourceV2>,
) -> Result<ReplayValue<'owner, ProtectedBrokerSessionVerificationContextV1>, BrokerSessionSecurityError> {
    let Some(originals) = originals else {
        return journal.current_context_with_storage_receiving_v2(transcript, None, receiving);
    };
    originals.observe_with_storage_receiving_v3(journal, transcript, receiving)?;
    originals.value().map(ReplayValue::Retained)
        .ok_or(BrokerSessionSecurityError::Currentness)
}

fn peer_value<'owner>(
    journal: &mut ProtectedBrokerSessionJournalV1,
    transcript: &VerifiedBrokerSessionTranscriptV1,
    connection_peer: &ConnectionPeerIdentity,
    originals: Option<&'owner mut CurrentPeerOriginalsV1>,
) -> Result<ReplayValue<'owner, ObservedBrokerPeerExecutionV1>, BrokerSessionSecurityError> {
    let Some(originals) = originals else {
        return journal.observe_peer(transcript, connection_peer).map(ReplayValue::Ordinary);
    };
    originals.observe_once(journal, transcript, connection_peer)?;
    originals.value().map(ReplayValue::Retained)
        .ok_or(BrokerSessionSecurityError::Currentness)
}

fn replay_values<'owner>(
    journal: &mut ProtectedBrokerSessionJournalV1,
    transcript: &VerifiedBrokerSessionTranscriptV1,
    context: &ProtectedBrokerSessionVerificationContextV1,
    peer: &ObservedBrokerPeerExecutionV1,
    originals: Option<&'owner mut ReopenCurrentOriginalsV1>,
    receiving: Option<&mut dyn StorageFloorFinancialSourceV2>,
) -> Result<(
    ReplayValue<'owner, BrokerSessionDurableHistoryV1>,
    ReplayValue<'owner, BrokerSessionTrafficStateV1>,
    ReplayValue<'owner, ProtectedBrokerSessionJournalSnapshotV1>,
), BrokerSessionSecurityError> {
    if let Some(source) = receiving {
        return super::super::current_replay::reopen_prepaid_with_storage_receiving_v3(
            journal, transcript, context, peer, source).map(|(history, traffic, current)| (
                ReplayValue::Ordinary(history), ReplayValue::Ordinary(traffic), ReplayValue::Ordinary(current),
            ));
    }
    let Some(originals) = originals else {
        return super::super::current_replay::reopen_ordinary_with_storage_receiving_v3(
            journal, transcript, context, peer, None).map(|(history, traffic, current)| (
            ReplayValue::Ordinary(history),
            ReplayValue::Ordinary(traffic),
            ReplayValue::Ordinary(current),
        ));
    };
    originals.observe_once(journal, transcript, context, peer)?;
    let (history, traffic, current) = originals.values()
        .ok_or(BrokerSessionSecurityError::Currentness)?;
    Ok((ReplayValue::Retained(history), ReplayValue::Retained(traffic), ReplayValue::Retained(current)))
}

fn terminal_value<'owner>(
    history: &BrokerSessionDurableHistoryV1,
    request: &AuthenticatedBrokerMethodRequestV1,
    transcript: &VerifiedBrokerSessionTranscriptV1,
    context: &ProtectedBrokerSessionVerificationContextV1,
    final_traffic: &BrokerSessionTrafficStateV1,
    originals: Option<&'owner mut TerminalSemanticsOriginalsV1>,
) -> Result<ReplayValue<'owner, AuthenticatedBrokerMethodOutcomeV1>, BrokerSessionSecurityError> {
    let Some(originals) = originals else {
        return reconstruct_terminal_semantics(history, request, transcript, context, final_traffic)
            .map(ReplayValue::Ordinary);
    };
    originals.observe_once(history, request, transcript, context, final_traffic)?;
    originals.value().map(ReplayValue::Retained)
        .ok_or(BrokerSessionSecurityError::Currentness)
}

impl ProtectedBrokerSessionJournalV1 {
    pub(super) fn validate_broker_outcome_with_originals(
        &mut self,
        owner: &ProtectedBrokerOutcomeCurrentnessOwnerV1,
        connection_peer: &ConnectionPeerIdentity,
        originals: Option<&mut OutcomeCurrentOriginalsV1>,
    ) -> Result<(), BrokerSessionSecurityError> {
        self.validate_broker_outcome_with_storage_receiving_v3(owner, connection_peer, originals, None)
    }

    pub(super) fn validate_broker_outcome_with_storage_receiving_v3(&mut self,
        owner: &ProtectedBrokerOutcomeCurrentnessOwnerV1,
        connection_peer: &ConnectionPeerIdentity,
        originals: Option<&mut OutcomeCurrentOriginalsV1>,
        mut receiving: Option<&mut dyn StorageFloorFinancialSourceV2>,
    ) -> Result<(), BrokerSessionSecurityError> {
        let ordinary_format = receiving.is_some();
        let retained_post = originals.is_some();
        let OutcomeDestinationsV1 {
            floor_method, context, context_comparison, before_peer, peer_binding,
            replay, head, protected_binding, head_comparison, terminal,
            terminal_comparison, after_peer, after_binding, after_comparison,
        } = OutcomeDestinationsV1::from(originals);
        let mut post = OutcomePeerPostDestinationsV1 {
            peer: after_peer, binding: after_binding, comparison: after_comparison,
        };
        let body = (|| {
            security_value(self.require_floor_method_with_storage_receiving_v2(owner.request.method(),
                receiving.as_mut().map(|source| &mut **source as &mut dyn StorageFloorFinancialSourceV2)), floor_method)?;

            let context = context_value(self, &owner.transcript, context,
                receiving.as_mut().map(|source| &mut **source as &mut dyn StorageFloorFinancialSourceV2))?;
            security_value(if context.protected_context_digest()
                != owner.context.protected_context_digest() {
                    Err(BrokerSessionSecurityError::Currentness)
                } else { Ok(()) }, context_comparison)?;
            let peer = peer_value(self, &owner.transcript, connection_peer, before_peer)?;
            let peer_binding = security_value(
                peer.binding(self.endpoint.role(), &owner.transcript, &owner.context),
                peer_binding,
            )?;
            let (history, traffic, current) = replay_values(
                self, &owner.transcript, &owner.context, &peer, replay,
                receiving.as_mut().map(|source| &mut **source as &mut dyn StorageFloorFinancialSourceV2),
            )?;
            let head = head_value(history.head(), head)?;
            // Preserve the original generation/head short circuit before computing
            // protected bindings; a skipped stage has no invented retained result.
            let head_matches = if current.generation != owner.protected_generation
                || current.current_head != owner.protected_head
            {
                Err(BrokerSessionSecurityError::Currentness)
            } else {
                let protected_binding = security_value(
                    current.protected_bindings(&owner.context), protected_binding,
                )?;
                if *protected_binding != owner.protected_bindings
                    || *peer_binding != owner.peer_binding
                    || head.endpoint() != self.endpoint.role()
                    || head.phase() != BrokerSessionDurablePhaseV1::Terminal
                    || !request_matches_head(
                        &owner.request, head, request_direction_for_endpoint(self.endpoint.role()),
                    )
                    || traffic.has_outstanding_request()
                    || head.outcome_packet() != Some(owner.outcome.canonical_packet())
                {
                    Err(BrokerSessionSecurityError::Currentness)
                } else { Ok(()) }
            };
            security_value(head_matches, head_comparison)?;
            let reconstructed = terminal_value(
                &history, &owner.request, &owner.transcript, &owner.context, &traffic,
                if ordinary_format { None } else { terminal },
            )?;
            security_value(if *reconstructed != owner.outcome
                || reconstructed.filesystem_worker_qualification_commitment()
                    != owner.qualification_record_commitment {
                    Err(BrokerSessionSecurityError::Currentness)
                } else { Ok(()) }, terminal_comparison)?;
            if !retained_post {
                // Keep ordinary replay values alive through their original post.
                self.finish_outcome_peer_post_v1(owner, connection_peer, &mut post)?;
            }
            Ok(())
        })();

        if !retained_post {
            return body;
        }

        // The same retained peer destination was paid before this interval.
        // A failed body cannot suppress its independent native observations.
        let after = self.finish_outcome_peer_post_v1(owner, connection_peer, &mut post);
        body?;
        after
    }

    fn finish_outcome_peer_post_v1(
        &mut self,
        owner: &ProtectedBrokerOutcomeCurrentnessOwnerV1,
        connection_peer: &ConnectionPeerIdentity,
        post: &mut OutcomePeerPostDestinationsV1<'_>,
    ) -> Result<(), BrokerSessionSecurityError> {
        let after_peer = peer_value(self, &owner.transcript, connection_peer, post.peer.as_deref_mut())?;
        let binding = security_value(
            after_peer.binding(self.endpoint.role(), &owner.transcript, &owner.context),
            post.binding.as_deref_mut(),
        )?;
        security_value(if *binding != owner.peer_binding {
            Err(BrokerSessionSecurityError::Currentness)
            } else { Ok(()) }, post.comparison.as_deref_mut())?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use super::super::lifecycle_test_fixture::LifecycleTerminalFixture;

    #[test]
    fn a_later_generation_refusal_retains_both_canonical_readbacks() {
        let mut fixture = LifecycleTerminalFixture::storage_broker();
        let owner = &mut fixture.committed.as_mut().unwrap().currentness_owner;
        // A passive expected-coordinate mutation reaches the real held
        // Journal comparison. It creates no selected J loan or role grant.
        owner.protected_generation = owner.protected_generation.checked_add(1).unwrap();
        let mut originals = OutcomeCurrentOriginalsV1::default();

        let result = fixture.journal.validate_broker_outcome_with_originals(
            owner, fixture.socket.peer(), Some(&mut originals),
        );
        originals.returned = Some(result);

        assert!(originals.require_complete().is_err());
        assert!(originals.context.value().is_some());
        assert!(originals.before_peer.value().is_some());
        let (history, traffic, snapshot) = originals.replay.values().unwrap();
        assert!(!history.records().is_empty());
        assert!(!traffic.has_outstanding_request());
        assert_ne!(snapshot.generation, owner.protected_generation);
        assert!(originals.protected_binding.is_none());
        assert!(matches!(originals.head_comparison, Some(Err(_))));
        assert!(originals.after_peer.value().is_some());
        assert!(matches!(originals.after_comparison, Some(Ok(()))));
        let cause = originals.head_comparison.as_ref().unwrap().as_ref().unwrap_err();
        assert!(std::ptr::eq(originals.failure().unwrap()
            .downcast_ref::<BrokerSessionSecurityError>().unwrap(), cause));
    }

    #[test]
    fn reconstructed_outcome_stays_after_later_qualification_refusal() {
        let mut fixture = LifecycleTerminalFixture::storage_broker();
        let owner = &mut fixture.committed.as_mut().unwrap().currentness_owner;
        owner.qualification_record_commitment = Some([0x59; 32]);
        let mut originals = OutcomeCurrentOriginalsV1::default();

        let result = fixture.journal.validate_broker_outcome_with_originals(
            owner, fixture.socket.peer(), Some(&mut originals),
        );
        originals.returned = Some(result);

        assert!(originals.require_complete().is_err());
        assert!(matches!(originals.head_comparison, Some(Ok(()))));
        assert_eq!(originals.terminal.value().unwrap(), &owner.outcome);
        assert!(matches!(originals.terminal_comparison, Some(Err(_))));
        assert!(originals.after_peer.value().is_some());
        assert!(matches!(originals.after_comparison, Some(Ok(()))));
        let cause = originals.terminal_comparison.as_ref().unwrap().as_ref().unwrap_err();
        assert!(std::ptr::eq(originals.failure().unwrap()
            .downcast_ref::<BrokerSessionSecurityError>().unwrap(), cause));
    }

    #[test]
    fn context_refusal_still_observes_the_real_peer_and_endpoint_post() {
        let mut fixture = LifecycleTerminalFixture::storage_broker();
        let foreign = LifecycleTerminalFixture::new();
        let owner = &mut fixture.committed.as_mut().unwrap().currentness_owner;
        owner.context = foreign.currentness.as_ref().unwrap().context.clone();
        let mut originals = OutcomeCurrentOriginalsV1::default();

        let result = fixture.journal.validate_broker_outcome_with_originals(
            owner, fixture.socket.peer(), Some(&mut originals),
        );
        originals.returned = Some(result);

        assert!(originals.require_complete().is_err());
        assert!(originals.context.value().is_some());
        assert!(matches!(originals.context_comparison, Some(Err(_))));
        assert!(originals.before_peer.value().is_none());
        assert!(originals.after_peer.value().is_some());
        assert!(originals.replay.values().is_none());
        assert!(originals.terminal.value().is_none());
        let cause = originals.context_comparison.as_ref().unwrap().as_ref().unwrap_err();
        assert!(std::ptr::eq(originals.failure().unwrap()
            .downcast_ref::<BrokerSessionSecurityError>().unwrap(), cause));
    }
}
