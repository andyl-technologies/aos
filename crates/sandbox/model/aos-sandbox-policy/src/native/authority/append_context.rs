//! Lends the same Authority writer separately from its genuine final gen1 cut.
//!
//! The private lender first completes the actual current-gen1 observation,
//! then moves its retained floor and fixed Source packet into this scope. The
//! writer remains the original mutable resident field; independent pins,
//! currentness custody, accepted Controller and Origin remain borrowed from
//! their same owners. No supplied DATA can construct this context.

use aos_sandbox_broker::receiving::RootQ04OriginBorrowerV1;
use aos_sandbox_ledger_replay::replay::root_genesis_records::SourceHierarchyFloorRecordV1;
use aos_sandbox_ledger_replay::source_signer_data::SourceTreeGenesisReadbackPacketV2;
use aos_sandbox_ledger_replay::source_signer_data::controller_genesis_readback::ControllerGenesisReadbackDataV1;
use aos_sandbox_protocol::domain_ledger::protected_names::ProtectedJournalNamesV1;

use super::currentness::RootAuthorityCurrentCustodyV1;
use super::error::RootAuthorityErrorV1;
use super::gen1::RootAuthorityGen1OwnerLoanV1;
use super::pins::RootAuthorityPinsOriginalV1;
use super::{RootAuthorityOriginalV1, RootAuthorityQ04FlightOriginalV1};
use crate::native::journal::RootPolicyJournalV1;

pub(super) struct RootAuthorityQ04AppendContextV1<'role, 'origin, 'startup> {
    instance: std::sync::Arc<crate::native::journal::PolicyJournalInstanceV1>,
    next: u64,
    pins: &'role RootAuthorityPinsOriginalV1,
    current: &'role RootAuthorityCurrentCustodyV1,
    names: ProtectedJournalNamesV1,
    origin: RootQ04OriginBorrowerV1<'origin, 'startup>,
    nonce: [u8; 16],
    identities: [u32; 4],
    accepted: &'role ControllerGenesisReadbackDataV1,
    floor: SourceHierarchyFloorRecordV1,
    source: SourceTreeGenesisReadbackPacketV2,
}

// This is the actual scope returned by the private disjoint-field lender.
// It carries existing native ownership; the instance Arc is cloned only as a
// shared allocation reference and never creates another writer or account.
type RootAuthorityQ04AppendScopeV1<'role, 'origin, 'startup> = (
    &'role mut RootPolicyJournalV1,
    RootAuthorityQ04AppendContextV1<'role, 'origin, 'startup>,
    &'role mut super::binding_history::RootAuthorityQ04HistoryV1,
);

pub(super) fn append_entry_receiving_demand_v1(
) -> Result<aos_sandbox_model::ResourceVector, RootAuthorityErrorV1> {
    use super::append_gate::{AuthorityAppendGateV1, RootAuthorityQ04AppendFailureV1};
    use crate::native::append::PolicyMutationGateV1;
    use aos_sandbox_model::{ResourceDimension, ResourceVector};

    // Context literal and destructured local; expression, return and receiving
    // scope Results; actual Authority variant literal; caller/commit-forward/
    // native-callee enum carriers. These precede common native preflight.
    let bytes = std::mem::size_of::<RootAuthorityQ04AppendContextV1<'_, '_, '_>>()
        .checked_mul(2)
        .and_then(|bytes| bytes.checked_add(std::mem::size_of::<
            Result<RootAuthorityQ04AppendScopeV1<'_, '_, '_>, RootAuthorityErrorV1>,
        >().checked_mul(3)?))
        .and_then(|bytes| bytes.checked_add(std::mem::size_of::<
            AuthorityAppendGateV1<'_, '_, '_, '_>,
        >()))
        .and_then(|bytes| bytes.checked_add(std::mem::size_of::<
            PolicyMutationGateV1<'_, '_, '_, '_, '_>,
        >().checked_mul(3)?))
        .and_then(|bytes| bytes.checked_add(std::mem::size_of::<(
            Result<(), RootAuthorityErrorV1>,
            Result<(), RootAuthorityQ04AppendFailureV1>,
            Result<ResourceVector, RootAuthorityErrorV1>,
            ResourceVector,
            // The real financial receiver/result and typed error literal are
            // reached before scope construction, outside common preflight.
            &RootPolicyJournalV1,
            Result<(), crate::native::PolicyNativeJournalErrorV1>,
            crate::native::PolicyNativeJournalErrorV1,
            RootAuthorityErrorV1,
        )>().checked_mul(3)?))
        .and_then(|bytes| u64::try_from(bytes).ok())
        .ok_or_else(crate::native::PolicyNativeJournalErrorV1::geometry)?;
    Ok(ResourceVector::ZERO.with(ResourceDimension::MemoryBytes, bytes))
}

impl<'role, 'origin, 'startup> RootAuthorityQ04AppendContextV1<'role, 'origin, 'startup> {
    pub(super) fn require_current_v1(
        &self,
        journal: &RootPolicyJournalV1,
    ) -> Result<(), RootAuthorityErrorV1> {
        journal.require_native_original()?;
        if !std::sync::Arc::ptr_eq(&self.instance, &journal.instance)
            || self.next != journal.next_sequence()
        {
            return Err(RootAuthorityErrorV1::Stale);
        }
        self.owner_v1(journal)
            .confirm_gen1_ack_v1(self.source.as_ref(), &self.floor)
    }

    pub(super) fn require_stage_cut_v1(
        &self,
        identity: &aos_sandbox_protocol::domain_ledger::create_q04_history::Q04CutIdentityV1,
        stage: &crate::q04_data::Q04RootStageRecipeV1,
    ) -> Result<(), RootAuthorityErrorV1> {
        require_stage_cut_v1(&self.floor, self.nonce, identity, stage)
    }

    pub(super) fn original_transport_v1(&self) -> RootQ04OriginBorrowerV1<'origin, 'startup> {
        self.origin
    }

    fn owner_v1<'check>(
        &'check self,
        journal: &'check RootPolicyJournalV1,
    ) -> RootAuthorityGen1OwnerLoanV1<'check, 'origin, 'startup> {
        RootAuthorityGen1OwnerLoanV1 {
            journal,
            pins: self.pins,
            current: self.current,
            names: self.names,
            origin: self.origin,
            nonce: self.nonce,
            identities: self.identities,
            accepted: self.accepted,
        }
    }
}

impl<'authority, 'origin, 'startup>
    RootAuthorityQ04FlightOriginalV1<'authority, 'origin, 'startup>
{
    pub(super) fn q04_append_scope_v1(
        &mut self,
        source_packet: &[u8],
    ) -> Result<
        (
            &mut RootPolicyJournalV1,
            RootAuthorityQ04AppendContextV1<'_, 'origin, 'startup>,
            &mut super::binding_history::RootAuthorityQ04HistoryV1,
        ),
        RootAuthorityErrorV1,
    > {
        self.recheck()?;
        // Move the real checked observation out before taking the disjoint
        // mutable journal loan. Its owner references end here; no floor or
        // packet allocation is cloned to manufacture another observation.
        let (floor, source) = {
            let current = self.current_anchored_floor_v1(source_packet)?;
            current.recheck()?;
            current.into_append_observation_v1()
        };
        let nonce = self.nonce_data_v1()?;
        let instance = std::sync::Arc::clone(&self.authority.journal.instance);
        let next = self.authority.journal.next_sequence();
        let identities = self.identities.ok_or(RootAuthorityErrorV1::Stale)?;
        let accepted = self.accepted.as_ref().ok_or(RootAuthorityErrorV1::Stale)?;
        let RootAuthorityOriginalV1 {
            journal,
            pins,
            current,
            names,
        } = &mut *self.authority;
        let history = self.history.as_mut().ok_or(RootAuthorityErrorV1::Stale)?;
        Ok((
            journal,
            RootAuthorityQ04AppendContextV1 {
                instance,
                next,
                pins,
                current,
                names: *names,
                origin: self.origin,
                nonce,
                identities,
                accepted,
                floor,
                source,
            },
            history,
        ))
    }
}

pub(super) fn require_stage_cut_v1(
    floor: &SourceHierarchyFloorRecordV1,
    nonce: [u8; 16],
    identity: &aos_sandbox_protocol::domain_ledger::create_q04_history::Q04CutIdentityV1,
    stage: &crate::q04_data::Q04RootStageRecipeV1,
) -> Result<(), RootAuthorityErrorV1> {
    if floor.digest() != identity.gen1_floor()
        || floor.project() != stage.project()
        || stage.staged().challenge() != nonce
        || stage.staged().base().next_generation() != identity.epoch()
    {
        return Err(crate::q04_data::PolicyQ04DataErrorV1::ChangedCut.into());
    }
    Ok(())
}
