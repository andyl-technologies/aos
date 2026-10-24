//! Checks actual terminal pair and lower-clearance context on the same loan.
//!
//! Canonical Controller/Source recipes and all row/hold codecs remain in their
//! sole lower DATA owners. These checks use real native History/gen1/Cache
//! originals; no supplied phase recipe or readback DATA creates this role.

use aos_sandbox_ledger_replay::controller_policy_hold::ControllerPolicyHoldCodecV1;

use super::terminal_cut::RootAuthorityQ04TerminalLoanV1;
use super::{RootAuthorityCacheTerminalOutcomeV1, RootAuthorityGen1LoanV1};
use crate::controller_project_readback::VerifiedControllerProjectAdmissionV1;
use crate::controller_readback::VerifiedControllerHoldReadbackV1;
use crate::native::target::RootPolicyPublicationErrorV1 as WorkError;
use aos_sandbox_model::ObjectDigest;
use aos_sandbox_ledger_replay::replay::root_genesis_records::SourceHierarchyFloorRecordV1;
use aos_sandbox_protocol::domain_ledger::create_q04_history::Q04CutIdentityV1;

#[allow(clippy::too_many_arguments)]
fn require_terminal_pairs(
    identity: &Q04CutIdentityV1,
    acknowledgement: &crate::q04_data::Q04AcknowledgementV1<'_>,
    controller: VerifiedControllerProjectAdmissionV1,
    original_held: VerifiedControllerHoldReadbackV1,
    floor: &SourceHierarchyFloorRecordV1,
    original_cache: aos_sandbox_protocol::cache_owner_readback::VerifiedClosedCacheOwnerReadbackV2,
    observed_cache: &aos_sandbox_cache::CacheResidencyRootReadOnlyPolicyHoldV1,
    release: &aos_sandbox_protocol::domain_ledger::create_q04_history::Q04PhaseRecordV1,
    settlement: Option<&aos_sandbox_protocol::domain_ledger::create_q04_history::Q04PhaseRecordV1>,
) -> Result<(), WorkError> {
    let (_, _, _, expected) =
        terminal_hold_pair_recipes(identity, controller, original_held, floor, original_cache)?;
    let packet = acknowledgement.bytes();
    for (index, digest) in expected.iter().enumerate() {
        if packet[344 + index * 32..376 + index * 32] != *digest.as_bytes() {
            return Err(WorkError::ChangedCut);
        }
    }
    if observed_cache.hold.is_held()
        || observed_cache.hold.record_digest()? != expected[5]
        || observed_cache.replay.quota_digest != identity.cache_quota()
        || release.phase() != 5
    {
        return Err(WorkError::ChangedCut);
    }
    if acknowledgement.kind() == crate::q04_data::Q04AcknowledgementKindV1::Clearance {
        let settlement = settlement.ok_or(WorkError::ChangedCut)?;
        if settlement.phase() != 6
            || settlement.bytes()[160..192] != *release.digest().as_bytes()
            || packet[536..568] != *settlement.digest().as_bytes()
        {
            return Err(WorkError::ChangedCut);
        }
    }
    Ok(())
}

fn terminal_hold_pair_recipes(
    identity: &Q04CutIdentityV1,
    controller: VerifiedControllerProjectAdmissionV1,
    original_held: VerifiedControllerHoldReadbackV1,
    floor: &SourceHierarchyFloorRecordV1,
    original_cache: aos_sandbox_protocol::cache_owner_readback::VerifiedClosedCacheOwnerReadbackV2,
) -> Result<
    (
        aos_sandbox_ledger_replay::controller_policy_hold::ControllerPolicyHoldV1,
        aos_sandbox_protocol::domain_ledger::source_policy_hold::SourceDomainPolicyHoldV1,
        aos_sandbox_protocol::domain_ledger::cache_policy_hold::CachePolicyHoldV1,
        [ObjectDigest; 6],
    ),
    WorkError,
> {
    let controller_hold =
        aos_sandbox_ledger_replay::controller_policy_hold::ControllerPolicyHoldV1::new(
            original_held.operation(),
            original_held.sandbox(),
            original_held.source(),
            original_held.binding(),
            original_held.epoch(),
        )?;
    let source_hold =
        aos_sandbox_protocol::domain_ledger::source_policy_hold::SourceDomainPolicyHoldV1::new(
            controller.operation(),
            controller.sandbox(),
            controller.source_commitment(),
            floor.tree_head(),
            identity.binding(),
            identity.epoch(),
        )?;
    let cache_hold = original_cache.hold();
    let expected = [
        controller_hold.record_digest()?,
        controller_hold.q04_released_record_digest()?,
        source_hold.record_digest()?,
        source_hold.q04_released_record_digest()?,
        cache_hold.record_digest()?,
        cache_hold.q04_released_record_digest()?,
    ];
    Ok((controller_hold, source_hold, cache_hold, expected))
}

#[allow(clippy::too_many_arguments)]
fn require_original_lower_clearance_recipe(
    gen1: &RootAuthorityGen1LoanV1<'_, '_, '_>,
    history: &super::binding_history::RootAuthorityQ04HistoryV1,
    prehold_metadata: &[u8],
    claim_fields: &[&[u8]; 14],
    acknowledgement: &crate::q04_data::Q04AcknowledgementV1<'_>,
    controller: VerifiedControllerProjectAdmissionV1,
    original_held: VerifiedControllerHoldReadbackV1,
    original_cache: aos_sandbox_protocol::cache_owner_readback::VerifiedClosedCacheOwnerReadbackV2,
) -> Result<(), WorkError> {
    if acknowledgement.kind() != crate::q04_data::Q04AcknowledgementKindV1::Clearance
        || history.committed()
            != history
                .binding_prefix_end()?
                .checked_add(4)
                .ok_or(WorkError::Bounds)?
    {
        return Err(WorkError::ChangedCut);
    }
    gen1.recheck()?;
    let identity = history.identity();
    let root_five = history.phase_record_v1(5).ok_or(WorkError::ChangedCut)?;
    let root_six = history.phase_record_v1(6).ok_or(WorkError::ChangedCut)?;
    if root_five.phase() != 5
        || root_six.phase() != 6
        || root_six.bytes()[160..192] != *root_five.digest().as_bytes()
    {
        return Err(WorkError::ChangedCut);
    }
    let (_, source_hold, cache_hold, pairs) = terminal_hold_pair_recipes(
        identity,
        controller,
        original_held,
        gen1.floor(),
        original_cache,
    )?;
    let source_names =
        aos_sandbox_protocol::domain_ledger::protected_names::ProtectedJournalNamesV1::from_bytes(
            &prehold_metadata[224..272],
        )
        .map_err(aos_sandbox_broker::canonical_journal::CanonicalJournalMechanicalErrorV1::from)
        .map_err(crate::native::PolicyNativeJournalErrorV1::from)?;
    let source_next = u64::from_be_bytes(crate::q04_data::fixed(prehold_metadata, 472));
    let cache_names =
        aos_sandbox_protocol::domain_ledger::protected_names::ProtectedJournalNamesV1::from_bytes(
            &prehold_metadata[272..320],
        )
        .map_err(aos_sandbox_broker::canonical_journal::CanonicalJournalMechanicalErrorV1::from)
        .map_err(crate::native::PolicyNativeJournalErrorV1::from)?;
    let cache_next = u64::from_be_bytes(crate::q04_data::fixed(prehold_metadata, 480));
    let observed_source = gen1.source_coordinates()?;
    if observed_source
        != (
            source_names,
            source_next.checked_add(11).ok_or(WorkError::Bounds)?,
        )
    {
        return Err(WorkError::ChangedCut);
    }
    // Cache's actual clear membership was independently replayed through the
    // same fixed read-only engine. These hashes use its exact native recipe,
    // not a new serializer or a checksum promoted to authority.
    let cache_clear =
        aos_sandbox_protocol::cache_state::hold_state::q04_recipes::clear_recipe_digest_data_v1(
            identity,
            cache_names,
            cache_next,
            cache_hold,
            root_five.digest(),
        ).map_err(project_lower_recipe_error_v1)?;
    let source_clear = aos_sandbox_protocol::domain_ledger::create_q04_history::recipes::source::q04_clear_recipe_digest_data(
        identity, source_names, source_next, source_hold, root_five.digest(),
    ).map_err(project_lower_recipe_error_v1)?;
    let decision =
        aos_sandbox_protocol::domain_ledger::create_q04_history::Q04RootDecisionV1::decode(
            history.transactions()[history.binding_prefix_end()?].records()[0]
                .value()
                .ok_or(WorkError::ChangedCut)?,
            identity,
        )
        .map_err(|error| WorkError::Data(error.into()))?;
    let consumed =
        aos_sandbox_protocol::domain_ledger::create_q04_history::root_consumed_gate_record_v1(
            identity, &decision,
        )?;
    let events = aos_sandbox_protocol::domain_ledger::create_q04_history::recipes::Q04ControllerPhaseEventsV1 {
        decision: decision.digest(), consumed_gate: consumed.digest(),
        release: root_five.digest(), settlement: root_six.digest(),
        clearance: ObjectDigest::from_bytes([0; 32]), final_root: ObjectDigest::from_bytes([0; 32]),
        pairs,
        policy_ack: history.phase_record_v1(4).ok_or(WorkError::ChangedCut)?.acknowledgement(),
        release_ack: root_five.acknowledgement(),
        settlement_ack: root_six.acknowledgement(),
        clearance_ack: ObjectDigest::from_bytes([0; 32]),
    };
    let mut prior = None;
    for phase in 1..=6 {
        prior = Some(aos_sandbox_protocol::domain_ledger::create_q04_history::recipes::controller_phase_recipe_v1(identity, phase, prior.as_ref(), &events).map_err(|error| WorkError::Data(error.into()))?);
    }
    let prior_c_six = prior.ok_or(WorkError::ChangedCut)?;
    let status_three = consumed
        .next_status_recipe(events.release_ack)?
        .next_status_recipe(events.settlement_ack)?;
    let rows = aos_sandbox_protocol::domain_ledger::create_q04_history::original_rows::read_original_q04_rows_v1(
        claim_fields[0], claim_fields[1], claim_fields[2], aos_sandbox_protocol::domain_ledger::create_q04_history::original_rows::Q04OriginalRowBindingV1 {
            operation: identity.operation(), sandbox: identity.sandbox(), project: identity.project(),
            accepted_generation: identity.accepted_generation(), desired_precondition: identity.desired_precondition(),
        },
    )?;
    let effect = rows.applying_effect_with_gate(&status_three)?;
    let clearance = aos_sandbox_protocol::domain_ledger::create_q04_history::recipes::lower_clearance_recipe_digest_v1(
        identity, root_six, cache_clear, source_clear, &prior_c_six, &effect,
    ).map_err(|error| WorkError::Data(error.into()))?;
    let packet = acknowledgement.bytes();
    if packet[568..600] != *cache_clear.as_bytes()
        || packet[600..632] != *source_clear.as_bytes()
        || packet[632..664] != *clearance.as_bytes()
    {
        return Err(WorkError::ChangedCut);
    }
    gen1.recheck()?;
    Ok(())
}

fn project_lower_recipe_error_v1(
    error: aos_sandbox_protocol::domain_ledger::create_q04_history::recipes::Q04RecipeDataErrorV1,
) -> WorkError {
    use aos_sandbox_protocol::domain_ledger::create_q04_history::recipes::Q04RecipeDataErrorV1 as Data;
    match error {
        Data::ChangedCut => WorkError::ChangedCut,
        Data::Bounds => WorkError::Bounds,
        Data::SequenceExhausted => WorkError::Journal(crate::native::PolicyNativeJournalErrorV1::Mechanical(
            aos_sandbox_broker::canonical_journal::CanonicalJournalMechanicalErrorV1::SequenceExhausted,
        )),
        Data::History(error) => WorkError::from(error),
        Data::Transaction(error) => WorkError::from(error),
    }
}

impl RootAuthorityQ04TerminalLoanV1<'_, '_, '_, '_> {
    #[allow(clippy::too_many_arguments)]
    pub(in crate::native) fn require_original_lower_recipe_v1(
        &self,
        prehold_metadata: &[u8],
        claim_fields: &[&[u8]; 14],
        acknowledgement: &crate::q04_data::Q04AcknowledgementV1<'_>,
        controller: VerifiedControllerProjectAdmissionV1,
        held: VerifiedControllerHoldReadbackV1,
        cache: aos_sandbox_protocol::cache_owner_readback::VerifiedClosedCacheOwnerReadbackV2,
        observation: Option<&RootAuthorityCacheTerminalOutcomeV1>,
    ) -> Result<(), WorkError> {
        // Authentication already occurred at the explicit old ACK frontier.
        // Compare that same body here without another signature/clock sample.
        if acknowledgement.kind() != self.kind_v1()
            || self.frame_data_v1().get(
                aos_sandbox_protocol::source_genesis_wire::ROOT_SOURCE_GENESIS_FRAME_HEADER_BYTES_V1..
            ) != Some(acknowledgement.bytes())
        { return Err(WorkError::ChangedCut); }
        let Some(observation) = observation else {
            return if matches!(
                self.kind_v1(),
                crate::q04_data::Q04AcknowledgementKindV1::Policy
                    | crate::q04_data::Q04AcknowledgementKindV1::Release
            ) {
                Ok(())
            } else {
                Err(WorkError::ChangedCut)
            };
        };
        let gen1 = self.gen1_v1();
        let history = self.history_v1();
        let observed = observation.require_same_terminal_original_v1(
            gen1,
            history.identity(),
            self.kind_v1(),
        )?;
        require_terminal_pairs(
            history.identity(),
            acknowledgement,
            controller,
            held,
            gen1.floor(),
            cache,
            observed,
            history.phase_record_v1(5).ok_or(WorkError::ChangedCut)?,
            history.phase_record_v1(6),
        )?;
        if self.kind_v1() == crate::q04_data::Q04AcknowledgementKindV1::Clearance {
            require_original_lower_clearance_recipe(
                gen1,
                history,
                prehold_metadata,
                claim_fields,
                acknowledgement,
                controller,
                held,
                cache,
            )?;
        }
        Ok(())
    }
}
