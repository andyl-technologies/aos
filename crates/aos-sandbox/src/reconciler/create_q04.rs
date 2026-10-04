//! Method-specific readback of a pending Create policy-admission subgate.
//!
//! Historical rows remain fenced and cannot dispatch, finish Create or start
//! another Stage. Live transitions separately require the original owners,
//! authenticated packets and validated native transaction membership.

use aos_sandbox_core::{ObjectDigest, OperationId, ProjectId, SandboxId};
use sha2::{Digest as _, Sha256};

use crate::controller_service::public_projection::{
    PublicProjectionKindV1, PublicProjectionRecordV1, PublicProjectionResourceV1,
    PublicProjectionStoreV1,
};
use crate::journal::{Journal, JournalRecord, RecordNamespace};
use crate::policy_compiler::create_q04::{
    CONTROLLER_IDENTITY_KEY, CONTROLLER_PHASE_PREFIX, CreateQ04ErrorV1, Q04CutIdentityV1,
    Q04EffectSubgateV1,
};

use super::effect::{
    EffectLedgerRecord, EffectState, decode_effect_with_q04, encode_effect, encode_q04_effect,
};
use super::{
    OperationState, ReconcilerError, decode_operation, effect_key, encode_operation_record,
    live_create_sandbox_admission_revision_v1,
};

use crate::policy_compiler::create_q04::{
    OriginalCreateQ04InvocationV1, Q04AcknowledgementKindV1, Q04ControllerPhaseEventsV1,
    Q04ControllerPreparationV1, Q04PhaseRecordV1, Q04RootDecisionV1,
    controller_phase_recipe_v1, encode_q04_acknowledgement_data_v1,
    lower_clearance_recipe_digest_v1, q04_controller_capacity_events_v1,
    sign_original_q04_acknowledgement_v1,
};

// The same installed invocation owns every returned compiler/native/signing
// result. Its destructor runs before any original credential or Root field is
// dropped. Source and Cache are separate short loans from their actual parent,
// with their own negative guard inside this same call, not a second owner graph.
struct InstalledOriginalCreateQ04V1<'profile> {
    root: OriginalCreateQ04InvocationV1<'profile>,
    credentials: crate::public_api_session::ControllerQ04CredentialCustodyV1,
    ledger: Option<Result<OriginalQ04ControllerLedgerV1, CreateQ04ErrorV1>>,
    preparation: Option<Result<Q04ControllerPreparationV1, CreateQ04ErrorV1>>,
    identity: Option<Result<Q04CutIdentityV1, CreateQ04ErrorV1>>,
    commits: [Option<Result<crate::journal::CommitResult, CreateQ04ErrorV1>>; 8],
    acknowledgements: [Vec<u8>; 4],
    signatures: [Option<Result<(), CreateQ04ErrorV1>>; 4],
    first: Option<CreateQ04ErrorV1>,
    postcheck: Option<CreateQ04ErrorV1>,
    complete: bool,
}

impl<'profile> InstalledOriginalCreateQ04V1<'profile> {
    fn park(profile: &'profile crate::normal_root::ProductionControllerNormalRootProfileV1) -> Self {
        Self {
            root: OriginalCreateQ04InvocationV1::park(profile),
            credentials: crate::public_api_session::ControllerQ04CredentialCustodyV1::new(),
            ledger: None,
            preparation: None,
            identity: None,
            commits: std::array::from_fn(|_| None),
            acknowledgements: std::array::from_fn(|_| Vec::new()),
            signatures: std::array::from_fn(|_| None),
            first: None,
            postcheck: None,
            complete: false,
        }
    }
}

impl Drop for InstalledOriginalCreateQ04V1<'_> {
    fn drop(&mut self) {
        if !self.complete {
            self.first.get_or_insert(CreateQ04ErrorV1::Unwind);
            std::process::exit(1);
        }
    }
}

// All eight canonical phases are owned DATA, with no self-borrowing Journal or
// Root loan. Rebuilding only future members uses the same phase/Effect/native
// encoders; the already committed prefix must remain byte-for-byte identical.
struct ControllerQ04RecipesV1 {
    phases: Vec<Q04PhaseRecordV1>,
    gates: [Q04EffectSubgateV1; 4],
}

impl ControllerQ04RecipesV1 {
    fn encode(
        identity: &Q04CutIdentityV1,
        decision: &Q04RootDecisionV1,
        events: &Q04ControllerPhaseEventsV1,
    ) -> Result<Self, CreateQ04ErrorV1> {
        let consumed = crate::policy_compiler::create_q04::root_consumed_gate_v1(identity, decision)?;
        let released = consumed.next_status_recipe(events.release_ack)?;
        let settled = released.next_status_recipe(events.settlement_ack)?;
        let cleared = settled.next_status_recipe(events.clearance_ack)?;
        let mut phases = Vec::new();
        phases.try_reserve_exact(8)?;
        for number in 1..=8 {
            let phase = controller_phase_recipe_v1(identity, number, phases.last(), events)?;
            phases.push(phase);
        }
        Ok(Self { phases, gates: [consumed, released, settled, cleared] })
    }

    fn transitions<'recipe>(
        &'recipe self,
        ledger: &'recipe OriginalQ04ControllerLedgerV1,
        identity: &'recipe Q04CutIdentityV1,
        decision: &'recipe Q04RootDecisionV1,
    ) -> Result<Vec<crate::journal::ControllerQ04TransitionV1<'recipe>>, CreateQ04ErrorV1> {
        let mut transitions = Vec::new();
        transitions.try_reserve_exact(8)?;
        for phase in &self.phases {
            let gate = match phase.phase() {
                2 => Some(&self.gates[0]),
                5 => Some(&self.gates[1]),
                7 => Some(&self.gates[2]),
                8 => Some(&self.gates[3]),
                _ => None,
            };
            transitions.push(crate::journal::ControllerQ04TransitionV1::recipe(
                ledger, identity, phase, (phase.phase() >= 2).then_some(decision), gate,
            )?);
        }
        Ok(transitions)
    }

    fn require_committed_prefix(
        &self,
        previous: &Self,
        ledger: &OriginalQ04ControllerLedgerV1,
        identity: &Q04CutIdentityV1,
        decision: &Q04RootDecisionV1,
        previous_decision: &Q04RootDecisionV1,
        committed: usize,
    ) -> Result<(), CreateQ04ErrorV1> {
        let current = self.transitions(ledger, identity, decision)?;
        let previous = previous.transitions(ledger, identity, previous_decision)?;
        if committed > 8 || current[..committed].iter().zip(&previous[..committed])
            .any(|(current, previous)| current.transaction() != previous.transaction())
        {
            return Err(CreateQ04ErrorV1::ChangedCut);
        }
        Ok(())
    }
}

fn retain_q04_data<T>(
    first: &mut Option<CreateQ04ErrorV1>,
    returned: Result<T, CreateQ04ErrorV1>,
) -> Result<T, ()> {
    match returned {
        Ok(value) if first.is_none() => Ok(value),
        Ok(_) => Err(()),
        Err(cause) => {
            first.get_or_insert(cause);
            Err(())
        }
    }
}

fn capture_controller_q04_commit(
    journal: &mut Journal,
    transitions: &[crate::journal::ControllerQ04TransitionV1<'_>],
    index: usize,
    root: &OriginalCreateQ04InvocationV1<'_>,
    destination: &mut Option<Result<crate::journal::CommitResult, CreateQ04ErrorV1>>,
    first: &mut Option<CreateQ04ErrorV1>,
    postcheck: &mut Option<CreateQ04ErrorV1>,
) -> Result<(), ()> {
    let prepared = (|| {
        if destination.is_some() || first.is_some() || postcheck.is_some() {
            return Err(CreateQ04ErrorV1::ChangedCut);
        }
        let transition = transitions.get(index).ok_or(CreateQ04ErrorV1::ChangedCut)?;
        root.cache_terminal_loan(transition.identity())
    })();
    let original = retain_q04_data(first, prepared)?;
    *destination = Some(journal.commit_controller_q04_phase_v1(transitions, index, &original));

    // Even an error result stays in its original slot. Readback/name/clock debt
    // is separate; none may replace a completed append with an ordinary error.
    let checked = (|| {
        let result = destination.as_ref().and_then(|returned| returned.as_ref().ok())
            .ok_or(CreateQ04ErrorV1::ChangedCut)?;
        journal.readback_controller_q04_phase_v1(transitions, index)?;
        journal.require_q04_returned_commit_v1(result)?;
        original.require_controller_transition(&transitions[index])
    })();
    if let Err(cause) = checked {
        postcheck.get_or_insert(cause);
    }
    if !matches!(destination, Some(Ok(_))) || postcheck.is_some() {
        return Err(());
    }
    Ok(())
}

fn replace_controller_q04_suffix(
    recipes: &mut ControllerQ04RecipesV1,
    ledger: &OriginalQ04ControllerLedgerV1,
    identity: &Q04CutIdentityV1,
    decision: &Q04RootDecisionV1,
    previous_decision: &Q04RootDecisionV1,
    events: &Q04ControllerPhaseEventsV1,
    committed: usize,
    first: &mut Option<CreateQ04ErrorV1>,
) -> Result<(), ()> {
    let next = retain_q04_data(first, ControllerQ04RecipesV1::encode(identity, decision, events))?;
    retain_q04_data(first, next.require_committed_prefix(
        recipes, ledger, identity, decision, previous_decision, committed,
    ))?;
    *recipes = next;
    Ok(())
}

fn capture_controller_q04_acknowledgement(
    journal: &mut Journal,
    transitions: &[crate::journal::ControllerQ04TransitionV1<'_>],
    committed: usize,
    root: &OriginalCreateQ04InvocationV1<'_>,
    credentials: &mut crate::public_api_session::ControllerQ04CredentialCustodyV1,
    kind: Q04AcknowledgementKindV1,
    events: &Q04ControllerPhaseEventsV1,
    clear_fields: Option<[ObjectDigest; 4]>,
    packet: &mut Vec<u8>,
    signature: &mut Option<Result<(), CreateQ04ErrorV1>>,
    first: &mut Option<CreateQ04ErrorV1>,
    postcheck: &mut Option<CreateQ04ErrorV1>,
) -> Result<ObjectDigest, ()> {
    let identity = retain_q04_data(first, transitions.first()
        .map(|transition| transition.identity()).ok_or(CreateQ04ErrorV1::ChangedCut))?;
    let current = retain_q04_data(first, committed.checked_sub(1)
        .filter(|index| *index < transitions.len()).ok_or(CreateQ04ErrorV1::ChangedCut))?;
    let original = retain_q04_data(first, root.cache_terminal_loan(identity))?;
    if credentials.recheck().is_err() {
        // The full typed first credential error is already resident there.
        return Err(());
    }
    retain_q04_data(first, journal.readback_controller_q04_phase_v1(transitions, current))?;
    retain_q04_data(first, original.recheck())?;
    if signature.is_some() || !packet.is_empty() {
        return retain_q04_data(first, Err(CreateQ04ErrorV1::ChangedCut));
    }
    retain_q04_data(first, encode_q04_acknowledgement_data_v1(
        packet, kind, identity, journal.snapshot_sequence(), events.consumed_gate,
        events.pairs, clear_fields,
    ))?;
    *signature = Some(match credentials.signer() {
        Some((_, signer)) => sign_original_q04_acknowledgement_v1(kind, packet, signer, identity, &original),
        None => Err(CreateQ04ErrorV1::ChangedCut),
    });

    let checked = (|| {
        journal.readback_controller_q04_phase_v1(transitions, current)?;
        original.recheck()
    })();
    if let Err(cause) = checked {
        postcheck.get_or_insert(cause);
    }
    // No named readback may replace or consume the already completed signing
    // Result or signed packet, including when this last refresh itself fails.
    if credentials.recheck().is_err() || !matches!(signature, Some(Ok(())))
        || postcheck.is_some()
    {
        return Err(());
    }
    retain_q04_data(first, original.recheck())?;
    Ok(ObjectDigest::from_bytes(Sha256::digest(packet.as_slice()).into()))
}

/// Continues only the original generation-one Create policy-admission subgate.
///
/// The installed selected executor supplies its actual Source, Cache and
/// Controller owners plus the genuinely admitted normal-Root profile. The
/// original stream and writers remain held through exact policy, release,
/// settlement, clearance and observed Root shutdown. Success leaves the
/// Operation and Effect Applying; it is not public Create completion.
/// # Errors
///
/// A selected failure or unwind retains the first typed result and separate
/// postcheck debt, then terminates before any original owner is destroyed.
/// There is no retry, alternate Root socket or ordinary dropped-error fallback.
#[allow(clippy::too_many_arguments)]
pub fn continue_original_create_q04_policy_subgate_v1(
    journal: &mut Journal,
    source: &mut crate::lifecycle::protected_journal_join::ProtectedSourceDomainJournalOwnerV1,
    initialization: &mut crate::cache_residency::CacheResidentInitializationV1,
    cache_owner: &mut crate::cache_residency::CacheResidencyProtectedOwnerV1,
    physical: &crate::cache_residency::DormantCacheOwnerV1,
    profile: &crate::normal_root::ProductionControllerNormalRootProfileV1,
    operation: OperationId,
    scope: crate::controller::ControllerRequestScopeV1,
    plan: &super::EffectPlan,
) -> Result<(), super::EffectFailure> {
    let mut resident = InstalledOriginalCreateQ04V1::park(profile);
    let mut source = crate::lifecycle::protected_journal_join::OriginalQ04SourceOwnerCutV1::park(source);
    let mut cache = match initialization.begin_original_q04(cache_owner, physical) {
        Ok(cache) => cache,
        // The actual initializer, including its original result, is still
        // borrowed from the parent. The prearmed negative owner exits before
        // that borrow or any initialized original can be dropped.
        Err(_) => std::process::exit(1),
    };
    let InstalledOriginalCreateQ04V1 {
        root, credentials, ledger, preparation, identity, commits, acknowledgements,
        signatures, first, postcheck, complete,
    } = &mut resident;

    let continued = (|| -> Result<(), ()> {
        retain_q04_data(first, profile.recheck().map_err(Into::into))?;
        if credentials.capture().is_err() { return Err(()); }
        *ledger = Some(OriginalQ04ControllerLedgerV1::capture(journal, operation, scope, plan));
        let ledger = match ledger.as_ref() { Some(Ok(ledger)) => ledger, _ => return Err(()) };
        cache.capture_prepare_readback(ledger.project)?;
        let (generation, signer) = retain_q04_data(first,
            credentials.signer().ok_or(CreateQ04ErrorV1::ChangedCut))?;
        source.connect_original_root(root, journal, ledger.project, generation, signer)?;
        root.receive_preview()?;
        if credentials.recheck().is_err() { return Err(()); }
        source.capture_controller_preparation(root, journal, ledger, &mut cache, credentials, preparation)?;
        let prepared = match preparation.as_ref() { Some(Ok(prepared)) => prepared, _ => return Err(()) };
        let (generation, signer) = retain_q04_data(first,
            credentials.signer().ok_or(CreateQ04ErrorV1::ChangedCut))?;
        root.sign_prehold_current(journal, ledger, prepared.staged(), prepared.proposed(), generation, signer)?;
        root.sign_prehold_data(journal, ledger, prepared.metadata(), prepared.proposed(), generation, signer)?;
        root.exchange_prehold_data()?;
        if credentials.recheck().is_err() { return Err(()); }
        // End the actual compiler/owner loans before independent comparisons.
        // The complete owned Result was parked before these postchecks.
        source.recheck_controller_preparation(root, journal, ledger, &mut cache, prepared)?;
        *identity = Some(root.form_finalized_identity(ledger, prepared));
        let identity = match identity.as_ref() { Some(Ok(identity)) => identity, _ => return Err(()) };
        let mut source_recipes = source.capture_recipes(ledger, identity)?;
        source.preflight_original_suffix(&source_recipes)?;
        let mut cache_recipes = cache.capture_transaction_recipes(ledger, identity)?;

        let controller_hold = retain_q04_data(first, crate::journal::ControllerPolicyHoldV1::new(
            identity.operation(), identity.sandbox(), ledger.source_commitment(), identity.binding(), identity.epoch(),
        ).map_err(Into::into))?;
        let source_pairs = retain_q04_data(first, source_recipes.terminal_pair_data())?;
        let cache_hold = cache_recipes.terminal_hold(crate::journal::Q04CacheTerminalPhaseV1::Held);
        let pairs = [
            retain_q04_data(first, controller_hold.record_digest().map_err(Into::into))?,
            retain_q04_data(first, controller_hold.q04_released_record_digest().map_err(Into::into))?,
            source_pairs[0], source_pairs[1],
            retain_q04_data(first, cache_hold.record_digest().map_err(Into::into))?,
            retain_q04_data(first, cache_hold.q04_released_record_digest().map_err(Into::into))?,
        ];
        let response = retain_q04_data(first, root.prehold_data())?;
        let state_next = u64::from_be_bytes(response.bytes()[392..400].try_into()
            .map_err(|_| ())?);
        let authority_next = u64::from_be_bytes(response.bytes()[384..392].try_into()
            .map_err(|_| ())?);
        let (capacity_decision, mut events) = retain_q04_data(first,
            q04_controller_capacity_events_v1(identity, pairs, state_next, authority_next))?;
        let mut recipes = retain_q04_data(first,
            ControllerQ04RecipesV1::encode(identity, &capacity_decision, &events))?;
        let transitions = retain_q04_data(first, recipes.transitions(ledger, identity, &capacity_decision))?;
        retain_q04_data(first, journal.preflight_controller_q04_suffix_v1(&transitions))?;
        // Complete Controller/Source/Cache native suffixes and Root's own DATA
        // preflight have all passed before the first logical hold or Stage.
        capture_controller_q04_commit(journal, &transitions, 0, root, &mut commits[0], first, postcheck)?;
        let (generation, signer) = retain_q04_data(first,
            credentials.signer().ok_or(CreateQ04ErrorV1::ChangedCut))?;
        source.refresh_original_root(root, journal, ledger, &transitions, ledger.project, generation, signer)?;
        {
            let original = retain_q04_data(first, root.cache_terminal_loan(identity))?;
            source.append_original_phase(&source_recipes, 0, &original)?;
        }
        source.refresh_original_root(root, journal, ledger, &transitions, ledger.project, generation, signer)?;
        {
            let original = retain_q04_data(first, root.cache_terminal_loan(identity))?;
            cache.append_original_phase(&original, &cache_recipes, 0)?;
            cache.capture_terminal_readback(&original, &cache_recipes, crate::journal::Q04CacheTerminalPhaseV1::Held)?;
            cache.capture_signed_held_readback(&original, &cache_recipes,
                prepared.staged(), prepared.proposed(), credentials)?;
        }
        let (generation, signer) = retain_q04_data(first,
            credentials.signer().ok_or(CreateQ04ErrorV1::ChangedCut))?;
        root.sign_actual_held_controller(journal, &transitions, prepared.staged(), prepared.proposed(), generation, signer)?;
        root.send_held_claim(ledger, identity, prepared.proposed(),
            retain_q04_data(first, cache.signed_held_readback())?, signer)?;
        root.receive_decision(identity)?;
        let decision = retain_q04_data(first, root.decision(identity))?;
        let consumed_gate = retain_q04_data(first, root.consumed_gate(identity))?;
        drop(transitions);
        events.decision = decision.digest();
        events.consumed_gate = consumed_gate.digest();
        replace_controller_q04_suffix(&mut recipes, ledger, identity, &decision, &capacity_decision, &events, 1, first)?;
        let transitions = retain_q04_data(first, recipes.transitions(ledger, identity, &decision))?;
        capture_controller_q04_commit(journal, &transitions, 1, root, &mut commits[1], first, postcheck)?;
        source.refresh_original_root(root, journal, ledger, &transitions, ledger.project, generation, signer)?;

        events.policy_ack = capture_controller_q04_acknowledgement(
            journal, &transitions, 2, root, credentials, Q04AcknowledgementKindV1::Policy,
            &events, None, &mut acknowledgements[0], &mut signatures[0], first, postcheck,
        )?;
        root.exchange_acknowledgement(identity, Q04AcknowledgementKindV1::Policy, &acknowledgements[0])?;
        drop(transitions);
        replace_controller_q04_suffix(&mut recipes, ledger, identity, &decision, &decision, &events, 2, first)?;
        let transitions = retain_q04_data(first, recipes.transitions(ledger, identity, &decision))?;
        for index in 2..=3 {
            capture_controller_q04_commit(journal, &transitions, index, root, &mut commits[index], first, postcheck)?;
            let (generation, signer) = retain_q04_data(first,
                credentials.signer().ok_or(CreateQ04ErrorV1::ChangedCut))?;
            source.refresh_original_root(root, journal, ledger, &transitions, ledger.project, generation, signer)?;
        }
        events.release_ack = capture_controller_q04_acknowledgement(
            journal, &transitions, 4, root, credentials, Q04AcknowledgementKindV1::Release,
            &events, None, &mut acknowledgements[1], &mut signatures[1], first, postcheck,
        )?;
        root.exchange_acknowledgement(identity, Q04AcknowledgementKindV1::Release, &acknowledgements[1])?;
        events.release = retain_q04_data(first, root.observed_root_phase(identity, 1))?.digest();
        {
            let original = retain_q04_data(first, root.cache_terminal_loan(identity))?;
            cache.bind_observed_release(&original, &mut cache_recipes)?;
            source.bind_observed_release(&mut source_recipes, &original)?;
            cache.append_original_phase(&original, &cache_recipes, 1)?;
            cache.capture_terminal_readback(&original, &cache_recipes, crate::journal::Q04CacheTerminalPhaseV1::Released)?;
            source.append_original_phase(&source_recipes, 1, &original)?;
        }
        let (generation, signer) = retain_q04_data(first,
            credentials.signer().ok_or(CreateQ04ErrorV1::ChangedCut))?;
        source.refresh_original_root(root, journal, ledger, &transitions, ledger.project, generation, signer)?;
        drop(transitions);
        replace_controller_q04_suffix(&mut recipes, ledger, identity, &decision, &decision, &events, 4, first)?;
        let transitions = retain_q04_data(first, recipes.transitions(ledger, identity, &decision))?;
        capture_controller_q04_commit(journal, &transitions, 4, root, &mut commits[4], first, postcheck)?;
        source.refresh_original_root(root, journal, ledger, &transitions, ledger.project, generation, signer)?;

        events.settlement_ack = capture_controller_q04_acknowledgement(
            journal, &transitions, 5, root, credentials, Q04AcknowledgementKindV1::Settlement,
            &events, None, &mut acknowledgements[2], &mut signatures[2], first, postcheck,
        )?;
        root.exchange_acknowledgement(identity, Q04AcknowledgementKindV1::Settlement, &acknowledgements[2])?;
        let root_six = retain_q04_data(first, root.observed_root_phase(identity, 2))?;
        events.settlement = root_six.digest();
        drop(transitions);
        replace_controller_q04_suffix(&mut recipes, ledger, identity, &decision, &decision, &events, 5, first)?;
        let transitions = retain_q04_data(first, recipes.transitions(ledger, identity, &decision))?;
        capture_controller_q04_commit(journal, &transitions, 5, root, &mut commits[5], first, postcheck)?;
        let (generation, signer) = retain_q04_data(first,
            credentials.signer().ok_or(CreateQ04ErrorV1::ChangedCut))?;
        source.refresh_original_root(root, journal, ledger, &transitions, ledger.project, generation, signer)?;
        {
            let original = retain_q04_data(first, root.cache_terminal_loan(identity))?;
            cache.append_original_phase(&original, &cache_recipes, 2)?;
            cache.capture_terminal_readback(&original, &cache_recipes, crate::journal::Q04CacheTerminalPhaseV1::Cleared)?;
            let clearance = cache.clearance_loan(&original, &cache_recipes)?;
            source.clear_after_original_cache(&source_recipes, clearance)?;
        }
        source.refresh_original_root(root, journal, ledger, &transitions, ledger.project, generation, signer)?;
        let cache_clear = retain_q04_data(first, cache_recipes.clear_recipe_digest())?;
        let source_clear = retain_q04_data(first, source_recipes.clear_recipe_digest())?;
        let status_three_effect = retain_q04_data(first, ledger.effect_record(&recipes.gates[2]))?;
        let status_three_bytes = retain_q04_data(first,
            status_three_effect.value().ok_or(CreateQ04ErrorV1::ChangedCut))?;
        events.clearance = retain_q04_data(first, lower_clearance_recipe_digest_v1(
            identity, &root_six, cache_clear, source_clear, &recipes.phases[5],
            status_three_bytes,
        ))?;
        drop(transitions);
        replace_controller_q04_suffix(&mut recipes, ledger, identity, &decision, &decision, &events, 6, first)?;
        let transitions = retain_q04_data(first, recipes.transitions(ledger, identity, &decision))?;
        capture_controller_q04_commit(journal, &transitions, 6, root, &mut commits[6], first, postcheck)?;
        source.refresh_original_root(root, journal, ledger, &transitions, ledger.project, generation, signer)?;

        events.clearance_ack = capture_controller_q04_acknowledgement(
            journal, &transitions, 7, root, credentials, Q04AcknowledgementKindV1::Clearance,
            &events, Some([root_six.digest(), cache_clear, source_clear, events.clearance]),
            &mut acknowledgements[3], &mut signatures[3], first, postcheck,
        )?;
        root.exchange_acknowledgement(identity, Q04AcknowledgementKindV1::Clearance, &acknowledgements[3])?;
        events.final_root = retain_q04_data(first, root.observed_root_phase(identity, 3))?.digest();
        drop(transitions);
        replace_controller_q04_suffix(&mut recipes, ledger, identity, &decision, &decision, &events, 7, first)?;
        let transitions = retain_q04_data(first, recipes.transitions(ledger, identity, &decision))?;
        capture_controller_q04_commit(journal, &transitions, 7, root, &mut commits[7], first, postcheck)?;
        let (generation, signer) = retain_q04_data(first,
            credentials.signer().ok_or(CreateQ04ErrorV1::ChangedCut))?;
        source.refresh_original_root(root, journal, ledger, &transitions, ledger.project, generation, signer)?;
        if credentials.recheck().is_err() { return Err(()); }
        source.finish_original_clearance(root, journal, ledger, &transitions,
            &source_recipes, &mut cache, &cache_recipes)?;
        if commits.iter().any(|result| !matches!(result, Some(Ok(_))))
            || signatures.iter().any(|result| !matches!(result, Some(Ok(()))))
            || first.is_some() || postcheck.is_some()
        {
            return Err(());
        }
        // No further fallible action may separate exact final clearance from
        // returning the original parents. The generic Create remains pending.
        *complete = true;
        Ok(())
    })();
    match continued {
        Ok(()) => Ok(()),
        Err(()) => std::process::exit(1),
    }
}

/// Retains exact original applying rows, not a transferable currentness permit.
///
/// Every action rechecks this DATA against the same real Controller journal.
/// The configured scope and executor plan still enter through their original
/// private installed caller; Root/Source/Cache/clock custody stays separate.
pub(crate) struct OriginalQ04ControllerLedgerV1 {
    operation: OperationId,
    sandbox: SandboxId,
    project: ProjectId,
    scope: crate::controller::ControllerRequestScopeV1,
    revision: ObjectDigest,
    accepted_generation: u64,
    operation_bytes: Vec<u8>,
    desired_key: Vec<u8>,
    desired_bytes: Vec<u8>,
    effect_bytes: Vec<u8>,
    effect: EffectLedgerRecord,
    before_rows: ObjectDigest,
    original_next: u64,
    original_names: crate::journal::ProtectedJournalNamesV1,
    source: crate::policy_compiler::CurrentCreateProjectPolicySourceV1,
}

impl OriginalQ04ControllerLedgerV1 {
    pub(crate) fn capture(
        journal: &mut Journal,
        operation: OperationId,
        scope: crate::controller::ControllerRequestScopeV1,
        expected_plan: &super::EffectPlan,
    ) -> Result<Self, CreateQ04ErrorV1> {
        journal.validate_held_protected_names()?;
        journal.require_q04_native_recipes_v1(&[])?;
        let original_next = journal.snapshot_sequence();
        let original_names = journal.protected_writer_physical_names_v1()?;
        let (revision, accepted_generation) =
            super::checked_live_create_sandbox_admission_revision_v1(
                journal, operation, scope, expected_plan,
            )?.ok_or(ReconcilerError::CorruptLedger("Q04 original admission is absent"))?;
        let operation_bytes = journal.get(RecordNamespace::Operation, operation.as_bytes())
            .ok_or(ReconcilerError::OperationNotFound)?;
        let operation_row = decode_operation(operation_bytes)?;
        let effect_bytes = journal.get(RecordNamespace::Effect, &effect_key(operation, 0))
            .ok_or(ReconcilerError::CorruptLedger("Q04 original Effect is absent"))?;
        let (effect, gate) = decode_effect_with_q04(effect_bytes)?;
        if operation_row.state != OperationState::Applying
            || operation_row.effect_count != 1
            || operation_row.ownership_gated
            || operation_row.runtime_intent_digest.is_some()
            || operation_row.public_operation.is_none()
            || !matches!(effect.state, EffectState::Applying { .. })
            || effect.dispatch.is_some()
            || effect.plan.authority().is_some()
            || effect.project_admission.is_some()
            || gate.is_some()
            || encode_operation_record(operation_row).as_slice() != operation_bytes
            || encode_effect(&effect)?.as_slice() != effect_bytes
        {
            return Err(ReconcilerError::CorruptLedger("Q04 original applying rows changed").into());
        }

        let context = effect.plan.public_mutation_context()?
            .ok_or(ReconcilerError::CorruptLedger("Q04 original Create context is absent"))?;
        let crate::cli_model::DormantSandboxRequestKindV1::Create(create) = context.validated_request()?
        else {
            return Err(ReconcilerError::CorruptLedger("Q04 original method changed").into());
        };
        let project = context.project();
        if !create.parent_sandbox_id.is_empty() {
            return Err(ReconcilerError::CorruptLedger("Q04 original Create is not parentless").into());
        }
        // Create's sandbox ID is the admitted projection, not a request field
        // or an independently re-derived identity recipe.
        let projections = PublicProjectionStoreV1::new(journal).list_operation(operation)?;
        let mut sandboxes = projections.iter().filter(|projection| {
            projection.resource().kind() == PublicProjectionKindV1::Sandbox
        });
        let projection = sandboxes.next()
            .ok_or(ReconcilerError::CorruptLedger("Q04 original sandbox projection is absent"))?;
        if sandboxes.next().is_some() {
            return Err(ReconcilerError::CorruptLedger("Q04 original sandbox projection is ambiguous").into());
        }
        let sandbox_bytes: [u8; 16] = projection.resource().resource_id().try_into()
            .map_err(|_| ReconcilerError::CorruptLedger("Q04 original sandbox is malformed"))?;
        let sandbox = SandboxId::from_bytes(sandbox_bytes);
        let desired_key = crate::controller_service::public_projection::projection_key(
            PublicProjectionKindV1::Sandbox, sandbox_bytes,
        );
        let desired_bytes = journal.get(RecordNamespace::DesiredState, &desired_key)
            .ok_or(ReconcilerError::CorruptLedger("Q04 original Desired is absent"))?;
        if projection.operation() != operation || projection.project() != project {
            return Err(ReconcilerError::CorruptLedger("Q04 original Desired owner changed").into());
        }
        let PublicProjectionResourceV1::Sandbox(resource) = projection.resource() else {
            return Err(ReconcilerError::CorruptLedger("Q04 original Desired kind changed").into());
        };
        let desired = resource.desired.as_option()
            .ok_or(ReconcilerError::CorruptLedger("Q04 original Desired is absent"))?;
        if create.project_id.as_slice() != project.as_bytes()
            || create.specification.as_option() != desired.specification.as_option()
            || create.requested_policy.as_option() != desired.requested_policy.as_option()
        {
            return Err(ReconcilerError::CorruptLedger("Q04 original Create/Desired changed").into());
        }

        let before_rows = crate::journal::q04_controller_before_rows_digest_v1(
            operation, sandbox_bytes, operation_bytes, desired_bytes, effect_bytes,
        )?;
        let operation_bytes = copy_original_row(operation_bytes)?;
        let desired_bytes = copy_original_row(desired_bytes)?;
        let effect_bytes = copy_original_row(effect_bytes)?;
        let source = crate::policy_compiler::current_parentless_create_project_source_v1(
            journal, operation, sandbox,
        )?;
        let retained = Self {
            operation, sandbox, project, scope, revision, accepted_generation,
            operation_bytes,
            desired_key,
            desired_bytes,
            effect_bytes,
            effect,
            before_rows,
            original_next,
            original_names,
            source,
        };
        retained.require_original(journal)?;
        journal.require_q04_native_recipes_v1(&[])?;
        if journal.snapshot_sequence() != original_next {
            return Err(CreateQ04ErrorV1::ChangedCut);
        }
        journal.validate_held_protected_names()?;
        Ok(retained)
    }

    pub(crate) fn before_rows(&self) -> ObjectDigest {
        self.before_rows
    }

    pub(crate) fn original_next(&self) -> u64 {
        self.original_next
    }

    pub(crate) fn source_commitment(&self) -> ObjectDigest {
        self.source.commitment()
    }

    pub(crate) fn write_original_metadata(
        &self,
        journal: &mut Journal,
        metadata: &mut [u8; crate::policy_compiler::create_q04::PREHOLD_METADATA_BYTES],
    ) -> Result<(), CreateQ04ErrorV1> {
        self.require_original(journal)?;
        journal.require_q04_native_recipes_v1(&[])?;
        if journal.snapshot_sequence() != self.original_next {
            return Err(CreateQ04ErrorV1::ChangedCut);
        }
        metadata[176..224].copy_from_slice(&self.original_names.to_bytes());
        metadata[464..472].copy_from_slice(&self.original_next.to_be_bytes());
        self.require_original(journal)
    }

    pub(crate) fn effect_plan_digest(&self) -> Result<ObjectDigest, CreateQ04ErrorV1> {
        let planned = encode_effect(&EffectLedgerRecord {
            state: EffectState::Planned,
            dispatch: None,
            project_admission: None,
            ..self.effect.clone()
        })?;
        Ok(ObjectDigest::from_bytes(Sha256::digest(planned).into()))
    }

    // Signing re-enters the same scoped/current source producer. The returned
    // source is local comparison DATA under the caller's real mutable Journal
    // borrow, never a replacement for that writer or a snapshot authority.
    pub(crate) fn signing_current_source(
        &self,
        journal: &mut Journal,
    ) -> Result<crate::policy_compiler::CurrentCreateProjectPolicySourceV1, CreateQ04ErrorV1> {
        self.require_original(journal)?;
        let current = crate::policy_compiler::current_parentless_create_project_source_for_operation_v1(
            journal, self.operation, self.project, self.scope, &self.effect.plan,
        )?;
        if current.commitment() != self.source.commitment()
            || current.operation_revision() != self.revision
            || current.accepted_generation() != self.accepted_generation
            || current.sandbox() != self.sandbox
        {
            return Err(CreateQ04ErrorV1::ChangedCut);
        }
        Ok(current)
    }

    pub(crate) fn original_rows(&self) -> [&[u8]; 3] {
        [&self.operation_bytes, &self.desired_bytes, &self.effect_bytes]
    }

    pub(crate) fn require_identity(&self, identity: &Q04CutIdentityV1) -> Result<(), CreateQ04ErrorV1> {
        if self.operation != identity.operation()
            || self.sandbox != identity.sandbox()
            || self.project != identity.project()
            || self.revision != identity.operation_revision()
            || self.accepted_generation != identity.accepted_generation()
            || self.before_rows != identity.before_controller_rows()
        {
            return Err(CreateQ04ErrorV1::ChangedCut);
        }
        validate_original_claim_rows_v1(
            &self.operation_bytes, &self.desired_bytes, &self.effect_bytes, identity,
        )
    }

    pub(crate) fn require_original(&self, journal: &mut Journal) -> Result<(), CreateQ04ErrorV1> {
        journal.validate_held_protected_names()?;
        if journal.protected_writer_physical_names_v1()? != self.original_names
            || journal.get(RecordNamespace::Operation, self.operation.as_bytes())
                != Some(self.operation_bytes.as_slice())
            || journal.get(RecordNamespace::DesiredState, &self.desired_key)
                != Some(self.desired_bytes.as_slice())
        {
            return Err(CreateQ04ErrorV1::ChangedCut);
        }
        let actual = journal.get(RecordNamespace::Effect, &effect_key(self.operation, 0))
            .ok_or(ReconcilerError::CorruptLedger("Q04 original Effect is absent"))?;
        let (effect, _) = decode_effect_with_q04(actual)?;
        if encode_effect(&effect)? != self.effect_bytes
            || super::checked_live_create_sandbox_admission_revision_v1(
                journal, self.operation, self.scope, &self.effect.plan,
            )? != Some((self.revision, self.accepted_generation))
        {
            return Err(CreateQ04ErrorV1::ChangedCut);
        }
        let current = crate::policy_compiler::current_parentless_create_project_source_v1(
            journal, self.operation, self.sandbox,
        )?;
        if current.commitment() != self.source.commitment() {
            return Err(CreateQ04ErrorV1::ChangedCut);
        }
        journal.validate_held_protected_names()?;
        Ok(())
    }

    pub(crate) fn effect_record(
        &self,
        gate: &Q04EffectSubgateV1,
    ) -> Result<JournalRecord, CreateQ04ErrorV1> {
        Ok(JournalRecord::put(
            RecordNamespace::Effect, effect_key(self.operation, 0).to_vec(),
            encode_q04_effect(&self.effect, gate)?,
        ))
    }

    // Pure equality for the existing preflight engine's materialized prefix.
    // The real Journal/full admission is checked before and after that engine;
    // a cloned prefix cannot become a Controller owner or current permit.
    pub(crate) fn require_materialized_rows(
        &self,
        state: &std::collections::BTreeMap<(RecordNamespace, Vec<u8>), Vec<u8>>,
    ) -> Result<Option<Q04EffectSubgateV1>, ReconcilerError> {
        if state.get(&(RecordNamespace::Operation, self.operation.as_bytes().to_vec()))
                != Some(&self.operation_bytes)
            || state.get(&(RecordNamespace::DesiredState, self.desired_key.clone()))
                != Some(&self.desired_bytes)
        {
            return Err(ReconcilerError::CorruptLedger("Q04 original materialized rows changed"));
        }
        let selected_key = effect_key(self.operation, 0);
        let bytes = state.get(&(RecordNamespace::Effect, selected_key.to_vec()))
            .ok_or(ReconcilerError::CorruptLedger("Q04 original materialized Effect is absent"))?;
        let (effect, gate) = decode_effect_with_q04(bytes)?;
        if encode_effect(&effect)? != self.effect_bytes
            || state.iter().any(|((namespace, key), bytes)| {
                *namespace == RecordNamespace::Effect
                    && bytes.first() == Some(&6)
                    && key != selected_key.as_slice()
            })
        {
            return Err(ReconcilerError::CorruptLedger("Q04 original materialized Effect changed"));
        }
        Ok(gate)
    }
}

fn copy_original_row(bytes: &[u8]) -> Result<Vec<u8>, CreateQ04ErrorV1> {
    if bytes.is_empty() || bytes.len() > 64 * 1024 {
        return Err(CreateQ04ErrorV1::Bounds);
    }
    let mut copy = Vec::new();
    copy.try_reserve_exact(bytes.len())?;
    copy.extend_from_slice(bytes);
    Ok(copy)
}

// This checks the original signed Claim's row DATA through the same existing
// codecs. It is not a synthetic Journal or complete Controller authority:
// the caller still requires the pinned actual current/held Controller cut.
pub(crate) fn validate_original_claim_rows_v1(
    operation_bytes: &[u8],
    desired_bytes: &[u8],
    effect_bytes: &[u8],
    identity: &Q04CutIdentityV1,
) -> Result<(), CreateQ04ErrorV1> {
    let rows = read_original_q04_rows_v1(
        operation_bytes, desired_bytes, effect_bytes,
        Q04OriginalRowBindingV1 {
            operation: identity.operation(),
            sandbox: identity.sandbox(),
            project: identity.project(),
            accepted_generation: identity.accepted_generation(),
            desired_precondition: identity.desired_precondition(),
        },
    )?;
    if rows.before != identity.before_controller_rows() {
        return Err(ReconcilerError::CorruptLedger("Q04 Claim original rows changed").into());
    }
    if rows.effect_plan_digest()? != identity.effect_plan_digest() {
        return Err(ReconcilerError::CorruptLedger("Q04 Claim original Effect plan changed").into());
    }
    Ok(())
}

// Borrowed original rows are checked by the same model/ledger codecs before
// Cut construction. These identities must separately join the actual pinned
// Controller readback; this DATA helper supplies no Controller authority.
pub(crate) struct Q04OriginalRowBindingV1 {
    pub(crate) operation: OperationId,
    pub(crate) sandbox: SandboxId,
    pub(crate) project: ProjectId,
    pub(crate) accepted_generation: u64,
    pub(crate) desired_precondition: ObjectDigest,
}

pub(crate) struct Q04OriginalRowDataV1 {
    pub(crate) before: ObjectDigest,
    effect: EffectLedgerRecord,
}

impl Q04OriginalRowDataV1 {
    pub(crate) fn effect_plan_digest(self) -> Result<ObjectDigest, CreateQ04ErrorV1> {
        let admitted = encode_effect(&EffectLedgerRecord {
            state: EffectState::Planned,
            dispatch: None,
            project_admission: None,
            ..self.effect
        })?;
        Ok(ObjectDigest::from_bytes(Sha256::digest(admitted).into()))
    }

    // Root reconstructs the exact planned Applying companion through the
    // same Effect codec. This DATA encoding cannot create a Controller owner
    // or waive its actual full-ledger CAS/current admission checks.
    pub(crate) fn applying_effect_with_gate(
        &self,
        gate: &Q04EffectSubgateV1,
    ) -> Result<Vec<u8>, CreateQ04ErrorV1> {
        Ok(encode_q04_effect(&self.effect, gate)?)
    }
}

pub(crate) fn read_original_q04_rows_v1(
    operation_bytes: &[u8],
    desired_bytes: &[u8],
    effect_bytes: &[u8],
    binding: Q04OriginalRowBindingV1,
) -> Result<Q04OriginalRowDataV1, CreateQ04ErrorV1> {
    let operation = decode_operation(operation_bytes)?;
    if operation.state != OperationState::Applying
        || operation.effect_count != 1
        || operation.ownership_gated
        || operation.runtime_intent_digest.is_some()
        || !operation.public_operation.is_some_and(|public| {
            public.method() == crate::controller_query::PublicOperationMethodV1::CreateSandbox
                && public.accepted_generation() == binding.accepted_generation
        })
        || encode_operation_record(operation).as_slice() != operation_bytes
    {
        return Err(ReconcilerError::CorruptLedger("Q04 Claim Operation changed").into());
    }

    let (effect, gate) = decode_effect_with_q04(effect_bytes)?;
    if gate.is_some()
        || !matches!(effect.state, EffectState::Applying { .. })
        || effect.dispatch.is_some()
        || effect.plan.authority().is_some()
        || effect.project_admission.is_some()
        || effect.plan.public_mutation_method()
            != Some(crate::controller_query::PublicOperationMethodV1::CreateSandbox)
        || encode_effect(&effect)?.as_slice() != effect_bytes
    {
        return Err(ReconcilerError::CorruptLedger("Q04 Claim original Effect changed").into());
    }
    let context = effect.plan.public_mutation_context()?
        .ok_or(ReconcilerError::CorruptLedger("Q04 Claim Create context is absent"))?;
    let request = context.validated_request()?;
    let crate::cli_model::DormantSandboxRequestKindV1::Create(create) = request else {
        return Err(ReconcilerError::CorruptLedger("Q04 Claim method changed").into());
    };
    let desired = PublicProjectionRecordV1::from_retained_record_bytes(
        PublicProjectionKindV1::Sandbox, *binding.sandbox.as_bytes(), desired_bytes,
    )?;
    let PublicProjectionResourceV1::Sandbox(resource) = desired.resource() else {
        return Err(ReconcilerError::CorruptLedger("Q04 Claim Desired kind changed").into());
    };
    let specification = resource.desired.as_option()
        .ok_or(ReconcilerError::CorruptLedger("Q04 Claim Desired is absent"))?;
    if desired.project() != binding.project
        || desired.operation() != binding.operation
        || desired.revision() != binding.desired_precondition
        || context.project() != binding.project
        || !create.parent_sandbox_id.is_empty()
        || create.project_id.as_slice() != binding.project.as_bytes()
        || create.specification.as_option() != specification.specification.as_option()
        || create.requested_policy.as_option() != specification.requested_policy.as_option()
    {
        return Err(ReconcilerError::CorruptLedger("Q04 Claim Desired/Create changed").into());
    }

    let before = crate::journal::q04_controller_before_rows_digest_v1(
        binding.operation, *binding.sandbox.as_bytes(),
        operation_bytes, desired_bytes, effect_bytes,
    )?;

    Ok(Q04OriginalRowDataV1 { before, effect })
}

// This structural readback never treats map state or named UUIDs as proof of
// atomic native membership. Its only generic outcome is pending/refusal.
pub(crate) fn require_original_pending(journal: &Journal) -> Result<bool, ReconcilerError> {
    let has_history = journal.records(RecordNamespace::ControllerPolicyHold)
        .any(|(key, _)| key == CONTROLLER_IDENTITY_KEY || key.starts_with(CONTROLLER_PHASE_PREFIX));
    let has_gate = journal.records(RecordNamespace::Effect)
        .any(|(_, bytes)| bytes.first() == Some(&6));
    if !has_history && !has_gate {
        // No new-purpose byte means no new owner/name/ledger check. Ordinary
        // journals and all their original validation/error order stay intact.
        return Ok(false);
    }
    let history = journal.controller_q04_history_v1()?;
    let Some(history) = history else {
        if has_gate {
            return Err(ReconcilerError::CorruptLedger("orphan Q04 policy subgate"));
        }
        return Ok(false);
    };

    journal.ensure_protected_authority()?;
    if journal.protected_owner_uid()? != history.identity.controller_uid() {
        return Err(ReconcilerError::CorruptLedger("Q04 Controller owner changed"));
    }
    let operation_id = history.identity.operation();
    let operation_bytes = journal.get(RecordNamespace::Operation, operation_id.as_bytes())
        .ok_or(ReconcilerError::CorruptLedger("Q04 Operation is absent"))?;
    let operation = decode_operation(operation_bytes)?;
    if operation.state != OperationState::Applying
        || operation.effect_count != 1
        || operation.ownership_gated
        || operation.runtime_intent_digest.is_some()
        || operation.public_operation.is_none()
    {
        return Err(ReconcilerError::CorruptLedger("Q04 Operation is not sole Applying Create"));
    }

    let selected_key = effect_key(operation_id, 0);
    let effect_bytes = journal.get(RecordNamespace::Effect, &selected_key)
        .ok_or(ReconcilerError::CorruptLedger("Q04 Effect is absent"))?;
    let (effect, gate) = decode_effect_with_q04(effect_bytes)?;
    if !matches!(effect.state, EffectState::Applying { .. })
        || effect.dispatch.is_some()
        || effect.plan.public_mutation_method()
            != Some(crate::controller_query::PublicOperationMethodV1::CreateSandbox)
    {
        return Err(ReconcilerError::CorruptLedger("Q04 Effect is not Applying Create"));
    }
    for (key, bytes) in journal.records(RecordNamespace::Effect) {
        if bytes.first() == Some(&6) && key != selected_key.as_slice() {
            return Err(ReconcilerError::CorruptLedger("foreign Q04 policy subgate"));
        }
    }

    // Reuse the original admitted Accepted/Planned-None reconstruction. The
    // actual Applying/v6 record is not rewritten into a counterfeit live cut.
    let (revision, generation, _) = live_create_sandbox_admission_revision_v1(journal, operation_id)?
        .ok_or(ReconcilerError::CorruptLedger("Q04 Create admission changed"))?;
    if revision != history.identity.operation_revision()
        || generation != history.identity.accepted_generation()
    {
        return Err(ReconcilerError::CorruptLedger("Q04 original admission changed"));
    }
    let admitted_effect = encode_effect(&EffectLedgerRecord {
        state: EffectState::Planned,
        dispatch: None,
        project_admission: None,
        ..effect
    })?;
    let plan_digest = ObjectDigest::from_bytes(Sha256::digest(admitted_effect).into());
    if plan_digest != history.identity.effect_plan_digest() {
        return Err(ReconcilerError::CorruptLedger("Q04 original Effect plan changed"));
    }
    let projection = PublicProjectionStoreV1::new(journal)
        .get(PublicProjectionKindV1::Sandbox, *history.identity.sandbox().as_bytes())
        .map_err(|_| ReconcilerError::CorruptLedger("Q04 Desired projection is corrupt"))?
        .ok_or(ReconcilerError::CorruptLedger("Q04 Desired projection is absent"))?;
    if projection.operation() != operation_id
        || projection.project() != history.identity.project()
        || projection.revision() != history.identity.desired_precondition()
    {
        return Err(ReconcilerError::CorruptLedger("Q04 Desired precondition changed"));
    }

    let last = history.phases.last()
        .ok_or(ReconcilerError::CorruptLedger("Q04 phase history is empty"))?;
    if last.phase() == 1 {
        if gate.is_some() {
            return Err(ReconcilerError::CorruptLedger("Q04 gate precedes its consumed phase"));
        }
        return Ok(true);
    }
    let gate = gate.ok_or(ReconcilerError::CorruptLedger("Q04 consumed gate is absent"))?;
    gate.require_cut_identity(&history.identity)?;
    let expected_status = match last.phase() {
        2..=4 => 1,
        5..=6 => 2,
        7 => 3,
        8 => 4,
        _ => return Err(ReconcilerError::CorruptLedger("Q04 phase is invalid")),
    };
    if gate.status() != expected_status
        || gate.bytes()[128..160] != last.bytes()[96..128]
        || gate.historical_consumed_record()?.digest().as_bytes() != &last.bytes()[128..160]
    {
        return Err(ReconcilerError::CorruptLedger("Q04 consumed gate/phase relation changed"));
    }
    let gate_ack_phase = match gate.status() {
        1 => None,
        2 => Some(5),
        3 => Some(6),
        4 => Some(8),
        _ => return Err(ReconcilerError::CorruptLedger("Q04 gate status is invalid")),
    };
    if let Some(phase) = gate_ack_phase {
        let prior = history.phases.get(phase - 1)
            .ok_or(ReconcilerError::CorruptLedger("Q04 gate acknowledgement phase is absent"))?;
        if gate.acknowledgement() != prior.acknowledgement() {
            return Err(ReconcilerError::CorruptLedger("Q04 gate acknowledgement changed"));
        }
    }
    Ok(true)
}
