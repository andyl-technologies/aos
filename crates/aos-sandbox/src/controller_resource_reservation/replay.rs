//! Replays the complete shared bank without constructing a second ledger.
//!
//! Each head is checked against every retained claim in the protected state.
//! Released operation claims remain as replay tombstones. Inclusive child
//! grants remain charged in their immediate parent, including after restart.

use std::collections::BTreeMap;

use aos_sandbox_core::{ResourceDimension, ResourceLimit, ResourceVector};

use super::{AccountHead, AccountKind, ClaimPurpose, ClaimState, EnrollmentIdentity, ResourceReservationErrorV1, codec, q04, settlement};
use crate::RecordNamespace;

pub(super) type State = BTreeMap<(RecordNamespace, Vec<u8>), Vec<u8>>;
pub(super) const HEAD_PREFIX: u8 = b'h';
pub(super) const CLAIM_PREFIX: u8 = b'c';
pub(super) const PREPARATION_PREFIX: u8 = b'p';

pub(super) fn key(prefix: u8, id: [u8; 16]) -> [u8; 17] {
    let mut key = [0; 17];
    key[0] = prefix;
    key[1..].copy_from_slice(&id);
    key
}

pub(super) fn validate(state: &State) -> Result<Option<EnrollmentIdentity>, ResourceReservationErrorV1> {
    let mut enrollment = None;
    let mut heads = 0_usize;
    let mut roots = 0_usize;
    let mut controllers = 0_usize;
    let mut components = 0_usize;

    for ((namespace, key_bytes), bytes) in state {
        if *namespace != RecordNamespace::ControllerResourceReservation {
            continue;
        }
        match key_bytes.first() {
            Some(&HEAD_PREFIX) => {
                let head = codec::decode_head(bytes)?;
                require_key(key_bytes, HEAD_PREFIX, head.id)?;
                require_enrollment(&mut enrollment, head.enrollment)?;
                heads = heads.checked_add(1).ok_or(ResourceReservationErrorV1::CorruptLedger)?;
                match head.kind {
                    AccountKind::Node => roots += 1,
                    AccountKind::Controller => controllers += 1,
                    AccountKind::Components => components += 1,
                    _ => {}
                }
            }
            Some(&CLAIM_PREFIX) => {
                let claim = codec::decode_claim(bytes)?;
                require_key(key_bytes, CLAIM_PREFIX, claim.id)?;
                require_enrollment(&mut enrollment, claim.enrollment)?;
            }
            Some(&PREPARATION_PREFIX) => {
                let binding = codec::decode_preparation(bytes)?;
                require_key(key_bytes, PREPARATION_PREFIX, binding.claim.id)?;
                require_enrollment(&mut enrollment, binding.claim.enrollment)?;
            }
            Some(&q04::PREFIX) => {
                let binding = q04::decode(bytes)?;
                let original = q04::original_claim(binding);
                require_key(key_bytes, q04::PREFIX, original.id)?;
                require_enrollment(&mut enrollment, original.enrollment)?;
            }
            Some(&settlement::PREFIX) => {
                let terminal = settlement::decode(bytes)?;
                require_key(key_bytes, settlement::PREFIX, terminal.original_id())?;
                let binding = q04::decode(record_bytes(state, q04::PREFIX, terminal.original_id())
                    .ok_or(ResourceReservationErrorV1::CorruptLedger)?)?;
                require_enrollment(&mut enrollment, q04::original_claim(binding).enrollment)?;
            }
            _ => return Err(ResourceReservationErrorV1::CorruptLedger),
        }
    }
    if enrollment.is_none() {
        return Ok(None);
    }
    if roots != 1 || controllers != 1 || components != 1 {
        return Err(ResourceReservationErrorV1::CorruptLedger);
    }

    for ((namespace, key_bytes), bytes) in state {
        if *namespace != RecordNamespace::ControllerResourceReservation {
            continue;
        }
        if key_bytes[0] == HEAD_PREFIX {
            let head = codec::decode_head(bytes)?;
            validate_head(state, head, heads)?;
        } else if key_bytes[0] == PREPARATION_PREFIX {
            let binding = codec::decode_preparation(bytes)?;
            let claim = record_bytes(state, CLAIM_PREFIX, binding.claim.id)
                .ok_or(ResourceReservationErrorV1::CorruptLedger)?;
            match record_bytes(state, q04::PREFIX, binding.claim.id) {
                Some(bytes) => {
                    let transferred = q04::decode(bytes)?;
                    if q04::original_claim(transferred) != binding.claim {
                        return Err(ResourceReservationErrorV1::CorruptLedger);
                    }
                    q04::require_replayed(state, transferred)?;
                }
                None if codec::decode_claim(claim)? == binding.claim => {}
                None => return Err(ResourceReservationErrorV1::CorruptLedger),
            }
        } else if key_bytes[0] == q04::PREFIX {
            q04::require_replayed(state, q04::decode(bytes)?)?;
        } else if key_bytes[0] == settlement::PREFIX {
            let terminal = settlement::decode(bytes)?;
            let binding = q04::decode(record_bytes(state, q04::PREFIX, terminal.original_id())
                .ok_or(ResourceReservationErrorV1::CorruptLedger)?)?;
            settlement::current_use(state, binding)?;
        } else {
            let claim = codec::decode_claim(bytes)?;
            let parent = find_head(state, claim.account)?;
            if claim.enrollment != parent.enrollment {
                return Err(ResourceReservationErrorV1::CorruptLedger);
            }
            if claim.child != [0; 16] {
                let child = find_head(state, claim.child)?;
                if child.parent != parent.id || child.enrollment != parent.enrollment
                    || claim.state != ClaimState::Reserved || !allowed_edge(parent.kind, child.kind)
                    || finite_ceilings(child)? != claim.amount
                    || claim.project != child.project || claim.sandbox != child.sandbox
                    || claim.tree_revision != child.tree_revision
                    || (matches!(parent.kind, AccountKind::Project | AccountKind::Sandbox)
                        && (parent.project != child.project || parent.tree_revision != child.tree_revision))
                {
                    return Err(ResourceReservationErrorV1::CorruptLedger);
                }
                let purpose_matches = match claim.purpose {
                    ClaimPurpose::ControllerBootstrap => child.kind == AccountKind::Controller,
                    ClaimPurpose::ComponentEnvelope => child.kind == AccountKind::Components,
                    ClaimPurpose::InclusiveGrant => matches!(child.kind,
                        AccountKind::Project | AccountKind::Sandbox | AccountKind::Operation),
                    ClaimPurpose::Snapshot | ClaimPurpose::ProjectPreparation
                        | ClaimPurpose::Q04Preparation => false,
                };
                if !purpose_matches {
                    return Err(ResourceReservationErrorV1::CorruptLedger);
                }
            } else if claim.project != parent.project || claim.sandbox != parent.sandbox
                || claim.tree_revision != parent.tree_revision
            {
                return Err(ResourceReservationErrorV1::CorruptLedger);
            } else if claim.purpose == ClaimPurpose::ProjectPreparation
                && parent.kind != AccountKind::Project
            {
                return Err(ResourceReservationErrorV1::CorruptLedger);
            }
            if claim.purpose == ClaimPurpose::ProjectPreparation {
                let binding = record_bytes(state, PREPARATION_PREFIX, claim.id)
                    .ok_or(ResourceReservationErrorV1::CorruptLedger)?;
                let original = codec::decode_preparation(binding)?.claim;
                if original != claim && record_bytes(state, q04::PREFIX, claim.id).is_none() {
                    return Err(ResourceReservationErrorV1::CorruptLedger);
                }
            }
            if claim.purpose == ClaimPurpose::Q04Preparation
                && (parent.kind != AccountKind::Sandbox
                    || !state.iter().any(|((namespace, key), bytes)| {
                        *namespace == RecordNamespace::ControllerResourceReservation
                            && key.first() == Some(&q04::PREFIX)
                            && q04::decode(bytes).is_ok_and(|binding|
                                q04::contains_use(binding, claim))
                    }))
            {
                return Err(ResourceReservationErrorV1::CorruptLedger);
            }
        }
    }
    Ok(enrollment)
}

fn validate_head(state: &State, head: AccountHead, maximum_depth: usize) -> Result<(), ResourceReservationErrorV1> {
    let mut reserved = ResourceVector::ZERO;
    let mut committed = head.baseline;
    let mut incoming = 0_usize;

    for ((namespace, key_bytes), bytes) in state {
        if *namespace != RecordNamespace::ControllerResourceReservation || key_bytes[0] != CLAIM_PREFIX {
            continue;
        }
        let claim = codec::decode_claim(bytes)?;
        if claim.child == head.id {
            incoming = incoming.checked_add(1).ok_or(ResourceReservationErrorV1::CorruptLedger)?;
        }
        if claim.account != head.id {
            continue;
        }
        match claim.state {
            ClaimState::Reserved => reserved = reserved.checked_add(claim.amount)?,
            ClaimState::Committed => committed = committed.checked_add(claim.amount)?,
            ClaimState::Released => {}
        }
    }
    if reserved != head.account.reserved() || committed != head.account.committed()
        || incoming != usize::from(head.kind != AccountKind::Node)
    {
        return Err(ResourceReservationErrorV1::CorruptLedger);
    }

    // A bounded parent walk detects cycles without allocating a visited set.
    let mut current = head;
    for _ in 0..maximum_depth {
        if current.kind == AccountKind::Node {
            return Ok(());
        }
        let parent = find_head(state, current.parent)?;
        if !allowed_edge(parent.kind, current.kind) || parent.enrollment != head.enrollment {
            return Err(ResourceReservationErrorV1::CorruptLedger);
        }
        current = parent;
    }
    Err(ResourceReservationErrorV1::CorruptLedger)
}

// This lookup recognizes historical initial payment only. The caller must
// still hold and recheck the current Controller, Source and Completed Root.
pub(super) fn prior_initial_project_grant(
    state: &State,
    expected: AccountHead,
    acceptance: [u8; 32],
    instance: [u8; 32],
) -> Result<Option<super::Claim>, ResourceReservationErrorV1> {
    if expected.kind != AccountKind::Project || expected.generation != 1
        || expected.sandbox != [0; 16] || expected.baseline != ResourceVector::ZERO
    {
        return Err(ResourceReservationErrorV1::Conflict);
    }
    let mut prior = None;
    for ((namespace, key), bytes) in state {
        if *namespace != RecordNamespace::ControllerResourceReservation
            || key.first() != Some(&CLAIM_PREFIX)
        {
            continue;
        }
        let claim = codec::decode_claim(bytes)?;
        if claim.child != expected.id { continue; }
        let child = find_head(state, expected.id)?;
        if prior.is_some() || claim.enrollment != expected.enrollment
            || claim.account != expected.parent || claim.owner != acceptance
            || claim.purpose != ClaimPurpose::InclusiveGrant
            || claim.project != expected.project || claim.sandbox != expected.sandbox
            || claim.tree_revision != expected.tree_revision || claim.genesis_instance != instance
            || claim.amount != finite_ceilings(expected)? || claim.state != ClaimState::Reserved
            || !matches!(claim.cut, super::ClaimCut::Operation { .. })
            || child.enrollment != expected.enrollment || child.id != expected.id
            || child.parent != expected.parent || child.kind != expected.kind
            || child.project != expected.project || child.sandbox != expected.sandbox
            || child.tree_revision != expected.tree_revision || child.baseline != expected.baseline
            || finite_ceilings(child)? != finite_ceilings(expected)?
        {
            return Err(ResourceReservationErrorV1::Conflict);
        }
        // Its original paid clock/cut remains untouched. A new live Root cut
        // authenticates this rejoin, not a second payment or renewed old loan.
        prior = Some(claim);
    }
    if prior.is_none() && has_head(state, expected.id) {
        return Err(ResourceReservationErrorV1::Conflict);
    }
    Ok(prior)
}

pub(super) fn find_head(state: &State, id: [u8; 16]) -> Result<AccountHead, ResourceReservationErrorV1> {
    let bytes = record_bytes(state, HEAD_PREFIX, id)
        .ok_or(ResourceReservationErrorV1::CorruptLedger)?;
    let head = codec::decode_head(bytes)?;
    if head.id != id {
        return Err(ResourceReservationErrorV1::CorruptLedger);
    }
    Ok(head)
}

pub(super) fn has_head(state: &State, id: [u8; 16]) -> bool {
    record_bytes(state, HEAD_PREFIX, id).is_some()
}

// Fixed bank-key lookup borrows the original state without allocating a key.
pub(super) fn record_bytes(state: &State, prefix: u8, id: [u8; 16]) -> Option<&[u8]> {
    let expected = key(prefix, id);
    state.iter().find_map(|((namespace, key_bytes), bytes)| {
        (*namespace == RecordNamespace::ControllerResourceReservation
            && key_bytes.as_slice() == expected)
            .then_some(bytes.as_slice())
    })
}

pub(super) fn finite_ceilings(head: AccountHead) -> Result<ResourceVector, ResourceReservationErrorV1> {
    let mut values = [0; ResourceDimension::COUNT];
    for (index, dimension) in ResourceDimension::ALL.into_iter().enumerate() {
        let ResourceLimit::Bounded(value) = head.account.ceilings().get(dimension) else {
            return Err(ResourceReservationErrorV1::CorruptLedger);
        };
        values[index] = value;
    }
    Ok(ResourceVector::new(values))
}

pub(super) fn allowed_edge(parent: AccountKind, child: AccountKind) -> bool {
    matches!((parent, child),
        (AccountKind::Node, AccountKind::Controller | AccountKind::Components | AccountKind::Project)
        | (AccountKind::Project, AccountKind::Sandbox)
        | (AccountKind::Sandbox, AccountKind::Sandbox | AccountKind::Operation)
        | (AccountKind::Controller | AccountKind::Components, AccountKind::Operation)
    )
}

fn require_key(bytes: &[u8], prefix: u8, id: [u8; 16]) -> Result<(), ResourceReservationErrorV1> {
    if bytes != key(prefix, id) {
        return Err(ResourceReservationErrorV1::CorruptLedger);
    }
    Ok(())
}

fn require_enrollment(current: &mut Option<EnrollmentIdentity>, value: EnrollmentIdentity) -> Result<(), ResourceReservationErrorV1> {
    match current {
        Some(expected) if *expected != value => Err(ResourceReservationErrorV1::CorruptLedger),
        Some(_) => Ok(()),
        None => {
            *current = Some(value);
            Ok(())
        }
    }
}
