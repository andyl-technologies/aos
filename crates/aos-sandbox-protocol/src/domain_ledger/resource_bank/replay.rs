//! Replays the complete historical bank without constructing a second ledger.
//!
//! Each head is checked against every retained claim in the protected state.
//! Released operation claims remain as replay tombstones. Inclusive child
//! grants remain charged in their immediate parent, including after restart.
//!
//! ```text
//! bank-key = prefix:u8 || identity[16]
//! prefix = h (head) | c (claim) | p (preparation) | q (co-issuance) | t (terminal)
//! ```

use std::collections::BTreeMap;

use aos_sandbox_core::{ResourceAccount, ResourceDimension, ResourceLimit, ResourceVector};

use super::{
    AccountHead, AccountKind, ClaimPurpose, ClaimState, EnrollmentIdentity, ResourceBankDataError,
    codec, q04, settlement,
};
use aos_sandbox_core::RecordNamespace;

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

/// Validates the complete retained account, claim and association graph.
///
/// Unrelated namespaces are ignored. A bank with no rows returns `None`; retained
/// rows require one enrollment and the exact closed account roles and usage.
///
/// # Errors
///
/// Rejects malformed records or keys, differing enrollment, missing or cyclic
/// parents, incorrect inclusive usage, and inconsistent preparation, co-issuance,
/// terminal or input history. Retains canonical decoding and arithmetic causes.
pub fn validate(state: &State) -> Result<Option<EnrollmentIdentity>, ResourceBankDataError> {
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
                heads = heads
                    .checked_add(1)
                    .ok_or(ResourceBankDataError::CorruptLedger)?;
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
                let binding = q04::decode(
                    record_bytes(state, q04::PREFIX, terminal.original_id())
                        .ok_or(ResourceBankDataError::CorruptLedger)?,
                )?;
                require_enrollment(&mut enrollment, q04::original_claim(binding).enrollment)?;
            }
            _ => return Err(ResourceBankDataError::CorruptLedger),
        }
    }
    if enrollment.is_none() {
        return Ok(None);
    }
    if roots != 1 || controllers != 1 || components != 1 {
        return Err(ResourceBankDataError::CorruptLedger);
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
                .ok_or(ResourceBankDataError::CorruptLedger)?;
            match record_bytes(state, q04::PREFIX, binding.claim.id) {
                Some(bytes) => {
                    let transferred = q04::decode(bytes)?;
                    if q04::original_claim(transferred) != binding.claim {
                        return Err(ResourceBankDataError::CorruptLedger);
                    }
                    q04::require_replayed(state, transferred)?;
                }
                None if codec::decode_claim(claim)? == binding.claim => {}
                None => return Err(ResourceBankDataError::CorruptLedger),
            }
        } else if key_bytes[0] == q04::PREFIX {
            q04::require_replayed(state, q04::decode(bytes)?)?;
        } else if key_bytes[0] == settlement::PREFIX {
            let terminal = settlement::decode(bytes)?;
            let binding = q04::decode(
                record_bytes(state, q04::PREFIX, terminal.original_id())
                    .ok_or(ResourceBankDataError::CorruptLedger)?,
            )?;
            settlement::current_use(state, binding)?;
        } else {
            let claim = codec::decode_claim(bytes)?;
            let parent = find_head(state, claim.account)?;
            if claim.enrollment != parent.enrollment {
                return Err(ResourceBankDataError::CorruptLedger);
            }
            if claim.child != [0; 16] {
                let child = find_head(state, claim.child)?;
                if child.parent != parent.id
                    || child.enrollment != parent.enrollment
                    || claim.state != ClaimState::Reserved
                    || !allowed_edge(parent.kind, child.kind)
                    || finite_ceilings(child)? != claim.amount
                    || claim.project != child.project
                    || claim.sandbox != child.sandbox
                    || claim.tree_revision != child.tree_revision
                    || (matches!(parent.kind, AccountKind::Project | AccountKind::Sandbox)
                        && (parent.project != child.project
                            || parent.tree_revision != child.tree_revision))
                {
                    return Err(ResourceBankDataError::CorruptLedger);
                }
                let purpose_matches = match claim.purpose {
                    ClaimPurpose::ControllerBootstrap => child.kind == AccountKind::Controller,
                    ClaimPurpose::ComponentEnvelope => child.kind == AccountKind::Components,
                    ClaimPurpose::InclusiveGrant => matches!(
                        child.kind,
                        AccountKind::Project | AccountKind::Sandbox | AccountKind::Operation
                    ),
                    ClaimPurpose::HostComponentBootstrap => {
                        parent.kind == AccountKind::Components
                            && child.kind == AccountKind::Operation
                    }
                    ClaimPurpose::Snapshot
                    | ClaimPurpose::ProjectPreparation
                    | ClaimPurpose::Q04Preparation
                    | ClaimPurpose::HostControlInterval
                    | ClaimPurpose::ControllerFirstGlobalPrefix
                    | ClaimPurpose::NixOriginalStartIntake
                    | ClaimPurpose::Q04OriginalIntake
                    | ClaimPurpose::RootReceiving => false,
                };
                if !purpose_matches {
                    return Err(ResourceBankDataError::CorruptLedger);
                }
            } else if claim.project != parent.project
                || claim.sandbox != parent.sandbox
                || claim.tree_revision != parent.tree_revision
            {
                return Err(ResourceBankDataError::CorruptLedger);
            } else if claim.purpose == ClaimPurpose::ProjectPreparation
                && parent.kind != AccountKind::Project
            {
                return Err(ResourceBankDataError::CorruptLedger);
            }
            if claim.purpose == ClaimPurpose::ProjectPreparation {
                let binding = record_bytes(state, PREPARATION_PREFIX, claim.id)
                    .ok_or(ResourceBankDataError::CorruptLedger)?;
                let original = codec::decode_preparation(binding)?.claim;
                if original != claim && record_bytes(state, q04::PREFIX, claim.id).is_none() {
                    return Err(ResourceBankDataError::CorruptLedger);
                }
            }
            if claim.purpose == ClaimPurpose::Q04Preparation
                && (parent.kind != AccountKind::Sandbox
                    || !state.iter().any(|((namespace, key), bytes)| {
                        *namespace == RecordNamespace::ControllerResourceReservation
                            && key.first() == Some(&q04::PREFIX)
                            && q04::decode(bytes)
                                .is_ok_and(|binding| q04::contains_use(binding, claim))
                    }))
            {
                return Err(ResourceBankDataError::CorruptLedger);
            }
            if matches!(
                claim.purpose,
                ClaimPurpose::HostComponentBootstrap | ClaimPurpose::HostControlInterval
            ) {
                require_host_component(state, claim)?;
            }
            if claim.purpose == ClaimPurpose::ControllerFirstGlobalPrefix {
                require_first_global_prefix(state, parent, claim)?;
            }
            if claim.purpose == ClaimPurpose::NixOriginalStartIntake {
                let intake_id = super::bootstrap::account_id(
                    claim.enrollment,
                    b"controller-nix-original-start-intake-v1",
                );
                let expected = codec::decode_claim(
                    record_bytes(state, CLAIM_PREFIX, intake_id)
                        .ok_or(ResourceBankDataError::CorruptLedger)?,
                )?;
                if claim.id != intake_id
                    || claim != expected
                    || claim.account
                        != super::bootstrap::account_id(claim.enrollment, b"controller")
                    || parent.enrollment != claim.enrollment
                {
                    return Err(ResourceBankDataError::CorruptLedger);
                }
                let prefix_id = super::bootstrap::account_id(
                    claim.enrollment,
                    b"controller-first-global-prefix-v1",
                );
                let prefix = codec::decode_claim(
                    record_bytes(state, CLAIM_PREFIX, prefix_id)
                        .ok_or(ResourceBankDataError::CorruptLedger)?,
                )?;
                require_first_global_prefix(state, parent, prefix)?;
            }
            if claim.purpose == ClaimPurpose::Q04OriginalIntake {
                let expected_id = super::bootstrap::account_id(
                    claim.enrollment,
                    b"controller-q04-original-intake-v1",
                );
                if claim.id != expected_id
                    || claim.account
                        != super::bootstrap::account_id(claim.enrollment, b"controller")
                    || parent.enrollment != claim.enrollment
                {
                    return Err(ResourceBankDataError::CorruptLedger);
                }
                let prefix_id = super::bootstrap::account_id(
                    claim.enrollment,
                    b"controller-first-global-prefix-v1",
                );
                let prefix = codec::decode_claim(
                    record_bytes(state, CLAIM_PREFIX, prefix_id)
                        .ok_or(ResourceBankDataError::CorruptLedger)?,
                )?;
                require_first_global_prefix(state, parent, prefix)?;
            }
            if claim.purpose == ClaimPurpose::RootReceiving {
                let expected_id =
                    super::bootstrap::account_id(claim.enrollment, b"root-receiving-v1");
                if claim.id != expected_id
                    || claim.account
                        != super::bootstrap::account_id(claim.enrollment, b"components")
                    || parent.kind != AccountKind::Components
                    || parent.enrollment != claim.enrollment
                {
                    return Err(ResourceBankDataError::CorruptLedger);
                }
                super::require_root_service_envelope(claim.amount)?;
                // R is a distinct retained row in the same K account as H.
                // Complete replay sums both claims against K only once.
                let host_id = super::bootstrap::account_id(claim.enrollment, b"host-component-v2");
                let host_claim_id = super::bootstrap::account_id(claim.enrollment, &host_id);
                let host = codec::decode_claim(
                    record_bytes(state, CLAIM_PREFIX, host_claim_id)
                        .ok_or(ResourceBankDataError::CorruptLedger)?,
                )?;
                require_host_component(state, host)?;
                finite_ceilings(parent)?
                    .checked_sub(host.amount)?
                    .checked_sub(claim.amount)?;
                let q04_id = super::bootstrap::account_id(
                    claim.enrollment,
                    b"controller-q04-original-intake-v1",
                );
                let q04 = codec::decode_claim(
                    record_bytes(state, CLAIM_PREFIX, q04_id)
                        .ok_or(ResourceBankDataError::CorruptLedger)?,
                )?;
                if q04.purpose != ClaimPurpose::Q04OriginalIntake {
                    return Err(ResourceBankDataError::CorruptLedger);
                }
            }
        }
    }
    Ok(enrollment)
}

// The original image supplies the expected P in the entered opening check.
// Replay independently enforces the closed native identity and accounting;
// a correctly decoded row alone is never a receiving or spending constructor.
fn require_first_global_prefix(
    state: &State,
    controller: AccountHead,
    claim: super::Claim,
) -> Result<(), ResourceBankDataError> {
    let identity = claim.enrollment;
    let controller_id = super::bootstrap::account_id(identity, b"controller");
    let claim_id = super::bootstrap::account_id(identity, b"controller-first-global-prefix-v1");
    let ceiling = finite_ceilings(controller)?;
    let intake_id =
        super::bootstrap::account_id(identity, b"controller-nix-original-start-intake-v1");
    if let Some(bytes) = record_bytes(state, CLAIM_PREFIX, intake_id) {
        let intake = codec::decode_claim(bytes)?;
        let q04_id = super::bootstrap::account_id(identity, b"controller-q04-original-intake-v1");
        let q04 = record_bytes(state, CLAIM_PREFIX, q04_id)
            .map(codec::decode_claim)
            .transpose()?;
        if let Some(part) = q04 {
            if part.purpose != ClaimPurpose::Q04OriginalIntake
                || part.enrollment != identity
                || part.id != q04_id
                || part.account != controller_id
            {
                return Err(ResourceBankDataError::CorruptLedger);
            }
        }
        let retained = ceiling
            .checked_sub(claim.amount)?
            .checked_sub(intake.amount)?
            .checked_sub(q04.map_or(ResourceVector::ZERO, |part| part.amount))?;
        let mut committed = retained;
        let mut reserved = ResourceVector::ZERO;
        let mut generation = 1;
        for part in [Some(claim), Some(intake), q04].into_iter().flatten() {
            match part.state {
                ClaimState::Reserved => reserved = reserved.checked_add(part.amount)?,
                ClaimState::Committed => {
                    committed = committed.checked_add(part.amount)?;
                    generation += 1;
                }
                ClaimState::Released => return Err(ResourceBankDataError::CorruptLedger),
            }
        }
        let expected = ResourceAccount::from_usage(
            aos_sandbox_core::ResourceCeilings::bounded(ceiling),
            committed,
            reserved,
        )?;
        if claim.purpose != ClaimPurpose::ControllerFirstGlobalPrefix
            || intake.purpose != ClaimPurpose::NixOriginalStartIntake
            || intake.enrollment != identity
            || intake.id != intake_id
            || intake.account != controller_id
            || controller.kind != AccountKind::Controller
            || controller.id != controller_id
            || claim.account != controller_id
            || claim.id != claim_id
            || controller.baseline != retained
            || controller.account != expected
            || controller.generation != generation
        {
            return Err(ResourceBankDataError::CorruptLedger);
        }
        return Ok(());
    }
    let q04_id = super::bootstrap::account_id(identity, b"controller-q04-original-intake-v1");
    if record_bytes(state, CLAIM_PREFIX, q04_id).is_some() {
        return Err(ResourceBankDataError::CorruptLedger);
    }
    let retained = ceiling.checked_sub(claim.amount)?;
    let expected = match claim.state {
        ClaimState::Reserved => ResourceAccount::from_usage(
            aos_sandbox_core::ResourceCeilings::bounded(ceiling),
            retained,
            claim.amount,
        )?,
        ClaimState::Committed => ResourceAccount::from_usage(
            aos_sandbox_core::ResourceCeilings::bounded(ceiling),
            ceiling,
            ResourceVector::ZERO,
        )?,
        ClaimState::Released => return Err(ResourceBankDataError::CorruptLedger),
    };
    if controller.kind != AccountKind::Controller
        || controller.id != controller_id
        || claim.account != controller_id
        || claim.id != claim_id
        || controller.baseline != retained
        || controller.account != expected
        || controller.generation
            != if claim.state == ClaimState::Reserved {
                1
            } else {
                2
            }
    {
        return Err(ResourceBankDataError::CorruptLedger);
    }
    Ok(())
}

// The Host record is a single Components subdivision with a reserved control
// interval. Neither claim can be interpreted as a Global or Sandbox grant.
fn require_host_component(state: &State, claim: super::Claim) -> Result<(), ResourceBankDataError> {
    let identity = claim.enrollment;
    let host_id = super::bootstrap::account_id(identity, b"host-component-v2");
    let components_id = super::bootstrap::account_id(identity, b"components");
    let component_claim_id = super::bootstrap::account_id(identity, &host_id);
    let control_claim_id = super::bootstrap::account_id(identity, b"host-control-v2");
    let host = find_head(state, host_id)?;
    let components = find_head(state, components_id)?;
    let component = codec::decode_claim(
        record_bytes(state, CLAIM_PREFIX, component_claim_id)
            .ok_or(ResourceBankDataError::CorruptLedger)?,
    )?;
    let control = codec::decode_claim(
        record_bytes(state, CLAIM_PREFIX, control_claim_id)
            .ok_or(ResourceBankDataError::CorruptLedger)?,
    )?;
    if host.kind != AccountKind::Operation
        || host.parent != components_id
        || host.generation != 1
        || host.enrollment != identity
        || host.project != [0; 16]
        || host.sandbox != [0; 16]
        || host.tree_revision != [0; 32]
        || host.account.committed() != host.baseline
        || components.kind != AccountKind::Components
        || components.enrollment != identity
        || component.purpose != ClaimPurpose::HostComponentBootstrap
        || component.id != component_claim_id
        || component.account != components_id
        || component.child != host_id
        || component.amount != finite_ceilings(host)?
        || control.purpose != ClaimPurpose::HostControlInterval
        || control.id != control_claim_id
        || control.account != host_id
        || control.child != [0; 16]
        || control.amount != host.account.reserved()
        || component.enrollment != identity
        || control.enrollment != identity
        || (claim != component && claim != control)
    {
        return Err(ResourceBankDataError::CorruptLedger);
    }
    Ok(())
}

fn validate_head(
    state: &State,
    head: AccountHead,
    maximum_depth: usize,
) -> Result<(), ResourceBankDataError> {
    let mut reserved = ResourceVector::ZERO;
    let mut committed = head.baseline;
    let mut incoming = 0_usize;

    for ((namespace, key_bytes), bytes) in state {
        if *namespace != RecordNamespace::ControllerResourceReservation
            || key_bytes[0] != CLAIM_PREFIX
        {
            continue;
        }
        let claim = codec::decode_claim(bytes)?;
        if claim.child == head.id {
            incoming = incoming
                .checked_add(1)
                .ok_or(ResourceBankDataError::CorruptLedger)?;
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
    if reserved != head.account.reserved()
        || committed != head.account.committed()
        || incoming != usize::from(head.kind != AccountKind::Node)
    {
        return Err(ResourceBankDataError::CorruptLedger);
    }

    // A bounded parent walk detects cycles without allocating a visited set.
    let mut current = head;
    for _ in 0..maximum_depth {
        if current.kind == AccountKind::Node {
            return Ok(());
        }
        let parent = find_head(state, current.parent)?;
        if !allowed_edge(parent.kind, current.kind) || parent.enrollment != head.enrollment {
            return Err(ResourceBankDataError::CorruptLedger);
        }
        current = parent;
    }
    Err(ResourceBankDataError::CorruptLedger)
}

// This lookup recognizes historical initial payment only. The caller must
// still hold and recheck the current Controller, Source and Completed Root.
/// Selects the exact retained initial Project payment by its complete joins.
///
/// This historical comparison does not retain or recheck a current Controller,
/// Source or Completed Root owner.
///
/// # Errors
///
/// Rejects an invalid expected Project shape or a malformed, ambiguous or
/// inconsistent retained initial-payment association.
pub fn prior_initial_project_grant(
    state: &State,
    expected: AccountHead,
    acceptance: [u8; 32],
    instance: [u8; 32],
) -> Result<Option<super::Claim>, ResourceBankDataError> {
    if expected.kind != AccountKind::Project
        || expected.generation != 1
        || expected.sandbox != [0; 16]
        || expected.baseline != ResourceVector::ZERO
    {
        return Err(ResourceBankDataError::Conflict);
    }
    let mut prior = None;
    for ((namespace, key), bytes) in state {
        if *namespace != RecordNamespace::ControllerResourceReservation
            || key.first() != Some(&CLAIM_PREFIX)
        {
            continue;
        }
        let claim = codec::decode_claim(bytes)?;
        if claim.child != expected.id {
            continue;
        }
        let child = find_head(state, expected.id)?;
        if prior.is_some()
            || claim.enrollment != expected.enrollment
            || claim.account != expected.parent
            || claim.owner != acceptance
            || claim.purpose != ClaimPurpose::InclusiveGrant
            || claim.project != expected.project
            || claim.sandbox != expected.sandbox
            || claim.tree_revision != expected.tree_revision
            || claim.genesis_instance != instance
            || claim.amount != finite_ceilings(expected)?
            || claim.state != ClaimState::Reserved
            || !matches!(claim.cut, super::ClaimCut::Operation { .. })
            || child.enrollment != expected.enrollment
            || child.id != expected.id
            || child.parent != expected.parent
            || child.kind != expected.kind
            || child.project != expected.project
            || child.sandbox != expected.sandbox
            || child.tree_revision != expected.tree_revision
            || child.baseline != expected.baseline
            || finite_ceilings(child)? != finite_ceilings(expected)?
        {
            return Err(ResourceBankDataError::Conflict);
        }
        // Its original paid clock/cut remains untouched. A new live Root cut
        // authenticates this rejoin, not a second payment or renewed old loan.
        prior = Some(claim);
    }
    if prior.is_none() && has_head(state, expected.id) {
        return Err(ResourceBankDataError::Conflict);
    }
    Ok(prior)
}

/// Decodes the exact historical account head selected by its identity.
///
/// # Errors
///
/// Rejects an absent or malformed retained account head.
pub fn find_head(state: &State, id: [u8; 16]) -> Result<AccountHead, ResourceBankDataError> {
    let bytes = record_bytes(state, HEAD_PREFIX, id).ok_or(ResourceBankDataError::CorruptLedger)?;
    let head = codec::decode_head(bytes)?;
    if head.id != id {
        return Err(ResourceBankDataError::CorruptLedger);
    }
    Ok(head)
}

/// Reports whether the exact historical account-head key is present.
pub fn has_head(state: &State, id: [u8; 16]) -> bool {
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

pub(super) fn finite_ceilings(head: AccountHead) -> Result<ResourceVector, ResourceBankDataError> {
    let mut values = [0; ResourceDimension::COUNT];
    for (index, dimension) in ResourceDimension::ALL.into_iter().enumerate() {
        let ResourceLimit::Bounded(value) = head.account.ceilings().get(dimension) else {
            return Err(ResourceBankDataError::CorruptLedger);
        };
        values[index] = value;
    }
    Ok(ResourceVector::new(values))
}

pub(super) fn allowed_edge(parent: AccountKind, child: AccountKind) -> bool {
    matches!(
        (parent, child),
        (
            AccountKind::Node,
            AccountKind::Controller | AccountKind::Components | AccountKind::Project
        ) | (AccountKind::Project, AccountKind::Sandbox)
            | (
                AccountKind::Sandbox,
                AccountKind::Sandbox | AccountKind::Operation
            )
            | (
                AccountKind::Controller | AccountKind::Components,
                AccountKind::Operation
            )
    )
}

fn require_key(bytes: &[u8], prefix: u8, id: [u8; 16]) -> Result<(), ResourceBankDataError> {
    if bytes != key(prefix, id) {
        return Err(ResourceBankDataError::CorruptLedger);
    }
    Ok(())
}

fn require_enrollment(
    current: &mut Option<EnrollmentIdentity>,
    value: EnrollmentIdentity,
) -> Result<(), ResourceBankDataError> {
    match current {
        Some(expected) if *expected != value => Err(ResourceBankDataError::CorruptLedger),
        Some(_) => Ok(()),
        None => {
            *current = Some(value);
            Ok(())
        }
    }
}
