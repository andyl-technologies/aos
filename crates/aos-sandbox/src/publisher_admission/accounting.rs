//! Checked reservation and residency accounting for publication operations.
//!
//! Reservation, residency, and pins are intentionally distinct. A completion
//! converts reserved bytes into resident bytes; it never releases occupied
//! capacity. Ambiguous effects remain charged at their full reservation until
//! authority-bound recovery proves a terminal outcome.

use std::collections::BTreeMap;

use aos_sandbox_core::{
    ObjectDigest, ProjectId, PublicationReservationId, ResourceId,
    model::{CacheDomain, CacheDomainKind},
};

use super::model::{PublicationAuthorityEpoch, digest_parts, validate_nonzero};

/// Configures one immutable cache-domain capacity envelope.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CapacityPolicyV1 {
    /// Logical cache resource.
    pub resource: ResourceId,
    /// Owning project.
    pub project: ProjectId,
    /// Exact disclosure domain.
    pub domain: CacheDomain,
    /// Physical isolation-policy commitment.
    pub isolation_policy: ObjectDigest,
    /// Hard physical byte ceiling.
    pub maximum_bytes: u64,
    /// Hard resident-object ceiling.
    pub maximum_objects: u64,
    /// Bytes retained for recovery and already-issued completion obligations.
    pub recovery_reserve_bytes: u64,
}

impl CapacityPolicyV1 {
    /// Validates a nonempty, fail-closed capacity envelope.
    ///
    /// # Errors
    ///
    /// Returns [`AccountingError::InvalidPolicy`] for sentinel identities, a
    /// zero ceiling, or recovery reserve larger than the byte ceiling.
    pub fn validate(self) -> Result<Self, AccountingError> {
        validate_nonzero(&[
            ("capacity resource", self.resource.as_bytes()),
            ("capacity project", self.project.as_bytes()),
            ("capacity domain", self.domain.domain_id().as_bytes()),
            ("isolation policy", self.isolation_policy.as_bytes()),
        ])
        .map_err(|_| AccountingError::InvalidPolicy)?;
        if self.maximum_bytes == 0
            || self.maximum_objects == 0
            || self.recovery_reserve_bytes > self.maximum_bytes
            || self.domain.kind() != CacheDomainKind::Project
        {
            return Err(AccountingError::InvalidPolicy);
        }
        Ok(self)
    }
}

/// States how one reservation contributes to capacity.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ReservationStateV1 {
    /// Worst-case bytes are promised before allocation.
    Reserved,
    /// A physical outcome is uncertain; the full promise remains charged.
    Uncertain,
    /// Exact used bytes became committed reusable residency.
    Resident,
    /// Recovery proved a pre-effect or absent outcome and released the promise.
    Released,
    /// A committed catalog entry and its residency were durably evicted.
    Evicted,
}

/// Retains exact accounting for one publication reservation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CapacityAccountV1 {
    /// Reservation identity.
    pub reservation: PublicationReservationId,
    /// Controller authority epoch that created it.
    pub authority_epoch: PublicationAuthorityEpoch,
    /// Logical cache resource.
    pub resource: ResourceId,
    /// Owning project.
    pub project: ProjectId,
    /// Exact disclosure domain.
    pub domain: CacheDomain,
    /// Worst-case bytes promised before work.
    pub reserved_bytes: u64,
    /// Exact resident bytes after completion, otherwise zero.
    pub resident_bytes: u64,
    /// Closed accounting state.
    pub state: ReservationStateV1,
    /// Monotone successor generation.
    pub generation: u64,
    /// Digest of the predecessor account, absent only at generation one.
    pub predecessor_digest: Option<ObjectDigest>,
    /// Digest of this complete account.
    pub digest: ObjectDigest,
}

impl CapacityAccountV1 {
    fn initial(
        policy: CapacityPolicyV1,
        reservation: PublicationReservationId,
        authority_epoch: PublicationAuthorityEpoch,
        bytes: u64,
    ) -> Result<Self, AccountingError> {
        if reservation.as_bytes() == &[0; 16] {
            return Err(AccountingError::InvalidReservation);
        }
        let mut account = Self {
            reservation,
            authority_epoch,
            resource: policy.resource,
            project: policy.project,
            domain: policy.domain,
            reserved_bytes: bytes,
            resident_bytes: 0,
            state: ReservationStateV1::Reserved,
            generation: 1,
            predecessor_digest: None,
            digest: ObjectDigest::from_bytes([0; 32]),
        };
        account.digest = account_digest(&account);
        Ok(account)
    }

    fn successor(
        &self,
        state: ReservationStateV1,
        resident_bytes: u64,
    ) -> Result<Self, AccountingError> {
        let generation = self
            .generation
            .checked_add(1)
            .ok_or(AccountingError::GenerationExhausted)?;
        let mut next = Self {
            reservation: self.reservation,
            authority_epoch: self.authority_epoch,
            resource: self.resource,
            project: self.project,
            domain: self.domain,
            reserved_bytes: self.reserved_bytes,
            resident_bytes,
            state,
            generation,
            predecessor_digest: Some(self.digest),
            digest: ObjectDigest::from_bytes([0; 32]),
        };
        next.digest = account_digest(&next);
        Ok(next)
    }
}

/// Reports fail-closed accounting failures.
#[derive(Clone, Debug, Eq, PartialEq, thiserror::Error)]
pub enum AccountingError {
    /// Capacity configuration is malformed.
    #[error("invalid publication capacity policy")]
    InvalidPolicy,
    /// Reservation identity or byte request is invalid.
    #[error("invalid publication reservation")]
    InvalidReservation,
    /// A reservation identity was reused with different facts.
    #[error("publication reservation conflicts with retained facts")]
    ReservationConflict,
    /// No retained reservation has this identity.
    #[error("publication reservation is absent")]
    ReservationAbsent,
    /// Reservation is not in the required source state.
    #[error("publication reservation transition is invalid")]
    InvalidTransition,
    /// Checked accounting exceeds the configured hard limit.
    #[error("publication capacity is exhausted")]
    CapacityExhausted,
    /// Checked arithmetic or a successor generation overflowed.
    #[error("publication accounting generation is exhausted")]
    GenerationExhausted,
    /// Replayed aggregate totals disagree with retained accounts.
    #[error("publication accounting replay is inconsistent")]
    CorruptState,
}

/// Materializes checked aggregate accounting for one physical cache partition.
#[derive(Clone, Debug)]
pub struct PublicationAccounting {
    policy: CapacityPolicyV1,
    accounts: BTreeMap<[u8; 16], CapacityAccountV1>,
    charged_bytes: u64,
    charged_objects: u64,
    resident_bytes: u64,
    resident_objects: u64,
}

impl PublicationAccounting {
    /// Replays complete accounts and recomputes all aggregate totals.
    ///
    /// # Errors
    ///
    /// Returns [`AccountingError`] for invalid policy, duplicate/conflicting
    /// identities, broken successor invariants, overflow, or ceiling excess.
    pub fn replay(
        policy: CapacityPolicyV1,
        accounts: impl IntoIterator<Item = CapacityAccountV1>,
    ) -> Result<Self, AccountingError> {
        let policy = policy.validate()?;
        let mut state = Self {
            policy,
            accounts: BTreeMap::new(),
            charged_bytes: 0,
            charged_objects: 0,
            resident_bytes: 0,
            resident_objects: 0,
        };
        for account in accounts {
            state.validate_account(&account)?;
            let key = *account.reservation.as_bytes();
            if let Some(previous) = state.accounts.get(&key) {
                validate_replayed_account_successor(previous, &account)?;
            } else if account.generation != 1 {
                return Err(AccountingError::CorruptState);
            }
            state.accounts.insert(key, account);
        }
        state.recompute()?;
        Ok(state)
    }

    /// Restores checked account heads from a verified floor and exact suffix.
    ///
    /// The floor checkpoint and equivocation index authenticate discarded
    /// predecessors. The first retained head may therefore have any nonzero
    /// generation; later suffix records must form its exact contiguous chain.
    /// Final heads are included in recomputed aggregate capacity.
    pub(super) fn replay_compacted(
        policy: CapacityPolicyV1,
        accounts: impl IntoIterator<Item = CapacityAccountV1>,
    ) -> Result<Self, AccountingError> {
        let policy = policy.validate()?;
        let mut state = Self {
            policy,
            accounts: BTreeMap::new(),
            charged_bytes: 0,
            charged_objects: 0,
            resident_bytes: 0,
            resident_objects: 0,
        };
        for account in accounts {
            state.validate_account(&account)?;
            let key = *account.reservation.as_bytes();
            if let Some(previous) = state.accounts.get(&key) {
                validate_replayed_account_successor(previous, &account)?;
            }
            state.accounts.insert(key, account);
        }
        state.recompute()?;
        Ok(state)
    }

    /// Reserves worst-case bytes before any allocation or fetch.
    ///
    /// Exact replay returns the original account and never charges twice.
    ///
    /// # Errors
    ///
    /// Returns [`AccountingError`] for conflicting identity reuse, malformed
    /// facts, overflow, or insufficient non-recovery capacity.
    pub fn reserve(
        &mut self,
        reservation: PublicationReservationId,
        authority_epoch: PublicationAuthorityEpoch,
        bytes: u64,
    ) -> Result<CapacityAccountV1, AccountingError> {
        if let Some(existing) = self.accounts.get(reservation.as_bytes()) {
            if existing.authority_epoch == authority_epoch
                && existing.reserved_bytes == bytes
                && existing.resource == self.policy.resource
                && existing.project == self.policy.project
                && existing.domain == self.policy.domain
            {
                return Ok(existing.clone());
            }
            return Err(AccountingError::ReservationConflict);
        }
        let account = CapacityAccountV1::initial(self.policy, reservation, authority_epoch, bytes)?;
        let ordinary_ceiling = self
            .policy
            .maximum_bytes
            .checked_sub(self.policy.recovery_reserve_bytes)
            .ok_or(AccountingError::CorruptState)?;
        let next = self
            .charged_bytes
            .checked_add(bytes)
            .ok_or(AccountingError::CapacityExhausted)?;
        if next > ordinary_ceiling {
            return Err(AccountingError::CapacityExhausted);
        }
        let next_objects = self
            .charged_objects
            .checked_add(1)
            .ok_or(AccountingError::CapacityExhausted)?;
        if next_objects > self.policy.maximum_objects {
            return Err(AccountingError::CapacityExhausted);
        }
        self.charged_bytes = next;
        self.charged_objects = next_objects;
        self.accounts
            .insert(*reservation.as_bytes(), account.clone());
        Ok(account)
    }

    /// Retains the full charge after an indeterminate physical or durable effect.
    ///
    /// # Errors
    ///
    /// Returns [`AccountingError`] when the reservation is absent or terminal.
    pub fn mark_uncertain(
        &mut self,
        reservation: PublicationReservationId,
    ) -> Result<CapacityAccountV1, AccountingError> {
        self.transition(reservation, ReservationStateV1::Uncertain, 0)
    }

    /// Converts one reservation into exact committed residency.
    ///
    /// Unused promised bytes are released, while physical resident bytes remain
    /// charged. Exact replay returns the retained resident account.
    ///
    /// # Errors
    ///
    /// Returns [`AccountingError`] for absence, a terminal/incompatible state,
    /// excessive resident bytes, object-ceiling exhaustion, or overflow.
    pub fn commit_residency(
        &mut self,
        reservation: PublicationReservationId,
        resident_bytes: u64,
    ) -> Result<CapacityAccountV1, AccountingError> {
        let current = self
            .accounts
            .get(reservation.as_bytes())
            .ok_or(AccountingError::ReservationAbsent)?;
        if current.state == ReservationStateV1::Resident {
            return if current.resident_bytes == resident_bytes {
                Ok(current.clone())
            } else {
                Err(AccountingError::ReservationConflict)
            };
        }
        if !matches!(
            current.state,
            ReservationStateV1::Reserved | ReservationStateV1::Uncertain
        ) || resident_bytes > current.reserved_bytes
        {
            return Err(AccountingError::InvalidTransition);
        }
        let next = current.successor(ReservationStateV1::Resident, resident_bytes)?;
        self.accounts.insert(*reservation.as_bytes(), next.clone());
        self.recompute()?;
        Ok(next)
    }

    /// Releases a reservation only after recovery proves no effect can remain.
    ///
    /// # Errors
    ///
    /// Returns [`AccountingError`] for absence, committed residency, or another
    /// terminal/incompatible state.
    pub fn release_without_effect(
        &mut self,
        reservation: PublicationReservationId,
    ) -> Result<CapacityAccountV1, AccountingError> {
        self.transition(reservation, ReservationStateV1::Released, 0)
    }

    /// Releases committed residency after durable unpinned catalog eviction.
    ///
    /// # Errors
    ///
    /// Returns [`AccountingError`] unless the reservation is currently resident.
    pub fn evict_residency(
        &mut self,
        reservation: PublicationReservationId,
    ) -> Result<CapacityAccountV1, AccountingError> {
        let current = self
            .accounts
            .get(reservation.as_bytes())
            .ok_or(AccountingError::ReservationAbsent)?;
        if current.state == ReservationStateV1::Evicted {
            return Ok(current.clone());
        }
        if current.state != ReservationStateV1::Resident {
            return Err(AccountingError::InvalidTransition);
        }
        let next = current.successor(ReservationStateV1::Evicted, 0)?;
        self.accounts.insert(*reservation.as_bytes(), next.clone());
        self.recompute()?;
        Ok(next)
    }

    /// Returns currently charged bytes, including uncertain reservations.
    #[must_use]
    pub const fn charged_bytes(&self) -> u64 {
        self.charged_bytes
    }

    /// Returns charged object slots, including uncertain reservations.
    #[must_use]
    pub const fn charged_objects(&self) -> u64 {
        self.charged_objects
    }

    /// Returns exact committed resident bytes.
    #[must_use]
    pub const fn resident_bytes(&self) -> u64 {
        self.resident_bytes
    }

    /// Resolves one retained account.
    #[must_use]
    pub fn account(&self, reservation: PublicationReservationId) -> Option<&CapacityAccountV1> {
        self.accounts.get(reservation.as_bytes())
    }

    pub(super) fn accounts(&self) -> impl Iterator<Item = &CapacityAccountV1> {
        self.accounts.values()
    }

    pub(super) const fn policy(&self) -> CapacityPolicyV1 {
        self.policy
    }

    fn transition(
        &mut self,
        reservation: PublicationReservationId,
        state: ReservationStateV1,
        resident_bytes: u64,
    ) -> Result<CapacityAccountV1, AccountingError> {
        let current = self
            .accounts
            .get(reservation.as_bytes())
            .ok_or(AccountingError::ReservationAbsent)?;
        if current.state == state && current.resident_bytes == resident_bytes {
            return Ok(current.clone());
        }
        let allowed = matches!(
            (current.state, state),
            (ReservationStateV1::Reserved, ReservationStateV1::Uncertain)
                | (ReservationStateV1::Reserved, ReservationStateV1::Released)
                | (ReservationStateV1::Uncertain, ReservationStateV1::Released)
        );
        if !allowed {
            return Err(AccountingError::InvalidTransition);
        }
        let next = current.successor(state, resident_bytes)?;
        self.accounts.insert(*reservation.as_bytes(), next.clone());
        self.recompute()?;
        Ok(next)
    }

    fn validate_account(&self, account: &CapacityAccountV1) -> Result<(), AccountingError> {
        if account.reservation.as_bytes() == &[0; 16]
            || account.authority_epoch.get() == 0
            || account.resource != self.policy.resource
            || account.project != self.policy.project
            || account.domain != self.policy.domain
            || account.resident_bytes > account.reserved_bytes
            || account.generation == 0
            || (account.generation == 1) != account.predecessor_digest.is_none()
            || account.digest != account_digest(account)
            || (account.state != ReservationStateV1::Resident && account.resident_bytes != 0)
        {
            return Err(AccountingError::CorruptState);
        }
        Ok(())
    }

    fn recompute(&mut self) -> Result<(), AccountingError> {
        let mut charged = 0_u64;
        let mut charged_objects = 0_u64;
        let mut resident = 0_u64;
        let mut objects = 0_u64;
        for account in self.accounts.values() {
            self.validate_account(account)?;
            match account.state {
                ReservationStateV1::Reserved | ReservationStateV1::Uncertain => {
                    charged = charged
                        .checked_add(account.reserved_bytes)
                        .ok_or(AccountingError::CorruptState)?;
                    charged_objects = charged_objects
                        .checked_add(1)
                        .ok_or(AccountingError::CorruptState)?;
                }
                ReservationStateV1::Resident => {
                    charged = charged
                        .checked_add(account.resident_bytes)
                        .ok_or(AccountingError::CorruptState)?;
                    resident = resident
                        .checked_add(account.resident_bytes)
                        .ok_or(AccountingError::CorruptState)?;
                    objects = objects
                        .checked_add(1)
                        .ok_or(AccountingError::CorruptState)?;
                    charged_objects = charged_objects
                        .checked_add(1)
                        .ok_or(AccountingError::CorruptState)?;
                }
                ReservationStateV1::Released | ReservationStateV1::Evicted => {}
            }
        }
        if charged > self.policy.maximum_bytes || charged_objects > self.policy.maximum_objects {
            return Err(AccountingError::CorruptState);
        }
        self.charged_bytes = charged;
        self.charged_objects = charged_objects;
        self.resident_bytes = resident;
        self.resident_objects = objects;
        Ok(())
    }
}

// Both replay forms retain the same successor semantics. Their distinct
// first-head requirements stay in the caller's replay loop.
fn validate_replayed_account_successor(
    previous: &CapacityAccountV1,
    account: &CapacityAccountV1,
) -> Result<(), AccountingError> {
    let next_generation = previous
        .generation
        .checked_add(1)
        .ok_or(AccountingError::GenerationExhausted)?;
    let valid_transition = matches!(
        (previous.state, account.state),
        (ReservationStateV1::Reserved, ReservationStateV1::Uncertain)
            | (ReservationStateV1::Reserved, ReservationStateV1::Resident)
            | (ReservationStateV1::Reserved, ReservationStateV1::Released)
            | (ReservationStateV1::Uncertain, ReservationStateV1::Resident)
            | (ReservationStateV1::Uncertain, ReservationStateV1::Released)
            | (ReservationStateV1::Resident, ReservationStateV1::Evicted)
    );
    if account.generation != next_generation
        || account.predecessor_digest != Some(previous.digest)
        || account.authority_epoch != previous.authority_epoch
        || account.resource != previous.resource
        || account.project != previous.project
        || account.domain != previous.domain
        || account.reserved_bytes != previous.reserved_bytes
        || !valid_transition
    {
        return Err(AccountingError::CorruptState);
    }
    Ok(())
}

fn account_digest(account: &CapacityAccountV1) -> ObjectDigest {
    let state = match account.state {
        ReservationStateV1::Reserved => 1,
        ReservationStateV1::Uncertain => 2,
        ReservationStateV1::Resident => 3,
        ReservationStateV1::Released => 4,
        ReservationStateV1::Evicted => 5,
    };
    let predecessor = account
        .predecessor_digest
        .map_or([0; 32], |digest| *digest.as_bytes());
    digest_parts(
        b"aos.sandbox.publisher.account.v1\0",
        &[
            account.reservation.as_bytes(),
            &account.authority_epoch.get().to_be_bytes(),
            account.resource.as_bytes(),
            account.project.as_bytes(),
            &[domain_code(account.domain)],
            account.domain.domain_id().as_bytes(),
            &account.reserved_bytes.to_be_bytes(),
            &account.resident_bytes.to_be_bytes(),
            &[state],
            &account.generation.to_be_bytes(),
            &predecessor,
        ],
    )
}

pub(super) fn domain_code(domain: CacheDomain) -> u8 {
    use aos_sandbox_core::model::CacheDomainKind;

    match domain.kind() {
        CacheDomainKind::Private => 1,
        CacheDomainKind::Project => 2,
        CacheDomainKind::TrustDomain => 3,
        CacheDomainKind::Public => 4,
    }
}

#[cfg(test)]
mod tests {
    use aos_sandbox_core::CacheDomainId;

    use super::*;

    fn policy() -> CapacityPolicyV1 {
        CapacityPolicyV1 {
            resource: ResourceId::from_bytes([1; 16]),
            project: ProjectId::from_bytes([2; 16]),
            domain: CacheDomain::new(CacheDomainKind::Project, CacheDomainId::from_bytes([3; 16])),
            isolation_policy: ObjectDigest::from_bytes([4; 32]),
            maximum_bytes: 1000,
            maximum_objects: 8,
            recovery_reserve_bytes: 16,
        }
    }

    fn initial_account(state: ReservationStateV1) -> CapacityAccountV1 {
        let mut account = CapacityAccountV1::initial(
            policy(),
            PublicationReservationId::from_bytes([5; 16]),
            PublicationAuthorityEpoch::new(1).unwrap(),
            16,
        )
        .unwrap();
        account.state = state;
        account.resident_bytes = if state == ReservationStateV1::Resident {
            8
        } else {
            0
        };
        account.digest = account_digest(&account);
        account
    }

    #[test]
    fn both_replay_forms_preserve_all_closed_successor_edges_and_account_totals() {
        use ReservationStateV1::{Evicted, Released, Reserved, Resident, Uncertain};

        let states = [Reserved, Uncertain, Resident, Released, Evicted];
        let allowed = [
            (Reserved, Uncertain),
            (Reserved, Resident),
            (Reserved, Released),
            (Uncertain, Resident),
            (Uncertain, Released),
            (Resident, Evicted),
        ];
        for previous_state in states {
            for next_state in states {
                let previous = initial_account(previous_state);
                let resident_bytes = if next_state == Resident { 8 } else { 0 };
                let next = previous.successor(next_state, resident_bytes).unwrap();
                let results = [
                    PublicationAccounting::replay(policy(), [previous.clone(), next.clone()]),
                    PublicationAccounting::replay_compacted(policy(), [previous, next.clone()]),
                ];

                for result in results {
                    if allowed.contains(&(previous_state, next_state)) {
                        let replay = result.unwrap();
                        assert_eq!(replay.account(next.reservation), Some(&next));
                        let charged = match next_state {
                            Reserved | Uncertain => 16,
                            Resident => 8,
                            Released | Evicted => 0,
                        };
                        assert_eq!(replay.charged_bytes(), charged);
                        assert_eq!(replay.charged_objects(), u64::from(charged != 0));
                        assert_eq!(replay.resident_bytes(), resident_bytes);
                        assert_eq!(replay.resident_objects, u64::from(next_state == Resident));
                    } else {
                        assert_eq!(result.unwrap_err(), AccountingError::CorruptState);
                    }
                }
            }
        }
    }

    #[test]
    fn both_replay_forms_reject_canonical_successor_binding_changes() {
        let previous = initial_account(ReservationStateV1::Reserved);
        for field in [
            "generation",
            "predecessor",
            "epoch",
            "resource",
            "project",
            "domain",
            "bytes",
        ] {
            let mut next = previous
                .successor(ReservationStateV1::Uncertain, 0)
                .unwrap();
            match field {
                "generation" => next.generation = 3,
                "predecessor" => next.predecessor_digest = Some(ObjectDigest::from_bytes([6; 32])),
                "epoch" => next.authority_epoch = PublicationAuthorityEpoch::new(2).unwrap(),
                "resource" => next.resource = ResourceId::from_bytes([6; 16]),
                "project" => next.project = ProjectId::from_bytes([6; 16]),
                "domain" => {
                    next.domain = CacheDomain::new(
                        CacheDomainKind::Project,
                        CacheDomainId::from_bytes([6; 16]),
                    )
                }
                "bytes" => next.reserved_bytes = 17,
                _ => unreachable!(),
            }
            next.digest = account_digest(&next);
            let results = [
                PublicationAccounting::replay(policy(), [previous.clone(), next.clone()]),
                PublicationAccounting::replay_compacted(policy(), [previous.clone(), next]),
            ];

            for result in results {
                assert_eq!(
                    result.unwrap_err(),
                    AccountingError::CorruptState,
                    "{field}"
                );
            }
        }
    }

    #[test]
    fn first_head_rules_and_compacted_overflow_frontier_remain_distinct() {
        let initial = initial_account(ReservationStateV1::Reserved);
        let retained = initial.successor(ReservationStateV1::Uncertain, 0).unwrap();
        assert_eq!(
            PublicationAccounting::replay(policy(), [retained.clone()]).unwrap_err(),
            AccountingError::CorruptState,
        );
        let compacted =
            PublicationAccounting::replay_compacted(policy(), [retained.clone()]).unwrap();
        assert_eq!(compacted.account(retained.reservation), Some(&retained));

        let mut previous = initial;
        previous.generation = u64::MAX;
        previous.predecessor_digest = Some(ObjectDigest::from_bytes([7; 32]));
        previous.digest = account_digest(&previous);
        let mut next = previous.clone();
        next.state = ReservationStateV1::Uncertain;
        next.authority_epoch = PublicationAuthorityEpoch::new(2).unwrap();
        next.predecessor_digest = Some(previous.digest);
        next.digest = account_digest(&next);

        // Both records pass the same account validation that precedes the
        // successor check in each real replay loop.
        compacted.validate_account(&previous).unwrap();
        compacted.validate_account(&next).unwrap();
        assert_eq!(
            PublicationAccounting::replay_compacted(policy(), [previous.clone(), next.clone()])
                .unwrap_err(),
            AccountingError::GenerationExhausted,
        );
        assert_eq!(
            PublicationAccounting::replay(policy(), [previous.clone(), next.clone()]).unwrap_err(),
            AccountingError::CorruptState,
        );

        next.resource = ResourceId::from_bytes([6; 16]);
        next.digest = account_digest(&next);
        assert_eq!(
            PublicationAccounting::replay_compacted(policy(), [previous, next]).unwrap_err(),
            AccountingError::CorruptState,
        );
    }
}
