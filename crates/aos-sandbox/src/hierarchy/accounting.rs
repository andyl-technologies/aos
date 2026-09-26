//! Exact checked resource accounting over logical ancestry.
//!
//! The accounting result is controller planning data. It does not alter a
//! cgroup, reserve node capacity, or authorize a child runtime.

use std::collections::BTreeMap;

use aos_sandbox_core::{
    DesiredGeneration, ObjectDigest, ProjectId, ResourceVector, Revision, SandboxId,
};

use super::graph::SandboxTreeV1;

/// Maximum account rows accepted by one accounting pass.
pub const MAXIMUM_RESERVATION_ACCOUNTS: usize = 65_536;

/// Carries a verified, generation-fenced delegation grant for one sandbox.
///
/// Its fields are private because an arbitrary claimed subtree reservation is
/// not accounting authority. The authority layer must verify the grant and
/// then construct this evidence inside the crate.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ReservationAccountV1 {
    project: ProjectId,
    tree_generation: Revision,
    sandbox: SandboxId,
    parent: Option<SandboxId>,
    desired_generation: DesiredGeneration,
    granted_envelope: ResourceVector,
    direct_reservation: ResourceVector,
    delegation_commitment: ObjectDigest,
}

impl ReservationAccountV1 {
    /// Records one grant after the authority boundary verified it.
    ///
    /// # Errors
    ///
    /// Returns [`ReservationError::UnspecifiedIdentity`] for zero identities,
    /// or [`ReservationError::EnvelopeExceeded`] when the direct charge is
    /// already outside the granted envelope.
    pub(crate) fn from_verified_parts(
        project: ProjectId,
        tree_generation: Revision,
        sandbox: SandboxId,
        parent: Option<SandboxId>,
        desired_generation: DesiredGeneration,
        granted_envelope: ResourceVector,
        direct_reservation: ResourceVector,
        delegation_commitment: ObjectDigest,
    ) -> Result<Self, ReservationError> {
        if project.as_bytes() == &[0; 16]
            || tree_generation.get() == 0
            || sandbox.as_bytes() == &[0; 16]
            || desired_generation.get() == 0
            || delegation_commitment.as_bytes() == &[0; 32]
        {
            return Err(ReservationError::UnspecifiedIdentity);
        }
        granted_envelope
            .checked_sub(direct_reservation)
            .map_err(|_| ReservationError::EnvelopeExceeded)?;

        Ok(Self {
            project,
            tree_generation,
            sandbox,
            parent,
            desired_generation,
            granted_envelope,
            direct_reservation,
            delegation_commitment,
        })
    }

    /// Returns the project whose authority issued the grant.
    #[must_use]
    pub const fn project(self) -> ProjectId {
        self.project
    }

    /// Returns the exact tree generation at which the grant was verified.
    #[must_use]
    pub const fn tree_generation(self) -> Revision {
        self.tree_generation
    }

    /// Returns the sandbox whose reservation is described.
    #[must_use]
    pub const fn sandbox(self) -> SandboxId {
        self.sandbox
    }

    /// Returns the exact parent identity bound into the grant.
    #[must_use]
    pub const fn parent(self) -> Option<SandboxId> {
        self.parent
    }

    /// Returns the exact desired generation evaluated.
    #[must_use]
    pub const fn desired_generation(self) -> DesiredGeneration {
        self.desired_generation
    }

    /// Returns the capacity explicitly delegated for the complete subtree.
    #[must_use]
    pub const fn granted_envelope(self) -> ResourceVector {
        self.granted_envelope
    }

    /// Returns this sandbox's direct reservation.
    #[must_use]
    pub const fn direct_reservation(self) -> ResourceVector {
        self.direct_reservation
    }

    /// Returns the parent or project delegation decision commitment.
    #[must_use]
    pub const fn delegation_commitment(self) -> ObjectDigest {
        self.delegation_commitment
    }
}

/// Carries a verified project-level reservation ceiling and tree CAS fence.
///
/// Request scalars cannot construct this value; a trusted authority adapter
/// must verify the project grant before minting it inside the crate.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ProjectReservationAccountV1 {
    project: ProjectId,
    tree_generation: Revision,
    envelope: ResourceVector,
    authority_commitment: ObjectDigest,
}

impl ProjectReservationAccountV1 {
    /// Records one project accounting fence after authority verification.
    ///
    /// # Errors
    ///
    /// Returns [`ReservationError::UnspecifiedIdentity`] for a zero project or
    /// tree generation.
    pub(crate) fn from_verified_parts(
        project: ProjectId,
        tree_generation: Revision,
        envelope: ResourceVector,
        authority_commitment: ObjectDigest,
    ) -> Result<Self, ReservationError> {
        if project.as_bytes() == &[0; 16]
            || tree_generation.get() == 0
            || authority_commitment.as_bytes() == &[0; 32]
        {
            return Err(ReservationError::UnspecifiedIdentity);
        }
        Ok(Self {
            project,
            tree_generation,
            envelope,
            authority_commitment,
        })
    }

    /// Returns the project identity.
    #[must_use]
    pub const fn project(self) -> ProjectId {
        self.project
    }

    /// Returns the exact tree generation accounted.
    #[must_use]
    pub const fn tree_generation(self) -> Revision {
        self.tree_generation
    }

    /// Returns the explicit project reservation ceiling.
    #[must_use]
    pub const fn envelope(self) -> ResourceVector {
        self.envelope
    }

    /// Returns the project reservation-authority commitment.
    #[must_use]
    pub const fn authority_commitment(self) -> ObjectDigest {
        self.authority_commitment
    }
}

/// Records the exact aggregate reservation computed for one subtree.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AggregateReservationV1 {
    sandbox: SandboxId,
    desired_generation: DesiredGeneration,
    delegation_commitment: ObjectDigest,
    direct_reservation: ResourceVector,
    descendant_reservation: ResourceVector,
    subtree_reservation: ResourceVector,
    remaining_envelope: ResourceVector,
}

impl AggregateReservationV1 {
    /// Returns the subtree root.
    #[must_use]
    pub const fn sandbox(self) -> SandboxId {
        self.sandbox
    }

    /// Returns the generation used for this accounting fact.
    #[must_use]
    pub const fn desired_generation(self) -> DesiredGeneration {
        self.desired_generation
    }

    /// Returns the delegation decision used for this reserved subtree.
    #[must_use]
    pub const fn delegation_commitment(self) -> ObjectDigest {
        self.delegation_commitment
    }

    /// Returns resources charged directly to the sandbox.
    #[must_use]
    pub const fn direct_reservation(self) -> ResourceVector {
        self.direct_reservation
    }

    /// Returns resources charged to strict descendants.
    #[must_use]
    pub const fn descendant_reservation(self) -> ResourceVector {
        self.descendant_reservation
    }

    /// Returns direct plus all descendant reservations.
    #[must_use]
    pub const fn subtree_reservation(self) -> ResourceVector {
        self.subtree_reservation
    }

    /// Returns the exact unreserved portion of the subtree envelope.
    #[must_use]
    pub const fn remaining_envelope(self) -> ResourceVector {
        self.remaining_envelope
    }
}

/// Contains canonical aggregate rows for a complete tree generation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReservationReportV1 {
    project: ProjectId,
    tree_generation: Revision,
    project_authority_commitment: ObjectDigest,
    project_reservation: ResourceVector,
    project_remaining: ResourceVector,
    rows: Vec<AggregateReservationV1>,
}

impl ReservationReportV1 {
    /// Returns the project whose complete forest was accounted.
    #[must_use]
    pub const fn project(&self) -> ProjectId {
        self.project
    }

    /// Returns the exact project tree generation.
    #[must_use]
    pub const fn tree_generation(&self) -> Revision {
        self.tree_generation
    }

    /// Returns the project reservation-authority commitment.
    #[must_use]
    pub const fn project_authority_commitment(&self) -> ObjectDigest {
        self.project_authority_commitment
    }

    /// Returns root subtree reservations charged once to the project.
    #[must_use]
    pub const fn project_reservation(&self) -> ResourceVector {
        self.project_reservation
    }

    /// Returns the unreserved part of the project ceiling.
    #[must_use]
    pub const fn project_remaining(&self) -> ResourceVector {
        self.project_remaining
    }

    /// Returns aggregate facts in canonical sandbox order.
    #[must_use]
    pub fn rows(&self) -> &[AggregateReservationV1] {
        &self.rows
    }

    /// Finds one aggregate fact without conferring reservation authority.
    #[must_use]
    pub fn get(&self, sandbox: SandboxId) -> Option<&AggregateReservationV1> {
        self.rows
            .binary_search_by_key(&sandbox, |row| row.sandbox)
            .ok()
            .and_then(|index| self.rows.get(index))
    }
}

/// Computes exact subtree charges and checks every ancestry envelope.
///
/// The account set must cover the tree exactly and be ordered by sandbox.
/// Each child's verified grant is charged once to its immediate parent. A
/// parent's full grant is in turn charged to its parent, so every delegated
/// subtree remains reserved through every ancestor without double-counting at
/// a single boundary. Each root grant is charged once to the project ceiling.
///
/// # Errors
///
/// Returns [`ReservationError`] for incomplete, stale, or noncanonical input,
/// arithmetic overflow, or a subtree total beyond its explicit envelope.
pub fn account_ancestry_reservations(
    tree: &SandboxTreeV1,
    project_account: ProjectReservationAccountV1,
    accounts: &[ReservationAccountV1],
) -> Result<ReservationReportV1, ReservationError> {
    if project_account.project() != tree.project()
        || project_account.tree_generation() != tree.tree_generation()
    {
        return Err(ReservationError::StaleTreeGeneration);
    }
    if accounts.len() > MAXIMUM_RESERVATION_ACCOUNTS
        || !accounts
            .windows(2)
            .all(|pair| pair[0].sandbox() < pair[1].sandbox())
    {
        return Err(ReservationError::AccountsNotCanonical);
    }
    if accounts.len() != tree.records().len() {
        return Err(ReservationError::IncompleteAccounts);
    }

    let by_sandbox: BTreeMap<_, _> = accounts
        .iter()
        .copied()
        .map(|account| (account.sandbox(), account))
        .collect();
    for record in tree.records() {
        let account = by_sandbox
            .get(&record.sandbox())
            .ok_or(ReservationError::IncompleteAccounts)?;
        if account.project() != tree.project()
            || account.tree_generation() != tree.tree_generation()
            || account.parent() != record.parent()
            || account.desired_generation() != record.desired_generation()
        {
            return Err(ReservationError::StaleGeneration);
        }
    }

    let granted_envelopes: BTreeMap<_, _> = accounts
        .iter()
        .map(|account| (account.sandbox(), account.granted_envelope()))
        .collect();
    let mut child_reservations = BTreeMap::<SandboxId, ResourceVector>::new();
    let mut deepest_first = Vec::new();
    deepest_first
        .try_reserve_exact(accounts.len())
        .map_err(|_| ReservationError::Capacity)?;
    for account in accounts {
        let depth = tree
            .depth(account.sandbox())
            .ok_or(ReservationError::IncompleteAccounts)?;
        deepest_first.push((depth, account.sandbox()));
    }
    deepest_first.sort_unstable_by(|left, right| right.cmp(left));
    for (_, sandbox) in deepest_first {
        let child_grant = granted_envelopes
            .get(&sandbox)
            .copied()
            .ok_or(ReservationError::IncompleteAccounts)?;
        let record = tree
            .record(sandbox)
            .ok_or(ReservationError::IncompleteAccounts)?;
        if let Some(parent) = record.parent() {
            let prior_children = child_reservations
                .get(&parent)
                .copied()
                .unwrap_or(ResourceVector::ZERO);
            child_reservations.insert(
                parent,
                prior_children
                    .checked_add(child_grant)
                    .map_err(|_| ReservationError::ArithmeticOverflow)?,
            );
        }
    }

    let mut rows = Vec::new();
    rows.try_reserve_exact(accounts.len())
        .map_err(|_| ReservationError::Capacity)?;
    for account in accounts {
        let descendant_reservation = child_reservations
            .get(&account.sandbox())
            .copied()
            .unwrap_or(ResourceVector::ZERO);
        let subtree_reservation = account
            .direct_reservation()
            .checked_add(descendant_reservation)
            .map_err(|_| ReservationError::ArithmeticOverflow)?;
        let remaining_envelope = account
            .granted_envelope()
            .checked_sub(subtree_reservation)
            .map_err(|_| ReservationError::DelegatedEnvelopeExceeded)?;

        rows.push(AggregateReservationV1 {
            sandbox: account.sandbox(),
            desired_generation: account.desired_generation(),
            delegation_commitment: account.delegation_commitment(),
            direct_reservation: account.direct_reservation(),
            descendant_reservation,
            subtree_reservation,
            remaining_envelope,
        });
    }

    let mut project_reservation = ResourceVector::ZERO;
    for account in accounts {
        let record = tree
            .record(account.sandbox())
            .ok_or(ReservationError::IncompleteAccounts)?;
        if record.parent().is_none() {
            project_reservation = project_reservation
                .checked_add(account.granted_envelope())
                .map_err(|_| ReservationError::ArithmeticOverflow)?;
        }
    }
    let project_remaining = project_account
        .envelope()
        .checked_sub(project_reservation)
        .map_err(|_| ReservationError::ProjectEnvelopeExceeded)?;

    Ok(ReservationReportV1 {
        project: tree.project(),
        tree_generation: tree.tree_generation(),
        project_authority_commitment: project_account.authority_commitment(),
        project_reservation,
        project_remaining,
        rows,
    })
}

/// Reports invalid ancestry reservation input or checked arithmetic.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum ReservationError {
    /// A sandbox or generation uses its zero sentinel.
    #[error("reservation account contains an unspecified identity")]
    UnspecifiedIdentity,
    /// Accounts are oversized, duplicated, or not in sandbox order.
    #[error("reservation accounts are not a canonical bounded set")]
    AccountsNotCanonical,
    /// Accounts do not cover the validated tree exactly.
    #[error("reservation accounts do not exactly cover the sandbox tree")]
    IncompleteAccounts,
    /// An account does not match the current sandbox generation.
    #[error("reservation account names a stale sandbox generation")]
    StaleGeneration,
    /// The project accounting fence differs from the current tree.
    #[error("reservation account names a stale project tree generation")]
    StaleTreeGeneration,
    /// A checked resource sum overflowed.
    #[error("aggregate ancestry reservation overflowed")]
    ArithmeticOverflow,
    /// A subtree reservation exceeds its explicit envelope.
    #[error("aggregate subtree reservation exceeds its envelope")]
    EnvelopeExceeded,
    /// Direct and child reservations exceed the declared subtree reservation.
    #[error("delegated child reservations exceed their subtree reservation")]
    DelegatedEnvelopeExceeded,
    /// Root subtree reservations exceed the project ceiling.
    #[error("aggregate root reservations exceed the project envelope")]
    ProjectEnvelopeExceeded,
    /// Bounded allocation could not be admitted.
    #[error("reservation accounting capacity is exhausted")]
    Capacity,
}
