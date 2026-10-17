//! Pins independently configured source authority before archive inspection.

use std::collections::{BTreeMap, BTreeSet};

use crucible::node_scheduling::InputPayload;
use crucible_campaign::ExecutionId;
use crucible_node_contract::{ContentRef, Validate};

use super::super::super::{InstalledNodeCatalog, NodeObservedError, refused};
use super::{InstalledOriginalLineagePreparation, InstalledOriginalLineageSourcePolicy};

/// Owns the immutable host pin and its independent original-source inspector.
///
/// Portable source documents cannot instantiate this object. The expected pin
/// is separately configured by the installing host and rechecked before every
/// original-source inspection.
pub struct InstalledOriginalLineageAuthority {
    expected: ContentRef,
    policy: Box<dyn InstalledOriginalLineageSourcePolicy>,
}

impl InstalledOriginalLineageAuthority {
    /// Authenticates the exact host-configured policy body before installation.
    ///
    /// # Errors
    /// Refuses invalid identity, a foreign full typed pin, changed bytes or a
    /// policy body larger than the independent one MiB installation ceiling.
    pub fn new(
        expected: ContentRef,
        policy: Box<dyn InstalledOriginalLineageSourcePolicy>,
    ) -> Result<Self, NodeObservedError> {
        check_pin(&expected, policy.immutable_policy())?;
        Ok(Self { expected, policy })
    }

    pub(super) fn check(&self) -> Result<(), NodeObservedError> {
        check_pin(&self.expected, self.policy.immutable_policy())
    }

    pub(super) fn policy(&self) -> &dyn InstalledOriginalLineageSourcePolicy {
        self.policy.as_ref()
    }
}

fn check_pin(expected: &ContentRef, actual: &InputPayload) -> Result<(), NodeObservedError> {
    expected.validate()?;
    if actual.reference != *expected || actual.bytes.len() > 1024 * 1024 {
        return Err(refused("original-lineage installed policy pin differs"));
    }
    actual.reference.verify(&actual.bytes)?;
    Ok(())
}

pub(in crate::node_observed_executor::factory) struct Installation {
    pub(in crate::node_observed_executor::factory) used: BTreeSet<ExecutionId>,
    pub(in crate::node_observed_executor::factory) authority:
        Option<InstalledOriginalLineageAuthority>,
    pub(in crate::node_observed_executor::factory) preparations:
        BTreeMap<ExecutionId, InstalledOriginalLineagePreparation>,
}

impl Installation {
    pub(in crate::node_observed_executor::factory) fn new() -> Self {
        Self {
            authority: None,
            used: BTreeSet::new(),
            preparations: BTreeMap::new(),
        }
    }
}

impl InstalledNodeCatalog {
    /// Installs one separately pinned original-source authority before preparation.
    ///
    /// Normal behavioral acceptance must also be installed before any source
    /// archive is opened. This method grants neither class acceptance nor Ready.
    ///
    /// # Errors
    /// Refuses replacement, changed pins or outstanding whole-world custody.
    pub fn install_original_lineage_authority(
        &mut self,
        authority: InstalledOriginalLineageAuthority,
    ) -> Result<(), NodeObservedError> {
        if self.original_lineage.authority.is_some()
            || !self.original_lineage.used.is_empty()
            || self.custody.reserved_worlds() != 0
        {
            return Err(refused(
                "original-lineage authority replacement or live custody",
            ));
        }
        authority.check()?;
        self.original_lineage.authority = Some(authority);
        Ok(())
    }

    /// Requires both host authorities before archive reads or source callbacks.
    ///
    /// # Errors
    /// Refuses missing behavioral acceptance, missing source policy or a changed
    /// immutable policy pin. An authenticated tape cannot waive either refusal.
    pub fn require_original_lineage_authorities(&self) -> Result<(), NodeObservedError> {
        if self.behavioral_acceptance.is_none() {
            return Err(refused(
                "original-lineage behavioral acceptance unavailable",
            ));
        }
        self.original_lineage
            .authority
            .as_ref()
            .ok_or_else(|| refused("original-lineage source authority unavailable"))?
            .check()
    }

    /// Reports whether the original actor has already reserved this operational nonce.
    pub fn owns_original_lineage_execution(&self, execution: ExecutionId) -> bool {
        self.original_lineage.used.contains(&execution)
    }

    /// Counts complete source capsules retained under the actor's world ceiling.
    pub fn original_lineage_preparation_count(&self) -> usize {
        self.original_lineage.preparations.len()
    }

    /// Borrows original prepared custody without redispatching its source inspection.
    pub fn original_lineage_preparation(
        &self,
        execution: ExecutionId,
    ) -> Option<&InstalledOriginalLineagePreparation> {
        self.original_lineage.preparations.get(&execution)
    }

    /// Transfers the complete original prepared capsule to its owning deployment caller.
    ///
    /// # Errors
    /// Refuses an unknown or unsuccessful original preparation. The returned
    /// capsule must outlive common Ready, publication and complete reclamation.
    pub fn take_original_lineage_preparation(
        &mut self,
        execution: ExecutionId,
    ) -> Result<InstalledOriginalLineagePreparation, NodeObservedError> {
        if self
            .original_lineage
            .preparations
            .get(&execution)
            .is_none_or(|owned| !owned.is_prepared())
        {
            return Err(refused("original-lineage prepared custody unavailable"));
        }
        self.original_lineage
            .preparations
            .remove(&execution)
            .ok_or_else(|| refused("original-lineage preparation disappeared"))
    }

    pub(in crate::node_observed_executor) fn retire_original_lineage_preparations(&mut self) {
        for owned in self.original_lineage.preparations.values_mut() {
            owned.retire();
        }
        // Original history and policy stay held until genuine whole-slot reclamation.
        if self.custody.reserved_worlds() == 0 {
            self.original_lineage.preparations.clear();
        }
    }
}
