//! Binds pre-roster retained ownership and its physical-first cleanup continuation.
//!
//! Constructing owns funding only. Published retains the original roster/Weak
//! close protocol; neither an empty stage nor history certifies World return.

use super::super::{Companion, Contract};

#[path = "node_construction/birth.rs"]
mod birth;
#[path = "node_construction/native.rs"]
mod native;

pub(in super::super) use birth::{NODE_BIRTH, NODE_CREDIT_BIRTH, NODE_PUBLISHER};
pub(in super::super) use native::{
    NODE_ISSUE, NODE_CONVERSION, NODE_SUBDIVISION, NODE_LEDGER, NODE_RETURN_HISTORY,
};

pub(in super::super) const OWNER_REQUIRED: &[(&str, usize)] = &[
    (
        r#"enum NormalNodeState {
    Constructing(NodeConstruction),
    Published {
        roster: OriginalNativeAccountRoster,
        binding: Option<OriginalNativeAccountFactoryBinding>,
    },
}

struct NodeConstruction {
    node: Option<AuthenticatedNativeNodeClaim>,
    subdivision: Option<AuthenticatedNativeSubdivision>,
    credit: Option<OriginalNativeAccountCredit>,
    attempted: bool,
}"#,
        1,
    ),
    (
        r#"pub(super) fn constructing(world: usize) -> Self {
        Self {
            world,
            state: NormalNodeState::Constructing(NodeConstruction {
                node: None,
                subdivision: None,
                credit: None,
                attempted: false,
            }),
        }
    }"#,
        1,
    ),
    (
        r#"pub(super) fn is_constructing(&self) -> bool {
        matches!(&self.state, NormalNodeState::Constructing(_))
    }"#,
        1,
    ),
    (
        r#"pub(super) fn prepare(
        &mut self,
        claim: &AuthenticatedNativeWorldClaim,
        node: [u8; 32],
        original: &Arc<HostOperationGuard>,
        controls: u64,
    ) -> Result<(), OriginalActorAccountError> {
        let NormalNodeState::Constructing(construction) = &mut self.state else {
            return Err(OriginalActorAccountError::Unavailable);
        };
        let (roster, binding) = construction.prepare(claim, node, original, controls)?;
        // Both actual results move directly into their prepaid destination.
        // No fallible operation or independent post follows Arc publication.
        self.state = NormalNodeState::Published {
            roster,
            binding: Some(binding),
        };
        Ok(())
    }"#,
        1,
    ),
    (
        r#"pub(super) fn binding(&self) -> Option<&OriginalNativeAccountFactoryBinding> {
        match &self.state {
            NormalNodeState::Published { binding, .. } => binding.as_ref(),
            NormalNodeState::Constructing(_) => None,
        }
    }"#,
        1,
    ),
    (
        r#"pub(super) fn verify_quiescent(&self) -> Result<(), OriginalActorAccountError> {
        match &self.state {
            NormalNodeState::Published { roster, .. } => roster.verify_quiescent(),
            // No roster/binding or physical Source constructor has been
            // published from this state. Real funding still needs retirement.
            NormalNodeState::Constructing(construction) => construction.verify_custody(),
        }
    }"#,
        1,
    ),
    (
        r#"pub(super) fn try_close(&mut self) -> Result<(), OriginalActorAccountError> {
        match &mut self.state {
            NormalNodeState::Constructing(construction) => construction.retire(),
            NormalNodeState::Published { roster, binding } => {
                drop(binding.take());
                roster.try_close()
            }
        }
    }"#,
        1,
    ),
    (
        r#"pub(super) fn can_remove(&self) -> bool {
        match &self.state {
            NormalNodeState::Published { roster, .. } => roster.is_physically_returned(),
            // An empty pre-issuance placeholder owns no node holder. Its
            // unissued reservation remains in the actual World ledger and
            // cannot return except through that World's full native checks.
            NormalNodeState::Constructing(construction) => construction.is_empty(),
        }
    }"#,
        1,
    ),
    (
        r#"pub(super) fn retry_cleanup(&mut self) -> Result<(), QemuVmRealizationError> {
        match &mut self.state {
            NormalNodeState::Constructing(construction) => construction
                .retire()
                .map_err(original_roster::original_error),
            NormalNodeState::Published { roster, .. } => {
                roster.retry_unsettled()?;
                roster
                    .verify_quiescent()
                    .map_err(original_roster::original_error)
            }
        }
    }"#,
        1,
    ),
    (
        r#"fn verify_custody(&self) -> Result<(), OriginalActorAccountError> {
        let owners = usize::from(self.node.is_some())
            + usize::from(self.subdivision.is_some())
            + usize::from(self.credit.is_some());
        if owners > 1 || (!self.attempted && owners != 0) {
            return Err(OriginalActorAccountError::Unavailable);
        }
        Ok(())
    }"#,
        1,
    ),
    (
        r#"fn is_empty(&self) -> bool {
        self.node.is_none() && self.subdivision.is_none() && self.credit.is_none()
    }"#,
        1,
    ),
    (
        r#"fn prepare(
        &mut self,
        claim: &AuthenticatedNativeWorldClaim,
        node: [u8; 32],
        original: &Arc<HostOperationGuard>,
        controls: u64,
    ) -> Result<
        (
            OriginalNativeAccountRoster,
            OriginalNativeAccountFactoryBinding,
        ),
        OriginalActorAccountError,
    > {
        if self.attempted || !self.is_empty() {
            return Err(OriginalActorAccountError::Unavailable);
        }
        self.attempted = true;
        claim.take_node_into(node, &mut self.node)?;
        AuthenticatedNativeNodeClaim::move_to_subdivision(
            &mut self.node,
            &mut self.subdivision,
            original,
        )?;
        OriginalNativeAccountCredit::move_from_normal_subdivision(
            &mut self.subdivision,
            &mut self.credit,
            original,
            controls,
        )?;
        OriginalNativeAccountRoster::publish_normal_credit(&mut self.credit)
    }"#,
        1,
    ),
    (
        r#"fn retire(&mut self) -> Result<(), OriginalActorAccountError> {
        self.verify_custody()?;
        if let Some(node) = self.node.as_mut() {
            let result = node.retire_before_subdivision();
            if node.is_physically_returned() {
                self.node = None;
            }
            result?;
        }
        if let Some(purpose) = self.subdivision.as_mut() {
            let cleanup = purpose.retained_world_cleanup()?;
            let result = purpose.retire_after_control_free(&cleanup);
            if purpose.is_physically_returned() {
                self.subdivision = None;
            }
            result?;
        }
        if let Some(credit) = self.credit.as_mut() {
            let result = credit.retire_after_control_free();
            if credit.is_physically_returned() {
                self.credit = None;
            }
            result?;
        }
        Ok(())
    }"#,
        1,
    ),
    (r#"HostOperationSupervisor::new("#, 0),
    (r#"begin_original_cleanup_control("#, 0),
    (r#"Instant::now("#, 0),
    (r#"thread::sleep("#, 0),
];

pub(in super::super) const NODE_OWNER: Companion = Companion {
    path: "crates/crucible/crucible-qemu-host/src/linux_attempt_host/normal_pool/node_construction.rs",
    required: OWNER_REQUIRED,
};

// These are the existing exact retirement and true-layout facts, reused whole.
pub(in super::super) const NODE_LAYOUT: Companion =
    super::super::source_world_admission::NATIVE_LAYOUT;
pub(in super::super) const NODE_ROSTER_RETURN: Companion = Companion {
    path: "crates/crucible/crucible-qemu-host/src/linux_attempt_host/original_roster/retirement.rs",
    required: super::roster_retirement::CONTRACT.required,
};
pub(in super::super) const NODE_CREDIT_RETURN: Companion = Companion {
    path: super::roster_retirement::CONTRACT.companions[1].path,
    required: super::roster_retirement::CONTRACT.companions[1].required,
};

pub(super) const CONTRACT: Contract = Contract {
    package: "crucible-qemu-host",
    target: "src/linux_attempt_host/normal_pool/node_construction",
    required: OWNER_REQUIRED,
    expressions: &[("roster.retry_unsettled()", 1)],
    identifiers: &[("retry_cleanup", 1), ("retry_unsettled", 1)],
    companions: &[
        Companion {
            path: super::normal_world::CONTRACT.companions[0].path,
            required: super::normal_world::CONTRACT.companions[0].required,
        },
        Companion {
            path: super::normal_world::CONTRACT.companions[1].path,
            required: super::normal_world::CONTRACT.companions[1].required,
        },
        Companion {
            path: super::normal_world::CONTRACT.companions[2].path,
            required: super::normal_world::CONTRACT.companions[2].required,
        },
        Companion {
            path: super::normal_world::CONTRACT.companions[3].path,
            required: super::normal_world::CONTRACT.companions[3].required,
        },
        NODE_BIRTH,
        NODE_ISSUE,
        NODE_CONVERSION,
        NODE_SUBDIVISION,
        NODE_LEDGER,
        NODE_RETURN_HISTORY,
        NODE_CREDIT_BIRTH,
        NODE_PUBLISHER,
        NODE_LAYOUT,
        NODE_ROSTER_RETURN,
        NODE_CREDIT_RETURN,
        super::roster_retirement::SOURCE_ORIGINAL,
        super::roster_storage::STORAGE,
        super::roster_storage::FUNDING,
    ],
};

#[cfg(test)]
#[path = "node_construction/tests.rs"]
mod tests;
