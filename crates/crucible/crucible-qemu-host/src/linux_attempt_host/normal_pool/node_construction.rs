//! Retains every pre-roster node owner in the permanently prepaid pool array.
//!
//! Native funding moves through explicit slots before any independent post can
//! refuse. No Source process, storage owner or binding escapes Constructing.
//! Published nodes keep the existing exclusive roster/Weak/control retirement.
// SPDX-License-Identifier: Apache-2.0

use super::*;
use crate::linux_attempt_host::native_account::OriginalNativeAccountCredit;
use crucible_host_resources::host_services::process_birth::{
    AuthenticatedNativeNodeClaim, AuthenticatedNativeSubdivision,
};

pub(super) struct NormalNode {
    pub(super) world: usize,
    state: NormalNodeState,
}

enum NormalNodeState {
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
}

impl NormalNode {
    pub(super) fn constructing(world: usize) -> Self {
        Self {
            world,
            state: NormalNodeState::Constructing(NodeConstruction {
                node: None,
                subdivision: None,
                credit: None,
                attempted: false,
            }),
        }
    }

    pub(super) fn is_constructing(&self) -> bool {
        matches!(&self.state, NormalNodeState::Constructing(_))
    }

    pub(super) fn prepare(
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
    }

    pub(super) fn binding(&self) -> Option<&OriginalNativeAccountFactoryBinding> {
        match &self.state {
            NormalNodeState::Published { binding, .. } => binding.as_ref(),
            NormalNodeState::Constructing(_) => None,
        }
    }

    pub(super) fn verify_quiescent(&self) -> Result<(), OriginalActorAccountError> {
        match &self.state {
            NormalNodeState::Published { roster, .. } => roster.verify_quiescent(),
            // No roster/binding or physical Source constructor has been
            // published from this state. Real funding still needs retirement.
            NormalNodeState::Constructing(construction) => construction.verify_custody(),
        }
    }

    pub(super) fn try_close(&mut self) -> Result<(), OriginalActorAccountError> {
        match &mut self.state {
            NormalNodeState::Constructing(construction) => construction.retire(),
            NormalNodeState::Published { roster, binding } => {
                drop(binding.take());
                roster.try_close()
            }
        }
    }

    pub(super) fn can_remove(&self) -> bool {
        match &self.state {
            NormalNodeState::Published { roster, .. } => roster.is_physically_returned(),
            // An empty pre-issuance placeholder owns no node holder. Its
            // unissued reservation remains in the actual World ledger and
            // cannot return except through that World's full native checks.
            NormalNodeState::Constructing(construction) => construction.is_empty(),
        }
    }

    pub(super) fn retry_cleanup(&mut self) -> Result<(), QemuVmRealizationError> {
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
    }
}

impl NodeConstruction {
    fn verify_custody(&self) -> Result<(), OriginalActorAccountError> {
        let owners = usize::from(self.node.is_some())
            + usize::from(self.subdivision.is_some())
            + usize::from(self.credit.is_some());
        if owners > 1 || (!self.attempted && owners != 0) {
            return Err(OriginalActorAccountError::Unavailable);
        }
        Ok(())
    }

    fn is_empty(&self) -> bool {
        self.node.is_none() && self.subdivision.is_none() && self.credit.is_none()
    }

    fn prepare(
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
    }

    fn retire(&mut self) -> Result<(), OriginalActorAccountError> {
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
    }
}

#[cfg(test)]
mod tests;
