//! Reserves an initial Project grant while its completed originals remain held.
//!
//! The existing current administrative and completed ancestry consumers supply
//! proposed DATA. Only the same enrolled bank's immediate-parent CAS pays it.
//! The original native transaction, ambiguous readback and independent debts
//! remain in the prearmed invocation; no failed or expired loan refunds it.

use std::cell::RefCell;
use std::sync::{Arc, Mutex};

use aos_sandbox_core::{ResourceAccount, ResourceCeilings, ResourceVector};
use sha2::{Digest as _, Sha256};

use crate::hierarchy::controller_genesis::HeldControllerSourceGenesisV1;
use crate::hierarchy::genesis_profile::SourceGenesisErrorV1;
use crate::hierarchy::protected_journal::RetainedTreeInventoryDataV1;
use crate::hierarchy::source_genesis::HeldSourceProjectGenesisObservationV3;
use crate::normal_root::ProductionControllerNormalRootProfileV1;
use crate::policy_compiler::CompletedRootSourceProjectGenesisFloorV3;
use crate::Journal;

use super::{
    AccountHead, AccountKind, AccountTransition, Claim, ClaimCut, ClaimPurpose,
    ClaimState, ControllerResourceBankOpeningV1, EnrollmentIdentity,
    ResourceReservationErrorV1, ReturnedAppend, replay,
};

struct OriginalProjectGrantData {
    project: [u8; 16],
    acceptance: [u8; 32],
    tree: [u8; 32],
    instance: [u8; 32],
    amount: ResourceVector,
    cut: ClaimCut,
    original_boot: [u8; 16],
    original_clock: aos_sandbox_core::RawPairedClockSample,
}

/// Keeps the whole grant action and every independent original-owner post.
pub(crate) struct ProjectResourceGrantAttemptV1 {
    preparation: Option<Result<OriginalProjectGrantData, ResourceReservationErrorV1>>,
    bank_lock: Option<Result<(), ResourceReservationErrorV1>>,
    writer: Option<Result<(), SourceGenesisErrorV1>>,
    append: ReturnedAppend,
    posts: [Option<Result<(), SourceGenesisErrorV1>>; 3],
    profile_post: Option<Result<(), crate::normal_root::NormalRootStartupErrorV1>>,
    final_clock: Option<Result<(), SourceGenesisErrorV1>>,
}

impl ProjectResourceGrantAttemptV1 {
    pub(crate) const fn new() -> Self {
        Self {
            preparation: None,
            bank_lock: None,
            writer: None,
            append: ReturnedAppend::new(),
            posts: [None, None, None],
            profile_post: None,
            final_clock: None,
        }
    }

    // Only the purpose-closed HeldController method lends this actual writer.
    pub(crate) fn run(
        &mut self,
        controller: &HeldControllerSourceGenesisV1<'_>,
        journal: &RefCell<&mut Journal>,
        bank: Option<&Arc<Mutex<ControllerResourceBankOpeningV1>>>,
        source: &HeldSourceProjectGenesisObservationV3<'_>,
        inventory: &RetainedTreeInventoryDataV1<'_>,
        root: &CompletedRootSourceProjectGenesisFloorV3<'_, '_>,
        profile: &ProductionControllerNormalRootProfileV1,
    ) -> Result<(), ()> {
        if self.preparation.is_some() {
            return Err(());
        }
        self.preparation = Some(prepare(controller, source, inventory, root));
        if let Some(Ok(original)) = self.preparation.as_ref() {
            match bank {
                Some(bank) => match bank.lock() {
                    Ok(bank) => {
                        self.bank_lock = Some(Ok(()));
                        match journal.try_borrow_mut() {
                            Ok(mut journal) => {
                                self.writer = Some(Ok(()));
                                let transition = bank.require_enrolled(&journal, profile)
                                    .and_then(|identity| original.transition(&journal, identity));
                                self.append.append_into(&mut journal, transition);
                            }
                            Err(_) => self.writer = Some(Err(SourceGenesisErrorV1::Stale)),
                        }
                    }
                    // The parent Arc still owns the poisoned mutex and all
                    // original enrollment/uncertain native owners within it.
                    Err(_) => self.bank_lock = Some(Err(ResourceReservationErrorV1::EnrollmentUnavailable)),
                },
                None => self.bank_lock = Some(Err(ResourceReservationErrorV1::EnrollmentUnavailable)),
            }
        }

        // Neither the bank mutex nor the writer RefCell spans these reentrant
        // original-owner checks. Native failure cannot suppress later debt.
        self.posts[0] = Some(controller.recheck_current_admission());
        self.posts[1] = Some(source.require_retained_inventory_v3(inventory));
        self.posts[2] = Some(root.recheck());
        self.profile_post = Some(profile.recheck());
        self.final_clock = Some(root.independent_resource_clock());
        if self.error().is_some() || self.append.require_committed().is_err() {
            Err(())
        } else {
            Ok(())
        }
    }

    pub(crate) fn error(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.preparation.as_ref().and_then(|result| result.as_ref().err())
            .map(|error| error as &(dyn std::error::Error + 'static))
            .or_else(|| self.bank_lock.as_ref().and_then(|result| result.as_ref().err())
                .map(|error| error as &(dyn std::error::Error + 'static)))
            .or_else(|| self.writer.as_ref().and_then(|result| result.as_ref().err())
                .map(|error| error as &(dyn std::error::Error + 'static)))
            .or_else(|| self.append.failure())
            .or_else(|| self.posts.iter().find_map(|result| result.as_ref()
                .and_then(|result| result.as_ref().err())
                .map(|error| error as &(dyn std::error::Error + 'static))))
            .or_else(|| self.profile_post.as_ref().and_then(|result| result.as_ref().err())
                .map(|error| error as &(dyn std::error::Error + 'static)))
            .or_else(|| self.final_clock.as_ref().and_then(|result| result.as_ref().err())
                .map(|error| error as &(dyn std::error::Error + 'static)))
    }
}

fn prepare(
    controller: &HeldControllerSourceGenesisV1<'_>,
    source: &HeldSourceProjectGenesisObservationV3<'_>,
    inventory: &RetainedTreeInventoryDataV1<'_>,
    root: &CompletedRootSourceProjectGenesisFloorV3<'_, '_>,
) -> Result<OriginalProjectGrantData, ResourceReservationErrorV1> {
    crate::policy_compiler::consume_completed_project_genesis_ancestry_v3(
        controller, source, inventory, root,
    )?;
    let authorization = controller.borrow_current_project_resources_v3()?;
    let project = authorization.acceptance().project();
    let (tree, _, _) = inventory.trees().map_err(SourceGenesisErrorV1::from)?
        .find(|(tree, _, _)| tree.project() == project)
        .ok_or(SourceGenesisErrorV1::Conflict)?;
    let tree = crate::hierarchy::codec::tree_commitment_v1(tree)
        .map_err(|_| SourceGenesisErrorV1::NonCanonical)?;
    let (original, deadline) = root.resource_admission_cut()?;
    let data = OriginalProjectGrantData {
        project: *project.as_bytes(),
        acceptance: *authorization.acceptance().digest().as_bytes(),
        tree: *tree.as_bytes(),
        instance: root.floor().instance(),
        amount: authorization.envelope(),
        original_boot: original.host_boot_id(),
        original_clock: original,
        cut: ClaimCut::Operation {
            original_wall_seconds: original.wall_seconds(),
            original_boottime_nanoseconds: original.boottime_nanoseconds(),
            deadline_boottime_nanoseconds: deadline,
        },
    };
    authorization.recheck()?;
    source.require_retained_inventory_v3(inventory)?;
    root.recheck()?;
    Ok(data)
}

impl OriginalProjectGrantData {
    fn transition(
        &self,
        journal: &Journal,
        enrollment: EnrollmentIdentity,
    ) -> Result<AccountTransition, ResourceReservationErrorV1> {
        let before = replay::find_head(journal.controller_resource_state_v1()?, enrollment.node)?;
        if before.kind != AccountKind::Node || enrollment.boot != self.original_boot {
            return Err(ResourceReservationErrorV1::Conflict);
        }
        let mut hash = Sha256::new();
        hash.update(b"AOS-resource-project-v1\0");
        hash.update(enrollment.node);
        hash.update(enrollment.epoch);
        hash.update(self.project);
        let hash = hash.finalize();
        let mut child_id = [0; 16];
        child_id.copy_from_slice(&hash[..16]);
        let child = AccountHead {
            enrollment,
            id: child_id,
            parent: before.id,
            kind: AccountKind::Project,
            generation: 1,
            project: self.project,
            sandbox: [0; 16],
            tree_revision: self.tree,
            baseline: ResourceVector::ZERO,
            account: ResourceAccount::from_usage(
                ResourceCeilings::bounded(self.amount),
                ResourceVector::ZERO,
                ResourceVector::ZERO,
            )?,
        };
        let operation = aos_sandbox_core::OperationId::new().into_bytes();
        let claim = Claim {
            enrollment,
            id: operation,
            account: before.id,
            child: child_id,
            owner: self.acceptance,
            purpose: ClaimPurpose::InclusiveGrant,
            operation,
            project: self.project,
            sandbox: [0; 16],
            tree_revision: self.tree,
            cut: self.cut,
            genesis_instance: self.instance,
            amount: self.amount,
            state: ClaimState::Reserved,
        };
        AccountTransition::grant(before, child, claim, self.original_clock)
    }
}
