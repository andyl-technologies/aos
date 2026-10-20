//! Lends exact canonical maintenance appends to the sole provisioning kernel.
//!
//! The same maintenance owns eight finite native destinations. A short context
//! borrows that original and Source while the actual C writer remains outside
//! the context; no account, operation, transaction or currentness DTO adopts it.

use super::append_recipe::{CatalogMaintenanceAppendKindV2, CatalogMaintenanceAppendRecipeV2};
use super::*;
use crate::journal::{CommitResult, JournalTransaction};
use crate::policy_compiler::create_q04::Q04CutIdentityV1;
use crate::reconciler::provisioning::ProvisioningAppendLoanV1;
use aos_sandbox_broker::controller_receiving::bank_launch::ControllerNativePostOriginalV1;
use std::collections::BTreeMap;

const APPEND_SLOTS: usize = 8;

#[derive(Clone, Copy)]
enum AppendFirst {
    Recipe,
    Geometry,
    Funding,
    Entry,
    Body,
    After,
    Disposal,
}

#[derive(Default)]
struct AppendOriginalV2 {
    kind: Option<CatalogMaintenanceAppendKindV2>,
    recipe: Option<Result<(), JournalError>>,
    geometry: Option<Result<ResourceVector, crate::journal::JournalAppendReceivingDemandErrorV1>>,
    funding: Option<Result<(), ResourceReservationErrorV1>>,
    entry: Option<Result<ControllerNativePostOriginalV1, ResourceReservationErrorV1>>,
    body: Option<Result<CommitResult, JournalError>>,
    after: Option<Result<(), JournalError>>,
    disposal: Option<Result<(), JournalError>>,
    first: Option<AppendFirst>,
}

pub(super) struct CatalogMaintenanceAppendOriginalsV2 {
    slots: [AppendOriginalV2; APPEND_SLOTS],
    next: usize,
    exhausted: Option<JournalError>,
}

impl CatalogMaintenanceAppendOriginalsV2 {
    pub(super) fn new() -> Self {
        Self {
            slots: std::array::from_fn(|_| Default::default()),
            next: 0,
            exhausted: None,
        }
    }

    pub(super) fn failure_v2(&self, index: usize) -> Option<&(dyn Error + 'static)> {
        fn error<T, E: Error + 'static>(
            slot: &Option<Result<T, E>>,
        ) -> Option<&(dyn Error + 'static)> {
            slot.as_ref()?.as_ref().err().map(|cause| cause as _)
        }
        let Some(slot) = self.slots.get(index) else {
            return self.exhausted.as_ref().map(|cause| cause as _);
        };
        let native = || {
            slot.entry
                .as_ref()
                .and_then(|entry| entry.as_ref().ok())
                .and_then(|post| post.failure())
        };
        match slot.first? {
            AppendFirst::Recipe => error(&slot.recipe),
            AppendFirst::Geometry => error(&slot.geometry),
            AppendFirst::Funding => error(&slot.funding),
            AppendFirst::Entry => native().or_else(|| error(&slot.entry)),
            AppendFirst::Body => error(&slot.body),
            AppendFirst::After => native().or_else(|| error(&slot.after)),
            AppendFirst::Disposal => native().or_else(|| error(&slot.disposal)),
        }
    }
}

/// Borrows the actual owner and exact private canonical recipe for one append.
///
/// Only `commit_append_recipe_once_v2` constructs this context after native
/// prearm and complete same-F prepayment. The C writer is never held inside it.
pub(crate) struct CatalogMaintenanceAppendContextV2<'loan> {
    owner: &'loan mut CatalogMaintenanceOriginalV2,
    source: &'loan ProtectedSourceDomainJournalOwnerV1,
    transaction: &'loan JournalTransaction,
    recipe: CatalogMaintenanceAppendRecipeV2<'loan, 'loan>,
    index: usize,
}

impl CatalogMaintenanceAppendContextV2<'_> {
    pub(crate) fn require_transition_v2(
        &mut self,
        controller: &Journal,
        transaction: &JournalTransaction,
    ) -> Result<(), JournalError> {
        self.owner
            .require_current_v2(controller, self.source)
            .map_err(|_| JournalError::ProtectedBoundary)?;
        self.owner
            .source_projection
            .require_same_projection_v2(self.source.journal_ref_v1())?;
        if transaction != self.transaction
            || self.owner.appends.slots[self.index].kind != Some(self.recipe.kind_v2())
            || self.owner.appends.slots[self.index]
                .entry
                .as_ref()
                .is_none_or(|entry| !entry.as_ref().is_ok_and(|post| post.failure().is_none()))
        {
            return Err(JournalError::ProtectedBoundary);
        }
        self.recipe.require_transaction_v2(controller, transaction)
    }

    pub(crate) fn matches_q04_v2(
        &self,
        identity: &Q04CutIdentityV1,
        state: &BTreeMap<(aos_sandbox_core::RecordNamespace, Vec<u8>), Vec<u8>>,
    ) -> bool {
        use aos_sandbox_protocol::domain_ledger::resource_bank as bank;
        bank::validate(state)
            .ok()
            .flatten()
            .is_some_and(|enrollment| {
                bank::require_enrolled_q04_coissuance_v2(state, identity, enrollment).is_ok()
            })
    }

    pub(crate) fn final_crossing_v2(&mut self, controller: &Journal) -> Result<(), JournalError> {
        self.require_transition_v2(controller, self.transaction)?;
        self.owner.check_frontier_v2()?;
        Ok(())
    }
}

impl CatalogMaintenanceOriginalV2 {
    /// Commits only a real canonical recipe under this same paid maintenance.
    ///
    /// Every entered native post runs after body refusal. Failed stages remain
    /// resident and cannot consume another slot as a retry. The eight actual
    /// post owners remain held until all enclosing Source/C/clock posts finish.
    pub(crate) fn commit_append_recipe_once_v2<'call>(
        &'call mut self,
        controller: &mut Journal,
        source: &'call ProtectedSourceDomainJournalOwnerV1,
        transaction: &'call JournalTransaction,
        recipe: CatalogMaintenanceAppendRecipeV2<'call, 'call>,
    ) -> Result<CommitResult, JournalError> {
        self.require_current_v2(controller, source)
            .map_err(|_| JournalError::ProtectedBoundary)?;
        let index = self.appends.next;
        if index >= APPEND_SLOTS {
            self.appends
                .exhausted
                .get_or_insert(JournalError::ProtectedBoundary);
            self.first.get_or_insert(First::Append(APPEND_SLOTS));
            return Err(JournalError::ProtectedBoundary);
        }
        self.appends.next += 1;
        self.appends.slots[index].kind = Some(recipe.kind_v2());
        self.appends.slots[index].recipe =
            Some(recipe.require_transaction_v2(controller, transaction));
        if !matches!(self.appends.slots[index].recipe, Some(Ok(()))) {
            self.appends.slots[index].first = Some(AppendFirst::Recipe);
        }
        if self.appends.slots[index].first.is_none() {
            self.appends.slots[index].geometry = Some(controller.append_receiving_demand_v1(
                transaction.records().iter().map(|record| {
                    aos_sandbox_journal::geometry::RecordShape {
                        key_bytes: record.key().len(),
                        value_bytes: record.value().map(<[u8]>::len),
                    }
                }),
            ));
            if !matches!(self.appends.slots[index].geometry, Some(Ok(_))) {
                self.appends.slots[index].first = Some(AppendFirst::Geometry);
            }
        }
        if self.appends.slots[index].first.is_none() {
            self.appends.slots[index].funding = Some((|| {
                let carrier = size_of::<CatalogMaintenanceAppendContextV2<'_>>()
                    .checked_add(size_of::<ProvisioningAppendLoanV1<'_>>())
                    .and_then(|bytes| u64::try_from(bytes).ok())
                    .ok_or(ResourceReservationErrorV1::Conflict)?;
                let demand = self.appends.slots[index]
                    .geometry
                    .as_ref()
                    .and_then(|geometry| geometry.as_ref().ok())
                    .copied()
                    .ok_or(ResourceReservationErrorV1::Conflict)?
                    .checked_add(controller.create_storage_semantic_append_demand_v1()?)?
                    .checked_add(ResourceVector::ZERO.with(D::MemoryBytes, carrier))?;
                self.reserve_additional_v2(controller, source, demand)
            })());
            if !matches!(self.appends.slots[index].funding, Some(Ok(()))) {
                self.appends.slots[index].first = Some(AppendFirst::Funding);
            }
        }
        if self.appends.slots[index].first.is_none() {
            self.appends.slots[index].entry = Some((|| {
                self.check_frontier_v2()?;
                let bank = self
                    .bank
                    .as_ref()
                    .ok_or(ResourceReservationErrorV1::Conflict)?
                    .lock()
                    .map_err(|_| ResourceReservationErrorV1::EnrollmentUnavailable)?;
                let profile = self
                    .profile
                    .as_ref()
                    .ok_or(ResourceReservationErrorV1::Conflict)?;
                bank.begin_catalog_maintenance_append_post_v2(
                    self.native
                        .as_mut()
                        .and_then(|entry| entry.as_mut().ok())
                        .ok_or(ResourceReservationErrorV1::Conflict)?,
                    controller,
                    profile,
                )
            })());
            if self.appends.slots[index]
                .entry
                .as_ref()
                .is_none_or(|entry| !entry.as_ref().is_ok_and(|post| post.failure().is_none()))
            {
                self.appends.slots[index].first = Some(AppendFirst::Entry);
            }
        }
        if self.appends.slots[index].first.is_none() {
            let result = {
                let context = CatalogMaintenanceAppendContextV2 {
                    owner: self,
                    source,
                    transaction,
                    recipe,
                    index,
                };
                let mut loan =
                    ProvisioningAppendLoanV1::catalog_maintenance_v2(context, transaction);
                controller.commit_create_provisioning_v1(transaction, &mut loan)
            };
            self.appends.slots[index].body = Some(result);
            if !matches!(self.appends.slots[index].body, Some(Ok(_))) {
                self.appends.slots[index].first = Some(AppendFirst::Body);
            }
        }
        // No healthy reentry is allowed on this independently owed destination.
        let slot = &mut self.appends.slots[index];
        if let Some(Ok(post)) = slot.entry.as_mut() {
            slot.after = Some(
                controller
                    .controller_coordinator_for_bank_read_v1()
                    .and_then(|writer| {
                        writer
                            .finish_independent_native_post_once(post)
                            .map_err(JournalError::ControllerNative)
                    }),
            );
            if !matches!(slot.after, Some(Ok(()))) {
                slot.first.get_or_insert(AppendFirst::After);
            }
        }
        if self.appends.slots[index].first.is_some() {
            self.first.get_or_insert(First::Append(index));
            return Err(JournalError::ProtectedBoundary);
        }
        self.appends.slots[index]
            .body
            .as_ref()
            .and_then(|result| result.as_ref().ok())
            .copied()
            .ok_or(JournalError::ProtectedBoundary)
    }
}

impl CatalogMaintenanceOriginalV2 {
    // All enclosing Source/C/clock posts precede this positive-only release.
    // A failed stage remains held and no later complete stage can mask it.
    pub(super) fn finish_append_disposals_v2(&mut self, controller: &Journal) {
        for index in 0..self.appends.next.min(APPEND_SLOTS) {
            if self.appends.slots[index].first.is_some()
                || !matches!(self.appends.slots[index].body, Some(Ok(_)))
                || !matches!(self.appends.slots[index].after, Some(Ok(())))
            {
                self.first.get_or_insert(First::Append(index));
                return;
            }
            let slot = &mut self.appends.slots[index];
            slot.disposal = Some((|| {
                let post = slot
                    .entry
                    .as_mut()
                    .and_then(|entry| entry.as_mut().ok())
                    .ok_or(JournalError::ProtectedBoundary)?;
                controller
                    .controller_coordinator_for_bank_read_v1()?
                    .dispose_native_post_after_upper_posts_once(post)
                    .map_err(JournalError::ControllerNative)
            })());
            if !matches!(slot.disposal, Some(Ok(()))) {
                slot.first.get_or_insert(AppendFirst::Disposal);
                self.first.get_or_insert(First::Append(index));
                return;
            }
        }
    }
}

impl CatalogMaintenanceAppendOriginalsV2 {
    pub(super) fn require_disposed_v2(&self) -> Result<(), JournalError> {
        if self.exhausted.is_some()
            || self.next > APPEND_SLOTS
            || self.slots[..self.next].iter().any(|slot| {
                slot.first.is_some()
                    || !matches!(slot.body, Some(Ok(_)))
                    || !matches!(slot.after, Some(Ok(())))
                    || !matches!(slot.disposal, Some(Ok(())))
            })
        {
            return Err(JournalError::ProtectedBoundary);
        }
        Ok(())
    }
}
