//! Keeps actual upper CreateStorage results around the native Cache original.
//!
//! Cache retains all native writers, shapes, byte encoding, replay and append
//! stages. This programme retains the same real J/Controller/Source operations,
//! their owning semantic failures, and their independently owed observations.

pub(crate) mod delete_inventory;
pub use delete_inventory::{CacheDeleteInventoryOriginalV1, CacheDeleteInventoryQueryV1};

use crate::journal::JournalTransaction;

use std::error::Error;
use std::sync::Arc;

use aos_sandbox_cache::{
    CacheCreateStorageReceivingShapeV1, CacheHeldClosedV1, CacheHeldCurrentnessOriginalV1,
    CacheHeldCurrentnessSiteV1, CacheHeldErrorV1, CacheHeldIdentityDataV1,
    CacheHeldPreRootCutV1, CacheResidencyProtectedOwnerV1, DormantCacheOwnerV1,
    OriginalCreateStorageCacheLoanV1 as NativeCreateStorageCacheLoanV1,
};
use aos_sandbox_model::{ResourceDimension, ResourceVector};
use aos_sandbox_protocol::domain_ledger::create_storage_history::{
    cache_held::{CacheHeldBodyDataV1, CacheHeldReceiptDataV1},
    source_held::SOURCE_HELD_RECEIPT_BYTES_V1,
};
use aos_sandbox_broker::canonical_journal::CommitResult;
use aos_sandbox_broker::controller_receiving::bank_launch::ControllerCacheAuditFundingLoanV1;

use crate::controller_resource_reservation::{
    CreateStorageOriginalLoanV1, ResourceReservationErrorV1,
};
use crate::normal_root::ProductionControllerNormalRootProfileV1;

use super::CacheResidentInitializationV1;

pub(crate) mod released;
pub(crate) use released::{CacheReleasedOriginalsV1, CacheReleasedCurrentnessSiteV1};

pub(crate) mod terminal;
pub(crate) use terminal::cache_terminal_receiving_demand_v1;

#[derive(Clone, Copy)]
enum Failure {
    Native,
    Payment(usize),
    Source,
    Join(usize),
    Funding,
    Root,
    Order,
}

/// Retains only actual upper semantic results; no native owner is copied here.
#[derive(Default)]
pub(crate) struct CacheHeldUpperProgressV1 {
    started: bool,
    producing: bool,
    first: Option<Failure>,
    payment: [Option<Result<(), ResourceReservationErrorV1>>; 2],
    source: Option<Result<(), ResourceReservationErrorV1>>,
    lane: Option<[u8; 16]>,
    joins: [Option<Result<(), ResourceReservationErrorV1>>; 5],
    funding: Option<Result<(), ResourceReservationErrorV1>>,
    order: Option<ResourceReservationErrorV1>,
    terminal: Option<Box<terminal::CacheTerminalOriginalsV1>>,
    root: Option<Result<(), ResourceReservationErrorV1>>,
}

impl CacheHeldUpperProgressV1 {
    pub(super) fn failure<'cause>(
        &'cause self,
        native: &'cause aos_sandbox_cache::CacheResidentInitializationV1,
    ) -> Option<&'cause (dyn Error + 'static)> {
        match self.first {
            Some(Failure::Native) => native.failure(),
            Some(Failure::Payment(index)) => error(&self.payment[index]),
            Some(Failure::Source) => error(&self.source),
            Some(Failure::Join(index)) => error(&self.joins[index]),
            Some(Failure::Funding) => error(&self.funding),
            Some(Failure::Root) => self.terminal.as_deref()
                .and_then(|terminal| terminal.failure(native.failure())).or_else(|| error(&self.root)),
            Some(Failure::Order) => self.order.as_ref().map(|cause| cause as _),
            None => None,
        }
    }

    fn fail(&mut self, failure: Failure) {
        self.first.get_or_insert(failure);
    }

    fn refuse(&mut self) {
        self.order.get_or_insert(ResourceReservationErrorV1::Conflict);
        self.fail(Failure::Order);
    }
}

/// Holds the actual native Cache and the upper CreateStorage results together.
///
/// Only the single resident initializer constructs this loan. Its native half
/// retains the original armed-clock abort law across every upper error.
pub(crate) struct OriginalCreateStorageCacheLoanV1<'cache> {
    pub(crate) native: NativeCreateStorageCacheLoanV1<'cache>,
    progress: &'cache mut CacheHeldUpperProgressV1,
}

impl CacheResidentInitializationV1 {
    pub(crate) fn borrow_create_storage_cache_once<'cache>(
        &'cache mut self,
        owner: &'cache mut CacheResidencyProtectedOwnerV1,
        physical: &'cache DormantCacheOwnerV1,
    ) -> Result<OriginalCreateStorageCacheLoanV1<'cache>, CacheHeldClosedV1> {
        if self.create_storage_held.started {
            self.create_storage_held.refuse();
            return Err(CacheHeldClosedV1);
        }
        let native = self.native.borrow_create_storage_cache_once(owner, physical)?;
        self.create_storage_held.started = true;
        Ok(OriginalCreateStorageCacheLoanV1 {
            native,
            progress: &mut self.create_storage_held,
        })
    }
}

impl OriginalCreateStorageCacheLoanV1<'_> {
    pub(crate) fn failure(&self) -> Option<&(dyn Error + 'static)> {
        match self.progress.first {
            Some(Failure::Native) => self.native.failure(),
            Some(Failure::Payment(index)) => error(&self.progress.payment[index]),
            Some(Failure::Source) => error(&self.progress.source),
            Some(Failure::Join(index)) => error(&self.progress.joins[index]),
            Some(Failure::Funding) => error(&self.progress.funding),
            Some(Failure::Root) => self.progress.terminal.as_deref()
                .and_then(|terminal| terminal.failure(self.native.failure()))
                .or_else(|| error(&self.progress.root)),
            Some(Failure::Order) => self.progress.order.as_ref().map(|cause| cause as _),
            None => self.native.failure(),
        }
    }

    pub(crate) fn currentness_original_v1(&self) -> CacheHeldCurrentnessOriginalV1<'_> {
        self.native.currentness_original_v1()
    }

    pub(crate) fn original_identity_v1(&self) -> CacheHeldIdentityDataV1 {
        self.native.original_identity_v1()
    }

    pub(crate) fn original_q04_identity_data_v1(
        &self,
    ) -> Result<aos_sandbox_protocol::domain_ledger::create_q04_history::Q04CutIdentityV1, CacheHeldClosedV1> {
        self.native.original_q04_identity_data_v1()
    }

    pub(crate) fn require_same_controller_original_v1(
        &self,
        profile: &ProductionControllerNormalRootProfileV1,
    ) -> Result<(), ResourceReservationErrorV1> {
        self.native.currentness_original_v1()
            .require_same_controller_original_v1(profile.lower_original_v1())
            .map_err(|_| ResourceReservationErrorV1::Conflict)
    }

    pub(crate) fn source_held_bytes_v1(
        &self,
    ) -> Result<&[u8; SOURCE_HELD_RECEIPT_BYTES_V1], CacheHeldClosedV1> {
        self.native.source_held_bytes_v1()
    }

    pub(crate) fn currentness_site_v1(&self) -> Result<CacheHeldCurrentnessSiteV1, CacheHeldClosedV1> {
        self.native.currentness_site_v1()
    }

    pub(crate) fn fixed_receiving_demand_v1(&self) -> Result<ResourceVector, CacheHeldErrorV1> {
        let native = self.native.fixed_receiving_demand_v1()?;
        let upper = crate::Journal::cache_audit_source_original_receiving_bytes_v1()
            .and_then(|bytes| bytes.checked_add(
                CreateStorageOriginalLoanV1::cache_audit_funding_forwarding_bytes_v1()?,
            ))
            .and_then(|bytes| bytes.checked_add(std::mem::size_of::<Self>()
                .checked_sub(std::mem::size_of::<NativeCreateStorageCacheLoanV1<'_>>())?))
            .and_then(|bytes| bytes.checked_add(std::mem::size_of::<(
                Result<(), ResourceReservationErrorV1>,
                Result<(), ResourceReservationErrorV1>,
                Result<(), CacheHeldClosedV1>,
                CacheHeldCurrentnessOriginalV1<'_>,
            )>()))
            // The outer append closure encloses the shared schedule's
            // primary closure. Both have constructor and FnOnce receiver
            // planes; the inner one additionally captures its guard slot.
            .and_then(|bytes| bytes.checked_add(std::mem::size_of::<(
                (
                    &mut aos_sandbox_cache::CacheHeldAppendContextV1<'_, '_, '_>,
                    &Arc<JournalTransaction>,
                    &mut aos_sandbox_cache::CacheHeldAppendGateV1,
                    &mut CreateStorageOriginalLoanV1<'_>,
                    &mut CacheHeldUpperProgressV1,
                ),
                (
                    &mut aos_sandbox_cache::CacheHeldAppendContextV1<'_, '_, '_>,
                    &JournalTransaction,
                    &mut aos_sandbox_cache::CacheHeldAppendGateV1,
                    &mut CreateStorageOriginalLoanV1<'_>,
                    &mut CacheHeldUpperProgressV1,
                    &mut Option<aos_sandbox_cache::CacheHeldAppendGuardV1>,
                ),
            )>().checked_mul(2)?))
            .ok_or(CacheHeldErrorV1::Order)?;
        native.checked_add(ResourceVector::ZERO.with(
            ResourceDimension::MemoryBytes,
            u64::try_from(upper).map_err(|_| CacheHeldErrorV1::Order)?,
        )).map_err(Into::into)
    }

    pub(crate) fn capture_receiving_shape_once(
        &mut self,
    ) -> Result<&CacheCreateStorageReceivingShapeV1, CacheHeldClosedV1> {
        let result = self.native.capture_receiving_shape_once();
        if result.is_err() {
            self.progress.fail(Failure::Native);
        }
        result
    }

    pub(crate) fn held_body_data_v1(&self) -> Result<&CacheHeldBodyDataV1, CacheHeldClosedV1> {
        self.require_upper_positive()?;
        self.native.held_body_data_v1()
    }

    pub(crate) fn held_receipt_data_v1(&self) -> Result<CacheHeldReceiptDataV1<'_>, CacheHeldClosedV1> {
        self.require_upper_positive()?;
        self.native.held_receipt_data_v1()
    }

    fn require_upper_positive(&self) -> Result<(), CacheHeldClosedV1> {
        if self.progress.first.is_some() {
            Err(CacheHeldClosedV1)
        } else {
            Ok(())
        }
    }
}

impl<'cache> OriginalCreateStorageCacheLoanV1<'cache> {
    pub(crate) fn bind_release_audit_funding_v1<'funding, 'profile>(
        &self,
        original: aos_sandbox_broker::controller_receiving::bank_launch::ControllerCreateStorageUseFundingLoanV1<'funding, 'profile>,
        source: &'funding aos_sandbox_broker::controller_receiving::ControllerSourceOriginalRefV1,
        non_cache: ResourceVector,
    ) -> Result<ControllerCacheAuditFundingLoanV1<'funding, 'profile>,
        aos_sandbox_broker::controller_receiving::bank_launch::ControllerCacheAuditFundingErrorV1>
    where 'cache: 'funding {
        use aos_sandbox_broker::controller_receiving::bank_launch::{ControllerBankLaunchErrorV1, ControllerCacheAuditFundingErrorV1};
        let closed = || ControllerCacheAuditFundingErrorV1::Native(ControllerBankLaunchErrorV1::Conflict);
        let fixed = released::release_upper_fixed_demand_v1().map_err(|_| closed())?;
        let semantic_supplement = crate::journal::cache_native_semantic_supplement_v1().map_err(|_| closed())?;
        self.native.bind_release_audit_funding_v1(original, source, Some(fixed), Some(semantic_supplement), non_cache)
    }

    pub(crate) fn borrow_pre_root_cut_v1(
        &mut self,
    ) -> Result<CacheHeldPreRootCutV1<'_, 'cache>, CacheHeldClosedV1> {
        self.require_upper_positive()?;
        if self.progress.joins[..4].iter().any(|result| !matches!(result, Some(Ok(()))))
            || !matches!(self.progress.payment, [Some(Ok(())), Some(Ok(()))])
        {
            return Err(CacheHeldClosedV1);
        }
        self.native.borrow_pre_root_cut_v1()
    }

    pub(crate) fn node_quotas_for_bundle_v1(
        &self,
    ) -> Result<&[aos_sandbox_protocol::cache_state::NodeCacheQuotaV1], CacheHeldClosedV1> {
        self.require_upper_positive()?;
        self.native.node_quotas_for_bundle_v1()
    }

    // Only these two actual upper observers sit inside the lexical append
    // programme. Native failures and native posts are parked before this call;
    // no native error can suppress this already prepaid independent observer.
    fn append_pair_once(
        &mut self,
        original: &mut CreateStorageOriginalLoanV1<'_>,
    ) {
        let transaction = match self.native.append_transaction_data_v1() {
            Ok(transaction) => Arc::clone(transaction),
            Err(_) => {
                self.progress.fail(Failure::Native);
                return;
            }
        };
        let funding = original.borrow_initial_cache_audit_funding_v1(&self.native);
        let mut funding = match funding {
            Ok(funding) => funding,
            Err(cause) => {
                self.progress.funding = Some(Err(cause));
                self.progress.fail(Failure::Funding);
                return;
            }
        };
        let context = self.native.begin_held_append_once_v1(&transaction, &mut funding);
        // The native context retains no mutable J/U borrower through the
        // independent upper observer. These exact real originals stay upper.
        drop(funding);
        let (mut context, mut gate) = match context {
            Ok(context) => context,
            Err(_) => {
                self.progress.fail(Failure::Native);
                return;
            }
        };

        let native_transition = context.observe_transition_native_once_v1();
        if native_transition.is_err() {
            self.progress.fail(Failure::Native);
        }
        self.progress.joins[1] = Some(
            original.require_cache_capture_current(&context.currentness_original_v1()),
        );
        if matches!(self.progress.joins[1], Some(Err(_))) {
            self.progress.fail(Failure::Join(1));
            context.reject_upper_currentness_v1();
        }

        let result = (|| {
            context.finish_transition_once_v1()?;
            let transaction = transaction.as_ref();
            aos_sandbox_broker::run_canonical_semantic_append_v1! {
                ordinary,
                context: context,
                transaction: transaction,
                gate: gate,
                boundary: aos_sandbox_cache::CacheJournalErrorV1::boundary_data_v1(),
                coordinates: (materialized_bytes, commit_sequence, following_sequence, durable_bytes),
                preflight: {
                    context.preflight_native_once_v1(materialized_bytes, following_sequence)?;
                },
                final_crossing: {
                    let native_final = context.observe_final_native_once_v1();
                    if native_final.is_err() {
                        self.progress.fail(Failure::Native);
                    }
                    self.progress.joins[2] = Some(
                        original.require_cache_capture_current(&context.currentness_original_v1()),
                    );
                    if matches!(self.progress.joins[2], Some(Err(_))) {
                        self.progress.fail(Failure::Join(2));
                        context.reject_upper_currentness_v1();
                    }
                    context.finish_final_crossing_once_v1()?;
                },
                durable_check: {},
                published: {},
                completed: {
                    Ok(CommitResult { commit_sequence, durable_bytes })
                },
            }
        })();
        if context.retain_result_once_v1(result).is_err() {
            self.progress.fail(Failure::Native);
        }
    }
}

fn error<T, E: Error + 'static>(
    slot: &Option<Result<T, E>>,
) -> Option<&(dyn Error + 'static)> {
    slot.as_ref().and_then(|result| result.as_ref().err()).map(|cause| cause as _)
}



impl OriginalCreateStorageCacheLoanV1<'_> {
    /// Produces the original Held stage under the same real J and Cache loans.
    ///
    /// All Controller/Source/profile/clock observations stay upper. Each
    /// native body cause is selected before its independently owed upper post;
    /// later posts cannot replace the original selected cause.
    ///
    /// # Errors
    /// Retains actual admission, Source, native, append and original-post debt.
    pub(crate) fn produce_held_once(
        &mut self,
        original: &mut CreateStorageOriginalLoanV1<'_>,
    ) -> Result<(), CacheHeldClosedV1> {
        if self.progress.producing || self.progress.first.is_some() {
            self.progress.refuse();
            return Err(CacheHeldClosedV1);
        }
        self.native.begin_production_once_v1()?;
        self.progress.producing = true;

        self.progress.payment[0] = Some(original.admit_cache_fixed_once(self));
        if matches!(self.progress.payment[0], Some(Err(_))) {
            self.progress.fail(Failure::Payment(0));
        }
        self.require_upper_positive()?;

        self.progress.payment[1] = Some(original.admit_cache_capture(self));
        if matches!(self.progress.payment[1], Some(Err(_))) {
            self.progress.fail(Failure::Payment(1));
        }
        if self.progress.first.is_some() {
            self.observe_posts_once(aos_sandbox_cache::CacheHeldPostSiteV1::Capture);
            return Err(CacheHeldClosedV1);
        }

        // This is the same checked lane of the still-live original J. It is
        // retained as comparison DATA, never as a phase or append authorizer.
        self.progress.source = Some((|| {
            let lane = original.create_storage_lane_v1()?;
            let receipt = original.source_held_data_v1()?;
            self.progress.lane = Some(lane);
            if self.native.capture_source_held_data_once_v1(receipt, lane).is_err() {
                self.progress.fail(Failure::Native);
            }
            Ok(())
        })());
        if matches!(self.progress.source, Some(Err(_))) {
            self.progress.fail(Failure::Source);
        }
        self.join_once(original, 0, CacheHeldCurrentnessSiteV1::BeforeCapture);

        if self.progress.first.is_none() {
            self.audit_set_once(original, 0);
        }
        if self.progress.first.is_none() {
            if let Some(lane) = self.progress.lane {
                self.native.capture_selection_once_v1(lane);
                self.select_native_failure();
            } else {
                self.progress.refuse();
            }
        }
        self.observe_posts_once(aos_sandbox_cache::CacheHeldPostSiteV1::Capture);
        self.require_upper_positive()?;

        if let Some(lane) = self.progress.lane {
            self.native.encode_pair_once_v1(lane);
            self.select_native_failure();
        } else {
            self.progress.refuse();
        }
        if self.progress.first.is_none() {
            self.admit_append_once(original);
        }
        if self.progress.first.is_none() {
            self.append_pair_once(original);
        }
        if self.progress.first.is_none() {
            self.native.capture_returned_pair_once_v1();
            self.select_native_failure();
        }
        if self.progress.first.is_none() {
            self.audit_set_once(original, 5);
        }
        self.observe_posts_once(aos_sandbox_cache::CacheHeldPostSiteV1::Append);
        self.join_once(original, 3, CacheHeldCurrentnessSiteV1::AfterAppend);
        self.require_upper_positive()?;
        self.held_receipt_data_v1().map(|_| ())
    }

    fn select_native_failure(&mut self) {
        if self.native.failure().is_some() {
            self.progress.fail(Failure::Native);
        }
    }

    fn observe_posts_once(&mut self, site: aos_sandbox_cache::CacheHeldPostSiteV1) {
        if !self.native.original_post_observed_data_v1(site) {
            let _ = self.native.observe_original_posts_once_v1(site);
        }
        self.select_native_failure();
    }

    fn join_once(
        &mut self,
        original: &mut CreateStorageOriginalLoanV1<'_>,
        index: usize,
        site: CacheHeldCurrentnessSiteV1,
    ) {
        if self.progress.joins[index].is_some() {
            self.progress.refuse();
            return;
        }
        self.native.select_currentness_site_v1(site);
        self.progress.joins[index] = Some(
            original.require_cache_capture_current(&self.native.currentness_original_v1()),
        );
        if matches!(self.progress.joins[index], Some(Err(_))) {
            self.progress.fail(Failure::Join(index));
        }
    }

    fn audit_set_once(
        &mut self,
        original: &mut CreateStorageOriginalLoanV1<'_>,
        first: usize,
    ) {
        let funding = original.borrow_initial_cache_audit_funding_v1(&self.native);
        let mut funding = match funding {
            Ok(funding) => funding,
            Err(cause) => {
                self.progress.funding = Some(Err(cause));
                self.progress.fail(Failure::Funding);
                return;
            }
        };
        let result = self.native.audit_initial_set_once_v1(&mut funding, first);
        drop(funding);
        if result.is_err() {
            self.progress.fail(Failure::Native);
        }
    }

    fn admit_append_once(&mut self, original: &mut CreateStorageOriginalLoanV1<'_>) {
        let funding = original.borrow_initial_cache_audit_funding_v1(&self.native);
        let mut funding = match funding {
            Ok(funding) => funding,
            Err(cause) => {
                self.progress.funding = Some(Err(cause));
                self.progress.fail(Failure::Funding);
                return;
            }
        };
        self.native.admit_append_once_v1(&mut funding);
        drop(funding);
        self.select_native_failure();
    }
}
