//! Encodes complete B from the same genuine Native and authenticated originals.
//!
//! The exact completed Inventory, signed HELLOs and terminal predecessor stay
//! on their original Session. Native owns the sole J ledger and the actual
//! Controller/Source/Cache association. This owner adds only a checked proposal
//! encoding; its successful bytes are never Root validation or Prepare authority.

use std::collections::TryReserveError;
use std::error::Error;
use std::mem::size_of;

use aos_sandbox_controller_domain::{CreateStorageBundleClosedV1, CreateStorageBundleShapeDataV1,
    CreateStorageReadyNativeInputsV1, OriginalCreateStorageBundleV1};
use aos_sandbox_model::{ObjectDigest, OperationId};
use aos_sandbox_protocol::cache_state::{NodeCacheQuotaV1, complete_node_quotas::{
    CompleteNodeQuotaDataErrorV1, complete_node_quota_rows_encoded_bytes_v1,
    encode_complete_node_quota_rows_v1,
}};
use aos_sandbox_protocol::domain_ledger::create_storage_history::{HistoryErrorV1,
    ready::{ControllerAdmissionDataV1, ReadyBundleDataV1}};
use aos_sandbox_protocol::semantics::{CatalogBindingV1, StorageSemanticsError};
use aos_sandbox_protocol::semantics::storage_prepare::{
    ProtectedStorageCreatePreparationV1, StoragePreparationSemanticsError,
};

use super::*;

#[derive(Clone, Copy)]
enum BundleFailureSite {
    Fixed,
    BeforeNative,
    ReplayAdmission,
    BeforeSecurity,
    Build,
    EncodingAdmission,
    Output,
    AfterSecurity,
    AfterNative,
    Completion,
    Closed,
}

#[derive(Debug, thiserror::Error)]
enum BundleBuildError {
    #[error(transparent)]
    Security(#[from] BrokerSessionSecurityError),
    #[error(transparent)]
    History(#[from] HistoryErrorV1),
    #[error(transparent)]
    Quota(#[from] CompleteNodeQuotaDataErrorV1),
    #[error(transparent)]
    Catalog(#[from] StorageSemanticsError),
    #[error(transparent)]
    Preparation(#[from] StoragePreparationSemanticsError),
    #[error(transparent)]
    Allocation(#[from] TryReserveError),
    #[error(transparent)]
    Assignment(#[from] aos_sandbox_model::InvalidBrokerAuthorizationPlan),
    #[error("original Create bundle inputs changed or exceeded their checked width")]
    Shape,
}

/// Reports a failed proposal encoding while its complete originals stay held.
#[doc(hidden)]
#[derive(Debug, thiserror::Error)]
#[error("original Create Ready bundle is closed with its originals retained")]
pub struct CreateStorageReadyBundleClosedV1;

/// Retains the exact complete proposal B and its independent observations.
///
/// Empty construction allocates nothing. The installed caller keeps this flight,
/// the same authenticated Inventory and Session, and genuine joined Ready
/// borrower resident through any failure and its service fence. Successful
/// encoding permits only borrowing proposal bytes for the actual Root exchange.
#[doc(hidden)]
#[must_use = "retain the actual full bundle flight beside the joined Ready and Session"]
pub struct OriginalStorageReadyBundleFlightV1 {
    fixed: Option<Result<(), CreateStorageBundleClosedV1>>,
    fixed_preparation: Option<Result<(), CreateStorageBundleClosedV1>>,
    before_recipe: Option<Result<(), BrokerSessionSecurityError>>,
    before_native: Option<Result<(), CreateStorageBundleClosedV1>>,
    replay_recipe: Option<Result<(), BrokerSessionSecurityError>>,
    replay_preparation: Option<Result<(), CreateStorageBundleClosedV1>>,
    before_originals: Option<Box<crate::recovery::OutcomeCurrentOriginalsV1>>,
    before_security: Option<Result<(), BrokerSessionSecurityError>>,
    build: Option<Result<usize, BundleBuildError>>,
    encoding_admission: Option<Result<(), CreateStorageBundleClosedV1>>,
    output: Option<Result<(), BundleBuildError>>,
    after_originals: Option<Box<crate::recovery::OutcomeCurrentOriginalsV1>>,
    after_security: Option<Result<(), BrokerSessionSecurityError>>,
    after_recipe: Option<Result<(), BrokerSessionSecurityError>>,
    after_native: Option<Result<(), CreateStorageBundleClosedV1>>,
    completion: Option<Result<(), CreateStorageBundleClosedV1>>,
    quotas: Vec<NodeCacheQuotaV1>,
    quota_bytes: Vec<u8>,
    intent_native: [u8; 104],
    admission: Vec<u8>,
    proposed: Option<ProtectedStorageCreatePreparationV1>,
    encoded: Vec<u8>,
    first: Option<BundleFailureSite>,
    completed: bool,
}

impl OriginalStorageReadyBundleFlightV1 {
    /// Constructs empty fixed custody without IO, allocation or authority.
    #[doc(hidden)]
    #[must_use]
    pub fn empty() -> Self {
        Self {
            fixed: None, fixed_preparation: None,
            before_recipe: None, before_native: None,
            replay_recipe: None, replay_preparation: None,
            before_originals: None,
            before_security: None,
            build: None, encoding_admission: None, output: None,
            after_originals: None,
            after_security: None, after_recipe: None, after_native: None,
            completion: None, quotas: Vec::new(), quota_bytes: Vec::new(),
            intent_native: [0; 104], admission: Vec::new(), proposed: None,
            encoded: Vec::new(), first: None, completed: false,
        }
    }

    fn shape() -> Option<CreateStorageBundleShapeDataV1> {
        // Self includes the inline receipt, Vec/Result headers and actual model.
        // The temporary Native views and frame coexist with this resident flight.
        let (replay_bytes, replay_cells) = crate::recovery::OutcomeCurrentOriginalsV1::boxed_receiving_footprint_v2()?;
        let flight_bytes = size_of::<Self>()
            .checked_add(2 * size_of::<CreateStorageReadyNativeInputsV1<'static>>())?
            .checked_add(size_of::<ReadyBundleDataV1<'static>>())?
            .checked_add(ProtectedStorageCreatePreparationV1::encoding_capacity_bytes_v1())?
            .checked_add(replay_bytes.checked_mul(2)?)?;
        // Fourteen direct Results (including recipe/receiving admission), five
        // Vec backings and one first-cause latch coexist. Both complete nested
        // validation capsules have a separate actual metadata census.
        let flight_cells = 20_usize.checked_add(replay_cells.checked_mul(2)?)?;
        Some(CreateStorageBundleShapeDataV1 { flight_bytes, flight_cells,
            // Actual before and owed-after capsules remain distinct owners.
            endpoint_open_files: crate::recovery::OutcomeCurrentOriginalsV1::
                retained_endpoint_open_files_v1()?.checked_mul(2)?,
        })
    }

    pub(crate) fn encode_once(&mut self,
        session: &mut DormantAuthenticatedBrokerSessionV1,
        inventory: &OriginalStorageInventoryClientFlightV1,
        original: &mut OriginalCreateStorageBundleV1<'_, '_, '_>)
        -> Result<(), CreateStorageReadyBundleClosedV1>
    {
        if self.fixed.is_some()
            || self.first.is_some()
            || self.completed
            || self.before_originals.is_some()
            || self.after_originals.is_some()
        {
            self.mark(BundleFailureSite::Closed);
            return Err(CreateStorageReadyBundleClosedV1);
        }

        let Some(shape) = Self::shape() else {
            self.mark(BundleFailureSite::Closed);
            return Err(CreateStorageReadyBundleClosedV1);
        };
        self.fixed = Some(original.admit_fixed_once(shape));
        if self.fixed.as_ref().is_some_and(Result::is_err) {
            self.mark(BundleFailureSite::Fixed);
            return Err(CreateStorageReadyBundleClosedV1);
        }
        self.fixed_preparation = Some(original.require_fixed_preparation_v1(shape));
        if self.fixed_preparation.as_ref().is_some_and(Result::is_err) {
            self.mark(BundleFailureSite::Fixed);
            return Err(CreateStorageReadyBundleClosedV1);
        }

        // Both destinations are funded and checked empty before either
        // native/security primary. A refused before still owes its own after.
        self.before_originals = Some(Box::new(Default::default()));
        self.after_originals = Some(Box::new(Default::default()));

        self.observe_native(session, original, false);
        if self.first.is_none() {
            self.replay_preparation = Some(match session.owner.retained_storage_client_journal_v1() {
                Ok(journal) => {
                    self.replay_recipe = Some(Ok(()));
                    original.admit_retained_validation_once(journal)
                }
                Err(cause) => {
                    self.replay_recipe = Some(Err(cause));
                    Err(CreateStorageBundleClosedV1)
                }
            });
            if !matches!(self.replay_preparation, Some(Ok(()))) {
                self.mark(BundleFailureSite::ReplayAdmission);
            }
        }
        if matches!(self.replay_preparation, Some(Ok(()))) {
            self.before_security = Some(
                self.before_originals
                    .as_deref_mut()
                    .ok_or(BrokerSessionSecurityError::Currentness)
                    .and_then(|originals| Self::observe_security(session, inventory, original, originals)),
            );
            if self.before_security.as_ref().is_some_and(Result::is_err) {
                self.mark(BundleFailureSite::BeforeSecurity);
            }
            if self.first.is_none() {
                self.build = Some(self.prepare_fields(session, inventory, original));
                if self.build.as_ref().is_some_and(Result::is_err) {
                    self.mark(BundleFailureSite::Build);
                }
            }
            if let Some(Ok(width)) = self.build.as_ref() {
                self.encoding_admission = Some(original.admit_encoding_once(*width));
                if self.encoding_admission.as_ref().is_some_and(Result::is_err) {
                    self.mark(BundleFailureSite::EncodingAdmission);
                }
            }
            if self.first.is_none() {
                self.output = Some(self.encode_output(session, inventory, original));
                if self.output.as_ref().is_some_and(Result::is_err) {
                    self.mark(BundleFailureSite::Output);
                }
            }

            // Both complete canonical destinations were paid before the first
            // primary. A later model/encoding/refusal still owes this after cut.
            self.after_security = Some(
                self.after_originals
                    .as_deref_mut()
                    .ok_or(BrokerSessionSecurityError::Currentness)
                    .and_then(|originals| Self::observe_security(session, inventory, original, originals)),
            );
            if self.after_security.as_ref().is_some_and(Result::is_err) {
                self.mark(BundleFailureSite::AfterSecurity);
            }
        }
        // Fixed admission prepays this independent Native lane even when the
        // variable canonical replay roster refused before entering Security.
        self.observe_native(session, original, true);
        if self.first.is_none() {
            self.completion = Some(original.finish_encoded_once(&self.encoded));
            if self.completion.as_ref().is_some_and(Result::is_err) {
                self.mark(BundleFailureSite::Completion);
            }
        }
        if self.first.is_some() {
            Err(CreateStorageReadyBundleClosedV1)
        } else {
            self.completed = true;
            Ok(())
        }
    }

    fn observe_native(&mut self, session: &mut DormantAuthenticatedBrokerSessionV1,
        original: &mut OriginalCreateStorageBundleV1<'_, '_, '_>, after: bool)
    {
        let observed = match session.owner.retained_storage_client_journal_v1() {
            Ok(journal) => {
                if after {
                    self.after_recipe = Some(Ok(()));
                    original.observe_after_once(journal, &session.socket, &session.transcript)
                } else {
                    self.before_recipe = Some(Ok(()));
                    original.observe_before_once(journal, &session.socket, &session.transcript)
                }
            }
            Err(cause) => {
                if after { self.after_recipe = Some(Err(cause)); }
                else { self.before_recipe = Some(Err(cause)); }
                Err(CreateStorageBundleClosedV1)
            }
        };
        let failed = observed.is_err();
        if after { self.after_native = Some(observed); }
        else { self.before_native = Some(observed); }
        if failed {
            self.mark(if after { BundleFailureSite::AfterNative } else { BundleFailureSite::BeforeNative });
        }
    }

    fn observe_security(session: &mut DormantAuthenticatedBrokerSessionV1,
        inventory: &OriginalStorageInventoryClientFlightV1,
        original: &OriginalCreateStorageBundleV1<'_, '_, '_>,
        originals: &mut crate::recovery::OutcomeCurrentOriginalsV1)
        -> Result<(), BrokerSessionSecurityError>
    {
        original.require_retained_validation_prepaid_v1()
            .map_err(|_| BrokerSessionSecurityError::Currentness)?;
        session.owner.require_original_storage_revalidation_healthy()?;
        if !session.owner.healthy_original_storage_floor_revalidation_v1() {
            return Err(BrokerSessionSecurityError::Currentness);
        }
        inventory.compare_bundle_predecessor_v1(session, originals)
    }

    fn prepare_fields(&mut self, session: &DormantAuthenticatedBrokerSessionV1,
        inventory: &OriginalStorageInventoryClientFlightV1,
        original: &OriginalCreateStorageBundleV1<'_, '_, '_>)
        -> Result<usize, BundleBuildError>
    {
        let native = original.native_inputs_v1().map_err(|_| BundleBuildError::Shape)?;
        let model = inventory.bundle_model_v1()?;
        let digest: [u8; 32] = model.lifecycle_catalog_head.as_slice().try_into()
            .map_err(|_| BundleBuildError::Shape)?;
        // The actual trusted journal Inventory uses the physical lifecycle
        // binding for BOTH inputs. Workspace generation and immutable source
        // identity remain separate fields; neither is a substitute for this head.
        let binding = CatalogBindingV1::from_publisher(model.lifecycle_catalog_generation,
            ObjectDigest::from_bytes(digest))?;
        self.proposed = Some(ProtectedStorageCreatePreparationV1::from_protected_inputs(
            native.manifest.broker_assignment()?, OperationId::from_bytes(native.operation),
            native.proposed_quota_bytes, native.proposed_reservation_bytes,
            binding, binding, native.proposed_expires_boottime_nanoseconds)?);
        self.quotas.try_reserve_exact(native.cache_node_quotas.len())?;
        self.quotas.extend_from_slice(native.cache_node_quotas);
        self.quotas.sort_unstable_by_key(|quota| quota.partition.digest());
        let quota_width = complete_node_quota_rows_encoded_bytes_v1(self.quotas.len())?;
        self.quota_bytes.try_reserve_exact(quota_width)?;
        self.quota_bytes.resize(quota_width, 0);
        encode_complete_node_quota_rows_v1(&self.quotas, &mut self.quota_bytes)?;
        self.intent_native = native.intent_native_receipt.encode()?;
        let admission = ControllerAdmissionDataV1 {
            controller: native.controller_head, sandbox: native.sandbox_head,
            intake: native.intake_claim,
        };
        let width = admission.encoded_bytes()?;
        self.admission.try_reserve_exact(width)?;
        self.admission.resize(width, 0);
        admission.encode_into(&mut self.admission)?;
        self.frame(&native, session, inventory)?.encoded_bytes().map_err(BundleBuildError::from)
    }

    fn encode_output(&mut self, session: &DormantAuthenticatedBrokerSessionV1,
        inventory: &OriginalStorageInventoryClientFlightV1,
        original: &OriginalCreateStorageBundleV1<'_, '_, '_>)
        -> Result<(), BundleBuildError>
    {
        let width = self.build.as_ref().and_then(|value| value.as_ref().ok()).copied()
            .ok_or(BundleBuildError::Shape)?;
        self.encoded.try_reserve_exact(width)?;
        self.encoded.resize(width, 0);
        let native = original.native_inputs_v1().map_err(|_| BundleBuildError::Shape)?;
        // Split the output borrow from all immutable component borrows. The
        // actual output Vec stays on this owner even if framing refuses.
        let frame = Self::frame_from(&native, session, inventory, &self.intent_native,
            &self.quota_bytes, &self.admission, self.proposed.as_ref().ok_or(BundleBuildError::Shape)?)?;
        if frame.encoded_bytes()? != width { return Err(BundleBuildError::Shape); }
        frame.encode_into(&mut self.encoded)?;
        Ok(())
    }

    fn frame<'fields>(&'fields self, native: &'fields CreateStorageReadyNativeInputsV1<'fields>,
        session: &'fields DormantAuthenticatedBrokerSessionV1,
        inventory: &'fields OriginalStorageInventoryClientFlightV1)
        -> Result<ReadyBundleDataV1<'fields>, BundleBuildError>
    {
        Self::frame_from(native, session, inventory, &self.intent_native,
            &self.quota_bytes, &self.admission, self.proposed.as_ref().ok_or(BundleBuildError::Shape)?)
    }

    fn frame_from<'fields>(native: &'fields CreateStorageReadyNativeInputsV1<'fields>,
        session: &'fields DormantAuthenticatedBrokerSessionV1,
        inventory: &'fields OriginalStorageInventoryClientFlightV1,
        intent_native: &'fields [u8], quotas: &'fields [u8], admission: &'fields [u8],
        proposed: &'fields ProtectedStorageCreatePreparationV1)
        -> Result<ReadyBundleDataV1<'fields>, BundleBuildError>
    {
        Ok(ReadyBundleDataV1 {
            lane: native.lane, intent_record: native.intent_record,
            intent_native_receipt: intent_native, specification: native.specification,
            source_held: &native.source_held, cache_held: &native.cache_held,
            cache_node_quotas: quotas, assignment_planned: native.assignment_planned,
            ownership_begin_request: native.ownership_begin_request,
            ownership_begin_response: native.ownership_begin_response.unwrap_or(&[]),
            ownership_completed_request: native.ownership_completed_request,
            ownership_completed_response: native.ownership_completed_response,
            ownership_claim: native.ownership_claim, ownership_lease: native.ownership_lease,
            ownership_signature: native.ownership_signature, ownership_receipt: native.ownership_receipt,
            ownership_receipt_signature: native.ownership_receipt_signature,
            storage_client_hello: session.checkpoint.client_hello_bytes(),
            storage_broker_hello: session.checkpoint.broker_hello_bytes(),
            storage_inventory_request: inventory.bundle_request_v1()?,
            storage_inventory_response: inventory.bundle_response_v1()?,
            storage_inventory_checkpoint: session.owner.retained_storage_client_stored_v1()?,
            proposed_storage: proposed.canonical_bytes(), controller_admission: admission,
            policy_sources: native.policy_sources, compiler_origin: native.compiler_origin,
        })
    }

    fn mark(&mut self, site: BundleFailureSite) { self.first.get_or_insert(site); }

    /// Borrows the complete original proposal after every local encoding post.
    ///
    /// The bytes remain DATA. The same Ready, Cache, Source and authenticated
    /// Session must stay held through the actual Root exchange and its outcome.
    #[doc(hidden)]
    #[must_use]
    pub fn encoded_bundle_v1(&self) -> Option<&[u8]> {
        self.completed.then_some(self.encoded.as_slice())
    }

    // Borrows only the real model that produced these completed B bytes.
    // The genuine Ready separately checks the same complete B commitment.
    pub(crate) fn proposed_for_create_use_v1(&self) -> Option<&ProtectedStorageCreatePreparationV1> {
        self.encoded_bundle_v1()?;
        self.proposed.as_ref()
    }

    pub(crate) fn failure_with_original<'a>(&'a self,
        session: &'a DormantAuthenticatedBrokerSessionV1,
        original: &'a OriginalCreateStorageBundleV1<'_, '_, '_>)
        -> Option<&'a (dyn Error + 'static)>
    {
        self.failure_with_native(session, original.failure())
    }

    pub(crate) fn failure_with_native<'a>(
        &'a self,
        session: &'a DormantAuthenticatedBrokerSessionV1,
        native: Option<&'a (dyn Error + 'static)>,
    ) -> Option<&'a (dyn Error + 'static)> {
        let error = match self.first? {
            BundleFailureSite::Fixed => native,
            BundleFailureSite::BeforeNative => retained_error(&self.before_recipe).or_else(|| native),
            BundleFailureSite::ReplayAdmission => retained_error(&self.replay_recipe)
                .or_else(|| native),
            BundleFailureSite::BeforeSecurity => self.before_originals
                .as_deref()
                .and_then(|originals| originals.failure())
                .or_else(|| retained_error(&self.before_security)),
            BundleFailureSite::Build => retained_error(&self.build),
            BundleFailureSite::EncodingAdmission => native,
            BundleFailureSite::Output => retained_error(&self.output),
            BundleFailureSite::AfterSecurity => self.after_originals
                .as_deref()
                .and_then(|originals| originals.failure())
                .or_else(|| retained_error(&self.after_security)),
            BundleFailureSite::AfterNative => retained_error(&self.after_recipe).or_else(|| native),
            BundleFailureSite::Completion => native,
            BundleFailureSite::Closed => None,
        };
        error.map(|cause| {
            if let Some(returned) = cause.downcast_ref::<BrokerSessionSecurityError>() {
                session.owner.retained_revalidation_failure_for(returned)
                    .or_else(|| session.owner.retained_storage_floor_revalidation_failure_for(returned))
                    .unwrap_or(cause)
            } else { cause }
        }).or(Some(&CreateStorageReadyBundleClosedV1 as &(dyn Error + 'static)))
    }
}

fn retained_error<T, E: Error + 'static>(value: &Option<Result<T, E>>)
    -> Option<&(dyn Error + 'static)>
{
    value.as_ref().and_then(|value| value.as_ref().err()).map(|cause| cause as _)
}
