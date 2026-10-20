//! Retains the genuine J-paid authenticated Storage Inventory operation.
//!
//! This purpose borrows the same joined Create, held Cache and completed narrow
//! Client association. Security retains the actual signed request, native IO,
//! committed outcome and exact predecessor owner. These Native stages pay and
//! observe that operation; their completion alone is never an Inventory proof.

use std::error::Error;

use aos_sandbox_broker_session_protocol::{
    AUTHENTICATED_RESPONSE_MAXIMUM_BYTES, VerifiedBrokerSessionTranscriptV1,
};
use aos_sandbox_model::{ResourceDimension as D, ResourceVector};
use aos_sandbox_linux::seqpacket::{
    RetainedSeqpacketReceiveErrorV1, SeqpacketSocket, StorageSeqpacketSendAttemptV1,
};

use crate::cache_residency::OriginalCreateStorageCacheLoanV1;
use crate::controller_resource_reservation::q04_intake::CreateContinuationCaptureOwnerV1;
use crate::journal::broker_session_receiving::{
    StorageSessionGeometryRefusalV1, initialization_demand, operation_flight_demand,
    outcome_demand, storage_inventory_client_request_demand_v1, schema_demand,
    storage_inventory_client_response_decode_demand_v1,
};
use crate::journal::{JournalError, ProtectedJournalPreopenReplayExtentV1};
use super::cache_receiving::{
    CacheControlOriginalsV1, CacheCurrentnessOriginalV1, OriginalCacheAssociationV1,
};
use super::client_session::{
    ClientSessionAssociationErrorV1, CreateStorageEndpointRevalidationShapeDataV1,
};
use super::production::OriginalCreateStorageReadyV1;
use super::outcome_receiving::{OutcomeReplayReceivingOriginalsV1, OutcomeReplayRosterV1};
use super::*;

/// Reports a closed Inventory operation while all reached originals remain held.
#[doc(hidden)]
#[derive(Debug, thiserror::Error)]
#[error("original Create Storage Inventory is closed; its actual custody remains resident")]
pub struct CreateStorageInventoryClosedV1;

/// Describes only new private Inventory carriers in the installed Security caller.
///
/// The already-admitted Client Session and its same healthy endpoint archive stay
/// paid by their original owner. Their body is not charged again here. Security's
/// closed bridge checks this exact DATA against its real private types before
/// allocation or witness IO. This DATA contains no resource amount or payer.
#[doc(hidden)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CreateStorageInventoryShapeDataV1 {
    /// Actual newly retained private flight and its inline result slots.
    pub flight_bytes: usize,
    /// Actual additional retained validated Inventory/model owner header.
    pub inventory_owner_bytes: usize,
    /// Actual upper sender attempt's inline layout.
    pub send_original_bytes: usize,
    /// Actual additional boxed failure backing, excluding inline slots.
    pub failure_bytes: usize,
    /// Actual independently retained predecessor endpoint native destinations.
    pub predecessor_open_files: usize,
    /// Exact SAME resident Client endpoint archive footprint for comparison only.
    pub endpoint_revalidation: CreateStorageEndpointRevalidationShapeDataV1,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
enum Phase {
    #[default]
    Fresh,
    Admitted,
    Prepared,
    Preparing,
    Sending,
    Receiving,
    WaitingSend,
    WaitingReceive,
    Decode,
    Complete,
    Failed,
}

#[derive(Default)]
pub(in crate::controller_resource_reservation::create_intake) struct InventoryOriginalsV1 {
    phase: Phase,
    borrowed: bool,
    closed: Option<CreateStorageInventoryClosedV1>,
    association: Option<OriginalCacheAssociationV1>,
    upper_shape: Option<CreateStorageInventoryShapeDataV1>,
    peak: Option<Result<(), ResourceReservationErrorV1>>,
    shape_binding: Option<Result<(), ClientSessionAssociationErrorV1>>,
    geometry: Option<Result<ResourceVector, ResourceReservationErrorV1>>,
    fixed: Option<Result<(), ResourceReservationErrorV1>>,
    complete_bound: ResourceVector,
    preparation: InventoryCurrentnessV1,
    metadata: Option<std::io::Result<std::fs::Metadata>>,
    extent: Option<Result<ProtectedJournalPreopenReplayExtentV1, JournalError>>,
    schema: Option<Result<ResourceVector, StorageSessionGeometryRefusalV1>>,
    initialization: Option<Result<ResourceVector, StorageSessionGeometryRefusalV1>>,
    request: Option<Result<ResourceVector, StorageSessionGeometryRefusalV1>>,
    operation: Option<Result<ResourceVector, StorageSessionGeometryRefusalV1>>,
    variable: Option<Result<(), ResourceReservationErrorV1>>,
    capture_post: InventoryCurrentnessV1,
    turn_before: InventoryCurrentnessV1,
    turn_after: InventoryCurrentnessV1,
    turn_active: bool,
    request_prepared: bool,
    pending_send_binding: Option<Result<(), aos_sandbox_linux::seqpacket::RecordBindingError>>,
    pending_turns: u64,
    turn_funding: Option<Result<(), ResourceReservationErrorV1>>,
    decode_geometry: Option<Result<ResourceVector, StorageSessionGeometryRefusalV1>>,
    decode: Option<Result<(), ResourceReservationErrorV1>>,
    outcome_geometry: Option<Result<ResourceVector, StorageSessionGeometryRefusalV1>>,
    outcome: Option<Result<(), ResourceReservationErrorV1>>,
    predecessor_association: Option<Result<(), ClientSessionAssociationErrorV1>>,
    predecessor_receiving: OutcomeReplayReceivingOriginalsV1,
    completion: InventoryCurrentnessV1,
}

#[derive(Default)]
struct InventoryCurrentnessV1 {
    control: CacheCurrentnessOriginalV1,
    association: Option<Result<(), ClientSessionAssociationErrorV1>>,
}

impl InventoryCurrentnessV1 {
    fn failure(&self) -> Option<&(dyn Error + 'static)> {
        self.control.failure().or_else(|| error(&self.association))
    }
}

impl InventoryOriginalsV1 {
    fn close(&mut self) {
        self.phase = Phase::Failed;
        self.closed.get_or_insert(CreateStorageInventoryClosedV1);
    }

    pub(in crate::controller_resource_reservation::create_intake) fn failure(&self)
        -> Option<&(dyn Error + 'static)>
    {
        error(&self.peak).or_else(|| error(&self.shape_binding)).or_else(|| error(&self.geometry))
            .or_else(|| error(&self.fixed)).or_else(|| self.preparation.failure())
            .or_else(|| error(&self.metadata)).or_else(|| error(&self.extent))
            .or_else(|| error(&self.schema)).or_else(|| error(&self.initialization))
            .or_else(|| error(&self.request)).or_else(|| error(&self.operation))
            .or_else(|| error(&self.variable)).or_else(|| self.capture_post.failure())
            .or_else(|| self.turn_before.failure()).or_else(|| self.turn_after.failure())
            .or_else(|| error(&self.turn_funding)).or_else(|| error(&self.pending_send_binding)).or_else(|| error(&self.decode_geometry))
            .or_else(|| error(&self.decode)).or_else(|| error(&self.outcome_geometry))
            .or_else(|| error(&self.outcome))
            .or_else(|| error(&self.predecessor_association))
            .or_else(|| self.predecessor_receiving.failure())
            .or_else(|| self.completion.failure())
            .or_else(|| self.closed.as_ref().map(|cause| cause as &(dyn Error + 'static)))
    }
}

#[derive(Clone, Copy, Eq, PartialEq)]
enum StorageIoPurposeV1 { Inventory, Preparation }

impl StorageIoPurposeV1 {
    fn select<'a>(self, inventory: &'a InventoryOriginalsV1, preparation: &'a InventoryOriginalsV1)
        -> &'a InventoryOriginalsV1 {
        match self { Self::Inventory => inventory, Self::Preparation => preparation }
    }

    fn select_mut<'a>(self, inventory: &'a mut InventoryOriginalsV1, preparation: &'a mut InventoryOriginalsV1)
        -> &'a mut InventoryOriginalsV1 {
        match self { Self::Inventory => inventory, Self::Preparation => preparation }
    }

    fn reserve_complete(self, intake: &mut crate::controller_resource_reservation::q04_intake::Q04OriginalIntakeAttemptV1,
        reservation: &mut super::use_reserved::reservation::UseReservationOriginalsV1,
        paid: ResourceVector, reached: ResourceVector,
    ) -> Result<(), ResourceReservationErrorV1> {
        match self {
            Self::Inventory => intake.reserve_create_capture_complete(
                CreateContinuationCaptureOwnerV1::StorageInventory, reached),
            Self::Preparation => {
                let (_, additional) = aos_sandbox_model::component_receiving::complete_bound_delta_v1(paid, reached)?;
                reservation.receiving_mut_v1()?.reserve_once(additional)
            }
        }
    }
}

/// Borrows the actual joined originals for one purpose-fixed Inventory request.
///
/// Security must keep its actual Session and complete flight resident through
/// every failure and independent post. The borrower never accepts a broker
/// method, signs a caller envelope, exports a writer or authorizes Prepare.
#[doc(hidden)]
#[must_use = "retain the genuine Inventory borrower through its whole authenticated operation"]
pub struct OriginalCreateStorageInventoryV1<'turn, 'original, 'cache> {
    original: &'turn mut CreateStorageOriginalLoanV1<'original>,
    cache: &'turn mut OriginalCreateStorageCacheLoanV1<'cache>,
    completed: bool,
    purpose: StorageIoPurposeV1,
}

impl<'original, 'cache> OriginalCreateStorageReadyV1<'original, 'cache> {
    /// Borrows only the retained Native inventory cause for upper diagnostics.
    ///
    /// The caller combines this with its own chronological stage selector.
    /// This performs no IO, borrowing transition, admission or debt reset.
    #[doc(hidden)]
    #[must_use]
    pub fn inventory_original_failure_v1(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.original.owner.inventory.failure()
    }

    /// Borrows the original Inventory purpose after actual planned assignment.
    ///
    /// # Errors
    /// Refuses failed or incomplete joined originals, absent planned manifest,
    /// reentry, or an incomplete held Cache. This fixed entrance performs no IO.
    #[doc(hidden)]
    pub fn borrow_inventory_once<'turn>(&'turn mut self)
        -> Result<OriginalCreateStorageInventoryV1<'turn, 'original, 'cache>, CreateStorageInventoryClosedV1>
    {
        if self.failure().is_some() || self.original.owner.inventory.borrowed
            || self.original.owner.assignment.planned_manifest_v1().is_err() {
            return Err(CreateStorageInventoryClosedV1);
        }
        let association = self.original.owner.cache_capture.currentness_association_v1()
            .map_err(|_| CreateStorageInventoryClosedV1)?;
        let progress = &mut self.original.owner.inventory;
        progress.association = Some(association);
        progress.borrowed = true;
        Ok(OriginalCreateStorageInventoryV1 {
            original: &mut self.original, cache: &mut self.cache, completed: false, purpose: StorageIoPurposeV1::Inventory,
        })
    }
}

impl<'turn, 'original, 'cache> OriginalCreateStorageInventoryV1<'turn, 'original, 'cache> {
    /// Borrows the immutable original accepted cutoff as comparison DATA.
    ///
    /// # Errors
    /// Refuses a failed operation or an unavailable actual accepted parent.
    #[doc(hidden)]
    pub fn original_cutoff_data_v1(&self) -> Result<u64, CreateStorageInventoryClosedV1> {
        if self.failure().is_some() { return Err(CreateStorageInventoryClosedV1); }
        let accepted = self.original.accepted().map_err(|_| CreateStorageInventoryClosedV1)?.original_cutoff;
        if self.purpose == StorageIoPurposeV1::Inventory { return Ok(accepted); }
        self.original.owner.root_exchange.preparation_cutoff_v1()
            .map(|root| accepted.min(root)).map_err(|_| CreateStorageInventoryClosedV1)
    }

    /// Admits new private carriers, the raw receive peak and named post lanes.
    ///
    /// The same Client endpoint archive remains charged by that original owner;
    /// only its exact completed footprint is compared here. Actual packet bytes
    /// fund hostile decoding later, before the first outer-envelope decode.
    ///
    /// # Errors
    /// Retains changed endpoint geometry, arithmetic failure and J refusal.
    #[doc(hidden)]
    pub fn admit_fixed_once(&mut self, upper: CreateStorageInventoryShapeDataV1)
        -> Result<(), CreateStorageInventoryClosedV1>
    {
        let peak = self.original.require_operation_currentness_peak_v1(self.cache);
        let progress = self.purpose.select_mut(&mut self.original.owner.inventory, &mut self.original.owner.storage_use.io);
        if progress.phase != Phase::Fresh || progress.fixed.is_some() {
            progress.close();
            return Err(CreateStorageInventoryClosedV1);
        }
        progress.peak = Some(peak);
        progress.upper_shape = Some(upper);
        progress.shape_binding = Some(self.original.owner.client_session
            .require_completed_endpoint_shape_v1(upper.endpoint_revalidation));
        progress.geometry = Some(fixed_demand(upper));
        progress.fixed = Some((|| {
            if !matches!(progress.peak, Some(Ok(()))) || !matches!(progress.shape_binding, Some(Ok(()))) {
                return Err(ResourceReservationErrorV1::Conflict);
            }
            let demand = progress.geometry.as_ref().and_then(|value| value.as_ref().ok())
                .copied().ok_or(ResourceReservationErrorV1::Conflict)?;
            self.purpose.reserve_complete(&mut self.original.owner.intake,
                &mut self.original.owner.storage_use.reservation, progress.complete_bound, demand)?;
            progress.complete_bound = demand;
            Ok(())
        })());
        if matches!(progress.fixed, Some(Ok(()))) {
            progress.phase = Phase::Admitted;
            Ok(())
        } else {
            progress.close();
            Err(CreateStorageInventoryClosedV1)
        }
    }

    /// Checks Security's actual private footprint before its first allocation.
    ///
    /// # Errors
    /// Refuses a different actual footprint, failed originals or unpaid phase.
    #[doc(hidden)]
    pub fn require_fixed_endpoint_preparation_v1(&mut self, actual: CreateStorageInventoryShapeDataV1)
        -> Result<(), CreateStorageInventoryClosedV1>
    {
        let progress = self.purpose.select_mut(&mut self.original.owner.inventory, &mut self.original.owner.storage_use.io);
        if progress.phase != Phase::Admitted || progress.upper_shape != Some(actual)
            || progress.failure().is_some() {
            progress.close();
            return Err(CreateStorageInventoryClosedV1);
        }
        Ok(())
    }

    /// Captures the same held Session and prepays its actual schema/request work.
    ///
    /// This runs only after fixed payment. A later metadata, geometry or account
    /// refusal still executes its already-paid independent operation post.
    ///
    /// # Errors
    /// Retains actual metadata, completed Client association, genuine J and
    /// C/Source/Cache/profile/clock failures without replacing earlier causes.
    #[doc(hidden)]
    pub fn capture_session_once(&mut self, journal: &Journal, socket: &SeqpacketSocket,
        transcript: &VerifiedBrokerSessionTranscriptV1) -> Result<(), CreateStorageInventoryClosedV1>
    {
        if self.purpose.select(&self.original.owner.inventory, &self.original.owner.storage_use.io).phase != Phase::Admitted {
            self.purpose.select_mut(&mut self.original.owner.inventory, &mut self.original.owner.storage_use.io).close();
            return Err(CreateStorageInventoryClosedV1);
        }
        self.prepay_operation_observations_once(2)?;
        self.observe(journal, socket, transcript, Site::Preparation);
        let progress = self.purpose.select_mut(&mut self.original.owner.inventory, &mut self.original.owner.storage_use.io);
        if progress.preparation.failure().is_none() {
            let (metadata, limits) = journal.held_native_receiving_metadata_v1();
            progress.metadata = Some(metadata);
            if let Some(Ok(metadata)) = progress.metadata.as_ref() {
                progress.extent = Some(crate::journal::protected_journal_preopen_replay_extent_for_prefix_v1(
                    limits, metadata.len()));
            }
            if let Some(Ok(extent)) = progress.extent.as_ref() {
                progress.schema = Some(if self.purpose == StorageIoPurposeV1::Inventory {
                    schema_demand(extent)
                } else { Ok(ResourceVector::ZERO) });
                progress.initialization = Some(if self.purpose == StorageIoPurposeV1::Inventory {
                    initialization_demand(extent)
                } else { Ok(ResourceVector::ZERO) });
                // Sender/result headers are already in the actual flight's
                // fixed layout. The shared supplier adds only request/schema
                // representations and future append bytes here.
                progress.request = Some(if self.purpose == StorageIoPurposeV1::Inventory {
                    storage_inventory_client_request_demand_v1(extent)
                } else { Ok(ResourceVector::ZERO) });
                progress.operation = Some(if self.purpose == StorageIoPurposeV1::Inventory {
                    operation_flight_demand(transcript)
                } else { Ok(ResourceVector::ZERO) });
            }
            progress.variable = Some((|| {
                let complete = [
                    progress.schema.as_ref(), progress.initialization.as_ref(),
                    progress.request.as_ref(), progress.operation.as_ref(),
                ].into_iter().try_fold(progress.complete_bound, |sum, result| {
                    let value = result.and_then(|value| value.as_ref().ok())
                        .copied().ok_or(ResourceReservationErrorV1::Conflict)?;
                    sum.checked_add(value).map_err(|_| ResourceReservationErrorV1::Conflict)
                })?;
                self.purpose.reserve_complete(&mut self.original.owner.intake,
                    &mut self.original.owner.storage_use.reservation, progress.complete_bound, complete)?;
                progress.complete_bound = complete;
                Ok(())
            })());
        }
        self.observe(journal, socket, transcript, Site::CapturePost);
        let progress = self.purpose.select_mut(&mut self.original.owner.inventory, &mut self.original.owner.storage_use.io);
        if progress.failure().is_none() && matches!(progress.variable, Some(Ok(()))) {
            progress.phase = Phase::Prepared;
            if self.purpose == StorageIoPurposeV1::Preparation { progress.request_prepared = true; }
            Ok(())
        } else {
            progress.close();
            Err(CreateStorageInventoryClosedV1)
        }
    }

    /// Starts actual purpose-fixed request construction before signing or CAS.
    ///
    /// # Errors
    /// Refuses reentry, unfinished prior turn or failed originals. The caller
    /// still runs the prepaid after-turn post when this entered check refuses.
    #[doc(hidden)]
    pub fn begin_request_preparation_once(&mut self, journal: &Journal, socket: &SeqpacketSocket,
        transcript: &VerifiedBrokerSessionTranscriptV1) -> Result<(), CreateStorageInventoryClosedV1>
    {
        if self.purpose.select(&self.original.owner.inventory, &self.original.owner.storage_use.io).request_prepared {
            self.purpose.select_mut(&mut self.original.owner.inventory, &mut self.original.owner.storage_use.io).close();
            return Err(CreateStorageInventoryClosedV1);
        }
        self.begin_turn(journal, socket, transcript, Phase::Prepared, Phase::Preparing)
    }

    /// Starts the same request's actual retained send turn before native IO.
    ///
    /// # Errors
    /// Refuses another phase or failed same-original association.
    #[doc(hidden)]
    pub fn begin_send_once(&mut self, journal: &Journal, socket: &SeqpacketSocket,
        transcript: &VerifiedBrokerSessionTranscriptV1) -> Result<(), CreateStorageInventoryClosedV1>
    {
        if !self.purpose.select(&self.original.owner.inventory, &self.original.owner.storage_use.io).request_prepared {
            self.purpose.select_mut(&mut self.original.owner.inventory, &mut self.original.owner.storage_use.io).close();
            return Err(CreateStorageInventoryClosedV1);
        }
        self.begin_turn(journal, socket, transcript, Phase::Prepared, Phase::Sending)
    }

    /// Starts an actual receive of the SAME already-sent Inventory request.
    ///
    /// # Errors
    /// Refuses another phase, unfinished prior turn or failed originals.
    #[doc(hidden)]
    pub fn begin_receive_once(&mut self, journal: &Journal, socket: &SeqpacketSocket,
        transcript: &VerifiedBrokerSessionTranscriptV1) -> Result<(), CreateStorageInventoryClosedV1>
    {
        self.begin_turn(journal, socket, transcript, Phase::Receiving, Phase::Receiving)
    }

    /// Starts one actual readiness wait for the same pending send or receive.
    ///
    /// # Errors
    /// Refuses a foreign phase, unfinished prior turn or failed original. The
    /// same prepaid before/after destinations stay armed through the poll.
    #[doc(hidden)]
    pub fn begin_wait_once(&mut self, journal: &Journal, socket: &SeqpacketSocket,
        transcript: &VerifiedBrokerSessionTranscriptV1, wants_write: bool)
        -> Result<(), CreateStorageInventoryClosedV1>
    {
        let (expected, entered) = if wants_write {
            (Phase::Prepared, Phase::WaitingSend)
        } else {
            (Phase::Receiving, Phase::WaitingReceive)
        };
        self.begin_turn(journal, socket, transcript, expected, entered)
    }

    /// Keeps a completed readiness observation through its positive disposal.
    ///
    /// # Errors
    /// Refuses failed/incomplete posts or a nonwait phase. The selected caller
    /// must dispose its actual successful poll capsule before completing this
    /// exclusive phase; failed or abandoned observations remain sticky-closed.
    #[doc(hidden)]
    pub fn prepare_positive_wait_disposal_once<'phase>(&'phase mut self)
        -> Result<CreateStorageInventoryPendingDisposalV1<'phase, 'turn, 'original, 'cache>, CreateStorageInventoryClosedV1>
    {
        let resume = match self.purpose.select(&self.original.owner.inventory, &self.original.owner.storage_use.io).phase {
            Phase::WaitingSend => Phase::Prepared,
            Phase::WaitingReceive => Phase::Receiving,
            _ => {
                self.purpose.select_mut(&mut self.original.owner.inventory, &mut self.original.owner.storage_use.io).close();
                return Err(CreateStorageInventoryClosedV1);
            }
        };
        self.prepare_pending_disposal(resume)
    }

    fn begin_turn(&mut self, journal: &Journal, socket: &SeqpacketSocket,
        transcript: &VerifiedBrokerSessionTranscriptV1, expected: Phase, entered: Phase)
        -> Result<(), CreateStorageInventoryClosedV1>
    {
        let progress = self.purpose.select_mut(&mut self.original.owner.inventory, &mut self.original.owner.storage_use.io);
        if progress.phase != expected || progress.turn_active || progress.failure().is_some() {
            progress.close();
            return Err(CreateStorageInventoryClosedV1);
        }
        self.prepay_operation_observations_once(2)?;
        let progress = self.purpose.select_mut(&mut self.original.owner.inventory, &mut self.original.owner.storage_use.io);
        progress.turn_active = true;
        progress.phase = entered;
        self.observe(journal, socket, transcript, Site::TurnBefore);
        self.status()
    }

    /// Runs the independent after-IO post, including after native IO failure.
    ///
    /// This does not classify the upper IO result or dispose any native receipt.
    /// The closed Security caller keeps its complete flight beside this loan.
    ///
    /// # Errors
    /// Retains changed original/native/profile/clock association after the IO.
    #[doc(hidden)]
    pub fn observe_io_post_once(&mut self, journal: &Journal, socket: &SeqpacketSocket,
        transcript: &VerifiedBrokerSessionTranscriptV1) -> Result<(), CreateStorageInventoryClosedV1>
    {
        if !self.purpose.select(&self.original.owner.inventory, &self.original.owner.storage_use.io).turn_active {
            self.purpose.select_mut(&mut self.original.owner.inventory, &mut self.original.owner.storage_use.io).close();
            return Err(CreateStorageInventoryClosedV1);
        }
        self.observe(journal, socket, transcript, Site::TurnAfter);
        self.status()
    }

    /// Retains a positive turn's compact disposition after all actual posts.
    ///
    /// Security calls this only after a complete actual send or consumed receive;
    /// it retains that successful native receipt in its flight. No outcome or
    /// authorization is inferred from this local Native disposition.
    ///
    /// # Errors
    /// Refuses failed/incomplete independent posts or an unrelated phase.
    #[doc(hidden)]
    pub fn finish_positive_io_once(&mut self) -> Result<(), CreateStorageInventoryClosedV1> {
        let progress = self.purpose.select_mut(&mut self.original.owner.inventory, &mut self.original.owner.storage_use.io);
        if !progress.turn_active || progress.turn_after.association.is_none()
            || progress.failure().is_some() {
            progress.close();
            return Err(CreateStorageInventoryClosedV1);
        }
        let next = match progress.phase {
            Phase::Preparing => {
                progress.request_prepared = true;
                Phase::Prepared
            }
            Phase::Sending => Phase::Receiving,
            Phase::Receiving => Phase::Decode,
            _ => { progress.close(); return Err(CreateStorageInventoryClosedV1); }
        };
        // All successful native samples have completed their own disposal. Only
        // positive comparison DATA and Vec backing remain in these local slots.
        progress.turn_before = InventoryCurrentnessV1::default();
        progress.turn_after = InventoryCurrentnessV1::default();
        progress.turn_active = false;
        progress.turn_funding = None;
        progress.phase = next;
        Ok(())
    }

    /// Keeps this actual nonconsuming send through positive disposal posts.
    ///
    /// Security must drop the SAME retained upper receipt before consuming the
    /// returned phase. A partial/fatal send never obtains this phase.
    ///
    /// # Errors
    /// Refuses a consumed receipt, changed socket or any incomplete/failed post.
    #[doc(hidden)]
    pub fn prepare_pending_send_disposal_once<'phase>(
        &'phase mut self, receipt: &StorageSeqpacketSendAttemptV1,
        socket: &SeqpacketSocket,
    ) -> Result<CreateStorageInventoryPendingDisposalV1<'phase, 'turn, 'original, 'cache>, CreateStorageInventoryClosedV1> {
        let progress = self.purpose.select_mut(&mut self.original.owner.inventory, &mut self.original.owner.storage_use.io);
        if progress.phase != Phase::Sending || !receipt.is_nonconsuming() {
            progress.close();
            return Err(CreateStorageInventoryClosedV1);
        }
        progress.pending_send_binding = Some(receipt.require_same_socket(socket));
        self.prepare_pending_disposal(Phase::Prepared)
    }

    /// Keeps the actual initial recvmsg refusal through positive disposal posts.
    ///
    /// Only the lower receiver's no-sample EAGAIN/EINTR class can reach this
    /// method's disposal phase. Consumed previews and all partial errors remain
    /// resident and permanently close the actual operation.
    ///
    /// # Errors
    /// Refuses consumed/fatal receipt or incomplete/failed independent posts.
    #[doc(hidden)]
    pub fn prepare_pending_receive_disposal_once<'phase>(
        &'phase mut self, receipt: &RetainedSeqpacketReceiveErrorV1,
    ) -> Result<CreateStorageInventoryPendingDisposalV1<'phase, 'turn, 'original, 'cache>, CreateStorageInventoryClosedV1> {
        let progress = self.purpose.select_mut(&mut self.original.owner.inventory, &mut self.original.owner.storage_use.io);
        if progress.phase != Phase::Receiving
            || !(receipt.is_nonconsuming_would_block() || receipt.is_nonconsuming_interrupted()) {
            progress.close();
            return Err(CreateStorageInventoryClosedV1);
        }
        self.prepare_pending_disposal(Phase::Receiving)
    }

    fn prepare_pending_disposal(&mut self, resume: Phase)
        -> Result<CreateStorageInventoryPendingDisposalV1<'_, 'turn, 'original, 'cache>, CreateStorageInventoryClosedV1>
    {
        let progress = self.purpose.select_mut(&mut self.original.owner.inventory, &mut self.original.owner.storage_use.io);
        if !progress.turn_active || progress.turn_after.association.is_none()
            || progress.failure().is_some() || progress.pending_turns.checked_add(1).is_none() {
            progress.close();
            return Err(CreateStorageInventoryClosedV1);
        }
        Ok(CreateStorageInventoryPendingDisposalV1 { original: self, resume, completed: false })
    }

    /// Admits hostile outer and inner decoding from the actual retained packet.
    ///
    /// # Errors
    /// Retains over-ceiling/overflow geometry and same-J admission failure before
    /// any signed-envelope or inner Inventory Buffa allocation may occur.
    #[doc(hidden)]
    pub fn admit_response_decode_once(&mut self, packet: &[u8]) -> Result<(), CreateStorageInventoryClosedV1> {
        let progress = self.purpose.select_mut(&mut self.original.owner.inventory, &mut self.original.owner.storage_use.io);
        if progress.phase != Phase::Decode || progress.decode.is_some() || progress.failure().is_some() {
            progress.close();
            return Err(CreateStorageInventoryClosedV1);
        }
        progress.decode_geometry = Some(if self.purpose == StorageIoPurposeV1::Inventory {
            storage_inventory_client_response_decode_demand_v1(packet.len())
        } else {
            aos_sandbox_protocol::authenticated_session::all_methods::outcome_capture::
                AuthenticatedBrokerMethodOutcomeCaptureV1::dynamic_receiving_demand_v1(packet.len())
                .ok_or(StorageSessionGeometryRefusalV1)
        });
        progress.decode = Some((|| {
            let demand = progress.decode_geometry.as_ref().and_then(|value| value.as_ref().ok())
                .copied().ok_or(ResourceReservationErrorV1::Conflict)?;
            // The later outer model equality retains its actual encoded Vec
            // beside the original response; three packet widths dominate its
            // live/growing/reallocation backing before any decoder enters.
            let canonical_bytes = packet.len().checked_mul(3)
                .ok_or(ResourceReservationErrorV1::Conflict)?;
            let canonical = ResourceVector::ZERO.with(D::MemoryBytes,
                u64::try_from(canonical_bytes).map_err(|_| ResourceReservationErrorV1::Conflict)?);
            let complete = progress.complete_bound.checked_add(demand)?.checked_add(canonical)?;
            self.purpose.reserve_complete(&mut self.original.owner.intake,
                &mut self.original.owner.storage_use.reservation, progress.complete_bound, complete)?;
            progress.complete_bound = complete;
            Ok(())
        })());
        self.status()
    }

    /// Admits the actual canonical history/outcome growth before its Native CAS.
    ///
    /// Security lends its actual retained preimage, original request and observed
    /// body here; these borrowed bytes alone grant no request or commit authority.
    ///
    /// # Errors
    /// Retains invalid real geometry or same-J refusal before model/CAS growth.
    #[doc(hidden)]
    pub fn admit_outcome_once(&mut self, stored: &[u8], request: &[u8], body: &[u8])
        -> Result<(), CreateStorageInventoryClosedV1>
    {
        let progress = self.purpose.select_mut(&mut self.original.owner.inventory, &mut self.original.owner.storage_use.io);
        if progress.phase != Phase::Decode || progress.failure().is_some()
            || !matches!(progress.decode, Some(Ok(()))) || progress.outcome.is_some() {
            progress.close();
            return Err(CreateStorageInventoryClosedV1);
        }
        let Some(Ok(extent)) = progress.extent.as_ref() else {
            progress.close(); return Err(CreateStorageInventoryClosedV1);
        };
        progress.outcome_geometry = Some(outcome_demand(extent, stored, request, body));
        progress.outcome = Some((|| {
            let demand = progress.outcome_geometry.as_ref().and_then(|value| value.as_ref().ok())
                .copied().ok_or(ResourceReservationErrorV1::Conflict)?;
            let complete = progress.complete_bound.checked_add(demand)
                .map_err(|_| ResourceReservationErrorV1::Conflict)?;
            self.purpose.reserve_complete(&mut self.original.owner.intake,
                &mut self.original.owner.storage_use.reservation, progress.complete_bound, complete)?;
            progress.complete_bound = complete;
            Ok(())
        })());
        self.status()
    }

    /// Prepays one whole retained comparison of the actual signed terminal.
    ///
    /// This is new receiving work after the Inventory CAS. The existing
    /// schema/outcome debit cannot substitute for its co-resident replay and
    /// terminal-semantics destinations. It observes no extra C/Source profile.
    ///
    /// # Errors
    /// Retains same-Journal mismatch, actual metadata/retained-map width,
    /// complete shared geometry or genuine same-J reservation refusal.
    #[doc(hidden)]
    pub fn admit_retained_predecessor_once(&mut self, journal: &Journal)
        -> Result<(), CreateStorageInventoryClosedV1>
    {
        let progress = self.purpose.select(&self.original.owner.inventory, &self.original.owner.storage_use.io);
        if progress.phase != Phase::Decode || progress.failure().is_some()
            || !matches!(progress.outcome, Some(Ok(())))
            || progress.predecessor_association.is_some() {
            self.purpose.select_mut(&mut self.original.owner.inventory, &mut self.original.owner.storage_use.io).close();
            return Err(CreateStorageInventoryClosedV1);
        }
        let association = self.original.owner.client_session.require_completed_journal_v1(journal);
        let progress = self.purpose.select_mut(&mut self.original.owner.inventory, &mut self.original.owner.storage_use.io);
        progress.predecessor_association = Some(association);
        if matches!(progress.predecessor_association, Some(Ok(()))) {
            let _ = progress.predecessor_receiving.capture_once(
                journal, OutcomeReplayRosterV1::InventoryTerminal,
            );
        }
        let admission = (|| {
            if !matches!(progress.predecessor_association, Some(Ok(()))) {
                return Err(ResourceReservationErrorV1::Conflict);
            }
            let complete = progress.complete_bound
                .checked_add(progress.predecessor_receiving.demand_v1()?)?;
            self.purpose.reserve_complete(&mut self.original.owner.intake,
                &mut self.original.owner.storage_use.reservation, progress.complete_bound, complete)?;
            progress.complete_bound = complete;
            Ok(())
        })();
        let _ = progress.predecessor_receiving.retain_admission_once(admission);
        self.status()
    }

    /// Checks the actual already-paid retained terminal-comparison lane.
    ///
    /// # Errors
    /// Refuses missing or failed original admission without IO or a new grant.
    #[doc(hidden)]
    pub fn require_retained_predecessor_prepaid_v1(&self)
        -> Result<(), CreateStorageInventoryClosedV1>
    {
        self.purpose.select(&self.original.owner.inventory, &self.original.owner.storage_use.io).predecessor_receiving.require_admitted_v1()
            .map_err(|_| CreateStorageInventoryClosedV1)
    }

    /// Runs the prepaid independent terminal post after entered decode or CAS.
    ///
    /// This remains available after a response geometry/account refusal. An
    /// already-failed IO turn has its own owed after-turn destination; it does
    /// not start a third simultaneous failed name observation here.
    ///
    /// # Errors
    /// Retains changed joined originals or the existing earlier primary debt.
    #[doc(hidden)]
    pub fn observe_terminal_post_once(&mut self, journal: &Journal, socket: &SeqpacketSocket,
        transcript: &VerifiedBrokerSessionTranscriptV1) -> Result<(), CreateStorageInventoryClosedV1>
    {
        let progress = self.purpose.select_mut(&mut self.original.owner.inventory, &mut self.original.owner.storage_use.io);
        if !matches!(progress.fixed, Some(Ok(()))) || progress.completion.association.is_some()
            || (!progress.request_prepared && !progress.turn_active) {
            progress.close();
            return Err(CreateStorageInventoryClosedV1);
        }
        if progress.turn_active {
            // The same upper IO already owns its named independent after lane.
            // Failure never allocates a third pair or substitutes a new loan.
            if progress.turn_after.association.is_none() {
                self.observe(journal, socket, transcript, Site::TurnAfter);
            }
        } else {
            self.prepay_operation_observations_once(1)?;
            self.observe(journal, socket, transcript, Site::Completion);
        }
        self.status()
    }

    /// Completes Native posts after Security's genuine authenticated outcome.
    ///
    /// Security must retain and independently compare the actual committed
    /// Inventory predecessor and its validated model. This completion provides
    /// no standalone B input or authority from parsed/digest DATA.
    ///
    /// # Errors
    /// Refuses unpaid outcome growth or changed actual joined originals.
    #[doc(hidden)]
    pub fn finish_after_authenticated_inventory_once(&mut self, journal: &Journal,
        socket: &SeqpacketSocket, transcript: &VerifiedBrokerSessionTranscriptV1)
        -> Result<(), CreateStorageInventoryClosedV1>
    {
        if self.purpose.select(&self.original.owner.inventory, &self.original.owner.storage_use.io).failure().is_some()
            || !matches!(self.purpose.select(&self.original.owner.inventory, &self.original.owner.storage_use.io).outcome, Some(Ok(())))
            || self.require_retained_predecessor_prepaid_v1().is_err() {
            self.purpose.select_mut(&mut self.original.owner.inventory, &mut self.original.owner.storage_use.io).close();
            return Err(CreateStorageInventoryClosedV1);
        }
        if self.purpose.select(&self.original.owner.inventory, &self.original.owner.storage_use.io).completion.association.is_none() {
            self.observe_terminal_post_once(journal, socket, transcript)?;
        }
        self.status()?;
        self.purpose.select_mut(&mut self.original.owner.inventory, &mut self.original.owner.storage_use.io).phase = Phase::Complete;
        self.completed = true;
        Ok(())
    }

    /// Borrows the actual first Native cause while every original remains held.
    #[doc(hidden)]
    #[must_use]
    pub fn failure(&self) -> Option<&(dyn Error + 'static)> {
        self.purpose.select(&self.original.owner.inventory, &self.original.owner.storage_use.io).failure()
    }

    fn status(&mut self) -> Result<(), CreateStorageInventoryClosedV1> {
        if self.failure().is_none() { Ok(()) } else {
            self.purpose.select_mut(&mut self.original.owner.inventory, &mut self.original.owner.storage_use.io).close();
            Err(CreateStorageInventoryClosedV1)
        }
    }

    fn observe(&mut self, journal: &Journal, socket: &SeqpacketSocket,
        transcript: &VerifiedBrokerSessionTranscriptV1, site: Site)
    {
        let expected_controller = self.original.current_controller_history_position_v1();
        let progress = self.purpose.select_mut(&mut self.original.owner.inventory, &mut self.original.owner.storage_use.io);
        let Some(expected) = progress.association else { progress.close(); return; };
        let slot = match site {
            Site::Preparation => &mut progress.preparation,
            Site::CapturePost => &mut progress.capture_post,
            Site::TurnBefore => &mut progress.turn_before,
            Site::TurnAfter => &mut progress.turn_after,
            Site::Completion => &mut progress.completion,
        };
        if slot.association.is_some() { progress.close(); return; }
        let _ = slot.control.observe_operation_once(CacheControlOriginalsV1 {
            parent: &self.original.owner.parent, intake: &self.original.owner.intake,
            controller: self.original.controller, source: self.original.source,
            profile: self.original.profile,
        }, self.cache, expected, expected_controller);
        slot.association = Some(self.original.owner.client_session
            .require_completed_association_v1(journal, socket, transcript));
    }
}

#[derive(Clone, Copy)]
enum Site { Preparation, CapturePost, TurnBefore, TurnAfter, Completion }

impl Drop for OriginalCreateStorageInventoryV1<'_, '_, '_> {
    fn drop(&mut self) {
        if !self.completed {
            self.purpose.select_mut(&mut self.original.owner.inventory, &mut self.original.owner.storage_use.io).close();
            self.original.owner.intake.close();
        }
    }
}

/// Keeps the genuine operation borrowed until actual nonconsuming IO disposal.
///
/// This is a local custody disposition. It issues no request, deadline, grant or
/// ledger refund. Failed or abandoned phases leave the operation sticky-closed.
#[doc(hidden)]
#[must_use = "drop the actual nonconsuming upper receipt before completing this phase"]
pub struct CreateStorageInventoryPendingDisposalV1<'phase, 'turn, 'original, 'cache> {
    original: &'phase mut OriginalCreateStorageInventoryV1<'turn, 'original, 'cache>,
    resume: Phase,
    completed: bool,
}

impl CreateStorageInventoryPendingDisposalV1<'_, '_, '_, '_> {
    /// Rearms the same pending IO phase after its actual readiness capsule drops.
    ///
    /// The selected Security caller obtains this phase only after its complete
    /// poll and both original posts. No fallible work remains after disposal.
    #[doc(hidden)]
    pub fn complete_after_wait_disposal(self) {
        self.complete_after_receipt_disposal();
    }

    /// Rearms the same prepaid peak after actual successful receipt disposal.
    ///
    /// The closed Security caller must first dispose its original nonconsuming
    /// receipt. No fallible work remains between that disposal and this move.
    #[doc(hidden)]
    pub fn complete_after_receipt_disposal(mut self) {
        let progress = self.original.purpose.select_mut(&mut self.original.original.owner.inventory, &mut self.original.original.owner.storage_use.io);
        // Checked before constructing this exclusive phase, with no mutation
        // possible between admission and this infallible disposition.
        progress.pending_turns += 1;
        progress.turn_before = InventoryCurrentnessV1::default();
        progress.turn_after = InventoryCurrentnessV1::default();
        progress.pending_send_binding = None;
        progress.turn_active = false;
        progress.turn_funding = None;
        progress.phase = self.resume;
        self.completed = true;
    }
}

impl Drop for CreateStorageInventoryPendingDisposalV1<'_, '_, '_, '_> {
    fn drop(&mut self) {
        if !self.completed { self.original.purpose.select_mut(&mut self.original.original.owner.inventory, &mut self.original.original.owner.storage_use.io).close(); }
    }
}

fn fixed_demand(shape: CreateStorageInventoryShapeDataV1)
    -> Result<ResourceVector, ResourceReservationErrorV1>
{
    if shape.flight_bytes == 0 || shape.inventory_owner_bytes == 0 || shape.send_original_bytes == 0 {
        return Err(ResourceReservationErrorV1::Conflict);
    }
    let (receive_bytes, receive_files) = SeqpacketSocket::storage_preparation_receive_obligations_v1(
        AUTHENTICATED_RESPONSE_MAXIMUM_BYTES).ok_or(ResourceReservationErrorV1::Conflict)?;
    // The two named sub-layouts are verified by Security but are embedded in
    // flight_bytes. Only additional backing and the raw receiver are summed.
    let memory = [shape.flight_bytes, shape.failure_bytes, receive_bytes].into_iter().try_fold(0usize, |sum, bytes|
            sum.checked_add(bytes).ok_or(ResourceReservationErrorV1::Conflict))?;
    // Only preparation/capture, one active request/send/receive turn and the
    // terminal post coexist. Positive turn probes are physically disposed
    // before reuse; any failed turn stops later growth and owes just its post.
    let native = CacheCurrentnessOriginalV1::receiving_backing_demand_v1(5)
        .map_err(|_| ResourceReservationErrorV1::Conflict)?;
    let own = ResourceVector::ZERO
        .with(D::MemoryBytes, u64::try_from(memory).map_err(|_| ResourceReservationErrorV1::Conflict)?)
        .with(D::OpenFiles, u64::try_from(receive_files.checked_add(shape.predecessor_open_files)
            .ok_or(ResourceReservationErrorV1::Conflict)?)
            .map_err(|_| ResourceReservationErrorV1::Conflict)?);
    let receiving = OutcomeReplayReceivingOriginalsV1::fixed_receiving_demand_v1()?;
    // Inline control fields and received descriptor carriers add no namespace
    // entries. Native currentness and dynamic replay retain their own demands.
    native.checked_add(own)?.checked_add(receiving)
        .map_err(ResourceReservationErrorV1::from)
}

fn error<E: Error + 'static, T>(result: &Option<Result<T, E>>) -> Option<&(dyn Error + 'static)> {
    result.as_ref().and_then(|result| result.as_ref().err()).map(|cause| cause as _)
}

impl InventoryOriginalsV1 {
    // Local Native completion is a sequencing prerequisite, never the signed
    // Inventory proof. The upper B borrower must retain that actual Security
    // terminal and recheck its same-Session predecessor under its paid stage.
    pub(super) fn require_complete_bundle_predecessor_v1(&self)
        -> Result<(), ResourceReservationErrorV1>
    {
        if self.phase != Phase::Complete || self.failure().is_some() {
            return Err(ResourceReservationErrorV1::Conflict);
        }
        Ok(())
    }
}

impl<'original, 'cache> OriginalCreateStorageReadyV1<'original, 'cache> {
    /// Borrows only the actual C8-reserved request's same-U IO operation.
    ///
    /// Repeated short turns retain one distinct operation beside the completed
    /// Inventory. Only successful native disposal can park a turn for reuse.
    /// No supplied method, packet, position, payer or amount selects this purpose.
    ///
    /// # Errors
    /// Refuses absent actual C8/Root4/U, foreign Session, unpaid receiving,
    /// reentry, changed originals or any previously retained IO failure.
    #[doc(hidden)]
    pub fn borrow_original_storage_prepare_io_once<'turn>(&'turn mut self,
        journal: &Journal, socket: &SeqpacketSocket, transcript: &VerifiedBrokerSessionTranscriptV1,
    ) -> Result<OriginalCreateStorageInventoryV1<'turn, 'original, 'cache>, CreateStorageInventoryClosedV1> {
        if self.failure().is_some() { return Err(CreateStorageInventoryClosedV1); }
        self.original.owner.storage_use.session.position().map_err(|_| CreateStorageInventoryClosedV1)?;
        self.original.owner.root_exchange.require_preparation_after_v1()
            .map_err(|_| CreateStorageInventoryClosedV1)?;
        let first = !self.original.owner.storage_use.io.borrowed;
        if first {
            let peak = self.original.require_operation_currentness_peak_v1(&self.cache);
            let association = self.original.owner.cache_capture.currentness_association_v1()
                .map_err(|_| CreateStorageInventoryClosedV1)?;
            let owner = &mut *self.original.owner;
            let progress = &mut owner.storage_use.io;
            progress.borrowed = true;
            progress.association = Some(association);
            progress.peak = Some(peak);
            progress.geometry = Some(preparation_io_receiving_demand_v1());
            progress.fixed = Some((|| {
                progress.peak.as_ref().and_then(|result| result.as_ref().ok())
                    .ok_or(ResourceReservationErrorV1::Conflict)?;
                let demand = progress.geometry.as_ref().and_then(|result| result.as_ref().ok())
                    .copied().ok_or(ResourceReservationErrorV1::Conflict)?;
                owner.storage_use.reservation.receiving_mut_v1()?.reserve_once(demand)?;
                progress.complete_bound = demand;
                Ok(())
            })());
            if matches!(progress.fixed, Some(Ok(()))) { progress.phase = Phase::Admitted; }
            else { progress.close(); return Err(CreateStorageInventoryClosedV1); }
        }
        if first { self.observe_original_storage_prepare_root_once(false)?; }
        let mut loan = OriginalCreateStorageInventoryV1 {
            original: &mut self.original, cache: &mut self.cache, completed: false,
            purpose: StorageIoPurposeV1::Preparation,
        };
        if first { loan.capture_session_once(journal, socket, transcript)?; }
        Ok(loan)
    }
}

impl OriginalCreateStorageInventoryV1<'_, '_, '_> {
    /// Parks a completed positive short Prepare turn without completing Create.
    ///
    /// The actual operation, U, request and Session stay in their original owners.
    /// No failed or unfinished observation can release this local borrow fence.
    ///
    /// # Errors
    /// Refuses Inventory purpose, a live/failed turn or unfinished decode.
    #[doc(hidden)]
    pub fn park_original_storage_prepare_turn_once(&mut self) -> Result<(), CreateStorageInventoryClosedV1> {
        let progress = self.purpose.select_mut(&mut self.original.owner.inventory, &mut self.original.owner.storage_use.io);
        if self.purpose != StorageIoPurposeV1::Preparation || progress.turn_active
            || progress.failure().is_some() || !matches!(progress.phase, Phase::Prepared | Phase::Receiving) {
            progress.close();
            return Err(CreateStorageInventoryClosedV1);
        }
        self.completed = true;
        Ok(())
    }

    fn prepay_operation_observations_once(&mut self, observations: usize)
        -> Result<(), CreateStorageInventoryClosedV1> {
        if self.purpose == StorageIoPurposeV1::Inventory { return Ok(()); }
        let actual = &mut self.original.owner.storage_use;
        actual.io.turn_funding = Some((|| {
            let (wire, logs) = crate::normal_root::ProductionControllerNormalRootProfileV1::
                create_storage_producer_traffic_bound_v1(observations)
                .ok_or(ResourceReservationErrorV1::Conflict)?;
            actual.reservation.receiving_mut_v1()?.reserve_once(ResourceVector::ZERO
                .with(D::NetworkBytes, wire).with(D::LogBytes, logs))
        })());
        if matches!(actual.io.turn_funding, Some(Ok(()))) { Ok(()) }
        else { actual.io.close(); Err(CreateStorageInventoryClosedV1) }
    }
}

// Actual native receiving is shared by both independent U amount calculations
// and this C8-only entrance. The upper flight is already priced by its real
// compiled Security shape; no second copy or Rust-field namespace fee is added.
pub(in crate::controller_resource_reservation)
fn preparation_io_receiving_demand_v1() -> Result<ResourceVector, ResourceReservationErrorV1> {
    let invalid = || ResourceReservationErrorV1::Conflict;
    let bytes = std::mem::size_of::<InventoryOriginalsV1>().checked_mul(2).ok_or_else(invalid)?;
    let (receive_bytes, files) = SeqpacketSocket::storage_preparation_receive_obligations_v1(
        AUTHENTICATED_RESPONSE_MAXIMUM_BYTES).ok_or_else(invalid)?;
    let memory = bytes.checked_add(receive_bytes).ok_or_else(invalid)?;
    let own = ResourceVector::ZERO
        .with(D::MemoryBytes, u64::try_from(memory).map_err(|_| invalid())?)
        .with(D::OpenFiles, u64::try_from(files).map_err(|_| invalid())?)
        .with(D::NetworkBytes, u64::try_from(AUTHENTICATED_RESPONSE_MAXIMUM_BYTES).map_err(|_| invalid())?)
        .with(D::ConcurrentOperations, 1);
    let native = CacheCurrentnessOriginalV1::receiving_backing_demand_v1(5)
        .map_err(|_| invalid())?;
    own.checked_add(native)?.checked_add(OutcomeReplayReceivingOriginalsV1::fixed_receiving_demand_v1()?)
        .map_err(ResourceReservationErrorV1::Accounting)
}

impl OriginalCreateStorageReadyV1<'_, '_> {
    fn observe_original_storage_prepare_root_once(&mut self, finish: bool)
        -> Result<(), CreateStorageInventoryClosedV1> {
        let owner = &mut *self.original.owner;
        let actual = &mut owner.storage_use;
        actual.session.position().map_err(|_| CreateStorageInventoryClosedV1)?;
        let width = actual.reservation.request_shape_bytes_v1().map_err(|_| CreateStorageInventoryClosedV1)?;
        let (append, receiving) = actual.reservation.split_retained_root_receiving_after_debt_v1()
            .map_err(|_| CreateStorageInventoryClosedV1)?;
        let reserved = super::use_reserved::OriginalCreateStorageUseReservedV1 {
            append, request_shape_bytes: width, record: &actual.reserved,
        };
        let signed = super::use_reserved::OriginalCreateStorageSignedV1::from_original_reserved_v1(
            reserved, &actual.signed).map_err(|_| CreateStorageInventoryClosedV1)?;
        owner.root_exchange.observe_preparation_terminal_root_once(&owner.parent, &mut owner.intake,
            self.original.controller, self.original.source, self.original.profile, &mut self.cache,
            &signed, &actual.dispatch, &actual.session, receiving, finish)
            .map_err(|_| CreateStorageInventoryClosedV1)
    }

    /// Runs the same prepaid Root after-check after an entered Prepare exchange.
    ///
    /// The actual C8 original and returned U remain mandatory after IO refusal.
    /// Completion additionally requires the same native authenticated terminal;
    /// this method never creates a receipt or completion from parsed DATA.
    ///
    /// # Errors
    /// Retains incomplete/failed IO, missing genuine C8, reentry or Root refusal.
    #[doc(hidden)]
    pub fn finish_original_storage_prepare_io_once(&mut self)
        -> Result<(), CreateStorageInventoryClosedV1> {
        let primary = self.original.owner.storage_use.io.phase == Phase::Complete
            && self.original.owner.storage_use.io.failure().is_none();
        let after = self.observe_original_storage_prepare_root_once(true);
        if primary && after.is_ok() { Ok(()) } else { Err(CreateStorageInventoryClosedV1) }
    }
}

impl InventoryOriginalsV1 {
    pub(super) fn completed_extent_v1(&self) -> Result<&ProtectedJournalPreopenReplayExtentV1, ResourceReservationErrorV1> {
        self.require_complete_bundle_predecessor_v1()?;
        self.extent.as_ref().and_then(|result| result.as_ref().ok()).ok_or(ResourceReservationErrorV1::Conflict)
    }
}
