//! Authenticates an original administrative capture reservation without modeled execution.
//!
//! Only the owning runtime creates an attempt after unchanged-cut and complete
//! finite-credit admission. The runtime retains the same attempt through native
//! uncertainty. Portable journals preserve history but cannot construct a ticket.

use crucible_node_format::{ContentRef, Id, Position, U64, Validate, canonical};
use std::{
    cell::{Cell, OnceCell, Ref, RefCell},
    rc::Rc,
    thread::{self, ThreadId},
};

use crate::node_contract::runtime::scheduling_state::OriginalSchedulingSource;
use crate::node_contract::{
    NativeCaptureLimits, OriginalInputLineageLimits, OriginalLineageRuntimeRecord, OwnerIdentity,
    RuntimeError, WorldActivation,
};
use crate::node_scheduling::InputPayload;

#[path = "capture_ticket/host_preparation.rs"]
pub(super) mod host_preparation;

#[path = "capture_ticket/geometry.rs"]
mod geometry;

#[path = "capture_ticket/storage.rs"]
mod storage;

#[path = "capture_ticket/attempt_precharge.rs"]
mod attempt_precharge;

#[path = "capture_ticket/value_layout.rs"]
mod value_layout;

#[path = "capture_ticket/owned.rs"]
pub(crate) mod owned;

#[path = "capture_ticket/serialization.rs"]
mod serialization;

#[path = "capture_ticket/restored_identity.rs"]
mod restored_identity;

#[path = "capture_ticket/restored_terminal17.rs"]
mod restored_terminal17;
pub use geometry::PreparedCompleteOriginalCaptureGeometry;

/// Borrows an unchanged-cut world for separately owned administrative capture.
///
/// These inputs are facts only; the retaining runtime authenticates its own
/// activation/ledgers and whole-world finite admission before issuing a ticket.
pub struct TicketedOriginalLineageCaptureRequest<'a> {
    /// Borrows the complete actual admitted graph.
    pub graph: &'a crate::node_admission::AdmittedGraph,
    /// Borrows the same runtime's published private world activation.
    pub activation: &'a WorldActivation,
    /// Names this lifetime-unique capture attempt without creating a model grant.
    pub capture_id: Id,
    /// Borrows the actual runtime's complete unchanged original ledger.
    pub source: &'a OriginalLineageRuntimeRecord,
    /// Borrows its exact canonical typed original object.
    pub runtime_object: &'a InputPayload,
    /// Bounds original lineage body occurrences before capture effects.
    pub lineage_limits: OriginalInputLineageLimits,
    /// Bounds whole-world snapshot and settlement object credits.
    pub limits: NativeCaptureLimits,
    /// Borrows the actual source plan sealed by the complete archive writer.
    pub geometry: &'a PreparedCompleteOriginalCaptureGeometry,
}

pub(crate) struct OriginalLineageCaptureAttempt {
    process: u32,
    thread: ThreadId,
    original: OriginalSchedulingSource,
    activation: WorldActivation,
    capture_id: Id,
    runtime_object: InputPayload,
    cut: Position,
    ordinal: U64,
    lineage_limits: OriginalInputLineageLimits,
    limits: NativeCaptureLimits,
    host: host_preparation::family::PreparedHostCaptureFamily,
    owners: Vec<OriginalCaptureOwnerReservation>,
    active: Cell<bool>,
    sequence: U64,
    settlements: RefCell<Vec<Option<(ContentRef, ContentRef)>>>,
    // Successful replies move here before validation or another owner callback.
    // A later failure must retain their bytes in the same original world.
    captures: RefCell<Vec<Option<super::InstalledOriginalLineageCapture>>>,
    persisted: OnceCell<crate::node_state::NativeArchiveRecord>,
}

struct OriginalCaptureOwnerReservation {
    owner: OwnerIdentity,
    participants: Vec<Id>,
    operation: Id,
    submitted: Cell<bool>,
    uncertain: Cell<bool>,
}

/// Borrows one core-issued owner reservation from the same retained world attempt.
///
/// This nonserializable ticket has no public constructor. Getter results are
/// facts, not source authority. An installed adapter must separately compare its
/// own retained original opaque activation and current native custody before
/// dispatching the same administrative Capture request. No modeled grant is issued.
pub struct OriginalLineageOwnerCaptureTicket<'a> {
    attempt: &'a OriginalLineageCaptureAttempt,
    owner: &'a OriginalCaptureOwnerReservation,
    // The actual new17 dispatcher lends its stack scope only for this callback.
    // Retained administrative attempts never borrow a transient caller scope.
    restored_scope: Option<&'a crate::node_contract::RestoredCollectingCaptureScope17<'a>>,
}

/// Retains complete settled capture bodies in their same original world attempt.
///
/// Dropping a read handle does not release the runtime's administrative hold or
/// discard earlier owner bodies. Only the installed complete-world archive may
/// authenticate and persist their joint closure before releasing that hold.
pub struct OriginalLineageWorldCapture {
    attempt: Rc<OriginalLineageCaptureAttempt>,
}

/// Borrows authentic settled bodies without copying snapshot or journal bytes.
pub struct OriginalLineageWorldCaptureRead<'a> {
    captures: Ref<'a, Vec<Option<super::InstalledOriginalLineageCapture>>>,
}

impl OriginalLineageWorldCapture {
    /// Checks genuine pending write purpose without parsing or releasing history.
    ///
    /// The actual writer separately authenticates the complete administrative
    /// journal and source codecs before persistence. This nonallocating check
    /// binds its active opaque runtime attempt to the exact settled owner bodies;
    /// it does not claim those codecs or a durable index have been accepted.
    pub(crate) fn authenticate_pending_archive_write_origin(
        &self,
        runtime: &crate::node_contract::NodeRuntime,
        archive: &crate::node_state::NativeArchiveRecord,
    ) -> Result<(), RuntimeError> {
        let attempt = &self.attempt;
        if attempt.process != std::process::id() || attempt.thread != thread::current().id() {
            return Err(RuntimeError::ForeignAuthority);
        }
        attempt.original.authenticate_runtime_authority(
            &attempt.activation.record().world_binding_hash,
            &runtime.authority,
        )?;
        let retained = runtime
            .original_capture_attempts
            .get(&attempt.capture_id)
            .ok_or(RuntimeError::ForeignAuthority)?;
        if !Rc::ptr_eq(retained, attempt)
            || !attempt.active.get()
            || attempt.persisted.get().is_some()
        {
            return Err(RuntimeError::ForeignAuthority);
        }
        runtime.validate_activation(&attempt.activation)?;
        let manifest = archive.manifest();
        if manifest.capture_id != attempt.capture_id
            || manifest.world_binding_hash != attempt.activation.record().world_binding_hash
            || manifest.cut != attempt.cut
            || manifest.event_ordinal != attempt.ordinal
            || archive.owners().len() != attempt.owners.len()
        {
            return Err(RuntimeError::ForeignAuthority);
        }
        let read = self.read()?;
        for ((reservation, captured), saved) in attempt
            .owners
            .iter()
            .zip(read.owners())
            .zip(archive.owners())
        {
            if reservation.uncertain.get()
                || !reservation.submitted.get()
                || captured.native().owner() != &reservation.owner.owner
                || captured.native().participants() != reservation.participants
                || captured.native().cut() != attempt.cut
                || saved.owner != reservation.owner.owner
                || saved.participants != reservation.participants
                || saved.cut != attempt.cut
                || saved.state != captured.native().state().reference
                || saved.key != *captured.native().key()
                || !saved.evidence.contains(&captured.journal().reference)
                || captured
                    .native()
                    .evidence()
                    .iter()
                    .any(|body| !saved.evidence.contains(&body.reference))
            {
                return Err(RuntimeError::InvalidReceipt);
            }
        }
        attempt.original.authenticate_runtime_authority(
            &attempt.activation.record().world_binding_hash,
            &runtime.authority,
        )
    }

    pub(crate) fn release_persisted_archive(
        &self,
        runtime: &mut crate::node_contract::NodeRuntime,
        archive: &crate::node_state::NativeArchiveRecord,
    ) -> Result<(), RuntimeError> {
        let attempt = &self.attempt;
        if attempt.process != std::process::id() || attempt.thread != thread::current().id() {
            return Err(RuntimeError::ForeignAuthority);
        }
        attempt.original.authenticate_runtime_authority(
            &attempt.activation.record().world_binding_hash,
            &runtime.authority,
        )?;
        let retained = runtime
            .original_capture_attempts
            .get(&attempt.capture_id)
            .ok_or(RuntimeError::ForeignAuthority)?;
        if !Rc::ptr_eq(retained, attempt) || !attempt.active.get() {
            return Err(RuntimeError::ForeignAuthority);
        }
        runtime.validate_activation(&attempt.activation)?;
        runtime.validate_all_declarations()?;
        let manifest = archive.manifest();
        if manifest.capture_id != attempt.capture_id
            || manifest.world_binding_hash != attempt.activation.record().world_binding_hash
            || manifest.cut != attempt.cut
            || manifest.event_ordinal != attempt.ordinal
        {
            return Err(RuntimeError::ForeignAuthority);
        }
        let journal = archive
            .original_capture_journal()
            .map_err(|_| RuntimeError::InvalidReceipt)?;
        let last = journal
            .attempts
            .last()
            .ok_or(RuntimeError::InvalidReceipt)?;
        if last.sequence != attempt.sequence
            || last.source_runtime != attempt.runtime_object.reference
            || last.owners.len() != attempt.owners.len()
            || archive.owners().len() != attempt.owners.len()
        {
            return Err(RuntimeError::InvalidReceipt);
        }
        let original = self.read()?;
        for (((reservation, settled), captured), saved) in attempt
            .owners
            .iter()
            .zip(&last.owners)
            .zip(original.owners())
            .zip(archive.owners())
        {
            let super::OriginalCaptureOwnerState::Settled { snapshot, journal } = &settled.state
            else {
                return Err(RuntimeError::OutstandingObligations);
            };
            if reservation.uncertain.get()
                || !reservation.submitted.get()
                || settled.owner != reservation.owner
                || settled.operation != reservation.operation
                || settled.participants != reservation.participants
                || saved.owner != reservation.owner.owner
                || &saved.state != snapshot
                || &captured.native().state().reference != snapshot
                || &captured.journal().reference != journal.as_ref()
                || saved.key != *captured.native().key()
                || !saved.evidence.contains(journal.as_ref())
            {
                return Err(RuntimeError::InvalidReceipt);
            }
        }
        runtime.validate_all_declarations()?;
        attempt.original.authenticate_runtime_authority(
            &attempt.activation.record().world_binding_hash,
            &runtime.authority,
        )?;
        // Only the owning archive writer calls this after actual durable index
        // persistence and source-specific whole-closure verification. Histories,
        // body slots and lifetime IDs remain retained; only the execution hold ends.
        attempt
            .persisted
            .set(archive.clone())
            .map_err(|_| RuntimeError::OutstandingObligations)?;
        attempt.active.set(false);
        Ok(())
    }

    /// Borrows complete actual owner captures under the original source guard.
    ///
    /// # Errors
    /// Refuses a foreign process/thread, revoked original world, reentrant read,
    /// or any incomplete owner settlement. A read never signs or releases custody.
    pub fn read(&self) -> Result<OriginalLineageWorldCaptureRead<'_>, RuntimeError> {
        let attempt = &self.attempt;
        if attempt.process != std::process::id() || attempt.thread != thread::current().id() {
            return Err(RuntimeError::ForeignAuthority);
        }
        attempt.original.authenticate_runtime_authority(
            &attempt.activation.record().world_binding_hash,
            &attempt.activation.authority,
        )?;
        let captures = attempt
            .captures
            .try_borrow()
            .map_err(|_| RuntimeError::OutstandingObligations)?;
        let settlements = attempt
            .settlements
            .try_borrow()
            .map_err(|_| RuntimeError::OutstandingObligations)?;
        if captures.len() != attempt.owners.len()
            || captures.iter().any(Option::is_none)
            || settlements.len() != attempt.owners.len()
            || settlements.iter().any(Option::is_none)
        {
            return Err(RuntimeError::OutstandingObligations);
        }
        Ok(OriginalLineageWorldCaptureRead { captures })
    }
}

impl OriginalLineageWorldCaptureRead<'_> {
    /// Borrows every settled owner body in the original reservation order.
    pub fn owners(&self) -> impl Iterator<Item = &super::InstalledOriginalLineageCapture> {
        // The read constructor has already checked every slot is occupied.
        // Keep the public iterator free of a panic even if an invariant regresses.
        self.captures.iter().filter_map(Option::as_ref)
    }
}

impl OriginalLineageOwnerCaptureTicket<'_> {
    /// Borrows only the actual current17 scope lent by its defining dispatcher.
    ///
    /// The optional loan carries no reconstructed scope or copied permissions.
    /// Each selected Source still authenticates its actual Window claim, launch,
    /// native owner and original runtime ticket before any effective callback.
    pub(crate) fn restored_capture_scope17_data(
        &self,
    ) -> Option<&crate::node_contract::RestoredCollectingCaptureScope17<'_>> {
        self.restored_scope
    }

    /// Borrows the original world capture identity.
    pub fn capture_id(&self) -> &Id {
        &self.attempt.capture_id
    }

    /// Borrows the core-issued administrative operation identity without renewing it.
    pub fn operation_id(&self) -> &Id {
        &self.owner.operation
    }

    /// Borrows actual original owner incarnation data.
    pub fn owner(&self) -> &OwnerIdentity {
        &self.owner.owner
    }

    /// Borrows the complete source-selected owner participant roster.
    pub fn participants(&self) -> &[Id] {
        &self.owner.participants
    }

    /// Returns the unchanged full model cut.
    pub fn cut(&self) -> Position {
        self.attempt.cut
    }

    /// Returns the unchanged coordinator event ordinal.
    pub fn ordinal(&self) -> U64 {
        self.attempt.ordinal
    }

    /// Borrows the complete original typed Runtime7 commitment as data.
    pub fn runtime_object(&self) -> &ContentRef {
        &self.attempt.runtime_object.reference
    }

    /// Moves the genuine common-state producer once into its original host adapter.
    ///
    /// The source must be the same actual factory-created host and attached
    /// runtime. This only transfers precharged snapshot data; it neither grants
    /// capture capability nor settles the administrative attempt.
    ///
    /// # Errors
    /// Refuses another original owner/source/world, foreign process/thread,
    /// stale custody, changed input bytes or a repeated snapshot transfer.
    pub fn take_prepared_host_continuation(
        &self,
        host: &crate::node_contract::HostSchedulingSource,
        activation: &WorldActivation,
        source: &OriginalLineageRuntimeRecord,
        runtime_object: &InputPayload,
    ) -> Result<crate::node_contract::HostSchedulingContinuationV2, RuntimeError> {
        self.authenticate_scope(
            activation,
            source,
            runtime_object,
            self.owner(),
            self.participants(),
        )?;
        self.attempt.host.take(host, self.owner(), activation)
    }

    /// Moves the same genuine Host17 producer through the current17 ticket family.
    ///
    /// # Errors
    /// Refuses absent current17 Scope, foreign custody, another checkpoint or a
    /// repeated transfer. The adapter must retain the returned value immediately.
    pub(crate) fn take_prepared_restored_host17_data(
        &self,
        host: &crate::node_contract::HostSchedulingSource,
        activation: &WorldActivation,
        source: &OriginalLineageRuntimeRecord,
        runtime_object: &InputPayload,
    ) -> Result<crate::node_contract::HostSchedulingRestoredContinuation17, RuntimeError> {
        let scope = self.restored_scope.ok_or(RuntimeError::UnsupportedFacet)?;
        scope.authenticate_current_data()?;
        self.authenticate_scope(
            activation,
            source,
            runtime_object,
            self.owner(),
            self.participants(),
        )?;
        self.attempt.host.take_restored17_data(
            host,
            self.owner(),
            activation,
            source,
            runtime_object,
        )
    }

    /// Authenticates this reservation against the adapter's independent original scope.
    ///
    /// The supplied activation must be the adapter's same retained opaque world
    /// handle, rather than a DTO or an echo of the capture callback argument.
    /// Actual native custody and source-specific settlement remain independent.
    ///
    /// # Errors
    /// Refuses foreign PID/thread, revoked original storage, another private
    /// runtime authority, an unsubmitted/closed attempt, changed source bytes,
    /// owner roster or unchanged-cut coordinates, or finite excess.
    pub fn authenticate_scope(
        &self,
        activation: &WorldActivation,
        source: &OriginalLineageRuntimeRecord,
        runtime_object: &InputPayload,
        owner: &OwnerIdentity,
        participants: &[Id],
    ) -> Result<(), RuntimeError> {
        let original = self.attempt;
        if original.process != std::process::id() || original.thread != thread::current().id() {
            return Err(RuntimeError::ForeignAuthority);
        }
        original.original.authenticate_runtime_authority(
            &original.activation.record().world_binding_hash,
            &activation.authority,
        )?;
        if !original.active.get()
            || !self.owner.submitted.get()
            || activation.record() != original.activation.record()
            || owner != &self.owner.owner
            || participants != self.owner.participants
            || !original
                .owners
                .iter()
                .any(|reservation| std::ptr::eq(reservation, self.owner))
            || source.capture_cut != original.cut
            || source.capture_ordinal != original.ordinal
            || runtime_object.reference != original.runtime_object.reference
            || runtime_object.bytes != original.runtime_object.bytes
        {
            return Err(RuntimeError::ForeignAuthority);
        }
        // Metadata counting and reference credit precede canonical buffer copies.
        source.validate_metadata(
            original.lineage_limits,
            original.limits.maximum_record_bytes,
        )?;
        crate::node_contract::NodeRuntime::capture_serialization_storage(
            source,
            original.limits.maximum_total_record_bytes,
        )?;
        let value = serde_json::to_value(source).map_err(|_| RuntimeError::InvalidReceipt)?;
        let bytes = canonical::canonical_json(&value).map_err(|_| RuntimeError::InvalidReceipt)?;
        if bytes != runtime_object.bytes {
            return Err(RuntimeError::InvalidReceipt);
        }
        runtime_object
            .reference
            .verify(&runtime_object.bytes)
            .map_err(|_| RuntimeError::InvalidReceipt)?;
        original.original.authenticate_runtime_authority(
            &original.activation.record().world_binding_hash,
            &activation.authority,
        )
    }
}

impl crate::node_contract::NodeRuntime {
    pub(in crate::node_contract) fn require_settled_capture_custody(
        &self,
    ) -> Result<(), RuntimeError> {
        if let Some(history) = &self.original_capture_history {
            history.authenticate_target(&self.authority)?;
        }
        if self.original_capture_attempts.values().any(|attempt| {
            attempt.process != std::process::id() || attempt.thread != thread::current().id()
        }) {
            return Err(RuntimeError::ForeignAuthority);
        }
        if self
            .original_capture_attempts
            .values()
            .any(|attempt| attempt.active.get())
        {
            return Err(RuntimeError::OutstandingObligations);
        }
        Ok(())
    }

    pub(crate) fn original_capture_archives(
        &self,
    ) -> Result<impl Iterator<Item = &crate::node_state::NativeArchiveRecord>, RuntimeError> {
        self.scheduling_origin()?.current()?;
        self.require_settled_capture_custody()?;
        if self
            .original_capture_attempts
            .values()
            .any(|attempt| attempt.persisted.get().is_none())
        {
            return Err(RuntimeError::OutstandingObligations);
        }
        Ok(self
            .original_capture_history
            .iter()
            .map(|history| history.archive())
            .chain(
                self.original_capture_attempts
                    .values()
                    .filter_map(|attempt| attempt.persisted.get()),
            ))
    }

    /// Reads retained administrative history without granting capture or execution.
    ///
    /// These inert rows preserve lifetime IDs, original owner incarnations and
    /// uncertain request custody. Only the new complete-world archive route may
    /// sign a settled joint closure; legacy Runtime7 remains unchanged.
    ///
    /// # Errors
    /// Refuses foreign original storage, reentrant settlement inspection or
    /// exhausted metadata credit while retaining the same world.
    pub fn original_capture_journal(
        &self,
    ) -> Result<super::RuntimeOriginalCaptureJournal, RuntimeError> {
        let maximum_bytes = self
            .original_capture_attempts
            .values()
            .map(|attempt| attempt.limits.maximum_record_bytes)
            .min()
            .unwrap_or(2 * 1024 * 1024);
        self.original_capture_journal_with_limit(maximum_bytes)
    }

    /// Copies inert administrative rows only after complete metadata credit admission.
    ///
    /// # Errors
    /// Refuses foreign original custody, reentrant reads or a conservative
    /// serialized metadata extent exceeding the caller's finite record credit.
    pub fn original_capture_journal_with_limit(
        &self,
        maximum_bytes: usize,
    ) -> Result<super::RuntimeOriginalCaptureJournal, RuntimeError> {
        self.scheduling_origin()?.current()?;
        self.capture_journal_metadata_credit(maximum_bytes)?;
        let mut attempts = Vec::new();
        attempts
            .try_reserve_exact(self.original_capture_count()?)
            .map_err(|_| RuntimeError::ResourceLimit)?;
        if let Some(history) = &self.original_capture_history {
            attempts.extend(history.administrative().attempts.iter().cloned());
        }
        for attempt in self.original_capture_attempts.values() {
            let settlements = attempt
                .settlements
                .try_borrow()
                .map_err(|_| RuntimeError::OutstandingObligations)?;
            let mut owners = Vec::new();
            owners
                .try_reserve_exact(attempt.owners.len())
                .map_err(|_| RuntimeError::ResourceLimit)?;
            for (index, owner) in attempt.owners.iter().enumerate() {
                let state = match settlements.get(index).ok_or(RuntimeError::InvalidReceipt)? {
                    Some((snapshot, journal)) => super::OriginalCaptureOwnerState::Settled {
                        snapshot: snapshot.clone(),
                        journal: Box::new(journal.clone()),
                    },
                    None if owner.uncertain.get() => super::OriginalCaptureOwnerState::Uncertain,
                    None if owner.submitted.get() => super::OriginalCaptureOwnerState::Submitted,
                    None => super::OriginalCaptureOwnerState::Reserved,
                };
                owners.push(super::OriginalCaptureOwnerRecord {
                    owner: owner.owner.clone(),
                    participants: owner.participants.clone(),
                    operation: owner.operation.clone(),
                    state,
                });
            }
            let record = attempt.activation.record();
            attempts.push(super::OriginalCaptureAttemptRecord {
                sequence: attempt.sequence,
                capture_id: attempt.capture_id.clone(),
                source_runtime: attempt.runtime_object.reference.clone(),
                source_activation: super::SavedRuntimeActivation {
                    generation: record.generation,
                    activation_id: record.activation_id.clone(),
                    world_binding_hash: record.world_binding_hash.clone(),
                    owners: record.owners.clone(),
                    boundary: record.boundary,
                },
                cut: attempt.cut,
                ordinal: attempt.ordinal,
                owners,
            });
        }
        attempts.sort_by_key(|attempt| attempt.sequence);
        Ok(super::RuntimeOriginalCaptureJournal {
            schema_version: 1,
            maximum_attempts: 64.into(),
            attempts,
        })
    }

    pub(in crate::node_contract) fn administrative_operation_used(&self, operation: &Id) -> bool {
        self.original_capture_history
            .as_ref()
            .is_some_and(|history| {
                history.administrative().attempts.iter().any(|attempt| {
                    attempt
                        .owners
                        .iter()
                        .any(|owner| &owner.operation == operation)
                })
            })
            || self.original_capture_attempts.values().any(|attempt| {
                attempt
                    .owners
                    .iter()
                    .any(|owner| &owner.operation == operation)
            })
    }

    fn original_capture_count(&self) -> Result<usize, RuntimeError> {
        let historical = if let Some(history) = &self.original_capture_history {
            history.authenticate_target(&self.authority)?;
            history.administrative().attempts.len()
        } else {
            0
        };
        historical
            .checked_add(self.original_capture_attempts.len())
            .ok_or(RuntimeError::ResourceLimit)
    }

    fn capture_journal_metadata_credit(
        &self,
        maximum_bytes: usize,
    ) -> Result<CaptureMetadataCredit, RuntimeError> {
        let mut credit = CaptureMetadataCredit::new(maximum_bytes);
        credit.reserve(1024)?;
        if let Some(history) = &self.original_capture_history {
            history.authenticate_target(&self.authority)?;
            credit.charge(history.administrative())?;
        }

        for attempt in self.original_capture_attempts.values() {
            if attempt.process != std::process::id() || attempt.thread != thread::current().id() {
                return Err(RuntimeError::ForeignAuthority);
            }
            charge_attempt_metadata(
                &mut credit,
                attempt.activation.record(),
                &attempt.capture_id,
                &attempt.runtime_object.reference,
                &attempt.owners,
            )?;
            // Actual references were validated before settlement. The precharge
            // above includes both maximum-sized references for every owner.
            let settlements = attempt
                .settlements
                .try_borrow()
                .map_err(|_| RuntimeError::OutstandingObligations)?;
            for (snapshot, journal) in settlements.iter().flatten() {
                snapshot
                    .validate()
                    .map_err(|_| RuntimeError::InvalidReceipt)?;
                journal
                    .validate()
                    .map_err(|_| RuntimeError::InvalidReceipt)?;
            }
        }
        Ok(credit)
    }

    /// Dispatches a separately owned original administrative capture attempt.
    ///
    /// The complete actual world and finite credits precede registration; the
    /// same registered ticket precedes every native callback. No modeled grant
    /// is created. A callback refusal or uncertainty keeps this original world
    /// and attempt; it never retries another request or signs partial snapshots.
    ///
    /// # Errors
    /// Refuses unsupported source/owner codecs, changed original world or cut,
    /// active administrative custody, reused lifetime IDs, incomplete records or
    /// finite excess. Native uncertainty preserves the same owning capsule.
    pub fn capture_installed_original_lineage_with_ticket(
        &mut self,
        request: TicketedOriginalLineageCaptureRequest<'_>,
    ) -> Result<OriginalLineageWorldCapture, super::RuntimePollFailure> {
        self.capture_installed_original_lineage_with_prepared_host_data(
            request,
            None::<
                fn(
                    &crate::node_contract::NodeRuntime,
                    &crate::node_contract::HostSchedulingSource,
                    &crate::node_scheduling::SchedulingSnapshot,
                    &InputPayload,
                ) -> Result<(), RuntimeError>,
            >,
        )
    }

    /// Runs a separately admitted preparation against the genuine retained host.
    ///
    /// The attempt is registered before this callback. Any callback refusal
    /// preserves it and its prepared host, before the first owner is submitted.
    ///
    /// # Errors
    /// Refuses the same capture admissions as the ordinary ticketed path, a
    /// consumed or foreign host preparation, or the callback's own validation.
    pub(crate) fn capture_installed_original_lineage_with_prepared_host_data(
        &mut self,
        request: TicketedOriginalLineageCaptureRequest<'_>,
        prepared: Option<
            impl FnOnce(
                &crate::node_contract::NodeRuntime,
                &crate::node_contract::HostSchedulingSource,
                &crate::node_scheduling::SchedulingSnapshot,
                &InputPayload,
            ) -> Result<(), RuntimeError>,
        >,
    ) -> Result<OriginalLineageWorldCapture, super::RuntimePollFailure> {
        self.capture_installed_original_lineage_family_data(request, prepared, None, None)
    }

    /// Dispatches genuinely scoped current17 owners with full observations between them.
    ///
    /// # Errors
    /// Refuses foreign current Scope or family, ordinary capture admission,
    /// callback failure or the genuine post-loan whole-graph observation.
    pub(crate) fn capture_installed_restored_lineage17_data(
        &mut self,
        request: TicketedOriginalLineageCaptureRequest<'_>,
        scope: &crate::node_contract::RestoredCollectingCaptureScope17<'_>,
        after_owner: &mut dyn FnMut(&crate::node_contract::NodeRuntime) -> Result<(), RuntimeError>,
    ) -> Result<OriginalLineageWorldCapture, super::RuntimePollFailure> {
        scope
            .authenticate_runtime_data(self)
            .map_err(super::RuntimePollFailure::Admission)?;
        self.capture_installed_original_lineage_family_data(
            request,
            None::<
                fn(
                    &crate::node_contract::NodeRuntime,
                    &crate::node_contract::HostSchedulingSource,
                    &crate::node_scheduling::SchedulingSnapshot,
                    &InputPayload,
                ) -> Result<(), RuntimeError>,
            >,
            Some(scope),
            Some(after_owner),
        )
    }

    fn capture_installed_original_lineage_family_data(
        &mut self,
        request: TicketedOriginalLineageCaptureRequest<'_>,
        prepared: Option<
            impl FnOnce(
                &crate::node_contract::NodeRuntime,
                &crate::node_contract::HostSchedulingSource,
                &crate::node_scheduling::SchedulingSnapshot,
                &InputPayload,
            ) -> Result<(), RuntimeError>,
        >,
        restored_scope: Option<&crate::node_contract::RestoredCollectingCaptureScope17<'_>>,
        mut after_owner: Option<
            &mut dyn FnMut(&crate::node_contract::NodeRuntime) -> Result<(), RuntimeError>,
        >,
    ) -> Result<OriginalLineageWorldCapture, super::RuntimePollFailure> {
        use super::RuntimePollFailure;
        let TicketedOriginalLineageCaptureRequest {
            graph,
            activation,
            capture_id,
            source,
            runtime_object,
            lineage_limits,
            limits,
            geometry,
        } = request;
        geometry
            .authenticate_host_family17_data(restored_scope.is_some())
            .map_err(RuntimePollFailure::Admission)?;
        geometry
            .authenticate(self, activation, &capture_id, runtime_object, limits)
            .map_err(RuntimePollFailure::Admission)?;
        self.validate_activation(activation)
            .map_err(RuntimePollFailure::Admission)?;
        self.validate_all_declarations()
            .map_err(RuntimePollFailure::Admission)?;
        capture_id
            .validate()
            .map_err(|_| RuntimePollFailure::Admission(RuntimeError::InvalidReceipt))?;
        if self
            .original_capture_count()
            .map_err(RuntimePollFailure::Admission)?
            >= 64
            || self
                .original_capture_history
                .as_ref()
                .is_some_and(|history| {
                    history
                        .administrative()
                        .attempts
                        .iter()
                        .any(|attempt| attempt.capture_id == capture_id)
                })
            || self.original_capture_attempts.contains_key(&capture_id)
            || self
                .original_capture_attempts
                .values()
                .any(|attempt| attempt.active.get())
        {
            return Err(RuntimePollFailure::Admission(
                RuntimeError::OutstandingObligations,
            ));
        }
        // Reserve the declared maximum snapshot and settlement for every owner
        // before the first callback; later actors cannot depend on optimistic
        // reuse of an earlier actor's smaller actual response.
        let peak = limits
            .maximum_record_bytes
            .checked_mul(42)
            .and_then(|bytes| bytes.checked_add(runtime_object.bytes.len()))
            .ok_or(RuntimePollFailure::Admission(RuntimeError::ResourceLimit))?;
        if limits.maximum_record_bytes == 0 || limits.maximum_total_record_bytes < peak {
            return Err(RuntimePollFailure::Admission(RuntimeError::ResourceLimit));
        }
        if graph.world_binding_hash() != &activation.record().world_binding_hash
            || graph.ownership_policy().capture_owners.len() != 4
            || graph.node_ids().count() != 4
            || limits.maximum_objects < 8
            || limits.maximum_total_record_bytes
                < runtime_object
                    .bytes
                    .len()
                    .checked_mul(2)
                    .ok_or(RuntimePollFailure::Admission(RuntimeError::ResourceLimit))?
            || self
                .original_lineage_runtime_snapshot(
                    source.capture_cut,
                    source.capture_ordinal,
                    lineage_limits,
                    limits.maximum_record_bytes,
                )
                .map_err(RuntimePollFailure::Admission)?
                != *source
        {
            return Err(RuntimePollFailure::Admission(
                RuntimeError::UnsupportedFacet,
            ));
        }
        source
            .validate_metadata(lineage_limits, limits.maximum_record_bytes)
            .map_err(RuntimePollFailure::Admission)?;
        geometry
            .authenticate_attempt_construction(
                self,
                graph,
                activation,
                &capture_id,
                source,
                runtime_object,
            )
            .map_err(RuntimePollFailure::Admission)?;
        let mut owners = Vec::new();
        owners
            .try_reserve_exact(4)
            .map_err(|_| RuntimePollFailure::Admission(RuntimeError::ResourceLimit))?;
        let sequence = U64::new(
            u64::try_from(
                self.original_capture_count()
                    .map_err(RuntimePollFailure::Admission)?,
            )
            .map_err(|_| RuntimePollFailure::Admission(RuntimeError::ResourceLimit))?
                + 1,
        );
        let mut native_count = 0;
        let mut host_count = 0;
        for (index, policy) in graph.ownership_policy().capture_owners.iter().enumerate() {
            let mut participants = Vec::new();
            participants
                .try_reserve_exact(1)
                .map_err(|_| RuntimePollFailure::Admission(RuntimeError::ResourceLimit))?;
            for node in graph.node_ids().filter(|node| {
                graph.binding(node).is_some_and(|binding| {
                    binding.compatibility.capture_owner.id == policy.owner_id
                })
            }) {
                if !participants.is_empty() {
                    return Err(RuntimePollFailure::Admission(
                        RuntimeError::UnsupportedFacet,
                    ));
                }
                participants.push(node.clone());
            }
            if participants.len() != 1 {
                return Err(RuntimePollFailure::Admission(
                    RuntimeError::UnsupportedFacet,
                ));
            }
            let node_id = &participants[0];
            let binding = graph
                .binding(node_id)
                .ok_or(RuntimePollFailure::Admission(RuntimeError::UnknownNode))?;
            let guarantee = graph
                .guarantees(node_id)
                .ok_or(RuntimePollFailure::Admission(RuntimeError::InvalidReceipt))?;
            if guarantee.capture_scope != crucible_node_format::CaptureScope::CompleteModel
                || guarantee.continuation != crucible_node_format::Continuation::Exact
                || !guarantee.durable_restart
            {
                return Err(RuntimePollFailure::Admission(
                    RuntimeError::UnsupportedFacet,
                ));
            }
            match binding
                .compatibility
                .implementation
                .implementation_id
                .as_str()
            {
                "source-owned.packet-native/5" => native_count += 1,
                "source-owned.host-scheduling-owner/2" => host_count += 1,
                _ => {
                    return Err(RuntimePollFailure::Admission(
                        RuntimeError::UnsupportedFacet,
                    ));
                }
            }
            let owner = activation
                .record()
                .owners
                .iter()
                .find(|owner| owner.owner == policy.owner_id)
                .cloned()
                .ok_or(RuntimePollFailure::Admission(RuntimeError::InvalidReceipt))?;
            if binding.compatibility.execution_owner.id != policy.owner_id
                || binding.authority.incarnation_id != owner.incarnation
                || binding.authority.owner_generation != owner.generation
            {
                return Err(RuntimePollFailure::Admission(
                    RuntimeError::ForeignAuthority,
                ));
            }
            let operation = attempt_precharge::operation(sequence, index)
                .map_err(RuntimePollFailure::Admission)?;
            if self.operations.contains_key(&operation)
                || self.input_batches.contains_key(&operation)
                || self.administrative_operation_used(&operation)
                || !self
                    .scheduling_origin()
                    .map_err(RuntimePollFailure::Admission)?
                    .retained()
                    .map_err(RuntimePollFailure::Admission)?
                    .terminal_identity_available(&operation)
            {
                return Err(RuntimePollFailure::Admission(
                    RuntimeError::DuplicateOperation,
                ));
            }
            owners.push(OriginalCaptureOwnerReservation {
                owner,
                participants,
                operation,
                submitted: Cell::new(false),
                uncertain: Cell::new(false),
            });
        }
        if native_count != 3 || host_count != 1 {
            return Err(RuntimePollFailure::Admission(
                RuntimeError::UnsupportedFacet,
            ));
        }
        // Reserve the complete future settled journal metadata before any
        // native effect or clone. Settled references cannot consume optimistic
        // post-effect credit; the independent archive separately charges its bytes.
        let mut journal_credit = self
            .capture_journal_metadata_credit(limits.maximum_record_bytes)
            .map_err(RuntimePollFailure::Admission)?;
        charge_attempt_metadata(
            &mut journal_credit,
            activation.record(),
            &capture_id,
            &runtime_object.reference,
            &owners,
        )
        .map_err(RuntimePollFailure::Admission)?;
        crate::node_contract::NodeRuntime::capture_serialization_storage(
            source,
            limits.maximum_total_record_bytes,
        )
        .map_err(RuntimePollFailure::Admission)?;
        let value = serde_json::to_value(source)
            .map_err(|_| RuntimePollFailure::Admission(RuntimeError::InvalidReceipt))?;
        let bytes = canonical::canonical_json(&value)
            .map_err(|_| RuntimePollFailure::Admission(RuntimeError::InvalidReceipt))?;
        if bytes != runtime_object.bytes || bytes.len() > limits.maximum_record_bytes {
            return Err(RuntimePollFailure::Admission(RuntimeError::InvalidReceipt));
        }
        runtime_object
            .reference
            .verify(&bytes)
            .map_err(|_| RuntimePollFailure::Admission(RuntimeError::InvalidReceipt))?;
        // The equality check is complete. Release the temporary Value before
        // preparing the independently owned host snapshot or entering effects.
        drop(value);

        // The genuine host closure includes all original payload bodies. Read
        // it from this same runtime/source before any native control request;
        // no later callback reconstructs it from portable metadata.
        let host = geometry
            .take_prepared_host(self, activation, runtime_object)
            .map_err(RuntimePollFailure::Admission)?;
        let mut settlements = Vec::new();
        settlements
            .try_reserve_exact(owners.len())
            .map_err(|_| RuntimePollFailure::Admission(RuntimeError::ResourceLimit))?;
        settlements.resize_with(owners.len(), || None);
        let mut retained_captures = Vec::new();
        retained_captures
            .try_reserve_exact(owners.len())
            .map_err(|_| RuntimePollFailure::Admission(RuntimeError::ResourceLimit))?;
        retained_captures.resize_with(owners.len(), || None);
        let attempt = Rc::new(OriginalLineageCaptureAttempt {
            process: std::process::id(),
            thread: thread::current().id(),
            original: self
                .scheduling_origin()
                .map_err(RuntimePollFailure::Admission)?
                .source(),
            activation: activation.clone(),
            capture_id: capture_id.clone(),
            runtime_object: InputPayload {
                reference: runtime_object.reference.clone(),
                bytes,
            },
            cut: source.capture_cut,
            ordinal: source.capture_ordinal,
            lineage_limits,
            limits,
            host,
            owners,
            active: Cell::new(true),
            sequence,
            settlements: RefCell::new(settlements),
            captures: RefCell::new(retained_captures),
            persisted: OnceCell::new(),
        });
        // Inspect the constructed banks before registering an administrative
        // attempt. This includes the still-held encoded/decoded host snapshot,
        // all empty-slot capacity and the cloned runtime/reference metadata.
        // The source-selected callback banks remain simultaneously reserved.
        geometry
            .authenticate_prepared_attempt_storage(self, &attempt)
            .map_err(RuntimePollFailure::Admission)?;
        self.original_capture_attempts
            .insert(capture_id, Rc::clone(&attempt));
        if let Some(prepared) = prepared {
            attempt
                .host
                .with_original_scheduling_data(
                    self,
                    activation,
                    &attempt.runtime_object,
                    |host, scheduling| prepared(self, host, scheduling, &attempt.runtime_object),
                )
                .map_err(RuntimePollFailure::Admission)?;
        }
        // Registration changes actual retained Runtime ownership. Reobserve it
        // before the first current17 Source claim, with no private mutable loan.
        if let Some(observe) = after_owner.as_mut() {
            observe(self).map_err(RuntimePollFailure::Admission)?;
        }
        let mut remaining = limits;
        remaining.maximum_total_record_bytes = remaining
            .maximum_total_record_bytes
            .checked_sub(attempt.runtime_object.bytes.len())
            .and_then(|bytes| bytes.checked_sub(limits.maximum_record_bytes.checked_mul(2)?))
            .ok_or(RuntimePollFailure::Admission(RuntimeError::ResourceLimit))?;
        for (index, owner) in attempt.owners.iter().enumerate() {
            let selected = geometry
                .owner(index)
                .map_err(RuntimePollFailure::Admission)?;
            if selected.owner != owner.owner.owner
                || selected.participants != owner.participants
                || remaining.maximum_objects < selected.maximum_objects
                || remaining.maximum_total_record_bytes < selected.maximum_retained_bytes
            {
                return Err(RuntimePollFailure::Admission(RuntimeError::ResourceLimit));
            }
            let owner_limits = NativeCaptureLimits {
                maximum_record_bytes: selected.maximum_record_bytes,
                maximum_objects: selected.maximum_objects,
                maximum_total_record_bytes: selected.maximum_retained_bytes,
                ..remaining
            };
            if let Some(scope) = restored_scope {
                scope
                    .authenticate_runtime_data(self)
                    .map_err(RuntimePollFailure::Admission)?;
            }
            let ticket = OriginalLineageOwnerCaptureTicket {
                attempt: &attempt,
                owner,
                restored_scope,
            };
            // Acquire the already reserved custody slot before entering a
            // possibly effective native callback. No post-effect allocation or
            // reentrant borrow can discard a successfully returned body.
            let mut retained = attempt
                .captures
                .try_borrow_mut()
                .map_err(|_| RuntimePollFailure::Admission(RuntimeError::OutstandingObligations))?;
            let owner_result = (|| -> Result<(), RuntimePollFailure> {
                let slot = retained
                    .get_mut(index)
                    .ok_or(RuntimePollFailure::Admission(RuntimeError::InvalidReceipt))?;
                geometry.reloan_owner(self, activation, source, runtime_object, index)?;
                owner.submitted.set(true);
                // A panic, callback error or failed complete validation leaves this
                // same request explicitly uncertain under its original world hold.
                owner.uncertain.set(true);
                let node = self
                    .nodes
                    .get_mut(&owner.participants[0])
                    .ok_or(RuntimePollFailure::Admission(RuntimeError::UnknownNode))?;
                node.capture_original_lineage_continuation_with_ticket_into(
                    &ticket,
                    activation,
                    source,
                    runtime_object,
                    owner_limits,
                    slot,
                )
                .map_err(RuntimePollFailure::Native)?;
                let captured = slot
                    .as_ref()
                    .ok_or(RuntimePollFailure::Admission(RuntimeError::InvalidReceipt))?;
                geometry
                    .authenticate_owner_key(index, captured.native.key())
                    .map_err(RuntimePollFailure::Admission)?;
                if captured.native.owner() != &owner.owner.owner
                    || captured.native.participants() != owner.participants
                    || captured.native.cut() != attempt.cut
                    || !captured.native.artifacts().is_empty()
                {
                    return Err(RuntimePollFailure::Admission(RuntimeError::InvalidReceipt));
                }
                let binding = graph
                    .binding(&owner.participants[0])
                    .ok_or(RuntimePollFailure::Admission(RuntimeError::UnknownNode))?;
                if captured.native.key().implementation
                    != binding.compatibility.implementation.implementation_id
                    || !binding
                        .compatibility
                        .implementation
                        .formats
                        .contains(&captured.native.key().schema)
                    || !binding
                        .compatibility
                        .operating_contract
                        .facets
                        .iter()
                        .any(|facet| facet.id == captured.native.key().profile)
                {
                    return Err(RuntimePollFailure::Admission(RuntimeError::InvalidReceipt));
                }
                geometry::charge_retained_capture_objects(captured, owner_limits, &mut remaining)
                    .map_err(RuntimePollFailure::Admission)?;
                attempt.settlements.try_borrow_mut().map_err(|_| {
                    RuntimePollFailure::Admission(RuntimeError::OutstandingObligations)
                })?[index] = Some((
                    captured.native.state().reference.clone(),
                    captured.journal.reference.clone(),
                ));
                owner.uncertain.set(false);
                Ok(())
            })();
            drop(retained);
            // Node callbacks have returned, so their Source claims and this
            // private result-slot loan are both gone on success and refusal.
            if let Some(observe) = after_owner.as_mut() {
                observe(self).map_err(RuntimePollFailure::Admission)?;
            }
            owner_result?;
            if let Some(scope) = restored_scope {
                scope
                    .authenticate_runtime_data(self)
                    .map_err(RuntimePollFailure::Admission)?;
            }
        }
        // The original runtime retains each body even if this read handle is
        // dropped. The archive must persist the joint closure before any release.
        Ok(OriginalLineageWorldCapture { attempt })
    }
}

// The counting sink serializes existing borrowed metadata directly. It
// allocates neither a JSON Value nor cloned IDs, owner rows or content refs.
struct CaptureMetadataCredit {
    remaining: usize,
}

impl CaptureMetadataCredit {
    fn new(maximum: usize) -> Self {
        Self { remaining: maximum }
    }

    fn reserve(&mut self, bytes: usize) -> Result<(), RuntimeError> {
        self.remaining = self
            .remaining
            .checked_sub(bytes)
            .ok_or(RuntimeError::ResourceLimit)?;
        Ok(())
    }

    fn charge(&mut self, value: &impl serde::Serialize) -> Result<(), RuntimeError> {
        serde_json::to_writer(self, value).map_err(|_| RuntimeError::ResourceLimit)
    }
}

impl std::io::Write for CaptureMetadataCredit {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        self.reserve(bytes.len())
            .map_err(|_| std::io::Error::other("capture metadata credit exhausted"))?;
        Ok(bytes.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

fn charge_attempt_metadata(
    credit: &mut CaptureMetadataCredit,
    activation: &crate::node_contract::ActivationRecord,
    capture: &Id,
    runtime: &ContentRef,
    owners: &[OriginalCaptureOwnerReservation],
) -> Result<(), RuntimeError> {
    // Structural keys, decimal coordinates and wrappers fit within 1 KiB.
    // Two valid ContentRefs fit within 2 KiB (bounded 128-byte ASCII media
    // types/domains and fixed hashes), charged even before either is returned.
    credit.reserve(1024)?;
    credit.charge(&(
        activation.generation,
        &activation.activation_id,
        &activation.world_binding_hash,
        &activation.owners,
        activation.boundary,
        capture,
        runtime,
    ))?;
    for owner in owners {
        credit.reserve(3 * 1024)?;
        credit.charge(&(&owner.owner, &owner.participants, &owner.operation))?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    // Opaque core activation and custody are actual; native peers, capture
    // registration and physical readiness are explicitly modeled here.
    // crucible-lint: allow panic-shortcut -- modeled test fixtures use panics as assertion failures.
    #![allow(clippy::unwrap_used)]

    use super::*;

    pub(super) fn fixture() -> (
        crate::node_contract::NodeRuntime,
        OriginalLineageRuntimeRecord,
        OriginalLineageCaptureAttempt,
    ) {
        let (runtime, source) = super::super::super::tests::capture_ticket_fixture();
        let activation = runtime
            .operations
            .values()
            .next()
            .unwrap()
            .admission
            .activation()
            .clone();
        let bytes = canonical::canonical_json(&serde_json::to_value(&source).unwrap()).unwrap();
        let runtime_object = InputPayload {
            reference: canonical::content_ref(
                &bytes,
                "application/vnd.crucible.runtime-original-lineage+json;version=7",
            )
            .unwrap(),
            bytes,
        };
        let owner = activation.record().owners[0].clone();
        let attempt = OriginalLineageCaptureAttempt {
            process: std::process::id(),
            thread: thread::current().id(),
            original: runtime.scheduling_origin().unwrap().source(),
            activation,
            capture_id: Id::new("model/capture").unwrap(),
            runtime_object,
            cut: source.capture_cut,
            ordinal: source.capture_ordinal,
            lineage_limits: OriginalInputLineageLimits::default(),
            limits: NativeCaptureLimits {
                maximum_record_bytes: 2 * 1024 * 1024,
                maximum_total_record_bytes: 32 * 1024 * 1024,
                maximum_objects: 64,
                maximum_artifact_bytes: 0,
                maximum_total_artifact_bytes: 0,
            },
            host: host_preparation::family::PreparedHostCaptureFamily::Initial15(Rc::new(
                host_preparation::OriginalHostCapturePreparation::absent(),
            )),
            owners: vec![OriginalCaptureOwnerReservation {
                owner,
                participants: vec![Id::new("a").unwrap()],
                operation: Id::new("native-capture/1/0").unwrap(),
                submitted: Cell::new(true),
                uncertain: Cell::new(false),
            }],
            active: Cell::new(true),
            sequence: 1.into(),
            settlements: RefCell::new(vec![None]),
            captures: RefCell::new(vec![None]),
            persisted: OnceCell::new(),
        };
        (runtime, source, attempt)
    }

    #[test]
    fn unsupported_into_slot_capture_keeps_preowned_result_and_attempt_unchanged() {
        let (mut runtime, source, attempt) = fixture();
        let mut completed = Some(modeled_capture(&runtime));
        let original_reference = completed.as_ref().unwrap().native.state.reference.clone();
        let owner = &attempt.owners[0];
        let ticket = OriginalLineageOwnerCaptureTicket {
            attempt: &attempt,
            owner,
            restored_scope: None,
        };
        let node = runtime.nodes.values_mut().next().unwrap();

        let error = node
            .capture_original_lineage_continuation_with_ticket_into(
                &ticket,
                &attempt.activation,
                &source,
                &attempt.runtime_object,
                attempt.limits,
                &mut completed,
            )
            .unwrap_err();
        assert_eq!(error.effects, super::super::EffectKnowledge::None);
        assert_eq!(
            completed.as_ref().unwrap().native.state.reference,
            original_reference
        );
        assert!(owner.submitted.get());
        assert!(!owner.uncertain.get());
        assert!(attempt.active.get());

        let mut empty = None;
        let error = node
            .capture_original_lineage_continuation_with_ticket_into(
                &ticket,
                &attempt.activation,
                &source,
                &attempt.runtime_object,
                attempt.limits,
                &mut empty,
            )
            .unwrap_err();
        assert_eq!(error.effects, super::super::EffectKnowledge::None);
        assert!(empty.is_none());
    }

    #[test]
    fn modeled_ticket_conjuncts_actual_private_world_and_complete_original_bytes() {
        let (_runtime, source, attempt) = fixture();
        let owner = &attempt.owners[0];
        let ticket = OriginalLineageOwnerCaptureTicket {
            attempt: &attempt,
            owner,
            restored_scope: None,
        };
        ticket
            .authenticate_scope(
                &attempt.activation,
                &source,
                &attempt.runtime_object,
                &owner.owner,
                &owner.participants,
            )
            .unwrap();
        let mut foreign = attempt.activation.clone();
        foreign.authority = Rc::new(());
        assert!(matches!(
            ticket.authenticate_scope(
                &foreign,
                &source,
                &attempt.runtime_object,
                &owner.owner,
                &owner.participants
            ),
            Err(RuntimeError::ForeignAuthority)
        ));
        let changed = InputPayload {
            reference: attempt.runtime_object.reference.clone(),
            bytes: vec![],
        };
        assert!(
            ticket
                .authenticate_scope(
                    &attempt.activation,
                    &source,
                    &changed,
                    &owner.owner,
                    &owner.participants
                )
                .is_err()
        );
        owner.submitted.set(false);
        assert!(
            ticket
                .authenticate_scope(
                    &attempt.activation,
                    &source,
                    &attempt.runtime_object,
                    &owner.owner,
                    &owner.participants
                )
                .is_err()
        );
    }

    #[test]
    fn modeled_foreign_ticket_birth_refuses_before_original_source_or_parser() {
        let (_runtime, mut source, mut attempt) = fixture();
        attempt.process = std::process::id().wrapping_add(1);
        source.schema_version = 0;
        let owner = &attempt.owners[0];
        let ticket = OriginalLineageOwnerCaptureTicket {
            attempt: &attempt,
            owner,
            restored_scope: None,
        };
        assert!(matches!(
            ticket.authenticate_scope(
                &attempt.activation,
                &source,
                &attempt.runtime_object,
                &owner.owner,
                &owner.participants
            ),
            Err(RuntimeError::ForeignAuthority)
        ));
    }

    #[test]
    fn modeled_unsettled_capture_holds_actual_tokens_and_ordinary_mutations_without_replay() {
        let (mut runtime, _source, attempt) = fixture();
        let token = runtime
            .operations
            .values()
            .next()
            .unwrap()
            .admission
            .token()
            .clone();
        runtime
            .original_capture_attempts
            .insert(attempt.capture_id.clone(), Rc::new(attempt));
        assert_eq!(
            runtime.original_capture_journal().unwrap().attempts.len(),
            1
        );
        assert!(runtime.require_settled_capture_custody().is_err());
        let mut cx = std::task::Context::from_waker(std::task::Waker::noop());
        assert!(matches!(
            runtime.poll(&token, &mut cx),
            std::task::Poll::Ready(Err(super::super::RuntimePollFailure::Admission(
                RuntimeError::OutstandingObligations
            )))
        ));
        assert!(runtime.cancel(&token).is_err());
        assert!(runtime.close_quantum(&token).is_err());
        assert!(runtime.acknowledge(&token, &[]).is_err());
        assert!(runtime.status(&token.route().node).is_err());
        let recovered = runtime.recover(token.operation()).unwrap();
        assert_eq!(recovered.operation(), token.operation());
        assert_eq!(
            runtime.original_capture_journal().unwrap().attempts[0].owners[0].state,
            super::super::OriginalCaptureOwnerState::Submitted
        );
    }
    pub(super) fn modeled_capture(
        runtime: &crate::node_contract::NodeRuntime,
    ) -> super::super::InstalledOriginalLineageCapture {
        let binding = runtime.nodes.values().next().unwrap().binding();
        let state_bytes = b"{}".to_vec();
        let journal_bytes = b"[]".to_vec();
        super::super::InstalledOriginalLineageCapture {
            native: super::super::InstalledNativeCapture {
                owner: binding.compatibility.capture_owner.id.clone(),
                participants: binding.compatibility.capture_owner.participant_ids.clone(),
                key: super::super::NativeStateKey {
                    implementation: binding
                        .compatibility
                        .implementation
                        .implementation_id
                        .clone(),
                    profile: Id::new("model/capture-profile").unwrap(),
                    schema: crucible_node_format::SchemaRef {
                        id: Id::new("model/capture-state").unwrap(),
                        version: 1,
                        definition: canonical::content_ref(&state_bytes, "application/json")
                            .unwrap(),
                        extensions: Default::default(),
                    },
                },
                cut: Position::new(
                    0.into(),
                    0.into(),
                    crucible_node_format::Phase::BoundaryControl,
                ),
                state: InputPayload {
                    reference: canonical::content_ref(&state_bytes, "application/json").unwrap(),
                    bytes: state_bytes,
                },
                evidence: vec![],
                artifacts: vec![],
            },
            journal: InputPayload {
                reference: canonical::content_ref(&journal_bytes, "application/json").unwrap(),
                bytes: journal_bytes,
            },
        }
    }

    #[test]
    fn modeled_later_failure_keeps_successful_original_bodies_through_whole_custody_transfer() {
        let (mut runtime, _source, attempt) = fixture();
        let captured = modeled_capture(&runtime);
        let state_pointer = captured.native.state.bytes.as_ptr();
        let journal_pointer = captured.journal.bytes.as_ptr();
        attempt.captures.borrow_mut()[0] = Some(captured);
        // No settled marker models a later callback or validation failure.
        let attempt = Rc::new(attempt);
        let view = OriginalLineageWorldCapture {
            attempt: Rc::clone(&attempt),
        };
        assert!(view.read().is_err());
        runtime
            .original_capture_attempts
            .insert(attempt.capture_id.clone(), Rc::clone(&attempt));

        runtime.transfer_whole_custody();

        super::super::TEST_CUSTODIES.with(|custodies| {
            let custodies = custodies.borrow();
            let custody = custodies.last().unwrap();
            let retained = custody
                .original_capture_attempts
                .get(&attempt.capture_id)
                .unwrap();
            assert!(Rc::ptr_eq(retained, &attempt));
            assert!(custody.retirement_history_pending());
            let bodies = retained.captures.borrow();
            let captured = bodies[0].as_ref().unwrap();
            assert_eq!(captured.native.state.bytes.as_ptr(), state_pointer);
            assert_eq!(captured.journal.bytes.as_ptr(), journal_pointer);
        });
        assert!(view.read().is_err());
    }

    #[test]
    fn modeled_retained_registry_counts_independent_spare_key_and_typed_nodes() {
        let (mut runtime, _source, attempt) = fixture();
        let before = runtime.retained_original_capture_buffer_bytes().unwrap();
        let attempt_storage = storage::attempt(&attempt).unwrap();
        let mut spelling = String::with_capacity(65536);
        spelling.push_str(attempt.capture_id.as_str());
        let key = Id::new(spelling).unwrap();
        let key_capacity = key.allocated_capacity();
        let node_storage = crate::node_contract::NodeRuntime::capture_map_node_storage::<
            Id,
            Rc<OriginalLineageCaptureAttempt>,
        >();
        let original = Rc::new(attempt);
        runtime
            .original_capture_attempts
            .insert(key, Rc::clone(&original));

        let after = runtime.retained_original_capture_buffer_bytes().unwrap();

        assert!(after >= before + attempt_storage + key_capacity + node_storage);
        assert_eq!(runtime.original_capture_attempts.len(), 1);
        assert!(Rc::ptr_eq(
            runtime.original_capture_attempts.values().next().unwrap(),
            &original,
        ));
    }

    #[test]
    fn modeled_settled_read_handle_drop_does_not_discard_world_owned_capture_bodies() {
        let (mut runtime, _source, attempt) = fixture();
        let captured = modeled_capture(&runtime);
        let state_pointer = captured.native.state.bytes.as_ptr();
        attempt.settlements.borrow_mut()[0] = Some((
            captured.native.state.reference.clone(),
            captured.journal.reference.clone(),
        ));
        attempt.captures.borrow_mut()[0] = Some(captured);
        let attempt = Rc::new(attempt);
        runtime
            .original_capture_attempts
            .insert(attempt.capture_id.clone(), Rc::clone(&attempt));
        let view = OriginalLineageWorldCapture {
            attempt: Rc::clone(&attempt),
        };

        {
            let read = view.read().unwrap();
            assert_eq!(read.owners().count(), 1);
            assert_eq!(
                read.owners().next().unwrap().native.state.bytes.as_ptr(),
                state_pointer
            );
        }
        drop(view);

        assert!(runtime.require_settled_capture_custody().is_err());
        assert_eq!(
            attempt.captures.borrow()[0]
                .as_ref()
                .unwrap()
                .native
                .state
                .bytes
                .as_ptr(),
            state_pointer
        );
    }
    #[test]
    fn modeled_admin_history_refuses_model_id_reuse_without_reserving_unissued_names() {
        let (mut runtime, _source, attempt) = fixture();
        let issued = attempt.owners[0].operation.clone();
        let request = runtime
            .operations
            .values()
            .next()
            .unwrap()
            .admission
            .request()
            .clone();
        let activation = attempt.activation.clone();
        // This component models a settled/released archive. It does not claim
        // that an operational archive signer has released this original world.
        attempt.active.set(false);
        runtime
            .original_capture_attempts
            .insert(attempt.capture_id.clone(), Rc::new(attempt));

        assert!(runtime.administrative_operation_used(&issued));
        assert!(!runtime.administrative_operation_used(&Id::new("native-capture/1/9").unwrap()));
        assert!(matches!(
            runtime.begin(&activation, &Id::new("a").unwrap(), issued, request),
            Err(RuntimeError::DuplicateOperation)
        ));
    }

    #[test]
    fn modeled_administrative_metadata_is_precharged_before_copying_rows() {
        let (mut runtime, _source, attempt) = fixture();
        runtime
            .original_capture_attempts
            .insert(attempt.capture_id.clone(), Rc::new(attempt));

        assert!(matches!(
            runtime.original_capture_journal_with_limit(1),
            Err(RuntimeError::ResourceLimit)
        ));
        let maximum = 2 * 1024 * 1024;
        let credit = runtime.capture_journal_metadata_credit(maximum).unwrap();
        let journal = runtime
            .original_capture_journal_with_limit(maximum)
            .unwrap();
        let actual = canonical::canonical_json(&serde_json::to_value(journal).unwrap()).unwrap();

        assert!(maximum - credit.remaining >= actual.len());
        assert!(
            runtime
                .original_capture_attempts
                .values()
                .next()
                .unwrap()
                .active
                .get()
        );
    }

    struct LegacyOnlyFactory;

    impl crate::node_state::NativeWorldFactory for LegacyOnlyFactory {
        fn authenticate_original_lineage_capture(
            &self,
            _: &crate::node_admission::AdmittedGraph,
            _: &OriginalLineageRuntimeRecord,
            _: &crate::node_scheduling::SchedulingSnapshot,
        ) -> Result<(), crate::node_state::StateError> {
            // Deliberately modeled old-codec support must not select the new route.
            Ok(())
        }

        fn authenticate_source(
            &self,
            _: &crate::node_admission::AdmittedGraph,
            _: &crucible_node_format::CapturedOwner,
            _: &crate::node_state::AuthenticatedNativeSource<'_>,
        ) -> Result<(), crate::node_state::StateError> {
            Err(unsupported_factory())
        }

        fn authenticate_coordinator(
            &self,
            _: &crate::node_admission::AdmittedGraph,
            _: &crate::node_contract::RuntimeSnapshot,
            _: &crate::node_scheduling::SchedulingSnapshot,
            _: &crate::node_state::VerifiedStateContent,
        ) -> Result<(), crate::node_state::StateError> {
            Err(unsupported_factory())
        }

        fn reservation(
            &self,
            _: &crate::node_admission::AdmittedGraph,
            _: &crucible_node_format::CapturedOwner,
            _: &crate::node_state::AuthenticatedNativeSource<'_>,
            _: crate::node_state::NativeArchiveLimits,
        ) -> Result<crate::node_state::RestoreReservations, crate::node_state::StateError> {
            Err(unsupported_factory())
        }

        fn empty_staging(
            &self,
            _: Rc<crate::node_admission::AdmittedGraph>,
            _: crate::node_state::NativeArchiveRecord,
            _: &crate::node_contract::ActivationRecord,
            _: crate::node_state::RestoreReservations,
            _: crate::node_state::NativeArchiveLimits,
        ) -> Result<Box<dyn crate::node_state::NativeRestoreStaging>, crate::node_state::StateError>
        {
            Err(unsupported_factory())
        }
    }

    fn unsupported_factory() -> crate::node_state::StateError {
        crate::node_state::StateError::new(
            crate::node_state::StateErrorCode::NativeEvidence,
            "model/legacy-only",
            "no modeled native callback is permitted",
        )
    }

    #[test]
    fn modeled_old_factory_support_does_not_select_complete_original_capture() {
        use crate::node_state::NativeWorldFactory;

        let (_, source, _) = fixture();
        let (graph, runtime, activation) =
            super::super::super::tests::host_continuation_runtime_fixture();
        // This factory-selection control uses a normally initialized core
        // allocation. Native source rows remain modeled selection arguments;
        // no original-lineage capture or cross-world association is asserted.
        let scheduler = runtime
            .host_scheduler_snapshot(activation.record().boundary, 0.into())
            .unwrap();
        let factory = LegacyOnlyFactory;
        factory
            .authenticate_original_lineage_capture(&graph, &source, &scheduler)
            .unwrap();

        let refusal = factory
            .authenticate_complete_original_lineage_capture(&graph, &source, &scheduler)
            .unwrap_err();

        assert_eq!(
            refusal.code,
            crate::node_state::StateErrorCode::NativeEvidence
        );
        assert_eq!(
            refusal.reason,
            "installed complete original capture preparation is unsupported"
        );
        assert!(runtime.original_capture_attempts.is_empty());
    }

    fn modeled_geometry_plan(
        attempt: &OriginalLineageCaptureAttempt,
        retained: usize,
        transient: usize,
    ) -> crate::node_state::CompleteOriginalCaptureGeometry {
        // This tests private issuer/credit mechanics only. The single modeled
        // row is not a four-owner factory plan and cannot qualify capture.
        crate::node_state::CompleteOriginalCaptureGeometry {
            owners: vec![crate::node_state::CompleteOriginalOwnerCaptureGeometry {
                owner: attempt.owners[0].owner.owner.clone(),
                participants: attempt.owners[0].participants.clone(),
                maximum_record_bytes: attempt.limits.maximum_record_bytes,
                maximum_objects: 2,
                maximum_retained_bytes: retained,
                maximum_dependency_edges: 0,
                maximum_transient_bytes: transient,
            }],
        }
    }

    #[test]
    fn modeled_geometry_seal_requires_same_original_runtime_activation_and_capture_id() {
        let (runtime, _, mut attempt) = fixture();
        attempt.limits.maximum_total_record_bytes = 128 * 1024 * 1024;
        let prepared = runtime
            .prepare_complete_capture_geometry(
                &attempt.activation,
                &attempt.capture_id,
                &attempt.runtime_object,
                modeled_geometry_plan(&attempt, 4 * 1024 * 1024, 0),
                attempt.limits,
            )
            .unwrap();
        prepared
            .authenticate(
                &runtime,
                &attempt.activation,
                &attempt.capture_id,
                &attempt.runtime_object,
                attempt.limits,
            )
            .unwrap();

        let (foreign, _, other) = fixture();
        assert_eq!(attempt.activation.record(), other.activation.record());
        assert!(
            prepared
                .authenticate(
                    &foreign,
                    &other.activation,
                    &attempt.capture_id,
                    &attempt.runtime_object,
                    attempt.limits
                )
                .is_err()
        );
        assert!(
            prepared
                .authenticate(
                    &runtime,
                    &attempt.activation,
                    &Id::new("different/capture").unwrap(),
                    &attempt.runtime_object,
                    attempt.limits
                )
                .is_err()
        );
        assert!(runtime.original_capture_attempts.is_empty());
    }

    #[test]
    fn modeled_prepared_attempt_accounts_spare_metadata_before_registration() {
        // The actor is modeled; this checks actual core banks and registration
        // order without issuing native or whole-world capture permission.
        let (runtime, _, mut attempt) = fixture();
        attempt.limits.maximum_total_record_bytes = 128 * 1024 * 1024;
        let prepared = runtime
            .prepare_complete_capture_geometry(
                &attempt.activation,
                &attempt.capture_id,
                &attempt.runtime_object,
                modeled_geometry_plan(&attempt, 4 * 1024 * 1024, 0),
                attempt.limits,
            )
            .unwrap();
        prepared
            .authenticate_prepared_attempt_storage(&runtime, &attempt)
            .unwrap();

        let submitted_before: Vec<_> = attempt
            .owners
            .iter()
            .map(|owner| owner.submitted.get())
            .collect();
        let requested_slots = attempt.limits.maximum_total_record_bytes
            / std::mem::size_of::<OriginalCaptureOwnerReservation>()
            + 1;
        attempt.owners.reserve_exact(requested_slots);
        assert_eq!(
            prepared.authenticate_prepared_attempt_storage(&runtime, &attempt),
            Err(RuntimeError::ResourceLimit),
        );
        assert!(runtime.original_capture_attempts.is_empty());
        assert!(
            attempt
                .owners
                .iter()
                .map(|owner| owner.submitted.get())
                .eq(submitted_before)
        );
    }

    #[test]
    fn modeled_geometry_peak_refuses_before_any_administrative_registration() {
        let (runtime, _, mut attempt) = fixture();
        attempt.limits.maximum_total_record_bytes = 96 * 1024 * 1024;
        let result = runtime.prepare_complete_capture_geometry(
            &attempt.activation,
            &attempt.capture_id,
            &attempt.runtime_object,
            modeled_geometry_plan(&attempt, 8 * 1024 * 1024, 8 * 1024 * 1024),
            attempt.limits,
        );
        assert!(matches!(result, Err(RuntimeError::ResourceLimit)));
        assert!(runtime.original_capture_attempts.is_empty());
    }

    #[test]
    fn modeled_geometry_seal_refuses_changed_limits_and_changed_original_bytes() {
        let (runtime, _, mut attempt) = fixture();
        attempt.limits.maximum_total_record_bytes = 128 * 1024 * 1024;
        let prepared = runtime
            .prepare_complete_capture_geometry(
                &attempt.activation,
                &attempt.capture_id,
                &attempt.runtime_object,
                modeled_geometry_plan(&attempt, 4 * 1024 * 1024, 0),
                attempt.limits,
            )
            .unwrap();
        let mut changed_limits = attempt.limits;
        changed_limits.maximum_objects += 1;
        assert!(
            prepared
                .authenticate(
                    &runtime,
                    &attempt.activation,
                    &attempt.capture_id,
                    &attempt.runtime_object,
                    changed_limits
                )
                .is_err()
        );
        attempt.runtime_object.bytes.push(b' ');
        assert!(
            prepared
                .authenticate(
                    &runtime,
                    &attempt.activation,
                    &attempt.capture_id,
                    &attempt.runtime_object,
                    attempt.limits
                )
                .is_err()
        );
        assert!(runtime.original_capture_attempts.is_empty());
    }

    #[test]
    fn modeled_geometry_retained_spare_capacity_is_charged_before_registration() {
        let (mut runtime, _, mut attempt) = fixture();
        attempt.limits.maximum_total_record_bytes = 96 * 1024 * 1024;
        let mut prior = fixture().2;
        prior.original = runtime.scheduling_origin().unwrap().source();
        prior.activation = attempt.activation.clone();
        prior.capture_id = Id::new("old/capture").unwrap();
        prior.runtime_object.bytes.reserve_exact(32 * 1024 * 1024);
        prior.active.set(false);
        let capacity = storage::payload(&prior.runtime_object).unwrap();
        assert!(capacity >= 32 * 1024 * 1024);
        assert!(prior.runtime_object.bytes.len() < 1024 * 1024);
        runtime
            .original_capture_attempts
            .insert(prior.capture_id.clone(), Rc::new(prior));
        // The raw spare bank is a lower bound; original rows, references and
        // retained metadata own additional allocations independently.
        assert!(runtime.retained_original_capture_buffer_bytes().unwrap() >= capacity);

        let result = runtime.prepare_complete_capture_geometry(
            &attempt.activation,
            &attempt.capture_id,
            &attempt.runtime_object,
            modeled_geometry_plan(&attempt, 4 * 1024 * 1024, 0),
            attempt.limits,
        );
        assert!(matches!(result, Err(RuntimeError::ResourceLimit)));
        assert_eq!(runtime.original_capture_attempts.len(), 1);
        assert!(
            !runtime
                .original_capture_attempts
                .contains_key(&attempt.capture_id)
        );
    }

    #[test]
    fn modeled_geometry_retained_buffer_guard_refuses_foreign_and_borrowed_owners() {
        let (mut runtime, _, mut prior) = fixture();
        prior.capture_id = Id::new("old/capture").unwrap();
        let prior = Rc::new(prior);
        runtime
            .original_capture_attempts
            .insert(prior.capture_id.clone(), prior.clone());
        let held = prior.captures.borrow_mut();
        assert_eq!(
            runtime.retained_original_capture_buffer_bytes(),
            Err(RuntimeError::OutstandingObligations)
        );
        drop(held);
        assert!(runtime.retained_original_capture_buffer_bytes().is_ok());

        let (foreign_runtime, _, mut foreign) = fixture();
        foreign.capture_id = Id::new("foreign/capture").unwrap();
        runtime
            .original_capture_attempts
            .insert(foreign.capture_id.clone(), Rc::new(foreign));
        assert_eq!(
            runtime.retained_original_capture_buffer_bytes(),
            Err(RuntimeError::ForeignAuthority)
        );
        drop(foreign_runtime);
    }

    #[test]
    fn modeled_returned_capacity_refusal_keeps_original_buffers_and_world_hold() {
        let (mut runtime, _, attempt) = fixture();
        let mut captured = modeled_capture(&runtime);
        captured.native.state.bytes.reserve_exact(8192);
        let pointer = captured.native.state.bytes.as_ptr();
        let owner = &attempt.owners[0];
        owner.uncertain.set(true);
        attempt.captures.borrow_mut()[0] = Some(captured);
        let selected = NativeCaptureLimits {
            maximum_total_record_bytes: 4096,
            ..attempt.limits
        };
        let mut remaining = attempt.limits;
        let before = remaining.maximum_total_record_bytes;
        let result = {
            let retained = attempt.captures.borrow();
            geometry::charge_retained_capture_objects(
                retained[0].as_ref().unwrap(),
                selected,
                &mut remaining,
            )
        };

        assert_eq!(result, Err(RuntimeError::ResourceLimit));
        assert_eq!(remaining.maximum_total_record_bytes, before);
        assert!(attempt.settlements.borrow()[0].is_none());
        let attempt = Rc::new(attempt);
        let view = OriginalLineageWorldCapture {
            attempt: Rc::clone(&attempt),
        };
        runtime
            .original_capture_attempts
            .insert(attempt.capture_id.clone(), Rc::clone(&attempt));

        assert!(view.read().is_err());
        assert!(runtime.require_settled_capture_custody().is_err());
        assert!(attempt.owners[0].uncertain.get());
        assert_eq!(
            attempt.captures.borrow()[0]
                .as_ref()
                .unwrap()
                .native
                .state
                .bytes
                .as_ptr(),
            pointer
        );
    }

    #[test]
    fn modeled_returned_capacity_charges_independent_equal_hash_buffers() {
        let (runtime, _, attempt) = fixture();
        let mut captured = modeled_capture(&runtime);
        let mut same_bytes = Vec::with_capacity(128);
        same_bytes.extend_from_slice(&captured.native.state.bytes);
        captured.native.evidence.push(InputPayload {
            reference: captured.native.state.reference.clone(),
            bytes: same_bytes,
        });
        let total = storage::captured(&captured).unwrap();
        let selected = NativeCaptureLimits {
            maximum_objects: 3,
            maximum_total_record_bytes: total,
            ..attempt.limits
        };
        let mut remaining = selected;

        geometry::charge_retained_capture_objects(&captured, selected, &mut remaining).unwrap();

        assert_eq!(remaining.maximum_total_record_bytes, 0);
        assert_eq!(remaining.maximum_objects, 0);
        let mut too_small = selected;
        too_small.maximum_total_record_bytes -= 1;
        assert_eq!(
            geometry::charge_retained_capture_objects(&captured, selected, &mut too_small),
            Err(RuntimeError::ResourceLimit)
        );
        assert_eq!(too_small.maximum_objects, selected.maximum_objects);
    }

    #[test]
    fn modeled_returned_metadata_spare_capacity_refuses_without_releasing_originals() {
        for shape in 0..5 {
            let (runtime, _, attempt) = fixture();
            let mut captured = modeled_capture(&runtime);
            match shape {
                0 => captured.native.evidence.reserve_exact(4096),
                1 => captured.native.participants.reserve_exact(4096),
                2 => captured.native.artifacts.reserve_exact(4096),
                3 => {
                    let mut owner = String::with_capacity(8192);
                    owner.push_str(captured.native.owner.as_str());
                    captured.native.owner = Id::new(owner).unwrap();
                }
                _ => captured
                    .native
                    .state
                    .reference
                    .media_type
                    .reserve_exact(8192),
            }
            let pointer = captured.native.state.bytes.as_ptr();
            attempt.owners[0].uncertain.set(true);
            attempt.captures.borrow_mut()[0] = Some(captured);
            let selected = NativeCaptureLimits {
                maximum_total_record_bytes: 4096,
                ..attempt.limits
            };
            let mut remaining = attempt.limits;
            let result = {
                let retained = attempt.captures.borrow();
                geometry::charge_retained_capture_objects(
                    retained[0].as_ref().unwrap(),
                    selected,
                    &mut remaining,
                )
            };

            assert_eq!(result, Err(RuntimeError::ResourceLimit), "shape {shape}");
            assert!(attempt.settlements.borrow()[0].is_none());
            assert!(attempt.owners[0].uncertain.get());
            assert_eq!(
                attempt.captures.borrow()[0]
                    .as_ref()
                    .unwrap()
                    .native
                    .state
                    .bytes
                    .as_ptr(),
                pointer
            );
        }
    }

    #[test]
    fn modeled_returned_logical_limit_precedes_hash_frame_copy() {
        let (runtime, _, attempt) = fixture();
        let mut captured = modeled_capture(&runtime);
        captured.native.state.bytes.resize(8192, 0);
        captured.native.state.reference.length = U64::new(8192);
        captured.native.state.reference.hash.digest = "0".repeat(64);
        let pointer = captured.native.state.bytes.as_ptr();
        attempt.owners[0].uncertain.set(true);
        attempt.captures.borrow_mut()[0] = Some(captured);
        let selected = NativeCaptureLimits {
            maximum_record_bytes: 4096,
            ..attempt.limits
        };
        let mut remaining = attempt.limits;
        let before = remaining.maximum_total_record_bytes;
        let result = geometry::charge_retained_capture_objects(
            attempt.captures.borrow()[0].as_ref().unwrap(),
            selected,
            &mut remaining,
        );

        // Verifying this syntactically valid wrong hash first would copy the
        // oversized frame and return InvalidReceipt instead of finite refusal.
        assert_eq!(result, Err(RuntimeError::ResourceLimit));
        assert_eq!(remaining.maximum_total_record_bytes, before);
        assert!(attempt.owners[0].uncertain.get());
        assert!(attempt.settlements.borrow()[0].is_none());
        assert_eq!(
            attempt.captures.borrow()[0]
                .as_ref()
                .unwrap()
                .native
                .state
                .bytes
                .as_ptr(),
            pointer
        );
    }

    #[test]
    fn modeled_geometry_seal_refuses_equal_bytes_with_unadmitted_spare_bank() {
        let (runtime, _, mut attempt) = fixture();
        attempt.limits.maximum_total_record_bytes = 128 * 1024 * 1024;
        let prepared = runtime
            .prepare_complete_capture_geometry(
                &attempt.activation,
                &attempt.capture_id,
                &attempt.runtime_object,
                modeled_geometry_plan(&attempt, 4 * 1024 * 1024, 0),
                attempt.limits,
            )
            .unwrap();
        let mut replacement = attempt.runtime_object.clone();
        replacement.bytes.reserve_exact(512 * 1024);
        assert_eq!(replacement.reference, attempt.runtime_object.reference);
        assert_eq!(replacement.bytes, attempt.runtime_object.bytes);

        assert_eq!(
            prepared.authenticate(
                &runtime,
                &attempt.activation,
                &attempt.capture_id,
                &replacement,
                attempt.limits
            ),
            Err(RuntimeError::ResourceLimit)
        );
        assert!(runtime.original_capture_attempts.is_empty());
    }
}

#[cfg(test)]
impl OriginalLineageWorldCapture {
    /// Supplies actual private Core custody with explicitly modeled native bodies.
    pub(crate) fn modeled_archive_write_origin_fixture() -> (
        crate::node_contract::NodeRuntime,
        OriginalLineageRuntimeRecord,
        Self,
    ) {
        let (mut runtime, source, mut attempt) = tests::fixture();
        // The ticket fixture selects only a. Original archive write purpose
        // requires the full shared-owner roster from this same node binding.
        attempt.owners[0].participants = runtime
            .nodes
            .values()
            .next()
            .unwrap()
            .binding()
            .compatibility
            .capture_owner
            .participant_ids
            .clone();
        let mut captured = tests::modeled_capture(&runtime);
        captured.native.cut = attempt.cut;
        attempt.settlements.borrow_mut()[0] = Some((
            captured.native.state.reference.clone(),
            captured.journal.reference.clone(),
        ));
        attempt.captures.borrow_mut()[0] = Some(captured);
        let attempt = Rc::new(attempt);
        runtime
            .original_capture_attempts
            .insert(attempt.capture_id.clone(), Rc::clone(&attempt));
        (runtime, source, Self { attempt })
    }

    pub(crate) fn erase_modeled_archive_write_active(&self) {
        self.attempt.active.set(false);
    }

    pub(crate) fn modeled_archive_write_hold_retained(
        &self,
        runtime: &crate::node_contract::NodeRuntime,
    ) -> bool {
        self.attempt.active.get()
            && runtime
                .original_capture_attempts
                .get(&self.attempt.capture_id)
                .is_some_and(|original| Rc::ptr_eq(original, &self.attempt))
    }
}
