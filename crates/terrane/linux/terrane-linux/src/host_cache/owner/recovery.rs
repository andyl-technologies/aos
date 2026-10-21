//! Runs serialized actual recovery without conflating it with tier readiness.
//!
//! Supported cases preserve cold policy and reconcile empty, inline
//! and manifest content using actual verified metadata and native bindings.
//! Standalone encoded chunks retain their verified original native sources;
//! acknowledged Resume imports those sources into actual cache custody.
//! Unknown names, unhandled private publication state, temporary files,
//! unhandled pending bodies and every other unhandled candidate remain non-ready.
//! Expired, unpinned pending chunks can be removed under funded recovery.
//! A receipt requires real shared/private scans, durable state, synchronized allocation,
//! fresh authenticated quota charges and the original successful drain epoch.
//! No Resume or file-bucket readiness is granted by this module.

use super::{
    recovery_accounting::{self, SynchronizedAllocation},
    recovery_candidates, recovery_encoded, recovery_indexes,
    recovery_inline::{self, AdoptedInline},
    recovery_manifest_state, recovery_manifests,
    recovery_namespace::SharedNamespaceObservation,
    recovery_pending, recovery_state,
    recovery_state_parent::StateParentObservation,
    retention::{Command, Custody, NativeMetadataOwner, NativeOwnerExecutor},
};
use crate::{
    host_cache::NativeRecoveryInspection,
    host_quota::synchronized_allocated_bytes,
    publisher_local::client::{Client, PublisherRecoveryContext},
};
use std::{
    io,
    sync::{Arc, Mutex, mpsc},
};
use terrane_sdk::host::cache::HostDomainLocation;
use tokio::sync::oneshot;

/// Retains genuine completion of a supported, fully reconciled recovery case.
///
/// Only the physical owner constructs this after exhaustive actual observations
/// and durable reconciliation. It cannot be constructed from a boolean, caller
/// epoch or file. It does not prove BKT-15 bucket validity, grant service handles,
/// resume exposures or authorize native admission. The physical owner may consume
/// it through its serialized publisher Resume handoff; that grants no Store readiness.
pub struct CompletedRecovery {
    /// Retains actual physical state/source ownership through this receipt.
    pub(super) custody: Arc<Mutex<Custody>>,
    /// Retains the original authenticated client instance.
    pub(super) session: Arc<Client<HostDomainLocation>>,
    /// Retains the original acknowledged Drain barrier, never a recaptured epoch.
    pub(super) context: PublisherRecoveryContext<HostDomainLocation>,
    /// Retains the exhaustive original shared namespace observation.
    pub(super) shared: SharedNamespaceObservation,
    /// Retains exact supported state-parent children and native custody.
    pub(super) state_parent: StateParentObservation,
    /// Retains the final exhaustive Inspector report.
    pub(super) inventory: NativeRecoveryInspection,
    /// Identifies the actual final owner mutation generation.
    pub(super) generation: u64,
    /// Names the real durable bootstrap reservation for this recovery.
    pub(super) recovery_id: [u8; 16],
    /// Records synchronized blocks only for the explicitly retained inodes.
    pub(super) allocation: SynchronizedAllocation,
    /// Records the separate fresh authenticated full-owner quota boundary.
    pub(super) charged_reserved_bytes: u64,
    /// Records distinct durable logical future holds, never physical allocation.
    pub(super) future_hold_bytes: u64,
    /// Retains actual adopted inline native handles independently of state reads.
    pub(super) adopted_inline: Vec<AdoptedInline>,
    /// Retains independent manifest/source/plaintext verification results.
    pub(super) manifest_results:
        Vec<Arc<crate::host_cache::recovery_inspection::VerifiedRecoveryManifest>>,
    /// Retains the exact verified full-pack/index source closure.
    pub(super) metadata_sources: Vec<Arc<crate::host_cache::NativeManifestSource>>,
    /// Retains actual independently verified standalone source inodes.
    pub(super) encoded_chunks: Vec<Arc<crate::host_cache::VerifiedStandaloneChunk>>,
    /// Retains exact reconstructed and preserved policy for a manifest case.
    pub(super) expected_policy: Option<terrane_sdk::host::cache::CacheState>,
}

/// Retains original owner and funding provenance after acknowledged Resume.
///
/// Cold inventory descriptors must not survive as hidden references to later
/// unlinked cache inodes. Actual adopted sources already belong to the physical
/// executor; standalone sources transfer there before any fallible import.
pub(crate) struct RunningRecovery {
    _custody: Arc<Mutex<Custody>>,
    bootstrap_id: [u8; 16],
    encoded_chunks: Vec<Arc<crate::host_cache::VerifiedStandaloneChunk>>,
}

impl RunningRecovery {
    /// Borrows the actual bootstrap registration retained after Resume.
    pub(crate) fn retained_bootstrap_id(&self) -> &[u8; 16] {
        &self.bootstrap_id
    }

    /// Transfers original standalone sources to the sole physical executor.
    pub(crate) fn take_encoded_sources(
        &mut self,
    ) -> Vec<Arc<crate::host_cache::VerifiedStandaloneChunk>> {
        std::mem::take(&mut self.encoded_chunks)
    }
}

impl CompletedRecovery {
    /// Compares actual producer custody without accepting an external authority token.
    pub(super) fn matches_custody(&self, custody: &Arc<Mutex<Custody>>) -> bool {
        Arc::ptr_eq(&self.custody, custody)
    }

    /// Borrows the actual producer session without acquiring its RPC mutex.
    pub(crate) fn publisher_session(&self) -> Arc<Client<HostDomainLocation>> {
        Arc::clone(&self.session)
    }

    /// Borrows the actual successful drain context; it contains no caller epoch.
    pub(crate) fn publisher_context(&self) -> &PublisherRecoveryContext<HostDomainLocation> {
        &self.context
    }

    /// Consumes cold observations only after the actual publisher acknowledges Resume.
    ///
    /// The owner already retains all adopted inline and manifest resources.
    /// Dropping exhaustive cold observations releases their duplicate handles;
    /// they cannot keep later retired sources charged outside the registry.
    pub(crate) fn into_running(self) -> RunningRecovery {
        RunningRecovery {
            _custody: self.custody,
            bootstrap_id: self.recovery_id,
            encoded_chunks: self.encoded_chunks,
        }
    }

    /// Returns synchronized allocation of the explicitly retained native inodes.
    ///
    /// This deduplicated st_blocks sum excludes unobserved filesystem metadata
    /// and private descendant inodes. It is not full project charge or a hold.
    pub fn synchronized_retained_inode_bytes(&self) -> u64 {
        self.allocation.retained_inode_bytes
    }

    /// Returns the number of distinct inodes in that synchronized observation.
    pub fn synchronized_retained_inodes(&self) -> usize {
        self.allocation.retained_inodes
    }

    /// Returns authenticated charged-and-reserved project usage at completion.
    ///
    /// This kernel observation is distinct from synchronized inode blocks and
    /// policy holds. It is a boundary snapshot, not a promise of unchanged usage.
    pub fn charged_reserved_bytes(&self) -> u64 {
        self.charged_reserved_bytes
    }

    /// Returns the durable logical future hold retained by this recovery owner.
    pub fn future_hold_bytes(&self) -> u64 {
        self.future_hold_bytes
    }

    /// Rechecks actual owner generation, namespaces, state and native custody.
    ///
    /// This may lock embedded state and must precede a consumer's RPC lock. It
    /// is never called on an already-sealed read. The consumer must separately
    /// check the opaque publisher context atomically under its actual RPC lock.
    ///
    /// # Errors
    /// Refuses changed generations/roots/names, faulted custody, missing durable
    /// state, another actual session or changed bootstrap policy records.
    pub fn check_current(&self) -> io::Result<()> {
        let owner = self
            .custody
            .lock()
            .map_err(|_| io::Error::other("recovery custody poisoned"))?;
        owner.check_current()?;
        if owner.faulted
            || owner.recovery_required
            || owner.snapshot.is_none()
            || owner.generation != self.generation
            || owner.recovery_id != Some(self.recovery_id)
            || !Arc::ptr_eq(&self.session, &owner.preparation.publisher_session())
        {
            return Err(invalid(
                "recovery completion no longer matches actual owner custody",
            ));
        }
        if let Some(expected) = &self.expected_policy {
            recovery_manifest_state::require_same(&owner.state, expected)?;
            recovery_encoded::check(&self.inventory, &self.encoded_chunks, &expected.residences)?;
            self.shared
                .require_sources(&self.metadata_sources, &self.encoded_chunks)?;
            self.state_parent.check_current()?;
            self.inventory.check_current()?;
            recovery_manifests::check_inventory(
                &self.inventory,
                &self.manifest_results,
                &self.metadata_sources,
                owner.preparation.layout(),
                &self.adopted_inline,
                &self.encoded_chunks,
            )?;
            drop(owner);
            for body in &self.manifest_results {
                body.check_current(&self.context)?;
            }
            return self
                .session
                .check_recovery_context(&self.context)
                .map_err(io::Error::other);
        }
        let claims = recovery_inline::selected_claims(&self.inventory, owner.preparation.layout())?;
        recovery_state::check_reconciled(
            &owner.preparation.config,
            &owner.state,
            &self.recovery_id,
            owner
                .recovery_cold
                .as_ref()
                .ok_or_else(|| invalid("recovery lost original cold policy candidates"))?,
            &recovery_encoded::sealed_residences(
                recovery_inline::residences(&claims),
                &self.encoded_chunks,
            )?,
            &recovery_encoded::hashes(&self.encoded_chunks),
        )?;
        recovery_encoded::check(
            &self.inventory,
            &self.encoded_chunks,
            &owner.state.residences,
        )?;
        self.shared.require_sources(&[], &self.encoded_chunks)?;
        self.state_parent.check_current()?;
        self.inventory.check_current()?;
        recovery_inline::check_subset(
            &self.inventory,
            owner.preparation.layout(),
            &self.adopted_inline,
        )
    }
}

impl NativeMetadataOwner {
    /// Runs bounded actual recovery in the retained physical command queue.
    ///
    /// Supported cases require reconciled cold policy and an exhaustively
    /// verified empty, inline, manifest or mixed namespace. Other cases remain unresolved;
    /// no record is auto-cleared and no exposure is resumed. Request cancellation
    /// never cancels accepted physical work or releases its durable future hold.
    ///
    /// # Errors
    /// Refuses a full/stopped queue, unresolved records/names/candidates, failed
    /// native synchronization, uncertain transport, quota excess and a changed
    /// publisher barrier. Late failure retains faulted custody and its hold.
    pub async fn recover(&self) -> io::Result<CompletedRecovery> {
        let (response, receive) = oneshot::channel();
        self.commands
            .as_ref()
            .ok_or_else(|| io::Error::other("native recovery owner stopped"))?
            .try_send(Command::Recover { response })
            .map_err(|error| match error {
                mpsc::TrySendError::Full(_) => {
                    io::Error::new(io::ErrorKind::WouldBlock, "native recovery queue is full")
                }
                mpsc::TrySendError::Disconnected(_) => {
                    io::Error::other("native recovery owner stopped")
                }
            })?;
        receive
            .await
            .map_err(|_| io::Error::other("native recovery owner terminated before completion"))?
    }
}

/// Completes a supported recovery case on the actual exclusive physical executor.
///
/// # Errors
/// Refuses every unresolved record/name/candidate, stale native or publisher
/// custody, failed durability, unknown quota or excessive actual charge. After
/// the first snapshot attempt, failures retain the owner's hold and fault state.
pub(super) async fn run(executor: &mut NativeOwnerExecutor) -> io::Result<CompletedRecovery> {
    let custody = Arc::clone(executor.custody());
    let (session, inspector, mut shared, state_parent, requires_cold_backing) = {
        let mut owner = custody
            .lock()
            .map_err(|_| io::Error::other("recovery custody poisoned"))?;
        owner.check_current()?;
        if owner.faulted {
            return Err(io::Error::new(
                io::ErrorKind::WouldBlock,
                "failed physical work requires native reconciliation",
            ));
        }
        if !owner.recovery_required {
            return Err(unresolved(
                "native recovery already completed for this physical owner",
            ));
        }
        owner.recovery_id = None;
        // Validate original lease and charge ownership before any durable change.
        // The captured records are candidates; actual adoption still follows the
        // new synchronized bootstrap and original publisher Drain context.
        super::recovery_cold::ColdPolicy::capture(&owner.preparation.config, &owner.state)?;
        let requires_cold_backing =
            !owner.state.pins.is_empty() || !owner.state.residences.is_empty();
        let state_parent = StateParentObservation::inspect(&owner.preparation)?;
        let shared = SharedNamespaceObservation::inspect(&owner.preparation)?;
        (
            owner.preparation.publisher_session(),
            owner.preparation.recovery_inspector()?,
            shared,
            state_parent,
            requires_cold_backing,
        )
    };
    // No embedded guard is held while acquiring the actual client RPC mutex.
    let context = session.recovery_context().map_err(io::Error::other)?;
    session
        .check_recovery_context(&context)
        .map_err(io::Error::other)?;
    // Uncommitted chunk and index scratch has no content/adoption authority.
    // Remove it before candidate scans, including when cold policy survives.
    // The physical executor owns these synchronous effects despite cancellation
    // of a requesting waiter; no embedded lock crosses the actual IO or RPC.
    if shared.discard_uncommitted_temporaries()? != 0 {
        let owner = custody
            .lock()
            .map_err(|_| io::Error::other("recovery custody poisoned"))?;
        owner.check_current()?;
        shared = SharedNamespaceObservation::inspect(&owner.preparation)?;
    }
    session
        .check_recovery_context(&context)
        .map_err(io::Error::other)?;
    if requires_cold_backing && !inspector.has_backing_candidates()? {
        return Err(unresolved(
            "cold policy has no native backing candidates to reconcile",
        ));
    }
    let (id, mut generation, bootstrap_write) = {
        let mut owner = custody
            .lock()
            .map_err(|_| io::Error::other("recovery custody poisoned"))?;
        owner.check_current()?;
        shared.check_current()?;
        state_parent.check_current()?;
        owner.preparation.recheck()?;
        let bootstrap = recovery_state::bootstrap(&owner.preparation.config, &owner.state)?;
        check_charge(&owner, owner.preparation.config.metadata_sync_hold_bytes)?;
        owner.begin_mutation()?;
        owner.recovery_cold = Some(bootstrap.cold);
        owner.state = bootstrap.snapshot;
        owner.faulted = true;
        let write = super::snapshot::prepare(executor, &mut owner)?;
        (bootstrap.id, owner.generation, write)
    };
    super::snapshot::persist(executor, bootstrap_write).await?;
    let work = recovery_indexes::run(executor, &inspector, &id, &context).await?;
    if let Some(repaired) = work.generation {
        let owner = custody
            .lock()
            .map_err(|_| io::Error::other("recovery custody poisoned"))?;
        owner.check_current()?;
        if owner.generation != repaired {
            return Err(unresolved("startup index repair generation changed"));
        }
        generation = repaired;
    }
    if work.generation.is_some() || work.pending_reconciled {
        let owner = custody
            .lock()
            .map_err(|_| io::Error::other("recovery custody poisoned"))?;
        // Repair and pending-pair reconciliation both change actual names. The
        // previous observation cannot supply final source-closure proof.
        shared = SharedNamespaceObservation::inspect(&owner.preparation)?;
    }
    // Publisher inventory may need the repaired metadata index to describe a
    // sealed manifest. Only this fresh complete scan can authorize adoption.
    let initial_inventory = inspector.inspect()?;
    let initial_inventory =
        if recovery_pending::run(executor, &initial_inventory, &shared, &id, &context)? {
            // Removal acknowledgements prove only namespace effects. Every later
            // adoption and completion still uses a fresh exhaustive actual scan.
            inspector.inspect()?
        } else {
            initial_inventory
        };
    recovery_candidates::preflight(&initial_inventory)?;
    let mut has_manifest = false;
    for candidate in initial_inventory.candidates() {
        has_manifest |= matches!(
            recovery_candidates::classify(candidate)?,
            recovery_candidates::RecoveryCase::Manifest(_)
        );
    }
    if has_manifest {
        return recovery_manifests::run(
            executor,
            recovery_manifests::ManifestRecoveryStart {
                session,
                inspector,
                shared,
                state_parent,
                original: context,
                bootstrap_id: id,
                inventory: initial_inventory,
            },
        )
        .await;
    }
    let encoded_chunks = recovery_encoded::select(&initial_inventory)?;
    shared.require_sources(&[], &encoded_chunks)?;
    let claims = {
        let mut owner = custody
            .lock()
            .map_err(|_| io::Error::other("recovery custody poisoned"))?;
        let claims =
            recovery_inline::selected_claims(&initial_inventory, owner.preparation.layout())?;
        let mut candidate = owner.state.clone();
        candidate.residences = recovery_encoded::sealed_residences(
            recovery_inline::residences(&claims),
            &encoded_chunks,
        )?;
        candidate
            .encoded_len(owner.preparation.config.state)
            .map_err(io::Error::other)?;
        owner.preparation.recheck()?;
        check_charge(&owner, 0)?;
        claims
    };
    // No embedded lock crosses the RPC. Each actual receipt enters the physical
    // registry before the next fallible operation, including a cancelled reply.
    executor
        .inline_registry_mut()
        .try_reserve(claims.len())
        .map_err(io::Error::other)?;
    for claim in claims {
        let body = session.adopt_inline(claim).map_err(io::Error::other)?;
        executor.inline_registry_mut().push(Arc::new(body));
    }
    let inventory = inspector.inspect()?;
    {
        let owner = custody
            .lock()
            .map_err(|_| io::Error::other("recovery custody poisoned"))?;
        recovery_inline::check_subset(
            &inventory,
            owner.preparation.layout(),
            executor.inline_registry(),
        )?;
    }
    session
        .check_recovery_context(&context)
        .map_err(io::Error::other)?;
    let final_write = {
        let mut owner = custody
            .lock()
            .map_err(|_| io::Error::other("recovery custody poisoned"))?;
        shared.check_current()?;
        state_parent.check_current()?;
        inventory.check_current()?;
        let cold = owner
            .recovery_cold
            .as_ref()
            .ok_or_else(|| invalid("recovery lost original cold policy candidates"))?;
        cold.check_bootstrap(&owner.preparation.config, &owner.state, &id)?;
        let claims = recovery_inline::selected_claims(&inventory, owner.preparation.layout())?;
        let residences = recovery_encoded::sealed_residences(
            recovery_inline::residences(&claims),
            &encoded_chunks,
        )?;
        recovery_encoded::check(&inventory, &encoded_chunks, &residences)?;
        cold.reconcile(&residences, &recovery_encoded::hashes(&encoded_chunks))?;
        owner.state.residences = residences;
        super::snapshot::prepare(executor, &mut owner)?
    };
    super::snapshot::persist(executor, final_write).await?;
    let (allocation, charged_reserved_bytes, future_hold_bytes) = {
        let mut owner = custody
            .lock()
            .map_err(|_| io::Error::other("recovery custody poisoned"))?;
        owner.check_current()?;
        let allocation = recovery_accounting::observe(
            &owner,
            &shared,
            &state_parent,
            executor.inline_registry(),
            executor.manifest_body_registry(),
        )?;
        owner.snapshot_allocated_bytes = owner
            .snapshot
            .as_ref()
            .ok_or_else(|| invalid("recovery snapshot is absent"))
            .and_then(|(file, _)| synchronized_allocated_bytes(file))?;
        owner.directory_allocated_bytes = synchronized_allocated_bytes(&owner.directory)?;
        owner.preparation.recheck()?;
        check_charge(&owner, 0)?;
        shared.check_current()?;
        state_parent.check_current()?;
        owner.check_current()?;
        recovery_inline::check_subset(
            &inventory,
            owner.preparation.layout(),
            executor.inline_registry(),
        )?;
        let expected = recovery_inline::selected_claims(&inventory, owner.preparation.layout())?;
        recovery_state::check_reconciled(
            &owner.preparation.config,
            &owner.state,
            &id,
            owner
                .recovery_cold
                .as_ref()
                .ok_or_else(|| invalid("recovery lost original cold policy candidates"))?,
            &recovery_encoded::sealed_residences(
                recovery_inline::residences(&expected),
                &encoded_chunks,
            )?,
            &recovery_encoded::hashes(&encoded_chunks),
        )?;
        recovery_encoded::check(&inventory, &encoded_chunks, &owner.state.residences)?;
        shared.require_sources(&[], &encoded_chunks)?;
        owner.recovery_id = Some(id);
        owner.recovery_required = false;
        owner.faulted = false;
        (
            allocation,
            owner
                .preparation
                .quota()
                .observation()
                .charged_reserved_bytes,
            owner
                .state
                .reservations
                .iter()
                .try_fold(0_u64, |sum, hold| {
                    sum.checked_add(hold.bytes)
                        .ok_or_else(|| invalid("recovery future holds overflow"))
                })?,
        )
    };
    // Any uncertainty after filesystem work withholds the receipt and restores
    // the faulted state. The durable reservation is never dropped with a waiter.
    if let Err(error) = session.check_recovery_context(&context) {
        let mut owner = custody
            .lock()
            .map_err(|_| io::Error::other("recovery custody poisoned"))?;
        owner.faulted = true;
        owner.recovery_required = true;
        owner.recovery_id = None;
        return Err(io::Error::other(error));
    }
    Ok(CompletedRecovery {
        custody: Arc::clone(&custody),
        session,
        context,
        shared,
        state_parent,
        inventory,
        generation,
        recovery_id: id,
        allocation,
        charged_reserved_bytes,
        future_hold_bytes,
        adopted_inline: executor.inline_registry().to_vec(),
        manifest_results: Vec::new(),
        metadata_sources: Vec::new(),
        encoded_chunks,
        expected_policy: None,
    })
}

/// Checks actual charged quota plus distinct existing and proposed future holds.
///
/// # Errors
/// Refuses overflowing holds and capacity excess before effects or acknowledgment.
pub(super) fn check_charge(owner: &Custody, additional: u64) -> io::Result<()> {
    let future = owner
        .state
        .reservations
        .iter()
        .try_fold(additional, |sum, hold| {
            sum.checked_add(hold.bytes)
                .ok_or_else(|| invalid("recovery future holds overflow"))
        })?;
    if owner
        .preparation
        .quota()
        .observation()
        .charged_reserved_bytes
        .checked_add(future)
        .is_none_or(|total| total > owner.preparation.config.policy.capacity)
    {
        return Err(io::Error::new(
            io::ErrorKind::StorageFull,
            "recovery charge and future holds exceed policy",
        ));
    }
    Ok(())
}

fn unresolved(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::WouldBlock, message)
}

fn invalid(error: impl Into<Box<dyn std::error::Error + Send + Sync>>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, error)
}
