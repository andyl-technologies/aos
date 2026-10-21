//! Reconciles manifest and inline recovery on the genuine physical owner executor.
//!
//! Every adoption follows a durable bootstrap. Manifest adoption additionally
//! requires actual metadata retention.
//! Accepted IPC resources and independent Inspector results enter physical
//! registries before further fallible work. Completion still requires exhaustive
//! final private/shared scans; unsupported records and names are never cleared.

use super::{
    recovery::{self, CompletedRecovery},
    recovery_accounting,
    recovery_candidates::{self, RecoveryCase},
    recovery_encoded, recovery_inline, recovery_manifest_state,
    recovery_namespace::SharedNamespaceObservation,
    recovery_residences::ResidenceSelection,
    recovery_state_parent::StateParentObservation,
    retention::{
        NativeOwnerExecutor, RecoveryManifestBackingRetention, RecoveryManifestBodyRetention,
    },
};
use crate::{
    host_cache::recovery_inspection::VerifiedRecoveryManifest,
    host_cache::{NativeRecoveryCandidate, NativeRecoveryInspection, NativeRecoveryInspector},
    host_quota::synchronized_allocated_bytes,
    publisher_local::client::{
        BodyIncarnationObservation, Client, PublisherRecoveryContext,
        recovery_manifest::{RecoveryManifestBody, RecoveryManifestError},
    },
};
use std::{io, sync::Arc};
use terrane_sdk::host::cache::HostDomainLocation;

/// Retains exact failed native response resources outside embedded custody.
pub(super) enum ManifestFailureResources {
    /// Keeps metadata custody when no verified response body was returned.
    Metadata {
        _retained: RecoveryManifestBackingRetention,
    },
    /// Keeps the actual registered body/pins and its original response token.
    Body {
        _retained: RecoveryManifestBodyRetention,
        _observation: BodyIncarnationObservation<HostDomainLocation>,
    },
    /// Keeps a failed independent inspection's original candidate and body.
    Inspection {
        _resources: Box<Option<(NativeRecoveryCandidate, RecoveryManifestBody)>>,
    },
    /// Keeps an unresolved report if ownership extraction was refused.
    Inventory {
        _report: Box<NativeRecoveryInspection>,
    },
}

/// Transfers actual bootstrap observations and the original barrier into this phase.
pub(super) struct ManifestRecoveryStart {
    /// Retains the original actual authenticated publisher client.
    pub(super) session: Arc<Client<HostDomainLocation>>,
    /// Retains actual prepared source, domain and quota custody.
    pub(super) inspector: NativeRecoveryInspector,
    /// Retains the exhaustive original shared namespace scan.
    pub(super) shared: SharedNamespaceObservation,
    /// Retains the exact supported state-parent observation.
    pub(super) state_parent: StateParentObservation,
    /// Owns the original acknowledged Drain context, never a fresh capture.
    pub(super) original: PublisherRecoveryContext<HostDomainLocation>,
    /// Names the actual durably synchronized bootstrap hold.
    pub(super) bootstrap_id: [u8; 16],
    /// Owns all initial candidate observations for consuming verification.
    pub(super) inventory: NativeRecoveryInspection,
}

/// Runs supported manifest candidates without inventing completion for other cases.
///
/// # Errors
/// Refuses cold/pending/unhandled candidates, failed source retention,
/// actual adoption/verification, incomplete final inventory or namespace closure,
/// changed policy and native synchronization/quota/context failures. Every
/// accepted resource stays physically registered independently of the waiter.
pub(super) async fn run(
    executor: &mut NativeOwnerExecutor,
    start: ManifestRecoveryStart,
) -> io::Result<CompletedRecovery> {
    let ManifestRecoveryStart {
        session,
        inspector,
        shared,
        state_parent,
        original,
        bootstrap_id,
        inventory,
    } = start;
    recovery_candidates::preflight(&inventory)?;
    let layout = {
        let owner = executor
            .custody()
            .lock()
            .map_err(|_| io::Error::other("recovery custody poisoned"))?;
        Arc::clone(owner.preparation.layout())
    };
    let encoded_chunks = recovery_encoded::select(&inventory)?;
    let inline_claims = recovery_inline::selected_claims(&inventory, &layout)?;
    executor
        .inline_registry_mut()
        .try_reserve(inline_claims.len())
        .map_err(io::Error::other)?;
    session
        .check_recovery_context(&original)
        .map_err(io::Error::other)?;
    // The synchronized bootstrap funds adoption before manifest-specific pins
    // exist. Keep every actual inline result with this physical executor even
    // if a later manifest fails or its waiter disappears.
    for claim in &inline_claims {
        let body = session
            .adopt_inline(claim.clone())
            .map_err(io::Error::other)?;
        executor.inline_registry_mut().push(Arc::new(body));
    }
    let candidates = match inventory.try_into_candidates() {
        Ok(candidates) => candidates,
        Err(report) => {
            executor.reserve_manifest_reconciliation()?;
            executor
                .retain_manifest_failure(ManifestFailureResources::Inventory { _report: report });
            return Err(unresolved(
                "unresolved inventory cannot transfer candidates",
            ));
        }
    };
    let (original, _) = {
        let mut live = executor.live_manifest_recovery(original, bootstrap_id)?;
        for candidate in candidates {
            let identity = match recovery_candidates::classify(&candidate)? {
                RecoveryCase::Manifest(identity) => identity,
                RecoveryCase::Pack | RecoveryCase::Inline | RecoveryCase::Chunk => continue,
            };
            // Reserve actual success/failure registry slots before source/publisher
            // effects. No fallible step precedes retaining an accepted result.
            live.reserve_reconciliation()?;
            let mut inspection_failure = Box::new(None);
            let receipt = live.retain_manifest(identity).await?;
            let body = match session.adopt_manifest_recovery(receipt, &candidate) {
                Ok(body) => body,
                Err(RecoveryManifestError::BeforeEffect(error)) => return Err(error),
                Err(RecoveryManifestError::Metadata(failure)) => {
                    let Some(failure) = *failure else {
                        return Err(unresolved("missing retained metadata failure"));
                    };
                    let (error, retained) = failure.into_parts();
                    live.retain_failure(ManifestFailureResources::Metadata {
                        _retained: retained,
                    });
                    return Err(error);
                }
                Err(RecoveryManifestError::Body(failure)) => {
                    let Some((failure, observation)) = *failure else {
                        return Err(unresolved("missing retained body failure"));
                    };
                    let (error, retained) = failure.into_parts();
                    live.retain_failure(ManifestFailureResources::Body {
                        _retained: retained,
                        _observation: observation,
                    });
                    return Err(error);
                }
            };
            match inspector.inspect_retained_manifest(candidate, body, live.publisher_context()) {
                Ok(verified) => {
                    live.retain_verified(verified);
                }
                Err(failure) => {
                    let (error, candidate, body) = failure.into_parts();
                    *inspection_failure = Some((candidate, body));
                    live.retain_failure(ManifestFailureResources::Inspection {
                        _resources: inspection_failure,
                    });
                    return Err(error);
                }
            }
        }
        live.finish()?
    };
    let verified = executor.verified_manifests().to_vec();
    if verified.is_empty() {
        return Err(unresolved("manifest recovery retained no verified body"));
    }
    // Every result already belongs to the executor before these fallible checks
    // or residence allocations. No embedded mutex crosses an Inspector RPC check.
    let mut selected = {
        let custody = executor
            .custody()
            .lock()
            .map_err(|_| io::Error::other("recovery custody poisoned"))?;
        let cold = custody
            .recovery_cold
            .as_ref()
            .ok_or_else(|| invalid("manifest recovery lost original cold policy candidates"))?;
        ResidenceSelection::new(custody.preparation.config.state.records, cold.residences())?
    };
    selected.extend(recovery_encoded::sealed_residences(
        recovery_inline::residences(&inline_claims),
        &encoded_chunks,
    )?)?;
    for body in &verified {
        body.check_current(&original)?;
        selected.extend(recovery_encoded::sealed_residences(
            body.residences()?,
            &encoded_chunks,
        )?)?;
    }
    shared.require_sources(executor.manifest_sources(), &encoded_chunks, &[])?;
    let final_inventory = inspector.inspect()?;
    check_inventory(
        &final_inventory,
        &verified,
        executor.manifest_sources(),
        &layout,
        executor.inline_registry(),
        &encoded_chunks,
    )?;
    for body in &verified {
        body.check_current(&original)?;
    }
    session
        .check_recovery_context(&original)
        .map_err(io::Error::other)?;

    let custody = Arc::clone(executor.custody());
    let (expected, final_write) = {
        let mut owner = custody
            .lock()
            .map_err(|_| io::Error::other("recovery custody poisoned"))?;
        owner.check_current()?;
        shared.check_current()?;
        state_parent.check_current()?;
        final_inventory.check_current()?;
        let resources = verified
            .iter()
            .map(|body| body.body().retained().clone())
            .collect::<Vec<_>>();
        let expected = recovery_manifest_state::reconstruct(
            &owner,
            &bootstrap_id,
            &resources,
            selected.finish(),
            &recovery_encoded::hashes(&encoded_chunks),
        )?;
        recovery_encoded::check(&final_inventory, &encoded_chunks, &expected.residences)?;
        owner.begin_mutation()?;
        owner.state = expected.clone();
        let write = super::snapshot::prepare(executor, &mut owner)?;
        (expected, write)
    };
    super::snapshot::persist(executor, final_write).await?;
    let (generation, allocation, charged_reserved_bytes, future_hold_bytes) = {
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
            .ok_or_else(|| invalid("manifest recovery snapshot absent"))
            .and_then(|(file, _)| synchronized_allocated_bytes(file))?;
        owner.directory_allocated_bytes = synchronized_allocated_bytes(&owner.directory)?;
        owner.preparation.recheck()?;
        recovery::check_charge(&owner, 0)?;
        recovery_manifest_state::require_same(&owner.state, &expected)?;
        shared.require_sources(executor.manifest_sources(), &encoded_chunks, &[])?;
        state_parent.check_current()?;
        let future = owner
            .state
            .reservations
            .iter()
            .try_fold(0_u64, |sum, hold| {
                sum.checked_add(hold.bytes)
                    .ok_or_else(|| invalid("manifest future holds overflow"))
            })?;
        (
            owner.generation,
            allocation,
            owner
                .preparation
                .quota()
                .observation()
                .charged_reserved_bytes,
            future,
        )
    };
    // Validate body/source/context again outside embedded state before marking
    // the generation complete. Any error leaves faulted recovery custody intact.
    for body in &verified {
        body.check_current(&original)?;
    }
    session
        .check_recovery_context(&original)
        .map_err(io::Error::other)?;
    {
        let mut owner = custody
            .lock()
            .map_err(|_| io::Error::other("recovery custody poisoned"))?;
        owner.check_current()?;
        if owner.generation != generation {
            return Err(invalid("manifest recovery generation changed"));
        }
        recovery_manifest_state::require_same(&owner.state, &expected)?;
        owner.recovery_id = Some(bootstrap_id);
        owner.recovery_required = false;
        owner.faulted = false;
    }
    Ok(CompletedRecovery {
        custody,
        session,
        context: original,
        shared,
        state_parent,
        inventory: final_inventory,
        generation,
        recovery_id: bootstrap_id,
        allocation,
        charged_reserved_bytes,
        future_hold_bytes,
        adopted_inline: executor.inline_registry().to_vec(),
        manifest_results: verified,
        metadata_sources: executor.manifest_sources().to_vec(),
        encoded_chunks,
        metadata_pairs: Vec::new(),
        expected_policy: Some(expected),
    })
}

/// Requires every final candidate to match actual retained verified results.
///
/// # Errors
/// Refuses global/unresolved issues, changed sealed sets or unrelated pack keys.
pub(super) fn check_inventory(
    inventory: &NativeRecoveryInspection,
    verified: &[Arc<VerifiedRecoveryManifest>],
    sources: &[Arc<crate::host_cache::NativeManifestSource>],
    layout: &Arc<crate::host_cache::NativeHostLayout<HostDomainLocation>>,
    inline: &[recovery_inline::AdoptedInline],
    chunks: &[Arc<crate::host_cache::VerifiedStandaloneChunk>],
) -> io::Result<()> {
    recovery_candidates::preflight(inventory)?;
    recovery_inline::check_subset(inventory, layout, inline)?;
    recovery_encoded::check(inventory, chunks, &[])?;
    let mut sealed = 0usize;
    for candidate in inventory.candidates() {
        match recovery_candidates::classify(candidate)? {
            RecoveryCase::Manifest(_) => {
                sealed += 1;
                if !verified
                    .iter()
                    .any(|body| body.candidate().key() == candidate.key())
                {
                    return Err(unresolved(
                        "final manifest set differs from adopted inventory",
                    ));
                }
            }
            RecoveryCase::Pack => {
                if !sources
                    .iter()
                    .any(|source| candidate.key().pack_id.as_slice() == source.pack_id().as_bytes())
                {
                    return Err(unresolved("final inventory contains unrelated shared pack"));
                }
            }
            RecoveryCase::Inline | RecoveryCase::Chunk => {}
        }
    }
    if sealed != verified.len() {
        return Err(unresolved("adopted manifest missing from final inventory"));
    }
    Ok(())
}

fn unresolved(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::WouldBlock, message)
}
fn invalid(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}
