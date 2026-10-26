//! Completes one direct immutable history through the captured actual native backend.
//!
//! Every invocation acquires its own real read namespace and Original exclusion.
//! Only immutable DATA is shared within that invocation; immutable completion
//! remains the enclosing Guard's fresh decision after complete physical closing.

use std::collections::BTreeMap;
use std::sync::Arc;

use super::{CheckFuture, OriginalState, read_configuration::ReadConfiguration, unavailable};
use crate::bucket::held::SingleHeld;
use crate::bucket::{BucketBinding, FileBucket};
use crate::guard::direct_history::{
    CheckedDirectHistoryInputs, DirectHistoryStore, DirectMode, DirectOutput, DirectPurpose,
    DirectReadCheck,
};
use crate::guard::{ConsumedResolver, Guard, HistoryObservation, OriginalAuthority, invalid};
use crate::repository::local_authority::retention::Record;
use crate::store::{Clock, ContentValidator, LocalFs, NativeEffectClock, StoreFailure};
use terrane_format::gc::publication::evidence::GuardSnapshot;
use terrane_format::identity::Digest;

/// Carries the original direct immutable request without authorizing a ref.
pub(super) struct DirectHistoryRequest<'a> {
    /// Names the immutable target independently from the current selected head.
    pub(super) target: Digest,
    /// Preserves whether the original caller requested a signed target tree.
    pub(super) mode: DirectMode,
    /// Preserves the original ordinary-unheld interpretation distinctions.
    pub(super) observation: HistoryObservation<'a>,
    /// Retains only the caller's actual ordinary configuration inputs.
    pub(super) configuration: ReadConfiguration,
}

/// Dispatches only the real factory installed from the opened native backend.
#[cfg(feature = "send")]
pub(super) type DirectHistoryCheck = dyn for<'a> Fn(DirectHistoryRequest<'a>, OriginalState) -> CheckFuture<'a, DirectOutput>
    + Send
    + Sync;
/// Dispatches the same factory without strengthening local future bounds.
#[cfg(not(feature = "send"))]
pub(super) type DirectHistoryCheck =
    dyn for<'a> Fn(DirectHistoryRequest<'a>, OriginalState) -> CheckFuture<'a, DirectOutput>;

impl<S: crate::store::Store, C: Clock> Guard<S, C> {
    /// Dispatches one ordinary direct immutable history through its configured native factory.
    ///
    /// Absence before dispatch preserves generic reading. A configured factory's
    /// refusal always propagates, including unsupported physical retention.
    ///
    /// # Errors
    /// Preserves configuration, unavailable state, foreign purpose and genuine
    /// native physical, Original, producer and complete history refusals.
    pub(in crate::guard) async fn direct_history_native(
        &self,
        target: Digest,
        mode: DirectMode,
        observation: HistoryObservation<'_>,
    ) -> Result<Option<DirectOutput>, StoreFailure> {
        if !observation.is_ordinary_unheld() {
            return Ok(None);
        }
        let verifier = self
            .original_verifier
            .read()
            .map_err(|_| unavailable())?
            .clone();
        let Some(verifier) = verifier else {
            return Ok(None);
        };
        let state = OriginalState {
            verifier: Some(verifier.clone()),
            baselines: self
                .original_baselines
                .read()
                .map_err(|_| unavailable())?
                .clone(),
            commits: self
                .original_commits
                .read()
                .map_err(|_| unavailable())?
                .clone(),
        };
        (verifier.direct)(
            DirectHistoryRequest {
                target,
                mode,
                observation,
                configuration: ReadConfiguration::capture(self),
            },
            state,
        )
        .await
        .map(Some)
    }
}

/// Captures the actual shared FileBucket, authority and genuine setup clock.
///
/// Immutable verification samples no clock. This is the original native setup
/// binding already retained for configuration, not a caller clock requirement
/// or a newly introduced request deadline.
pub(super) fn capture<F, B, V>(
    concrete: Arc<Guard<FileBucket<F, B, V>, ()>>,
    authority: OriginalAuthority,
    setup_clock: NativeEffectClock,
) -> Arc<DirectHistoryCheck>
where
    F: LocalFs + BucketBinding + 'static,
    B: Clock + BucketBinding + 'static,
    V: ContentValidator + BucketBinding + 'static,
{
    let setup_clock = Arc::new(setup_clock);
    Arc::new(move |request, state| {
        let concrete = Arc::clone(&concrete);
        let authority = authority.clone();
        let setup_clock = Arc::clone(&setup_clock);
        Box::pin(async move {
            let clock = setup_clock
                .retain_native_clock()
                .map_err(crate::guard::retained_clock_failure)?;
            let DirectHistoryRequest {
                target,
                mode,
                observation,
                configuration,
            } = request;
            if !observation.is_ordinary_unheld() {
                return Err(invalid());
            }
            let held = SingleHeld::acquire_read_namespace(concrete.store()).await?;
            let source = held.source();
            let observed = source.observe_publication_ordinary_retained().await?;
            let guard = configuration.bind_direct(
                held.source(),
                clock
                    .retain_native_clock()
                    .map_err(crate::guard::retained_clock_failure)?,
                concrete.keys(),
            )?;
            *guard.original_verifier.write().map_err(|_| unavailable())? = state.verifier;
            *guard
                .original_baselines
                .write()
                .map_err(|_| unavailable())? = state.baselines;
            *guard.original_commits.write().map_err(|_| unavailable())? = state.commits;

            if guard.configured_original_authority()? != authority {
                return Err(invalid());
            }
            let consumed = ConsumedResolver::new(&guard, &authority)?;
            let snapshot_bytes = consumed.snapshot_bytes()?;
            let snapshot_read = source
                .selected_guard_snapshot_record_retained(&observed)
                .await?
                .ok_or_else(invalid)?;
            if snapshot_read.bytes() != Some(snapshot_bytes.as_slice()) {
                return Err(invalid());
            }
            let snapshot = GuardSnapshot::decode(&snapshot_bytes).map_err(|_| invalid())?;
            let proof = source.identity_proof();
            let history = observation.direct_held_from_ordinary(&proof, &consumed)?;
            let mut exclusion = concrete
                .hold_original_registration(&authority, &proof)
                .await?;
            concrete
                .check_retained_trust_controls(&authority, &mut exclusion, &snapshot)
                .await?;
            let mut named = BTreeMap::new();
            named.insert(
                "registration.cbor".to_owned(),
                exclusion.read_record("registration.cbor").await?,
            );
            for row in snapshot
                .disclosures
                .iter()
                .filter(|row| row.repository == super::super::hex(authority.id()))
            {
                let role = crate::repository::local_authority::public_trust::DisclosureRoleRecord {
                    repository: row.repository.clone(),
                    domain: row.domain.clone(),
                    public_key: row.public_key,
                    not_before: row.not_before,
                    not_after: row.not_after,
                };
                let key = role
                    .selector()
                    .map_err(super::super::import::retention_failure)?;
                let bytes = role
                    .encode()
                    .map_err(super::super::import::retention_failure)?;
                if named.insert(key, bytes).is_some() {
                    return Err(invalid());
                }
            }
            // Direct immutable reads can name a genuine local commit retained
            // by another writer since this reader opened. Rebind those records
            // within this invocation's actual exclusions before walking history.
            let refreshed = super::local_contexts::refresh_local(
                &concrete,
                &guard,
                &authority,
                &proof,
                &mut exclusion,
                &mut named,
            )
            .await?;
            // Every reached history view already requires an installed opaque
            // Original context. Capture those contexts' real records before
            // installing a retained read scope; this grants no history or ACL.
            // Keep this prefetch trace separate from actual walk consumption.
            let configured = ConsumedResolver::new(&guard, &authority)?;
            configured.registration(&authority)?;
            let originals = guard
                .original_commits
                .read()
                .map_err(|_| unavailable())?
                .values()
                .cloned()
                .collect::<Vec<_>>();
            for original in &originals {
                configured.original(original)?;
            }
            let actual_owner = crate::guard::consumed_registration(&authority);
            for pin in configured.finish()?.controls {
                if pin.owner != actual_owner {
                    return Err(StoreFailure::new(crate::store::StoreErrorKind::Unsupported));
                }
                let bytes = exclusion.read_record(&pin.key).await?;
                pin.check_record(&bytes).map_err(|_| invalid())?;
                if named
                    .get(&pin.key)
                    .is_some_and(|previous| previous != &bytes)
                {
                    return Err(invalid());
                }
                named.insert(pin.key, bytes);
            }
            let early = exclusion
                .retain_named(
                    &named
                        .iter()
                        .map(|(key, bytes)| (key.clone(), bytes.clone()))
                        .collect::<Vec<_>>(),
                )
                .await?;
            guard.retain_original_controls(&early)?;
            let registration_pin = configured
                .control_pins()?
                .into_iter()
                .find(|pin| pin.key == "registration.cbor")
                .ok_or_else(invalid)?;
            let check =
                DirectReadCheck::capture(target, &authority, registration_pin, early.clone())?;
            let purpose = DirectPurpose::capture(target, &observed, history, check.clone())?;
            let reads = source.direct_node_reads(&observed, &check).await?;
            let store = DirectHistoryStore::new(&source, &reads)?;
            let reader_guard = guard.current_history_guard(store, clock)?;
            let (tree, pending) = reader_guard
                .prepare_direct_history(target, mode, history, &purpose, &reads)
                .await?;

            let registration = crate::guard::consumed_registration(&authority);
            for pin in consumed.control_pins()? {
                if pin.owner != registration {
                    return Err(StoreFailure::new(crate::store::StoreErrorKind::Unsupported));
                }
                let bytes = exclusion.read_record(&pin.key).await?;
                pin.check_record(&bytes).map_err(|_| invalid())?;
                if named
                    .get(&pin.key)
                    .is_some_and(|previous| previous != &bytes)
                {
                    return Err(invalid());
                }
                named.insert(pin.key, bytes);
            }
            let late = exclusion
                .retain_named(&named.into_iter().collect::<Vec<_>>())
                .await?;
            reader_guard.retain_original_controls(&late)?;
            let controls = [refreshed, early, late];
            let original_reads = [snapshot_read];
            let checked = CheckedDirectHistoryInputs::close(
                source.fs(),
                &observed,
                &purpose,
                &reads,
                &controls,
                &original_reads,
            )
            .await?;
            let history = reader_guard.promote_direct_history(pending, checked)?;
            Ok(DirectOutput { tree, history })
        })
    })
}
