//! Completes one borrowed overlay owning history through the captured actual native backend.
//!
//! Each invocation borrows its existing namespace exclusion. It borrows retained
//! Original controls when available, or acquires their first genuine exclusion
//! in the established namespace-before-control order.
//! Only immutable DATA is shared within that invocation; actor authorization
//! remains the enclosing Guard's fresh decision after complete physical closing.

use std::collections::BTreeMap;
use std::sync::Arc;

use super::{CheckFuture, OriginalState, read_configuration::ReadConfiguration, unavailable};
use crate::bucket::held::HeldBucket;
use crate::bucket::{BucketBinding, FileBucket};
use crate::guard::overlay_history::OverlayReadCheck;
use crate::guard::overlay_history::{
    CheckedOverlayHistoryInputs, OverlayHistoryStore, OverlayPurpose,
};
use crate::guard::{ConsumedResolver, Guard, HistoryObservation, OriginalAuthority, invalid};
use crate::repository::local_authority::retention::Record;
use crate::store::{Clock, ContentValidator, LocalFs, NativeEffectClock, StoreFailure};
use terrane_format::gc::publication::evidence::GuardSnapshot;
use terrane_format::identity::Digest;
use terrane_format::provenance::VerifiedHistory;

/// Carries the exact immutable layer and borrowed observation without permissions.
pub(super) struct OverlayHistoryRequest<'a> {
    /// Names the exact immutable layer, independently from live policy heads.
    pub(super) target: Digest,
    /// Borrows synchronization and trace inputs without supplying authority.
    pub(super) observation: HistoryObservation<'a>,
    /// Retains this caller's actual ordinary interpretation and selection inputs.
    pub(super) configuration: ReadConfiguration,
}

/// Dispatches only the real factory installed from the opened native backend.
#[cfg(feature = "send")]
pub(super) type OverlayHistoryCheck = dyn for<'a> Fn(
        OverlayHistoryRequest<'a>,
        OriginalState,
    ) -> CheckFuture<'a, (crate::guard::history::VerifiedTree, VerifiedHistory)>
    + Send
    + Sync;
/// Dispatches the same factory without strengthening local future bounds.
#[cfg(not(feature = "send"))]
pub(super) type OverlayHistoryCheck =
    dyn for<'a> Fn(
        OverlayHistoryRequest<'a>,
        OriginalState,
    ) -> CheckFuture<'a, (crate::guard::history::VerifiedTree, VerifiedHistory)>;

impl<S: crate::store::Store, C: Clock> Guard<S, C> {
    /// Dispatches a fresh layer walk through the configured borrowed native factory.
    ///
    /// Absence before dispatch preserves generic reading. A configured factory's
    /// refusal always propagates, including unsupported physical retention.
    ///
    /// # Errors
    /// Preserves authentication, unavailable state, foreign purpose and genuine
    /// native physical, Original, producer and complete history refusals.
    pub(in crate::guard) async fn overlay_history_native(
        &self,
        target: Digest,
        observation: HistoryObservation<'_>,
    ) -> Result<Option<(crate::guard::history::VerifiedTree, VerifiedHistory)>, StoreFailure> {
        if observation.identity().is_none()
            || observation.resolver().is_none()
            || observation.paired_transition_purpose().is_some()
        {
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
        (verifier.overlay)(
            OverlayHistoryRequest {
                target,
                observation,
                configuration: ReadConfiguration::capture(self),
            },
            state,
        )
        .await
        .map(Some)
    }
}

/// Captures the actual shared FileBucket and independently configured authority.
pub(super) fn capture<F, B, V>(
    concrete: Arc<Guard<FileBucket<F, B, V>, ()>>,
    authority: OriginalAuthority,
    setup_clock: NativeEffectClock,
) -> Arc<OverlayHistoryCheck>
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
            let OverlayHistoryRequest {
                target,
                observation,
                configuration,
            } = request;
            observation.same_held_scope(observation)?;
            if observation.paired_transition_purpose().is_some() {
                return Err(invalid());
            }
            let proof = observation.identity().ok_or_else(invalid)?;
            let source =
                HeldBucket::<F, B, V, false>::borrow_read_namespace(concrete.store(), proof)
                    .await?;
            let observed = source.observe_publication_ordinary_retained().await?;
            let clock = setup_clock
                .retain_native_clock()
                .map_err(crate::guard::retained_clock_failure)?;
            let guard = configuration.bind_direct(
                HeldBucket::<F, B, V, false>::borrow_read_namespace(concrete.store(), proof)
                    .await?,
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

            let consumed = observation.resolver().ok_or_else(invalid)?;
            consumed.check_guard(&guard)?;
            let snapshot_bytes = consumed.snapshot_bytes()?;
            let snapshot_read = source
                .selected_guard_snapshot_record_retained(&observed)
                .await?
                .ok_or_else(invalid)?;
            if snapshot_read.bytes() != Some(snapshot_bytes.as_slice()) {
                return Err(invalid());
            }
            let verifier = guard.original_verifier()?;
            if verifier.authority != authority {
                return Err(invalid());
            }
            // Reuse an existing administrative hold. Early admission has not
            // acquired one yet, so only that lane takes its first real hold in
            // the established namespace-before-control order.
            let (early, mut exclusion) = if let Some(retained) = verifier.retained {
                (retained, None)
            } else {
                let snapshot = GuardSnapshot::decode(&snapshot_bytes).map_err(|_| invalid())?;
                let mut exclusion = concrete
                    .hold_original_registration(&authority, proof)
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
                    let role =
                        crate::repository::local_authority::public_trust::DisclosureRoleRecord {
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
                (early, Some(exclusion))
            };
            guard.retain_original_controls(&early)?;
            consumed.registration(&authority)?;
            let registration = consumed
                .control_pins()?
                .into_iter()
                .find(|pin| pin.key == "registration.cbor")
                .ok_or_else(invalid)?;
            let check = OverlayReadCheck::capture(target, &authority, registration, early.clone())?;
            let reads = source.overlay_node_reads(&observed, &check).await?;
            let store = OverlayHistoryStore::new(&source, &reads)?;
            let reader_guard = guard.current_history_guard(store, clock)?;
            let tree = reader_guard
                .signed_overlay_layer_observed(target, observation)
                .await?;
            let history = observation.overlay_layer(target, tree.evidence.root);
            let purpose = OverlayPurpose::capture(target, &observed, history, check)?;
            let pending = reader_guard
                .prepare_overlay_history_with_reads(target, history, &purpose, &reads)
                .await?;

            let mut controls = vec![early];
            if let Some(exclusion) = exclusion.as_mut() {
                let pins = consumed.control_pins()?;
                let registration = crate::guard::consumed_registration(&authority);
                if pins.iter().any(|pin| pin.owner != registration) {
                    return Err(StoreFailure::new(crate::store::StoreErrorKind::Unsupported));
                }
                let late = exclusion.retain_used(&pins).await?;
                reader_guard.retain_original_controls(&late)?;
                controls.push(late);
            }
            let original_reads = [snapshot_read];
            let checked = CheckedOverlayHistoryInputs::close(
                source.fs(),
                &observed,
                &purpose,
                &reads,
                &controls,
                &original_reads,
            )
            .await?;
            let history = reader_guard.promote_overlay_history(pending, checked)?;
            Ok((tree, history))
        })
    })
}
