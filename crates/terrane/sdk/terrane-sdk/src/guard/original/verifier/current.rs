//! Completes one current history through the captured actual native backend.
//!
//! Every invocation acquires its own real read namespace and Original exclusion.
//! Only immutable DATA is shared within that invocation; actor authorization
//! remains the enclosing Guard's fresh decision after complete physical closing.

use std::collections::BTreeMap;
use std::sync::Arc;

use super::{CheckFuture, OriginalState, read_configuration::ReadConfiguration, unavailable};
use crate::bucket::held::SingleHeld;
use crate::bucket::{BucketBinding, FileBucket};
use crate::guard::current_history::{
    CheckedCurrentHistoryInputs, CurrentHistoryStore, CurrentPurpose, PendingCurrentReadCheck,
};
use crate::guard::{ConsumedResolver, Guard, HistoryObservation, OriginalAuthority, invalid};
use crate::repository::local_authority::retention::Record;
use crate::store::{Clock, ContentValidator, LocalFs, StoreFailure};
use terrane_format::auth::Verb;
use terrane_format::gc::publication::evidence::GuardSnapshot;
use terrane_format::refs::RefRecord;

/// Carries the exact initial current observation without supplying permissions.
pub(super) struct CurrentHistoryRequest<'a> {
    /// Names the reference whose whole current head must remain selected.
    pub(super) reference: String,
    /// Retains the exact current record captured before history completion.
    pub(super) record: RefRecord,
    /// Retains genuine token and time rechecks for this current invocation.
    pub(super) current: PendingCurrentReadCheck,
    /// Borrows synchronization and trace inputs without supplying authority.
    pub(super) observation: HistoryObservation<'a>,
    /// Retains this caller's actual ordinary interpretation and selection inputs.
    pub(super) configuration: ReadConfiguration,
}

/// Dispatches only the real factory installed from the opened native backend.
#[cfg(feature = "send")]
pub(super) type CurrentHistoryCheck = dyn for<'a> Fn(
        CurrentHistoryRequest<'a>,
        OriginalState,
    ) -> CheckFuture<'a, crate::guard::history::VerifiedTree>
    + Send
    + Sync;
/// Dispatches the same factory without strengthening local future bounds.
#[cfg(not(feature = "send"))]
pub(super) type CurrentHistoryCheck =
    dyn for<'a> Fn(
        CurrentHistoryRequest<'a>,
        OriginalState,
    ) -> CheckFuture<'a, crate::guard::history::VerifiedTree>;

impl<S: crate::store::Store, C: Clock> Guard<S, C> {
    /// Dispatches one ordinary current history through its configured native factory.
    ///
    /// Absence before dispatch preserves generic reading. A configured factory's
    /// refusal always propagates, including unsupported physical retention.
    ///
    /// # Errors
    /// Preserves authentication, unavailable state, foreign purpose and genuine
    /// native physical, Original, producer and complete history refusals.
    pub(in crate::guard) async fn current_history_native(
        &self,
        reference: &str,
        token: &[u8],
        verb: Verb,
        record: &RefRecord,
        observation: HistoryObservation<'_>,
    ) -> Result<Option<crate::guard::history::VerifiedTree>, StoreFailure> {
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
        let current = PendingCurrentReadCheck::capture(self, reference, token, verb)?;
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
        (verifier.current)(
            CurrentHistoryRequest {
                reference: reference.to_owned(),
                record: record.clone(),
                current,
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
) -> Arc<CurrentHistoryCheck>
where
    F: LocalFs + BucketBinding + 'static,
    B: Clock + BucketBinding + 'static,
    V: ContentValidator + BucketBinding + 'static,
{
    Arc::new(move |request, state| {
        let concrete = Arc::clone(&concrete);
        let authority = authority.clone();
        Box::pin(async move {
            let CurrentHistoryRequest {
                reference,
                record,
                current,
                observation,
                configuration,
            } = request;
            if !observation.is_ordinary_unheld() {
                return Err(invalid());
            }
            current.recheck()?;
            current.check_configured_keys(&concrete.keys)?;
            let held = SingleHeld::acquire_read_namespace(concrete.store()).await?;
            let source = held.source();
            let observed = source.observe_publication_ordinary_retained().await?;
            let clock = current.retained_clock()?;
            let guard = configuration.bind(held.source(), clock, &current)?;
            *guard.original_verifier.write().map_err(|_| unavailable())? = state.verifier;
            *guard
                .original_baselines
                .write()
                .map_err(|_| unavailable())? = state.baselines;
            *guard.original_commits.write().map_err(|_| unavailable())? = state.commits;

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
            let history = observation.current_held_from_ordinary(&proof, &consumed)?;
            let purpose = CurrentPurpose::capture(
                &source,
                &observed,
                &reference,
                &record,
                history,
                current.clone(),
            )
            .await?;

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
            // Other genuine writers can retain new local baselines and commit
            // associations after this reader opened. Rebind their actual protected
            // records inside this operation's real exclusions before walking history.
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
            let reads = source.current_node_reads(&observed, &current).await?;
            let store = CurrentHistoryStore::new(&source, &reads)?;
            let reader_guard = guard.current_history_guard(store, current.retained_clock()?)?;
            let (tree, pending) = reader_guard
                .prepare_current_tree_with_node_reads(record.commit, history, &purpose, &reads)
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
            let checked = CheckedCurrentHistoryInputs::close(
                source.fs(),
                &observed,
                &purpose,
                &reads,
                &controls,
                &original_reads,
            )
            .await?;
            reader_guard.promote_current_history(pending, checked)?;
            Ok(tree)
        })
    })
}
