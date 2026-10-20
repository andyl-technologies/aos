//! Checks bounded candidate reuse through genuine native admission and retained history.
//!
//! Counters observe candidate preparation only; full history and metadata
//! validation remain independent work and never become incremental delta.

use std::sync::atomic::{AtomicU8, AtomicUsize, Ordering};

use terrane_format::{
    identity::{Digest, Identity, IdentityKind},
    properties::{selected::Selection, semantics::RecordedContext},
    tree_format::TreeUse,
};

use super::{HistoryObservation, candidate_preparation::Key, completion::PendingViewUse};
use crate::bucket::held::SingleHeld;
use crate::guard::{ConsumedResolver, Guard, TreeEvidence};
use crate::ref_advance::tests::{fixture, request_file, token};
use crate::store::{
    ByteRange, Capabilities, CapabilityReport, ContentStore, ContentUpload, IdentityPrefix,
    StoreErrorKind, StoreFailure, TokioClock,
};

type TestResult = Result<(), Box<dyn std::error::Error>>;
const SOURCE: &str = "refs/heads/_/main";

/// Observes real held metadata reads and injects bounded read failures only.
struct Reads<'a, S> {
    actual: &'a S,
    root: Digest,
    node_reads: AtomicUsize,
    fault: AtomicU8,
}

impl<S: CapabilityReport> CapabilityReport for Reads<'_, S> {
    fn capabilities(&self) -> &Capabilities {
        self.actual.capabilities()
    }
}

#[cfg_attr(feature = "send", async_trait::async_trait)]
#[cfg_attr(not(feature = "send"), async_trait::async_trait(?Send))]
impl<S: ContentStore + Sync> ContentStore for Reads<'_, S> {
    async fn put(&self, upload: ContentUpload<'_>) -> Result<Identity, StoreFailure> {
        self.actual.put(upload).await
    }

    async fn get(
        &self,
        identity: &Identity,
        range: Option<ByteRange>,
    ) -> Result<Vec<u8>, StoreFailure> {
        if identity.kind() == IdentityKind::Node {
            self.node_reads.fetch_add(1, Ordering::Relaxed);
        }
        let root = identity.kind() == IdentityKind::Node
            && identity.terrane_v1_digest().ok() == Some(self.root);
        if root && self.fault.load(Ordering::Relaxed) == 1 {
            return Err(StoreFailure::new(StoreErrorKind::Absent(identity.clone())));
        }
        let mut bytes = self.actual.get(identity, range).await?;
        if root && self.fault.load(Ordering::Relaxed) == 2 {
            // The fixture's canonical root encoding is always nonempty.
            bytes[0] ^= 1;
        }
        Ok(bytes)
    }

    async fn has(&self, identities: &[Identity]) -> Result<Vec<bool>, StoreFailure> {
        self.actual.has(identities).await
    }

    async fn list(&self, prefix: &IdentityPrefix) -> Result<Vec<Identity>, StoreFailure> {
        self.actual.list(prefix).await
    }
}

// Copies only the fixture's actual protected callbacks into a measured adapter.
// No completed data, history receipt or fabricated Original context is installed.
fn measured<S>(
    source: &Guard<S, TokioClock>,
    root: Digest,
) -> Result<Guard<Reads<'_, S>, TokioClock>, Box<dyn std::error::Error>> {
    let guard = source.configuration_adapter(
        Reads {
            actual: source.store(),
            root,
            node_reads: AtomicUsize::new(0),
            fault: AtomicU8::new(0),
        },
        *source.clock(),
    );
    *guard
        .original_verifier
        .write()
        .map_err(|_| "fixture verifier lock poisoned")? = source
        .original_verifier
        .read()
        .map_err(|_| "fixture verifier lock poisoned")?
        .clone();
    *guard
        .original_baselines
        .write()
        .map_err(|_| "fixture baseline lock poisoned")? = source
        .original_baselines
        .read()
        .map_err(|_| "fixture baseline lock poisoned")?
        .clone();
    *guard
        .original_commits
        .write()
        .map_err(|_| "fixture commit lock poisoned")? = source
        .original_commits
        .read()
        .map_err(|_| "fixture commit lock poisoned")?
        .clone();
    Ok(guard)
}

#[tokio::test]
async fn identical_candidate_preparation_reuses_only_operation_local_pure_work() -> TestResult {
    let repository = fixture().await;
    let mut writer = repository.begin(SOURCE, &token(), "sdk").await?;
    let base = repository
        .advance(&mut writer, request_file(Vec::new(), b"base"))
        .await?;
    let head = repository
        .advance(&mut writer, request_file(vec![base.commit], b"head"))
        .await?;
    let admitted = repository
        .guard()
        .admit_policy(SOURCE, None, &token(), "sdk")
        .await?;
    let ancestor = repository
        .guard()
        .admit_rollback(SOURCE, base.commit, &token(), "sdk")
        .await?;
    let original = repository.guard().original_commit(&head.commit)?;

    let holder = SingleHeld::acquire_read_only(repository.store()).await?;
    let adapter = holder.source();
    let identity = adapter.identity_proof();
    let actual = repository.guard().held_guard(holder.source(), TokioClock)?;
    let guard = measured(&actual, admitted.commit.commit().tree)?;
    let consumed = ConsumedResolver::new(&guard, original.baseline().authority())?;
    let observation = HistoryObservation::held(&identity).tracked(&consumed);

    observation.record_candidate(&guard, &admitted).await?;
    observation.record_candidate(&guard, &admitted).await?;

    assert_eq!(consumed.candidate_preparation_work()?, (1, 1));
    assert_eq!(guard.store().node_reads.load(Ordering::Relaxed), 2);
    assert!(
        consumed
            .observed_completed_view_contexts_for_tests()?
            .is_empty()
    );
    assert!(consumed.finish().is_err());
    let evidence = TreeEvidence::load_tree_for(
        guard.store(),
        admitted.commit.commit().tree,
        &[],
        guard.config().min_chunk_size,
        admitted.tree_usage,
    )
    .await?;
    let expected =
        PendingViewUse::prepare(&admitted.completion_inputs, &admitted.commit, &evidence)?;
    assert_eq!(
        consumed.candidate_preparation_pending(head.commit)?,
        Some(expected.clone())
    );

    // The disabled path executes the original body on each call and retains
    // exactly the same complete pure row, without creating completion evidence.
    let disabled = ConsumedResolver::new(&guard, original.baseline().authority())?;
    let uncached = HistoryObservation::default().tracked(&disabled);
    uncached.record_candidate(&guard, &admitted).await?;
    uncached.record_candidate(&guard, &admitted).await?;
    assert_eq!(disabled.candidate_preparation_work()?, (2, 0));
    assert_eq!(
        disabled.candidate_preparation_pending(head.commit)?,
        Some(expected.clone())
    );

    let mut contradictory = expected;
    contradictory.policy.default_domain.push_str("-different");
    assert!(consumed.pending_view(&contradictory).is_err());
    observation.record_candidate(&guard, &admitted).await?;
    assert_eq!(consumed.candidate_preparation_work()?, (1, 2));

    // Genuine full history promotes the candidate. A later identical call
    // must prepare again and pass the existing completed-row equality check.
    actual
        .verified_history_observed(head.commit, observation)
        .await?;
    observation.record_candidate(&guard, &admitted).await?;
    observation.record_candidate(&guard, &admitted).await?;
    assert_eq!(consumed.candidate_preparation_work()?, (3, 2));
    assert_eq!(consumed.finish()?.views.len(), 2);

    // A real parent namespace promotion has the same invalidation rule.
    let parents = ConsumedResolver::new(&guard, original.baseline().authority())?;
    let parent_observation = HistoryObservation::held(&identity).tracked(&parents);
    parent_observation
        .record_candidate(&guard, &ancestor)
        .await?;
    parent_observation
        .record_candidate(&guard, &ancestor)
        .await?;
    actual
        .verified_history_observed(head.commit, parent_observation.requested_target())
        .await?;
    parent_observation
        .record_candidate(&guard, &ancestor)
        .await?;
    parent_observation
        .record_candidate(&guard, &ancestor)
        .await?;
    assert_eq!(parents.candidate_preparation_work()?, (3, 1));
    assert!(parents.finish()?.view_interpretations.is_some());
    Ok(())
}

#[tokio::test]
async fn candidate_preparation_reuse_distinguishes_complete_inputs_and_typed_geometry() -> TestResult
{
    let repository = fixture().await;
    let mut writer = repository.begin(SOURCE, &token(), "sdk").await?;
    let head = repository
        .advance(&mut writer, request_file(Vec::new(), b"key geometry"))
        .await?;
    let mut admitted = repository
        .guard()
        .admit_policy(SOURCE, None, &token(), "sdk")
        .await?;
    let same_root_candidate = repository
        .guard()
        .admit(
            SOURCE,
            writer.epoch(),
            request_file(vec![head.commit], b"key geometry"),
        )
        .await?;
    let changed_root_candidate = repository
        .guard()
        .admit(
            SOURCE,
            writer.epoch(),
            request_file(vec![head.commit], b"different root geometry"),
        )
        .await?;
    let original = repository.guard().original_commit(&head.commit)?;
    let holder = SingleHeld::acquire_read_only(repository.store()).await?;
    let adapter = holder.source();
    let identity = adapter.identity_proof();
    let mut guard = repository.guard().held_guard(holder.source(), TokioClock)?;
    let evidence = TreeEvidence::load_tree_for(
        guard.store(),
        admitted.commit.commit().tree,
        &[],
        guard.config().min_chunk_size,
        TreeUse::Ordinary,
    )
    .await?;
    let inputs = admitted.completion_inputs.clone();
    let key = Key::capture(
        &guard,
        Some(&identity),
        &inputs,
        &admitted.commit,
        &evidence,
        TreeUse::Ordinary,
    )
    .ok_or("missing genuine key")?;
    assert_eq!(same_root_candidate.commit.commit().tree, evidence.root);
    assert_ne!(
        same_root_candidate.commit.identity(),
        admitted.commit.identity()
    );
    let signed_other = Key::capture(
        &guard,
        Some(&identity),
        &inputs,
        &same_root_candidate.commit,
        &evidence,
        TreeUse::Ordinary,
    )
    .ok_or("missing independently signed key")?;
    assert!(!key.matches(&signed_other));
    let changed_root = TreeEvidence::load_tree_for(
        guard.store(),
        changed_root_candidate.commit.commit().tree,
        &changed_root_candidate.uploads,
        guard.config().min_chunk_size,
        TreeUse::Ordinary,
    )
    .await?;
    assert_ne!(evidence.root, changed_root.root);
    assert_ne!(evidence.default_domain, changed_root.default_domain);
    let root_other = Key::capture(
        &guard,
        Some(&identity),
        &inputs,
        &changed_root_candidate.commit,
        &changed_root,
        TreeUse::Ordinary,
    )
    .ok_or("missing independently validated changed-root key")?;
    assert!(!key.matches(&root_other));
    let consumed = ConsumedResolver::new(&guard, original.baseline().authority())?;
    HistoryObservation::held(&identity)
        .tracked(&consumed)
        .record_candidate(&guard, &admitted)
        .await?;

    let mut variants = Vec::new();
    for field in 0..9 {
        let mut changed = inputs.clone();
        match field {
            0 => {
                changed.selection =
                    Selection::Recorded(RecordedContext::new(1, 3, &["future-name"])?)
            }
            1 => changed.registries.property_revision += 1,
            2 => changed.registries.attribute_revision += 1,
            3 => changed.registries.selector_revision += 1,
            4 => changed.registries.tree_revision += 1,
            5 => changed.registries.chunk_revision += 1,
            6 => changed.registries.identity_profile.push_str("-different"),
            7 => assert!(changed.registries.behavioral_properties.pop().is_some()),
            _ => changed
                .registries
                .later_properties
                .push("future-name".into()),
        }
        variants.push(changed);
    }
    for context in [
        RecordedContext::new(1, 1, &[])?,
        RecordedContext::new(1, 3, &[])?,
        RecordedContext::new(2, 3, &["other-future-name"])?,
    ] {
        let mut changed = inputs.clone();
        changed.selection = Selection::Recorded(context);
        variants.push(changed);
    }
    for changed in variants {
        let other = Key::capture(
            &guard,
            Some(&identity),
            &changed,
            &admitted.commit,
            &evidence,
            TreeUse::Ordinary,
        )
        .ok_or("missing changed key")?;
        assert!(!key.matches(&other));
        admitted.completion_inputs = changed;
        assert!(
            HistoryObservation::held(&identity)
                .tracked(&consumed)
                .record_candidate(&guard, &admitted)
                .await
                .is_err()
        );
    }
    admitted.completion_inputs = inputs.clone();
    assert_eq!(consumed.candidate_preparation_work()?, (1, 0));

    // Failure in the original pure body is also advisory: neither the error nor
    // an absent pending row can become a reusable result on the next attempt.
    let failed = ConsumedResolver::new(&guard, original.baseline().authority())?;
    let mut unsupported = inputs.clone();
    unsupported.registries.attribute_revision = 99;
    for _ in 0..2 {
        let unsupported_key = Key::capture(
            &guard,
            Some(&identity),
            &unsupported,
            &admitted.commit,
            &evidence,
            TreeUse::Ordinary,
        );
        let failure = failed
            .prepare_candidate(unsupported_key, &unsupported, &admitted.commit, &evidence)
            .err()
            .ok_or("unsupported pure preparation succeeded")?;
        assert!(matches!(failure.kind(), StoreErrorKind::Invalid(_)));
    }
    assert_eq!(failed.candidate_preparation_work()?, (2, 0));
    assert!(failed.candidate_preparation_pending(head.commit)?.is_none());
    assert!(failed.finish()?.views.is_empty());

    let bounded = ConsumedResolver::new(&guard, original.baseline().authority())?;
    let bounded_observation = HistoryObservation::held(&identity).tracked(&bounded);
    bounded_observation
        .record_candidate(&guard, &admitted)
        .await?;
    bounded_observation
        .record_candidate(&guard, &same_root_candidate)
        .await?;
    bounded_observation
        .record_candidate(&guard, &admitted)
        .await?;
    assert_eq!(bounded.candidate_preparation_work()?, (3, 0));
    bounded_observation
        .record_candidate(&guard, &admitted)
        .await?;
    assert_eq!(bounded.candidate_preparation_work()?, (3, 1));

    // Each default is produced by the real input constructor, with the same
    // Guard discriminator. Geometry is revalidated at the changed minimum.
    let saved = guard.config.clone();
    for field in 0..3 {
        guard.config = saved.clone();
        match field {
            0 => guard.config.store_name.push_str("-different"),
            1 => guard.config.home.region = Some("other-region".into()),
            _ => guard.config.min_chunk_size *= 2,
        }
        let changed = guard.completion_inputs()?;
        if field == 2 {
            assert!(
                Key::capture(
                    &guard,
                    Some(&identity),
                    &changed,
                    &admitted.commit,
                    &evidence,
                    TreeUse::Ordinary
                )
                .is_none()
            );
        }
        let fresh = TreeEvidence::load_tree_for(
            guard.store(),
            evidence.root,
            &[],
            guard.config().min_chunk_size,
            TreeUse::Ordinary,
        )
        .await?;
        let other = Key::capture(
            &guard,
            Some(&identity),
            &changed,
            &admitted.commit,
            &fresh,
            TreeUse::Ordinary,
        )
        .ok_or("missing changed default key")?;
        assert!(!key.matches(&other));
    }
    guard.config = saved;
    let layered = TreeEvidence::load_tree_for(
        guard.store(),
        evidence.root,
        &[],
        guard.config().min_chunk_size,
        TreeUse::OverlayLayer,
    )
    .await?;
    // Canonical validation narrows this compatible layer to ordinary evidence;
    // the explicitly requested type still distinguishes the preparation key.
    assert_eq!(layered.usage, TreeUse::Ordinary);
    let layer_key = Key::capture(
        &guard,
        Some(&identity),
        &inputs,
        &admitted.commit,
        &layered,
        TreeUse::OverlayLayer,
    )
    .ok_or("missing typed layer key")?;
    assert!(!key.matches(&layer_key));
    admitted.tree_usage = TreeUse::OverlayLayer;
    HistoryObservation::held(&identity)
        .tracked(&consumed)
        .record_candidate(&guard, &admitted)
        .await?;
    assert_eq!(consumed.candidate_preparation_work()?, (2, 0));

    // Equivalent fresh Guard adapters must miss; weak keys do not own Guards.
    let foreign = repository.guard().held_guard(holder.source(), TokioClock)?;
    HistoryObservation::held(&identity)
        .tracked(&consumed)
        .record_candidate(&foreign, &admitted)
        .await?;
    assert_eq!(consumed.candidate_preparation_work()?, (3, 0));
    let replacement_key = Key::capture(
        &foreign,
        Some(&identity),
        &inputs,
        &admitted.commit,
        &evidence,
        TreeUse::Ordinary,
    )
    .ok_or("missing fresh Guard key")?;
    assert!(!key.matches(&replacement_key));
    drop(foreign);
    assert!(!replacement_key.matches(&replacement_key));

    let next = ConsumedResolver::new(&guard, original.baseline().authority())?;
    HistoryObservation::held(&identity)
        .tracked(&next)
        .record_candidate(&guard, &admitted)
        .await?;
    assert_eq!(next.candidate_preparation_work()?, (1, 0));
    assert!(
        Key::capture(
            &guard,
            None,
            &inputs,
            &admitted.commit,
            &evidence,
            TreeUse::Ordinary
        )
        .is_none()
    );
    let held_key = Key::capture(
        repository.guard(),
        Some(&identity),
        &inputs,
        &admitted.commit,
        &evidence,
        TreeUse::Ordinary,
    )
    .ok_or("missing held allocation key")?;
    drop(next);
    drop(guard);
    drop(adapter);
    drop(holder);

    // Weak retention leaves the real exclusion free to end and reacquire.
    // The old allocation remains reserved, preventing address-reuse false hits.
    assert!(!key.matches(&key));
    let replacement = SingleHeld::acquire_read_only(repository.store()).await?;
    let adapter = replacement.source();
    let replacement_identity = adapter.identity_proof();
    let guard = repository
        .guard()
        .held_guard(replacement.source(), TokioClock)?;
    let replacement_key = Key::capture(
        &guard,
        Some(&replacement_identity),
        &inputs,
        &admitted.commit,
        &evidence,
        TreeUse::Ordinary,
    )
    .ok_or("missing replacement holder key")?;
    assert!(!key.matches(&replacement_key));
    let held_replacement = Key::capture(
        repository.guard(),
        Some(&replacement_identity),
        &inputs,
        &admitted.commit,
        &evidence,
        TreeUse::Ordinary,
    )
    .ok_or("missing replaced held allocation key")?;
    assert!(!held_key.matches(&held_key));
    assert!(!held_key.matches(&held_replacement));
    Ok(())
}

#[tokio::test]
async fn candidate_preparation_reuse_rechecks_physical_and_issuer_refusals() -> TestResult {
    let repository = fixture().await;
    let mut writer = repository.begin(SOURCE, &token(), "sdk").await?;
    let head = repository
        .advance(&mut writer, request_file(Vec::new(), b"fresh refusal"))
        .await?;
    let admitted = repository
        .guard()
        .admit_policy(SOURCE, None, &token(), "sdk")
        .await?;
    let original = repository.guard().original_commit(&head.commit)?;
    let holder = SingleHeld::acquire_read_only(repository.store()).await?;
    let adapter = holder.source();
    let identity = adapter.identity_proof();
    let actual = repository.guard().held_guard(holder.source(), TokioClock)?;
    let guard = measured(&actual, admitted.commit.commit().tree)?;
    let mut consumed = ConsumedResolver::new(&guard, original.baseline().authority())?;
    HistoryObservation::held(&identity)
        .tracked(&consumed)
        .record_candidate(&guard, &admitted)
        .await?;
    HistoryObservation::held(&identity)
        .tracked(&consumed)
        .record_candidate(&guard, &admitted)
        .await?;
    assert_eq!(consumed.candidate_preparation_work()?, (1, 1));

    for fault in [1, 2] {
        guard.store().fault.store(fault, Ordering::Relaxed);
        let failure = HistoryObservation::held(&identity)
            .tracked(&consumed)
            .record_candidate(&guard, &admitted)
            .await
            .err()
            .ok_or("fresh metadata refusal bypassed")?;
        match fault {
            1 => assert!(matches!(failure.kind(), StoreErrorKind::Absent(_))),
            _ => assert!(matches!(failure.kind(), StoreErrorKind::Invalid(_))),
        }
        assert_eq!(consumed.candidate_preparation_work()?, (1, 1));
    }
    guard.store().fault.store(0, Ordering::Relaxed);

    let suffix = head
        .commit
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    let path = original
        .baseline()
        .authority()
        .control()
        .join(format!("commit-{suffix}.cbor"));
    let bytes = std::fs::read(&path)?;
    let before_original = guard.store().node_reads.load(Ordering::Relaxed);
    std::fs::remove_file(&path)?;
    // Original bytes are independently reread at the real producer boundary,
    // not by the ordinary original_commit map accessor inside record_candidate.
    let observation = HistoryObservation::held(&identity).tracked(&consumed);
    let refusal = guard
        .revalidate_original_context(&original, observation)
        .await;
    let closing = actual
        .verified_history_observed(head.commit, observation)
        .await;
    use std::{io::Write, os::unix::fs::OpenOptionsExt};
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&path)?;
    file.write_all(&bytes)?;
    file.sync_all()?;
    for failure in [
        refusal
            .err()
            .ok_or("missing Original producer evidence accepted")?,
        closing
            .err()
            .ok_or("missing Original closing history accepted")?,
    ] {
        assert!(matches!(
            failure.kind(),
            StoreErrorKind::Unavailable { retry_after: None }
        ));
        assert_eq!(
            std::error::Error::source(&failure)
                .and_then(|source| source.downcast_ref::<std::io::Error>())
                .map(std::io::Error::kind),
            Some(std::io::ErrorKind::NotFound)
        );
    }
    // These factories retain their own genuine concrete store; their separate
    // reads do not traverse the measured candidate-only adapter.
    assert_eq!(
        guard.store().node_reads.load(Ordering::Relaxed),
        before_original
    );
    assert_eq!(consumed.candidate_preparation_work()?, (1, 1));

    consumed.candidate_preparation_issuer_retirement(Some(0));
    let refusal = HistoryObservation::held(&identity)
        .tracked(&consumed)
        .record_candidate(&guard, &admitted)
        .await;
    assert!(matches!(
        refusal.err().ok_or("fresh issuer refusal bypassed")?.kind(),
        StoreErrorKind::Invalid(_)
    ));
    assert_eq!(consumed.candidate_preparation_work()?, (1, 1));
    assert_eq!(
        guard.store().node_reads.load(Ordering::Relaxed),
        before_original + 1
    );
    consumed.candidate_preparation_issuer_retirement(None);
    HistoryObservation::held(&identity)
        .tracked(&consumed)
        .record_candidate(&guard, &admitted)
        .await?;
    assert_eq!(consumed.candidate_preparation_work()?, (1, 2));
    assert_eq!(
        guard.store().node_reads.load(Ordering::Relaxed),
        before_original + 2
    );
    assert!(consumed.finish().is_err());
    assert!(
        consumed
            .observed_completed_view_contexts_for_tests()?
            .is_empty()
    );
    Ok(())
}
