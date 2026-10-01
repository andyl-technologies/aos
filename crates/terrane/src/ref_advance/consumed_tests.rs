//! Checks consumed controls and canonical policy witnesses through actual retention.

#![allow(
    clippy::unwrap_used,
    reason = "Genuine native fixtures panic when required setup or asserted effects fail."
)]

use super::tests::{fixture, request, token};
use crate::bucket::held::SingleHeld;
use crate::guard::{ConsumedResolver, HistoryObservation};
use crate::store::TokioClock;
use terrane_core::gc::publication::evidence::{
    CheckedLineage, ControlKind, GuardSnapshot, LineageUsedInputs, PhysicalRegistration,
};

#[tokio::test]
async fn empty_tree_tag_retains_actual_view_root_authorization() {
    use crate::store::Clock;

    let repository = fixture().await;
    let source = "refs/heads/_/main";
    let target = "refs/tags/_/empty";
    let capability = token();
    let mut session = repository.begin(source, &capability, "sdk").await.unwrap();
    let head = repository
        .advance(&mut session, request(Vec::new()))
        .await
        .unwrap();

    let selected = repository.guard().verified_tree(head.commit).await.unwrap();
    let roots = repository
        .guard()
        .authoring_roots(&selected.evidence)
        .unwrap();
    assert_eq!(roots.len(), 1);
    assert_eq!(roots[0].0, b"/");

    let started = repository.guard().clock().monotonic();
    let publication = repository
        .guard()
        .admit_tag(source, target, &capability, "sdk")
        .await
        .unwrap();
    let captured = repository
        .guard()
        .capture_tag_authorizations_observed(
            source,
            &capability,
            "sdk",
            &publication,
            HistoryObservation::default(),
        )
        .await
        .unwrap();
    assert_eq!(captured.len(), 1);
    repository
        .guard()
        .retain_request_checks(&captured, started, std::time::Duration::from_secs(30))
        .unwrap()
        .recheck()
        .unwrap();

    let tag = repository
        .tag(source, target, &capability, "sdk")
        .await
        .unwrap();
    assert_eq!(tag.commit, head.commit);
}

#[tokio::test]
async fn actual_selected_guard_setup_refuses_stale_reopen_configuration() {
    use crate::guard::Guard;
    use crate::store::StoreErrorKind;

    let repository = fixture().await;
    let reference = "refs/heads/_/main";
    let mut session = repository.begin(reference, &token(), "sdk").await.unwrap();
    let first = repository
        .advance(&mut session, request(Vec::new()))
        .await
        .unwrap();
    let original = repository.guard().original_commit(&first.commit).unwrap();
    let authority = original.baseline().authority();
    let expected = ConsumedResolver::new(repository.guard(), authority)
        .unwrap()
        .snapshot_bytes()
        .unwrap();
    let before = {
        let namespace = SingleHeld::acquire(repository.store()).await.unwrap();
        let destination = namespace.destination();
        let observed = destination.observe_publication().await.unwrap();
        assert_eq!(
            destination
                .selected_guard_snapshot(&observed)
                .await
                .unwrap(),
            Some(expected)
        );
        let lineage_bytes = destination
            .selected_lineage(&observed, reference)
            .await
            .unwrap()
            .unwrap();
        let lineage = CheckedLineage::decode(&lineage_bytes).unwrap();
        assert_eq!(lineage.source_name, reference);
        assert_eq!(lineage.source, first);
        assert_eq!(lineage.commit_id, first.commit);
        assert_eq!(lineage.guard_digest, observed.state().guard.unwrap());
        assert_eq!(lineage.loss_generation, observed.state().loss_generation);
        assert_eq!(lineage.controls, lineage.used.controls);
        assert!(
            lineage
                .used
                .views
                .iter()
                .any(|view| view.view == first.commit)
        );
        observed.stamp()
    };

    let mut stale_keys = repository.guard().keys().to_vec();
    stale_keys[0].retirement = Some(0);
    let stale = Guard::new(
        repository.store().clone(),
        TokioClock,
        stale_keys,
        repository.guard().config().clone(),
    );
    let rejected = stale
        .install_original_verifier(authority)
        .await
        .unwrap_err();
    assert!(matches!(rejected.kind(), StoreErrorKind::Denied { .. }));

    let mut wrong_profile = repository.guard().config().clone();
    wrong_profile.chunk_profile = Box::new(terrane_core::chunking::ChunkProfile::cdc_1m([1; 32]));
    let mismatched = Guard::new(
        repository.store().clone(),
        TokioClock,
        repository.guard().keys().to_vec(),
        wrong_profile,
    );
    assert!(matches!(
        mismatched
            .install_original_verifier(authority)
            .await
            .unwrap_err()
            .kind(),
        StoreErrorKind::Invalid(_)
    ));

    let namespace = SingleHeld::acquire(repository.store()).await.unwrap();
    let destination = namespace.destination();
    let observed = destination.observe_publication().await.unwrap();
    assert_eq!(observed.stamp(), before);
    assert_eq!(repository.store().root(), authority.root());
}

#[tokio::test]
async fn actual_guard_installation_rechecks_used_registration_after_slot_staging() {
    use super::fault_tests::FaultFs;
    use super::tests::{configured_with_fs, raw_fixture};
    use crate::bucket::FileBucket;
    use crate::domain::DomainNamespace;
    use crate::repository::Repository;
    use crate::store::{LocalFs, TokioLocalFs};
    use std::os::unix::fs::PermissionsExt;

    let unused = raw_fixture().await;
    let root = unused.store().root().to_owned();
    let fs = FaultFs::default();
    let bucket = FileBucket::open(
        super::tests::config(root.clone()).await,
        fs.clone(),
        TokioClock,
        super::tests::Validator,
    )
    .await
    .unwrap();
    let coordinator = configured_with_fs(bucket, fs.clone());
    let owner = coordinator.store().publication_operator_uid().unwrap();
    let control = root.with_file_name(format!(
        "{}-staging-control",
        root.file_name().unwrap().to_string_lossy()
    ));
    fs.create_dir_new(&control).await.unwrap();
    fs.set_permissions_and_sync(&control, std::fs::Permissions::from_mode(0o700))
        .await
        .unwrap();
    let namespace = DomainNamespace {
        root: root.clone(),
        domain: coordinator.guard().config().storage_domain.clone(),
    };
    let before = {
        let holder = SingleHeld::acquire(coordinator.store()).await.unwrap();
        let destination = holder.destination();
        let observed = destination.observe_publication().await.unwrap();
        assert!(observed.state().guard.is_none());
        observed.stamp()
    };
    let actual_bucket = coordinator.store().clone();
    fs.change_registration_during_slot_staging(control.join("registration.cbor"));
    let attempted =
        Repository::initialize_native_retention(coordinator, &namespace, &control, owner).await;
    assert!(fs.registration_slot_change_consumed());
    assert!(attempted.is_err());
    {
        let holder = SingleHeld::acquire(&actual_bucket).await.unwrap();
        let destination = holder.destination();
        let observed = destination.observe_publication().await.unwrap();
        assert_eq!(observed.stamp(), before);
        assert!(observed.state().guard.is_none());
        fs.assert_registration_slot_refused(observed.stamp())
            .await
            .unwrap();
    }

    let reopened = FileBucket::open(
        super::tests::config(root).await,
        TokioLocalFs,
        TokioClock,
        super::tests::Validator,
    )
    .await
    .unwrap();
    let holder = SingleHeld::acquire(&reopened).await.unwrap();
    let destination = holder.destination();
    let observed = destination.observe_publication().await.unwrap();
    eprintln!("registration-fault setup refused: {}", attempted.is_err());
    fs.report_selected_registration_fault(observed.stamp())
        .await
        .unwrap();
    // Reopen may publish a distinct Raw CAPABILITIES repair. The checked
    // Guard dispatch was already refused above before that independent effect.
    assert!(observed.state().guard.is_none());
}

#[tokio::test]
async fn held_consumed_resolver_records_exact_original_rows_and_canonical_policy() {
    let repository = fixture().await;
    let reference = "refs/heads/_/main";
    let mut session = repository.begin(reference, &token(), "sdk").await.unwrap();
    let first = repository
        .advance(&mut session, request(Vec::new()))
        .await
        .unwrap();
    let second = repository
        .advance(&mut session, request(vec![first.commit]))
        .await
        .unwrap();
    let original = repository.guard().original_commit(&second.commit).unwrap();

    {
        let held = SingleHeld::acquire(repository.store()).await.unwrap();
        let destination = held.destination();
        let proof = destination.identity_proof();
        let guard = repository
            .guard()
            .held_guard(held.destination(), TokioClock)
            .unwrap();
        let resolver = ConsumedResolver::new(&guard, original.baseline().authority()).unwrap();
        let snapshot = GuardSnapshot::decode(&resolver.snapshot_bytes().unwrap()).unwrap();
        let PhysicalRegistration::Local(registration) = &snapshot.registration else {
            panic!("actual local factory must record the local physical registration");
        };
        assert_eq!(
            registration.original_id,
            *original.baseline().authority().id()
        );
        assert_eq!(
            (registration.root_device, registration.root_inode),
            original.baseline().authority().physical_identity().0
        );
        assert_eq!(
            snapshot.configuration.chunk_profile.seed,
            repository.guard().config().chunk_profile.seed()
        );
        assert_eq!(
            snapshot
                .configuration
                .initial_acl
                .iter()
                .map(|grant| (grant.principal.clone(), grant.verbs))
                .collect::<Vec<_>>(),
            repository.guard().config().initial_acl
        );
        let observation = HistoryObservation::held(&proof).tracked(&resolver);
        guard
            .verified_history_observed(second.commit, observation)
            .await
            .unwrap();
        guard
            .revalidate_original_context(&original, observation)
            .await
            .unwrap();
        let used = resolver.finish().unwrap();

        assert_eq!(used.controls.len(), 4);
        assert_eq!(
            used.controls
                .iter()
                .filter(|pin| pin.kind == ControlKind::Registration)
                .count(),
            1
        );
        assert_eq!(
            used.controls
                .iter()
                .filter(|pin| pin.kind == ControlKind::Bootstrap)
                .count(),
            1
        );
        assert_eq!(
            used.controls
                .iter()
                .filter(|pin| pin.kind == ControlKind::Association)
                .count(),
            2
        );
        assert_eq!(used.issuers.len(), 1);
        assert_eq!(used.issuers[0].issuer, "test");
        assert_eq!(used.issuers[0].key_id, "key");
        assert_eq!(used.views.len(), 2);
        for view in &used.views {
            assert_eq!(view.roots.len(), 1);
            assert_eq!(view.roots[0].path, b"/");
            assert_eq!(view.roots[0].layers.len(), 1);
            assert_ne!(view.roots[0].layers[0].properties, vec![0xa0]);
            assert_eq!(view.roots[0].layers[0].overrides, vec![0xa0]);
        }
        assert_eq!(
            used.configuration.storage_domain,
            repository.guard().config().storage_domain
        );
        assert_eq!(
            used.configuration.chunk_profile.seed,
            repository.guard().config().chunk_profile.seed()
        );
        assert_eq!(
            LineageUsedInputs::decode(&used.encode().unwrap()).unwrap(),
            used
        );

        let repeated = resolver.finish().unwrap();
        assert_eq!(
            repeated, used,
            "finishing cannot add caller-selected dependencies"
        );

        let mut controls = repository
            .guard()
            .hold_original_registration(original.baseline().authority(), &proof)
            .await
            .unwrap();
        let retained = controls.retain_used(&used.controls).await.unwrap();
        assert_eq!(retained.records().len(), used.controls.len());
        assert_eq!(retained.exclusions().len(), 1);
        for (pin, record) in used.controls.iter().zip(retained.records()) {
            pin.check_record(record.bytes()).unwrap();
            assert_eq!(record.path().file_name().unwrap(), pin.key.as_str());
            let metadata = tokio::fs::symlink_metadata(record.path()).await.unwrap();
            use std::os::unix::fs::MetadataExt;
            assert_eq!(record.identity(), (metadata.dev(), metadata.ino()));
            assert_eq!(metadata.mode() & 0o777, 0o600);
        }
        assert_eq!(
            retained.ancestors().last().unwrap().path(),
            retained.directory()
        );

        // The original guard can disappear without unlocking its duplicated
        // descriptor. An independent native lock opener still waits until the
        // retained receipt is released; no authority is minted by this probe.
        let coordination = retained.directory().join("retention.lock");
        drop(controls);
        let (started, waiting) = tokio::sync::oneshot::channel();
        let mut competitor = tokio::spawn(async move {
            use crate::store::LocalFs;
            started.send(()).unwrap();
            crate::store::TokioLocalFs
                .lock_existing_exclusive(&coordination)
                .await
        });
        waiting.await.unwrap();
        assert!(
            tokio::time::timeout(std::time::Duration::from_millis(100), &mut competitor)
                .await
                .is_err()
        );
        drop(retained);
        competitor.await.unwrap().unwrap();
    }
    tokio::fs::remove_dir_all(repository.store().root())
        .await
        .unwrap();
}

#[derive(Clone)]
struct RequestClock(std::sync::Arc<std::sync::atomic::AtomicU64>);

struct SendOnlyClock(std::cell::Cell<()>);

#[async_trait::async_trait]
impl crate::store::Clock for SendOnlyClock {
    fn now(&self) -> std::time::SystemTime {
        self.0.get();
        std::time::UNIX_EPOCH + std::time::Duration::from_secs(1000)
    }

    fn monotonic(&self) -> std::time::Duration {
        std::time::Duration::ZERO
    }
}

#[tokio::test]
async fn stored_advance_methods_preserve_send_only_clock_and_unsupported_setup_has_no_effects() {
    use crate::guard::Guard;
    use crate::ref_advance::{CommitTiming, Coordinator};
    use crate::store::{RefStore, StoreErrorKind, TokioLocalFs};
    use std::time::Duration;

    fn assert_send<T: Send>() {}
    assert_send::<SendOnlyClock>();
    let repository = fixture().await;
    let reference = "refs/heads/_/main";
    let mut session = repository.begin(reference, &token(), "sdk").await.unwrap();
    let first = repository
        .advance(&mut session, request(Vec::new()))
        .await
        .unwrap();
    let original = repository.guard().original_commit(&first.commit).unwrap();
    let before = {
        let held = SingleHeld::acquire(repository.store()).await.unwrap();
        held.destination()
            .observe_publication()
            .await
            .unwrap()
            .stamp()
    };

    let guard = Guard::new(
        repository.store().clone(),
        SendOnlyClock(std::cell::Cell::new(())),
        repository.guard().keys().to_vec(),
        repository.guard().config().clone(),
    );
    let unsupported = guard
        .install_original_verifier(original.baseline().authority())
        .await
        .unwrap_err();
    assert!(matches!(unsupported.kind(), StoreErrorKind::Unsupported));
    let coordinator = Coordinator::new(
        guard,
        CommitTiming::new(
            Duration::from_secs(30),
            Duration::from_secs(120),
            Duration::from_secs(1),
        )
        .unwrap(),
        TokioLocalFs,
    );
    let capability = token();
    // Constructing these futures is a compile-time check of the unchanged
    // public C: Clock contract. Unsupported retention was exercised above.
    drop(coordinator.rollback(&mut session, first.commit, &capability, "sdk"));
    drop(coordinator.set_policy(reference, None, &capability, "sdk"));

    assert_eq!(
        repository.store().ref_get(reference).await.unwrap(),
        Some(first)
    );
    let held = SingleHeld::acquire(repository.store()).await.unwrap();
    let destination = held.destination();
    assert_eq!(
        destination.observe_publication().await.unwrap().stamp(),
        before
    );
}

#[async_trait::async_trait]
impl crate::store::Clock for RequestClock {
    fn now(&self) -> std::time::SystemTime {
        std::time::UNIX_EPOCH
            + std::time::Duration::from_secs(self.0.load(std::sync::atomic::Ordering::SeqCst))
    }

    fn monotonic(&self) -> std::time::Duration {
        std::time::Duration::from_secs(self.0.load(std::sync::atomic::Ordering::SeqCst))
    }
}

#[tokio::test]
async fn actual_held_request_refresh_rejects_expiry_and_issuer_retirement() {
    use crate::guard::Guard;
    use crate::store::{RefStore, StoreErrorKind};
    use terrane_core::auth::{self, Token, Verb};

    let repository = fixture().await;
    let reference = "refs/heads/_/main";
    let mut session = repository.begin(reference, &token(), "sdk").await.unwrap();
    let published = repository
        .advance(&mut session, request(Vec::new()))
        .await
        .unwrap();
    let mut authority = auth::verify(&token(), repository.guard().keys(), 100)
        .unwrap()
        .authority()
        .clone();
    authority.not_after = 101;
    let capability = Token::issue(
        authority,
        &super::tests::secret(),
        repository.guard().keys()[0].public_key,
    )
    .unwrap()
    .encode();

    let held = SingleHeld::acquire(repository.store()).await.unwrap();
    let destination = held.destination();
    let proof = destination.identity_proof();
    let now = std::sync::Arc::new(std::sync::atomic::AtomicU64::new(100));
    let clock = RequestClock(std::sync::Arc::clone(&now));
    let guard = repository
        .guard()
        .held_guard(held.destination(), clock.clone())
        .unwrap();
    let authorized = guard
        .authorize_observed(
            reference,
            &capability,
            Verb::Commit,
            &[],
            "sdk",
            HistoryObservation::held(&proof),
        )
        .await
        .unwrap();
    assert_eq!(authorized.record(), Some(&published));
    assert_eq!(authorized.root_paths(), [b"/".to_vec()]);

    now.store(102, std::sync::atomic::Ordering::SeqCst);
    let expired = guard.refresh_authorized_time(&authorized).unwrap_err();
    assert!(matches!(expired.kind(), StoreErrorKind::Denied { .. }));

    now.store(100, std::sync::atomic::Ordering::SeqCst);
    let mut keys = repository.guard().keys().to_vec();
    keys[0].retirement = Some(99);
    let retired = Guard::new(
        held.destination(),
        clock,
        keys,
        repository.guard().config().clone(),
    );
    let retirement = retired.refresh_authorized_time(&authorized).unwrap_err();
    assert!(matches!(retirement.kind(), StoreErrorKind::Denied { .. }));
    assert_eq!(
        held.source().ref_get(reference).await.unwrap(),
        Some(published)
    );
}
