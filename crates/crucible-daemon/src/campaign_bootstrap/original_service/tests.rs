//! Exercises the real prepared owner and its actual parent alias lifetimes.
//!
//! Fixture banks and native SQLite are mechanism inputs. These tests do not
//! certify a Parent workflow, component-file issuer or complete deployment.

// crucible-lint: allow panic-shortcut -- failed real ownership assertions stop these controls.
#![allow(clippy::unwrap_used)]

use crate::private_measurement_runtime::catalog::tests::{
    GraphQuotaFixture, fixture, fixture_original,
};
use crucible_cas::content_store::{ObjectKind, OriginalSqliteGraphConfig};
use std::cell::RefCell;

use super::*;

mod creation;

thread_local! {
    static PUBLICATION: RefCell<Option<Box<dyn FnOnce()>>> = RefCell::new(None);
}

pub(super) fn after_publication() {
    PUBLICATION.with(|hook| {
        let callback = hook.borrow_mut().take();
        if let Some(callback) = callback {
            callback();
        }
    });
}

fn configuration() -> (CampaignLoopbackServerConfig, CampaignLocalServiceMode) {
    (
        CampaignLoopbackServerConfig::new(
            1,
            1,
            1,
            Duration::from_millis(1),
            crate::LoopbackCampaignTimeouts::new(
                Duration::from_millis(10),
                Duration::from_millis(10),
            )
            .unwrap(),
        )
        .unwrap(),
        CampaignLocalServiceMode::ReadOnly,
    )
}

enum Publication {
    Healthy,
    Cancel,
    BudgetThenCancel,
    Panic,
}

fn exercise(publication: Publication) {
    let (root, decoder, catalog) = fixture();
    let directory = tempfile::TempDir::new().unwrap();
    let budget = decoder.budget().unwrap();
    let quota = Arc::new(GraphQuotaFixture(budget.clone()));
    let heap = crucible_cas::content_store::fixture_sqlite_heap().unwrap();
    let mut graph = crucible_cas::content_store::OriginalSqliteGraphOwner::open(
        OriginalSqliteGraphConfig {
            name: "campaign-primary",
            root: &directory.path().join("objects"),
            admitted_kinds: &[ObjectKind::CampaignFact],
            maximum_sqlite_heap_bytes: heap.maximum_heap_bytes(),
        },
        quota.clone(),
        catalog.supervisor().unwrap(),
        &heap,
    )
    .unwrap();
    let mut refs = crucible_cas::content_store::OriginalDirectoryRefOwner::open(
        &directory.path().join("refs"),
        quota.clone(),
    )
    .unwrap();
    let mut repository = OriginalCampaignRepositoryBootstrap::prepare_with_components(
        &mut graph,
        &refs,
        budget,
        (
            PlannerAuthorityKey::from_bytes([1; 32]).unwrap(),
            DebuggerAuthorityKey::from_bytes([2; 32]).unwrap(),
        ),
    )
    .unwrap();
    let state_path = directory.path().join("state");
    fs::create_dir(&state_path).unwrap();
    fs::set_permissions(&state_path, Permissions::from_mode(0o700)).unwrap();
    let mut state = Some(OriginalCampaignStateBootstrap::fixture_at(&state_path, budget).unwrap());
    let state_handle = state.as_mut().unwrap().share_for_service().unwrap().into();
    let mut retention =
        crate::hot_checkpoint_retention::OriginalHotCheckpointRetentionOwner::fixture_at(
            &directory.path().join("retention"),
            catalog.supervisor().unwrap(),
            quota.clone(),
            budget,
        )
        .unwrap();
    let mut transfers = crate::campaign_transfer::OriginalCampaignTransferJournalOwner::fixture_at(
        &directory.path().join("transfers"),
        catalog.supervisor().unwrap(),
        quota.clone(),
        budget,
    )
    .unwrap();
    let policy = Arc::new(
        UnixPeerCampaignPolicy::from_toml_bytes(
            br#"
schema = "crucible.campaign-local-policy"
version = 1
[[bindings]]
user_id = 0
group_id = 0
principal = "operator"
[[grants]]
principal = "operator"
operation = "get-campaign-status"
campaign = "example"
"#,
        )
        .unwrap(),
    );
    let policy_weak = Arc::downgrade(&policy);
    let shared_retention = retention.share().unwrap();
    let shared_transfers = transfers.share().unwrap();
    let refusal = !matches!(publication, Publication::Healthy);
    let panic = matches!(publication, Publication::Panic);
    let sticky = matches!(publication, Publication::BudgetThenCancel);
    let original = ServiceOriginal::Fixture(fixture_original(&catalog));
    let (server, mode) = configuration();
    let callback: Option<Box<dyn FnOnce()>> = match publication {
        Publication::Healthy => None,
        Publication::Cancel => Some(Box::new(move || root.cancel().unwrap())),
        Publication::BudgetThenCancel => {
            let budget = budget.clone();
            Some(Box::new(move || {
                assert!(budget.reserve_scratch_bytes(5 << 20).is_err());
                root.cancel().unwrap();
            }))
        }
        Publication::Panic => Some(Box::new(|| panic!("publication unwind"))),
    };
    PUBLICATION.with(|hook| *hook.borrow_mut() = callback);
    let competitor = File::open(directory.path().join("retention/writer.lock")).unwrap();

    let attempted = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        OriginalPreparedCampaignServiceOwner::prepare_configured(
            (server, mode, original),
            &mut repository,
            state_handle,
            policy,
            shared_retention,
            shared_transfers,
            budget,
        )
    }));

    if refusal {
        if panic {
            assert!(attempted.is_err());
        } else {
            let error = attempted.unwrap().err().unwrap();
            assert!(error.is_admission());
            assert!(matches!(
                error.original_after(),
                Some(
                    crucible_linux_resource::host_supervision::HostSupervisionError::Terminal { .. }
                )
            ));
            if sticky {
                assert!(budget.check().is_err());
            }
        }
        assert!(policy_weak.upgrade().is_some());
        assert!(retention.try_close().is_err());
        assert!(transfers.try_close().is_err());
        assert!(repository.try_close().is_err());
        assert!(flock(&competitor, FlockOperation::NonBlockingLockExclusive).is_err());
        return;
    }
    let mut prepared = attempted.unwrap().unwrap();
    let service = prepared.service.as_ref().unwrap();
    assert_eq!(service.endpoint.path(), Path::new(ENDPOINT));
    assert_eq!(service.mode, CampaignLocalServiceMode::ReadOnly);
    assert!(service.planner_authority.is_some());
    assert!(service.maintenance.is_some());
    assert!(policy_weak.upgrade().is_some());
    assert!(retention.try_close().is_err());
    assert!(transfers.try_close().is_err());
    assert!(repository.try_close().is_err());
    let scenario = crucible::happy_path_scenario().unwrap().scenario;
    let refusal = prepared
        .import_configuration(&scenario, &crucible::Schedule::empty())
        .err()
        .unwrap();
    assert!(
        matches!(&refusal.failure, PreparedFailure::Retained(purpose)
        if matches!(purpose.data.source,
            Some(PreparedCause::Service(CampaignLocalServiceError::ArtifactImportReadOnly))))
    );
    // The actual typed error owns its admitted body until physical Drop.
    drop(refusal);
    prepared.try_close().unwrap();
    prepared.try_close().unwrap();
    assert!(policy_weak.upgrade().is_none());
    assert!(prepared.controls.is_none());
    drop(policy_weak);
    repository.try_close().unwrap();
    retention.try_close().unwrap();
    transfers.try_close().unwrap();
    assert!(state.take().unwrap().try_close().is_ok());
    refs.try_close().unwrap();
    graph.try_close().unwrap();
    drop(prepared);
    drop(repository);
    drop(retention);
    drop(transfers);
    drop(refs);
    drop(graph);
    drop(quota);
    assert!(catalog.try_close().is_ok());
    assert!(decoder.try_close().is_ok());
}

#[test]
fn actual_prepared_service_holds_all_parent_aliases_then_closes_before_reuse() {
    exercise(Publication::Healthy);
}

#[test]
fn unwind_after_publication_retains_actual_service_and_writer_aliases() {
    exercise(Publication::Panic);
}

#[test]
fn real_original_cancel_after_publication_retains_service_and_writer_credit() {
    exercise(Publication::Cancel);
}

#[test]
fn earlier_budget_refusal_keeps_the_distinct_later_raw_original_cancellation() {
    exercise(Publication::BudgetThenCancel);
}

#[test]
fn admitted_failure_storage_retains_the_same_account_until_its_body_is_dropped() {
    let (_root, decoder, catalog) = fixture();
    let purpose = PreparedFailurePurpose::prepare(decoder.budget().unwrap(), || None).unwrap();
    let error = purpose.refuse(PreparedCause::Configuration, None);
    assert!(matches!(
        &error.failure,
        PreparedFailure::Retained(purpose)
            if matches!(purpose.data.source, Some(PreparedCause::Configuration))
    ));

    assert!(catalog.try_close().is_ok());
    let decoder = decoder.try_close().err().unwrap();
    drop(error);
    // This consuming fixture close is terminal after it takes the budget.
    drop(decoder);

    let (_root, decoder, catalog) = fixture();
    let purpose = PreparedFailurePurpose::prepare(decoder.budget().unwrap(), || None).unwrap();
    let error = purpose.refuse(PreparedCause::Configuration, None);
    assert!(catalog.try_close().is_ok());
    drop(error);
    assert!(decoder.try_close().is_ok());
}

#[test]
fn unused_admitted_failure_storage_releases_only_after_its_body_is_dropped() {
    let (_root, decoder, catalog) = fixture();
    let purpose = PreparedFailurePurpose::prepare(decoder.budget().unwrap(), || None).unwrap();

    assert!(catalog.try_close().is_ok());
    let decoder = decoder.try_close().err().unwrap();
    drop(purpose);
    drop(decoder);

    let (_root, decoder, catalog) = fixture();
    let purpose = PreparedFailurePurpose::prepare(decoder.budget().unwrap(), || None).unwrap();
    assert!(catalog.try_close().is_ok());
    drop(purpose);
    assert!(decoder.try_close().is_ok());
}
