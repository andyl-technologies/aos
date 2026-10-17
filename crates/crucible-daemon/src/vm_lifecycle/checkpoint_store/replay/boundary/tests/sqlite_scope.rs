//! Genuine SQL outcomes and original loans crossing the linear native bridge.

use std::cell::Cell;
use std::sync::Arc;

use super::*;
use crucible_cas::content_store::{
    SqliteBlobBackend, SqliteCatalogOperation, SqliteCatalogOperationKind, SqliteCatalogSupervisor,
    SqliteCommitOutcome, SqliteScopeError, StoreError, StorePhysicalQuotaGuard,
};
use crucible_cas::owned_decode::DecodeBudget;
use crucible_linux_resource::host_services::HostServiceAllocator;

struct FixtureQuota(HostServiceAllocator);

impl StorePhysicalQuotaGuard for FixtureQuota {
    fn decoded_metadata_limit(&self) -> Result<u64, StoreError> {
        Ok(self.0.maximum_resident_bytes())
    }

    fn reserve_resources(
        &self,
        descriptors: u64,
        bytes: u64,
    ) -> Result<crucible_cas::owned_decode::ResourceLoan, StoreError> {
        self.verify()?;
        self.0
            .reserve_resources(0, descriptors, bytes)
            .map(crucible_cas::owned_decode::ResourceLoan::new)
            .map_err(|_| StoreError::Quota)
    }

    fn verify(&self) -> Result<(), StoreError> {
        self.0.verify_live().map_err(|_| StoreError::Unavailable)
    }
}

struct FixtureSupervisor(Arc<FixtureQuota>);
struct FixtureOperation(Arc<FixtureQuota>);

impl SqliteCatalogSupervisor for FixtureSupervisor {
    fn reserve_resident_bytes(
        &self,
        bytes: u64,
    ) -> Result<crucible_cas::owned_decode::ResourceLoan, StoreError> {
        self.0.reserve_resources(0, bytes)
    }

    fn begin(
        &self,
        _: SqliteCatalogOperationKind,
    ) -> Result<Box<dyn SqliteCatalogOperation>, StoreError> {
        self.0.verify()?;
        Ok(Box::new(FixtureOperation(Arc::clone(&self.0))))
    }
}

impl SqliteCatalogOperation for FixtureOperation {
    fn check(&self) -> Result<(), StoreError> {
        self.0.verify()
    }

    fn complete(self: Box<Self>) -> Result<(), StoreError> {
        self.0.verify()
    }
}

fn scope(error: &StoreError) -> &SqliteScopeError {
    match error {
        StoreError::SqliteDiagnostic { source } => scope(source.failure()),
        StoreError::SqliteScope { source } => source,
        other => panic!("complete original SQL scope lost: {other:?}"),
    }
}

fn isolated(name: &str) -> bool {
    if std::env::var_os("CRUCIBLE_NATIVE_SQL_SCOPE_CHILD").is_some() {
        return false;
    }
    // SQLite's process-global native cap can only decrease. Each actual 8 MiB
    // fixture runs in its own test process, leaving other API fixtures intact.
    let name =
        format!("vm_lifecycle::checkpoint_store::replay::boundary::tests::sqlite_scope::{name}");
    let output = std::process::Command::new(std::env::current_exe().expect("API test executable"))
        .args(["--exact", &name, "--nocapture"])
        .env("CRUCIBLE_NATIVE_SQL_SCOPE_CHILD", "1")
        .output()
        .expect("isolated genuine native SQL component");
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(output.status.success(), "{stdout}\n{stderr}");
    print!("{stdout}");
    eprint!("{stderr}");
    assert!(
        stdout.contains("1 passed; 0 failed"),
        "exact child did not run: {stdout}"
    );
    true
}

fn exercise(committed: bool) {
    let root = tempfile::tempdir().expect("actual private catalog");
    let bank =
        HostServiceAllocator::new(1, 128, 64 * 1024 * 1024).expect("finite original fixture bank");
    let guard = Arc::new(FixtureQuota(bank.clone()));
    let account = DecodeBudget::for_store(guard.clone()).expect("same original account");
    let entered = account.enter();
    let supervisor = Arc::new(FixtureSupervisor(Arc::clone(&guard)));
    let started = Cell::new(false);
    let calls = Cell::new(0);
    let observed = Cell::new(None);

    let error = read_with_boundary(
        &mut || {
            calls.set(calls.get() + 1);
            if started.get() {
                Err(QemuRamReadBoundaryError::Supervision(
                    HostSupervisionError::DeadlineExpired {
                        operation_id: 41,
                        class: HostOperationClass::PageIn,
                    },
                ))
            } else {
                Ok(())
            }
        },
        |ram_boundary| {
            let observation = SqliteBlobBackend::checked_scope_failure_fixture_for_test(
                root.path(),
                &account,
                supervisor,
                committed,
                &mut || ram_boundary().map_err(|_| StoreError::Unavailable),
                &mut || started.set(true),
                &crucible_cas::content_store::fixture_sqlite_heap()
                    .expect("authored SQLite fixture process"),
            )
            .map_err(RamStoreError::from)?;
            observed.set(Some((
                observation.generation,
                observation.busy_timeout_ms,
                observation.quarantined,
                observation.autocommit,
            )));
            Err::<(), _>(RamStoreError::from(observation.failure))
        },
    )
    .expect_err("complete actual SQL result and first refusal must survive");

    eprintln!(
        "native SQL observed committed={committed}: {:?}",
        observed.get()
    );
    assert_eq!(
        calls.get(),
        3,
        "two preparation checks and only the first refusal"
    );
    let QemuRamSourceError::RamBackingFailure {
        kind: BackendOperationalFailureKind::Expired,
        first:
            Some(QemuRamReadBoundaryError::Supervision(HostSupervisionError::DeadlineExpired {
                operation_id: 41,
                class: HostOperationClass::PageIn,
            })),
        source: RamStoreError::Store(ref storage),
    } = error
    else {
        panic!("original native refusal or full SQL cause replaced: {error:?}");
    };
    let failure = scope(storage);
    assert!(matches!(
        failure.work_failure(),
        Some(StoreError::Unavailable)
    ));
    if committed {
        assert_eq!(failure.outcome(), SqliteCommitOutcome::Committed);
        assert!(failure.rollback_failure().is_none());
        assert!(failure.restoration_failure().is_none());
        assert_eq!(observed.get(), Some((2, 5000, false, true)));
    } else {
        assert_eq!(failure.outcome(), SqliteCommitOutcome::Uncertain);
        assert!(matches!(
            failure.rollback_failure(),
            Some(rusqlite::Error::InvalidQuery)
        ));
        assert!(matches!(
            failure.restoration_failure(),
            Some(rusqlite::Error::InvalidQuery)
        ));
        assert_eq!(observed.get(), Some((1, 0, true, false)));
    }

    let weak = Arc::downgrade(&guard);
    drop(entered);
    drop(account);
    drop(guard);
    assert!(
        weak.upgrade().is_some(),
        "native error retains actual SQL credit owner"
    );
    drop(error);
    assert!(
        weak.upgrade().is_none(),
        "last native error closes original SQL owner"
    );
    assert!(
        bank.reserve_resources(0, 0, bank.maximum_resident_bytes())
            .is_ok()
    );
}

#[test]
fn retains_actual_committed_sqlite_outcome_and_original_credit() {
    if isolated("retains_actual_committed_sqlite_outcome_and_original_credit") {
        return;
    }
    exercise(true);
}

#[test]
fn retains_actual_dual_cleanup_and_uncertain_sqlite_outcome() {
    if isolated("retains_actual_dual_cleanup_and_uncertain_sqlite_outcome") {
        return;
    }
    exercise(false);
}
