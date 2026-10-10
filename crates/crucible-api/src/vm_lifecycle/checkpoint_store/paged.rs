//! Durable, bounded RAM catalogs owned by one attempt-local checkpoint store.
//!
//! The SQLite catalog is private to the scenario's native checkpoint catalog.
//! A shared retention fence protects capture and every live root reader; native
//! catalog retirement takes its exclusive counterpart before removing bytes.
//! RAM descendants remain in the authenticated CAS tree and never enter the
//! manifest's flat inventory of non-RAM continuation objects.

use std::fs::{File, OpenOptions};
use std::path::{Path, PathBuf};
use std::sync::Arc;

use crucible_cas::content_store::{ContentId, DurabilityRequirement, StorePhysicalQuotaGuard};
use crucible_cas::ram::{
    LeasedRamRoot, RamRetention, RamRootLease, RamStore, RamStoreError, RamStoreLimits,
};
use crucible_ram::{RootRecord, Scope};
use rustix::fs::{FlockOperation, flock};

use super::*;

const DIRECTORY: &str = "checkpoint-ram-objects";
const FENCE: &str = "retention.lock";

/// Preserves the supervisor's typed cancellation or resource-limit result.
///
/// # Errors
///
/// Returns the original boundary error, or a mapped storage error when no
/// boundary failed.
pub(in crate::vm_lifecycle) fn with_ram_boundary<T, E>(
    boundary: &mut dyn FnMut() -> Result<(), E>,
    operation: impl FnOnce(&mut dyn FnMut() -> Result<(), RamStoreError>) -> Result<T, RamStoreError>,
    map_storage_error: impl FnOnce(RamStoreError) -> E,
) -> Result<T, E> {
    let mut failure = None;
    let result = operation(&mut || match boundary() {
        Ok(()) => Ok(()),
        Err(error) => {
            failure = Some(error);
            Err(RamStoreError::Canceled)
        }
    });
    if let Some(error) = failure {
        return Err(error);
    }
    result.map_err(map_storage_error)
}

/// Acquires deletion exclusion before retiring a scenario catalog.
///
/// The nonblocking acquisition lets the supervisor reconcile live consumers
/// instead of waiting indefinitely behind an in-flight capture or transfer.
///
/// # Errors
///
/// Returns an I/O error when the fence cannot be opened or live readers still
/// retain deletion exclusion.
pub(in crate::vm_lifecycle) fn retirement_fence(
    scenario_directory: &Path,
) -> std::io::Result<Option<File>> {
    let path = scenario_directory.join(DIRECTORY).join(FENCE);
    let fence = match OpenOptions::new().read(true).write(true).open(&path) {
        Ok(fence) => fence,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error),
    };
    flock(&fence, FlockOperation::NonBlockingLockExclusive).map_err(std::io::Error::from)?;
    Ok(Some(fence))
}

/// Owns a private durable RAM backend and its live deletion exclusion.
#[derive(Clone)]
pub(in crate::vm_lifecycle) struct PagedRamCatalog {
    store: RamStore,
    retention: Arc<CatalogRetention>,
    provider: Arc<dyn ProductionRamCatalogProvider>,
    original: crucible_cas::owned_decode::DecodeBudget,
}

impl std::fmt::Debug for PagedRamCatalog {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("PagedRamCatalog")
            .field("directory", &self.retention.directory)
            .finish_non_exhaustive()
    }
}

impl PagedRamCatalog {
    /// Opens the scenario's bounded RAM store with live GC exclusion.
    ///
    /// # Errors
    ///
    /// Returns an error if catalog creation, deletion fencing, durable backend
    /// initialization, or resource admission fails.
    pub(in crate::vm_lifecycle) fn open(
        run_state_root: &Path,
        scenario: ContentHash,
        limits: FaultResourceLimits,
        provider: Option<&Arc<dyn ProductionRamCatalogProvider>>,
    ) -> Result<Self, SchedulerError> {
        let directory = run_state_root.join(scenario.to_hex()).join(DIRECTORY);
        let provider = provider
            .ok_or_else(|| store_error("RAM catalog requires retained physical quota authority"))?;
        let storage = provider
            .open_catalog(&directory)
            .map_err(|error| store_error(format!("open quota-bound RAM catalog: {error}")))?;
        storage
            .quota
            .verify()
            .map_err(|error| store_error(format!("verify RAM catalog quota: {error}")))?;
        let maximum_logical_bytes = limits.fat_checkpoint_bytes;
        // Each region may have its own partial final page. Bound geometry by
        // the full catalog limit rather than assuming one contiguous region.
        let maximum_pages = maximum_logical_bytes.div_ceil(4096).saturating_add(4095);
        let bounds = RamStoreLimits {
            maximum_logical_bytes,
            maximum_pages,
            maximum_object_visits: maximum_pages.saturating_mul(8).max(4096),
            maximum_io_bytes: maximum_logical_bytes.saturating_mul(8),
        };
        let durability = DurabilityRequirement::new(1, false)
            .map_err(|error| store_error(format!("admit RAM durability: {error}")))?;
        let store = RamStore::new(storage.backend, durability, bounds)
            .map_err(|error| store_error(format!("admit RAM catalog: {error}")))?;
        Ok(Self {
            store,
            retention: Arc::new(CatalogRetention {
                directory,
                fence: storage.retention_fence,
                quota: storage.quota,
                _root_credit: Default::default(),
            }),
            provider: Arc::clone(provider),
            original: storage.original,
        })
    }

    /// Reopens and verifies a complete image under a retained catalog fence.
    ///
    /// # Errors
    ///
    /// Returns an error for a mismatched binding, corrupt or missing backing,
    /// cancellation, or an exhausted verification bound.
    pub(in crate::vm_lifecycle) fn open_root(
        &self,
        identity: ContentId,
        expected: &RootRecord,
        boundary: &mut dyn FnMut() -> Result<(), RamStoreError>,
    ) -> Result<LeasedRamRoot, RamStoreError> {
        let account = self.operation_account()?;
        let retention = self.retention()?;
        let lease = retention.retain_root(identity)?;
        let root = self.store.open(lease, &account, boundary)?;
        if root.record() != expected || root.record().scope() != Scope::Exact {
            return Err(RamStoreError::Invalid("checkpoint RAM root binding"));
        }
        self.store.verify(&root, &account, boundary)?;
        Ok(root)
    }

    /// Authenticates one complete graph under an independent original operation account.
    ///
    /// # Errors
    /// Refuses canceled namespace authority, exhausted resources or corrupt descendants.
    pub(in crate::vm_lifecycle) fn verify(
        &self,
        root: &LeasedRamRoot,
        boundary: &mut dyn FnMut() -> Result<(), RamStoreError>,
    ) -> Result<crucible_cas::ram::RamVerificationReport, RamStoreError> {
        let account = self.operation_account()?;
        self.store.verify(root, &account, boundary)
    }

    pub(in crate::vm_lifecycle) fn original(&self) -> &crucible_cas::owned_decode::DecodeBudget {
        &self.original
    }

    fn operation_account(&self) -> Result<crucible_cas::owned_decode::DecodeBudget, RamStoreError> {
        self.original
            .child()
            .map_err(|source| RamStoreError::from_admission(&self.original, source))
    }

    pub(in crate::vm_lifecycle) fn store(&self) -> &RamStore {
        &self.store
    }

    /// Reserves decoded-root capacity and retains its origin through every lease.
    ///
    /// # Errors
    ///
    /// Refuses overflow, unavailable service capacity or closed catalog authority.
    pub(in crate::vm_lifecycle) fn retention(
        &self,
    ) -> Result<Arc<dyn RamRetention>, RamStoreError> {
        let bytes = crucible_cas::ram::maximum_ram_root_decoding_bytes()?;
        let credit = self
            .provider
            .reserve_root_metadata(&self.retention.directory, bytes)?;
        let mut retention = self.retention.as_ref().clone();
        retention._root_credit = credit.into();
        Ok(Arc::new(retention))
    }

    /// Admits portable root metadata before the manifest's owned root decode.
    ///
    /// # Errors
    ///
    /// Refuses overflow, unavailable service capacity or closed catalog authority.
    pub(in crate::vm_lifecycle) fn reserve_record_decode(
        &self,
    ) -> Result<crucible_cas::owned_decode::ResourceLoan, RamStoreError> {
        let bytes = RootRecord::decoding_memory_bound(crucible_ram::Limits::default())
            .map_err(|error| RamStoreError::Logical(error.to_string()))?;
        self.provider
            .reserve_root_metadata(&self.retention.directory, bytes)
            .map_err(RamStoreError::from)
    }
}

#[cfg(all(test, feature = "test-support"))]
impl PagedRamCatalog {
    /// Corrupts exactly one authenticated leaf realization in a small test image.
    pub(in crate::vm_lifecycle) fn corrupt_page_object_for_test(
        &self,
        root: &LeasedRamRoot,
        region_id: &str,
        page_index: u64,
    ) -> Result<(ContentId, Vec<u8>), SchedulerError> {
        let region = root
            .record()
            .topology()
            .region(region_id)
            .ok_or_else(|| store_error("test corruption names an absent RAM region"))?;
        region
            .geometry()
            .valid_length(page_index)
            .map_err(|error| store_error(error.to_string()))?;
        let ordinal = root
            .record()
            .topology()
            .regions()
            .iter()
            .position(|region| region.id() == region_id)
            .ok_or_else(|| store_error("test RAM region ordinal disappeared"))?;
        let connection = crucible_cas::content_store::fixture_sqlite_connection(
            self.retention.directory.join("objects.sqlite3"),
        )
        .map_err(|error| store_error(format!("open test RAM corruption database: {error}")))?;
        let read = |identity: ContentId| -> Result<crucible_cas::content_envelope::ContentEnvelope, SchedulerError> {
            let bytes: Vec<u8> = connection.query_row(
                "SELECT body FROM objects WHERE id = ?1", [identity.encode()], |row| row.get(0),
            ).map_err(|error| store_error(format!("read test RAM envelope: {error}")))?;
            if !identity.authenticates(&bytes) {
                return Err(store_error("test RAM envelope was already corrupt"));
            }
            crucible_cas::content_envelope::ContentEnvelope::from_canonical_bytes(&bytes)
                .map_err(|error| store_error(error.to_string()))
        };
        let child = |envelope: &crucible_cas::content_envelope::ContentEnvelope, role: &str| {
            envelope
                .children()
                .iter()
                .find(|child| child.role() == role)
                .map(|child| child.id())
                .ok_or_else(|| store_error("test RAM envelope is missing a child"))
        };
        let mut identity = child(&read(root.object_id())?, &format!("region-{ordinal:08x}"))?;
        for bit in (0..region.geometry().height()).rev() {
            identity = child(
                &read(identity)?,
                if (page_index >> bit) & 1 == 0 {
                    "left"
                } else {
                    "right"
                },
            )?;
        }
        let page = child(&read(identity)?, "page")?;
        let original: Vec<u8> = connection
            .query_row(
                "SELECT body FROM objects WHERE id = ?1",
                [page.encode()],
                |row| row.get(0),
            )
            .map_err(|error| store_error(format!("read selected test RAM page: {error}")))?;
        let mut corrupted = original.clone();
        let last = corrupted
            .last_mut()
            .ok_or_else(|| store_error("empty test page envelope"))?;
        *last ^= 1;
        connection
            .execute(
                "UPDATE objects SET body = ?1 WHERE id = ?2",
                rusqlite::params![corrupted, page.encode()],
            )
            .map_err(|error| store_error(format!("corrupt selected test RAM page: {error}")))?;
        Ok((page, original))
    }

    /// Restores a test-corrupted realization after checking its original identity.
    pub(in crate::vm_lifecycle) fn restore_object_for_test(
        &self,
        identity: ContentId,
        original: &[u8],
    ) -> Result<(), SchedulerError> {
        if !identity.authenticates(original) {
            return Err(store_error("test restore bytes do not authenticate"));
        }
        let connection = crucible_cas::content_store::fixture_sqlite_connection(
            self.retention.directory.join("objects.sqlite3"),
        )
        .map_err(|error| store_error(format!("open test RAM restoration database: {error}")))?;
        connection
            .execute(
                "UPDATE objects SET body = ?1 WHERE id = ?2",
                rusqlite::params![original, identity.encode()],
            )
            .map_err(|error| store_error(format!("restore selected test RAM page: {error}")))?;
        Ok(())
    }
}

#[derive(Clone)]
struct CatalogRetention {
    directory: PathBuf,
    // The fence is deliberately retained by every root lease. A digest or a
    // SQLite connection cannot prevent deletion of an attempt-local catalog.
    fence: Arc<File>,
    quota: Arc<dyn StorePhysicalQuotaGuard>,
    // Every root and its last deferred source retain the predecode credit.
    _root_credit: crucible_cas::owned_decode::ResourceLoanSlot,
}

impl RamRetention for CatalogRetention {
    fn retain_object(&self, _identity: ContentId) -> Result<(), RamStoreError> {
        self.quota.verify()?;
        self.fence
            .metadata()
            .map_err(|error| RamStoreError::Retention(error.to_string()))?;
        Ok(())
    }

    fn retain_root(&self, root: ContentId) -> Result<Arc<dyn RamRootLease>, RamStoreError> {
        self.retain_object(root)?;
        Ok(Arc::new(CatalogRootLease {
            root,
            _retention: self.clone(),
        }))
    }
}

struct CatalogRootLease {
    root: ContentId,
    _retention: CatalogRetention,
}

impl RamRootLease for CatalogRootLease {
    fn root(&self) -> ContentId {
        self.root
    }
}

#[cfg(test)]
// crucible-lint: allow panic-shortcut -- catalog fixture setup and explicit last-reader assertions intentionally panic on failure.
#[allow(clippy::expect_used)]
mod tests {
    use super::*;
    use crucible_ram::Topology;

    #[test]
    fn absent_physical_quota_authority_refuses_before_catalog_allocation() {
        let directory = tempfile::tempdir().expect("empty RAM namespace");
        let scenario = ContentHash::from_bytes(b"missing catalog authority");

        assert!(
            PagedRamCatalog::open(
                directory.path(),
                scenario,
                FaultResourceLimits::compiled_maximum(),
                None,
            )
            .is_err()
        );

        assert!(!directory.path().join(scenario.to_hex()).exists());
        assert_eq!(
            std::fs::read_dir(directory.path())
                .expect("empty namespace")
                .count(),
            0
        );
    }

    #[test]
    fn cached_catalog_retirement_retains_deferred_handles_and_open_readers() {
        use crucible_cas::content_store::{BlobHandle, ObjectKind};

        let root = tempfile::tempdir().expect("catalog namespace");
        let active = root
            .path()
            .join(ContentHash::from_bytes(b"reader loans").to_hex());
        let directory = active.join(DIRECTORY);
        let provider =
            crate::vm_lifecycle::checkpoint_store::test_support::test_ram_catalog_provider();
        let storage = provider.open_catalog(&directory).expect("fixture catalog");
        let bytes = b"retained SQLite reader";
        let identity = ContentId::for_bytes(ObjectKind::CampaignFact, 1, bytes);
        storage
            .backend
            .put_if_absent(identity, &BlobHandle::from_bytes(bytes))
            .expect("retained object");
        let handle = storage
            .backend
            .read(identity, None)
            .expect("deferred handle");
        let mut reader = handle.open().expect("opened reader");
        drop(storage);

        assert!(provider.begin_catalog_retirement(&directory).is_err());
        drop(handle);
        assert!(provider.begin_catalog_retirement(&directory).is_err());
        let mut actual = Vec::new();
        reader
            .read_to_end(&mut actual)
            .expect("authenticated retained read");
        assert_eq!(actual, bytes);
        drop(reader);

        let retirement = provider
            .begin_catalog_retirement(&directory)
            .expect("close catalog only after every deferred loan releases");
        assert!(provider.open_catalog(&directory).is_err());
        assert!(retirement.finish_deleted().is_err());
        std::fs::remove_dir_all(&active).expect("complete scenario deletion");
        retirement.finish_deleted().expect("authenticated deletion");
        assert!(provider.open_catalog(&directory).is_err());
        provider
            .begin_catalog_retirement(&directory)
            .expect("same pending receipt")
            .finish_deleted()
            .expect("idempotent authenticated completion");
    }

    #[test]
    fn root_metadata_credit_precedes_capture_and_survives_last_reader_clone() {
        use std::sync::atomic::Ordering;

        let directory = tempfile::tempdir().expect("RAM catalog");
        let (provider, loans) = super::test_support::tracked_ram_catalog_provider();
        let catalog = PagedRamCatalog::open(
            directory.path(),
            ContentHash::from_bytes(b"root credit lifetime"),
            FaultResourceLimits::compiled_maximum(),
            Some(&provider),
        )
        .expect("catalog");
        let topology = Topology::new(
            vec![
                crucible_ram::RegionDescriptor::new(
                    "main",
                    crucible_ram::RegionClass::MutableMain,
                    4096,
                )
                .expect("region"),
            ],
            crucible_ram::Limits::default(),
        )
        .expect("topology");
        let root = {
            let account = catalog
                .operation_account()
                .expect("original capture account");
            let retention = catalog.retention().expect("capture retention");

            catalog.store().capture(
                topology,
                Scope::Exact,
                &mut |_, _, output| {
                    assert_eq!(
                        loans.load(Ordering::SeqCst),
                        1,
                        "root memory must be admitted before the first capture callback"
                    );
                    output.fill(7);
                    Ok(())
                },
                retention.as_ref(),
                &account,
                &mut || Ok(()),
            )
        }
        .expect("capture");
        let reader = root.clone();

        drop(root);
        drop(catalog);
        assert_eq!(loans.load(Ordering::SeqCst), 1);
        drop(reader);
        assert_eq!(loans.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn canceled_update_preserves_typed_supervision_failure_and_committed_root() {
        let directory = tempfile::tempdir().expect("RAM test catalog");
        let catalog = PagedRamCatalog::open(
            directory.path(),
            ContentHash::from_bytes(b"canceled RAM update"),
            FaultResourceLimits::compiled_maximum(),
            Some(&crate::vm_lifecycle::checkpoint_store::test_support::test_ram_catalog_provider()),
        )
        .expect("open RAM catalog");
        let topology = Topology::new(
            vec![
                crucible_ram::RegionDescriptor::new(
                    "main",
                    crucible_ram::RegionClass::MutableMain,
                    8192,
                )
                .expect("region"),
            ],
            crucible_ram::Limits::default(),
        )
        .expect("topology");
        let parent = {
            let account = catalog
                .operation_account()
                .expect("original capture account");
            let retention = catalog.retention().expect("capture retention");

            catalog.store().capture(
                topology,
                Scope::Exact,
                &mut |_, _, output| {
                    output.fill(3);
                    Ok(())
                },
                retention.as_ref(),
                &account,
                &mut || Ok(()),
            )
        }
        .expect("committed image");

        let mut changes = [crucible_cas::ram::RamPageChange {
            region_id: String::from("main"),
            page_index: 1,
            bytes: vec![7; 4096],
        }]
        .into_iter();
        let mut boundaries = 0;
        let result = with_ram_boundary(
            &mut || {
                boundaries += 1;
                if boundaries == 2 {
                    Err("outer host cap exhausted")
                } else {
                    Ok(())
                }
            },
            |boundary| {
                catalog.store().update_with_reader(
                    &parent,
                    &mut || Ok(changes.next()),
                    catalog.retention().expect("admit successor root").as_ref(),
                    &catalog
                        .original()
                        .child()
                        .expect("same original update account"),
                    boundary,
                )
            },
            |_| "storage failure",
        );

        assert!(matches!(result, Err("outer host cap exhausted")));
        assert_eq!(
            catalog
                .store()
                .read_page(
                    &parent,
                    "main",
                    1,
                    &catalog
                        .original()
                        .child()
                        .expect("same original read account"),
                    &mut || Ok(())
                )
                .expect("preserved parent page")
                .bytes(),
            vec![3; 4096]
        );
        assert_eq!(
            catalog
                .verify(&parent, &mut || Ok(()))
                .expect("preserved complete image")
                .pages,
            2
        );
    }
}
