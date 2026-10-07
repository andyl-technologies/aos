//! Cold RAM cache promotion under one explicit finite component authority.

use std::sync::atomic::AtomicBool;

use crucible_ram::{Limits, RegionClass, RegionDescriptor, Scope, Topology};

use super::super::composition::ReadThroughStore;
use super::*;
use crate::owned_decode::DecodeBudget;
use crate::ram::{RamRetention, RamRootLease, RamStore, RamStoreError, RamStoreLimits};

struct Quota {
    resources: crate::content_store::test_resources::FixtureResourceBudget,
    closed: AtomicBool,
}

#[derive(Debug, thiserror::Error)]
enum CacheTestError {
    #[error(transparent)]
    Store(#[from] StoreError),
    #[error(transparent)]
    Ram(#[from] RamStoreError),
    #[error(transparent)]
    Logical(#[from] crucible_ram::RamError),
    #[error(transparent)]
    Decode(#[from] crate::owned_decode::DecodeAdmissionError),
    #[error(transparent)]
    Io(#[from] std::io::Error),
}

impl StorePhysicalQuotaGuard for Quota {
    fn decoded_metadata_limit(&self) -> Result<u64, StoreError> {
        Ok(64 * 1024 * 1024)
    }

    fn verify(&self) -> Result<(), StoreError> {
        if self.closed.load(Ordering::SeqCst) {
            return Err(StoreError::Unauthorized);
        }
        Ok(())
    }

    fn reserve_resources(
        &self,
        descriptors: u64,
        bytes: u64,
    ) -> Result<Arc<dyn Send + Sync>, StoreError> {
        self.verify()?;
        self.resources.reserve(descriptors, bytes)
    }
}

struct Lease(ContentId);

impl RamRootLease for Lease {
    fn root(&self) -> ContentId {
        self.0
    }
}

struct Retention;

impl RamRetention for Retention {
    fn retain_object(&self, _: ContentId) -> Result<(), RamStoreError> {
        Ok(())
    }

    fn retain_root(&self, root: ContentId) -> Result<Arc<dyn RamRootLease>, RamStoreError> {
        Ok(Arc::new(Lease(root)))
    }
}

#[test]
fn cold_ram_directory_cache_without_tls_retains_original_bank_until_last_reader()
-> Result<(), CacheTestError> {
    let directory = tempfile::tempdir()?;
    let quota = Arc::new(Quota {
        resources: crate::content_store::test_resources::FixtureResourceBudget::new(
            128,
            64 * 1024 * 1024,
        ),
        closed: AtomicBool::new(false),
    });
    let source =
        DirectoryBlobBackend::new_with_physical_quota("source", directory.path(), quota.clone())?;
    // The supported RAM cache is a durable streaming directory leaf. Generic
    // Memory cache final-copy lifetimes are exercised separately; its bounded
    // whole-object put contract does not advertise streaming RAM eligibility.
    let (cache, cache_admin) = DirectoryBlobBackend::new_with_physical_quota_and_admin(
        "cache",
        directory.path().join("cache"),
        quota.clone(),
    )?;
    let composed = Arc::new(ReadThroughStore::new("read-through", cache.clone(), source));
    let ram = RamStore::new(
        composed,
        DurabilityRequirement::new(1, false)?,
        RamStoreLimits::default(),
    )?;
    let budget = DecodeBudget::for_store(quota.clone())?;
    let scope = budget.enter();
    let captured = ram.capture(
        Topology::new(
            vec![RegionDescriptor::new(
                "main",
                RegionClass::MutableMain,
                4096,
            )?],
            Limits::default(),
        )?,
        Scope::Exact,
        &mut |_, _, bytes| {
            bytes.fill(11);
            Ok(())
        },
        &Retention,
        &mut || Ok(()),
    )?;
    let root =
        ram.open_with_metadata_resources(Arc::new(Lease(captured.object_id())), &mut || Ok(()))?;
    drop(captured);
    drop(scope);
    drop(budget);
    assert!(crate::owned_decode::current_budget().is_none());

    // Force a genuine cold promotion after the caller's account has closed.
    // The read path projects the exact same quota guard before copying bytes.
    {
        let mut fence = cache_admin.acquire_inventory_fence()?;
        let mut ids = Vec::new();
        fence.visit_inventory(&mut |record| {
            ids.push(record.id());
            Ok(())
        })?;
        for id in ids {
            fence.delete_candidate(id)?;
        }
    }
    let empty = cache_admin
        .acquire_inventory_fence()?
        .visit_inventory(&mut |_| Ok(()))?;
    assert_eq!(empty.objects(), 0);
    let page = ram.read_page(&root, "main", 0, &mut || Ok(()))?;
    assert_eq!(page, vec![11; 4096]);
    let mut fence = cache_admin.acquire_inventory_fence()?;
    let mut page_id = None;
    fence.visit_inventory(&mut |record| {
        if record.id().kind() == ObjectKind::RamExtent {
            page_id = Some(record.id());
        }
        Ok(())
    })?;
    drop(fence);
    let id = page_id.ok_or(StoreError::InvalidId)?;
    let handle = cache.read(id, None)?;
    let mut reader = handle.open()?;
    let mut fence = cache_admin.acquire_inventory_fence()?;
    fence.delete_candidate(id)?;
    drop(fence);
    quota.closed.store(true, Ordering::SeqCst);
    assert!(matches!(
        cache.read(id, None),
        Err(StoreError::Unauthorized)
    ));
    assert!(matches!(handle.open(), Err(StoreError::Unauthorized)));
    drop(handle);
    drop(root);
    drop(ram);
    drop(cache);
    drop(cache_admin);
    assert!(quota.resources.usage()?.1 > 4096);
    let mut observed = [0; 4179];
    let refusal = reader
        .read(&mut observed)
        .err()
        .ok_or(StoreError::InvalidId)?;
    assert!(matches!(
        refusal
            .get_ref()
            .and_then(|source| source.downcast_ref::<StoreError>()),
        Some(StoreError::Unauthorized)
    ));
    drop(refusal);
    drop(reader);
    assert_eq!(quota.resources.usage()?, (0, 0));
    Ok(())
}
