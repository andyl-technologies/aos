//! Prepays the real fresh transfer journal catalog and keeps credit outside its Arcs.
//!
//! The fixed original image has no prior transfer journal namespace. This path creates
//! it once under the existing physical catalog and original Writeback scope;
//! it does not reuse ordinary recovery allocations or mint a service account.
//! Ordinary transfer journal/recovery remains separate and unchanged.

use std::alloc::Layout;
use std::io;
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};

use crucible::owned_decode::{DecodeBudget, DecodeCustody, ResourceLoan};
use crucible_cas::content_store::{
    SqliteCatalogOperation, SqliteCatalogOperationKind, SqliteCatalogSupervisor, StoreError,
    StorePhysicalQuotaGuard,
};

use super::*;
use std::path::Path;

pub(super) enum OriginalWriterRelease {
    Held,
    Released,
}

/// Retains actual transfer journal controls and writer ownership until original close.
pub(crate) struct OriginalCampaignTransferJournalOwner {
    store: Option<DirectoryCampaignTransferJournal>,
    staged_root: Option<PathBuf>,
    staged_lock: Option<File>,
    credit: Option<ResourceLoan>,
    catalog: Arc<dyn SqliteCatalogSupervisor>,
    quota: Arc<dyn StorePhysicalQuotaGuard>,
    budget: DecodeBudget,
    custody: DecodeCustody,
    closed: bool,
}

impl OriginalCampaignTransferJournalOwner {
    pub(crate) fn prepare(
        catalog: Arc<dyn SqliteCatalogSupervisor>,
        quota: Arc<dyn StorePhysicalQuotaGuard>,
        budget: &DecodeBudget,
    ) -> Result<Self, OriginalJournalError> {
        Self::prepare_at(
            Path::new("/var/lib/crucible/measurement/catalog/transfers"),
            catalog,
            quota,
            budget,
        )
    }

    #[cfg(test)]
    pub(crate) fn fixture_at(
        root: &Path,
        catalog: Arc<dyn SqliteCatalogSupervisor>,
        quota: Arc<dyn StorePhysicalQuotaGuard>,
        budget: &DecodeBudget,
    ) -> Result<Self, OriginalJournalError> {
        Self::prepare_at(root, catalog, quota, budget)
    }

    fn prepare_at(
        root: &Path,
        catalog: Arc<dyn SqliteCatalogSupervisor>,
        quota: Arc<dyn StorePhysicalQuotaGuard>,
        budget: &DecodeBudget,
    ) -> Result<Self, OriginalJournalError> {
        budget
            .verify_live()
            .map_err(OriginalJournalError::original)?;
        let mut owner = Self {
            store: None,
            staged_root: None,
            staged_lock: None,
            credit: None,
            catalog,
            quota,
            budget: budget.clone(),
            custody: budget.custody(),
            closed: false,
        };
        // Root, lock path and one retained kernel diagnostic name overlap.
        let bytes = shared_bytes::<DirectoryCampaignTransferJournalInner>()?
            .checked_add(3 * root.as_os_str().len() as u64 + 2 * "/writer.lock".len() as u64)
            .ok_or_else(OriginalJournalError::geometry)?;
        // Persistent writer FD plus actual directory-sync temporary, each
        // admitted before opening either; no namespace walk/recovery is used.
        owner.credit = Some(
            owner
                .quota
                .reserve_resources(2, bytes)
                .map_err(OriginalJournalError::store)?,
        );
        owner.staged_root = Some(exact_path(root, "")?);
        let work = owner.initialize();
        let after = owner.budget.verify_live();
        match (work, after) {
            (Ok(()), Ok(())) => Ok(owner),
            (Err(mut error), after) => {
                if error.original_after.is_none() {
                    error.original_after = after.err();
                }
                Err(error)
            }
            (Ok(()), Err(source)) => Err(OriginalJournalError::original(source)),
        }
    }

    fn initialize(&mut self) -> Result<(), OriginalJournalError> {
        let operation = self
            .catalog
            .begin(SqliteCatalogOperationKind::Write)
            .map_err(OriginalJournalError::store)?;
        let root = self
            .staged_root
            .as_ref()
            .ok_or_else(OriginalJournalError::geometry)?;
        operation.check().map_err(OriginalJournalError::store)?;
        // create_dir, rather than create_dir_all/open-existing, makes a prior
        // namespace a refusal and leaves recovery on the ordinary API.
        self.work(operation.as_ref(), || fs::create_dir(root))?;
        self.work(operation.as_ref(), || {
            fs::set_permissions(root, fs::Permissions::from_mode(0o700))
        })?;
        for name in ["/records", "/staging"] {
            let child = exact_path(root, name)?;
            self.work(operation.as_ref(), || fs::create_dir(&child))?;
            self.work(operation.as_ref(), || {
                fs::set_permissions(&child, fs::Permissions::from_mode(0o700))
            })?;
            self.work(operation.as_ref(), || {
                File::open(&child).and_then(|file| file.sync_all())
            })?;
        }
        let lock_path = exact_path(root, "/writer.lock")?;
        self.pre_effect(operation.as_ref())?;
        let opened = OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&lock_path);
        Self::publish_writer(
            &mut self.staged_lock,
            &self.budget,
            operation.as_ref(),
            opened,
        )?;
        let lock = self
            .staged_lock
            .as_ref()
            .ok_or_else(OriginalJournalError::geometry)?;
        self.work(operation.as_ref(), || {
            flock(lock, FlockOperation::NonBlockingLockExclusive).map_err(io::Error::from)
        })?;
        self.work(operation.as_ref(), || lock.sync_all())?;
        self.work(operation.as_ref(), || {
            File::open(root).and_then(|file| file.sync_all())
        })?;
        let parent = root.parent().ok_or_else(OriginalJournalError::geometry)?;
        self.work(operation.as_ref(), || {
            File::open(parent).and_then(|file| file.sync_all())
        })?;
        let inner = DirectoryCampaignTransferJournalInner {
            root: self
                .staged_root
                .take()
                .ok_or_else(OriginalJournalError::geometry)?,
            writer_lock: self
                .staged_lock
                .take()
                .ok_or_else(OriginalJournalError::geometry)?,
            lifecycle: RwLock::new(()),
            original_release: Some(OriginalWriterRelease::Held),
        };
        self.store = Some(DirectoryCampaignTransferJournal {
            inner: Arc::new(inner),
        });
        self.budget
            .verify_live()
            .map_err(OriginalJournalError::original)?;
        operation.complete().map_err(OriginalJournalError::store)
    }

    fn publish_writer(
        staged_lock: &mut Option<File>,
        budget: &DecodeBudget,
        operation: &dyn SqliteCatalogOperation,
        opened: io::Result<File>,
    ) -> Result<(), OriginalJournalError> {
        match opened {
            Ok(file) => *staged_lock = Some(file),
            Err(source) => return Self::reconcile_kernel(budget, operation, Err(source)),
        }
        // The actual successful descriptor is accessible before either
        // postcheck can refuse. Drop retains this pin and its external credit.
        Self::reconcile_kernel(budget, operation, Ok(()))
    }

    fn pre_effect(
        &self,
        operation: &dyn SqliteCatalogOperation,
    ) -> Result<(), OriginalJournalError> {
        self.budget
            .verify_live()
            .map_err(OriginalJournalError::original)?;
        operation.check().map_err(OriginalJournalError::store)
    }

    fn work<T>(
        &self,
        operation: &dyn SqliteCatalogOperation,
        work: impl FnOnce() -> io::Result<T>,
    ) -> Result<T, OriginalJournalError> {
        self.pre_effect(operation)?;
        self.kernel(operation, work())
    }

    fn kernel<T>(
        &self,
        operation: &dyn SqliteCatalogOperation,
        result: io::Result<T>,
    ) -> Result<T, OriginalJournalError> {
        Self::reconcile_kernel(&self.budget, operation, result)
    }

    fn reconcile_kernel<T>(
        budget: &DecodeBudget,
        operation: &dyn SqliteCatalogOperation,
        result: io::Result<T>,
    ) -> Result<T, OriginalJournalError> {
        // Keep the kernel cause before checking either retained scope. These
        // checks are independent: a sticky catalog failure cannot stand in
        // for the later original observation.
        let operation_after = operation.check();
        let original_after = budget.verify_live();
        match (result, operation_after, original_after) {
            (Err(source), operation_after, original_after) => Err(OriginalJournalError {
                source: OriginalJournalCause::Kernel {
                    source,
                    operation_after: operation_after.err(),
                },
                original_after: original_after.err(),
            }),
            (Ok(_), Err(source), original_after) => Err(OriginalJournalError {
                source: OriginalJournalCause::Store(source),
                original_after: original_after.err(),
            }),
            (Ok(_), Ok(()), Err(source)) => Err(OriginalJournalError::original(source)),
            (Ok(value), Ok(()), Ok(())) => Ok(value),
        }
    }

    pub(crate) fn share(&self) -> Result<DirectoryCampaignTransferJournal, OriginalJournalError> {
        self.budget
            .verify_live()
            .map_err(OriginalJournalError::original)?;
        self.store
            .as_ref()
            .cloned()
            .ok_or_else(OriginalJournalError::geometry)
    }

    pub(crate) fn try_close(&mut self) -> Result<(), OriginalJournalError> {
        if self.closed {
            return Ok(());
        }
        self.budget
            .check()
            .map_err(OriginalJournalError::original)?;
        self.budget
            .verify_live()
            .map_err(OriginalJournalError::original)?;
        let store = self
            .store
            .as_mut()
            .ok_or_else(OriginalJournalError::geometry)?;
        let inner = Arc::get_mut(&mut store.inner).ok_or_else(OriginalJournalError::aliases)?;
        let operation = self
            .catalog
            .begin(SqliteCatalogOperationKind::Write)
            .map_err(OriginalJournalError::store)?;
        operation.check().map_err(OriginalJournalError::store)?;
        let unlocked = flock(&inner.writer_lock, FlockOperation::Unlock).map_err(io::Error::from);
        if unlocked.is_ok() {
            inner.original_release = Some(OriginalWriterRelease::Released);
        }
        self.kernel(operation.as_ref(), unlocked)?;
        operation.complete().map_err(OriginalJournalError::store)?;
        drop(self.store.take());
        self.budget
            .verify_live()
            .map_err(OriginalJournalError::original)?;
        drop(self.credit.take());
        self.closed = true;
        Ok(())
    }
}

impl Drop for OriginalCampaignTransferJournalOwner {
    fn drop(&mut self) {
        if !self.closed {
            std::mem::forget(self.store.take());
            std::mem::forget(self.staged_lock.take());
            std::mem::forget(self.staged_root.take());
            std::mem::forget(self.credit.take());
            std::mem::forget(self.budget.clone());
            std::mem::forget(self.custody.clone());
        }
    }
}

fn exact_path(base: &Path, suffix: &str) -> Result<PathBuf, OriginalJournalError> {
    let length = base
        .as_os_str()
        .len()
        .checked_add(suffix.len())
        .ok_or_else(OriginalJournalError::geometry)?;
    let mut path = PathBuf::new();
    path.try_reserve_exact(length)
        .map_err(|source| OriginalJournalError {
            source: OriginalJournalCause::Allocation(source),
            original_after: None,
        })?;
    path.push(base);
    if !suffix.is_empty() {
        path.push(
            suffix
                .strip_prefix('/')
                .ok_or_else(OriginalJournalError::geometry)?,
        );
    }
    Ok(path)
}

fn shared_bytes<T>() -> Result<u64, OriginalJournalError> {
    let (layout, _) = Layout::new::<(usize, usize)>()
        .extend(Layout::new::<T>())
        .map_err(|_| OriginalJournalError::geometry())?;
    u64::try_from(layout.pad_to_align().size()).map_err(|_| OriginalJournalError::geometry())
}

#[derive(Debug, thiserror::Error)]
#[error("original transfer journal refused: {source}; original: {original_after:?}")]
/// Preserves the actual support-catalog cause and its independent original cut.
pub struct OriginalJournalError {
    #[source]
    source: OriginalJournalCause,
    original_after: Option<crucible::owned_decode::DecodeAdmissionError>,
}

#[derive(Debug, thiserror::Error)]
enum OriginalJournalCause {
    #[error("original admission refused: {0}")]
    Original(#[source] crucible::owned_decode::DecodeAdmissionError),
    #[error("catalog operation refused: {0}")]
    Store(#[source] StoreError),
    #[error("actual path allocation refused: {0}")]
    Allocation(#[source] std::collections::TryReserveError),
    #[error("actual kernel operation refused: {source}; operation: {operation_after:?}")]
    Kernel {
        #[source]
        source: io::Error,
        operation_after: Option<StoreError>,
    },
    #[error("original transfer journal control geometry or state is invalid")]
    Geometry,
    #[error("actual transfer journal strong or weak aliases remain")]
    Aliases,
}

impl OriginalJournalError {
    fn original(source: crucible::owned_decode::DecodeAdmissionError) -> Self {
        Self {
            source: OriginalJournalCause::Original(source),
            original_after: None,
        }
    }
    fn store(source: StoreError) -> Self {
        Self {
            source: OriginalJournalCause::Store(source),
            original_after: None,
        }
    }
    fn geometry() -> Self {
        Self {
            source: OriginalJournalCause::Geometry,
            original_after: None,
        }
    }
    fn aliases() -> Self {
        Self {
            source: OriginalJournalCause::Aliases,
            original_after: None,
        }
    }
}

#[cfg(test)]
mod tests;
