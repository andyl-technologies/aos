//! Prebirth promotion geometry and deferred construction under the actual payer.
//!
//! The plan owns existing inputs, but no promotion vector or new baked map. One
//! checked query joins the existing semantic-worker debit before its builder is
//! called. It measures visible owned payloads, not private thread/stack controls.

use super::*;
use crucible_engine::owned_decode::DecodeBudget;
use crucible_host_resources::host_services::process_birth::AuthenticatedNativePoolPurpose;
use std::ffi::OsString;
use std::fmt::Write;
use std::marker::PhantomData;

#[derive(Clone, Copy)]
pub(super) enum PromotionControlPayer<'a> {
    Main(&'a AuthenticatedNativePoolPurpose),
    Decode(&'a DecodeBudget),
}

impl PromotionControlPayer<'_> {
    pub(super) fn catalog_payment(self) -> crate::qemu_baked_genesis::catalog::CatalogPayment {
        match self {
            Self::Main(purpose) => crate::qemu_baked_genesis::catalog::CatalogPayment::Main {
                _purpose: purpose.clone(),
            },
            Self::Decode(original) => crate::qemu_baked_genesis::catalog::CatalogPayment::Decode {
                _custody: original.custody(),
            },
        }
    }
}

pub(super) struct UnbuiltPromotions<P, T, B> {
    count: usize,
    catalog_bytes: u64,
    build: B,
    _output: PhantomData<fn() -> (P, T)>,
}

pub(super) struct AdmittedPromotions<P, T, B>(UnbuiltPromotions<P, T, B>);

impl<P, T, B> UnbuiltPromotions<P, T, B> {
    pub(super) fn new(count: usize, catalog_bytes: u64, build: B) -> Self {
        Self {
            count,
            catalog_bytes,
            build,
            _output: PhantomData,
        }
    }

    pub(super) fn control_bytes(&self, root: &Path) -> Result<u64, PackagedQemuExecutorError> {
        let geometry = || -> Option<u64> {
            let worker = crate::executor_pool::promotion_control_bytes::<
                DirectoryAssignmentLedger,
                PackagedAttemptAdmission,
                P,
            >(self.count)?;
            let root_bytes = path_bytes(root, ROOT_NAME.len())?;
            let mut bytes = self
                .catalog_bytes
                .checked_add(worker)?
                .checked_add(u64::try_from(root_bytes).ok()?)?;
            let mut longest_name = 0usize;
            for slot in 0..self.count {
                let name = worker_name_bytes(slot)?;
                let path = root_bytes.checked_add(1)?.checked_add(name)?;
                bytes = bytes.checked_add(u64::try_from(path).ok()?)?;
                longest_name = longest_name.max(name);
            }
            // One name buffer is temporary during sequential construction.
            bytes
                .checked_add(u64::try_from(longest_name).ok()?)?
                .checked_add(u64::try_from(std::mem::size_of::<Self>()).ok()?)?
                .checked_add(u64::try_from(std::mem::size_of::<T>()).ok()?)
        };
        geometry().ok_or_else(|| {
            crate::executor_pool::LocalExecutorPoolConfigError::WorkerControlGeometry.into()
        })
    }

    /// The callback cannot run until this exact query has reached admission.
    pub(super) fn admit<A>(
        self,
        root: &Path,
        reserve: impl FnOnce(u64, usize) -> Result<A, PackagedQemuExecutorError>,
    ) -> Result<(A, AdmittedPromotions<P, T, B>), PackagedQemuExecutorError> {
        let bytes = self.control_bytes(root)?;
        let admitted = reserve(bytes, self.count)?;
        Ok((admitted, AdmittedPromotions(self)))
    }
}

impl<P, T, B> AdmittedPromotions<P, T, B> {
    pub(super) fn build<H>(
        self,
        store: &CampaignExecutorStore,
        checkpoints: &Arc<ExactCheckpointStore>,
        shared: &SharedQemuAttemptHostResourceFactory<H>,
        root: &Path,
        payer: PromotionControlPayer<'_>,
    ) -> Result<(Vec<P>, T), PackagedQemuExecutorError>
    where
        B: FnOnce(
            &CampaignExecutorStore,
            &Arc<ExactCheckpointStore>,
            &SharedQemuAttemptHostResourceFactory<H>,
            &Path,
            usize,
            PromotionControlPayer<'_>,
        ) -> Result<(Vec<P>, T), PackagedQemuExecutorError>,
    {
        let plan = self.0;
        let (workers, output) = (plan.build)(store, checkpoints, shared, root, plan.count, payer)?;
        if workers.len() != plan.count
            || (std::mem::size_of::<P>() != 0 && workers.capacity() != plan.count)
        {
            return Err(
                crate::executor_pool::LocalExecutorPoolConfigError::WorkerControlGeometry.into(),
            );
        }
        Ok((workers, output))
    }
}

const ROOT_NAME: &str = "campaign-checkpoint-promotions";

pub(super) fn worker_root(base: &Path) -> Result<PathBuf, PackagedQemuExecutorError> {
    let bytes = path_bytes(base, ROOT_NAME.len())
        .ok_or(crate::executor_pool::LocalExecutorPoolConfigError::WorkerControlGeometry)?;
    let mut root = OsString::with_capacity(bytes);
    root.push(base);
    if !base.as_os_str().is_empty() && base.as_os_str().as_encoded_bytes().last() != Some(&b'/') {
        root.push("/");
    }
    root.push(ROOT_NAME);
    Ok(PathBuf::from(root))
}

fn worker_name_bytes(slot: usize) -> Option<usize> {
    let mut value = slot;
    let mut digits = 1usize;
    while value >= 10 {
        value /= 10;
        digits = digits.checked_add(1)?;
    }
    7usize.checked_add(digits.max(3))
}

fn path_bytes(root: &Path, name: usize) -> Option<usize> {
    let bytes = root.as_os_str().as_encoded_bytes();
    let separator = usize::from(!bytes.is_empty() && bytes.last() != Some(&b'/'));
    bytes.len().checked_add(separator)?.checked_add(name)
}

/// Constructs the exact queried worker path without growth or another root clone.
pub(super) fn worker_path(root: &Path, slot: usize) -> Result<PathBuf, PackagedQemuExecutorError> {
    let geometry = || crate::executor_pool::LocalExecutorPoolConfigError::WorkerControlGeometry;
    let name_bytes = worker_name_bytes(slot).ok_or_else(geometry)?;
    let mut name = String::with_capacity(name_bytes);
    write!(&mut name, "worker-{slot:03}").map_err(|_| geometry())?;
    let bytes = path_bytes(root, name_bytes).ok_or_else(geometry)?;
    let mut path = OsString::with_capacity(bytes);
    path.push(root);
    if !root.as_os_str().is_empty() && root.as_os_str().as_encoded_bytes().last() != Some(&b'/') {
        path.push("/");
    }
    path.push(name);
    Ok(PathBuf::from(path))
}

#[cfg(test)]
mod tests;
