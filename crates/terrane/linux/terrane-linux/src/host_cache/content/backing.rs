//! Closes original signed Reads around warm or missing-file native preparation.
//!
//! Only an original registry miss permits lower I/O. A selected publication's
//! filesystem, integrity or custody failure propagates without replacement.
//! Cold producer handoff is attempted even when the final authorization refuses;
//! no descriptor is returned before closing Read and actual cache handoff.

use super::NativeReadDriver;
#[cfg(feature = "surface-fuse")]
use crate::host_cache::{NativeExposureLease, NativeRootIndex};
use crate::host_cache::{NativeFileBacking, owner::NativeFilePreparation};
use std::time::Duration;
use terrane_sdk::{
    bucket::BucketBinding,
    host::cache::ReassemblyMode,
    repository::{Error, PreparedFileRead},
    store::{Clock, ContentStore, Store},
};

impl<S: ContentStore + BucketBinding> NativeReadDriver<S> {
    /// Prepares original warm backing or fetches a missing selected whole file.
    ///
    /// Signed storage requirements and the physical domain precede native pin
    /// effects. A warm result keeps its original inode without fetching content
    /// or resolving a manifest. Only genuine registry absence enters bounded
    /// cold publication. The same original selection closes Read after backing
    /// is prepared; cold cache handoff is attempted after a refused close too.
    ///
    /// The fetch budget is independent of individual worker open deadlines.
    /// A serving owner must retain this future through their expiry. Cancellation
    /// leaves accepted effects owned; dropping the future does not itself finish
    /// pending producer handoff or acknowledge physical resource closure.
    ///
    /// # Errors
    /// Refuses unsupported signed policy, invalid budgets, foreign domains,
    /// invalid native deadlines, failed warm custody, cold input or publication
    /// failures, closing Read denial and failed cache handoff.
    pub async fn prepare_file_backing<T: Store, C: Clock>(
        &self,
        selection: PreparedFileRead<'_, T, C>,
        mode: ReassemblyMode,
        budget: Duration,
        expires: u64,
    ) -> Result<NativeFileBacking, Error> {
        self.prepare_backing(
            selection,
            mode,
            budget,
            expires,
            #[cfg(feature = "surface-fuse")]
            None,
        )
        .await
    }

    /// Prepares a warm or missing file under its original durable exposure.
    ///
    /// The mapped signed root, exact path/content and live exposure deadline
    /// are checked before any fetch. Actual backing protection is attached to
    /// that exposure before the original selection finishes Read. The caller
    /// still authenticates the worker and serializes final descriptor disclosure
    /// with drain through the native owner. This grants no transport credential.
    ///
    /// # Errors
    /// Refuses mismatched selection, foreign or draining exposure, an outliving
    /// file deadline, and all ordinary warm/cold preparation and closing failures.
    #[cfg(feature = "surface-fuse")]
    pub async fn prepare_exposure_file_backing<T: Store, C: Clock>(
        &self,
        exposure: &NativeExposureLease,
        served: &NativeRootIndex,
        selection: PreparedFileRead<'_, T, C>,
        mode: ReassemblyMode,
        budget: Duration,
        expires: u64,
    ) -> Result<NativeFileBacking, Error> {
        self.prepare_backing(selection, mode, budget, expires, Some((exposure, served)))
            .await
    }

    async fn prepare_backing<T: Store, C: Clock>(
        &self,
        selection: PreparedFileRead<'_, T, C>,
        mode: ReassemblyMode,
        budget: Duration,
        expires: u64,
        #[cfg(feature = "surface-fuse")] exposure: Option<(&NativeExposureLease, &NativeRootIndex)>,
    ) -> Result<NativeFileBacking, Error> {
        self.validate_cold_selection(&selection, mode, budget)?;
        let owner = self.native().ready().owner();
        #[cfg(feature = "surface-fuse")]
        let prepared = if let Some((exposure, served)) = exposure {
            owner
                .try_prepare_exposure_selected_file(exposure, served, selection, expires)
                .await?
        } else {
            owner
                .try_prepare_selected_file(selection, expires, None)
                .await?
        };
        #[cfg(not(feature = "surface-fuse"))]
        let prepared = owner.try_prepare_selected_file(selection, expires).await?;
        let selection = match prepared {
            NativeFilePreparation::Ready(prepared) => return prepared.finish(owner).await,
            NativeFilePreparation::Missing(selection) => *selection,
        };

        let object = super::diagnostic::stage(
            "backing-cold-file",
            self.prepare_cold_file(&selection, mode, budget),
        )
        .await?;
        #[cfg(feature = "surface-fuse")]
        let grant = if let Some((exposure, served)) = exposure {
            super::diagnostic::stage(
                "backing-closing-read",
                owner.prepare_exposure_file_backing(exposure, served, selection, expires),
            )
            .await
        } else {
            super::diagnostic::stage(
                "backing-closing-read",
                owner.prepare_file_backing(selection, expires),
            )
            .await
        };
        #[cfg(not(feature = "surface-fuse"))]
        let grant = super::diagnostic::stage(
            "backing-closing-read",
            owner.prepare_file_backing(selection, expires),
        )
        .await;

        // Authorized disclosure and cache maintenance are separate outcomes.
        // Even a refused close leaves verified cache data worth retaining.
        let handoff = super::diagnostic::stage("backing-cache-handoff", object.into_cache()).await;
        let grant = grant?;
        handoff?;
        Ok(grant)
    }
}
