//! Closes genuine scoped repository reads around native whole-file preparation.
//!
//! The physical worker checks the selected domain before accepting pin effects.
//! Only the original SDK selection can authorize disclosure after actual backing
//! and its independent durable consumer pin have been prepared.

use super::{NativeSealedBacking, NativeSealedObjectLease};
use crate::host_cache::{NativeMetadataOwner, content::native_failure};
use std::{
    io,
    os::fd::{AsFd, BorrowedFd},
};
use terrane_format::{
    identity::{Digest, IdentityKind, TERRANE_V1},
    tree_format::ContentRef,
};
use terrane_sdk::{
    repository::{Error, PreparedFileRead},
    store::{Clock, Store, StoreErrorKind, StoreFailure},
};

/// Retains actual whole-file backing after one fresh scoped repository Read.
///
/// This value has no raw-file constructor. It retains the original sealed inode
/// and its independent durable physical consumer grant. A trusted transport must
/// retain this owner until every delegated worker and kernel backing reference
/// closes. Its descriptor may outlive lease revocation, just as an already
/// disclosed read result may outlive its original authorization check.
///
/// Ordinary grants carry no exposure context. Exposure file preparations also
/// retain the acknowledged exposure identity and generation. Each later
/// disclosure still needs fresh authorization and authenticated transport.
/// Dropping this value closes its descriptor; ordinary consumer policy remains
/// until release or expiry, while exposure obligations survive draining.
pub struct NativeFileBacking {
    // Close the real descriptor before dropping its physical grant handle.
    backing: NativeSealedBacking,
    lease: NativeSealedObjectLease,
    commit: Digest,
    root: Digest,
    size: u64,
    #[cfg(feature = "surface-fuse")]
    exposure: Option<crate::host_cache::NativeExposureLease>,
}

/// Preserves the original scoped Read across a native publication lookup.
pub(crate) enum NativeFilePreparation<'repository, S, C> {
    Ready(Box<PreparedNativeFile<'repository, S, C>>),
    Missing(Box<PreparedFileRead<'repository, S, C>>),
}

/// Keeps native backing and its original selection private until Read finishes.
pub(crate) struct PreparedNativeFile<'repository, S, C> {
    backing: NativeFileBacking,
    selection: PreparedFileRead<'repository, S, C>,
}

impl<S: Store, C: Clock> PreparedNativeFile<'_, S, C> {
    /// Closes the retained original selection before exposing its native grant.
    ///
    /// # Errors
    /// Refuses closing Read denial or an expired grant. Failed cleanup retains
    /// accepted physical obligations with their owner.
    pub(crate) async fn finish(
        self,
        owner: &NativeMetadataOwner,
    ) -> Result<NativeFileBacking, Error> {
        let lease = self.backing.lease.clone();
        let result = async {
            self.selection.finish().await?;
            lease
                .expires_at()
                .map_err(|error| native_failure(error, lease.identity()))?;
            Ok(self.backing)
        }
        .await;
        if result.is_err() {
            let _ = owner.release_sealed_object_lease(&lease).await;
        }
        result
    }
}

impl AsFd for NativeFileBacking {
    fn as_fd(&self) -> BorrowedFd<'_> {
        self.backing.as_fd()
    }
}

impl NativeFileBacking {
    /// Borrows acknowledged exposure protection when this is an exposure grant.
    ///
    /// Ordinary whole-file grants return `None`. This context is not a worker
    /// credential and does not replace transport authentication or fresh Read.
    #[cfg(feature = "surface-fuse")]
    pub fn exposure(&self) -> Option<&crate::host_cache::NativeExposureLease> {
        self.exposure.as_ref()
    }

    /// Returns the signed commit selected by the original repository operation.
    pub const fn commit(&self) -> Digest {
        self.commit
    }

    /// Returns the canonical root containing the original selected file.
    pub const fn root(&self) -> Digest {
        self.root
    }

    /// Returns the complete logical size checked against the actual inode.
    pub const fn size(&self) -> u64 {
        self.size
    }

    /// Borrows the physical grant for renewal and release by its original owner.
    ///
    /// Physical renewal does not refresh repository authorization. This value
    /// must remain alive through all delegated descriptor and kernel references,
    /// including when that grant has already been revoked or expired.
    pub fn lease(&self) -> &NativeSealedObjectLease {
        &self.lease
    }
}

impl NativeMetadataOwner {
    /// Prepares existing whole-file backing and closes its original scoped Read.
    ///
    /// The opaque selection comes from the actual repository guard. Its effective
    /// domain must equal this physical worker's configured domain before pin
    /// effects begin. Effective signed erasure policy must permit permanent
    /// sealed storage, independently of the repository's installed read driver.
    /// The exact typed content identity selects a genuine warm
    /// publication or an adopted recovery source after acknowledged Resume;
    /// metadata, chunk ranges and pathname claims cannot supply whole backing.
    /// The actual inode size must equal signed metadata. Only a fresh successful
    /// finish of the same selection permits returning the descriptor.
    ///
    /// This method neither fetches nor publishes missing content. Preparation
    /// failure drops any private descriptor and attempts durable lease release.
    /// A cancelled waiter or failed cleanup leaves accepted work with the native
    /// owner and its finite lease expiry, never an acknowledged physical release.
    ///
    /// # Errors
    /// Refuses another domain, absent or corrupt whole-file custody, an elapsed
    /// physical deadline, exhausted bounds, changed inode size, failed native
    /// durability or quota checks, and any closing repository authorization failure.
    pub async fn prepare_file_backing<S: Store, C: Clock>(
        &self,
        selection: PreparedFileRead<'_, S, C>,
        expires: u64,
    ) -> Result<NativeFileBacking, Error> {
        self.prepare_file_backing_inner(
            selection,
            expires,
            #[cfg(feature = "surface-fuse")]
            None,
        )
        .await
    }

    /// Prepares an original file with durable exposure protection before closing Read.
    ///
    /// # Errors
    /// Refuses foreign or draining exposure context and every ordinary file
    /// preparation, synchronization and closing authorization failure.
    #[cfg(feature = "surface-fuse")]
    pub(in crate::host_cache::owner) async fn prepare_file_backing_for_exposure<
        S: Store,
        C: Clock,
    >(
        &self,
        selection: PreparedFileRead<'_, S, C>,
        expires: u64,
        exposure: &crate::host_cache::NativeExposureLease,
    ) -> Result<NativeFileBacking, Error> {
        self.prepare_file_backing_inner(selection, expires, Some(exposure))
            .await
    }

    async fn prepare_file_backing_inner<S: Store, C: Clock>(
        &self,
        selection: PreparedFileRead<'_, S, C>,
        expires: u64,
        #[cfg(feature = "surface-fuse")] exposure: Option<&crate::host_cache::NativeExposureLease>,
    ) -> Result<NativeFileBacking, Error> {
        match self
            .try_prepare_selected_file(
                selection,
                expires,
                #[cfg(feature = "surface-fuse")]
                exposure,
            )
            .await?
        {
            NativeFilePreparation::Ready(prepared) => prepared.finish(self).await,
            NativeFilePreparation::Missing(selection) => {
                Err(StoreFailure::new(StoreErrorKind::Absent(file_identity(&selection)?)).into())
            }
        }
    }

    /// Prepares private backing, preserving the selected Read on a registry miss.
    ///
    /// `Missing` means only that no original whole-file publication or recovery
    /// source was registered. All failures involving a selected original source
    /// propagate, including ordinary filesystem NotFound. The returned value
    /// exposes no descriptor until the same selection successfully finishes.
    ///
    /// # Errors
    /// Refuses signed storage policy, foreign domains or exposure context, invalid
    /// deadlines, changed backing and native integrity, quota or custody failures.
    pub(crate) async fn try_prepare_selected_file<'repository, S: Store, C: Clock>(
        &self,
        selection: PreparedFileRead<'repository, S, C>,
        expires: u64,
        #[cfg(feature = "surface-fuse")] exposure: Option<&crate::host_cache::NativeExposureLease>,
    ) -> Result<NativeFilePreparation<'repository, S, C>, Error> {
        // A native caller can supply a preparation from a repository without
        // a read driver. Enforce sealed storage policy at this boundary too.
        selection.validate_storage_policy(&crate::host_cache::NativeSealedReadPolicy)?;
        let identity = file_identity(&selection)?;
        let domain = selection.storage_domain();
        self.admission_bounds
            .check(domain.len(), 0)
            .map_err(|error| native_failure(error, &identity))?;
        #[cfg(feature = "surface-fuse")]
        if let Some(exposure) = exposure {
            self.check_surface_file_deadline(exposure, expires)
                .await
                .map_err(|error| native_failure(error, &identity))?;
        }
        let lease = match self
            .pin_object(identity.clone(), Some(domain.to_owned()), expires)
            .await
        {
            Ok(lease) => lease,
            Err(error)
                if error.get_ref().is_some_and(|source| {
                    source.is::<super::super::publication::object_source::MissingWholeFile>()
                }) =>
            {
                return Ok(NativeFilePreparation::Missing(Box::new(selection)));
            }
            Err(error) => return Err(native_failure(error, &identity).into()),
        };

        let prepared = async {
            let backing = lease
                .backing()
                .map_err(|error| native_failure(error, &identity))?;
            let stat = rustix::fs::fstat(&backing)
                .map_err(|error| native_failure(error.into(), &identity))?;
            if u64::try_from(stat.st_size).ok() != Some(selection.size()) {
                return Err(native_failure(
                    io::Error::new(io::ErrorKind::InvalidData, "scoped file size changed"),
                    &identity,
                )
                .into());
            }
            let commit = selection.commit();
            let root = selection.root();
            let size = selection.size();
            #[cfg(feature = "surface-fuse")]
            if let Some(exposure) = exposure {
                self.protect_surface_object(exposure, &lease)
                    .await
                    .map_err(|error| native_failure(error, &identity))?;
            }
            Ok(NativeFilePreparation::Ready(Box::new(PreparedNativeFile {
                backing: NativeFileBacking {
                    backing,
                    lease: lease.clone(),
                    commit,
                    root,
                    size,
                    #[cfg(feature = "surface-fuse")]
                    exposure: exposure.cloned(),
                },
                selection,
            })))
        }
        .await;

        if prepared.is_err() {
            // Preserve the original refusal. Failed cleanup cannot make backing
            // public and cannot erase the owner's durable expiry obligation.
            let _ = self.release_sealed_object_lease(&lease).await;
        }
        prepared
    }
}

fn file_identity<S: Store, C: Clock>(
    selection: &PreparedFileRead<'_, S, C>,
) -> Result<terrane_format::identity::Identity, Error> {
    let (kind, digest) = match selection.content() {
        ContentRef::Inline(digest) => (IdentityKind::Chunk, digest),
        ContentRef::Manifest(digest) => (IdentityKind::Manifest, digest),
    };
    TERRANE_V1
        .from_digest(kind, &digest)
        .map_err(|_| StoreFailure::new(StoreErrorKind::Unsupported).into())
}
