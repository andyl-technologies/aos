//! Closes an original complete-root Read around physical index preparation.

use super::{NativeExposureLease, NativeMetadataOwner, NativeSurfaceIndex};
use crate::{
    host_cache::{NativeFileBacking, content::native_failure},
    structural_index::{Index, IndexKey, Kind, MappedIndex},
};
use std::{
    fs::File,
    io,
    os::fd::{AsFd, BorrowedFd},
};
use terrane_format::identity::Digest;
use terrane_format::identity::{IdentityKind, TERRANE_V1};
use terrane_sdk::{
    repository::{Error, PreparedFileRead, PreparedRootRead},
    store::{Clock, Store, StoreErrorKind, StoreFailure},
};

/// Retains a checked original-inode mapping after one complete root Read.
///
/// This value retains its physical admission receipt, preventing warm cache
/// retirement while its mapping lives. It exposes borrowed metadata, not a raw
/// descriptor or an exposure lease. The mapping is dropped before its receipt.
/// Already disclosed metadata may outlive the original Read; a worker's startup,
/// later file disclosures and durable exposure protection require their own
/// current authorization and custody.
pub struct NativeRootIndex {
    mapping: MappedIndex,
    pub(super) admission: NativeSurfaceIndex,
    pub(super) commit: Digest,
    pub(super) domain: String,
}

/// Retains original sealed index backing after a fresh complete-root Read.
///
/// This value has no raw-file constructor. Its descriptor is the original
/// read-only admitted inode, protected by an acknowledged durable exposure.
/// A trusted worker transport must bind the exposure generation and peer before
/// disclosure. The grant supplies neither a worker credential nor enduring Read.
/// Dropping it closes its descriptor without releasing durable obligations.
pub struct NativeExposureRootBacking {
    backing: File,
    exposure: NativeExposureLease,
}

impl AsFd for NativeExposureRootBacking {
    fn as_fd(&self) -> BorrowedFd<'_> {
        self.backing.as_fd()
    }
}

impl NativeExposureRootBacking {
    /// Borrows the original acknowledged exposure context for this index grant.
    pub const fn exposure(&self) -> &NativeExposureLease {
        &self.exposure
    }
}

impl NativeRootIndex {
    /// Returns the exact signed commit selected by the complete root Read.
    pub const fn commit(&self) -> Digest {
        self.commit
    }

    /// Returns the canonical root and format version actually compiled.
    pub fn key(&self) -> IndexKey {
        self.admission.key()
    }

    /// Borrows checked mapped metadata without storage access or allocation.
    pub fn index(&self) -> Index<'_> {
        self.mapping.index()
    }

    /// Rechecks the retained original inode without granting serving authority.
    ///
    /// # Errors
    /// Refuses changed inode identity, ownership, mode, project or permanent seal.
    pub fn check_native_backing(&self) -> io::Result<()> {
        self.admission.check_native_backing()
    }
}

impl NativeMetadataOwner {
    /// Prepares original index backing and closes a fresh complete-root Read.
    ///
    /// The actual SDK selection must match the exposure and mapped commit,
    /// canonical root and physical domain. A live physical queue check and
    /// original-incarnation descriptor duplication precede the same selection's
    /// closing authorization. No content bodies are fetched or paths reopened.
    /// Failure drops private descriptors while retaining durable index custody.
    ///
    /// The caller still authenticates its worker transport, checks live exposure
    /// context and bounds in-flight delegation. This is an authorized read result,
    /// not permission to start a connection after draining. An
    /// already disclosed descriptor can remain readable after draining; it is
    /// never a kernel-closure acknowledgment.
    ///
    /// # Errors
    /// Refuses mismatched selection, foreign or draining exposure context,
    /// incompatible chunk geometry, changed native backing, queue exhaustion
    /// and any closing complete-root authorization failure.
    pub async fn prepare_exposure_root_backing<S: Store, C: Clock>(
        &self,
        exposure: &NativeExposureLease,
        served: &NativeRootIndex,
        selection: PreparedRootRead<'_, S, C>,
    ) -> Result<NativeExposureRootBacking, Error> {
        let metadata = selection.metadata();
        if exposure.commit() != served.commit
            || exposure.key() != served.key()
            || metadata.commit() != served.commit
            || metadata.root() != served.key().root()
            || selection.storage_domain() != served.domain
        {
            return Err(Error::Denied);
        }
        if metadata.minimum_chunk_size() != self.chunk_profile.minimum() as u64 {
            return Err(StoreFailure::new(StoreErrorKind::Unsupported).into());
        }
        let identity = root_identity(&selection)?;
        self.check_surface_exposure(exposure)
            .await
            .map_err(|error| native_failure(error, &identity))?;
        let backing = exposure
            .original_root_file(&served.admission)
            .map_err(|error| native_failure(error, &identity))?;
        selection.finish().await?;
        served
            .check_native_backing()
            .map_err(|error| native_failure(error, &identity))?;
        Ok(NativeExposureRootBacking {
            backing,
            exposure: exposure.clone(),
        })
    }

    /// Admits an original authorized root and closes its Read before returning.
    ///
    /// The physical worker checks the exact selected storage domain before any
    /// durable state or copy effects. Only a fresh successful finish of the same
    /// SDK preparation permits returning the admission receipt. This fetches no
    /// content bodies and grants no descriptor, exposure lease or enduring Read.
    ///
    /// Failure or cancellation can leave a funded immutable cache entry. Its
    /// original physical owner retains that entry for maintenance or recovery;
    /// a failed closing authorization never acknowledges native release.
    ///
    /// # Errors
    /// Refuses disabled or oversized admission, incompatible chunk geometry,
    /// another physical domain,
    /// absent writable native custody, canonical or kernel backing failures,
    /// capacity, and any closing full-root authorization or trust failure.
    pub async fn prepare_surface_index<S: Store, C: Clock>(
        &self,
        selection: PreparedRootRead<'_, S, C>,
    ) -> Result<NativeSurfaceIndex, Error> {
        let identity = root_identity(&selection)?;
        let index = self.admit_prepared_root(&selection).await?;
        selection.finish().await?;
        index
            .check_native_backing()
            .map_err(|error| native_failure(error, &identity))?;
        Ok(index)
    }

    /// Maps a prepared signed root from its original sealed native cache inode.
    ///
    /// The mapping is created privately from the admitted descriptor, never by
    /// reopening a pathname. Canonical compilation and native admission precede
    /// mapping; the original complete root Read finishes after mapping and before
    /// this value is returned. Failure or cancellation discloses no mapping and
    /// leaves funded cache custody with the physical owner.
    ///
    /// # Errors
    /// Returns the same admission and authorization refusals as
    /// [`Self::prepare_surface_index`], plus descriptor, mapping, measurement,
    /// size or checked-index errors. This grants no durable exposure lease.
    pub async fn prepare_surface_mapping<S: Store, C: Clock>(
        &self,
        selection: PreparedRootRead<'_, S, C>,
    ) -> Result<NativeRootIndex, Error> {
        let identity = root_identity(&selection)?;
        let commit = selection.metadata().commit();
        let admission = self.admit_prepared_root(&selection).await?;
        let mapping = map_original(&admission).map_err(|error| native_failure(error, &identity))?;
        let domain = selection.storage_domain().to_owned();
        selection.finish().await?;
        admission
            .check_native_backing()
            .map_err(|error| native_failure(error, &identity))?;
        Ok(NativeRootIndex {
            mapping,
            admission,
            commit,
            domain,
        })
    }

    /// Prepares backing only for a freshly authorized file in this served root.
    ///
    /// The exact signed commit, canonical root and effective physical domain must
    /// match the original mapped selection. Its checked path must name the same
    /// typed content and logical size. These comparisons precede physical pin
    /// effects. The ordinary native file bridge then checks original backing and
    /// finishes this file's fresh scoped Read before returning its descriptor.
    ///
    /// This supplies object-scope checking, not an exposure ID, durable exposure
    /// lease or local transport credential. The caller must separately verify
    /// those and retain the returned backing through all delegated references.
    ///
    /// # Errors
    /// Denies a selection outside the mapped root, native backing failures and
    /// any initial or closing authorization refusal. Existing whole-file backing
    /// must be available; this method does not fetch missing content.
    pub async fn prepare_surface_file_backing<S: Store, C: Clock>(
        &self,
        served: &NativeRootIndex,
        selection: PreparedFileRead<'_, S, C>,
        expires: u64,
    ) -> Result<NativeFileBacking, Error> {
        check_file_scope(served, &selection)?;
        self.prepare_file_backing(selection, expires).await
    }

    /// Prepares a freshly authorized file under this exact durable exposure.
    ///
    /// Original commit, canonical index, domain, path and typed object must match
    /// before pin effects. The physical owner checks live exposure context,
    /// prepares the real whole-file grant and durably attaches its complete
    /// protected hashes before finishing the original file Read. Draining or
    /// expiry never removes these attached physical obligations.
    ///
    /// This grants no worker credential or transport authentication and does not
    /// fetch missing data. The requested file deadline must fit the exposure's
    /// live deadline. Failure after attachment may retain conservative pins.
    ///
    /// # Errors
    /// Refuses mismatched, expired, draining or foreign exposure context, absent
    /// whole-file backing, native capacity or IO failures and closing Read denial.
    pub async fn prepare_exposure_file_backing<S: Store, C: Clock>(
        &self,
        exposure: &super::NativeExposureLease,
        served: &NativeRootIndex,
        selection: PreparedFileRead<'_, S, C>,
        expires: u64,
    ) -> Result<NativeFileBacking, Error> {
        if exposure.commit() != served.commit || exposure.key() != served.key() {
            return Err(Error::Denied);
        }
        check_file_scope(served, &selection)?;
        self.prepare_file_backing_for_exposure(selection, expires, exposure)
            .await
    }

    async fn admit_prepared_root<S: Store, C: Clock>(
        &self,
        selection: &PreparedRootRead<'_, S, C>,
    ) -> Result<NativeSurfaceIndex, Error> {
        let metadata = selection.metadata();
        let identity = root_identity(selection)?;
        if metadata.minimum_chunk_size() != self.chunk_profile.minimum() as u64 {
            return Err(StoreFailure::new(StoreErrorKind::Unsupported).into());
        }

        // Check the immutable physical bound before copying the SDK inventory.
        self.check_surface_input(metadata.nodes())
            .map_err(|error| native_failure(error, &identity))?;
        self.admission_bounds
            .check(selection.storage_domain().len(), 0)
            .map_err(|error| native_failure(error, &identity))?;

        let index = self
            .submit_surface_index(
                metadata.root(),
                metadata.nodes().clone(),
                Some(selection.storage_domain().to_owned()),
            )
            .await
            .map_err(|error| native_failure(error, &identity))?;
        Ok(index)
    }
}

/// Checks the mapped immutable file selection before any native pin request.
fn check_file_scope<S: Store, C: Clock>(
    served: &NativeRootIndex,
    selection: &PreparedFileRead<'_, S, C>,
) -> Result<(), Error> {
    if selection.commit() != served.commit
        || selection.root() != served.key().root()
        || selection.storage_domain() != served.domain
    {
        return Err(Error::Denied);
    }
    let path = selection.path().strip_prefix(b"/").ok_or(Error::Denied)?;
    let entry = served.index().lookup(path).ok_or(Error::Denied)?;
    if !matches!(entry.kind(), Kind::File { content, size }
        if content == selection.content() && size == selection.size())
    {
        return Err(Error::Denied);
    }
    let identity = TERRANE_V1
        .from_digest(IdentityKind::Node, &served.key().root())
        .map_err(|_| StoreFailure::new(StoreErrorKind::Unsupported))?;
    served
        .check_native_backing()
        .map_err(|error| native_failure(error, &identity))?;
    Ok(())
}

fn root_identity<S: Store, C: Clock>(
    selection: &PreparedRootRead<'_, S, C>,
) -> Result<terrane_format::identity::Identity, Error> {
    TERRANE_V1
        .from_digest(IdentityKind::Node, &selection.metadata().root())
        .map_err(|_| StoreFailure::new(StoreErrorKind::Unsupported).into())
}

/// Duplicates only the originally admitted descriptor; namespace substitution
/// cannot select a different inode between admission and mapping.
fn map_original(admission: &NativeSurfaceIndex) -> io::Result<MappedIndex> {
    let backing = &admission.backing;
    backing.check()?;
    let maximum = usize::try_from(backing.metadata.len())
        .map_err(|_| io::Error::other("surface mapping size exceeds address space"))?;
    MappedIndex::open(
        backing.file.try_clone()?.into(),
        backing.key.root(),
        &backing.binding,
        maximum,
    )
    .map_err(io::Error::other)
}
