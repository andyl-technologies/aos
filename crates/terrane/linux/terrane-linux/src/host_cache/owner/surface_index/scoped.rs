//! Closes an original complete-root Read around physical index preparation.

use super::{NativeMetadataOwner, NativeSurfaceIndex};
use crate::{
    host_cache::content::native_failure,
    structural_index::{Index, IndexKey, MappedIndex},
};
use std::io;
use terrane_format::identity::Digest;
use terrane_format::identity::{IdentityKind, TERRANE_V1};
use terrane_sdk::{
    repository::{Error, PreparedRootRead},
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
    admission: NativeSurfaceIndex,
    commit: Digest,
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
        selection.finish().await?;
        admission
            .check_native_backing()
            .map_err(|error| native_failure(error, &identity))?;
        Ok(NativeRootIndex {
            mapping,
            admission,
            commit,
        })
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
