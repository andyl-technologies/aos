//! Retains bounded member DATA through complete chunk and dictionary validation.
//!
//! This ordinary wrapper is used only for ranged chunk requests. Its observations
//! close before return and never enter an effect or history authority carrier.

use super::ranged_pack::{self, MemberReadMode, RetainedMemberRanges};
use super::*;
use crate::bucket::publication::receipts::RecordRead;
use std::sync::Mutex;
use terrane_format::bucket::BucketKey;

/// Collects bounded physical reads belonging to one ordinary request.
pub(super) struct BoundedReads<'request, F, C, V> {
    bucket: &'request FileBucket<F, C, V>,
    members: Mutex<Vec<RetainedMemberRanges>>,
    mode: MemberReadMode,
    #[cfg(all(feature = "tokio", unix))]
    records: Mutex<Vec<RecordRead>>,
}

/// Chooses one DATA route before the request consumes selected or payload bytes.
///
/// # Errors
/// Propagates optional native probe failures rather than selecting a fallback.
pub(super) async fn mode<F: LocalFs + BucketBinding>(
    fs: &F,
) -> Result<MemberReadMode, StoreFailure> {
    #[cfg(all(feature = "tokio", unix))]
    if crate::store::native_publication_effects::PayloadRangeCapture::supported(fs).await? {
        return Ok(MemberReadMode::Native);
    }
    #[cfg(not(all(feature = "tokio", unix)))]
    let _ = fs;
    Ok(MemberReadMode::Ordinary)
}

impl<'request, F, C, V> BoundedReads<'request, F, C, V>
where
    F: LocalFs + BucketBinding,
    C: Clock + BucketBinding,
    V: ContentValidator + BucketBinding,
{
    /// Retains the one route already selected before this request's reads.
    pub(super) fn with_mode(bucket: &'request FileBucket<F, C, V>, mode: MemberReadMode) -> Self {
        Self {
            bucket,
            members: Mutex::new(Vec::new()),
            mode,
            #[cfg(all(feature = "tokio", unix))]
            records: Mutex::new(Vec::new()),
        }
    }

    /// Freshly closes every actual member and native index input before return.
    ///
    /// # Errors
    /// Refuses changed inputs, missing original evidence and unavailable reads.
    pub(super) async fn close(self) -> Result<(), StoreFailure> {
        #[cfg(all(feature = "tokio", unix))]
        for record in self
            .records
            .into_inner()
            .map_err(|_| files::layout_corrupt())?
        {
            record.revalidate_retained(self.bucket.fs()).await?;
        }
        let members = self
            .members
            .into_inner()
            .map_err(|_| files::layout_corrupt())?;
        for member in members {
            member.revalidate(self.bucket.fs()).await?;
        }
        Ok(())
    }
}

/// Retains a member's actual closing observations in the caller's request ledger.
///
/// # Errors
/// Preserves selected absence, malformed pack/index bounds and actual I/O failures.
pub(super) async fn read_member<F, C, V, R>(
    bucket: &FileBucket<F, C, V>,
    catalog: &Catalog,
    identity: &Identity,
    reads: &R,
    members: &Mutex<Vec<RetainedMemberRanges>>,
    mode: MemberReadMode,
) -> Result<(Vec<u8>, usize), StoreFailure>
where
    F: LocalFs + BucketBinding,
    C: Clock + BucketBinding,
    V: ContentValidator + BucketBinding,
    R: CatalogReads + ?Sized,
{
    let location = bucket.location(catalog, identity)?;
    let index = reads
        .read_artifact(&registered(&location.pack().index_key())?)
        .await?;
    let (encoded, length, retained) =
        ranged_pack::read_member(bucket, catalog, identity, &index, mode)
            .await?
            .into_parts();
    members
        .lock()
        .map_err(|_| files::layout_corrupt())?
        .push(retained);
    Ok((encoded, length))
}

#[cfg_attr(feature = "send", async_trait::async_trait)]
#[cfg_attr(not(feature = "send"), async_trait::async_trait(?Send))]
impl<F, C, V> CatalogReads for BoundedReads<'_, F, C, V>
where
    F: LocalFs + BucketBinding,
    C: Clock + BucketBinding,
    V: ContentValidator + BucketBinding,
{
    async fn read_artifact(&self, key: &BucketKey) -> Result<RecordRead, StoreFailure> {
        #[cfg(all(feature = "tokio", unix))]
        if matches!(self.mode, MemberReadMode::Native) {
            let record = self.bucket.read_optional_ordinary_retained(key).await?;
            self.records
                .lock()
                .map_err(|_| files::layout_corrupt())?
                .push(record.clone());
            return Ok(record);
        }
        self.bucket.read_optional_observed(key).await
    }

    async fn read_member(
        &self,
        catalog: &Catalog,
        identity: &Identity,
    ) -> Result<Option<(Vec<u8>, usize)>, StoreFailure> {
        read_member(
            self.bucket,
            catalog,
            identity,
            self,
            &self.members,
            self.mode,
        )
        .await
        .map(Some)
    }
}
