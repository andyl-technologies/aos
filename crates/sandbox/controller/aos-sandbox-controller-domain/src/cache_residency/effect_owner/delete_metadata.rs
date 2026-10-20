//! Reads Source-recorded Snapshot metadata without a public disclosure grant.
//!
//! Only the private genuine D Cache query constructs this destination, after
//! its same C17/Source admission and exact descriptor-byte/model pricing. The
//! ordinary current View/Attachment read capability is never synthesized. A
//! decoded descriptor, checksum, model or empty result conveys no read grant.

use super::*;
use aos_sandbox_model::format::{CanonicalCborError, DecodeLimits, decode_snapshot,
    snapshot_decode_receiving_bytes_v2, decode_view, view_decode_receiving_bytes_v2};
use aos_sandbox_model::model::{Snapshot, View};
use aos_sandbox_model::registry::{PortableMediaType, RegistryError};
use aos_sandbox_linux::immutable_file::{FsVerityReadOriginalV2, FsVerityReadClosedV2};
use crate::journal::SourceDeleteMetadataRequestDataV2;

#[derive(Debug, thiserror::Error)]
enum MetadataErrorV2 {
    #[error(transparent)]
    Physical(#[from] CacheOwnerErrorV1),
    #[error(transparent)]
    Native(#[from] FsVerityReadClosedV2),
    #[error(transparent)]
    Registry(#[from] RegistryError),
    #[error("the Snapshot descriptor or logical source relation differs")]
    Relation,
    #[error("the actual Snapshot metadata native frontier {0} reached its original cutoff")]
    Deadline(usize),
}

/// Retains one internal Snapshot metadata read on the actual physical Cache.
///
/// The constructor is confined to the C17 query. This original retains its
/// whole native file and partial bytes even on refusal; models are lent only
/// through the enclosing completed actual Cache query's held scope.
pub(in crate::cache_residency) struct CacheDeleteMetadataReadOriginalV2<'cache> {
    physical: &'cache DormantCacheOwnerV1,
    request: SourceDeleteMetadataRequestDataV2,
    selected: Option<(&'cache ObjectKey, &'cache DiskEntry)>,
    native: FsVerityReadOriginalV2,
    metadata: Option<rustix::fs::Stat>,
    result: Option<Result<(), MetadataErrorV2>>,
    model: Option<Result<CacheDeleteMetadataModelV2, CanonicalCborError>>,
    bytes: Option<Vec<u8>>,
    closed: Option<CacheDeleteMetadataReadClosedV2>,
    samples: [Option<rustix::time::Timespec>; 6],
    horizons: [Option<Result<(), crate::JournalError>>; 6],
    after: Option<Result<(), MetadataErrorV2>>,
}

impl<'cache> CacheDeleteMetadataReadOriginalV2<'cache> {
    pub(in crate::cache_residency) fn new(
        physical: &'cache DormantCacheOwnerV1,
        request: SourceDeleteMetadataRequestDataV2,
    ) -> Self {
        Self { physical, request, selected: None, native: FsVerityReadOriginalV2::new(),
            metadata: None, result: None, model: None, bytes: None, closed: None,
            samples: std::array::from_fn(|_| None), horizons: std::array::from_fn(|_| None), after: None }
    }

    pub(in crate::cache_residency) fn receiving_bytes_v2(
        physical: &DormantCacheOwnerV1,
        request: &SourceDeleteMetadataRequestDataV2,
    ) -> Result<usize, CacheOwnerErrorV1> {
        let descriptor = request.descriptor_v2();
        let bytes = usize::try_from(descriptor.encoded_size())
            .map_err(|_| CacheOwnerErrorV1::CapacityExhausted)?;
        let model = if request.snapshot_saved_v2().is_some() {
            snapshot_decode_receiving_bytes_v2(bytes, DecodeLimits::default())
        } else {
            view_decode_receiving_bytes_v2(bytes, DecodeLimits::default())
        }.ok_or(CacheOwnerErrorV1::CapacityExhausted)?;
        let name = physical.disk.iter().find(|(key, _)| key.descriptor == *descriptor)
            .map(|(_, entry)| entry.file_name.len()).unwrap_or(0);
        std::mem::size_of::<Self>().checked_mul(3)
            .and_then(|fixed| fixed.checked_add(std::mem::size_of::<CacheDeleteMetadataModelOriginalV2>().checked_mul(3)?))
            .and_then(|fixed| fixed.checked_add(name.checked_add(1)?.checked_mul(4)?))
            .and_then(|fixed| fixed.checked_add(bytes.checked_add(1)?.checked_mul(3)?))
            .and_then(|fixed| fixed.checked_add(model))
            .ok_or(CacheOwnerErrorV1::CapacityExhausted)
    }

    pub(in crate::cache_residency) const fn opened_file_bound_v2() -> u64 {
        // This fixed leaf recipe uses only path.open_regular_once_v1. It never
        // enters the independent root-duplication or directory-opening arms.
        1
    }

    // Caller enforces the original nonce deadline around each reached native
    // frontier, and dispatches independent enclosing physical/C/profile posts
    // while this whole original remains resident on the Cache query.
    pub(in crate::cache_residency) fn run_once_v2(&mut self, cutoff: u64) -> Result<(), CacheDeleteMetadataReadClosedV2> {
        if self.result.is_some() || self.closed.is_some() {
            self.closed.get_or_insert(CacheDeleteMetadataReadClosedV2);
            return Err(CacheDeleteMetadataReadClosedV2);
        }
        self.result = Some(self.read_inner_v2(cutoff));
        // Independent and prepaid before the first native primary. A failed
        // open/read/parser does not suppress this local cutoff observation.
        self.after = Some(self.observe_deadline_v2(5, cutoff));
        if matches!(self.result, Some(Ok(()))) && matches!(self.after, Some(Ok(()))) {
            Ok(())
        } else { Err(CacheDeleteMetadataReadClosedV2) }
    }

    fn read_inner_v2(&mut self, cutoff: u64) -> Result<(), MetadataErrorV2> {
        let descriptor = self.request.descriptor_v2();
        let expected = if self.request.snapshot_saved_v2().is_some() {
            PortableMediaType::Snapshot
        } else {
            PortableMediaType::View
        };
        if PortableMediaType::parse(descriptor.media_type().as_str())? != expected {
            return Err(MetadataErrorV2::Relation);
        }
        observe_deadline_v2(&mut self.samples, &mut self.horizons, 0, cutoff)?;
        let descriptor = self.request.descriptor_v2();
        self.physical.ensure_unfenced()?;
        // The enclosing retained Cache query owns its real rooted before and
        // independent after. This read stays beneath that same held root.

        // A real durable disk entry is mandatory. An additional memory copy
        // neither supplies this proof nor disqualifies the same disk original.
        self.selected = self.physical.disk.iter().find(|(key, _)| key.descriptor == *descriptor);
        let (key, entry) = self.selected.ok_or(CacheOwnerErrorV1::NotResident)?;
        validate_basename(&entry.file_name)?;
        self.native.open_once_v2(&self.physical.mapping_root, Path::new(&entry.file_name),
            FsVerityDigest::Sha256(entry.verity), descriptor.encoded_size())?;
        observe_deadline_v2(&mut self.samples, &mut self.horizons, 1, cutoff)?;
        let file = self.native.file_v2().ok_or(MetadataErrorV2::Relation)?;
        self.physical.require_disk_file_post_v2(file, key, entry.device, entry.inode, Some(&mut self.metadata))?;
        observe_deadline_v2(&mut self.samples, &mut self.horizons, 2, cutoff)?;
        let maximum = usize::try_from(descriptor.encoded_size()).map_err(|_| MetadataErrorV2::Relation)?;
        if maximum > DecodeLimits::default().maximum_bytes { return Err(MetadataErrorV2::Relation); }
        self.native.read_once_v2(maximum)?;
        observe_deadline_v2(&mut self.samples, &mut self.horizons, 3, cutoff)?;
        self.bytes = self.native.take_completed_bytes_v2();
        let bytes = self.bytes.as_deref().ok_or(MetadataErrorV2::Relation)?;
        verify_bytes(descriptor, bytes)?;
        observe_deadline_v2(&mut self.samples, &mut self.horizons, 4, cutoff)?;
        let bytes = self.bytes.as_deref().ok_or(MetadataErrorV2::Relation)?;
        self.model = Some(if self.request.snapshot_saved_v2().is_some() {
            decode_snapshot(bytes, DecodeLimits::default()).map(CacheDeleteMetadataModelV2::Snapshot)
        } else {
            decode_view(bytes, DecodeLimits::default()).map(CacheDeleteMetadataModelV2::View)
        });
        let model = self.model.as_ref().and_then(|model| model.as_ref().ok())
            .ok_or(MetadataErrorV2::Relation)?;
        if let (Some(saved), CacheDeleteMetadataModelV2::Snapshot(snapshot)) =
            (self.request.snapshot_saved_v2(), model)
        {
            if snapshot.source_assignment().sandbox() != saved.sandbox() {
                return Err(MetadataErrorV2::Relation);
            }
        }
        Ok(())
    }

    fn observe_deadline_v2(&mut self, index: usize, cutoff: u64) -> Result<(), MetadataErrorV2> {
        observe_deadline_v2(&mut self.samples, &mut self.horizons, index, cutoff)
    }

    pub(in crate::cache_residency) fn failure(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.result.as_ref().and_then(|result| result.as_ref().err())
            .and_then(|cause| self.cause_v2(cause))
            .or_else(|| self.after.as_ref().and_then(|result| result.as_ref().err())
                .and_then(|cause| self.cause_v2(cause)))
            .or_else(|| self.closed.as_ref().map(|cause| cause as _))
    }

    fn cause_v2<'cause>(&'cause self, cause: &'cause MetadataErrorV2)
        -> Option<&'cause (dyn std::error::Error + 'static)>
    {
        match cause {
            MetadataErrorV2::Native(marker) => self.native.failure().or(Some(marker as _)),
            MetadataErrorV2::Relation if self.model.as_ref().is_some_and(Result::is_err) =>
                self.model.as_ref().and_then(|model| model.as_ref().err()).map(|cause| cause as _),
            MetadataErrorV2::Deadline(index) => self.horizons[*index].as_ref()
                .and_then(|result| result.as_ref().err()).map(|cause| cause as _),
            cause => Some(cause as _),
        }
    }

    pub(in crate::cache_residency) fn is_positive_v2(&self) -> bool {
        self.closed.is_none() && matches!(self.result, Some(Ok(())))
            && matches!(self.after, Some(Ok(()))) && matches!(self.model, Some(Ok(_)))
            && self.bytes.is_some() && self.native.failure().is_none()
    }

    // Internal semantic work may borrow a successful local parse while every
    // whole-query after is still owed. No answer or native grant escapes here.
    pub(crate) fn parsed_metadata_data_v2(&self)
        -> Option<aos_sandbox_ledger_replay::delete_graph::DeleteGraphMetadataDataV2<'_>>
    {
        use aos_sandbox_ledger_replay::delete_graph::DeleteGraphMetadataDataV2 as Data;
        if !self.is_positive_v2() { return None; }
        match (&self.request, self.model.as_ref()?.as_ref().ok()?) {
            (SourceDeleteMetadataRequestDataV2::Snapshot(saved), CacheDeleteMetadataModelV2::Snapshot(model)) =>
                Some(Data::Snapshot { saved, model }),
            (SourceDeleteMetadataRequestDataV2::View { view, descriptor }, CacheDeleteMetadataModelV2::View(model)) =>
                Some(Data::View { id: *view, descriptor, model }),
            _ => None,
        }
    }

    // Only the enclosing actual Cache query invokes this after all its real
    // physical/authority/C/profile/nonce posts and final cutoff succeeded, with
    // its same native disposition token still held. No second buffer is made.
    pub(in crate::cache_residency) fn complete_after_query_posts_v2(self) -> CacheDeleteMetadataModelOriginalV2 {
        if !self.is_positive_v2() { std::process::abort(); }
        let Self { request, native, bytes, model, .. } = self;
        let (Some(bytes), Some(Ok(model))) = (bytes, model) else { std::process::abort(); };
        drop(native);
        CacheDeleteMetadataModelOriginalV2 { request, bytes, model }
    }
}

// This completed DATA owner retains exact content-addressed bytes and the
// sole canonical typed model. It cannot be adopted or built from caller DATA.
pub(in crate::cache_residency) struct CacheDeleteMetadataModelOriginalV2 {
    request: SourceDeleteMetadataRequestDataV2,
    bytes: Vec<u8>,
    model: CacheDeleteMetadataModelV2,
}

pub(crate) enum CacheDeleteMetadataModelV2 {
    Snapshot(Snapshot),
    View(View),
}

impl CacheDeleteMetadataModelOriginalV2 {
    pub(in crate::cache_residency) fn request_v2(&self) -> &SourceDeleteMetadataRequestDataV2 {
        &self.request
    }

    pub(in crate::cache_residency) fn bytes_v2(&self) -> &[u8] { &self.bytes }

    pub(in crate::cache_residency) fn model_v2(&self) -> &CacheDeleteMetadataModelV2 { &self.model }
}

#[derive(Clone, Copy, Debug, thiserror::Error)]
#[error("the actual Cache Snapshot metadata reader is closed")]
pub(in crate::cache_residency) struct CacheDeleteMetadataReadClosedV2;

fn observe_deadline_v2(
    samples: &mut [Option<rustix::time::Timespec>; 6],
    horizons: &mut [Option<Result<(), crate::JournalError>>; 6],
    index: usize,
    cutoff: u64,
) -> Result<(), MetadataErrorV2> {
    if samples[index].is_some() || horizons[index].is_some() {
        return Err(MetadataErrorV2::Deadline(index));
    }
    samples[index] = Some(rustix::time::clock_gettime(rustix::time::ClockId::Boottime));
    horizons[index] = Some(require_deadline_sample_v2(samples[index], cutoff));
    if matches!(horizons[index], Some(Ok(()))) { Ok(()) } else { Err(MetadataErrorV2::Deadline(index)) }
}

// The same actual pure conversion serves the existing Cache query bookend.
pub(in crate::cache_residency) fn require_deadline_sample_v2(
    sample: Option<rustix::time::Timespec>, cutoff: u64,
) -> Result<(), crate::JournalError> {
    let sample = sample.ok_or(crate::JournalError::ProtectedBoundary)?;
    let seconds = u64::try_from(sample.tv_sec).map_err(|_| crate::JournalError::ProtectedBoundary)?;
    let nanos = u64::try_from(sample.tv_nsec).map_err(|_| crate::JournalError::ProtectedBoundary)?;
    let now = seconds.checked_mul(1_000_000_000).and_then(|value| value.checked_add(nanos))
        .ok_or(crate::JournalError::ProtectedBoundary)?;
    if nanos >= 1_000_000_000 || now >= cutoff { return Err(crate::JournalError::ProtectedBoundary); }
    Ok(())
}
