//! Restricts shared views to concrete verified host readers.

use crate::bucket::BucketBinding;
use crate::host::cache::{
    DomainHostLayout, HostReadOnlyContent, HostResidenceReader, HostResidentContent,
};
use crate::store::{ContentStore, ContentValidator, LocalFs};

mod sealed {
    pub trait Sealed {}
}

/// Restricts shared views to the ordinary and residence-aware host readers.
///
/// This interface cannot be implemented outside this module. It exposes only
/// routing observations; those observations grant no authorization or native
/// custody. The host reader remains responsible for verifying every result.
pub trait HostViewReader: ContentStore + BucketBinding + sealed::Sealed {
    /// Returns the immutable configured domain layout.
    fn host_layout(&self) -> &DomainHostLayout;

    /// Returns the opening observation used solely to reject configured aliases.
    fn observed_directory_identity(&self) -> (u64, u64);
}

impl<F, V> sealed::Sealed for HostReadOnlyContent<F, V> {}

impl<F, V> HostViewReader for HostReadOnlyContent<F, V>
where
    F: LocalFs + BucketBinding,
    V: ContentValidator + BucketBinding,
{
    fn host_layout(&self) -> &DomainHostLayout {
        self.layout()
    }

    fn observed_directory_identity(&self) -> (u64, u64) {
        self.directory_identity()
    }
}

impl<F, V, R> sealed::Sealed for HostResidentContent<F, V, R> {}

impl<F, V, R> HostViewReader for HostResidentContent<F, V, R>
where
    F: LocalFs + BucketBinding,
    V: ContentValidator + BucketBinding,
    R: HostResidenceReader,
{
    fn host_layout(&self) -> &DomainHostLayout {
        self.layout()
    }

    fn observed_directory_identity(&self) -> (u64, u64) {
        self.directory_identity()
    }
}
