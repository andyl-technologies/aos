//! Descriptor-relative streaming of staged portable View source objects.
//!
//! The directory is a source-adapter input, not a trusted publication root.
//! Callers must obtain the root through their own authority path, and the
//! portable-object compiler verifies every returned byte against the requested
//! descriptor before using it as View data.
//!
//! The protected project source layout is:
//!
//! ```text
//! /var/lib/aos/sandboxd/view-sources/<project-uuid>/sha256-<digest-hex>
//! ```
//!
//! Each project directory is separately pinned and every object opened from
//! it must be a sealed regular file. No public request supplies either path.

use std::ffi::OsStr;
use std::io::{self, Read};
use std::path::Path;

use aos_filesystem_view_core::ObjectSource;
use aos_sandbox_core::{ObjectDescriptor, ProjectId};
use aos_sandbox_linux::immutable_file::{
    FsVerityPublicationRoot, InvalidPublicationName, ObserveSealedPublicationError,
    ObservedSealedPublicationReader, PublicationName, PublicationRootError,
};
use aos_sandbox_linux::path::{BeneathRoot, ResolvedFile};

const FIXED_PROJECT_VIEW_SOURCE_ROOT: &str = "/var/lib/aos/sandboxd/view-sources";

/// Reports why a project-scoped immutable View source cannot be read.
#[derive(Debug, thiserror::Error)]
pub enum ProjectSealedViewSourceErrorV1 {
    /// The project identity is unspecified.
    #[error("project View source identity is invalid")]
    InvalidProject,
    /// The fixed project source directory is absent or not protected.
    #[error(transparent)]
    Root(#[from] PublicationRootError),
    /// A descriptor-derived basename is not canonical.
    #[error(transparent)]
    Name(#[from] InvalidPublicationName),
    /// The exact immutable object is not staged for this project.
    #[error("project View source object is absent")]
    Missing,
    /// A staged object failed exact sealed-file observation.
    #[error(transparent)]
    Observation(#[from] ObserveSealedPublicationError),
}

/// Streams only sealed portable objects from one protected project source root.
///
/// The fixed project directory is a source-availability boundary, not a View
/// authorization decision. The caller must independently authenticate the
/// View revision and recheck the consuming project before using compiled
/// membership. [`aos_filesystem_view_core::load_exact`] verifies content bytes
/// against each requested descriptor after this adapter opens an inode.
pub struct ProjectSealedViewObjectSourceV1 {
    root: FsVerityPublicationRoot,
    project: ProjectId,
}

impl ProjectSealedViewObjectSourceV1 {
    /// Opens the protected, project-specific source directory at its fixed path.
    ///
    /// # Errors
    ///
    /// Returns an error for a sentinel project or unsafe, missing, replaced,
    /// or non-fs-verity directory anywhere on the fixed protected path.
    pub fn open_fixed(project: ProjectId) -> Result<Self, ProjectSealedViewSourceErrorV1> {
        if project.as_bytes() == &[0; 16] {
            return Err(ProjectSealedViewSourceErrorV1::InvalidProject);
        }

        let path = Path::new(FIXED_PROJECT_VIEW_SOURCE_ROOT).join(project.to_string());
        let root = FsVerityPublicationRoot::from_protected_absolute_path(&path)?;
        Ok(Self { root, project })
    }

    /// Returns the sole project whose sealed source directory is retained.
    #[must_use]
    pub const fn project(&self) -> ProjectId {
        self.project
    }
}

impl ObjectSource for ProjectSealedViewObjectSourceV1 {
    type Error = ProjectSealedViewSourceErrorV1;
    type Reader<'source> = ObservedSealedPublicationReader<'source>;

    fn open(&mut self, descriptor: &ObjectDescriptor) -> Result<Self::Reader<'_>, Self::Error> {
        let basename = staged_object_name(descriptor);
        let name = PublicationName::new(OsStr::new(&basename))?;
        let file = self
            .root
            .open_named_sealed(&name, descriptor.encoded_size())?
            .ok_or(ProjectSealedViewSourceErrorV1::Missing)?;
        Ok(file.into_reader())
    }
}

/// Opens digest-named staged objects beneath one pinned source directory.
///
/// This adapter performs no network work and does not authenticate the root or
/// establish that an object belongs to a View. Its caller must supply a root
/// scoped to the correct source adapter, while the compiler performs exact
/// descriptor and graph verification on the streamed bytes.
pub struct DirectoryPortableObjectSource {
    root: BeneathRoot,
}

impl DirectoryPortableObjectSource {
    /// Adopts the source adapter's already-pinned directory.
    #[must_use]
    pub const fn new(root: BeneathRoot) -> Self {
        Self { root }
    }
}

/// Reads one regular staged object through a pinned, read-only descriptor.
pub struct PortableObjectReader {
    file: ResolvedFile,
}

impl Read for PortableObjectReader {
    fn read(&mut self, destination: &mut [u8]) -> io::Result<usize> {
        rustix::io::read(self.file.as_fd(), destination).map_err(Into::into)
    }
}

impl ObjectSource for DirectoryPortableObjectSource {
    type Error = aos_sandbox_linux::Error;
    type Reader<'source> = PortableObjectReader;

    fn open(&mut self, descriptor: &ObjectDescriptor) -> Result<Self::Reader<'_>, Self::Error> {
        let name = staged_object_name(descriptor);
        let file = self.root.open_regular(Path::new(&name))?;
        Ok(PortableObjectReader { file })
    }
}

fn staged_object_name(descriptor: &ObjectDescriptor) -> String {
    descriptor.digest().to_string().replacen(':', "-", 1)
}

#[cfg(test)]
mod tests {
    use std::fs::{self, File};
    use std::os::unix::fs::symlink;

    use aos_filesystem_view_core::{SourceError, load_exact};
    use aos_sandbox_core::{MediaType, descriptor_for_bytes};

    use super::*;

    #[test]
    fn staged_source_streams_only_exact_regular_object_bytes() {
        let directory = tempfile::tempdir().unwrap();
        let media = MediaType::new("application/vnd.aos.sandbox.content.v1").unwrap();
        let descriptor = descriptor_for_bytes(media, b"portable object");
        let name = staged_object_name(&descriptor);
        let path = directory.path().join(name);
        fs::write(&path, b"portable object").unwrap();

        let root = BeneathRoot::from_owned(File::open(directory.path()).unwrap().into()).unwrap();
        let mut source = DirectoryPortableObjectSource::new(root);
        let exact = load_exact(&mut source, &descriptor, 1024).unwrap();
        assert_eq!(exact.bytes(), b"portable object");

        fs::write(&path, b"different bytes").unwrap();
        assert!(matches!(
            load_exact(&mut source, &descriptor, 1024),
            Err(SourceError::DescriptorMismatch)
        ));

        fs::remove_file(&path).unwrap();
        symlink("elsewhere", &path).unwrap();
        assert!(matches!(
            load_exact(&mut source, &descriptor, 1024),
            Err(SourceError::Source(_))
        ));
    }
}
