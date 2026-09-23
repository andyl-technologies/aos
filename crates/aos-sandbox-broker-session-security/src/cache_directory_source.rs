//! Descriptor-relative streaming of staged portable View source objects.
//!
//! The directory is a source-adapter input, not a trusted publication root.
//! Callers must obtain the root through their own authority path, and the
//! portable-object compiler verifies every returned byte against the requested
//! descriptor before using it as View data.

use std::io::{self, Read};
use std::path::Path;

use aos_filesystem_view_core::ObjectSource;
use aos_sandbox_core::ObjectDescriptor;
use aos_sandbox_linux::path::{BeneathRoot, ResolvedFile};

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
