//! Streaming canonical fixture construction and exact temporary-file cleanup.

use std::fs::{self, OpenOptions};
use std::os::unix::fs::DirBuilderExt;
use std::path::{Path, PathBuf};
use std::time::{Instant, SystemTime, UNIX_EPOCH};

use aos_filesystem_view::{IndexStaging, TreeCompileLimits};
use aos_filesystem_view_core::test_fixtures::{IndexNode, IndexRecord, StructuralIndexBuilder};
use aos_sandbox_core::model::{ContentLayout, FilesystemMetadata};
use aos_sandbox_core::{MediaType, ObjectDescriptor, ObjectDigest};

use super::report::{BuildReport, Config, Profile, ResourceSnapshot};
use crate::{Result, allocation};

pub(super) const ABI: [u8; 32] = [23; 32];

pub(super) fn descriptors() -> Result<(ObjectDescriptor, ObjectDescriptor)> {
    // Synthetic commitments deliberately grant no source membership authority.
    Ok((
        ObjectDescriptor::new(
            MediaType::new("application/vnd.aos.sandbox.tree.v1+cbor")?,
            ObjectDigest::from_bytes([7; 32]),
            9,
        ),
        ObjectDescriptor::new(
            MediaType::new("application/vnd.aos.sandbox.directory.v1+cbor")?,
            ObjectDigest::from_bytes([8; 32]),
            13,
        ),
    ))
}

pub(super) fn name(mut ordinal: u64, missing: bool) -> [u8; 9] {
    let mut bytes = [b'0'; 9];
    bytes[0] = if missing { b'z' } else { b'f' };
    for position in (1..bytes.len()).rev() {
        bytes[position] = b'0' + (ordinal % 10) as u8;
        ordinal /= 10;
    }
    assert_eq!(ordinal, 0, "fixture name width exhausted");
    bytes
}

pub(super) fn elapsed_ns(start: Instant) -> Result<u64> {
    Ok(u64::try_from(start.elapsed().as_nanos())?)
}

pub(super) fn build(directory: &Path, config: Config) -> Result<BuildReport> {
    let (tree, root) = descriptors()?;
    let directory_metadata = FilesystemMetadata::new(0o755, 0, 0, 0, 0, Vec::new(), None)?;
    let file_metadata = FilesystemMetadata::new(0o444, 0, 0, 0, 0, Vec::new(), None)?;
    let empty = ContentLayout::whole(aos_sandbox_core::descriptor_for_bytes(
        MediaType::new("application/vnd.aos.sandbox.content.v1")?,
        &[],
    ));
    let staging_path = directory.join("index.staging");
    let writer = OpenOptions::new()
        .read(true)
        .write(true)
        .create_new(true)
        .open(&staging_path)?;
    let before = ResourceSnapshot::take()?;
    let started = Instant::now();
    let limits = TreeCompileLimits::default();
    // IndexStaging uses its index-byte cap as its internal builder working cap.
    // Small CI stays within normal compiler working limits; the opt-in million
    // fixture separately declares the existing 2 GiB index/builder envelope.
    let staging_cap = match config.profile {
        Profile::Small => limits.index_bytes.min(limits.working_bytes),
        Profile::Million => limits.index_bytes,
    };
    let (result, allocation) = allocation::measure(|| -> Result<_> {
        let mut builder = StructuralIndexBuilder::new(
            IndexStaging::new(writer, staging_cap, limits.index_record_bytes),
            ABI,
            tree,
            root.clone(),
            0,
        )?;
        builder.push(&IndexRecord {
            parent: u64::MAX,
            depth: 0,
            sibling_ordinal: 0,
            name: &[],
            metadata: &directory_metadata,
            node: IndexNode::Directory { descriptor: &root },
        })?;
        for ordinal in 0..config.profile.children() {
            let name = name(ordinal, false);
            builder.push(&IndexRecord {
                parent: 0,
                depth: 1,
                sibling_ordinal: u32::try_from(ordinal)?,
                name: &name,
                metadata: &file_metadata,
                node: IndexNode::File {
                    content: &empty,
                    hardlink_group: None,
                },
            })?;
        }
        let (file, summary) = builder.finish()?.into_parts();
        file.sync_all()?;
        assert_eq!(file.metadata()?.len(), summary.bytes);
        drop(file);
        Ok(summary)
    });
    let summary = result?;
    let elapsed_ns = elapsed_ns(started)?;
    let after = ResourceSnapshot::take()?;
    fs::rename(staging_path, directory.join("index.bin"))?;
    Ok(BuildReport {
        records: summary.records,
        index_bytes: summary.bytes,
        builder_index_and_working_cap_bytes: staging_cap,
        normal_portable_compiler_working_cap_bytes: limits.working_bytes,
        elapsed_ns,
        allocation,
        before,
        after,
    })
}

pub(super) struct TemporaryFixture {
    directory: PathBuf,
}

impl TemporaryFixture {
    pub(super) fn create() -> Result<Self> {
        let time = SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos();
        let directory =
            std::env::temp_dir().join(format!("aos-metadata-scale-{}-{time}", std::process::id()));
        fs::DirBuilder::new().mode(0o700).create(&directory)?;
        Ok(Self { directory })
    }

    pub(super) fn path(&self) -> &Path {
        &self.directory
    }

    pub(super) fn finish(self) -> Result<()> {
        fs::remove_file(self.directory.join("index.bin"))?;
        fs::remove_dir(&self.directory)?;
        assert!(!self.directory.exists());
        Ok(())
    }
}

impl Drop for TemporaryFixture {
    fn drop(&mut self) {
        // Exact generated names only; never recursively delete unexpected data.
        for name in ["index.bin", "index.staging"] {
            let _ = fs::remove_file(self.directory.join(name));
        }
        let _ = fs::remove_dir(&self.directory);
    }
}
