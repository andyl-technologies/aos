//! Runs the public Rust metadata adapter against an inherited real FUSE mount.
//!
//! The VM-only C coordinator passes three distinct descriptors: the mounted
//! FUSE connection, a cancellation pipe reader, and a report pipe writer. This
//! fixture builds a six-record canonical tree and its validated presentation
//! before running the adapter. An optional fallback mode seals its own known
//! object under a VM-provided fs-verity root; it never obtains a consumer grant
//! or qualifies the production Mount/connected-FD handoff.
//!
//! The report is a fixed test-only textual record, written only after expected
//! cancellation and verification that both borrowed descriptors remain open:
//!
//! ```text
//! aos.fuse-rust-worker/v1 cancelled borrowed-fds-retained
//! ```

use std::error::Error;
use std::ffi::OsStr;
use std::io::{Cursor, Write};
use std::os::fd::{AsFd, AsRawFd, FromRawFd, OwnedFd};
use std::path::Path;

use aos_filesystem_fuse::dormant_libfuse::ProtectedFuseRegistrationOwnerV2;
use aos_filesystem_fuse::{RunError, TransportLimits, run_fallback_test_fixture, run_metadata};
use aos_filesystem_view::{
    AclCapability, DataPlaneLimits, DirectoryHandleLimits, INDEX_MEDIA_TYPE, IdMapExtent,
    IdentityMap, IndexExpectation, IndexStaging, InodeTableLimits, MetadataConnection,
    ObjectSource, PreparedPresentation, PresentationLimits, PresentationPlan, ProjectionLimits,
    ReplyScratch, RequestBudget, TreeCompileLimits, TreeCompiler, WorkerLimits,
    compile_view_projection, validate_index,
};
use aos_sandbox_core::format::ObjectDescriptorVerifier;
use aos_sandbox_core::format::{encode_directory, encode_tree, encode_view};
use aos_sandbox_core::model::{
    CacheDomain, CacheDomainKind, ContentLayout, Directory, DirectoryEntry, FileNode,
    FilesystemMetadata, Node, SymlinkNode, Tree, View, ViewConsistency, ViewMutation, ViewSource,
};
use aos_sandbox_core::{
    CacheDomainId, DecodeLimits, FeatureRef, MediaType, ObjectDescriptor, PathName, Revision,
    ViewId, descriptor_for_bytes,
};
use aos_sandbox_linux::immutable_file::{
    FsVerityBacking, FsVerityPublicationRoot, MaterializationCallbacks, PublicationName,
};

type Result<T> = std::result::Result<T, Box<dyn Error>>;

#[derive(Default)]
struct Source(Vec<(ObjectDescriptor, Vec<u8>)>);

impl Source {
    fn insert(&mut self, media: &str, bytes: Vec<u8>) -> Result<ObjectDescriptor> {
        let descriptor = descriptor_for_bytes(MediaType::new(media)?, &bytes);
        self.0.push((descriptor.clone(), bytes));
        Ok(descriptor)
    }
}

impl ObjectSource for Source {
    type Error = std::io::Error;
    type Reader<'source> = Cursor<Vec<u8>>;

    fn open(&mut self, descriptor: &ObjectDescriptor) -> std::io::Result<Self::Reader<'_>> {
        let (_, bytes) = self
            .0
            .iter()
            .find(|(key, _)| key == descriptor)
            .ok_or_else(|| std::io::Error::from(std::io::ErrorKind::NotFound))?;
        Ok(Cursor::new(bytes.clone()))
    }
}

fn metadata(mode: u16) -> Result<FilesystemMetadata> {
    Ok(FilesystemMetadata::new(mode, 0, 0, 17, 19, vec![], None)?)
}

fn directory_entry(name: &[u8], node: Node) -> Result<DirectoryEntry> {
    Ok(DirectoryEntry {
        name: PathName::new(name.to_vec())?,
        node,
    })
}

fn compile_fixture(
    source: &mut Source,
    fallback: bool,
) -> Result<(ObjectDescriptor, ObjectDescriptor)> {
    let content = source.insert("application/vnd.aos.sandbox.content.v1", vec![42])?;
    let mut directories = Vec::new();
    for (name, mode) in [
        (b"private".as_slice(), 0o700),
        (b"public".as_slice(), 0o555),
    ] {
        let file = Node::File(FileNode {
            metadata: metadata(if fallback && name == b"private" {
                0
            } else {
                0o444
            })?,
            content: ContentLayout::whole(content.clone()),
            hardlink_group: None,
        });
        let entries = vec![directory_entry(b"leaf", file)?];
        let directory = Directory::new(metadata(mode)?, entries)?;
        let descriptor = source.insert(
            "application/vnd.aos.sandbox.directory.v1+cbor",
            encode_directory(&directory),
        )?;
        directories.push(directory_entry(name, Node::Directory(descriptor))?);
    }
    let mut root_entries = vec![directory_entry(
        b"link",
        Node::Symlink(SymlinkNode::new(metadata(0o777)?, b"public/leaf".to_vec())?),
    )?];
    root_entries.extend(directories);
    let root = source.insert(
        "application/vnd.aos.sandbox.directory.v1+cbor",
        encode_directory(&Directory::new(metadata(0o555)?, root_entries)?),
    )?;
    let tree = source.insert(
        "application/vnd.aos.sandbox.tree.v1+cbor",
        encode_tree(&Tree::new(root.clone(), vec![])?),
    )?;
    Ok((root, tree))
}

fn serve(connected: &OwnedFd, cancellation: &OwnedFd, fallback_root: Option<&Path>) -> Result<()> {
    let mut source = Source::default();
    let (root, tree) = compile_fixture(&mut source, fallback_root.is_some())?;
    let (_, staged) = TreeCompiler::new(TreeCompileLimits::default()).compile(
        &mut source,
        IndexStaging::new(Cursor::new(Vec::new()), 65_536, 4096),
        &tree,
        [7; 32],
    )?;
    let (writer, _) = staged.into_parts();
    let bytes = writer.into_inner();
    let artifact = descriptor_for_bytes(MediaType::new(INDEX_MEDIA_TYPE)?, &bytes);
    let index = validate_index(
        &bytes,
        65_536,
        1_048_576,
        &IndexExpectation {
            index: &artifact,
            compiler_abi: [7; 32],
            tree: &tree,
            root: &root,
            tree_features: 0,
        },
    )?;
    let view = View::new(
        ViewSource::ImmutableTree { tree: tree.clone() },
        Vec::new(),
        ViewConsistency::Immutable,
        ViewMutation::ReadOnly,
        FeatureRef::new("aos.sandbox.identity.posix32", 1, 0)?,
        CacheDomain::new(CacheDomainKind::Private, CacheDomainId::from_bytes([3; 16])),
        Vec::new(),
    )?;
    let view_bytes = encode_view(&view);
    let view_descriptor = descriptor_for_bytes(
        MediaType::new("application/vnd.aos.sandbox.view.v1+cbor")?,
        &view_bytes,
    );
    let projection = compile_view_projection(
        &view_bytes,
        &view_descriptor,
        ViewId::from_bytes([4; 16]),
        Revision::new(1),
        &index,
        ProjectionLimits {
            decode: DecodeLimits {
                maximum_bytes: 65_536,
                maximum_collection_items: 128,
                maximum_total_items: 512,
                maximum_byte_string_bytes: 65_536,
                maximum_text_bytes: 4_096,
                maximum_depth: 32,
            },
            maximum_actions: 1,
            maximum_source_records: 128,
            maximum_projected_nodes: 128,
            maximum_path_components: 64,
            maximum_path_bytes: 1_048_576,
            maximum_working_bytes: 16 * 1_048_576,
        },
    )?;
    let extent = IdMapExtent {
        portable_start: 0,
        presented_start: 1000,
        length: 1,
    };
    let plan = PresentationPlan::new(
        IdentityMap::new(vec![extent], vec![extent])?,
        AclCapability::Unsupported,
    );
    let presentation =
        PreparedPresentation::prepare(&index, &plan, 1, [8; 32], PresentationLimits::new(6, 0, 2))?;
    // Scratch retains both the 64 KiB names buffer and typed directory slots.
    let worker_limits =
        WorkerLimits::new(65_536, 128, 65_536, 131_072).with_maximum_forget_entries(128);
    let inode_limits = InodeTableLimits::new(128, 1_048_576, 1024, 128, 128);
    let directory_limits = DirectoryHandleLimits::new(64, 128);
    let (connection, data) = if fallback_root.is_some() {
        let (connection, data) = MetadataConnection::new_fallback_test_fixture(
            &projection,
            &presentation,
            [9; 32],
            inode_limits,
            directory_limits,
            worker_limits,
            DataPlaneLimits {
                maximum_read_bytes: 65_536,
                maximum_read_segments: 64,
                maximum_plan_heap_bytes: 65_536,
                maximum_attempts_per_segment: 2,
                maximum_retry_delay_ns: 1_000_000,
                maximum_scratch_heap_bytes: 65_536,
            },
        )?;
        (connection, Some(data))
    } else {
        (
            MetadataConnection::new_test_fixture(
                &projection,
                &presentation,
                [9; 32],
                inode_limits,
                directory_limits,
                worker_limits,
            )?,
            None,
        )
    };
    let mut scratch = ReplyScratch::new(worker_limits)?;
    // SAFETY: sysconf reads one process-global scalar and borrows no pointer.
    let page_size = u64::try_from(unsafe { libc::sysconf(libc::_SC_PAGESIZE) })?;
    if page_size == 0 {
        return Err("zero kernel page size".into());
    }
    let limits = TransportLimits {
        maximum_metadata_records: 6,
        maximum_name_bytes: 255,
        maximum_symlink_bytes: 4096,
        maximum_readdir_bytes: 65_536,
        maximum_readdir_entries: 128,
        maximum_write_bytes: 65_536,
        maximum_pages: u32::try_from(65_536_u64.div_ceil(page_size))?,
        time_granularity_ns: 1,
        request_timeout_seconds: 1,
        entry_valid_ns: 0,
        attribute_valid_ns: 0,
    };
    let budget = RequestBudget::new(65_536, 128, 65_536).with_forget_entries(128);
    let result = if let (Some(root), Some(data)) = (fallback_root, data) {
        let content = descriptor_for_bytes(
            MediaType::new("application/vnd.aos.sandbox.content.v1")?,
            &[42],
        );
        let backing = seal_fixture_object(root, &content)?;
        let mut owner = ProtectedFuseRegistrationOwnerV2::open_test_fixture(&root.join("journal"))?;
        run_fallback_test_fixture(
            connection,
            data,
            &mut scratch,
            &mut owner,
            vec![(content, backing)],
            connected.as_fd(),
            cancellation.as_fd(),
            limits,
            budget,
        )
    } else {
        run_metadata(
            connection,
            &mut scratch,
            connected.as_fd(),
            cancellation.as_fd(),
            limits,
            budget,
        )
    };
    match result {
        Err(RunError::Transport(error)) if error.raw_os_error() == Some(libc::ECANCELED) => Ok(()),
        Err(error) => Err(error.into()),
        Ok(_) => Err("worker unexpectedly returned without cancellation".into()),
    }
}

struct FixtureVerifier(Option<ObjectDescriptorVerifier>);

impl MaterializationCallbacks for FixtureVerifier {
    type Error = std::io::Error;

    fn checkpoint(&mut self) -> std::io::Result<()> {
        Ok(())
    }

    fn verify_chunk(&mut self, bytes: &[u8]) -> std::io::Result<()> {
        self.0
            .as_mut()
            .ok_or_else(|| std::io::Error::other("finished fixture verifier"))?
            .update(bytes)
            .map_err(std::io::Error::other)
    }

    fn finish_verification(&mut self) -> std::io::Result<()> {
        self.0
            .take()
            .ok_or_else(|| std::io::Error::other("finished fixture verifier"))?
            .finish()
            .map_err(std::io::Error::other)
    }
}

fn seal_fixture_object(root: &Path, content: &ObjectDescriptor) -> Result<FsVerityBacking> {
    // This is an explicit VM fixture owner, never a worker read grant. The
    // exact one-byte raw object is hashed before and after private copying.
    let source_path = root.join("source");
    let mut source = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&source_path)?;
    source.write_all(&[42])?;
    source.sync_all()?;
    drop(source);
    let publication =
        FsVerityPublicationRoot::from_owned(std::fs::File::open(root.join("objects"))?.into())?;
    let sealed = publication.materialize_and_seal(
        std::fs::File::open(source_path)?.into(),
        PublicationName::new(OsStr::new("content"))?,
        1,
        &mut FixtureVerifier(Some(ObjectDescriptorVerifier::new(content.clone()))),
    )?;
    Ok(FsVerityBacking::from_received(
        sealed.as_fd().try_clone_to_owned()?,
        sealed.verity_digest(),
        1,
        1,
    )?)
}

fn run() -> Result<()> {
    let args = std::env::args().skip(1).collect::<Vec<_>>();
    if args.len() != 3 && !(args.len() == 5 && args[3] == "--fallback") {
        return Err("expected FUSE, cancellation, and report descriptor numbers".into());
    }
    let fds = [
        args[0].parse::<libc::c_int>()?,
        args[1].parse::<libc::c_int>()?,
        args[2].parse::<libc::c_int>()?,
    ];
    if fds.iter().any(|fd| *fd < 3) || fds[0] == fds[1] || fds[0] == fds[2] || fds[1] == fds[2] {
        return Err("fixture descriptors must be distinct and outside stdio".into());
    }
    for fd in fds {
        // SAFETY: F_GETFD inspects a scalar descriptor without accessing memory.
        if unsafe { libc::fcntl(fd, libc::F_GETFD) } < 0 {
            return Err(std::io::Error::last_os_error().into());
        }
    }
    // SAFETY: The test coordinator exclusively transfers these three inherited
    // descriptors across exec. They are live, distinct, and each is adopted once.
    let [connected, cancellation, report] = unsafe { fds.map(|fd| OwnedFd::from_raw_fd(fd)) };
    // Make the fixture nondumpable before retaining sealed backing. The kernel
    // DAC checks below do not qualify production memory/FD isolation or MAC.
    if args.len() == 5 {
        // SAFETY: Both prctl calls use scalar arguments and no borrowed pointer.
        if unsafe { libc::prctl(libc::PR_SET_DUMPABLE, 0, 0, 0, 0) } != 0
            || unsafe { libc::prctl(libc::PR_GET_DUMPABLE, 0, 0, 0, 0) } != 0
        {
            return Err("fixture remained dumpable".into());
        }
    }
    let fallback_root = (args.len() == 5).then(|| Path::new(&args[4]));
    serve(&connected, &cancellation, fallback_root)?;
    for fd in [&connected, &cancellation] {
        // SAFETY: Both OwnedFd values still own the borrowed descriptors.
        if unsafe { libc::fcntl(fd.as_raw_fd(), libc::F_GETFD) } < 0 {
            return Err("adapter consumed a borrowed descriptor".into());
        }
    }
    drop(connected);
    drop(cancellation);
    let mut report = std::fs::File::from(report);
    report.write_all(b"aos.fuse-rust-worker/v1 cancelled borrowed-fds-retained\n")?;
    report.flush()?;
    Ok(())
}

pub(super) fn main() {
    if let Err(error) = run() {
        eprintln!("Rust FUSE kernel fixture failed: {error}");
        std::process::exit(1);
    }
}
