//! Runs the public Rust metadata adapter against an inherited real FUSE mount.
//!
//! The VM-only C coordinator passes three distinct descriptors: the mounted
//! FUSE connection, a cancellation pipe reader, and a report pipe writer. This
//! fixture builds a six-record canonical tree and its validated presentation
//! before running the adapter. It has no privileged mount or credential code.
//!
//! The report is a fixed test-only textual record, written only after expected
//! cancellation and verification that both borrowed descriptors remain open:
//!
//! ```text
//! aos.fuse-rust-worker/v1 cancelled borrowed-fds-retained
//! ```

use std::error::Error;
use std::io::{Cursor, Write};
use std::os::fd::{AsFd, AsRawFd, FromRawFd, OwnedFd};

use aos_filesystem_fuse::{RunError, TransportLimits, run_metadata};
use aos_filesystem_view::{
    AclCapability, DirectoryHandleLimits, INDEX_MEDIA_TYPE_V3, IdMapExtent, IdentityMap,
    IndexExpectation, IndexStaging, InodeTableLimits, MetadataConnection, ObjectSource,
    PreparedPresentation, PresentationLimits, PresentationPlan, ReplyScratch, RequestBudget,
    TreeCompileLimits, TreeCompiler, WorkerLimits, validate_index,
};
use aos_sandbox_core::format::{encode_directory, encode_tree};
use aos_sandbox_core::model::{
    ContentLayout, Directory, DirectoryEntry, FileNode, FilesystemMetadata, Node, SymlinkNode, Tree,
};
use aos_sandbox_core::{MediaType, ObjectDescriptor, PathName, descriptor_for_bytes};

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
    type Reader = Cursor<Vec<u8>>;

    fn open(&mut self, descriptor: &ObjectDescriptor) -> std::io::Result<Self::Reader> {
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

fn compile_fixture(source: &mut Source) -> Result<(ObjectDescriptor, ObjectDescriptor)> {
    let content = source.insert("application/vnd.aos.sandbox.content.v1", vec![42])?;
    let mut directories = Vec::new();
    for (name, mode) in [
        (b"private".as_slice(), 0o700),
        (b"public".as_slice(), 0o555),
    ] {
        let file = Node::File(FileNode {
            metadata: metadata(0o444)?,
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

fn serve(connected: &OwnedFd, cancellation: &OwnedFd) -> Result<()> {
    let mut source = Source::default();
    let (root, tree) = compile_fixture(&mut source)?;
    let (_, staged) = TreeCompiler::new(TreeCompileLimits::default()).compile(
        &mut source,
        IndexStaging::new(Cursor::new(Vec::new()), 65_536, 4096),
        &tree,
        [7; 32],
    )?;
    let (writer, _) = staged.into_parts();
    let bytes = writer.into_inner();
    let artifact = descriptor_for_bytes(MediaType::new(INDEX_MEDIA_TYPE_V3)?, &bytes);
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
    let connection = MetadataConnection::new(
        &presentation,
        [9; 32],
        InodeTableLimits::new(128, 1_048_576, 1024, 128, 128),
        DirectoryHandleLimits::new(64, 128),
        worker_limits,
    )?;
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
    let result = run_metadata(
        connection,
        &mut scratch,
        connected.as_fd(),
        cancellation.as_fd(),
        limits,
        RequestBudget::new(65_536, 128, 65_536).with_forget_entries(128),
    );
    match result {
        Err(RunError::Transport(error)) if error.raw_os_error() == Some(libc::ECANCELED) => Ok(()),
        Err(error) => Err(error.into()),
        Ok(_) => Err("worker unexpectedly returned without cancellation".into()),
    }
}

fn run() -> Result<()> {
    let args = std::env::args().skip(1).collect::<Vec<_>>();
    if args.len() != 3 {
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
    serve(&connected, &cancellation)?;
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
