//! Scoped callback fixtures without a kernel mount or privileged descriptor.

// Fixture construction failure is a test failure, never a production fallback.
#![allow(clippy::unwrap_used)]

use std::ffi::{c_int, c_void};
use std::io::Cursor;
use std::os::fd::AsFd;
use std::os::unix::net::UnixStream;

use aos_filesystem_view::{
    AclCapability, DirectoryHandleLimits, INDEX_MEDIA_TYPE_V3, IdMapExtent, IdentityMap,
    IndexExpectation, IndexStaging, InodeTableLimits, ObjectSource, PreparedPresentation,
    PresentationLimits, PresentationPlan, ROOT_NODE_ID, TreeCompileLimits, TreeCompiler,
    WorkerLimits, validate_index,
};
use aos_sandbox_core::format::{encode_directory, encode_tree};
use aos_sandbox_core::model::{
    ContentLayout, Directory, DirectoryEntry, FileNode, FilesystemMetadata, Node, SymlinkNode, Tree,
};
use aos_sandbox_core::{MediaType, ObjectDescriptor, ObjectDigest, PathName, descriptor_for_bytes};

use super::*;

fn limits() -> TransportLimits {
    TransportLimits {
        maximum_name_bytes: 255,
        maximum_symlink_bytes: 4096,
        maximum_readdir_bytes: 4096,
        maximum_readdir_entries: 16,
        maximum_write_bytes: 4096,
        maximum_pages: 1,
        time_granularity_ns: 1,
        request_timeout_seconds: 2,
        entry_valid_ns: 0,
        attribute_valid_ns: 0,
    }
}

fn budget() -> RequestBudget {
    RequestBudget::new(4096, 16, 4096).with_forget_entries(16)
}

fn descriptor(media: &str, byte: u8) -> ObjectDescriptor {
    ObjectDescriptor::new(
        MediaType::new(media).unwrap(),
        ObjectDigest::from_bytes([byte; 32]),
        1,
    )
}

#[derive(Default)]
struct Source(Vec<(ObjectDescriptor, Vec<u8>)>);

impl Source {
    fn insert(&mut self, media: &str, bytes: Vec<u8>) -> ObjectDescriptor {
        let descriptor = descriptor_for_bytes(MediaType::new(media).unwrap(), &bytes);
        self.0.push((descriptor.clone(), bytes));
        descriptor
    }
}

impl ObjectSource for Source {
    type Error = std::convert::Infallible;
    type Reader = Cursor<Vec<u8>>;
    fn open(&mut self, descriptor: &ObjectDescriptor) -> Result<Self::Reader, Self::Error> {
        Ok(Cursor::new(
            self.0
                .iter()
                .find(|(key, _)| key == descriptor)
                .unwrap()
                .1
                .clone(),
        ))
    }
}

fn with_connection(
    action: impl FnOnce(
        MetadataConnection<'_, '_, '_, '_>,
        &mut ReplyScratch,
        BorrowedFd<'_>,
        BorrowedFd<'_>,
    ),
) {
    let content = ContentLayout::whole(descriptor("application/vnd.aos.sandbox.content.v1", 3));
    let metadata = FilesystemMetadata::new(0o755, 0, 0, 0, 0, vec![], None).unwrap();
    let mut source = Source::default();
    let child = source.insert(
        "application/vnd.aos.sandbox.directory.v1+cbor",
        encode_directory(&Directory::new(metadata.clone(), vec![]).unwrap()),
    );
    let entries = [
        (b"dir".as_slice(), Node::Directory(child)),
        (
            b"file".as_slice(),
            Node::File(FileNode {
                metadata: metadata.clone(),
                content,
                hardlink_group: None,
            }),
        ),
        (
            b"link".as_slice(),
            Node::Symlink(SymlinkNode::new(metadata.clone(), b"target".to_vec()).unwrap()),
        ),
    ]
    .into_iter()
    .map(|(name, node)| DirectoryEntry {
        name: PathName::new(name.to_vec()).unwrap(),
        node,
    })
    .collect();
    let root = source.insert(
        "application/vnd.aos.sandbox.directory.v1+cbor",
        encode_directory(&Directory::new(metadata, entries).unwrap()),
    );
    let tree = source.insert(
        "application/vnd.aos.sandbox.tree.v1+cbor",
        encode_tree(&Tree::new(root.clone(), vec![]).unwrap()),
    );
    let (_, staged) = TreeCompiler::new(TreeCompileLimits::default())
        .compile(
            &mut source,
            IndexStaging::new(Cursor::new(Vec::new()), 65536, 4096),
            &tree,
            [7; 32],
        )
        .unwrap();
    let (writer, _) = staged.into_parts();
    let bytes = writer.into_inner();
    let artifact = descriptor_for_bytes(MediaType::new(INDEX_MEDIA_TYPE_V3).unwrap(), &bytes);
    let index = validate_index(
        &bytes,
        65536,
        1_048_576,
        &IndexExpectation {
            index: &artifact,
            compiler_abi: [7; 32],
            tree: &tree,
            root: &root,
            tree_features: 0,
        },
    )
    .unwrap();
    let extent = IdMapExtent {
        portable_start: 0,
        presented_start: 0,
        length: 1,
    };
    let plan = PresentationPlan::new(
        IdentityMap::new(vec![extent], vec![extent]).unwrap(),
        AclCapability::Unsupported,
    );
    let presentation =
        PreparedPresentation::prepare(&index, &plan, 1, [8; 32], PresentationLimits::new(4, 0, 2))
            .unwrap();
    let worker_limits = WorkerLimits::new(4096, 16, 4096, 65536).with_maximum_forget_entries(16);
    let worker = MetadataConnection::new(
        &presentation,
        [9; 32],
        InodeTableLimits::new(32, 1_048_576, 64, 16, 16),
        DirectoryHandleLimits::new(8, 16),
        worker_limits,
    )
    .unwrap();
    let mut scratch = ReplyScratch::new(worker_limits).unwrap();
    let (connected, cancellation) = UnixStream::pair().unwrap();
    connected.set_nonblocking(true).unwrap();
    cancellation.set_nonblocking(true).unwrap();
    action(
        worker,
        &mut scratch,
        connected.as_fd(),
        cancellation.as_fd(),
    );
}

unsafe extern "C" fn reply_success(responder: *mut c_void, handle: u64) -> c_int {
    // SAFETY: The fixture passes a unique live u64 as its responder.
    unsafe {
        *responder.cast::<u64>() = handle;
    }
    0
}

unsafe extern "C" fn fixture_run(
    _: c_int,
    _: c_int,
    ops: *const abi::Operations,
    raw: *mut c_void,
    _: *const abi::Limits,
) -> c_int {
    // SAFETY: run_with supplies a live operation table and context for this
    // synchronous fixture; every output below is a distinct local allocation.
    unsafe {
        let ops = &*ops;
        let mut attributes = abi::Attributes::default();
        assert_eq!(
            (ops.lookup)(raw, ROOT_NODE_ID, b"absent".as_ptr(), 6, &mut attributes),
            libc::ENOENT
        );
        assert_eq!(
            (ops.lookup)(raw, ROOT_NODE_ID, b"link".as_ptr(), 4, &mut attributes),
            0
        );
        let link = attributes.node_id;
        let mut target = [0_u8; 16];
        let mut length = 0;
        assert_eq!(
            (ops.readlink)(raw, link, target.as_mut_ptr(), 16, &mut length),
            0
        );
        assert_eq!(&target[..length as usize], b"target");
        assert_eq!((ops.forget)(raw, link, 1), 0);
        assert_eq!((ops.getattr)(raw, link, &mut attributes), libc::ESTALE);
        let mut handle = 0_u64;
        assert_eq!(
            (ops.opendir)(
                raw,
                ROOT_NODE_ID,
                (&mut handle as *mut u64).cast(),
                reply_success
            ),
            0
        );
        let mut entries = [abi::DirectoryEntry::default(); 16];
        let mut names = [0_u8; 4096];
        let mut count = 0;
        let mut names_length = 0;
        // The callback's typed output remains independent of a zero wire limit.
        // C owns complete-entry packing and must return a size error when this
        // nonempty page cannot fit its first entry, rather than claiming EOF.
        assert_eq!(
            (ops.readdir)(
                raw,
                ROOT_NODE_ID,
                handle,
                0,
                0,
                entries.as_mut_ptr(),
                16,
                &mut count,
                names.as_mut_ptr(),
                4096,
                &mut names_length
            ),
            0
        );
        assert_eq!(count, 5);
        assert_eq!(&names[..names_length as usize], b"...dirfilelink");
        assert_eq!((ops.releasedir)(raw, ROOT_NODE_ID, handle), 0);
        (ops.destroy)(raw);
    }
    0
}

#[test]
fn scoped_callbacks_preserve_metadata_handle_and_descriptor_contracts() {
    with_connection(|worker, scratch, connected, cancellation| {
        let result = run_with(
            worker,
            scratch,
            connected,
            cancellation,
            limits(),
            budget(),
            fixture_run,
        )
        .unwrap();
        assert_eq!(result.directory_handles, 0);
        // SAFETY: The borrowed descriptors remain live in with_connection.
        assert!(unsafe { libc::fcntl(connected.as_raw_fd(), libc::F_GETFD) } >= 0);
        // SAFETY: The same ownership check applies to the cancellation descriptor.
        assert!(unsafe { libc::fcntl(cancellation.as_raw_fd(), libc::F_GETFD) } >= 0);
    });
}

unsafe extern "C" fn tiny_budget_run(
    _: c_int,
    _: c_int,
    ops: *const abi::Operations,
    raw: *mut c_void,
    _: *const abi::Limits,
) -> c_int {
    // SAFETY: This fixture supplies bounded outputs for the scoped callbacks.
    unsafe {
        let ops = &*ops;
        let mut handle = 0_u64;
        assert_eq!(
            (ops.opendir)(
                raw,
                ROOT_NODE_ID,
                (&mut handle as *mut u64).cast(),
                reply_success
            ),
            0
        );
        let mut entries = [abi::DirectoryEntry::default(); 1];
        let mut names = [0_u8; 1];
        let mut count = 99;
        let mut length = 99;
        assert_eq!(
            (ops.readdir)(
                raw,
                ROOT_NODE_ID,
                handle,
                2,
                4096,
                entries.as_mut_ptr(),
                1,
                &mut count,
                names.as_mut_ptr(),
                1,
                &mut length
            ),
            libc::ENOMEM
        );
        assert_eq!((count, length), (0, 0));
        (ops.destroy)(raw);
    }
    0
}

#[test]
fn insufficient_typed_page_capacity_cannot_masquerade_as_eof() {
    with_connection(|worker, scratch, connected, cancellation| {
        let result = run_with(
            worker,
            scratch,
            connected,
            cancellation,
            limits(),
            budget(),
            tiny_budget_run,
        )
        .unwrap();
        assert_eq!(result.directory_handles, 1);
    });
}

#[test]
fn installed_transport_rejects_non_fuse_fd_without_consuming_it() {
    with_connection(|worker, scratch, connected, cancellation| {
        assert!(matches!(
            run_metadata(worker, scratch, connected, cancellation, limits(), budget()),
            Err(RunError::Transport(_))
        ));
        // SAFETY: The transport only borrows this live descriptor, even on error.
        assert!(unsafe { libc::fcntl(connected.as_raw_fd(), libc::F_GETFD) } >= 0);
    });
}

unsafe extern "C" fn fatal_run(
    _: c_int,
    _: c_int,
    ops: *const abi::Operations,
    raw: *mut c_void,
    _: *const abi::Limits,
) -> c_int {
    // SAFETY: The fixture uses its unique scoped context and valid local output.
    unsafe {
        assert_eq!(callbacks::inject_panic(raw), -1);
        let mut attributes = abi::Attributes::default();
        assert_eq!(((*ops).getattr)(raw, ROOT_NODE_ID, &mut attributes), -1);
        ((*ops).destroy)(raw);
    }
    0
}

#[test]
fn caught_panic_poisoning_outlives_callbacks_and_cannot_return_success() {
    with_connection(|worker, scratch, connected, cancellation| {
        assert!(matches!(
            run_with(
                worker,
                scratch,
                connected,
                cancellation,
                limits(),
                budget(),
                fatal_run
            ),
            Err(RunError::Integrity)
        ));
    });
}

unsafe extern "C" fn reply_failure(_: *mut c_void, _: u64) -> c_int {
    libc::EIO
}

unsafe extern "C" fn failed_reply_run(
    _: c_int,
    _: c_int,
    ops: *const abi::Operations,
    raw: *mut c_void,
    _: *const abi::Limits,
) -> c_int {
    // SAFETY: The fake responder and context are exclusively borrowed for each
    // callback. Inspection occurs after the callback's mutable borrow ends.
    unsafe {
        let mut responder = 0_u64;
        assert_eq!(
            ((*ops).opendir)(
                raw,
                ROOT_NODE_ID,
                (&mut responder as *mut u64).cast(),
                reply_failure
            ),
            -1
        );
        let context = &*raw.cast::<callbacks::Context<'_, '_, '_, '_, '_>>();
        assert_eq!(context.connection.inode_table().live_directory_handles(), 0);
        assert_eq!(
            context.connection.inode_table().pending_directory_handles(),
            0
        );
        ((*ops).destroy)(raw);
    }
    0
}

#[test]
fn failed_opendir_responder_aborts_pending_handle_and_terminates() {
    with_connection(|worker, scratch, connected, cancellation| {
        assert!(matches!(
            run_with(
                worker,
                scratch,
                connected,
                cancellation,
                limits(),
                budget(),
                failed_reply_run
            ),
            Err(RunError::Integrity)
        ));
    });
}

struct CancellingResponder {
    handle: u64,
    sender: c_int,
}

unsafe extern "C" fn reply_then_cancel(raw: *mut c_void, handle: u64) -> c_int {
    // SAFETY: The fixture provides one live CancellingResponder and a writable
    // UnixStream descriptor; the single byte lives through the synchronous write.
    unsafe {
        let responder = &mut *raw.cast::<CancellingResponder>();
        responder.handle = handle;
        assert_eq!(libc::write(responder.sender, b"x".as_ptr().cast(), 1), 1);
    }
    0
}

unsafe extern "C" fn cancellation_run(
    connected: c_int,
    _: c_int,
    ops: *const abi::Operations,
    raw: *mut c_void,
    _: *const abi::Limits,
) -> c_int {
    // SAFETY: The borrowed connected stream is paired with cancellation in this
    // fixture; callbacks and the later read-only context inspection do not overlap.
    unsafe {
        let mut responder = CancellingResponder {
            handle: 0,
            sender: connected,
        };
        assert_eq!(
            ((*ops).opendir)(
                raw,
                ROOT_NODE_ID,
                (&mut responder as *mut CancellingResponder).cast(),
                reply_then_cancel
            ),
            0
        );
        let context = &*raw.cast::<callbacks::Context<'_, '_, '_, '_, '_>>();
        assert!(
            context
                .connection
                .inode_table()
                .resolve_active_directory_for_node(responder.handle, ROOT_NODE_ID)
                .is_ok()
        );
        let mut attributes = abi::Attributes::default();
        assert_eq!(
            ((*ops).getattr)(raw, ROOT_NODE_ID, &mut attributes),
            libc::EINTR
        );
        ((*ops).destroy)(raw);
    }
    0
}

#[test]
fn cancellation_after_successful_reply_cannot_skip_handle_commit() {
    with_connection(|worker, scratch, connected, cancellation| {
        let result = run_with(
            worker,
            scratch,
            connected,
            cancellation,
            limits(),
            budget(),
            cancellation_run,
        )
        .unwrap();
        assert_eq!(result.directory_handles, 1);
        assert_eq!(result.pending_directory_handles, 0);
    });
}

unsafe extern "C" fn failed_release_run(
    _: c_int,
    _: c_int,
    ops: *const abi::Operations,
    raw: *mut c_void,
    _: *const abi::Limits,
) -> c_int {
    // SAFETY: The fixture supplies a live unique responder and scoped context.
    unsafe {
        let mut handle = 0_u64;
        assert_eq!(
            ((*ops).opendir)(
                raw,
                ROOT_NODE_ID,
                (&mut handle as *mut u64).cast(),
                reply_success
            ),
            0
        );
        assert_eq!(((*ops).releasedir)(raw, u64::MAX, handle), -1);
        let mut attributes = abi::Attributes::default();
        assert_eq!(((*ops).getattr)(raw, ROOT_NODE_ID, &mut attributes), -1);
        ((*ops).destroy)(raw);
    }
    0
}

#[test]
fn unretryable_release_failure_discards_the_connection() {
    with_connection(|worker, scratch, connected, cancellation| {
        assert!(matches!(
            run_with(
                worker,
                scratch,
                connected,
                cancellation,
                limits(),
                budget(),
                failed_release_run
            ),
            Err(RunError::Integrity)
        ));
    });
}
