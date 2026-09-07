//! Allocation regression for public borrowed structural-index semantics.

#![deny(unsafe_op_in_unsafe_fn)]

use std::alloc::{GlobalAlloc, Layout, System};
use std::convert::Infallible;
use std::hint::black_box;
use std::io::Cursor;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

use aos_filesystem_view::{
    AclCapability, DirectoryHandleLimits, ForgetRequest, INDEX_MEDIA_TYPE, IdMapExtent,
    IdentityMap, IndexContentView, IndexExpectation, IndexNodeBodyView, IndexStaging, InitRequest,
    InodeError, InodeTable, InodeTableLimits, LookupReply, MetadataConnection,
    MetadataTransportLimits, ObjectSource, PreparedPresentation, PresentationError,
    PresentationLimits, PresentationPlan, ROOT_NODE_ID, ReplyScratch, RequestBudget,
    TreeCompileLimits, TreeCompiler, Uninterrupted, WorkerError, WorkerLimits, validate_index,
};
use aos_sandbox_core::format::{encode_directory, encode_tree};
use aos_sandbox_core::model::{
    Acl, AclEntry, ContentLayout, Directory, DirectoryEntry, Extent, FileNode, FilesystemMetadata,
    Node, SparseContent, SymlinkNode, Tree, Xattr,
};
use aos_sandbox_core::{
    FeatureRef, MediaType, ObjectDescriptor, ObjectDigest, PathName, descriptor_for_bytes,
};

// This harness-free binary runs only `main` and starts no threads. Global
// atomics therefore observe exactly the synchronous operation inside the
// tracking guard, without test-harness or peer-test allocation races.
static TRACKING: AtomicBool = AtomicBool::new(false);
static ALLOCATIONS: AtomicUsize = AtomicUsize::new(0);

struct CountingAllocator;

#[global_allocator]
static ALLOCATOR: CountingAllocator = CountingAllocator;

// SAFETY: Every operation delegates to `System` with the original layout and
// pointer. The additional atomics neither allocate nor alter allocator state.
unsafe impl GlobalAlloc for CountingAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        if TRACKING.load(Ordering::SeqCst) {
            ALLOCATIONS.fetch_add(1, Ordering::SeqCst);
        }
        // SAFETY: The caller supplied `layout` under `GlobalAlloc::alloc`'s
        // contract, and it is forwarded unchanged to the system allocator.
        unsafe { System.alloc(layout) }
    }

    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        if TRACKING.load(Ordering::SeqCst) {
            ALLOCATIONS.fetch_add(1, Ordering::SeqCst);
        }
        // SAFETY: The caller supplied `layout` under
        // `GlobalAlloc::alloc_zeroed`'s contract, and it is forwarded unchanged.
        unsafe { System.alloc_zeroed(layout) }
    }

    unsafe fn dealloc(&self, pointer: *mut u8, layout: Layout) {
        // SAFETY: The caller supplied a pointer/layout pair satisfying
        // `GlobalAlloc::dealloc`, and both are forwarded unchanged.
        unsafe { System.dealloc(pointer, layout) }
    }

    unsafe fn realloc(&self, pointer: *mut u8, layout: Layout, size: usize) -> *mut u8 {
        if TRACKING.load(Ordering::SeqCst) {
            ALLOCATIONS.fetch_add(1, Ordering::SeqCst);
        }
        // SAFETY: The caller supplied the pointer, old layout, and new size
        // under `GlobalAlloc::realloc`'s contract; all are forwarded unchanged.
        unsafe { System.realloc(pointer, layout, size) }
    }
}

struct TrackingGuard;

impl TrackingGuard {
    fn begin() -> Self {
        ALLOCATIONS.store(0, Ordering::SeqCst);
        TRACKING.store(true, Ordering::SeqCst);
        Self
    }
}

impl Drop for TrackingGuard {
    fn drop(&mut self) {
        TRACKING.store(false, Ordering::SeqCst);
    }
}

fn measure_allocations<T>(operation: impl FnOnce() -> T) -> (T, usize) {
    let guard = TrackingGuard::begin();
    let result = operation();
    drop(guard);
    let allocations = ALLOCATIONS.load(Ordering::SeqCst);
    (result, allocations)
}

#[derive(Default)]
struct MemorySource(Vec<(ObjectDescriptor, Vec<u8>)>);

impl MemorySource {
    fn insert(&mut self, media_type: &str, bytes: Vec<u8>) -> ObjectDescriptor {
        let media_type =
            MediaType::new(media_type).unwrap_or_else(|error| panic!("media type failed: {error}"));
        let descriptor = descriptor_for_bytes(media_type, &bytes);
        self.0.push((descriptor.clone(), bytes));
        descriptor
    }
}

impl ObjectSource for MemorySource {
    type Error = Infallible;
    type Reader = Cursor<Vec<u8>>;

    fn open(&mut self, descriptor: &ObjectDescriptor) -> Result<Self::Reader, Self::Error> {
        Ok(Cursor::new(
            self.0
                .iter()
                .find(|(candidate, _)| candidate == descriptor)
                .map(|(_, bytes)| bytes.clone())
                .unwrap_or_default(),
        ))
    }
}

fn metadata(mode: u16) -> FilesystemMetadata {
    FilesystemMetadata::new(mode, 0, 0, 0, 0, Vec::new(), None)
        .unwrap_or_else(|error| panic!("metadata failed: {error}"))
}

fn fixture() -> (Vec<u8>, ObjectDescriptor, ObjectDescriptor) {
    let content_media = MediaType::new("application/vnd.aos.sandbox.content.v1")
        .unwrap_or_else(|error| panic!("content media failed: {error}"));
    let first = ObjectDescriptor::new(content_media.clone(), ObjectDigest::from_bytes([3; 32]), 3);
    let second = ObjectDescriptor::new(content_media, ObjectDigest::from_bytes([4; 32]), 4);
    let sparse = SparseContent::new(
        20,
        vec![
            Extent::new(2, 3, first).unwrap_or_else(|error| panic!("extent failed: {error}")),
            Extent::new(10, 4, second).unwrap_or_else(|error| panic!("extent failed: {error}")),
        ],
    )
    .unwrap_or_else(|error| panic!("sparse content failed: {error}"));
    let acl = Acl::new(vec![
        AclEntry::UserObject(7),
        AclEntry::NamedUser {
            uid: 42,
            permissions: 6,
        },
        AclEntry::GroupObject(5),
        AclEntry::Mask(5),
        AclEntry::Other(4),
    ])
    .unwrap_or_else(|error| panic!("ACL failed: {error}"));
    let file_metadata = FilesystemMetadata::new(
        0o754,
        7,
        8,
        9,
        10,
        vec![
            Xattr::new(b"a".to_vec(), Vec::new())
                .unwrap_or_else(|error| panic!("xattr failed: {error}")),
            Xattr::new(b"b".to_vec(), b"value".to_vec())
                .unwrap_or_else(|error| panic!("xattr failed: {error}")),
        ],
        Some(acl),
    )
    .unwrap_or_else(|error| panic!("file metadata failed: {error}"));
    let file = Node::File(FileNode {
        metadata: file_metadata,
        content: ContentLayout::Sparse(sparse),
        hardlink_group: None,
    });
    let link = Node::Symlink(
        SymlinkNode::new(metadata(0o777), b"target".to_vec())
            .unwrap_or_else(|error| panic!("symlink failed: {error}")),
    );
    let directory = Directory::new(
        metadata(0o755),
        vec![
            DirectoryEntry {
                name: PathName::new(b"file".to_vec())
                    .unwrap_or_else(|error| panic!("file name failed: {error}")),
                node: file,
            },
            DirectoryEntry {
                name: PathName::new(b"link".to_vec())
                    .unwrap_or_else(|error| panic!("link name failed: {error}")),
                node: link,
            },
        ],
    )
    .unwrap_or_else(|error| panic!("directory failed: {error}"));

    let mut source = MemorySource::default();
    let root = source.insert(
        "application/vnd.aos.sandbox.directory.v1+cbor",
        encode_directory(&directory),
    );
    let feature = FeatureRef::new("aos.sandbox.metadata.posix-acl", 1, 0)
        .unwrap_or_else(|error| panic!("feature failed: {error}"));
    let tree = Tree::new(root.clone(), vec![feature])
        .unwrap_or_else(|error| panic!("tree failed: {error}"));
    let tree = source.insert(
        "application/vnd.aos.sandbox.tree.v1+cbor",
        encode_tree(&tree),
    );
    let limits = TreeCompileLimits::default();
    let staging = IndexStaging::new(
        Cursor::new(Vec::new()),
        limits.index_bytes,
        limits.index_record_bytes,
    );
    let (_, staged) = TreeCompiler::new(limits)
        .compile(&mut source, staging, &tree, [9; 32])
        .unwrap_or_else(|error| panic!("compile failed: {error}"));
    let (writer, _) = staged.into_parts();
    (writer.into_inner(), tree, root)
}

fn main() {
    let (bytes, tree, root_descriptor) = fixture();
    let index_media =
        MediaType::new(INDEX_MEDIA_TYPE).unwrap_or_else(|error| panic!("media failed: {error}"));
    let index_descriptor = descriptor_for_bytes(index_media, &bytes);
    let index = validate_index(
        &bytes,
        u64::try_from(bytes.len()).unwrap_or_else(|_| panic!("index length does not fit u64")),
        u64::MAX,
        &IndexExpectation {
            index: &index_descriptor,
            compiler_abi: [9; 32],
            tree: &tree,
            root: &root_descriptor,
            tree_features: 1,
        },
    )
    .unwrap_or_else(|error| panic!("validation failed: {error}"));
    let root = index
        .root()
        .unwrap_or_else(|error| panic!("root failed: {error}"));
    let file_name =
        PathName::new(b"file".to_vec()).unwrap_or_else(|error| panic!("name failed: {error}"));
    let file = index
        .lookup_child(&root, &file_name)
        .unwrap_or_else(|error| panic!("lookup failed: {error}"))
        .unwrap_or_else(|| panic!("file missing"));
    let link_name =
        PathName::new(b"link".to_vec()).unwrap_or_else(|error| panic!("name failed: {error}"));
    let link = index
        .lookup_child(&root, &link_name)
        .unwrap_or_else(|error| panic!("lookup failed: {error}"))
        .unwrap_or_else(|| panic!("link missing"));
    let uid = (0_u32..64)
        .map(|portable_start| IdMapExtent {
            portable_start,
            presented_start: (63 - portable_start) * 2,
            length: 1,
        })
        .collect();
    let gid = (0_u32..64)
        .map(|portable_start| IdMapExtent {
            portable_start,
            presented_start: 1_000 + (63 - portable_start) * 2,
            length: 1,
        })
        .collect();
    let (validated_map, map_validation_allocations) =
        measure_allocations(|| IdentityMap::new(uid, gid));
    validated_map.unwrap_or_else(|error| panic!("large identity map failed: {error}"));
    assert_eq!(map_validation_allocations, 0);

    let identity = IdentityMap::new(
        vec![IdMapExtent {
            portable_start: 0,
            presented_start: 1_000,
            length: 100,
        }],
        vec![IdMapExtent {
            portable_start: 0,
            presented_start: 2_000,
            length: 100,
        }],
    )
    .unwrap_or_else(|error| panic!("identity map failed: {error}"));
    let plan = PresentationPlan::new(identity, AclCapability::Posix);
    let (prepared, preparation_allocations) = measure_allocations(|| {
        PreparedPresentation::prepare(&index, &plan, 1, [7; 32], PresentationLimits::new(3, 5, 2))
    });
    let prepared = prepared.unwrap_or_else(|error| panic!("preparation failed: {error}"));
    assert_eq!(preparation_allocations, 0);

    let (transport_result, transport_allocations) = measure_allocations(|| {
        prepared.validate_transport_representation(MetadataTransportLimits {
            maximum_records: 3,
            maximum_uid: u32::MAX,
            maximum_gid: u32::MAX,
            maximum_link_count: u32::MAX,
            maximum_size: u64::MAX,
            allocation_unit_bytes: 512,
            maximum_allocation_units: u64::MAX,
            minimum_timestamp_seconds: i64::MIN,
            maximum_timestamp_seconds: i64::MAX,
            maximum_name_bytes: u64::MAX,
            maximum_symlink_bytes: u64::MAX,
            maximum_directory_cookie: u64::MAX,
        })
    });
    transport_result.unwrap_or_else(|error| panic!("transport admission failed: {error}"));
    assert_eq!(transport_allocations, 0);

    let (hot_result, hot_allocations) = measure_allocations(|| {
        for record in index.records() {
            black_box(record?);
        }
        let attributes = prepared.present(&file)?;
        black_box((
            attributes.record_id(),
            attributes.kind(),
            attributes.mode(),
            attributes.uid(),
            attributes.gid(),
            attributes.nlink(),
            attributes.size(),
            attributes.mtime_seconds(),
            attributes.mtime_nanos(),
        ));
        for xattr in attributes.xattrs() {
            black_box(xattr?);
        }
        if let Some(acl) = attributes.acl() {
            for entry in acl.iter() {
                black_box(entry?);
            }
        }
        Ok::<(), PresentationError>(())
    });
    hot_result.unwrap_or_else(|error| panic!("hot presentation failed: {error}"));
    assert_eq!(hot_allocations, 0);

    let worker_limits =
        WorkerLimits::new(4096, 16, 1024, 1_048_576).with_maximum_forget_entries(16);
    let worker_budget = RequestBudget::new(4096, 16, 1024).with_forget_entries(16);
    let mut worker = MetadataConnection::new(
        &prepared,
        [60; 32],
        InodeTableLimits::new(16, 1_048_576, 16, 16, 8),
        DirectoryHandleLimits::new(2, 8),
        worker_limits,
    )
    .unwrap_or_else(|error| panic!("worker failed: {error}"));
    worker
        .initialize(
            InitRequest {
                batch_forget: true,
                directory_handles: true,
                readdir_plus: false,
            },
            worker_budget,
            &Uninterrupted,
        )
        .unwrap_or_else(|error| panic!("worker initialization failed: {error}"));
    let LookupReply::Positive {
        attributes: link_attributes,
        ..
    } = worker
        .lookup(ROOT_NODE_ID, b"link", worker_budget, &Uninterrupted)
        .unwrap_or_else(|error| panic!("worker link lookup failed: {error}"))
    else {
        panic!("worker link lookup was negative");
    };
    let mut pending_directory = worker
        .prepare_opendir(ROOT_NODE_ID, worker_budget, &Uninterrupted)
        .unwrap_or_else(|error| panic!("worker OPENDIR failed: {error}"));
    let (directory, commit_allocations) =
        measure_allocations(|| worker.commit_opendir_after_reply(&mut pending_directory));
    let directory = directory
        .unwrap_or_else(|error| panic!("worker OPENDIR post-reply commit failed: {error}"));
    assert_eq!(commit_allocations, 0);
    let mut worker_scratch = ReplyScratch::new(worker_limits)
        .unwrap_or_else(|error| panic!("worker scratch failed: {error}"));
    let (worker_result, worker_allocations) = measure_allocations(|| {
        black_box(worker.getattr(ROOT_NODE_ID, worker_budget, &Uninterrupted)?);
        black_box(worker.lookup(
            ROOT_NODE_ID,
            black_box(b"absent"),
            worker_budget,
            &Uninterrupted,
        )?);
        black_box(
            worker
                .readlink(
                    link_attributes.node_id,
                    worker_budget,
                    &mut worker_scratch,
                    &Uninterrupted,
                )?
                .target(),
        );
        for entry in worker
            .readdir_for_node(
                ROOT_NODE_ID,
                directory.handle.get(),
                0,
                worker_budget,
                &mut worker_scratch,
                &Uninterrupted,
            )?
            .entries()
        {
            black_box(entry);
        }
        black_box(worker.forget_one(
            ForgetRequest::new(link_attributes.node_id, 1),
            worker_budget,
            &Uninterrupted,
        )?);
        worker.releasedir_for_node(ROOT_NODE_ID, directory.handle.get(), &Uninterrupted)?;
        Ok::<(), WorkerError>(())
    });
    worker_result.unwrap_or_else(|error| panic!("worker access failed: {error}"));
    assert_eq!(worker_allocations, 0);

    let mut inode_table = InodeTable::new_with_directory_limits(
        &index,
        [61; 32],
        InodeTableLimits::new(16, 1_048_576, 16, 16, 8),
        DirectoryHandleLimits::new(2, 8),
    )
    .unwrap_or_else(|error| panic!("inode table failed: {error}"));
    let mut directory_reservation = inode_table
        .reserve_directory(ROOT_NODE_ID)
        .unwrap_or_else(|error| panic!("directory reserve failed: {error}"));
    let directory_raw = directory_reservation.raw_protocol_handle();
    let directory_handle = inode_table
        .activate_directory(&mut directory_reservation)
        .unwrap_or_else(|error| panic!("directory activation failed: {error}"));

    let (result, allocations) = measure_allocations(|| {
        PathName::validate(black_box(b"file"))
            .map_err(|_| aos_filesystem_view::IndexError::InvalidRecord)?;
        let file_from_bytes = index
            .lookup_child_bytes(&root, black_box(b"file"))?
            .ok_or(aos_filesystem_view::IndexError::InvalidRecord)?;
        black_box(file_from_bytes);

        let root_semantics = index.record_semantics(&root)?;
        let IndexNodeBodyView::Directory { descriptor } = root_semantics.body() else {
            return Err(aos_filesystem_view::IndexError::InvalidRecord.into());
        };
        black_box(descriptor.media_type());

        let semantics = index.record_semantics(&file)?;
        for xattr in semantics.xattrs() {
            let xattr = xattr?;
            black_box((xattr.name(), xattr.value()));
        }
        if let Some(acl) = semantics.acl() {
            for entry in acl {
                black_box(entry?);
            }
        }
        let IndexNodeBodyView::File(file) = semantics.body() else {
            return Err(aos_filesystem_view::IndexError::InvalidRecord.into());
        };
        let IndexContentView::Sparse(sparse) = file.content() else {
            return Err(aos_filesystem_view::IndexError::InvalidRecord.into());
        };
        black_box(sparse.logical_size());
        for extent in sparse.extents() {
            let extent = extent?;
            black_box((extent.offset(), extent.length(), extent.content()));
        }

        let link = index.record_semantics(&link)?;
        let IndexNodeBodyView::Symlink { target } = link.body() else {
            return Err(aos_filesystem_view::IndexError::InvalidRecord.into());
        };
        black_box(target);
        let resolved = inode_table.resolve_active_directory(black_box(directory_raw))?;
        for entry in inode_table.directory_entries(resolved, black_box(0))? {
            let entry = entry?;
            black_box((entry.name(), entry.next_cookie()));
        }
        black_box(directory_handle);
        Ok::<(), InodeError>(())
    });

    result.unwrap_or_else(|error| panic!("semantic access failed: {error}"));
    assert_eq!(allocations, 0);
}
