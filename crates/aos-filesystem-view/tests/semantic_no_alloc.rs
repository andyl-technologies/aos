//! Allocation regression for public borrowed structural-index semantics.

#![deny(unsafe_op_in_unsafe_fn)]

use std::alloc::{GlobalAlloc, Layout, System};
use std::convert::Infallible;
use std::hint::black_box;
use std::io::Cursor;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

use aos_filesystem_view::{
    DirectoryHandleLimits, INDEX_MEDIA_TYPE, IndexContentView, IndexExpectation, IndexNodeBodyView,
    IndexStaging, InodeError, InodeTable, InodeTableLimits, ObjectSource, ROOT_NODE_ID,
    TreeCompileLimits, TreeCompiler, validate_index,
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
