//! Tests for bounded backend-neutral metadata request execution.

use std::cell::Cell;
use std::io::Cursor;

use aos_sandbox_core::model::{ContentLayout, FilesystemMetadata};
use aos_sandbox_core::{MediaType, ObjectDescriptor, ObjectDigest, descriptor_for_bytes};

use super::*;
use crate::index::{IndexNode, IndexRecord, StructuralIndexBuilder};
use crate::{
    AclCapability, IdMapExtent, IdentityMap, IndexExpectation, IndexStaging, PresentationLimits,
    PresentationPlan, ROOT_NODE_ID, validate_index,
};

struct Fixture {
    bytes: Vec<u8>,
    tree: ObjectDescriptor,
    root: ObjectDescriptor,
}

impl Fixture {
    fn validate(&self) -> ValidatedIndex<'_> {
        let media = MediaType::new(crate::INDEX_MEDIA_TYPE_V3)
            .unwrap_or_else(|error| panic!("media type failed: {error}"));
        let descriptor = descriptor_for_bytes(media, &self.bytes);
        validate_index(
            &self.bytes,
            64 * 1024,
            1_048_576,
            &IndexExpectation {
                index: &descriptor,
                compiler_abi: [7; 32],
                tree: &self.tree,
                root: &self.root,
                tree_features: 0,
            },
        )
        .unwrap_or_else(|error| panic!("validation failed: {error}"))
    }
}

fn fixture() -> Fixture {
    let tree = descriptor("application/vnd.aos.sandbox.tree.v1+cbor", [1; 32]);
    let root = descriptor("application/vnd.aos.sandbox.directory.v1+cbor", [2; 32]);
    let content_descriptor = descriptor("application/vnd.aos.sandbox.content.v1", [3; 32]);
    let content = ContentLayout::whole(content_descriptor);
    let directory_metadata = FilesystemMetadata::new(0o755, 10, 20, 30, 40, Vec::new(), None)
        .unwrap_or_else(|error| panic!("directory metadata failed: {error}"));
    let file_metadata = FilesystemMetadata::new(0o640, 11, 21, 31, 41, Vec::new(), None)
        .unwrap_or_else(|error| panic!("file metadata failed: {error}"));
    let link_metadata = FilesystemMetadata::new(0o777, 12, 22, 32, 42, Vec::new(), None)
        .unwrap_or_else(|error| panic!("link metadata failed: {error}"));
    let staging = IndexStaging::new(Cursor::new(Vec::new()), 64 * 1024, 4096);
    let mut builder =
        StructuralIndexBuilder::new_v3(staging, [7; 32], tree.clone(), root.clone(), 0)
            .unwrap_or_else(|error| panic!("builder failed: {error}"));
    builder
        .push(&IndexRecord {
            parent: u64::MAX,
            depth: 0,
            sibling_ordinal: 0,
            name: &[],
            metadata: &directory_metadata,
            node: IndexNode::Directory { descriptor: &root },
        })
        .unwrap_or_else(|error| panic!("root push failed: {error}"));
    builder
        .push(&IndexRecord {
            parent: 0,
            depth: 1,
            sibling_ordinal: 0,
            name: b"dir",
            metadata: &directory_metadata,
            node: IndexNode::Directory { descriptor: &root },
        })
        .unwrap_or_else(|error| panic!("directory push failed: {error}"));
    builder
        .push(&IndexRecord {
            parent: 0,
            depth: 1,
            sibling_ordinal: 1,
            name: b"file",
            metadata: &file_metadata,
            node: IndexNode::File {
                content: &content,
                hardlink_group: None,
            },
        })
        .unwrap_or_else(|error| panic!("file push failed: {error}"));
    builder
        .push(&IndexRecord {
            parent: 0,
            depth: 1,
            sibling_ordinal: 2,
            name: b"link",
            metadata: &link_metadata,
            node: IndexNode::Symlink { target: b"target" },
        })
        .unwrap_or_else(|error| panic!("link push failed: {error}"));
    builder
        .push(&IndexRecord {
            parent: 0,
            depth: 1,
            sibling_ordinal: 3,
            name: &[0x80],
            metadata: &file_metadata,
            node: IndexNode::File {
                content: &content,
                hardlink_group: None,
            },
        })
        .unwrap_or_else(|error| panic!("byte-name push failed: {error}"));
    let (writer, _) = builder
        .finish()
        .unwrap_or_else(|error| panic!("finish failed: {error}"))
        .into_parts();
    Fixture {
        bytes: writer.into_inner(),
        tree,
        root,
    }
}

fn descriptor(media: &str, digest: [u8; 32]) -> ObjectDescriptor {
    ObjectDescriptor::new(
        MediaType::new(media).unwrap_or_else(|error| panic!("media failed: {error}")),
        ObjectDigest::from_bytes(digest),
        0,
    )
}

fn plan() -> PresentationPlan {
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
    PresentationPlan::new(identity, AclCapability::Unsupported)
}

fn worker_limits() -> WorkerLimits {
    WorkerLimits::new(4096, 16, 1024, 1_048_576).with_maximum_forget_entries(16)
}

fn inode_limits() -> InodeTableLimits {
    InodeTableLimits::new(32, 1_048_576, 64, 16, 16)
}

fn full_budget() -> RequestBudget {
    RequestBudget::new(4096, 16, 1024).with_forget_entries(16)
}

fn initialize(worker: &mut MetadataConnection<'_, '_, '_, '_>) {
    worker
        .initialize(
            InitRequest {
                batch_forget: true,
                directory_handles: true,
                readdir_plus: true,
            },
            full_budget(),
            &Uninterrupted,
        )
        .unwrap_or_else(|error| panic!("initialization failed: {error}"));
}

struct StopAt {
    checkpoint: RequestCheckpoint,
    state: RequestControlState,
}

impl RequestControl for StopAt {
    fn state(&self, checkpoint: RequestCheckpoint) -> RequestControlState {
        if checkpoint == self.checkpoint {
            self.state
        } else {
            RequestControlState::Continue
        }
    }
}

struct StopOnNth {
    checkpoint: RequestCheckpoint,
    remaining: Cell<usize>,
    state: RequestControlState,
}

impl RequestControl for StopOnNth {
    fn state(&self, checkpoint: RequestCheckpoint) -> RequestControlState {
        if checkpoint != self.checkpoint {
            return RequestControlState::Continue;
        }
        let remaining = self.remaining.get();
        if remaining == 0 {
            self.state
        } else {
            self.remaining.set(remaining - 1);
            RequestControlState::Continue
        }
    }
}

fn metadata_transport_limits() -> MetadataTransportLimits {
    MetadataTransportLimits {
        maximum_records: 5,
        maximum_uid: u32::MAX,
        maximum_gid: u32::MAX,
        maximum_link_count: u32::MAX,
        maximum_size: u64::MAX,
        allocation_unit_bytes: 512,
        maximum_allocation_units: u64::MAX,
        minimum_timestamp_seconds: i64::MIN,
        maximum_timestamp_seconds: i64::MAX,
        maximum_name_bytes: 255,
        maximum_symlink_bytes: 4096,
        maximum_directory_cookie: i64::MAX as u64,
    }
}

#[test]
fn transport_preflight_is_controlled_and_does_not_initialize_connection() {
    let fixture = fixture();
    let index = fixture.validate();
    let plan = plan();
    let presentation =
        PreparedPresentation::prepare(&index, &plan, 1, [89; 32], PresentationLimits::new(5, 0, 2))
            .unwrap_or_else(|error| panic!("presentation failed: {error}"));
    let make_worker = |key| {
        MetadataConnection::new(
            &presentation,
            key,
            inode_limits(),
            DirectoryHandleLimits::new(8, 16),
            worker_limits(),
        )
        .unwrap_or_else(|error| panic!("worker failed: {error}"))
    };

    for (checkpoint, state, interrupted) in [
        (
            RequestCheckpoint::BeforeWork,
            RequestControlState::Cancelled,
            true,
        ),
        (
            RequestCheckpoint::DuringReadOnlyWork,
            RequestControlState::DeadlineExpired,
            false,
        ),
        (
            RequestCheckpoint::BeforeCommit,
            RequestControlState::Cancelled,
            true,
        ),
    ] {
        let worker = make_worker([checkpoint as u8; 32]);
        let result = worker.validate_transport_representation(
            metadata_transport_limits(),
            &StopAt { checkpoint, state },
        );
        if interrupted {
            assert!(matches!(result, Err(MetadataTransportError::Interrupted)));
        } else {
            assert!(matches!(result, Err(MetadataTransportError::TimedOut)));
        }
    }

    let mut worker = make_worker([90; 32]);
    worker
        .validate_transport_representation(metadata_transport_limits(), &Uninterrupted)
        .unwrap_or_else(|error| panic!("transport preflight failed: {error}"));
    initialize(&mut worker);
}

#[test]
fn opendir_synchronous_reply_commits_once_without_post_reply_cancellation() {
    let fixture = fixture();
    let index = fixture.validate();
    let plan = plan();
    let presentation =
        PreparedPresentation::prepare(&index, &plan, 1, [93; 32], PresentationLimits::new(5, 0, 2))
            .unwrap_or_else(|error| panic!("presentation failed: {error}"));
    let make_worker = |key| {
        MetadataConnection::new(
            &presentation,
            key,
            inode_limits(),
            DirectoryHandleLimits::new(8, 16),
            worker_limits(),
        )
        .unwrap_or_else(|error| panic!("worker failed: {error}"))
    };
    let mut worker = make_worker([94; 32]);
    initialize(&mut worker);
    let mut pending = worker
        .prepare_opendir(ROOT_NODE_ID, full_budget(), &Uninterrupted)
        .unwrap_or_else(|error| panic!("prepare failed: {error}"));
    let raw = pending.raw_handle();

    // A synchronous responder observes an unavailable reservation, publishes
    // its raw handle, and then reports that cancellation has arrived.
    let published = Cell::new(None);
    let cancelled = Cell::new(false);
    let reply = || {
        assert!(worker.inode_table().resolve_active_directory(raw).is_err());
        published.set(Some(raw));
        cancelled.set(true);
        Ok::<(), ()>(())
    };
    assert_eq!(reply(), Ok(()));
    assert!(cancelled.get());
    let opened = worker
        .commit_opendir_after_reply(&mut pending)
        .unwrap_or_else(|error| panic!("post-reply commit failed: {error}"));
    assert_eq!(published.get(), Some(opened.handle.get()));
    assert_eq!(worker.inode_table().pending_directory_handles(), 0);
    let mut scratch = ReplyScratch::new(worker_limits())
        .unwrap_or_else(|error| panic!("scratch failed: {error}"));
    assert!(
        worker
            .readdir_for_node(
                ROOT_NODE_ID,
                raw,
                0,
                full_budget(),
                &mut scratch,
                &Uninterrupted
            )
            .is_ok()
    );
    // A replay is fatal to this connection even though its original handle
    // remains active; teardown discards it without another protocol reply.
    assert!(matches!(
        worker.commit_opendir_after_reply(&mut pending),
        Err(WorkerError::Stale)
    ));
    assert_eq!(worker.teardown().directory_handles, 1);

    let mut worker = make_worker([95; 32]);
    initialize(&mut worker);
    let mut rejected = worker
        .prepare_opendir(ROOT_NODE_ID, full_budget(), &Uninterrupted)
        .unwrap_or_else(|error| panic!("prepare failed: {error}"));
    let rejected_raw = rejected.raw_handle();
    let failed_reply = || Err::<(), ()>(());
    assert_eq!(failed_reply(), Err(()));
    worker
        .abort_opendir(&mut rejected)
        .unwrap_or_else(|error| panic!("abort failed: {error}"));
    assert!(
        worker
            .inode_table()
            .resolve_active_directory(rejected_raw)
            .is_err()
    );
    assert_eq!(worker.inode_table().live_directory_handles(), 0);
    assert_eq!(worker.inode_table().pending_directory_handles(), 0);

    let mut foreign = make_worker([96; 32]);
    initialize(&mut foreign);
    let mut pending = worker
        .prepare_opendir(ROOT_NODE_ID, full_budget(), &Uninterrupted)
        .unwrap_or_else(|error| panic!("prepare failed: {error}"));
    assert!(matches!(
        foreign.commit_opendir_after_reply(&mut pending),
        Err(WorkerError::Stale)
    ));
    assert_eq!(foreign.teardown().directory_handles, 0);
    assert_eq!(worker.teardown().pending_directory_handles, 1);
}

#[test]
fn singleton_forget_and_directory_node_association_are_independent_of_batching() {
    let fixture = fixture();
    let index = fixture.validate();
    let plan = plan();
    let presentation =
        PreparedPresentation::prepare(&index, &plan, 1, [91; 32], PresentationLimits::new(5, 0, 2))
            .unwrap_or_else(|error| panic!("presentation failed: {error}"));
    let mut worker = MetadataConnection::new(
        &presentation,
        [92; 32],
        inode_limits(),
        DirectoryHandleLimits::new(8, 16),
        worker_limits(),
    )
    .unwrap_or_else(|error| panic!("worker failed: {error}"));
    assert!(matches!(
        worker.forget_one(
            ForgetRequest::new(ROOT_NODE_ID, 1),
            full_budget(),
            &Uninterrupted
        ),
        Err(WorkerError::InvalidArgument)
    ));
    worker
        .initialize(
            InitRequest {
                batch_forget: false,
                directory_handles: true,
                readdir_plus: false,
            },
            full_budget(),
            &Uninterrupted,
        )
        .unwrap_or_else(|error| panic!("init failed: {error}"));
    let LookupReply::Positive { attributes, .. } = worker
        .lookup(ROOT_NODE_ID, b"dir", full_budget(), &Uninterrupted)
        .unwrap_or_else(|error| panic!("lookup failed: {error}"))
    else {
        panic!("directory absent");
    };
    let node = attributes.node_id;
    let mut pending = worker
        .prepare_opendir(node, full_budget(), &Uninterrupted)
        .unwrap_or_else(|error| panic!("prepare failed: {error}"));
    let raw = pending.raw_handle();
    assert!(
        worker
            .inode_table()
            .resolve_active_directory_for_node(raw, node)
            .is_err()
    );
    worker
        .publish_opendir(&mut pending)
        .unwrap_or_else(|error| panic!("publish failed: {error}"));
    let mut scratch = ReplyScratch::new(worker_limits())
        .unwrap_or_else(|error| panic!("scratch failed: {error}"));
    for wrong_node in [0, ROOT_NODE_ID, u64::MAX] {
        assert!(matches!(
            worker.readdir_for_node(
                wrong_node,
                raw,
                0,
                full_budget(),
                &mut scratch,
                &Uninterrupted
            ),
            Err(WorkerError::Stale)
        ));
        assert_eq!(
            worker.releasedir_for_node(wrong_node, raw, &Uninterrupted),
            Err(WorkerError::Stale)
        );
    }
    assert_eq!(worker.inode_table().live_directory_handles(), 1);
    assert!(matches!(
        worker.forget(
            &mut [ForgetRequest::new(node, 1)],
            full_budget(),
            &Uninterrupted
        ),
        Err(WorkerError::OperationNotSupported)
    ));
    let references = worker.inode_table().total_lookup_references();
    assert!(matches!(
        worker.forget_one(
            ForgetRequest::new(node, 1),
            full_budget().with_forget_entries(0),
            &Uninterrupted
        ),
        Err(WorkerError::ResourceExhausted)
    ));
    assert!(matches!(
        worker.forget_one(
            ForgetRequest::new(node, 1),
            full_budget(),
            &StopAt {
                checkpoint: RequestCheckpoint::BeforeCommit,
                state: RequestControlState::Cancelled
            }
        ),
        Err(WorkerError::Interrupted)
    ));
    assert!(matches!(
        worker.forget_one(ForgetRequest::new(node, 2), full_budget(), &Uninterrupted),
        Err(WorkerError::InvalidArgument)
    ));
    assert_eq!(worker.inode_table().total_lookup_references(), references);
    worker
        .forget_one(ForgetRequest::new(node, 1), full_budget(), &Uninterrupted)
        .unwrap_or_else(|error| panic!("singleton forget failed: {error}"));
    // The open directory pin keeps the authenticated node association alive
    // after its last lookup reference disappears.
    assert!(
        worker
            .readdir_for_node(node, raw, 0, full_budget(), &mut scratch, &Uninterrupted)
            .is_ok()
    );
    worker
        .releasedir_for_node(node, raw, &Uninterrupted)
        .unwrap_or_else(|error| panic!("release failed: {error}"));
    assert_eq!(worker.inode_table().live_directory_handles(), 0);
    assert_eq!(
        worker.releasedir_for_node(node, raw, &Uninterrupted),
        Err(WorkerError::Stale)
    );
    assert!(matches!(
        worker.getattr(node, full_budget(), &Uninterrupted),
        Err(WorkerError::Stale)
    ));
}

#[test]
fn init_lookup_getattr_readlink_and_rejections_are_bounded() {
    let fixture = fixture();
    let index = fixture.validate();
    let plan = plan();
    let presentation =
        PreparedPresentation::prepare(&index, &plan, 1, [4; 32], PresentationLimits::new(5, 0, 2))
            .unwrap_or_else(|error| panic!("presentation failed: {error}"));
    let mut worker = MetadataConnection::new(
        &presentation,
        [5; 32],
        inode_limits(),
        DirectoryHandleLimits::new(8, 16),
        worker_limits(),
    )
    .unwrap_or_else(|error| panic!("worker failed: {error}"));
    assert!(matches!(
        worker.getattr(ROOT_NODE_ID, full_budget(), &Uninterrupted),
        Err(WorkerError::InvalidArgument)
    ));
    assert!(matches!(
        worker.reject(RejectedOperation::Mutation),
        Err(WorkerError::InvalidArgument)
    ));
    assert!(matches!(
        worker.initialize(
            InitRequest {
                batch_forget: true,
                directory_handles: true,
                readdir_plus: true,
            },
            RequestBudget::new(INIT_REPLY_BYTES - 1, 0, 0),
            &Uninterrupted,
        ),
        Err(WorkerError::ResourceExhausted)
    ));
    let init = worker
        .initialize(
            InitRequest {
                batch_forget: true,
                directory_handles: true,
                readdir_plus: true,
            },
            RequestBudget::new(INIT_REPLY_BYTES, 0, 0),
            &Uninterrupted,
        )
        .unwrap_or_else(|error| panic!("init failed: {error}"));
    assert_eq!(
        init,
        InitReply {
            batch_forget: true,
            directory_handles: true,
            readdir_plus: false,
            read_only: true,
        }
    );
    assert!(matches!(
        worker.initialize(
            InitRequest {
                batch_forget: false,
                directory_handles: false,
                readdir_plus: false,
            },
            full_budget(),
            &Uninterrupted,
        ),
        Err(WorkerError::InvalidArgument)
    ));

    let root = worker
        .getattr(
            ROOT_NODE_ID,
            RequestBudget::new(ATTRIBUTE_REPLY_BYTES, 0, 0),
            &Uninterrupted,
        )
        .unwrap_or_else(|error| panic!("getattr failed: {error}"));
    assert_eq!(
        (root.uid, root.gid, root.kind),
        (1_010, 2_020, IndexNodeKind::Directory)
    );
    assert!(matches!(
        worker.getattr(
            ROOT_NODE_ID,
            RequestBudget::new(ATTRIBUTE_REPLY_BYTES - 1, 0, 0),
            &Uninterrupted,
        ),
        Err(WorkerError::ResourceExhausted)
    ));
    assert!(matches!(
        worker.getattr(
            ROOT_NODE_ID,
            RequestBudget::new(worker_limits().maximum_output_bytes + 1, 0, 0),
            &Uninterrupted,
        ),
        Err(WorkerError::ResourceExhausted)
    ));
    assert!(matches!(
        worker.getattr(
            ROOT_NODE_ID,
            full_budget(),
            &StopAt {
                checkpoint: RequestCheckpoint::BeforeWork,
                state: RequestControlState::DeadlineExpired,
            },
        ),
        Err(WorkerError::TimedOut)
    ));
    assert_eq!(worker.inode_table().live_nodes(), 1);
    assert_eq!(
        worker
            .lookup(ROOT_NODE_ID, b"missing", full_budget(), &Uninterrupted)
            .unwrap_or_else(|error| panic!("negative lookup failed: {error}")),
        LookupReply::Negative
    );
    assert_eq!(worker.inode_table().live_nodes(), 1);
    assert!(matches!(
        worker.lookup(ROOT_NODE_ID, b"", full_budget(), &Uninterrupted),
        Err(WorkerError::InvalidArgument)
    ));

    let references = worker.inode_table().total_lookup_references();
    assert!(matches!(
        worker.lookup(
            ROOT_NODE_ID,
            b"file",
            RequestBudget::new(LOOKUP_REPLY_BYTES - 1, 0, 0),
            &Uninterrupted,
        ),
        Err(WorkerError::ResourceExhausted)
    ));
    assert_eq!(worker.inode_table().total_lookup_references(), references);
    assert!(matches!(
        worker.lookup(
            ROOT_NODE_ID,
            b"file",
            full_budget(),
            &StopAt {
                checkpoint: RequestCheckpoint::AfterReadOnlyWork,
                state: RequestControlState::Cancelled,
            },
        ),
        Err(WorkerError::Interrupted)
    ));
    assert_eq!(worker.inode_table().total_lookup_references(), references);
    let file = worker
        .lookup(ROOT_NODE_ID, b"file", full_budget(), &Uninterrupted)
        .unwrap_or_else(|error| panic!("file lookup failed: {error}"));
    let LookupReply::Positive { attributes, .. } = file else {
        panic!("file lookup was negative");
    };
    assert_eq!((attributes.uid, attributes.gid), (1_011, 2_021));

    let link = worker
        .lookup(ROOT_NODE_ID, b"link", full_budget(), &Uninterrupted)
        .unwrap_or_else(|error| panic!("link lookup failed: {error}"));
    let LookupReply::Positive {
        attributes: link, ..
    } = link
    else {
        panic!("link lookup was negative");
    };
    let mut scratch = ReplyScratch::new(worker_limits())
        .unwrap_or_else(|error| panic!("scratch failed: {error}"));
    assert!(matches!(
        worker.readlink(
            link.node_id,
            RequestBudget::new(READLINK_REPLY_BYTES + 5, 0, 6),
            &mut scratch,
            &Uninterrupted,
        ),
        Err(WorkerError::ResourceExhausted)
    ));
    let target = worker
        .readlink(
            link.node_id,
            RequestBudget::new(READLINK_REPLY_BYTES + 6, 0, 6),
            &mut scratch,
            &Uninterrupted,
        )
        .unwrap_or_else(|error| panic!("readlink failed: {error}"));
    assert_eq!(target.target(), b"target");
    assert!(matches!(
        worker.readlink(
            attributes.node_id,
            full_budget(),
            &mut scratch,
            &Uninterrupted,
        ),
        Err(WorkerError::NotSymlink)
    ));

    assert_eq!(
        worker.reject(RejectedOperation::Mutation),
        Err(WorkerError::ReadOnlyFilesystem)
    );
    for operation in [
        RejectedOperation::FileData,
        RejectedOperation::ReadDirPlus,
        RejectedOperation::ExtendedAttribute,
    ] {
        assert_eq!(
            worker.reject(operation),
            Err(WorkerError::OperationNotSupported)
        );
    }

    let mut minimal = MetadataConnection::new(
        &presentation,
        [71; 32],
        inode_limits(),
        DirectoryHandleLimits::new(0, 0),
        worker_limits(),
    )
    .unwrap_or_else(|error| panic!("minimal worker failed: {error}"));
    let negotiated = minimal
        .initialize(
            InitRequest {
                batch_forget: false,
                directory_handles: true,
                readdir_plus: false,
            },
            full_budget(),
            &Uninterrupted,
        )
        .unwrap_or_else(|error| panic!("minimal init failed: {error}"));
    assert!(!negotiated.directory_handles);
    assert!(matches!(
        minimal.prepare_opendir(ROOT_NODE_ID, full_budget(), &Uninterrupted),
        Err(WorkerError::OperationNotSupported)
    ));
    assert!(matches!(
        minimal.forget(&mut [], full_budget(), &Uninterrupted),
        Err(WorkerError::OperationNotSupported)
    ));
}

#[test]
fn opendir_readdir_pages_replay_and_partial_publication_are_exact() {
    let fixture = fixture();
    let index = fixture.validate();
    let plan = plan();
    let presentation =
        PreparedPresentation::prepare(&index, &plan, 1, [6; 32], PresentationLimits::new(5, 0, 2))
            .unwrap_or_else(|error| panic!("presentation failed: {error}"));
    let mut worker = MetadataConnection::new(
        &presentation,
        [7; 32],
        inode_limits(),
        DirectoryHandleLimits::new(8, 16),
        worker_limits(),
    )
    .unwrap_or_else(|error| panic!("worker failed: {error}"));
    initialize(&mut worker);
    let mut scratch = ReplyScratch::new(worker_limits())
        .unwrap_or_else(|error| panic!("scratch failed: {error}"));
    assert!(scratch.heap_bytes() <= worker_limits().maximum_scratch_heap_bytes);
    let scratch_heap = scratch.heap_bytes();
    let mut insufficient = worker_limits();
    insufficient.maximum_scratch_heap_bytes = scratch_heap - 1;
    assert!(matches!(
        ReplyScratch::new(insufficient),
        Err(WorkerError::ResourceExhausted)
    ));
    assert!(matches!(
        ReplyScratch::new(WorkerLimits::new(u64::MAX, usize::MAX, 0, u64::MAX)),
        Err(WorkerError::ResourceExhausted)
    ));

    let mut aborted = worker
        .prepare_opendir(ROOT_NODE_ID, full_budget(), &Uninterrupted)
        .unwrap_or_else(|error| panic!("prepare abort failed: {error}"));
    let aborted_raw = aborted.raw_handle();
    assert!(matches!(
        worker.readdir(0, 0, full_budget(), &mut scratch, &Uninterrupted),
        Err(WorkerError::Stale)
    ));
    let handles_before_tiny_reply = worker.inode_table().live_directory_handles();
    assert!(matches!(
        worker.prepare_opendir(
            ROOT_NODE_ID,
            RequestBudget::new(HANDLE_REPLY_BYTES - 1, 0, 0),
            &Uninterrupted,
        ),
        Err(WorkerError::ResourceExhausted)
    ));
    assert_eq!(
        worker.inode_table().live_directory_handles(),
        handles_before_tiny_reply
    );
    worker
        .abort_opendir(&mut aborted)
        .unwrap_or_else(|error| panic!("abort failed: {error}"));
    assert!(matches!(
        worker.readdir(aborted_raw, 0, full_budget(), &mut scratch, &Uninterrupted),
        Err(WorkerError::Stale)
    ));

    let mut pending = worker
        .prepare_opendir(
            ROOT_NODE_ID,
            RequestBudget::new(HANDLE_REPLY_BYTES, 0, 0),
            &Uninterrupted,
        )
        .unwrap_or_else(|error| panic!("prepare failed: {error}"));
    assert!(matches!(
        worker.readdir(
            pending.raw_handle(),
            0,
            full_budget(),
            &mut scratch,
            &Uninterrupted,
        ),
        Err(WorkerError::Stale)
    ));
    let mut foreign = MetadataConnection::new(
        &presentation,
        [70; 32],
        inode_limits(),
        DirectoryHandleLimits::new(8, 16),
        worker_limits(),
    )
    .unwrap_or_else(|error| panic!("foreign worker failed: {error}"));
    initialize(&mut foreign);
    assert!(matches!(
        foreign.publish_opendir(&mut pending),
        Err(WorkerError::Stale)
    ));
    let opened = worker
        .publish_opendir(&mut pending)
        .unwrap_or_else(|error| panic!("publish failed: {error}"));
    assert!(matches!(
        foreign.rollback_opendir(opened),
        Err(WorkerError::Stale)
    ));
    let raw = opened.handle.get();
    assert!(matches!(
        worker.readdir(
            raw,
            0,
            RequestBudget::new(DIRECTORY_PAGE_BYTES - 1, 0, 0),
            &mut scratch,
            &Uninterrupted,
        ),
        Err(WorkerError::ResourceExhausted)
    ));
    assert!(matches!(
        worker.readdir(
            raw,
            0,
            RequestBudget::new(4096, worker_limits().maximum_directory_entries + 1, 1024),
            &mut scratch,
            &Uninterrupted,
        ),
        Err(WorkerError::ResourceExhausted)
    ));
    let dot = worker
        .readdir(
            raw,
            0,
            RequestBudget::new(DIRECTORY_PAGE_BYTES + DIRECTORY_ENTRY_BYTES + 1, 1, 1),
            &mut scratch,
            &Uninterrupted,
        )
        .unwrap_or_else(|error| panic!("dot page failed: {error}"));
    assert_eq!(
        (dot.len(), dot.continuation_cookie(), dot.is_eof()),
        (1, 1, false)
    );
    let dot_entry = dot
        .entries()
        .next()
        .unwrap_or_else(|| panic!("dot missing"));
    assert_eq!(
        (dot_entry.name, dot_entry.node_id),
        (b".".as_slice(), Some(ROOT_NODE_ID))
    );

    let too_small = worker
        .readdir(
            raw,
            1,
            RequestBudget::new(DIRECTORY_PAGE_BYTES + DIRECTORY_ENTRY_BYTES + 1, 1, 2),
            &mut scratch,
            &Uninterrupted,
        )
        .unwrap_or_else(|error| panic!("small page failed: {error}"));
    assert!(too_small.is_empty());
    assert_eq!(too_small.continuation_cookie(), 1);
    let exact = worker
        .readdir(
            raw,
            1,
            RequestBudget::new(DIRECTORY_PAGE_BYTES + DIRECTORY_ENTRY_BYTES + 2, 1, 2),
            &mut scratch,
            &Uninterrupted,
        )
        .unwrap_or_else(|error| panic!("exact page failed: {error}"));
    assert_eq!(
        exact.entries().next().map(|entry| entry.name),
        Some(b"..".as_slice())
    );
    assert_eq!(exact.continuation_cookie(), 2);

    let full = worker
        .readdir(raw, 2, full_budget(), &mut scratch, &Uninterrupted)
        .unwrap_or_else(|error| panic!("full page failed: {error}"));
    let names = full
        .entries()
        .map(|entry| entry.name.to_vec())
        .collect::<Vec<_>>();
    assert_eq!(
        names,
        [
            b"dir".to_vec(),
            b"file".to_vec(),
            b"link".to_vec(),
            vec![0x80]
        ]
    );
    assert_eq!((full.continuation_cookie(), full.is_eof()), (6, true));
    let replay = worker
        .readdir(raw, 2, full_budget(), &mut scratch, &Uninterrupted)
        .unwrap_or_else(|error| panic!("replay failed: {error}"));
    assert_eq!(replay.continuation_cookie(), 6);
    assert!(matches!(
        worker.readdir(raw, 7, full_budget(), &mut scratch, &Uninterrupted),
        Err(WorkerError::InvalidArgument)
    ));
    assert!(matches!(
        worker.readdir(
            raw,
            0,
            full_budget(),
            &mut scratch,
            &StopAt {
                checkpoint: RequestCheckpoint::DuringReadOnlyWork,
                state: RequestControlState::DeadlineExpired,
            },
        ),
        Err(WorkerError::TimedOut)
    ));
    assert!(scratch.entries.is_empty() && scratch.names.is_empty());

    assert!(matches!(
        worker.releasedir(
            raw,
            &StopAt {
                checkpoint: RequestCheckpoint::BeforeCommit,
                state: RequestControlState::Cancelled,
            },
        ),
        Err(WorkerError::Interrupted)
    ));
    assert!(
        worker
            .readdir(raw, 0, full_budget(), &mut scratch, &Uninterrupted)
            .is_ok()
    );
    worker
        .releasedir(raw, &Uninterrupted)
        .unwrap_or_else(|error| panic!("release failed: {error}"));
    assert!(matches!(
        worker.readdir(raw, 0, full_budget(), &mut scratch, &Uninterrupted),
        Err(WorkerError::Stale)
    ));

    let mut rollback = worker
        .prepare_opendir(ROOT_NODE_ID, full_budget(), &Uninterrupted)
        .unwrap_or_else(|error| panic!("rollback prepare failed: {error}"));
    let rollback = worker
        .publish_opendir(&mut rollback)
        .unwrap_or_else(|error| panic!("rollback publish failed: {error}"));
    let rollback_raw = rollback.handle.get();
    worker
        .rollback_opendir(rollback)
        .unwrap_or_else(|error| panic!("rollback failed: {error}"));
    assert!(matches!(
        worker.readdir(rollback_raw, 0, full_budget(), &mut scratch, &Uninterrupted),
        Err(WorkerError::Stale)
    ));
    let pending_teardown = worker
        .prepare_opendir(ROOT_NODE_ID, full_budget(), &Uninterrupted)
        .unwrap_or_else(|error| panic!("teardown prepare failed: {error}"));
    assert_ne!(pending_teardown.raw_handle(), 0);
    assert_eq!(
        worker.teardown(),
        TeardownSummary {
            file_handles: 0,
            pending_file_handles: 0,
            directory_handles: 1,
            pending_directory_handles: 1,
        }
    );
}

#[test]
fn forget_cancellation_handles_and_growth_fail_closed() {
    let fixture = fixture();
    let index = fixture.validate();
    let plan = plan();
    let presentation =
        PreparedPresentation::prepare(&index, &plan, 1, [8; 32], PresentationLimits::new(5, 0, 2))
            .unwrap_or_else(|error| panic!("presentation failed: {error}"));
    let mut worker = MetadataConnection::new(
        &presentation,
        [9; 32],
        inode_limits(),
        DirectoryHandleLimits::new(8, 16),
        worker_limits(),
    )
    .unwrap_or_else(|error| panic!("worker failed: {error}"));
    initialize(&mut worker);
    let LookupReply::Positive { attributes, .. } = worker
        .lookup(ROOT_NODE_ID, b"file", full_budget(), &Uninterrupted)
        .unwrap_or_else(|error| panic!("lookup failed: {error}"))
    else {
        panic!("lookup was negative");
    };
    let before = worker.inode_table().total_lookup_references();
    let mut over_budget = [
        ForgetRequest::new(attributes.node_id, 1),
        ForgetRequest::new(ROOT_NODE_ID, 1),
    ];
    let original = over_budget;
    assert!(matches!(
        worker.forget(
            &mut over_budget,
            full_budget().with_forget_entries(1),
            &Uninterrupted,
        ),
        Err(WorkerError::ResourceExhausted)
    ));
    assert_eq!(over_budget, original);
    assert_eq!(worker.inode_table().total_lookup_references(), before);
    let mut forget = [ForgetRequest::new(attributes.node_id, 1)];
    assert!(matches!(
        worker.forget(
            &mut forget,
            full_budget(),
            &StopAt {
                checkpoint: RequestCheckpoint::BeforeCommit,
                state: RequestControlState::Cancelled,
            },
        ),
        Err(WorkerError::Interrupted)
    ));
    assert_eq!(worker.inode_table().total_lookup_references(), before);
    assert!(
        worker
            .getattr(attributes.node_id, full_budget(), &Uninterrupted)
            .is_ok()
    );
    assert!(matches!(
        worker.forget(
            &mut forget,
            full_budget(),
            &StopOnNth {
                checkpoint: RequestCheckpoint::DuringReadOnlyWork,
                remaining: Cell::new(1),
                state: RequestControlState::DeadlineExpired,
            },
        ),
        Err(WorkerError::TimedOut)
    ));
    assert_eq!(worker.inode_table().total_lookup_references(), before);
    assert!(
        worker
            .getattr(attributes.node_id, full_budget(), &Uninterrupted)
            .is_ok()
    );
    worker
        .forget(&mut forget, full_budget(), &Uninterrupted)
        .unwrap_or_else(|error| panic!("forget failed: {error}"));
    assert!(matches!(
        worker.getattr(attributes.node_id, full_budget(), &Uninterrupted),
        Err(WorkerError::Stale)
    ));

    let initial_nodes = worker.inode_table().live_nodes();
    let initial_refs = worker.inode_table().total_lookup_references();
    for _ in 0..128 {
        assert_eq!(
            worker
                .lookup(ROOT_NODE_ID, b"absent", full_budget(), &Uninterrupted)
                .unwrap_or_else(|error| panic!("negative lookup failed: {error}")),
            LookupReply::Negative
        );
    }
    assert_eq!(worker.inode_table().live_nodes(), initial_nodes);
    assert_eq!(worker.inode_table().total_lookup_references(), initial_refs);

    let mut scratch = ReplyScratch::new(worker_limits())
        .unwrap_or_else(|error| panic!("scratch failed: {error}"));
    for _ in 0..64 {
        let mut pending = worker
            .prepare_opendir(ROOT_NODE_ID, full_budget(), &Uninterrupted)
            .unwrap_or_else(|error| panic!("prepare failed: {error}"));
        worker
            .abort_opendir(&mut pending)
            .unwrap_or_else(|error| panic!("abort failed: {error}"));
    }
    assert_eq!(worker.inode_table().live_directory_handles(), 0);

    let LookupReply::Positive { attributes, .. } = worker
        .lookup(ROOT_NODE_ID, b"file", full_budget(), &Uninterrupted)
        .unwrap_or_else(|error| panic!("second lookup failed: {error}"))
    else {
        panic!("second lookup was negative");
    };
    let mut file_reservation = worker
        .inodes
        .reserve_open(attributes.node_id)
        .unwrap_or_else(|error| panic!("file reserve failed: {error}"));
    let file_raw = file_reservation.raw_protocol_handle();
    let file_handle = worker
        .inodes
        .activate_open(&mut file_reservation)
        .unwrap_or_else(|error| panic!("file activation failed: {error}"));
    assert!(matches!(
        worker.readdir(file_raw, 0, full_budget(), &mut scratch, &Uninterrupted),
        Err(WorkerError::Stale)
    ));
    worker
        .inodes
        .release_open(file_handle)
        .unwrap_or_else(|error| panic!("file release failed: {error}"));
}
