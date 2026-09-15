//! Tier promotion, repair, routing, and durability-policy tests.

use super::*;

#[test]
fn tiered_reads_promote_only_verified_objects() {
    let cache = Arc::new(MemoryBlobBackend::new("cache", 1_024));
    let durable = Arc::new(MemoryBlobBackend::new("durable-test", 1_024));
    let bytes = b"finding bundle";
    let id = ContentId::for_bytes(ObjectKind::Finding, 1, bytes);
    put_bytes(durable.as_ref(), id, bytes).expect("seed lower tier");

    let tiers = vec![
        tier(cache.clone(), true, false, true),
        tier(durable, true, true, false),
    ];
    let store = TieredStore::new("tiered", tiers).expect("valid tiers");
    assert!(!store.capabilities().streaming_read);
    assert_eq!(read_bytes(&store, id, None).expect("tiered read"), bytes);
    assert!(cache.contains(id).expect("promoted cache object"));
}

#[test]
fn tier_policy_separates_read_write_and_promotion_roles() {
    let cache = Arc::new(MemoryBlobBackend::new("tier-cache", 1_024));
    let archive = Arc::new(MemoryBlobBackend::new("tier-archive", 1_024));
    let primary = Arc::new(MemoryBlobBackend::new("tier-primary", 1_024));
    let store = TieredStore::new(
        "tier-policy",
        vec![
            tier(cache.clone(), true, false, true),
            tier(archive.clone(), false, true, false),
            tier(primary.clone(), true, true, false),
        ],
    )
    .expect("valid tier-specific policy");
    let bytes = b"tier-specific placement";
    let id = ContentId::for_bytes(ObjectKind::Finding, 1, bytes);

    let receipt = put_bytes(&store, id, bytes).expect("policy-directed write");
    assert_eq!(receipt.placements.len(), 2);
    assert!(!cache.contains(id).expect("cache presence"));
    assert!(archive.contains(id).expect("archive presence"));
    assert!(primary.contains(id).expect("primary presence"));

    assert_eq!(read_bytes(&store, id, None).expect("policy read"), bytes);
    assert!(cache.contains(id).expect("promoted cache presence"));
}

#[test]
fn graph_marks_every_non_write_tier_as_reconstructible_cache() {
    let root = node_id("tiered");
    let cache = node_id("cache");
    let source = node_id("source");
    let (_, admin) = StoreGraph::build_with_admin(StoreGraphConfig {
        root: root.clone(),
        admitted_kinds: BTreeSet::from([ObjectKind::Trace]),
        nodes: BTreeMap::from([
            (
                root,
                StoreNodeSpec::Tiered {
                    tiers: vec![
                        StoreTierPolicy {
                            child: cache.clone(),
                            readable: true,
                            writable: false,
                            promote_reads: false,
                        },
                        StoreTierPolicy {
                            child: source.clone(),
                            readable: true,
                            writable: true,
                            promote_reads: false,
                        },
                    ],
                },
            ),
            (
                cache.clone(),
                StoreNodeSpec::Memory {
                    max_logical_bytes: 1_024,
                },
            ),
            (
                source.clone(),
                StoreNodeSpec::Memory {
                    max_logical_bytes: 1_024,
                },
            ),
        ]),
    })
    .expect("tiered graph");

    let physical = admin.physical();
    let cache_role = physical
        .iter()
        .find(|physical| physical.node() == &cache)
        .and_then(|physical| physical.retention(ObjectKind::Trace));
    let source_role = physical
        .iter()
        .find(|physical| physical.node() == &source)
        .and_then(|physical| physical.retention(ObjectKind::Trace));
    assert_eq!(cache_role, Some(StoreGraphPhysicalRetention::Cache));
    assert_eq!(source_role, Some(StoreGraphPhysicalRetention::Required));
}

#[test]
fn stopped_owner_repairs_one_physical_copy_from_an_independent_source() {
    let temporary = TempDir::new().expect("physical repair fixture root");
    let tiered = node_id("tiered");
    let source = node_id("source");
    let target = node_id("target");
    let source_root = temporary.path().join("source");
    let target_root = temporary.path().join("target");
    let (graph, admin) = StoreGraph::build_with_admin(StoreGraphConfig {
        root: tiered.clone(),
        admitted_kinds: BTreeSet::from([ObjectKind::Finding]),
        nodes: BTreeMap::from([
            (
                tiered,
                StoreNodeSpec::Tiered {
                    tiers: vec![
                        StoreTierPolicy {
                            child: target.clone(),
                            readable: true,
                            writable: true,
                            promote_reads: false,
                        },
                        StoreTierPolicy {
                            child: source.clone(),
                            readable: true,
                            writable: true,
                            promote_reads: false,
                        },
                    ],
                },
            ),
            (
                source.clone(),
                StoreNodeSpec::Directory { root: source_root },
            ),
            (
                target.clone(),
                StoreNodeSpec::Directory {
                    root: target_root.clone(),
                },
            ),
        ]),
    })
    .expect("repair graph");
    let bytes = b"independently authenticated physical repair";
    let id = ContentId::for_bytes(ObjectKind::Finding, 1, bytes);
    put_bytes(&graph, id, bytes).expect("seed both physical copies");
    fs::write(object_path(&target_root, id), b"corrupt target").expect("corrupt target placement");

    let repaired = admin
        .repair_physical_copy(&source, &target, id)
        .expect("repair corrupt target");
    assert_eq!(repaired.configuration(), graph.configuration_id());
    assert_eq!(repaired.content(), id);
    assert_eq!(repaired.source(), &source);
    assert_eq!(repaired.target(), &target);
    assert_eq!(repaired.logical_length(), bytes.len() as u64);
    assert_eq!(
        repaired.disposition(),
        StorePhysicalRepairDisposition::Repaired
    );
    assert_eq!(
        read_bytes(&graph, id, None).expect("read repaired graph"),
        bytes
    );

    let replay = admin
        .repair_physical_copy(&source, &target, id)
        .expect("repeat completed repair");
    assert_eq!(
        replay.disposition(),
        StorePhysicalRepairDisposition::AlreadyValid
    );
    assert!(matches!(
        admin.repair_physical_copy(&source, &source, id),
        Err(StoreError::Incompatible)
    ));
}

#[cfg(feature = "destructive-recovery-faults")]
#[test]
fn corrupt_tier_copy_fails_closed_then_repairs_from_authenticated_lower_tier() {
    if std::env::var_os(CORRUPT_TIER_COPY_CHILD_ENVIRONMENT).is_some() {
        run_corrupt_tier_copy_child();
        panic!("corrupt-tier child returned without recording the injected failure");
    }

    let temporary = TempDir::new().expect("tier corruption fixture root");
    let upper_root = temporary.path().join("upper");
    let lower_root = temporary.path().join("lower");
    let bytes = b"authenticated tier-copy recovery";
    let id = ContentId::for_bytes(ObjectKind::Finding, 1, bytes);
    let upper = DirectoryBlobBackend::new("upper-tier", &upper_root);
    let lower = DirectoryBlobBackend::new("lower-tier", &lower_root);
    put_bytes(&upper, id, bytes).expect("seed upper placement");
    put_bytes(&lower, id, bytes).expect("seed lower placement");

    let child = std::process::Command::new(std::env::current_exe().expect("current test binary"))
        .arg("--exact")
        .arg(CORRUPT_TIER_COPY_TEST_NAME)
        .arg("--nocapture")
        .env(CORRUPT_TIER_COPY_CHILD_ENVIRONMENT, "1")
        .env(CORRUPT_TIER_COPY_ROOT_ENVIRONMENT, temporary.path())
        .env(
            DESTRUCTIVE_RECOVERY_TRIGGER_ENVIRONMENT,
            CORRUPT_TIER_COPY_TRIGGER,
        )
        .output()
        .expect("run corrupt-tier child");
    assert_eq!(
        child.status.code(),
        Some(CORRUPT_TIER_COPY_CHILD_EXIT_CODE),
        "corrupt-tier child did not preserve the expected state:\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&child.stdout),
        String::from_utf8_lossy(&child.stderr),
    );

    let upper = Arc::new(DirectoryBlobBackend::new("upper-tier", &upper_root));
    let lower = Arc::new(DirectoryBlobBackend::new("lower-tier", &lower_root));
    assert!(matches!(
        read_bytes(upper.as_ref(), id, None),
        Err(StoreError::Corrupt { id: corrupt }) if corrupt == id
    ));
    assert_eq!(
        read_bytes(lower.as_ref(), id, None).expect("valid lower placement after restart"),
        bytes
    );
    let strict_tiers = vec![
        tier(upper.clone(), true, false, false),
        tier(lower.clone(), true, true, false),
    ];
    let strict = TieredStore::new("strict-tiered", strict_tiers).expect("strict tier policy");
    assert!(matches!(
        read_bytes(&strict, id, None),
        Err(StoreError::Corrupt { id: corrupt }) if corrupt == id
    ));

    fs::remove_file(object_path(&upper_root, id)).expect("remove diagnosed corrupt placement");
    let recovery_tiers = vec![
        tier(upper.clone(), true, false, true),
        tier(lower, true, true, false),
    ];
    let recovery =
        TieredStore::new("recovery-tiered", recovery_tiers).expect("recovery tier policy");
    assert_eq!(
        read_bytes(&recovery, id, None).expect("fallback to authenticated lower placement"),
        bytes
    );
    assert_eq!(
        read_bytes(upper.as_ref(), id, None).expect("authenticated promoted repair"),
        bytes
    );
}

#[cfg(feature = "destructive-recovery-faults")]
fn run_corrupt_tier_copy_child() {
    let root = std::env::var_os(CORRUPT_TIER_COPY_ROOT_ENVIRONMENT)
        .map(PathBuf::from)
        .expect("corrupt-tier fixture root");
    let bytes = b"authenticated tier-copy recovery";
    let id = ContentId::for_bytes(ObjectKind::Finding, 1, bytes);
    let upper = Arc::new(DirectoryBlobBackend::new("upper-tier", root.join("upper")));
    let lower = Arc::new(DirectoryBlobBackend::new("lower-tier", root.join("lower")));
    let tiers = vec![
        tier(upper.clone(), true, false, false),
        tier(lower.clone(), true, true, false),
    ];
    let store = TieredStore::new("tiered", tiers).expect("tier policy");

    assert!(matches!(
        read_bytes(&store, id, None),
        Err(StoreError::Corrupt { id: corrupt }) if corrupt == id
    ));
    assert_eq!(
        read_bytes(lower.as_ref(), id, None).expect("unaffected lower placement"),
        bytes
    );

    std::process::exit(CORRUPT_TIER_COPY_CHILD_EXIT_CODE);
}

#[test]
fn read_through_cache_failure_does_not_hide_authenticated_source_bytes() {
    let cache = Arc::new(MemoryBlobBackend::new("full-cache", 0));
    let source = Arc::new(MemoryBlobBackend::new("source", 1_024));
    let bytes = b"source remains authoritative";
    let id = ContentId::for_bytes(ObjectKind::Finding, 1, bytes);
    put_bytes(source.as_ref(), id, bytes).expect("seed source");
    let store = ReadThroughStore::new("read-through", cache.clone(), source.clone());

    assert_eq!(
        read_bytes(&store, id, None).expect("read despite cache quota"),
        bytes
    );
    assert!(!cache.contains(id).expect("failed promotion remains absent"));

    let unavailable_cache: Arc<dyn ImmutableBlobBackend> = Arc::new(UnavailableReadBackend);
    let strict = ReadThroughStore::new("strict-read-through", unavailable_cache, source);
    assert!(matches!(
        read_bytes(&strict, id, None),
        Err(StoreError::Unavailable)
    ));
}

#[test]
fn routed_and_write_through_stores_preserve_logical_identity() {
    let metadata_a = Arc::new(MemoryBlobBackend::new("metadata-a", 1_024));
    let metadata_b = Arc::new(MemoryBlobBackend::new("metadata-b", 1_024));
    let mirror_children: Vec<Arc<dyn ImmutableBlobBackend>> =
        vec![metadata_a.clone(), metadata_b.clone()];
    let mirror =
        Arc::new(WriteThroughStore::new("metadata-mirror", mirror_children).expect("valid mirror"));
    let ram = Arc::new(MemoryBlobBackend::new("ram", 1_024));
    let mut routes: BTreeMap<ObjectKind, Arc<dyn ImmutableBlobBackend>> = BTreeMap::new();
    routes.insert(ObjectKind::CampaignFact, mirror);
    routes.insert(ObjectKind::RamExtent, ram.clone());
    let routed = RoutedStore::new("router", routes).expect("valid routes");

    let fact_bytes = b"fact";
    let fact = ContentId::for_bytes(ObjectKind::CampaignFact, 1, fact_bytes);
    let receipt = put_bytes(&routed, fact, fact_bytes).expect("mirrored fact put");
    assert_eq!(receipt.placements.len(), 2);
    assert!(metadata_a.contains(fact).expect("first mirror"));
    assert!(metadata_b.contains(fact).expect("second mirror"));

    let ram_bytes = b"page";
    let page = ContentId::for_bytes(ObjectKind::RamExtent, 1, ram_bytes);
    put_bytes(&routed, page, ram_bytes).expect("routed page put");
    assert!(ram.contains(page).expect("ram route"));
}

#[test]
fn invalid_ranges_and_mismatched_puts_are_rejected() {
    let store = MemoryBlobBackend::new("memory", 3);
    let id = ContentId::for_bytes(ObjectKind::Trace, 1, b"abc");
    assert!(matches!(
        put_bytes(&store, id, b"different"),
        Err(StoreError::Corrupt { .. })
    ));
    put_bytes(&store, id, b"abc").expect("valid put");
    let overflow_id = ContentId::for_bytes(ObjectKind::Trace, 1, b"d");
    assert!(matches!(
        put_bytes(&store, overflow_id, b"d"),
        Err(StoreError::Quota)
    ));
    assert!(matches!(
        read_bytes(
            &store,
            id,
            Some(ByteRange::new(2, 2).expect("non-overflowing range"))
        ),
        Err(StoreError::InvalidRange { .. })
    ));
}

#[test]
fn directory_put_and_ref_cas_are_process_concurrent() {
    let temp = TempDir::new().expect("temporary directory");
    let blobs = Arc::new(DirectoryBlobBackend::new(
        "directory",
        temp.path().join("blobs"),
    ));
    let bytes = b"shared immutable bytes";
    let id = ContentId::for_bytes(ObjectKind::CampaignFact, 1, bytes);
    let barrier = Arc::new(Barrier::new(8));
    let mut putters = Vec::new();
    for _ in 0..8 {
        let blobs = blobs.clone();
        let barrier = barrier.clone();
        putters.push(thread::spawn(move || {
            barrier.wait();
            put_bytes(blobs.as_ref(), id, bytes)
        }));
    }
    for putter in putters {
        assert!(putter.join().expect("put thread").is_ok());
    }
    assert_eq!(
        read_bytes(blobs.as_ref(), id, None).expect("concurrent object"),
        bytes
    );

    let refs = Arc::new(DirectoryRefBackend::new(temp.path().join("authority")));
    let name = RefName::new("campaigns/race").expect("valid ref");
    let candidates: Vec<_> = (0_u8..8)
        .map(|value| ContentId::for_bytes(ObjectKind::CampaignSnapshot, 1, &[value]))
        .collect();
    let barrier = Arc::new(Barrier::new(candidates.len()));
    let mut writers = Vec::new();
    for next in candidates.iter().copied() {
        let refs = refs.clone();
        let name = name.clone();
        let barrier = barrier.clone();
        writers.push(thread::spawn(move || {
            barrier.wait();
            refs.compare_exchange(&name, None, next)
        }));
    }
    let outcomes: Vec<_> = writers
        .into_iter()
        .map(|writer| writer.join().expect("ref thread").expect("ref CAS"))
        .collect();
    assert_eq!(
        outcomes
            .iter()
            .filter(|outcome| matches!(outcome, RefCasOutcome::Advanced { .. }))
            .count(),
        1
    );
    assert_eq!(
        outcomes
            .iter()
            .filter(|outcome| matches!(outcome, RefCasOutcome::Conflict { .. }))
            .count(),
        candidates.len() - 1
    );
    assert!(
        candidates.contains(
            &refs
                .read_ref(&name)
                .expect("read winning ref")
                .expect("winning ref")
        )
    );
}

#[test]
fn capabilities_and_composed_failures_are_truthful() {
    let temp = TempDir::new().expect("temporary directory");
    let directory = Arc::new(DirectoryBlobBackend::new(
        "directory",
        temp.path().join("blobs"),
    ));
    assert_eq!(
        directory.capabilities(),
        BackendCapabilities {
            durable: true,
            deferred_write: false,
            range_read: true,
            streaming_read: true,
            conditional_create: true,
            streaming_put: true,
            repair_inventory: false,
            planned_delete: false,
        }
    );

    let memory = Arc::new(MemoryBlobBackend::new("memory", 1_024));
    let children: Vec<Arc<dyn ImmutableBlobBackend>> = vec![memory.clone(), directory];
    let write_through =
        WriteThroughStore::new("write-through", children).expect("valid write-through");
    assert!(write_through.capabilities().durable);

    let lower = Arc::new(MemoryBlobBackend::new("lower", 1_024));
    let bytes = b"lower bytes";
    let id = ContentId::for_bytes(ObjectKind::Trace, 1, bytes);
    put_bytes(lower.as_ref(), id, bytes).expect("seed lower tier");
    let unavailable: Arc<dyn ImmutableBlobBackend> = Arc::new(UnavailableReadBackend);
    let lower_trait: Arc<dyn ImmutableBlobBackend> = lower;
    let tiered = TieredStore::new(
        "tiered",
        vec![
            tier(unavailable, true, false, false),
            tier(lower_trait, true, true, false),
        ],
    )
    .expect("valid tiered store");
    assert!(matches!(
        read_bytes(&tiered, id, None),
        Err(StoreError::Unavailable)
    ));
}

#[test]
fn partial_write_through_is_retryable() {
    let first = Arc::new(MemoryBlobBackend::new("first", 1_024));
    let second = Arc::new(FailFirstPutBackend::new());
    let children: Vec<Arc<dyn ImmutableBlobBackend>> = vec![first.clone(), second.clone()];
    let store = WriteThroughStore::new("mirror", children).expect("valid mirror");
    let bytes = b"retryable immutable object";
    let id = ContentId::for_bytes(ObjectKind::CampaignFact, 1, bytes);

    assert!(matches!(
        put_bytes(&store, id, bytes),
        Err(StoreError::Unavailable)
    ));
    assert!(first.contains(id).expect("first orphan is readable"));
    assert!(!second.contains(id).expect("second placement absent"));
    assert!(store.contains(id).expect("partial mirror is readable"));
    assert_eq!(
        read_bytes(&store, id, None).expect("partial mirror read"),
        bytes
    );

    let receipt = put_bytes(&store, id, bytes).expect("retry mirror put");
    assert_eq!(receipt.placements.len(), 2);
    assert!(second.contains(id).expect("second placement repaired"));
}

#[test]
fn streaming_sources_are_reopenable_and_length_checked() {
    let temp = TempDir::new().expect("temporary directory");
    let store = DirectoryBlobBackend::new("directory", temp.path().join("blobs"));
    let source = Arc::new(RepeatSource {
        byte: 0xab,
        logical_length: 4 * 1024 * 1024,
    });
    let id = ContentId::for_source(ObjectKind::RamExtent, 1, source.as_ref())
        .expect("stream source identity");
    let source = BlobHandle::new(source);
    let receipt = store
        .put_if_absent(id, &source)
        .expect("stream directory put");
    assert_eq!(
        receipt.placements[0].logical_length,
        source.logical_length()
    );

    let stored = store.read(id, None).expect("stream directory read");
    let mut copied = Vec::new();
    assert_eq!(
        stored.copy_to(&mut copied).expect("bounded streaming copy"),
        source.logical_length()
    );
    assert_eq!(copied, vec![0xab; source.logical_length() as usize]);
    assert_eq!(
        ContentId::for_source(ObjectKind::RamExtent, 1, &stored).expect("stored stream identity"),
        id
    );
    assert_eq!(
        store
            .read(
                id,
                Some(ByteRange::new(source.logical_length() - 16, 16).expect("valid tail range"))
            )
            .expect("tail stream")
            .read_all(16)
            .expect("tail bytes"),
        vec![0xab; 16]
    );

    let too_long = Arc::new(MismatchedLengthSource {
        declared: 2,
        bytes: b"abc",
    });
    assert!(matches!(
        ContentId::for_source(ObjectKind::Trace, 1, too_long.as_ref()),
        Err(StoreError::InvalidSourceLength { .. })
    ));
    let expected = ContentId::for_bytes(ObjectKind::Trace, 1, b"ab");
    let too_long = BlobHandle::new(too_long);
    assert!(matches!(
        store.put_if_absent(expected, &too_long),
        Err(StoreError::Corrupt { .. })
    ));

    let too_short = MismatchedLengthSource {
        declared: 4,
        bytes: b"abc",
    };
    assert!(matches!(
        ContentId::for_source(ObjectKind::Trace, 1, &too_short),
        Err(StoreError::InvalidSourceLength { .. })
    ));

    let enormous = BlobHandle::new(Arc::new(MismatchedLengthSource {
        declared: u64::MAX,
        bytes: b"",
    }));
    assert!(matches!(
        enormous.read_all(u64::MAX),
        Err(StoreError::Quota)
    ));
}

#[test]
fn verification_evidence_bounds_source_passes_through_a_mirror_graph() {
    let temp = TempDir::new().expect("temporary directory");
    let root = node_id("root");
    let router = node_id("router");
    let mirror = node_id("mirror");
    let directory = node_id("directory");
    let memory = node_id("memory");
    let graph = StoreGraph::build(StoreGraphConfig {
        root: root.clone(),
        admitted_kinds: BTreeSet::from([ObjectKind::CampaignFact]),
        nodes: BTreeMap::from([
            (
                root,
                StoreNodeSpec::Verified {
                    child: router.clone(),
                },
            ),
            (
                router,
                StoreNodeSpec::Routed {
                    routes: BTreeMap::from([(ObjectKind::CampaignFact, mirror.clone())]),
                },
            ),
            (
                mirror,
                StoreNodeSpec::WriteThrough {
                    children: vec![directory.clone(), memory.clone()],
                },
            ),
            (
                directory,
                StoreNodeSpec::Directory {
                    root: temp.path().join("objects"),
                },
            ),
            (
                memory,
                StoreNodeSpec::Memory {
                    max_logical_bytes: 1024 * 1024,
                },
            ),
        ]),
    })
    .expect("valid mirror graph");
    let bytes = vec![0x5a; 128 * 1024];
    let opens = Arc::new(AtomicUsize::new(0));
    let bytes_read = Arc::new(AtomicUsize::new(0));
    let source = BlobHandle::new(Arc::new(CountingSource {
        bytes: Arc::from(bytes.clone()),
        opens: opens.clone(),
        bytes_read: bytes_read.clone(),
    }));
    let id = ContentId::for_bytes(ObjectKind::CampaignFact, 1, &bytes);
    let receipt = graph
        .put_if_absent(id, &source)
        .expect("mirrored streaming put");

    assert_eq!(receipt.placements.len(), 2);
    assert_eq!(opens.load(Ordering::SeqCst), 3);
    assert_eq!(bytes_read.load(Ordering::SeqCst), bytes.len() * 3);
}

#[test]
fn directory_handles_pin_inodes_and_authenticate_ranges_at_eof() {
    let temp = TempDir::new().expect("temporary directory");
    let store = DirectoryBlobBackend::new("directory", temp.path().join("objects"));
    let bytes = b"stable pinned bytes";
    let id = ContentId::for_bytes(ObjectKind::Trace, 1, bytes);
    put_bytes(&store, id, bytes).expect("put pinned object");
    let handle = store.read(id, None).expect("open pinned handle");
    fs::remove_file(object_path(store.root(), id)).expect("unlink object path");
    assert_eq!(handle.read_all(1_024).expect("read unlinked inode"), bytes);
    assert_eq!(
        handle.read_all(1_024).expect("reopen unlinked inode"),
        bytes
    );
    assert!(matches!(
        store.read(id, None),
        Err(StoreError::NotFound { .. })
    ));

    let mutated = b"mutable-object";
    let mutated_id = ContentId::for_bytes(ObjectKind::Trace, 1, mutated);
    put_bytes(&store, mutated_id, mutated).expect("put mutation object");
    let mutated_handle = store.read(mutated_id, None).expect("open mutation handle");
    fs::write(object_path(store.root(), mutated_id), b"changed-object")
        .expect("mutate pinned inode");
    assert!(matches!(
        mutated_handle.read_all(1_024),
        Err(StoreError::Corrupt { .. })
    ));

    let range_bytes = vec![0x11; 4_096];
    let range_id = ContentId::for_bytes(ObjectKind::RamExtent, 1, &range_bytes);
    put_bytes(&store, range_id, &range_bytes).expect("put range object");
    let range = store
        .read(range_id, Some(ByteRange::new(0, 16).expect("valid range")))
        .expect("open range handle");
    let mut corrupt = range_bytes;
    corrupt[4_095] ^= 0xff;
    fs::write(object_path(store.root(), range_id), corrupt).expect("corrupt outside range");
    assert!(matches!(
        range.read_all(16),
        Err(StoreError::Corrupt { .. })
    ));
}

#[test]
fn changing_and_failing_sources_leave_no_published_object_or_staging_file() {
    let temp = TempDir::new().expect("temporary directory");
    let directory = Arc::new(DirectoryBlobBackend::new(
        "directory",
        temp.path().join("objects"),
    ));
    let verified = super::composition::VerifiedStore::new("verified", directory.clone());
    let expected_bytes = b"first opening is valid";
    let id = ContentId::for_bytes(ObjectKind::CampaignFact, 1, expected_bytes);
    let source = BlobHandle::new(Arc::new(ChangingSource {
        opens: AtomicUsize::new(0),
        first: expected_bytes,
        later: b"second opening differs",
    }));
    assert!(matches!(
        verified.put_if_absent(id, &source),
        Err(StoreError::Corrupt { .. })
    ));
    assert!(
        !directory
            .contains(id)
            .expect("changed source not published")
    );
    assert_no_staging(directory.root(), id);

    let failing_bytes = b"reader fails in the middle";
    let failing_id = ContentId::for_bytes(ObjectKind::Trace, 1, failing_bytes);
    let failing = BlobHandle::new(Arc::new(FailingSource {
        bytes: failing_bytes,
        fail_after: 8,
    }));
    assert!(matches!(
        directory.put_if_absent(failing_id, &failing),
        Err(StoreError::StreamIo { .. })
    ));
    assert!(
        !directory
            .contains(failing_id)
            .expect("failed source not published")
    );
    assert_no_staging(directory.root(), failing_id);

    let interrupted = InterruptOnceSource {
        bytes: b"retry interrupted reads",
    };
    assert_eq!(
        ContentId::for_source(ObjectKind::Trace, 1, &interrupted)
            .expect("interrupted read retried"),
        ContentId::for_bytes(ObjectKind::Trace, 1, interrupted.bytes)
    );
}

#[test]
fn source_chunk_boundaries_do_not_change_content_identity() {
    for length in [65_535_usize, 65_536, 65_537] {
        let bytes = vec![0x7c; length];
        let source = RepeatSource {
            byte: 0x7c,
            logical_length: length as u64,
        };
        assert_eq!(
            ContentId::for_source(ObjectKind::RamExtent, 1, &source).expect("chunked identity"),
            ContentId::for_bytes(ObjectKind::RamExtent, 1, &bytes)
        );
    }
}

#[test]
fn closed_store_graph_routes_shared_leaves_and_is_introspectable() {
    let temp = TempDir::new().expect("temporary directory");
    let root = node_id("root");
    let router = node_id("router");
    let mirror = node_id("metadata-mirror");
    let ram_tiers = node_id("ram-tiers");
    let directory = node_id("directory");
    let metadata_cache = node_id("metadata-cache");
    let ram_cache = node_id("ram-cache");
    let nodes = BTreeMap::from([
        (
            root.clone(),
            StoreNodeSpec::Verified {
                child: router.clone(),
            },
        ),
        (
            router,
            StoreNodeSpec::Routed {
                routes: BTreeMap::from([
                    (ObjectKind::CampaignFact, mirror.clone()),
                    (ObjectKind::RamExtent, ram_tiers.clone()),
                ]),
            },
        ),
        (
            mirror,
            StoreNodeSpec::WriteThrough {
                children: vec![metadata_cache.clone(), directory.clone()],
            },
        ),
        (
            ram_tiers,
            StoreNodeSpec::Tiered {
                tiers: vec![
                    StoreTierPolicy {
                        child: ram_cache.clone(),
                        readable: true,
                        writable: false,
                        promote_reads: true,
                    },
                    StoreTierPolicy {
                        child: directory.clone(),
                        readable: true,
                        writable: true,
                        promote_reads: false,
                    },
                ],
            },
        ),
        (
            directory,
            StoreNodeSpec::Directory {
                root: temp.path().join("objects"),
            },
        ),
        (
            metadata_cache,
            StoreNodeSpec::Memory {
                max_logical_bytes: 1_024,
            },
        ),
        (
            ram_cache,
            StoreNodeSpec::Memory {
                max_logical_bytes: 1_024,
            },
        ),
    ]);
    let (graph, admin) = StoreGraph::build_with_admin(StoreGraphConfig {
        root: root.clone(),
        admitted_kinds: BTreeSet::from([ObjectKind::CampaignFact, ObjectKind::RamExtent]),
        nodes,
    })
    .expect("valid closed graph");
    assert_eq!(graph.root_id(), &root);
    assert_eq!(graph.configuration_id(), admin.configuration_id());
    assert_eq!(graph.describe().len(), 7);
    assert!(
        graph
            .describe()
            .iter()
            .any(|node| node.kind == StoreNodeKind::Routed)
    );
    assert_eq!(
        admin
            .physical()
            .into_iter()
            .map(|physical| physical.node().as_str())
            .collect::<Vec<_>>(),
        vec!["directory", "metadata-cache", "ram-cache"]
    );
    let ram_roles = admin
        .physical()
        .into_iter()
        .map(|physical| {
            (
                physical.node().as_str(),
                physical.retention(ObjectKind::RamExtent),
            )
        })
        .collect::<BTreeMap<_, _>>();
    assert_eq!(
        ram_roles["ram-cache"],
        Some(StoreGraphPhysicalRetention::Cache)
    );
    assert_eq!(
        ram_roles["directory"],
        Some(StoreGraphPhysicalRetention::Required)
    );

    let fact_bytes = b"graph fact";
    let fact = ContentId::for_bytes(ObjectKind::CampaignFact, 1, fact_bytes);
    let fact_receipt = put_bytes(&graph, fact, fact_bytes).expect("graph fact put");
    assert_eq!(fact_receipt.placements.len(), 2);
    assert!(fact_receipt.is_durable());

    let ram_bytes = b"graph ram";
    let ram = ContentId::for_bytes(ObjectKind::RamExtent, 1, ram_bytes);
    assert!(
        put_bytes(&graph, ram, ram_bytes)
            .expect("graph RAM put")
            .is_durable()
    );
    assert_eq!(
        read_bytes(&graph, ram, None).expect("graph RAM read"),
        ram_bytes
    );

    let trace = ContentId::for_bytes(ObjectKind::Trace, 1, b"trace");
    assert!(matches!(
        put_bytes(&graph, trace, b"trace"),
        Err(StoreError::InvalidGraph {
            violation: GraphViolation::RouteCoverage,
            ..
        })
    ));
}

#[test]
fn durability_policy_enforces_distinct_placements_and_exact_kind_coverage() {
    let temp = TempDir::new().expect("temporary directory");
    let policy = node_id("durability");
    let mirror = node_id("mirror");
    let first = node_id("first");
    let second = node_id("second");
    let requirement = DurabilityRequirement::new(2, false).expect("durability requirement");
    let config = |requirement| StoreGraphConfig {
        root: policy.clone(),
        admitted_kinds: BTreeSet::from([ObjectKind::CampaignFact]),
        nodes: BTreeMap::from([
            (
                policy.clone(),
                StoreNodeSpec::DurabilityPolicy {
                    child: mirror.clone(),
                    requirements: BTreeMap::from([(ObjectKind::CampaignFact, requirement)]),
                },
            ),
            (
                mirror.clone(),
                StoreNodeSpec::WriteThrough {
                    children: vec![first.clone(), second.clone()],
                },
            ),
            (
                first.clone(),
                StoreNodeSpec::Directory {
                    root: temp.path().join("first"),
                },
            ),
            (
                second.clone(),
                StoreNodeSpec::Directory {
                    root: temp.path().join("second"),
                },
            ),
        ]),
    };
    let graph = StoreGraph::build(config(requirement)).expect("durability graph");
    assert!(
        graph
            .describe()
            .iter()
            .any(|node| node.kind == StoreNodeKind::DurabilityPolicy)
    );
    let bytes = b"durable campaign fact";
    let id = ContentId::for_bytes(ObjectKind::CampaignFact, 1, bytes);
    let receipt = put_bytes(&graph, id, bytes).expect("durability-qualified put");
    assert_eq!(receipt.durable_placements(), 2);
    assert_eq!(read_bytes(&graph, id, None).expect("policy read"), bytes);

    let restarted = StoreGraph::build(config(requirement)).expect("restart durability graph");
    assert_eq!(graph.configuration_id(), restarted.configuration_id());
    assert_eq!(
        read_bytes(&restarted, id, None).expect("restart read"),
        bytes
    );
    let weaker = StoreGraph::build(config(
        DurabilityRequirement::new(1, false).expect("weaker requirement"),
    ))
    .expect("weaker durability graph");
    assert_ne!(graph.configuration_id(), weaker.configuration_id());

    let golden_policy = node_id("durability");
    let golden_mirror = node_id("mirror");
    let golden_first = node_id("first");
    let golden_second = node_id("second");
    let golden = StoreGraph::build(StoreGraphConfig {
        root: golden_policy.clone(),
        admitted_kinds: BTreeSet::from([ObjectKind::CampaignFact]),
        nodes: BTreeMap::from([
            (
                golden_policy,
                StoreNodeSpec::DurabilityPolicy {
                    child: golden_mirror.clone(),
                    requirements: BTreeMap::from([(ObjectKind::CampaignFact, requirement)]),
                },
            ),
            (
                golden_mirror,
                StoreNodeSpec::WriteThrough {
                    children: vec![golden_first.clone(), golden_second.clone()],
                },
            ),
            (
                golden_first,
                StoreNodeSpec::Directory {
                    root: PathBuf::from("/var/lib/crucible/campaign-primary"),
                },
            ),
            (
                golden_second,
                StoreNodeSpec::Directory {
                    root: PathBuf::from("/var/lib/crucible/campaign-archive"),
                },
            ),
        ]),
    })
    .expect("golden durability graph");
    assert_eq!(
        encode_hex(&golden.configuration_id().as_bytes()),
        "fa61d3d1f852797e8ee40f8147f18cb2c2df1cdad172db82ddda9a968b5b39c5"
    );

    let missing = StoreGraph::build(StoreGraphConfig {
        root: policy.clone(),
        admitted_kinds: BTreeSet::from([ObjectKind::CampaignFact]),
        nodes: BTreeMap::from([
            (
                policy.clone(),
                StoreNodeSpec::DurabilityPolicy {
                    child: first.clone(),
                    requirements: BTreeMap::new(),
                },
            ),
            (
                first.clone(),
                StoreNodeSpec::Directory {
                    root: temp.path().join("missing"),
                },
            ),
        ]),
    });
    assert!(matches!(
        missing,
        Err(StoreError::InvalidGraph {
            violation: GraphViolation::DurabilityCoverage,
            ..
        })
    ));

    let extraneous = StoreGraph::build(StoreGraphConfig {
        root: policy.clone(),
        admitted_kinds: BTreeSet::from([ObjectKind::CampaignFact]),
        nodes: BTreeMap::from([
            (
                policy,
                StoreNodeSpec::DurabilityPolicy {
                    child: first.clone(),
                    requirements: BTreeMap::from([
                        (ObjectKind::CampaignFact, requirement),
                        (ObjectKind::Trace, requirement),
                    ]),
                },
            ),
            (
                first,
                StoreNodeSpec::Directory {
                    root: temp.path().join("extraneous"),
                },
            ),
        ]),
    });
    assert!(matches!(
        extraneous,
        Err(StoreError::InvalidGraph {
            violation: GraphViolation::DurabilityCoverage,
            ..
        })
    ));
}

#[test]
fn durability_policy_rejects_duplicate_receipts_and_unadmitted_deferral() {
    let temp = TempDir::new().expect("temporary directory");
    let policy = node_id("durability");
    let mirror = node_id("mirror");
    let directory = node_id("directory");
    let requirement = DurabilityRequirement::new(2, false).expect("durability requirement");
    let duplicate = StoreGraph::build(StoreGraphConfig {
        root: policy.clone(),
        admitted_kinds: BTreeSet::from([ObjectKind::CampaignFact]),
        nodes: BTreeMap::from([
            (
                policy.clone(),
                StoreNodeSpec::DurabilityPolicy {
                    child: mirror.clone(),
                    requirements: BTreeMap::from([(ObjectKind::CampaignFact, requirement)]),
                },
            ),
            (
                mirror,
                StoreNodeSpec::WriteThrough {
                    children: vec![directory.clone(), directory.clone()],
                },
            ),
            (
                directory.clone(),
                StoreNodeSpec::Directory {
                    root: temp.path().join("duplicate"),
                },
            ),
        ]),
    })
    .expect("duplicate-child graph remains structurally valid");
    let bytes = b"one physical placement";
    let id = ContentId::for_bytes(ObjectKind::CampaignFact, 1, bytes);
    assert!(matches!(
        put_bytes(&duplicate, id, bytes),
        Err(StoreError::DurabilityUnsatisfied {
            minimum_durable_placements: 2,
            observed_durable_placements: 1,
            ..
        })
    ));

    let write_back = node_id("write-back");
    let staging = node_id("staging");
    let destination = node_id("destination");
    let deferred_config = |allow_deferred_write| StoreGraphConfig {
        root: policy.clone(),
        admitted_kinds: BTreeSet::from([ObjectKind::Finding]),
        nodes: BTreeMap::from([
            (
                policy.clone(),
                StoreNodeSpec::DurabilityPolicy {
                    child: write_back.clone(),
                    requirements: BTreeMap::from([(
                        ObjectKind::Finding,
                        DurabilityRequirement::new(1, allow_deferred_write)
                            .expect("deferred requirement"),
                    )]),
                },
            ),
            (
                write_back.clone(),
                StoreNodeSpec::WriteBack {
                    staging: staging.clone(),
                    destination: destination.clone(),
                    journal_root: temp.path().join("journal"),
                    maximum_pending_objects: 8,
                    maximum_pending_bytes: 1_024,
                },
            ),
            (
                staging.clone(),
                StoreNodeSpec::Directory {
                    root: temp.path().join("staging"),
                },
            ),
            (
                destination.clone(),
                StoreNodeSpec::Directory {
                    root: temp.path().join("destination"),
                },
            ),
        ]),
    };
    assert!(matches!(
        StoreGraph::build(deferred_config(false)),
        Err(StoreError::InvalidGraph {
            violation: GraphViolation::UnsupportedChild,
            ..
        })
    ));
    let deferred = StoreGraph::build(deferred_config(true)).expect("admitted deferred policy");
    let finding_bytes = b"journaled durable staging";
    let finding = ContentId::for_bytes(ObjectKind::Finding, 1, finding_bytes);
    assert_eq!(
        put_bytes(&deferred, finding, finding_bytes)
            .expect("allowed deferred put")
            .durable_placements(),
        1
    );

    assert!(matches!(
        DurabilityRequirement::new(0, false),
        Err(StoreError::InvalidComposition { .. })
    ));
    assert!(matches!(
        StoreGraph::build(StoreGraphConfig {
            root: policy.clone(),
            admitted_kinds: BTreeSet::from([ObjectKind::Finding]),
            nodes: BTreeMap::from([
                (
                    policy,
                    StoreNodeSpec::DurabilityPolicy {
                        child: directory.clone(),
                        requirements: BTreeMap::from([(
                            ObjectKind::Finding,
                            DurabilityRequirement::new(1, false).expect("memory requirement"),
                        )]),
                    },
                ),
                (
                    directory,
                    StoreNodeSpec::Memory {
                        max_logical_bytes: 1_024,
                    },
                ),
            ]),
        }),
        Err(StoreError::InvalidGraph {
            violation: GraphViolation::UnsupportedChild,
            ..
        })
    ));
}
