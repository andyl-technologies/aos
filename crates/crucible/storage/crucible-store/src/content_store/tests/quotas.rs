//! Logical and physical quota admission and recovery tests.

use super::*;

#[test]
fn physical_quota_binds_exact_leaf_limits_and_survives_restart_and_admin() {
    let temp = TempDir::new().expect("temporary directory");
    let physical = node_id("physical-quota");
    let directory = node_id("directory");
    let policy =
        StorePhysicalQuotaPolicyId::new("host/ext4/campaign-store").expect("physical quota policy");
    let object_root = temp.path().join("objects");
    let config = |root: PathBuf, maximum_physical_bytes| StoreGraphConfig {
        root: physical.clone(),
        admitted_kinds: BTreeSet::from([ObjectKind::Trace]),
        nodes: BTreeMap::from([
            (
                physical.clone(),
                StoreNodeSpec::PhysicalQuota {
                    child: directory.clone(),
                    policy: policy.clone(),
                    project_id: 41,
                    maximum_physical_bytes,
                    maximum_inodes: 64,
                },
            ),
            (
                directory.clone(),
                StoreNodeSpec::CompressedDirectory {
                    root,
                    maximum_logical_object_bytes: 1_024,
                },
            ),
        ]),
    };
    assert!(matches!(
        StoreGraph::build(config(object_root.clone(), 128 * 1024)),
        Err(StoreError::Unauthorized)
    ));

    let binder = Arc::new(RecordingPhysicalQuotaBinder::new(true));
    let mut binders = StoreGraphPhysicalQuotaBinders::new();
    binders
        .insert(policy.clone(), binder.clone())
        .expect("physical quota capability");
    assert!(matches!(
        binders.insert(policy.clone(), binder.clone()),
        Err(StoreError::InvalidComposition { .. })
    ));
    let build = |config| {
        StoreGraph::build_with_admin_and_all_capabilities(
            config,
            &StoreGraphKeyring::new(),
            &StoreGraphNamespaceAuthorizers::new(),
            &StoreGraphObjectProfilers::new(),
            &binders,
            &StoreGraphS3Clients::new(),
        )
    };
    let (graph, admin) =
        build(config(object_root.clone(), 128 * 1024)).expect("physical quota graph");
    assert_eq!(admin.physical().len(), 1);
    assert_eq!(admin.physical()[0].node(), &physical);
    assert_eq!(
        binder.bindings(),
        vec![RecordedPhysicalQuotaBinding {
            root: object_root.clone(),
            project_id: 41,
            maximum_physical_bytes: 128 * 1024,
            maximum_inodes: 64,
        }]
    );

    let bytes = b"physically bounded trace";
    let id = ContentId::for_bytes(ObjectKind::Trace, 1, bytes);
    let receipt = put_bytes(&graph, id, bytes).expect("physical quota put");
    assert_eq!(receipt.placements[0].backend, "physical-quota");
    assert!(graph.contains(id).expect("physical quota contains"));
    assert_eq!(
        read_bytes(&graph, id, None).expect("physical quota read"),
        bytes
    );
    let mut fence = admin.physical()[0]
        .admin()
        .acquire_inventory_fence()
        .expect("physical quota inventory fence");
    let summary = fence
        .visit_inventory(&mut |_| Ok(()))
        .expect("physical quota inventory");
    assert_eq!(summary.backend(), "physical-quota");
    assert_eq!(summary.objects(), 1);
    drop(fence);
    drop(admin);
    drop(graph);

    let (restarted, restarted_admin) =
        build(config(object_root.clone(), 128 * 1024)).expect("restarted physical quota graph");
    assert!(restarted.contains(id).expect("restart retained object"));
    let mut fence = restarted_admin.physical()[0]
        .admin()
        .acquire_inventory_fence()
        .expect("restarted inventory fence");
    assert_eq!(
        fence.delete_candidate(id).expect("quota deletion"),
        PlannedDeleteDisposition::Deleted
    );
    drop(fence);
    assert!(!restarted.contains(id).expect("deleted object absent"));

    binder.guard.set_allowed(false);
    let rejected_bytes = b"rejected before child allocation";
    let rejected = ContentId::for_bytes(ObjectKind::Trace, 1, rejected_bytes);
    assert!(matches!(
        put_bytes(&restarted, rejected, rejected_bytes),
        Err(StoreError::Quota)
    ));
    binder.guard.set_allowed(true);
    let direct = CompressedDirectoryBlobBackend::new("direct", &object_root, 1_024)
        .expect("direct compressed leaf");
    assert!(!direct.contains(rejected).expect("rejected child absent"));

    let (changed, _admin) =
        build(config(object_root, 256 * 1024)).expect("changed physical quota graph");
    assert_ne!(restarted.configuration_id(), changed.configuration_id());
    let (golden, _admin) = build(config(
        PathBuf::from("/var/lib/crucible/campaign-store/objects"),
        128 * 1024,
    ))
    .expect("golden physical quota graph");
    assert_eq!(
        encode_hex(&golden.configuration_id().as_bytes()),
        "3c76577dc61b54a6a611a127cf3187dd8a0e55cda80c5e61b0e697867d48c225"
    );
}

#[test]
fn physical_quota_admission_rejects_invalid_shared_and_nonleaf_children() {
    let temp = TempDir::new().expect("temporary directory");
    let physical = node_id("physical-quota");
    let directory = node_id("directory");
    let policy = StorePhysicalQuotaPolicyId::new("host/ext4").expect("quota policy");
    let config = |project_id, maximum_physical_bytes, maximum_inodes| StoreGraphConfig {
        root: physical.clone(),
        admitted_kinds: BTreeSet::from([ObjectKind::Trace]),
        nodes: BTreeMap::from([
            (
                physical.clone(),
                StoreNodeSpec::PhysicalQuota {
                    child: directory.clone(),
                    policy: policy.clone(),
                    project_id,
                    maximum_physical_bytes,
                    maximum_inodes,
                },
            ),
            (
                directory.clone(),
                StoreNodeSpec::Directory {
                    root: temp.path().join("objects"),
                },
            ),
        ]),
    };
    for invalid in [config(0, 1, 1), config(1, 0, 1), config(1, 1, 0)] {
        assert!(matches!(
            StoreGraph::build(invalid),
            Err(StoreError::InvalidGraph {
                violation: GraphViolation::InvalidPhysicalQuotaBounds,
                ..
            })
        ));
    }

    let metrics = node_id("metrics");
    assert!(matches!(
        StoreGraph::build(StoreGraphConfig {
            root: physical.clone(),
            admitted_kinds: BTreeSet::from([ObjectKind::Trace]),
            nodes: BTreeMap::from([
                (
                    physical.clone(),
                    StoreNodeSpec::PhysicalQuota {
                        child: metrics.clone(),
                        policy: policy.clone(),
                        project_id: 1,
                        maximum_physical_bytes: 1,
                        maximum_inodes: 1,
                    },
                ),
                (
                    metrics,
                    StoreNodeSpec::Metrics {
                        child: directory.clone(),
                    },
                ),
                (
                    directory.clone(),
                    StoreNodeSpec::Directory {
                        root: temp.path().join("nonleaf"),
                    },
                ),
            ]),
        }),
        Err(StoreError::InvalidGraph {
            violation: GraphViolation::InvalidPhysicalQuotaChild,
            ..
        })
    ));

    let mirror = node_id("mirror");
    assert!(matches!(
        StoreGraph::build(StoreGraphConfig {
            root: mirror.clone(),
            admitted_kinds: BTreeSet::from([ObjectKind::Trace]),
            nodes: BTreeMap::from([
                (
                    mirror,
                    StoreNodeSpec::WriteThrough {
                        children: vec![physical.clone(), directory.clone()],
                    },
                ),
                (
                    physical,
                    StoreNodeSpec::PhysicalQuota {
                        child: directory.clone(),
                        policy,
                        project_id: 1,
                        maximum_physical_bytes: 1,
                        maximum_inodes: 1,
                    },
                ),
                (
                    directory,
                    StoreNodeSpec::Directory {
                        root: temp.path().join("shared"),
                    },
                ),
            ]),
        }),
        Err(StoreError::InvalidGraph {
            violation: GraphViolation::InvalidPhysicalQuotaChild,
            ..
        })
    ));
}

#[test]
fn physical_quota_binding_precedes_allocating_leaf_construction() {
    let temp = TempDir::new().expect("temporary directory");
    let physical = node_id("physical-quota");
    let packed = node_id("packed");
    let policy =
        StorePhysicalQuotaPolicyId::new("host/ext4/preflight").expect("physical quota policy");
    let pack_root = temp.path().join("packs");
    let binder = Arc::new(RecordingPhysicalQuotaBinder::new(false));
    let mut binders = StoreGraphPhysicalQuotaBinders::new();
    binders
        .insert(policy.clone(), binder)
        .expect("physical quota capability");
    let result = StoreGraph::build_with_admin_and_all_capabilities(
        StoreGraphConfig {
            root: physical.clone(),
            admitted_kinds: BTreeSet::from([ObjectKind::Trace]),
            nodes: BTreeMap::from([
                (
                    physical,
                    StoreNodeSpec::PhysicalQuota {
                        child: packed.clone(),
                        policy,
                        project_id: 43,
                        maximum_physical_bytes: 128 * 1024,
                        maximum_inodes: 64,
                    },
                ),
                (
                    packed,
                    StoreNodeSpec::Packed {
                        root: pack_root.clone(),
                        target_pack_bytes: 4 * 1024,
                    },
                ),
            ]),
        },
        &StoreGraphKeyring::new(),
        &StoreGraphNamespaceAuthorizers::new(),
        &StoreGraphObjectProfilers::new(),
        &binders,
        &StoreGraphS3Clients::new(),
    );
    assert!(matches!(result, Err(StoreError::Quota)));
    assert!(!pack_root.exists());
}

#[test]
fn logical_and_physical_quotas_compose_without_an_admin_bypass() {
    let temp = TempDir::new().expect("temporary directory");
    let logical = node_id("logical-quota");
    let physical = node_id("physical-quota");
    let directory = node_id("directory");
    let policy =
        StorePhysicalQuotaPolicyId::new("host/ext4/composed").expect("physical quota policy");
    let binder = Arc::new(RecordingPhysicalQuotaBinder::new(true));
    let mut binders = StoreGraphPhysicalQuotaBinders::new();
    binders
        .insert(policy.clone(), binder)
        .expect("physical quota capability");
    let (graph, admin) = StoreGraph::build_with_admin_and_all_capabilities(
        StoreGraphConfig {
            root: logical.clone(),
            admitted_kinds: BTreeSet::from([ObjectKind::Trace]),
            nodes: BTreeMap::from([
                (
                    logical.clone(),
                    StoreNodeSpec::LogicalQuota {
                        child: physical.clone(),
                        state_root: temp.path().join("logical-state"),
                        maximum_objects: 1,
                        maximum_logical_bytes: 64,
                    },
                ),
                (
                    physical,
                    StoreNodeSpec::PhysicalQuota {
                        child: directory.clone(),
                        policy,
                        project_id: 42,
                        maximum_physical_bytes: 128 * 1024,
                        maximum_inodes: 64,
                    },
                ),
                (
                    directory,
                    StoreNodeSpec::Directory {
                        root: temp.path().join("objects"),
                    },
                ),
            ]),
        },
        &StoreGraphKeyring::new(),
        &StoreGraphNamespaceAuthorizers::new(),
        &StoreGraphObjectProfilers::new(),
        &binders,
        &StoreGraphS3Clients::new(),
    )
    .expect("composed quota graph");
    assert_eq!(admin.physical().len(), 1);
    assert_eq!(admin.physical()[0].node(), &logical);

    let bytes = b"one quota-owned object";
    let id = ContentId::for_bytes(ObjectKind::Trace, 1, bytes);
    put_bytes(&graph, id, bytes).expect("composed quota put");
    let rejected_bytes = b"second object";
    let rejected = ContentId::for_bytes(ObjectKind::Trace, 1, rejected_bytes);
    assert!(matches!(
        put_bytes(&graph, rejected, rejected_bytes),
        Err(StoreError::Quota)
    ));
}

#[test]
fn sqlite_physical_quota_binds_the_database_and_wal_root() {
    let temp = TempDir::new().expect("temporary directory");
    let physical = node_id("physical-quota");
    let sqlite = node_id("sqlite");
    let object_root = temp.path().join("sqlite-objects");
    let policy =
        StorePhysicalQuotaPolicyId::new("host/ext4/sqlite").expect("SQLite physical quota policy");
    let binder = Arc::new(RecordingPhysicalQuotaBinder::new(true));
    let mut binders = StoreGraphPhysicalQuotaBinders::new();
    binders
        .insert(policy.clone(), binder.clone())
        .expect("physical quota capability");
    let (graph, admin) = StoreGraph::build_with_admin_and_all_capabilities(
        StoreGraphConfig {
            root: physical.clone(),
            admitted_kinds: BTreeSet::from([ObjectKind::CampaignFact]),
            nodes: BTreeMap::from([
                (
                    physical.clone(),
                    StoreNodeSpec::PhysicalQuota {
                        child: sqlite.clone(),
                        policy,
                        project_id: 43,
                        maximum_physical_bytes: 128 * 1024,
                        maximum_inodes: 64,
                    },
                ),
                (
                    sqlite,
                    StoreNodeSpec::Sqlite {
                        root: object_root.clone(),
                    },
                ),
            ]),
        },
        &StoreGraphKeyring::new(),
        &StoreGraphNamespaceAuthorizers::new(),
        &StoreGraphObjectProfilers::new(),
        &binders,
        &StoreGraphS3Clients::new(),
    )
    .expect("quota-owned SQLite graph");
    assert_eq!(admin.physical().len(), 1);
    assert_eq!(admin.physical()[0].node(), &physical);
    assert_eq!(
        binder.bindings(),
        vec![RecordedPhysicalQuotaBinding {
            root: object_root,
            project_id: 43,
            maximum_physical_bytes: 128 * 1024,
            maximum_inodes: 64,
        }]
    );

    let bytes = b"quota-owned SQLite fact";
    let id = ContentId::for_bytes(ObjectKind::CampaignFact, 1, bytes);
    put_bytes(&graph, id, bytes).expect("SQLite quota put");
    binder.guard.set_allowed(false);
    let rejected_bytes = b"rejected SQLite fact";
    let rejected = ContentId::for_bytes(ObjectKind::CampaignFact, 1, rejected_bytes);
    assert!(matches!(
        put_bytes(&graph, rejected, rejected_bytes),
        Err(StoreError::Quota)
    ));
    binder.guard.set_allowed(true);
    assert!(
        !graph
            .contains(rejected)
            .expect("rejected object remains absent")
    );
}

#[test]
fn logical_quota_reclaims_accounting_through_graph_admin_and_survives_restart() {
    let temp = TempDir::new().expect("temporary directory");
    let quota = node_id("quota");
    let directory = node_id("directory");
    let state_root = temp.path().join("quota-state");
    let object_root = temp.path().join("objects");
    let config = || StoreGraphConfig {
        root: quota.clone(),
        admitted_kinds: BTreeSet::from([ObjectKind::Trace]),
        nodes: BTreeMap::from([
            (
                quota.clone(),
                StoreNodeSpec::LogicalQuota {
                    child: directory.clone(),
                    state_root: state_root.clone(),
                    maximum_objects: 2,
                    maximum_logical_bytes: 10,
                },
            ),
            (
                directory.clone(),
                StoreNodeSpec::CompressedDirectory {
                    root: object_root.clone(),
                    maximum_logical_object_bytes: 1_024,
                },
            ),
        ]),
    };
    let (graph, admin) = StoreGraph::build_with_admin(config()).expect("logical quota graph");
    assert_eq!(graph.describe().len(), 2);
    assert!(
        graph
            .describe()
            .iter()
            .any(|node| node.kind == StoreNodeKind::LogicalQuota)
    );
    assert_eq!(admin.physical().len(), 1);
    assert_eq!(admin.physical()[0].node(), &quota);

    let first_bytes = b"four";
    let first = ContentId::for_bytes(ObjectKind::Trace, 1, first_bytes);
    let first_receipt = put_bytes(&graph, first, first_bytes).expect("first quota put");
    assert_eq!(first_receipt.placements[0].backend, "quota");
    put_bytes(&graph, first, first_bytes).expect("idempotent quota put");
    let second_bytes = b"second";
    let second = ContentId::for_bytes(ObjectKind::Trace, 1, second_bytes);
    put_bytes(&graph, second, second_bytes).expect("second quota put");
    let rejected_bytes = b"more";
    let rejected = ContentId::for_bytes(ObjectKind::Trace, 1, rejected_bytes);
    let rejected_opens = Arc::new(AtomicUsize::new(0));
    let rejected_source = BlobHandle::new(Arc::new(CountingSource {
        bytes: Arc::from(rejected_bytes.as_slice()),
        opens: Arc::clone(&rejected_opens),
        bytes_read: Arc::new(AtomicUsize::new(0)),
    }));
    assert!(matches!(
        graph.put_if_absent(rejected, &rejected_source),
        Err(StoreError::Quota)
    ));
    assert_eq!(rejected_opens.load(Ordering::SeqCst), 0);

    let mut fence = admin.physical()[0]
        .admin()
        .acquire_inventory_fence()
        .expect("logical quota inventory fence");
    let summary = fence
        .visit_inventory(&mut |_| Ok(()))
        .expect("logical quota inventory");
    assert_eq!(summary.backend(), "quota");
    assert_eq!(summary.objects(), 2);
    assert_eq!(summary.logical_bytes(), 10);
    assert_eq!(
        fence
            .delete_candidate(first)
            .expect("delete quota candidate"),
        PlannedDeleteDisposition::Deleted
    );
    assert_eq!(
        fence
            .delete_candidate(first)
            .expect("repeat quota candidate deletion"),
        PlannedDeleteDisposition::AlreadyAbsent
    );
    drop(fence);
    put_bytes(&graph, rejected, rejected_bytes).expect("reclaimed quota put");
    drop(admin);
    drop(graph);

    let (restarted, restarted_admin) =
        StoreGraph::build_with_admin(config()).expect("restart logical quota graph");
    assert!(!restarted.contains(first).expect("deleted object absent"));
    assert!(restarted.contains(second).expect("second object retained"));
    assert!(restarted.contains(rejected).expect("replacement retained"));
    let mut fence = restarted_admin.physical()[0]
        .admin()
        .acquire_inventory_fence()
        .expect("restarted logical quota fence");
    let summary = fence
        .visit_inventory(&mut |_| Ok(()))
        .expect("restarted logical quota inventory");
    assert_eq!(summary.objects(), 2);
    assert_eq!(summary.logical_bytes(), 10);
}

#[test]
fn dirty_logical_quota_state_recovers_from_the_owned_child_inventory() {
    let temp = TempDir::new().expect("temporary directory");
    let quota = node_id("quota");
    let directory = node_id("directory");
    let state_root = temp.path().join("quota-state");
    let object_root = temp.path().join("objects");
    let config = || StoreGraphConfig {
        root: quota.clone(),
        admitted_kinds: BTreeSet::from([ObjectKind::Trace]),
        nodes: BTreeMap::from([
            (
                quota.clone(),
                StoreNodeSpec::LogicalQuota {
                    child: directory.clone(),
                    state_root: state_root.clone(),
                    maximum_objects: 2,
                    maximum_logical_bytes: 16,
                },
            ),
            (
                directory.clone(),
                StoreNodeSpec::Directory {
                    root: object_root.clone(),
                },
            ),
        ]),
    };
    let graph = StoreGraph::build(config()).expect("logical quota graph");
    let first_bytes = b"first";
    let first = ContentId::for_bytes(ObjectKind::Trace, 1, first_bytes);
    put_bytes(&graph, first, first_bytes).expect("first quota put");
    super::quota::mark_quota_state_dirty(&state_root).expect("mark interrupted quota state");

    let child = DirectoryBlobBackend::new("directory", &object_root);
    let second_bytes = b"second";
    let second = ContentId::for_bytes(ObjectKind::Trace, 1, second_bytes);
    put_bytes(&child, second, second_bytes).expect("simulate committed child put");
    drop(graph);

    let (restarted, admin) =
        StoreGraph::build_with_admin(config()).expect("recover logical quota graph");
    let third_bytes = b"third";
    let third = ContentId::for_bytes(ObjectKind::Trace, 1, third_bytes);
    assert!(matches!(
        put_bytes(&restarted, third, third_bytes),
        Err(StoreError::Quota)
    ));
    let mut fence = admin.physical()[0]
        .admin()
        .acquire_inventory_fence()
        .expect("recovered quota fence");
    let summary = fence
        .visit_inventory(&mut |_| Ok(()))
        .expect("recovered quota inventory");
    assert_eq!(summary.objects(), 2);
    assert_eq!(summary.logical_bytes(), 11);
    drop(fence);
    drop(admin);
    drop(restarted);

    let changed = StoreGraphConfig {
        root: quota.clone(),
        admitted_kinds: BTreeSet::from([ObjectKind::Trace]),
        nodes: BTreeMap::from([
            (
                quota,
                StoreNodeSpec::LogicalQuota {
                    child: directory.clone(),
                    state_root,
                    maximum_objects: 3,
                    maximum_logical_bytes: 16,
                },
            ),
            (directory, StoreNodeSpec::Directory { root: object_root }),
        ]),
    };
    assert!(matches!(
        StoreGraph::build(changed),
        Err(StoreError::InvalidComposition {
            reason: "logical quota state belongs to another graph configuration"
        })
    ));
}

#[test]
fn concurrent_logical_quota_instances_share_one_durable_admission_lock() {
    let temp = TempDir::new().expect("temporary directory");
    let quota = node_id("quota");
    let directory = node_id("directory");
    let config = || StoreGraphConfig {
        root: quota.clone(),
        admitted_kinds: BTreeSet::from([ObjectKind::Trace]),
        nodes: BTreeMap::from([
            (
                quota.clone(),
                StoreNodeSpec::LogicalQuota {
                    child: directory.clone(),
                    state_root: temp.path().join("quota-state"),
                    maximum_objects: 1,
                    maximum_logical_bytes: 16,
                },
            ),
            (
                directory.clone(),
                StoreNodeSpec::Directory {
                    root: temp.path().join("objects"),
                },
            ),
        ]),
    };
    let first = Arc::new(StoreGraph::build(config()).expect("first quota instance"));
    let second = Arc::new(StoreGraph::build(config()).expect("second quota instance"));
    let barrier = Arc::new(Barrier::new(3));
    let launch = |graph: Arc<StoreGraph>, byte| {
        let barrier = Arc::clone(&barrier);
        thread::spawn(move || {
            let bytes = [byte; 8];
            let id = ContentId::for_bytes(ObjectKind::Trace, 1, &bytes);
            barrier.wait();
            graph.put_if_absent(id, &BlobHandle::from_bytes(bytes))
        })
    };
    let first_put = launch(first, 0x31);
    let second_put = launch(second, 0x32);
    barrier.wait();
    let results = [
        first_put.join().expect("first quota writer"),
        second_put.join().expect("second quota writer"),
    ];
    assert_eq!(results.iter().filter(|result| result.is_ok()).count(), 1);
    assert_eq!(
        results
            .iter()
            .filter(|result| matches!(result, Err(StoreError::Quota)))
            .count(),
        1
    );
}

#[test]
fn logical_quota_admission_rejects_unbounded_shared_and_nonleaf_children() {
    let temp = TempDir::new().expect("temporary directory");
    let quota = node_id("quota");
    let directory = node_id("directory");
    let config = |maximum_objects, maximum_logical_bytes| StoreGraphConfig {
        root: quota.clone(),
        admitted_kinds: BTreeSet::from([ObjectKind::Trace]),
        nodes: BTreeMap::from([
            (
                quota.clone(),
                StoreNodeSpec::LogicalQuota {
                    child: directory.clone(),
                    state_root: temp.path().join("quota-state"),
                    maximum_objects,
                    maximum_logical_bytes,
                },
            ),
            (
                directory.clone(),
                StoreNodeSpec::Directory {
                    root: temp.path().join("objects"),
                },
            ),
        ]),
    };
    for invalid in [config(0, 1), config(1, 0), config(u64::MAX, 1)] {
        assert!(matches!(
            StoreGraph::build(invalid),
            Err(StoreError::InvalidGraph {
                violation: GraphViolation::InvalidLogicalQuotaBounds,
                ..
            })
        ));
    }

    assert!(matches!(
        StoreGraph::build(StoreGraphConfig {
            root: quota.clone(),
            admitted_kinds: BTreeSet::from([ObjectKind::Trace]),
            nodes: BTreeMap::from([
                (
                    quota.clone(),
                    StoreNodeSpec::LogicalQuota {
                        child: directory.clone(),
                        state_root: temp.path().join("memory-state"),
                        maximum_objects: 1,
                        maximum_logical_bytes: 1,
                    },
                ),
                (
                    directory.clone(),
                    StoreNodeSpec::Memory {
                        max_logical_bytes: 1,
                    },
                ),
            ]),
        }),
        Err(StoreError::InvalidGraph {
            violation: GraphViolation::InvalidLogicalQuotaChild,
            ..
        })
    ));

    let metrics = node_id("metrics");
    assert!(matches!(
        StoreGraph::build(StoreGraphConfig {
            root: quota.clone(),
            admitted_kinds: BTreeSet::from([ObjectKind::Trace]),
            nodes: BTreeMap::from([
                (
                    quota.clone(),
                    StoreNodeSpec::LogicalQuota {
                        child: metrics.clone(),
                        state_root: temp.path().join("nonleaf-state"),
                        maximum_objects: 1,
                        maximum_logical_bytes: 1,
                    },
                ),
                (
                    metrics,
                    StoreNodeSpec::Metrics {
                        child: directory.clone(),
                    },
                ),
                (
                    directory.clone(),
                    StoreNodeSpec::Directory {
                        root: temp.path().join("nonleaf-objects"),
                    },
                ),
            ]),
        }),
        Err(StoreError::InvalidGraph {
            violation: GraphViolation::InvalidLogicalQuotaChild,
            ..
        })
    ));

    assert!(matches!(
        StoreGraph::build(StoreGraphConfig {
            root: quota.clone(),
            admitted_kinds: BTreeSet::from([ObjectKind::Trace]),
            nodes: BTreeMap::from([
                (
                    quota.clone(),
                    StoreNodeSpec::LogicalQuota {
                        child: directory.clone(),
                        state_root: temp.path().join("overlap"),
                        maximum_objects: 1,
                        maximum_logical_bytes: 1,
                    },
                ),
                (
                    directory.clone(),
                    StoreNodeSpec::Directory {
                        root: temp.path().join("overlap").join("objects"),
                    },
                ),
            ]),
        }),
        Err(StoreError::InvalidGraph {
            violation: GraphViolation::OverlappingAdministrativePath,
            ..
        })
    ));

    let mirror = node_id("mirror");
    assert!(matches!(
        StoreGraph::build(StoreGraphConfig {
            root: mirror.clone(),
            admitted_kinds: BTreeSet::from([ObjectKind::Trace]),
            nodes: BTreeMap::from([
                (
                    mirror,
                    StoreNodeSpec::WriteThrough {
                        children: vec![quota.clone(), directory.clone()],
                    },
                ),
                (
                    quota,
                    StoreNodeSpec::LogicalQuota {
                        child: directory.clone(),
                        state_root: temp.path().join("shared-state"),
                        maximum_objects: 1,
                        maximum_logical_bytes: 1,
                    },
                ),
                (
                    directory,
                    StoreNodeSpec::Directory {
                        root: temp.path().join("shared-objects"),
                    },
                ),
            ]),
        }),
        Err(StoreError::InvalidGraph {
            violation: GraphViolation::InvalidLogicalQuotaChild,
            ..
        })
    ));
}
