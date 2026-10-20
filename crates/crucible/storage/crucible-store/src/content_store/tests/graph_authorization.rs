//! Store-graph identity, namespace, profile, and authorization tests.

use super::*;

#[test]
fn store_graph_configuration_identity_is_canonical_and_complete() {
    let root = node_id("root");
    let config = |maximum| StoreGraphConfig {
        root: root.clone(),
        admitted_kinds: BTreeSet::from([ObjectKind::Finding, ObjectKind::Trace]),
        nodes: BTreeMap::from([(
            root.clone(),
            StoreNodeSpec::Memory {
                max_logical_bytes: maximum,
            },
        )]),
    };

    let (first, first_admin) = StoreGraph::build_with_admin(config(1_024)).expect("first graph");
    let (restarted, restarted_admin) =
        StoreGraph::build_with_admin(config(1_024)).expect("restarted graph");
    let (changed, changed_admin) =
        StoreGraph::build_with_admin(config(2_048)).expect("changed graph");

    assert_eq!(first.configuration_id(), first_admin.configuration_id());
    assert_eq!(first.configuration_id(), restarted.configuration_id());
    assert_eq!(first.configuration_id(), restarted_admin.configuration_id());
    assert_eq!(changed.configuration_id(), changed_admin.configuration_id());
    assert_ne!(first.configuration_id(), changed.configuration_id());
    assert_eq!(
        encode_hex(&first.configuration_id().as_bytes()),
        "b5d72c74a91d3eea5cf688a42d79dfdbddb9dc4fc0c6fd20cb8f42dcb9d772dd"
    );
}

#[test]
fn namespaced_graph_authorizes_every_operation_before_child_access() {
    for invalid in ["", "/absolute", "a//b", "a/../b", "snowman-☃"] {
        assert!(matches!(
            StoreNamespaceId::new(invalid),
            Err(StoreError::InvalidComposition { .. })
        ));
    }
    assert!(matches!(
        StoreNamespaceId::new("a".repeat(256)),
        Err(StoreError::InvalidComposition { .. })
    ));
    assert!(matches!(
        StoreNamespaceId::new(format!("{}/{}/c", "a".repeat(255), "b".repeat(255))),
        Err(StoreError::InvalidComposition { .. })
    ));

    let namespace = StoreNamespaceId::new("tenant-a/campaigns").expect("namespace");
    let namespaced = node_id("namespaced");
    let memory = node_id("memory");
    let config = |namespace| StoreGraphConfig {
        root: namespaced.clone(),
        admitted_kinds: BTreeSet::from([ObjectKind::CampaignFact]),
        nodes: BTreeMap::from([
            (
                namespaced.clone(),
                StoreNodeSpec::Namespaced {
                    child: memory.clone(),
                    namespace,
                },
            ),
            (
                memory.clone(),
                StoreNodeSpec::Memory {
                    max_logical_bytes: 1_024,
                },
            ),
        ]),
    };

    assert!(matches!(
        StoreGraph::build(config(namespace.clone())),
        Err(StoreError::Unauthorized)
    ));
    let bypass = node_id("bypass");
    assert!(matches!(
        StoreGraph::build(StoreGraphConfig {
            root: bypass.clone(),
            admitted_kinds: BTreeSet::from([ObjectKind::CampaignFact]),
            nodes: BTreeMap::from([
                (
                    bypass,
                    StoreNodeSpec::WriteThrough {
                        children: vec![namespaced.clone(), memory.clone()],
                    },
                ),
                (
                    namespaced.clone(),
                    StoreNodeSpec::Namespaced {
                        child: memory.clone(),
                        namespace: namespace.clone(),
                    },
                ),
                (
                    memory.clone(),
                    StoreNodeSpec::Memory {
                        max_logical_bytes: 1_024,
                    },
                ),
            ]),
        }),
        Err(StoreError::InvalidGraph {
            violation: GraphViolation::InvalidNamespaceBoundary,
            ..
        })
    ));
    let nested = node_id("nested-namespace");
    assert!(matches!(
        StoreGraph::build(StoreGraphConfig {
            root: namespaced.clone(),
            admitted_kinds: BTreeSet::from([ObjectKind::CampaignFact]),
            nodes: BTreeMap::from([
                (
                    namespaced.clone(),
                    StoreNodeSpec::Namespaced {
                        child: nested.clone(),
                        namespace: namespace.clone(),
                    },
                ),
                (
                    nested,
                    StoreNodeSpec::Namespaced {
                        child: memory.clone(),
                        namespace: namespace.clone(),
                    },
                ),
                (
                    memory.clone(),
                    StoreNodeSpec::Memory {
                        max_logical_bytes: 1_024,
                    },
                ),
            ]),
        }),
        Err(StoreError::InvalidGraph {
            violation: GraphViolation::InvalidNamespaceBoundary,
            ..
        })
    ));
    let unrelated = StoreNamespaceId::new("tenant-b/campaigns").expect("other namespace");
    let authorizer = Arc::new(RecordingNamespaceAuthorizer::default());
    let mut authorizers = StoreGraphNamespaceAuthorizers::new();
    authorizers
        .insert(unrelated.clone(), authorizer.clone())
        .expect("unrelated capability");
    assert!(matches!(
        StoreGraph::build_with_authorizers(config(namespace.clone()), &authorizers),
        Err(StoreError::Unauthorized)
    ));
    authorizers
        .insert(namespace.clone(), authorizer.clone())
        .expect("namespace capability");
    assert!(matches!(
        authorizers.insert(namespace.clone(), authorizer.clone()),
        Err(StoreError::InvalidComposition { .. })
    ));

    let graph = StoreGraph::build_with_authorizers(config(namespace.clone()), &authorizers)
        .expect("authorized namespace graph");
    assert_eq!(graph.describe()[1].kind, StoreNodeKind::Namespaced);
    let bytes = b"namespace protected object";
    let id = ContentId::for_bytes(ObjectKind::CampaignFact, 1, bytes);
    let denied_opens = Arc::new(AtomicUsize::new(0));
    let denied_bytes = Arc::new(AtomicUsize::new(0));
    let denied_source = BlobHandle::new(Arc::new(CountingSource {
        bytes: Arc::from(bytes.as_slice()),
        opens: denied_opens.clone(),
        bytes_read: denied_bytes.clone(),
    }));
    assert!(matches!(
        graph.put_if_absent(id, &denied_source),
        Err(StoreError::Unauthorized)
    ));
    assert_eq!(denied_opens.load(Ordering::SeqCst), 0);
    assert_eq!(denied_bytes.load(Ordering::SeqCst), 0);

    authorizer.set_allowed(true);
    assert!(!graph.contains(id).expect("denied put reached no child"));
    put_bytes(&graph, id, bytes).expect("authorized put");
    assert!(graph.contains(id).expect("authorized contains"));
    assert_eq!(
        read_bytes(&graph, id, None).expect("authorized read"),
        bytes
    );

    authorizer.set_allowed(false);
    assert!(matches!(graph.contains(id), Err(StoreError::Unauthorized)));
    assert!(matches!(
        graph.read(id, None),
        Err(StoreError::Unauthorized)
    ));
    assert_eq!(
        authorizer.calls(),
        vec![
            (StoreNamespaceOperation::Put, id),
            (StoreNamespaceOperation::Contains, id),
            (StoreNamespaceOperation::Put, id),
            (StoreNamespaceOperation::Contains, id),
            (StoreNamespaceOperation::Read, id),
            (StoreNamespaceOperation::Contains, id),
            (StoreNamespaceOperation::Read, id),
        ]
    );

    let mut alternate_authorizers = StoreGraphNamespaceAuthorizers::new();
    alternate_authorizers
        .insert(unrelated.clone(), authorizer)
        .expect("alternate namespace capability");
    let alternate = StoreGraph::build_with_authorizers(config(unrelated), &alternate_authorizers)
        .expect("alternate namespace graph");
    assert_ne!(graph.configuration_id(), alternate.configuration_id());
    assert_eq!(
        encode_hex(&graph.configuration_id().as_bytes()),
        "24af313c4576e05b17da6745dc1ecabc020deab10d7d1fe9877f07babc4d8071"
    );
}

#[test]
fn profile_graph_derives_authenticated_classes_without_caller_hints() {
    for invalid in ["", "/absolute", "a//b", "a/../b", "snowman-☃"] {
        assert!(matches!(
            StoreObjectProfilePolicyId::new(invalid),
            Err(StoreError::InvalidComposition { .. })
        ));
    }

    let policy = StoreObjectProfilePolicyId::new("crucible.campaign.object-profile.v1")
        .expect("profile policy");
    let profile = node_id("profile");
    let memory = node_id("memory");
    let config = |policy| StoreGraphConfig {
        root: profile.clone(),
        admitted_kinds: BTreeSet::from([ObjectKind::Trace]),
        nodes: BTreeMap::from([
            (
                profile.clone(),
                StoreNodeSpec::ProfileValidated {
                    child: memory.clone(),
                    policy,
                },
            ),
            (
                memory.clone(),
                StoreNodeSpec::Memory {
                    max_logical_bytes: 1_024,
                },
            ),
        ]),
    };
    assert!(matches!(
        StoreGraph::build(config(policy.clone())),
        Err(StoreError::Unauthorized)
    ));

    let profiler = Arc::new(RecordingObjectProfiler::new(false));
    let mut profilers = StoreGraphObjectProfilers::new();
    profilers
        .insert(policy.clone(), profiler.clone())
        .expect("profile capability");
    assert!(matches!(
        profilers.insert(policy.clone(), profiler.clone()),
        Err(StoreError::InvalidComposition { .. })
    ));
    let keys = StoreGraphKeyring::new();
    let authorizers = StoreGraphNamespaceAuthorizers::new();
    let graph = StoreGraph::build_with_all_capabilities(
        config(policy.clone()),
        &keys,
        &authorizers,
        &profilers,
        &StoreGraphPhysicalQuotaBinders::new(),
        &StoreGraphS3Clients::new(),
    )
    .expect("profile graph");
    assert_eq!(graph.describe()[1].kind, StoreNodeKind::ProfileValidated);

    let bytes = b"profiled trace";
    let id = ContentId::for_bytes(ObjectKind::Trace, 1, bytes);
    assert!(matches!(
        put_bytes(&graph, id, bytes),
        Err(StoreError::Unauthorized)
    ));

    profiler.set_allowed(true);
    assert!(!graph.contains(id).expect("denied put left child empty"));
    put_bytes(&graph, id, bytes).expect("profiled put");
    assert!(graph.contains(id).expect("profiled contains"));
    assert_eq!(
        read_bytes(
            &graph,
            id,
            Some(ByteRange::new(2, 5).expect("profiled range")),
        )
        .expect("profiled range read"),
        b"ofile"
    );
    assert_eq!(profiler.calls.load(Ordering::SeqCst), 4);

    profiler.set_returned_kind(Some(ObjectKind::Finding));
    assert!(matches!(graph.contains(id), Err(StoreError::Incompatible)));

    let other_policy = StoreObjectProfilePolicyId::new("crucible.campaign.object-profile.v2")
        .expect("other profile policy");
    let other_profiler = Arc::new(RecordingObjectProfiler::new(true));
    let mut other_profilers = StoreGraphObjectProfilers::new();
    other_profilers
        .insert(other_policy.clone(), other_profiler)
        .expect("other profile capability");
    let other = StoreGraph::build_with_all_capabilities(
        config(other_policy),
        &keys,
        &authorizers,
        &other_profilers,
        &StoreGraphPhysicalQuotaBinders::new(),
        &StoreGraphS3Clients::new(),
    )
    .expect("other profile graph");
    assert_ne!(graph.configuration_id(), other.configuration_id());
    assert_eq!(
        encode_hex(&graph.configuration_id().as_bytes()),
        "c198ff2a2f52c3db30492d38fe125240834876b6ec7ded78d60ac541f9e8cce4"
    );

    let bypass = node_id("bypass");
    assert!(matches!(
        StoreGraph::build(StoreGraphConfig {
            root: bypass.clone(),
            admitted_kinds: BTreeSet::from([ObjectKind::Trace]),
            nodes: BTreeMap::from([
                (
                    bypass,
                    StoreNodeSpec::WriteThrough {
                        children: vec![profile.clone(), memory.clone()],
                    },
                ),
                (
                    profile,
                    StoreNodeSpec::ProfileValidated {
                        child: memory.clone(),
                        policy,
                    },
                ),
                (
                    memory,
                    StoreNodeSpec::Memory {
                        max_logical_bytes: 1_024,
                    },
                ),
            ]),
        }),
        Err(StoreError::InvalidGraph {
            violation: GraphViolation::InvalidProfileBoundary,
            ..
        })
    ));
}

#[test]
fn profile_and_namespace_boundaries_compose_at_the_graph_root() {
    let policy = StoreObjectProfilePolicyId::new("crucible.campaign.object-profile.v1")
        .expect("profile policy");
    let namespace = StoreNamespaceId::new("tenant-a/profiled").expect("namespace");
    let profile = node_id("profile");
    let namespaced = node_id("namespaced");
    let memory = node_id("memory");
    let profiler = Arc::new(RecordingObjectProfiler::new(true));
    let authorizer = Arc::new(RecordingNamespaceAuthorizer::default());
    authorizer.set_allowed(true);
    let mut profilers = StoreGraphObjectProfilers::new();
    profilers
        .insert(policy.clone(), profiler)
        .expect("profile capability");
    let mut authorizers = StoreGraphNamespaceAuthorizers::new();
    authorizers
        .insert(namespace.clone(), authorizer)
        .expect("namespace capability");
    let graph = StoreGraph::build_with_all_capabilities(
        StoreGraphConfig {
            root: profile.clone(),
            admitted_kinds: BTreeSet::from([ObjectKind::Trace]),
            nodes: BTreeMap::from([
                (
                    profile,
                    StoreNodeSpec::ProfileValidated {
                        child: namespaced.clone(),
                        policy,
                    },
                ),
                (
                    namespaced,
                    StoreNodeSpec::Namespaced {
                        child: memory.clone(),
                        namespace,
                    },
                ),
                (
                    memory,
                    StoreNodeSpec::Memory {
                        max_logical_bytes: 1_024,
                    },
                ),
            ]),
        },
        &StoreGraphKeyring::new(),
        &authorizers,
        &profilers,
        &StoreGraphPhysicalQuotaBinders::new(),
        &StoreGraphS3Clients::new(),
    )
    .expect("composed boundaries");
    let bytes = b"composed operational boundaries";
    let id = ContentId::for_bytes(ObjectKind::Trace, 1, bytes);
    put_bytes(&graph, id, bytes).expect("composed put");
    assert_eq!(read_bytes(&graph, id, None).expect("composed read"), bytes);
}

#[test]
fn profile_graph_validates_deferred_transfer_and_root_inventory() {
    let temp = TempDir::new().expect("temporary directory");
    let policy = StoreObjectProfilePolicyId::new("crucible.campaign.object-profile.v1")
        .expect("profile policy");
    let profile = node_id("profile");
    let write_back = node_id("write-back");
    let staging = node_id("staging");
    let destination = node_id("destination");
    let profiler = Arc::new(RecordingObjectProfiler::new(true));
    let mut profilers = StoreGraphObjectProfilers::new();
    profilers
        .insert(policy.clone(), profiler.clone())
        .expect("profile capability");
    let graph = StoreGraph::build_with_all_capabilities(
        StoreGraphConfig {
            root: profile.clone(),
            admitted_kinds: BTreeSet::from([ObjectKind::Finding]),
            nodes: BTreeMap::from([
                (
                    profile,
                    StoreNodeSpec::ProfileValidated {
                        child: write_back.clone(),
                        policy,
                    },
                ),
                (
                    write_back,
                    StoreNodeSpec::WriteBack {
                        staging: staging.clone(),
                        destination: destination.clone(),
                        journal_root: temp.path().join("journal"),
                        maximum_pending_objects: 8,
                        maximum_pending_bytes: 1_024,
                    },
                ),
                (
                    staging,
                    StoreNodeSpec::Directory {
                        root: temp.path().join("staging"),
                    },
                ),
                (
                    destination,
                    StoreNodeSpec::Directory {
                        root: temp.path().join("destination"),
                    },
                ),
            ]),
        },
        &StoreGraphKeyring::new(),
        &StoreGraphNamespaceAuthorizers::new(),
        &profilers,
        &StoreGraphPhysicalQuotaBinders::new(),
        &StoreGraphS3Clients::new(),
    )
    .expect("profiled write-back graph");
    let bytes = b"profiled deferred finding";
    let id = ContentId::for_bytes(ObjectKind::Finding, 1, bytes);
    put_bytes(&graph, id, bytes).expect("profiled staging put");

    profiler.set_allowed(false);
    assert!(matches!(
        graph.flush_write_back(1),
        Err(StoreError::Unauthorized)
    ));
    {
        let mut fence = graph
            .acquire_write_back_retention_fence()
            .expect("retention fence");
        assert!(matches!(
            fence.visit_roots(&mut |_root| Ok(())),
            Err(StoreError::Unauthorized)
        ));
    }
    let destination = DirectoryBlobBackend::new("inspection", temp.path().join("destination"));
    assert!(!destination.contains(id).expect("destination remains empty"));

    profiler.set_allowed(true);
    assert_eq!(
        graph
            .flush_write_back(1)
            .expect("profiled flush")
            .completed(),
        1
    );
    let mut fence = graph
        .acquire_write_back_retention_fence()
        .expect("empty retention fence");
    assert_eq!(
        fence
            .visit_roots(&mut |_root| Ok(()))
            .expect("empty inventory")
            .roots(),
        0
    );
}

#[test]
fn namespaced_graph_authorizes_deferred_transfer_and_root_inventory() {
    let temp = TempDir::new().expect("temporary directory");
    let namespace = StoreNamespaceId::new("tenant-a/archive").expect("namespace");
    let namespaced = node_id("namespaced");
    let write_back = node_id("write-back");
    let staging = node_id("staging");
    let destination = node_id("destination");
    let authorizer = Arc::new(RecordingNamespaceAuthorizer::default());
    authorizer.set_allowed(true);
    let mut authorizers = StoreGraphNamespaceAuthorizers::new();
    authorizers
        .insert(namespace.clone(), authorizer.clone())
        .expect("namespace capability");
    let graph = StoreGraph::build_with_authorizers(
        StoreGraphConfig {
            root: namespaced.clone(),
            admitted_kinds: BTreeSet::from([ObjectKind::Finding]),
            nodes: BTreeMap::from([
                (
                    namespaced,
                    StoreNodeSpec::Namespaced {
                        child: write_back.clone(),
                        namespace,
                    },
                ),
                (
                    write_back,
                    StoreNodeSpec::WriteBack {
                        staging: staging.clone(),
                        destination: destination.clone(),
                        journal_root: temp.path().join("journal"),
                        maximum_pending_objects: 8,
                        maximum_pending_bytes: 1_024,
                    },
                ),
                (
                    staging,
                    StoreNodeSpec::Directory {
                        root: temp.path().join("staging"),
                    },
                ),
                (
                    destination,
                    StoreNodeSpec::Directory {
                        root: temp.path().join("destination"),
                    },
                ),
            ]),
        },
        &authorizers,
    )
    .expect("namespaced write-back graph");
    let bytes = b"authorized deferred finding";
    let id = ContentId::for_bytes(ObjectKind::Finding, 1, bytes);
    put_bytes(&graph, id, bytes).expect("authorized staging put");

    authorizer.set_allowed(false);
    assert!(matches!(
        graph.flush_write_back(1),
        Err(StoreError::Unauthorized)
    ));
    let destination = DirectoryBlobBackend::new("inspection", temp.path().join("destination"));
    assert!(!destination.contains(id).expect("destination remains empty"));
    {
        let mut fence = graph
            .acquire_write_back_retention_fence()
            .expect("retention fence");
        assert!(matches!(
            fence.visit_roots(&mut |_root| Ok(())),
            Err(StoreError::Unauthorized)
        ));
    }

    authorizer.set_allowed(true);
    let summary = graph.flush_write_back(1).expect("authorized transfer");
    assert_eq!(summary.completed(), 1);
    assert_eq!(summary.pending(), 0);
    assert_eq!(
        read_bytes(&destination, id, None).expect("destination bytes"),
        bytes
    );
}
