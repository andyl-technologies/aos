//! Graph metrics content-store behavior tests.

use super::*;

#[test]
fn read_through_and_metrics_nodes_report_exact_operations_and_streams() {
    let root = node_id("root-metrics");
    let read_through = node_id("read-through");
    let cache_metrics = node_id("cache-metrics");
    let source_metrics = node_id("source-metrics");
    let cache = node_id("cache");
    let source = node_id("source");
    let graph = StoreGraph::build(StoreGraphConfig {
        root: root.clone(),
        admitted_kinds: BTreeSet::from([ObjectKind::Finding]),
        nodes: BTreeMap::from([
            (
                root.clone(),
                StoreNodeSpec::Metrics {
                    child: read_through.clone(),
                },
            ),
            (
                read_through,
                StoreNodeSpec::ReadThrough {
                    cache: cache_metrics.clone(),
                    source: source_metrics.clone(),
                },
            ),
            (
                cache_metrics.clone(),
                StoreNodeSpec::Metrics {
                    child: cache.clone(),
                },
            ),
            (
                source_metrics.clone(),
                StoreNodeSpec::Metrics {
                    child: source.clone(),
                },
            ),
            (
                cache,
                StoreNodeSpec::Memory {
                    max_logical_bytes: 1_024,
                },
            ),
            (
                source,
                StoreNodeSpec::Memory {
                    max_logical_bytes: 1_024,
                },
            ),
        ]),
    })
    .expect("valid read-through metrics graph");
    assert_eq!(graph.metrics().len(), 3);
    assert!(
        graph
            .describe()
            .iter()
            .any(|node| node.kind == StoreNodeKind::ReadThrough)
    );
    assert!(
        graph
            .describe()
            .iter()
            .any(|node| node.kind == StoreNodeKind::Metrics)
    );

    let bytes = b"metric bytes";
    let id = ContentId::for_bytes(ObjectKind::Finding, 1, bytes);
    put_bytes(&graph, id, bytes).expect("source-only logical put");
    assert_eq!(
        read_bytes(&graph, id, None).expect("source read and promotion"),
        bytes
    );
    assert_eq!(
        read_bytes(&graph, id, Some(ByteRange::new(7, 5).expect("valid range")))
            .expect("cache range read"),
        b"bytes"
    );
    assert!(graph.contains(id).expect("cached object present"));

    let metrics = graph.metrics();
    let root_snapshot = metrics_for(&metrics, &root);
    assert_eq!(root_snapshot.put_calls, 1);
    assert_eq!(root_snapshot.put_logical_bytes, bytes.len() as u64);
    assert_eq!(root_snapshot.read_calls, 2);
    assert_eq!(root_snapshot.read_logical_bytes, bytes.len() as u64 + 5);
    assert_eq!(root_snapshot.read_stream_opens, 2);
    assert_eq!(root_snapshot.read_stream_completions, 2);
    assert_eq!(root_snapshot.read_stream_abandons, 0);
    assert_eq!(root_snapshot.read_stream_failures, 0);
    assert_eq!(root_snapshot.read_stream_bytes, bytes.len() as u64 + 5);
    assert_eq!(root_snapshot.contains_calls, 1);
    assert_eq!(root_snapshot.contains_hits, 1);
    assert_eq!(root_snapshot.failures, 0);

    let cache_snapshot = metrics_for(&metrics, &cache_metrics);
    assert_eq!(cache_snapshot.read_calls, 3);
    assert_eq!(cache_snapshot.failures, 1);
    assert_eq!(cache_snapshot.put_calls, 1);
    assert_eq!(cache_snapshot.put_logical_bytes, bytes.len() as u64);

    let source_snapshot = metrics_for(&metrics, &source_metrics);
    assert_eq!(source_snapshot.put_calls, 1);
    assert_eq!(source_snapshot.read_calls, 1);
    assert_eq!(source_snapshot.read_logical_bytes, bytes.len() as u64);
    assert_eq!(source_snapshot.read_stream_opens, 2);
    assert_eq!(source_snapshot.read_stream_completions, 2);
    assert_eq!(source_snapshot.read_stream_abandons, 0);
    assert_eq!(source_snapshot.read_stream_failures, 0);
    assert_eq!(source_snapshot.read_stream_bytes, 2 * bytes.len() as u64);
    assert_eq!(source_snapshot.failures, 0);
}

#[test]
fn metrics_distinguish_complete_abandoned_and_failed_deferred_reads() {
    let child = Arc::new(MemoryBlobBackend::new("metrics-child", 1_024));
    let (store, state) = MetricsStore::new("metrics", child.clone());
    let bytes = b"authenticated stream";
    let id = ContentId::for_bytes(ObjectKind::Trace, 1, bytes);
    put_bytes(child.as_ref(), id, bytes).expect("seed metrics child");

    let complete = store.read(id, None).expect("complete handle");
    assert_eq!(
        complete.read_all(TEST_READ_LIMIT).expect("complete read"),
        bytes
    );
    let partial = store.read(id, None).expect("partial handle");
    let mut reader = partial.open().expect("open partial stream");
    let mut prefix = [0_u8; 4];
    reader.read_exact(&mut prefix).expect("read partial prefix");
    drop(reader);

    let snapshot = state.snapshot();
    assert_eq!(snapshot.read_calls, 2);
    assert_eq!(snapshot.read_stream_opens, 2);
    assert_eq!(snapshot.read_stream_completions, 1);
    assert_eq!(snapshot.read_stream_abandons, 1);
    assert_eq!(snapshot.read_stream_failures, 0);
    assert_eq!(snapshot.read_stream_bytes, bytes.len() as u64 + 4);

    let broken = Arc::new(FixedReadBackend {
        source: BlobHandle::new(Arc::new(MismatchedLengthSource {
            declared: 4,
            bytes: b"abc",
        })),
    });
    let (broken_metrics, broken_state) = MetricsStore::new("broken-metrics", broken);
    assert!(matches!(
        broken_metrics
            .read(id, None)
            .expect("deferred failure handle")
            .read_all(TEST_READ_LIMIT),
        Err(StoreError::InvalidSourceLength { .. })
    ));
    let snapshot = broken_state.snapshot();
    assert_eq!(snapshot.read_stream_opens, 1);
    assert_eq!(snapshot.read_stream_completions, 0);
    assert_eq!(snapshot.read_stream_abandons, 0);
    assert_eq!(snapshot.read_stream_failures, 1);
    assert_eq!(snapshot.read_stream_bytes, 3);
}

#[test]
fn metrics_measure_synchronous_and_deferred_host_latency() {
    let delay = Duration::from_millis(2);
    let child = Arc::new(MemoryBlobBackend::new("latency-child", 1_024));
    let delayed = Arc::new(DelayedMetricsBackend {
        child: child.clone(),
        delay,
    });
    let (store, state) = MetricsStore::new("latency-metrics", delayed);
    let bytes = b"latency bytes";
    let id = ContentId::for_bytes(ObjectKind::Trace, 1, bytes);
    put_bytes(child.as_ref(), id, bytes).expect("seed latency child");

    assert!(store.contains(id).expect("delayed contains"));
    assert_eq!(
        store
            .read(id, None)
            .expect("delayed handle")
            .read_all(TEST_READ_LIMIT)
            .expect("delayed stream"),
        bytes
    );
    let second = b"second latency object";
    let second_id = ContentId::for_bytes(ObjectKind::Trace, 1, second);
    put_bytes(&store, second_id, second).expect("delayed put");

    let minimum = u64::try_from(delay.as_nanos()).expect("test duration fits u64");
    let snapshot = state.snapshot();
    assert!(snapshot.contains_elapsed_nanoseconds >= minimum);
    assert!(snapshot.read_elapsed_nanoseconds >= minimum);
    assert!(snapshot.read_stream_open_elapsed_nanoseconds >= minimum);
    assert!(snapshot.read_stream_read_elapsed_nanoseconds >= minimum);
    assert!(snapshot.put_elapsed_nanoseconds >= minimum);
}

#[test]
fn closed_store_graph_rejects_cycles_missing_routes_and_unreachable_nodes() {
    let root = node_id("root");
    assert!(matches!(
        StoreGraph::build(StoreGraphConfig {
            root: root.clone(),
            admitted_kinds: BTreeSet::from([ObjectKind::CampaignFact]),
            nodes: BTreeMap::from([(
                root.clone(),
                StoreNodeSpec::Verified {
                    child: root.clone()
                }
            )]),
        }),
        Err(StoreError::InvalidGraph {
            violation: GraphViolation::Cycle,
            ..
        })
    ));

    let router = node_id("router");
    let leaf = node_id("leaf");
    assert!(matches!(
        StoreGraph::build(StoreGraphConfig {
            root: router.clone(),
            admitted_kinds: BTreeSet::from([ObjectKind::CampaignFact, ObjectKind::RamExtent]),
            nodes: BTreeMap::from([
                (
                    router,
                    StoreNodeSpec::Routed {
                        routes: BTreeMap::from([(ObjectKind::CampaignFact, leaf.clone())])
                    }
                ),
                (
                    leaf,
                    StoreNodeSpec::Memory {
                        max_logical_bytes: 1_024
                    }
                ),
            ]),
        }),
        Err(StoreError::InvalidGraph {
            violation: GraphViolation::RouteCoverage,
            ..
        })
    ));

    let root = node_id("root");
    let unused = node_id("unused");
    assert!(matches!(
        StoreGraph::build(StoreGraphConfig {
            root: root.clone(),
            admitted_kinds: BTreeSet::from([ObjectKind::CampaignFact]),
            nodes: BTreeMap::from([
                (
                    root,
                    StoreNodeSpec::Memory {
                        max_logical_bytes: 1_024
                    }
                ),
                (
                    unused,
                    StoreNodeSpec::Memory {
                        max_logical_bytes: 1_024
                    }
                ),
            ]),
        }),
        Err(StoreError::InvalidGraph {
            violation: GraphViolation::UnreachableNode,
            ..
        })
    ));
}

#[test]
fn closed_store_graph_rejects_unbounded_or_ambient_administrative_paths() {
    let root = node_id("directory");
    assert!(matches!(
        StoreGraph::build(StoreGraphConfig {
            root: root.clone(),
            admitted_kinds: BTreeSet::from([ObjectKind::Finding]),
            nodes: BTreeMap::from([(
                root,
                StoreNodeSpec::Directory {
                    root: PathBuf::from("relative-store-root"),
                },
            )]),
        }),
        Err(StoreError::InvalidGraph {
            violation: GraphViolation::RelativeAdministrativePath,
            ..
        })
    ));

    let root = node_id("oversized-directory");
    assert!(matches!(
        StoreGraph::build(StoreGraphConfig {
            root: root.clone(),
            admitted_kinds: BTreeSet::from([ObjectKind::Finding]),
            nodes: BTreeMap::from([(
                root,
                StoreNodeSpec::Directory {
                    root: PathBuf::from(format!("/{}", "a".repeat(4_096))),
                },
            )]),
        }),
        Err(StoreError::InvalidGraph {
            violation: GraphViolation::AdministrativePathTooLong,
            ..
        })
    ));
}
