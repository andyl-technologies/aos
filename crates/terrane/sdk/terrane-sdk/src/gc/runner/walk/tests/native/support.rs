//! Builds genuine retained native fixtures and independent physical read oracles.

use super::*;

/// Uses the unchanged collector retention windows.
///
/// # Panics
/// Panics if genuine setup, canonical fixture data or an asserted invariant fails.
pub(super) fn windows() -> Windows {
    Windows::new(30, 60, 60, 90).assert_success()
}

/// Calculates a typed immutable identity for fixture bytes.
///
/// # Panics
/// Panics if genuine setup, canonical fixture data or an asserted invariant fails.
pub(super) fn digest(kind: IdentityKind, bytes: &[u8]) -> Digest {
    TERRANE_V1
        .calculate(kind, bytes)
        .assert_success()
        .terrane_v1_digest()
        .assert_success()
}

/// Returns the actual fixed native fixture terminal seed.
///
/// # Panics
/// Panics if genuine setup, canonical fixture data or an asserted invariant fails.
pub(super) fn terminal_seed() -> [u8; 32] {
    // The actual configured GC fixture terminal key, not a verifier bypass.
    let hex = b"9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60";
    std::array::from_fn(|index| {
        u8::from_str_radix(
            std::str::from_utf8(&hex[index * 2..index * 2 + 2]).assert_success(),
            16,
        )
        .assert_success()
    })
}

/// Names the genuine retained repository with the production metadata validator.
pub(super) type RepositoryWithIndexes =
    Repository<FileBucket<TestFs, NativeEffectClock, MetadataValidator>, NativeEffectClock, TestFs>;

/// Reopens the same native bucket, issuer and protected controls with all
/// production metadata codecs, retaining the actual injected effect clock.
///
/// # Panics
/// Panics if genuine setup, canonical fixture data or an asserted invariant fails.
pub(super) async fn production_repository(fixture: &Fixture) -> RepositoryWithIndexes {
    let selections = if fixture.authoring.is_some() {
        crate::gc::runner::fixture::capture_view_selections(fixture.guard(), &[fixture.head.commit])
            .await
    } else {
        Vec::new()
    };
    production_repository_with_selections(fixture, selections).await
}

/// Reopens the genuine native repository with independently retained historical inputs.
///
/// The caller captures these rows from the actual owning Guard before dropping it.
/// Current and authoring configuration remain the fixture's original inputs.
///
/// # Panics
/// Panics if historical installation, native reopening or retained controls fail.
pub(super) async fn production_repository_with_selections(
    fixture: &Fixture,
    selections: Vec<crate::guard::ViewSelection>,
) -> RepositoryWithIndexes {
    let clock = fixture.clock.retain_native_clock().assert_success();
    let bucket = FileBucket::open(
        fixture.config.clone(),
        fixture.fs.clone(),
        clock.retain_native_clock().assert_success(),
        MetadataValidator::new(fixture.config.chunk_profile.clone()),
    )
    .await
    .assert_success();
    let guard = crate::gc::runner::fixture::configured_guard(
        bucket,
        clock,
        fixture.guard().keys().to_vec(),
        fixture.guard().config().clone(),
        fixture.authoring.as_ref(),
    );
    let guard = if fixture.authoring.is_some() {
        guard.with_view_selections(selections).assert_success()
    } else {
        assert!(selections.is_empty());
        guard
    };
    let coordinator = Coordinator::new(
        guard,
        CommitTiming::new(
            std::time::Duration::from_secs(30),
            std::time::Duration::from_secs(60),
            std::time::Duration::from_secs(10),
        )
        .assert_success(),
        fixture.fs.clone(),
    );
    Repository::reopen_native_retention(
        coordinator,
        &DomainNamespace {
            root: fixture.config.root.clone(),
            domain: "public".into(),
        },
        &fixture.parent.join("original"),
        fixture
            .config
            .publication_control
            .as_ref()
            .assert_success()
            .operator_uid,
    )
    .await
    .assert_success()
}

/// Issues the actual configured native fixture token.
///
/// # Panics
/// Panics if genuine setup, canonical fixture data or an asserted invariant fails.
pub(super) fn token(fixture: &Fixture) -> Vec<u8> {
    use terrane_format::auth::{Authority, Grant, Token, Verbs};
    use terrane_format::refs::PrincipalKind;
    Token::issue(
        Authority {
            issuer: "fixture".into(),
            key_id: "fixture".into(),
            subject: "writer".into(),
            kind: PrincipalKind::Human,
            groups: Vec::new(),
            not_after: u64::MAX,
            not_before: None,
            token_id: [1; 16],
            grants: vec![
                Grant::new("refs/**".into(), Verbs::new(31).assert_success()).assert_success(),
            ],
            workload: None,
        },
        &terminal_seed(),
        fixture.guard().keys()[0].public_key,
    )
    .assert_success()
    .encode()
}

/// Stages an ordinary signed proposal with explicit metadata and chunk inputs.
///
/// # Panics
/// Panics if genuine setup, canonical fixture data or an asserted invariant fails.
pub(super) async fn proposal(
    fixture: &Fixture,
    tree: &Tree<'_>,
    data: Option<&IndexData>,
    plaintexts: &[&[u8]],
) -> CommitRequest {
    // Candidate construction needs only the original unsigned data. Actual
    // parent, source, Original and current authority checks belong to admission.
    let mut commit = fixture.proposal_template.clone();
    commit.tree = tree.root_identity();
    commit.parents = vec![fixture.head.commit];
    commit.signature = None;
    commit.timestamp = 0;
    commit.message = "Publish complete collector metadata".into();
    let mut uploads = tree
        .nodes()
        .map(|node| StagedUpload::Meta {
            kind: IdentityKind::Node,
            bytes: node.encoded().to_vec(),
        })
        .collect::<Vec<_>>();
    if let Some(data) = data {
        uploads.extend(data.nodes.values().map(|bytes| StagedUpload::Meta {
            kind: IdentityKind::Node,
            bytes: bytes.clone(),
        }));
    }
    for plaintext in plaintexts {
        uploads.push(StagedUpload::Chunk {
            encoded: terrane_format::codec::encode_envelope(terrane_format::codec::EncodedChunk {
                codec: terrane_format::codec::Codec::Raw,
                body: plaintext,
            }),
            identity: TERRANE_V1
                .calculate(IdentityKind::Chunk, plaintext)
                .assert_success(),
            declared_plaintext_len: plaintext.len(),
            position: crate::store::ChunkPosition::Final,
            profile: Box::new(fixture.config.chunk_profile.clone()),
        });
    }
    CommitRequest {
        commit,
        uploads,
        token: token(fixture),
        terminal_secret: terminal_seed(),
        surface: "sdk".into(),
        reference_records: Vec::new(),
        disclosures: Vec::new(),
    }
}

/// Creates an ordinary file without attribution claims.
///
/// # Panics
/// Panics if genuine setup, canonical fixture data or an asserted invariant fails.
pub(super) fn entry(plaintext: &[u8]) -> Entry<'static> {
    Entry {
        kind: EntryKind::File {
            mode: 0o644,
            size: plaintext.len() as u64,
            content: ContentRef::Inline(digest(IdentityKind::Chunk, plaintext)),
            link_id: None,
        },
        attrs: Vec::new(),
        attrs_present: false,
        xattrs: Vec::new(),
        xattrs_present: false,
        provenance: None,
    }
}

/// Encodes one Index row independently from the registered wire schema.
///
/// # Panics
/// Panics if genuine setup, canonical fixture data or an asserted invariant fails.
pub(super) fn raw_carrier(
    key: &[u8],
    object: Digest,
    route: Option<Digest>,
    gap: Option<Digest>,
) -> Vec<u8> {
    use terrane_format::cbor;
    let mut bytes = vec![if gap.is_some() { 0xa3 } else { 0xa2 }, 1, 0, 2, 0x81, 0x83];
    cbor::write_bytes(&mut bytes, key);
    bytes.push(0);
    bytes.extend_from_slice(&[if route.is_some() { 0xa3 } else { 0xa2 }, 1, 7]);
    if let Some(route) = route {
        bytes.extend_from_slice(b"\x09\xa1\x71index.occurrences");
        cbor::write_bytes(&mut bytes, &route);
    }
    bytes.extend_from_slice(&[14, 0x81]);
    cbor::write_bytes(&mut bytes, &object);
    if let Some(gap) = gap {
        bytes.extend_from_slice(b"\x03\xa1\x6aindex-gaps\xa2\x65value");
        cbor::write_text(
            &mut bytes,
            &gap.iter()
                .map(|byte| format!("{byte:02x}"))
                .collect::<String>(),
        );
        bytes.extend_from_slice(b"\x67inherit\xf4");
    }
    bytes
}

/// Publishes canonical side metadata through the actual native backend.
///
/// # Panics
/// Panics if genuine setup, canonical fixture data or an asserted invariant fails.
pub(super) async fn put_record(fixture: &Fixture, record: &AttrRecord) -> Digest {
    let bytes = record.encode().assert_success();
    fixture
        .guard()
        .store()
        .put(ContentUpload::Meta(
            MetaUpload::new(IdentityKind::Attribute, &bytes).assert_success(),
        ))
        .await
        .assert_success()
        .terrane_v1_digest()
        .assert_success()
}

/// Arms LocalFs traps on data packs classified by independent detached headers.
///
/// # Panics
/// Panics if genuine setup, canonical fixture data or an asserted invariant fails.
pub(super) async fn arm_data_reads<V: ContentValidator + crate::bucket::BucketBinding>(
    fixture: &Fixture,
    store: &MetadataStore<'_, '_, TestFs, NativeEffectClock, V>,
) -> Vec<std::path::PathBuf> {
    let catalog: crate::bucket::publication::collection_observation::CollectionCatalog =
        store.collection_catalog().await.assert_success();
    let mut paths = Vec::new();
    for entry in catalog.inventory().assert_success() {
        let pack = crate::pack::PackId::from_random_bytes(entry.pack_id);
        let bytes = fixture
            .fs
            .read(&fixture.config.root.join(pack.index_key()))
            .await
            .assert_success();
        assert_eq!(&bytes[..6], b"TRPK\x01\x00");
        // This fixed flag is an independent physical classification oracle;
        // no object digest or namespace role determines the pack's type.
        if bytes[6] & 2 == 0 {
            paths.push(fixture.config.root.join(pack.pack_key()));
        }
    }
    assert!(!paths.is_empty());
    fixture.fs.forbid_data_body_reads(&paths).assert_success();
    paths
}

/// Proves every counted LocalFs trap is armed after asserting the walk's count.
///
/// # Panics
/// Panics if genuine setup, canonical fixture data or an asserted invariant fails.
pub(super) async fn prove_data_read_traps(fixture: &Fixture, paths: &[std::path::PathBuf]) {
    assert_eq!(fixture.fs.data_body_read_attempts(), 0);
    assert!(fixture.fs.read(&paths[0]).await.is_err());
    assert!(
        fixture
            .fs
            .read_range(
                &paths[0],
                crate::store::ByteRange {
                    start: 0,
                    length: 1
                }
            )
            .await
            .is_err()
    );
    assert!(fixture.fs.read_nofollow(&paths[0]).await.is_err());
    assert_eq!(fixture.fs.data_body_read_attempts(), 3);
}

/// Creates an unacknowledged traversal input for one actual signed view.
pub(super) fn frontier(commit: Digest, witness: bool) -> GcState {
    let mut state = state();
    state.pending = vec![Pending {
        kind: 3,
        hash: commit,
        parent_cutoff: ParentCutoff::RootsOnly,
        flags: if witness { WITNESS } else { 0 },
        proof_context: None,
    }];
    state
}

/// Owns real native publication data for independent reachability assertions.
pub(super) struct IndexedPublication {
    /// Actual selected signed reference record.
    pub(super) head: terrane_format::refs::RefRecord,
    /// Final immutable owner root carrying the selected binding.
    pub(super) owner: Digest,
    /// Exact materialized I/P/G bytes constructed from the namespace.
    pub(super) data: IndexData,
    /// Present file's actual typed Chunk digest.
    pub(super) present_object: Digest,
    /// Missing-value file's actual typed Chunk digest.
    pub(super) missing_object: Digest,
    /// Canonical inline value used by the independent Index oracle.
    pub(super) value: Vec<u8>,
}

/// Publishes a real ordinary owner with both present and missing Index coverage.
///
/// # Panics
/// Panics on invalid immutable construction or failed signed native publication.
pub(super) async fn publish_indexed(
    fixture: &Fixture,
    repository: &RepositoryWithIndexes,
) -> IndexedPublication {
    let value = AttributeValue::Sha256([11; 32]).encode().assert_success();
    let present_bytes = b"present index object";
    let missing_bytes = b"missing value remains reachable";
    let present_object = digest(IdentityKind::Chunk, present_bytes);
    let missing_object = digest(IdentityKind::Chunk, missing_bytes);
    let mut present = entry(present_bytes);
    present.attrs = vec![Attribute {
        name: "hash.sha256",
        value: &value,
    }];
    present.attrs_present = true;
    let source = Tree::build(
        vec![
            LeafItem {
                key: b"missing".to_vec(),
                entry: entry(missing_bytes),
            },
            LeafItem {
                key: b"present".to_vec(),
                entry: present,
            },
        ],
        Some(vec![
            Property {
                name: "acl",
                value: b"\x81\x82\x66writer\x18\x1f",
            },
            Property {
                name: "domain",
                value: b"\x66public",
            },
        ]),
        262144,
        TreeUse::Ordinary,
    )
    .assert_success();
    let graph = BTreeMap::from([(source.root_identity(), source.clone())]);
    let recipe = IndexEvaluationRecipe::new(source.root_identity(), "hash.sha256").assert_success();
    let context = SemanticContext::new(3, 2, 1).assert_success();
    let data = evaluation::construct(&recipe, &graph, 262144, context).assert_success();
    let arena = maintenance::ByteArena::new(1 << 20).assert_success();
    let completed = completion::complete(
        source.root_identity(),
        &graph,
        &[completion::Selection {
            attribute: "hash.sha256",
            data: &data,
        }],
        &arena,
        262144,
        context,
        completion::MemoPolicy::Omit,
    )
    .assert_success();
    let request = proposal(
        fixture,
        &completed.owner.tree,
        Some(&data),
        &[present_bytes, missing_bytes],
    )
    .await;
    let mut writer = repository
        .begin("refs/heads/_/main", &token(fixture), "sdk")
        .await
        .assert_success();
    let head = repository
        .commit_request(&mut writer, request)
        .await
        .assert_success();
    let owner = completed.owner.tree.root_identity();
    drop(completed);
    drop(graph);
    drop(source);

    IndexedPublication {
        head,
        owner,
        data,
        present_object,
        missing_object,
        value,
    }
}
